// Package asvs holds test-only ASVS guard tests for the Go line of rgt-vault.
//
// This file covers ASVS V2 (Authentication) and V3 (Session Management);
// the applicability matrix is docs/security/asvs/V2-V3.md.
//
// rgt-vault's Go server authenticates with exactly one thing: a random bearer
// token sent in the Authorization header. It has no user accounts, passwords,
// cookies, browser sessions, OAuth/federation, OOB/SMS/e-mail authenticators,
// OTP/TOTP verification or challenge-response. Many V2/V3 rows are therefore
// "N/A because X does not exist". These tests turn those claims into
// assertions that fail if X appears, so an N/A verdict cannot go stale, and
// they check the properties the bearer token does have.
//
// The tests live in their own package so they do not share a compile unit with
// the packages they inspect, and they run on Linux, macOS and Windows (file
// mode assertions are skipped on Windows).
package asvs

import (
	"bytes"
	"encoding/base64"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/server/handlers"
)

// goRoot is the go/ module root relative to this package directory.
const goRoot = "../.."

// publicPaths are the only routes the server serves without a credential.
var publicPaths = map[string]bool{
	"/healthz":                true,
	"/crossdomain.xml":        true,
	"/clientaccesspolicy.xml": true,
}

// credentialName matches names that must never be a URL parameter or JSON field
// that carries a credential (ASVS 3.1.1, 2.1.x).
var credentialName = regexp.MustCompile(`(?i)token|pass(word|wd|phrase|code)|pwd|credential|api[_-]?key|apikey|auth|session|bearer|jwt|secret`)

type testServer struct {
	router    chi.Router
	token     string
	tokenPath string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "state", "server.token")
	tok, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	ts := auth.NewTokenStore(tokenPath)
	if err := ts.Write(tok); err != nil {
		t.Fatalf("Write token: %v", err)
	}
	router := server.NewRouter(handlers.NewHandlers(handlers.NewStore(), ts), server.NewMiddleware(ts))
	return &testServer{router: router, token: tok, tokenPath: tokenPath}
}

type route struct{ method, path string }

// allRoutes walks the real chi router and returns every registered route with
// path parameters filled in.
func allRoutes(t *testing.T, r chi.Router) []route {
	t.Helper()
	var out []route
	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		p := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(pattern, "x")
		out = append(out, route{method, p})
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if len(out) < 10 {
		t.Fatalf("route walk found only %d routes; the guard would be vacuous", len(out))
	}
	return out
}

func isPublic(p string) bool { return publicPaths[strings.TrimSuffix(p, "/")] }

func serve(ts *testServer, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	ts.router.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// RGT-284 / 324 / 326 / 319: the bearer token is >=256 bits from a CSPRNG, unique, no default
// ---------------------------------------------------------------------------

func TestBearerTokenIs256BitAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, err := auth.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		raw, err := base64.URLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("token is not url-safe base64: %v", err)
		}
		if len(raw) < 32 {
			t.Fatalf("token carries %d bits, want >= 256", len(raw)*8)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}

func TestTokenGeneratorUsesCryptoRandNotMathRand(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(goRoot, "internal", "auth", "token.go"), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var imports []string
	for _, imp := range f.Imports {
		imports = append(imports, strings.Trim(imp.Path.Value, `"`))
	}
	has := func(p string) bool {
		for _, i := range imports {
			if i == p {
				return true
			}
		}
		return false
	}
	if !has("crypto/rand") {
		t.Errorf("internal/auth/token.go must import crypto/rand; imports: %v", imports)
	}
	if has("math/rand") || has("math/rand/v2") {
		t.Errorf("internal/auth/token.go must not use math/rand; imports: %v", imports)
	}
	if !has("crypto/subtle") {
		t.Errorf("internal/auth/token.go must compare tokens with crypto/subtle; imports: %v", imports)
	}
}

func TestNoDefaultCredential(t *testing.T) {
	// A fresh state dir mints a fresh random token each time: nothing is baked in.
	a, b := filepath.Join(t.TempDir(), "a.token"), filepath.Join(t.TempDir(), "b.token")
	_, ta, err := auth.LoadOrCreateToken(a)
	if err != nil {
		t.Fatal(err)
	}
	_, tb, err := auth.LoadOrCreateToken(b)
	if err != nil {
		t.Fatal(err)
	}
	if ta == tb || ta == "" || tb == "" {
		t.Fatalf("LoadOrCreateToken must mint distinct non-empty tokens, got %q / %q", ta, tb)
	}
	if err := auth.NewTokenStore(filepath.Join(t.TempDir(), "e.token")).Write(""); err == nil {
		t.Fatal("an empty token must be refused")
	}

	// Missing, empty, guessed and well-known values never authenticate.
	ts := newTestServer(t)
	for _, h := range []string{"", "Bearer ", "Bearer changeme", "Bearer admin", "Bearer password", "Bearer " + strings.Repeat("A", 43)} {
		hdr := map[string]string{}
		if h != "" {
			hdr["Authorization"] = h
		}
		if rec := serve(ts, "GET", "/v1/audit", hdr); rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status %d, want 401", h, rec.Code)
		}
	}
	if rec := serve(ts, "GET", "/v1/audit", map[string]string{"Authorization": "Bearer " + ts.token}); rec.Code != http.StatusOK {
		t.Errorf("the real token: status %d, want 200", rec.Code)
	}
}

func TestTokenFileIsOwnerOnlyOnPOSIX(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes only")
	}
	ts := newTestServer(t)
	fi, err := os.Stat(ts.tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(ts.tokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("token dir mode %v, want 0700", di.Mode().Perm())
	}
}

// ---------------------------------------------------------------------------
// RGT-322: the credential is never accepted from, or revealed in, the URL
// ---------------------------------------------------------------------------

func TestEveryNonPublicRouteRequiresBearer(t *testing.T) {
	ts := newTestServer(t)
	for _, rt := range allRoutes(t, ts.router) {
		if isPublic(rt.path) {
			continue
		}
		rec := serve(ts, rt.method, rt.path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without credentials: status %d, want 401", rt.method, rt.path, rec.Code)
		}
	}
}

func TestValidTokenInQueryStringIsNotAccepted(t *testing.T) {
	ts := newTestServer(t)
	names := []string{"token", "access_token", "api_key", "apikey", "bearer", "authorization", "auth", "session", "key", "secret"}
	for _, rt := range allRoutes(t, ts.router) {
		if isPublic(rt.path) {
			continue
		}
		for _, n := range names {
			for _, v := range []string{ts.token, "Bearer " + ts.token} {
				target := rt.path + "?namespace=default&agent=tester&" + n + "=" + strings.ReplaceAll(v, " ", "%20")
				if rec := serve(ts, rt.method, target, nil); rec.Code != http.StatusUnauthorized {
					t.Errorf("%s %s: valid token in ?%s= gave status %d, want 401", rt.method, rt.path, n, rec.Code)
				}
			}
		}
	}
}

func TestPresentedTokenIsNeverLoggedOrEchoed(t *testing.T) {
	ts := newTestServer(t)
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	// Valid token in the header, and the same value smuggled in the URL.
	rec := serve(ts, "GET", "/v1/audit?token="+ts.token, map[string]string{"Authorization": "Bearer " + ts.token})
	// A wrong token must not be reflected back.
	wrong := "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmE"
	bad := serve(ts, "GET", "/v1/audit", map[string]string{"Authorization": "Bearer " + wrong})

	if strings.Contains(buf.String(), ts.token) {
		t.Errorf("server log contains the bearer token: %q", buf.String())
	}
	if strings.Contains(rec.Body.String(), ts.token) || strings.Contains(rec.Header().Get("Location"), ts.token) {
		t.Error("response echoes the bearer token")
	}
	if strings.Contains(bad.Body.String(), wrong) || strings.Contains(buf.String(), wrong) {
		t.Error("a rejected token is reflected in the response or the log")
	}
}

// ---------------------------------------------------------------------------
// RGT-323 / 325 / 331..335 / 347: no cookie is ever set or honoured; no ambient credential
// ---------------------------------------------------------------------------

func TestNoCookieIsEverSet(t *testing.T) {
	ts := newTestServer(t)
	authed := map[string]string{"Authorization": "Bearer " + ts.token}
	for _, rt := range allRoutes(t, ts.router) {
		for _, hdr := range []map[string]string{nil, authed} {
			if rec := serve(ts, rt.method, rt.path, hdr); len(rec.Result().Cookies()) != 0 || rec.Header().Get("Set-Cookie") != "" {
				t.Errorf("%s %s set a cookie: %v", rt.method, rt.path, rec.Header().Values("Set-Cookie"))
			}
		}
	}
}

// A cookie (or any other ambient browser credential) must never authenticate a
// request, which is what makes cross-site request forgery impossible on the
// server itself: state-changing routes need the Authorization header.
func TestCookieIsNotACredentialSoNoCSRF(t *testing.T) {
	ts := newTestServer(t)
	hdr := map[string]string{
		"Cookie":       "session=" + ts.token + "; token=" + ts.token + "; csrf_token=abc",
		"Origin":       "https://evil.example",
		"Content-Type": "text/plain",
	}
	for _, rt := range allRoutes(t, ts.router) {
		if isPublic(rt.path) {
			continue
		}
		if rec := serve(ts, rt.method, rt.path, hdr); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with only a cookie: status %d, want 401", rt.method, rt.path, rec.Code)
		}
	}
	// Public routes must be read-only.
	for _, rt := range allRoutes(t, ts.router) {
		if isPublic(rt.path) && rt.method != http.MethodGet {
			t.Errorf("public route %s %s is not GET: unauthenticated state changes are a CSRF risk", rt.method, rt.path)
		}
	}
}

// ---------------------------------------------------------------------------
// Source-level guards: the surfaces behind the N/A rows must stay absent
// ---------------------------------------------------------------------------

func goSources(t *testing.T, includeTests bool) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(goRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "asvs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || (!includeTests && strings.HasSuffix(p, "_test.go")) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(p)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking go sources: %v", err)
	}
	if len(out) < 10 {
		t.Fatalf("only %d go sources found; the guard would be vacuous", len(out))
	}
	return out
}

func TestNoCredentialSurfacePackagesImported(t *testing.T) {
	forbidden := []string{
		"net/smtp", "net/http/cookiejar", "golang.org/x/oauth2", "golang.org/x/crypto/bcrypt",
		"golang.org/x/crypto/pbkdf2", "golang.org/x/crypto/scrypt", "webauthn", "gorilla/sessions",
		"gorilla/securecookie", "golang-jwt", "go-jose", "pquerna/otp", "twilio", "go-ldap", "crewjam/saml",
	}
	fset := token.NewFileSet()
	for path := range goSources(t, true) {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(ip, bad) {
					t.Errorf("%s imports %q: an authentication surface appeared; re-verify docs/security/asvs/V2-V3.md", path, ip)
				}
			}
		}
	}
	mod, err := os.ReadFile(filepath.Join(goRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range forbidden {
		if strings.Contains(string(mod), bad) {
			t.Errorf("go.mod requires %q: an authentication surface appeared", bad)
		}
	}
}

func TestNoCookiesFormsOrPasswordFieldsInGoSource(t *testing.T) {
	banned := regexp.MustCompile(`http\.SetCookie|http\.Cookie\{|\.Cookies\(\)|\.Cookie\(|FormValue\(|ParseForm\(|ParseMultipartForm\(|\.PostForm\b|\bgetpass\b`)
	pwField := regexp.MustCompile(`json:"[^"]*(pass(word|wd|phrase|code)|pwd)[^"]*"`)
	for path, src := range goSources(t, false) {
		if m := banned.FindString(src); m != "" {
			t.Errorf("%s uses %q: cookies/forms/prompts appeared; re-verify the V3 N/A rows", path, m)
		}
		if m := pwField.FindString(src); m != "" {
			t.Errorf("%s declares a password-like field %s; re-verify the V2 N/A rows", path, m)
		}
	}
}

// Only non-credential keys may ever be read from the query string.
func TestQueryStringKeysAreNeverCredentials(t *testing.T) {
	getKey := regexp.MustCompile(`\.Query\(\)\.Get\("([^"]+)"\)`)
	anyQuery := regexp.MustCompile(`\.Query\(\)`)
	var keys []string
	for path, src := range goSources(t, false) {
		matched := getKey.FindAllStringSubmatch(src, -1)
		if len(anyQuery.FindAllString(src, -1)) != len(matched) {
			t.Errorf("%s reads r.URL.Query() other than via .Get(\"key\"); use a literal key so this guard can check it", path)
		}
		for _, m := range matched {
			keys = append(keys, m[1])
			if credentialName.MatchString(m[1]) {
				t.Errorf("%s reads credential-looking query parameter %q (ASVS 3.1.1)", path, m[1])
			}
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		t.Fatal("found no query-parameter reads at all; the scan is broken")
	}
	t.Logf("query keys read by the Go line: %v", keys)
}

func TestHeaderIsTheOnlyAuthSource(t *testing.T) {
	// The server middleware, the TUI client and the MCP bridge all use the Authorization header.
	for _, f := range []string{"internal/server/middleware.go", "internal/tui/client.go", "internal/mcp/mcp.go"} {
		b, err := os.ReadFile(filepath.Join(goRoot, filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"Authorization"`) {
			t.Errorf("%s no longer references the Authorization header", f)
		}
	}
}

// ---------------------------------------------------------------------------
// RGT-321: no keys or secrets committed in the Go tree
// ---------------------------------------------------------------------------

func TestNoSecretMaterialInGoTree(t *testing.T) {
	patterns := map[string]*regexp.Regexp{
		"private key block": regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY`),
		"aws access key id": regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		"github token":      regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
		"slack token":       regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
		"openai-style key":  regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}\b`),
		"google api key":    regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	}
	for path, src := range goSources(t, true) {
		for label, re := range patterns {
			if re.MatchString(src) {
				t.Errorf("%s contains what looks like a %s", path, label)
			}
		}
	}
}
