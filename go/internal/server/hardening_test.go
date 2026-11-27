package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server/handlers"
)

// hardenedServer builds a router over a real (test) vault with the supplied
// middleware tweaks.
func hardenedServer(t *testing.T, tweak func(*Middleware)) (http.Handler, string) {
	t.Helper()
	e := newEnv(t, envOpts{})
	ts := auth.NewTokenStore(filepath.Join(t.TempDir(), "server.token"))
	token, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Write(token); err != nil {
		t.Fatal(err)
	}
	mw := NewMiddleware(ts)
	if tweak != nil {
		tweak(mw)
	}
	h := &handlers.Handlers{Vault: e.stack.Vault, Actions: e.stack.Actions, Capabilities: e.stack.Capabilities}
	return NewRouter(h, mw), token
}

func do(h http.Handler, method, path, token string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustJSONError(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json (body %q)", ct, rec.Body.String())
	}
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("error body is not valid JSON: %v (%q)", err, rec.Body.String())
	}
	return m
}

// --- CORS -----------------------------------------------------------------

func TestCORSDeniedByDefault(t *testing.T) {
	h, token := hardenedServer(t, nil)
	for _, origin := range []string{"https://evil.example", "http://localhost:3000", "null"} {
		rec := do(h, "GET", "/healthz", "", map[string]string{"Origin": origin}, "")
		if rec.Code != 200 {
			t.Fatalf("healthz status %d", rec.Code)
		}
		for k := range rec.Header() {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Errorf("origin %q: unexpected CORS header %s (deny-by-default)", origin, k)
			}
		}
		rec = do(h, "GET", "/v1/actions", token, map[string]string{"Origin": origin}, "")
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q reflected as %q", origin, got)
		}
	}
}

func TestCORSAllowListExactMatchOnly(t *testing.T) {
	h, _ := hardenedServer(t, func(mw *Middleware) { mw.AllowedOrigins = []string{"https://app.example"} })

	rec := do(h, "GET", "/healthz", "", map[string]string{"Origin": "https://app.example"}, "")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("allowed origin: ACAO = %q", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
		t.Errorf("Vary: Origin missing, got %q", rec.Header().Get("Vary"))
	}
	for _, bad := range []string{"https://app.example.evil.com", "http://app.example", "https://APP.example", "https://app.example/", "*"} {
		rec = do(h, "GET", "/healthz", "", map[string]string{"Origin": bad}, "")
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q must not match, got ACAO %q", bad, got)
		}
	}
}

func TestParseAllowedOriginsRejectsWildcard(t *testing.T) {
	ok, rejected := ParseAllowedOrigins(" https://a.example , *, NULL,,https://*.b.example,https://c.example")
	if strings.Join(ok, "|") != "https://a.example|https://c.example" {
		t.Errorf("origins = %v", ok)
	}
	if len(rejected) != 3 {
		t.Errorf("rejected = %v, want 3 entries", rejected)
	}
	h, _ := hardenedServer(t, func(mw *Middleware) { mw.AllowedOrigins, _ = ParseAllowedOrigins("*") })
	rec := do(h, "GET", "/healthz", "", map[string]string{"Origin": "https://anything.example"}, "")
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("wildcard CORS_ALLOWED_ORIGINS must not enable CORS")
	}
}

func TestPreflightOnlyForAllowedOrigins(t *testing.T) {
	h, token := hardenedServer(t, func(mw *Middleware) { mw.AllowedOrigins = []string{"https://app.example"} })
	pre := func(origin string) map[string]string {
		return map[string]string{
			"Origin":                         origin,
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "authorization",
		}
	}

	// Allowed origin: answered 204 without credentials.
	rec := do(h, "OPTIONS", "/v1/secrets", "", pre("https://app.example"), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("ACAO = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if m := rec.Header().Get("Access-Control-Allow-Methods"); strings.Contains(m, "PUT") || strings.Contains(m, "PATCH") {
		t.Errorf("Allow-Methods advertises forbidden verbs: %q", m)
	}

	// Disallowed origin: NOT answered before auth -> 401, no CORS headers.
	rec = do(h, "OPTIONS", "/v1/secrets", "", pre("https://evil.example"), "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("disallowed preflight (no token) status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Error("disallowed preflight received CORS headers")
	}

	// No Origin at all, plain OPTIONS: 401 without token...
	rec = do(h, "OPTIONS", "/v1/secrets", "", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bare OPTIONS (no token) status = %d, want 401", rec.Code)
	}
	// ...and never a 204 preflight answer, even with a valid token.
	rec = do(h, "OPTIONS", "/v1/secrets", token, pre("https://evil.example"), "")
	if rec.Code == http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("authed OPTIONS from disallowed origin got preflight answer: %d %v", rec.Code, rec.Header())
	}

	// Allowed origin asking for a verb we do not serve.
	hdr := pre("https://app.example")
	hdr["Access-Control-Request-Method"] = "PUT"
	rec = do(h, "OPTIONS", "/v1/secrets", "", hdr, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("preflight for PUT status = %d, want 405", rec.Code)
	}
}

func TestOptionsNoLongerBypassesAuth(t *testing.T) {
	// No CORS configured at all: OPTIONS must authenticate like everything else.
	h, _ := hardenedServer(t, nil)
	rec := do(h, "OPTIONS", "/v1/secrets", "", map[string]string{
		"Origin": "https://evil.example", "Access-Control-Request-Method": "GET",
	}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- verbs ----------------------------------------------------------------

func TestUnknownVerbsAndTraceReturn405(t *testing.T) {
	h, token := hardenedServer(t, nil)
	for _, m := range []string{"TRACE", "PUT", "PATCH", "CONNECT", "HEAD", "PROPFIND", "FOO"} {
		for _, tok := range []string{"", token} {
			rec := do(h, m, "/v1/secrets", tok, nil, "")
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s token=%v: status = %d, want 405", m, tok != "", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
				t.Errorf("%s: Allow header = %q", m, allow)
			}
			mustJSONError(t, rec)
		}
	}
	// A real route with a verb chi does not register is 405 too (not 404).
	rec := do(h, "GET", "/v1/rotate", token, nil, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/rotate status = %d, want 405", rec.Code)
	}
	mustJSONError(t, rec)
	// Unknown path (authenticated) is a JSON 404.
	rec = do(h, "GET", "/nope", token, nil, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("/nope status = %d", rec.Code)
	}
	mustJSONError(t, rec)
}

// --- JSON error bodies ----------------------------------------------------

func TestAuthErrorBodiesAreValidJSONAndDoNotEchoInput(t *testing.T) {
	h, _ := hardenedServer(t, nil)
	hostile := `"},"x":"<script>alert(1)</script>`
	for _, hdr := range []string{"", "Bearer ", "Bearer " + hostile, hostile} {
		headers := map[string]string{}
		if hdr != "" {
			headers["Authorization"] = hdr
		}
		rec := do(h, "GET", "/v1/actions", "", headers, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("hdr %q: status %d", hdr, rec.Code)
		}
		m := mustJSONError(t, rec)
		if m["error"] != "ServerAuthError" || m["detail"] == "" {
			t.Errorf("hdr %q: body %v", hdr, m)
		}
		if strings.Contains(rec.Body.String(), "script") {
			t.Errorf("auth error echoes the request: %q", rec.Body.String())
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Error("401 without WWW-Authenticate")
		}
	}
}

func TestAuthErrorDoesNotLeakTokenPath(t *testing.T) {
	dir := t.TempDir()
	ts := auth.NewTokenStore(filepath.Join(dir, "gone", "secret-location.token")) // never created
	mw := NewMiddleware(ts)
	e := newEnv(t, envOpts{})
	h := NewRouter(&handlers.Handlers{Vault: e.stack.Vault}, mw)
	var logbuf bytes.Buffer
	log.SetOutput(&logbuf)
	defer log.SetOutput(io.Discard)
	rec := do(h, "GET", "/v1/actions", "", map[string]string{"Authorization": "Bearer abc"}, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	mustJSONError(t, rec)
	if strings.Contains(rec.Body.String(), "secret-location") {
		t.Errorf("response leaks token path: %q", rec.Body.String())
	}
}

func TestWriteJSONErrorEscapes(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSONError(rec, 400, "E", `a"b\n</x>`+"\n")
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["detail"] != `a"b\n</x>`+"\n" {
		t.Errorf("round trip mismatch: %q", m["detail"])
	}
}

// --- body handling --------------------------------------------------------

func TestUnknownFieldsRejected(t *testing.T) {
	h, token := hardenedServer(t, nil)
	cases := map[string]string{
		"/v1/secrets":         `{"name":"a","value":"b","is_admin":true}`,
		"/v1/rotate":          `{"target":"dek","extra":1}`,
		"/v1/policy/simulate": `{"agent":"a","namespace":"n","bogus":1}`,
	}
	for path, body := range cases {
		rec := do(h, "POST", path, token, map[string]string{"Content-Type": "application/json"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, rec.Code)
		}
		m := mustJSONError(t, rec)
		if strings.Contains(m["detail"], "is_admin") {
			t.Errorf("%s: error echoes field name: %v", path, m)
		}
	}
	rec := do(h, "POST", "/v1/secrets/default/x/use", token, nil, `{"action":"echo","agent":"a","zzz":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("use: status = %d", rec.Code)
	}
	// Known fields still work, and trailing garbage is refused.
	rec = do(h, "POST", "/v1/secrets", token, nil, `{"name":"a","value":"b"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("valid body status = %d (%s)", rec.Code, rec.Body.String())
	}
	rec = do(h, "POST", "/v1/secrets", token, nil, `{"name":"a","value":"b"} {"name":"c"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("trailing value status = %d, want 400", rec.Code)
	}
}

func TestOversizedBodyReturns413(t *testing.T) {
	h, token := hardenedServer(t, func(mw *Middleware) { mw.MaxBodyBytes = 256 })
	big := `{"name":"a","value":"` + strings.Repeat("x", 1024) + `"}`

	// Declared Content-Length over the limit.
	rec := do(h, "POST", "/v1/secrets", token, nil, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared-length status = %d, want 413", rec.Code)
	}
	mustJSONError(t, rec)

	// Undeclared length (chunked): the reader cuts it off mid-decode.
	req := httptest.NewRequest("POST", "/v1/secrets", io.NopCloser(strings.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked status = %d, want 413 (%s)", rec.Code, rec.Body.String())
	}
	mustJSONError(t, rec)

	// A body understating its length is still capped.
	req = httptest.NewRequest("POST", "/v1/secrets", io.NopCloser(strings.NewReader(big)))
	req.ContentLength = 10
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("understated-length status = %d, want 413", rec.Code)
	}

	// Under the limit is fine.
	rec = do(h, "POST", "/v1/secrets", token, nil, `{"name":"a","value":"b"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("small body status = %d", rec.Code)
	}
}

func TestDefaultBodyLimitIsOneMiB(t *testing.T) {
	h, token := hardenedServer(t, nil)
	rec := do(h, "POST", "/v1/secrets", token, nil, `{"name":"a","value":"`+strings.Repeat("x", int(DefaultMaxBodyBytes))+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

// --- recover --------------------------------------------------------------

func TestRecoverMiddlewareGenericMessageWithIncidentID(t *testing.T) {
	var logbuf bytes.Buffer
	log.SetOutput(&logbuf)
	defer log.SetOutput(io.Discard)

	mw := &Middleware{}
	h := mw.RecoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("db password hunter2 exploded")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	m := mustJSONError(t, rec)
	if m["detail"] != "internal server error" || m["error"] != "InternalError" {
		t.Errorf("body = %v", m)
	}
	id := m["incident_id"]
	if len(id) != 16 {
		t.Errorf("incident_id = %q", id)
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "goroutine") {
		t.Errorf("response leaks panic detail: %q", rec.Body.String())
	}
	if !strings.Contains(logbuf.String(), "incident="+id) {
		t.Errorf("incident id not in server log: %q", logbuf.String())
	}
	if strings.Contains(logbuf.String(), "hunter2") {
		t.Error("panic value must not be logged")
	}

	// Two panics get distinct ids.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "/boom", nil))
	if mustJSONError(t, rec2)["incident_id"] == id {
		t.Error("incident ids repeat")
	}
}

func TestRecoverRepanicsOnAbortHandler(t *testing.T) {
	mw := &Middleware{}
	h := mw.RecoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("recovered %v, want ErrAbortHandler re-panic", r)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestRouterRecoversHandlerPanic(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := auth.NewTokenStore(filepath.Join(t.TempDir(), "t"))
	_ = ts.Write("tok")
	// A nil Vault makes /healthz panic (nil deref) -> proves the router wires recover.
	h := NewRouter(&handlers.Handlers{}, NewMiddleware(ts))
	rec := do(h, "GET", "/healthz", "", nil, "")
	if rec.Code != 500 || mustJSONError(t, rec)["incident_id"] == "" {
		t.Errorf("router did not recover: %d %s", rec.Code, rec.Body.String())
	}
}

// --- list never returns value --------------------------------------------

func TestListSecretsNeverReturnsValue(t *testing.T) {
	h, token := hardenedServer(t, nil)
	const sentinel = "sk-SENTINEL-do-not-leak-123"
	rec := do(h, "POST", "/v1/secrets", token, nil, `{"name":"k","value":"`+sentinel+`","namespace":"ns","agent":"a","purpose":"p"}`)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}

	for _, path := range []string{"/v1/secrets?namespace=ns", "/v1/secrets/ns/k"} {
		rec = do(h, "GET", path, token, nil, "")
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), sentinel) || strings.Contains(rec.Body.String(), `"value"`) {
			t.Errorf("%s leaks a value: %s", path, rec.Body.String())
		}
	}
	var lr struct {
		Secrets []map[string]interface{} `json:"secrets"`
	}
	rec = do(h, "GET", "/v1/secrets?namespace=ns", token, nil, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)
	if len(lr.Secrets) != 1 || lr.Secrets[0]["name"] != "k" {
		t.Errorf("list lost its metadata: %s", rec.Body.String())
	}
	// An unfiltered list of a different namespace is still empty and value-free.
	rec = do(h, "GET", "/v1/secrets", token, nil, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "value") {
		t.Errorf("default list: %d %s", rec.Code, rec.Body.String())
	}
}

// TODO(D5/H1): remove this test with the transitional plaintext-by-name path.
func TestTransitionalNameLookupKeepsCLIWorking(t *testing.T) {
	h, token := hardenedServer(t, nil)
	do(h, "POST", "/v1/secrets", token, nil, `{"name":"k","value":"v1","namespace":"ns"}`)
	do(h, "POST", "/v1/secrets", token, nil, `{"name":"other","value":"v2","namespace":"ns"}`)

	// Exact shape the CLI (runGet) and MCP (lease_secret) parse.
	rec := do(h, "GET", "/v1/secrets?namespace=ns&name=k", token, nil, "")
	var resp struct {
		Secrets []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Secrets) != 1 || resp.Secrets[0].Name != "k" || resp.Secrets[0].Value != "v1" {
		t.Errorf("name lookup = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "v2") {
		t.Error("name lookup returned a different secret")
	}
	// Missing name: empty list, no value, no error.
	rec = do(h, "GET", "/v1/secrets?namespace=ns&name=missing", token, nil, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "value") {
		t.Errorf("missing lookup = %d %s", rec.Code, rec.Body.String())
	}
	// The read was audited.
	rec = do(h, "GET", "/v1/audit?limit=1000", token, nil, "")
	if !strings.Contains(rec.Body.String(), "SECRET_READ") {
		t.Errorf("plaintext read not audited: %s", rec.Body.String())
	}
}

// DELETE was a Go-only route of the stub store; it is gone (D5).
func TestDeleteRouteRemoved(t *testing.T) {
	h, token := hardenedServer(t, nil)
	do(h, "POST", "/v1/secrets", token, nil, `{"name":"k","value":"v"}`)
	rec := do(h, "DELETE", "/v1/secrets/default/k", token, nil, "")
	if rec.Code != http.StatusMethodNotAllowed || strings.Contains(rec.Header().Get("Allow"), "DELETE") {
		t.Errorf("DELETE: %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
}

// Python StrictURLNormalizationMiddleware: ambiguous paths are 400 before auth.
func TestAmbiguousPathsRejected(t *testing.T) {
	h, token := hardenedServer(t, nil)
	for _, p := range []string{"/v1/secrets/a/../b", "/v1//secrets", "/v1/secrets/a%2F..%2Fb/x", "/v1/secrets/a%5Cb/x", "/v1/secrets/a%00b/x", "/v1/requests/..%2F..%2Fsecrets"} {
		for _, tok := range []string{"", token} {
			req := httptest.NewRequest("GET", "http://x"+p, nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || mustJSONError(t, rec)["detail"] != "Invalid URI path" {
				t.Errorf("%s: %d %s", p, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestRecoverAfterHeadersSentAbortsInsteadOfCorrupting(t *testing.T) {
	log.SetOutput(io.Discard)
	mw := &Middleware{}
	h := mw.LoggingMiddleware(mw.RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("partial"))
		panic("late")
	})))
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("recovered %v, want ErrAbortHandler", r)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestPanicIsLoggedWithStatus500(t *testing.T) {
	var logbuf bytes.Buffer
	log.SetOutput(&logbuf)
	defer log.SetOutput(io.Discard)
	mw := &Middleware{}
	h := mw.LoggingMiddleware(mw.RecoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("x") })))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/boom", nil))
	if !strings.Contains(logbuf.String(), "HTTP GET /boom -> 500") {
		t.Errorf("request not logged as 500: %q", logbuf.String())
	}
}

func TestNoVaryHeaderWhenCORSDisabledAndAllowOn405(t *testing.T) {
	h, _ := hardenedServer(t, nil)
	rec := do(h, "GET", "/healthz", "", nil, "")
	if rec.Header().Get("Vary") != "" {
		t.Errorf("Vary = %q with CORS disabled", rec.Header().Get("Vary"))
	}
	h, _ = hardenedServer(t, func(mw *Middleware) { mw.AllowedOrigins = []string{"https://app.example"} })
	rec = do(h, "OPTIONS", "/v1/secrets", "", map[string]string{
		"Origin": "https://app.example", "Access-Control-Request-Method": "PUT"}, "")
	if rec.Code != 405 || rec.Header().Get("Allow") == "" {
		t.Errorf("preflight PUT: %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
	// A disallowed verb from an allowed origin still carries ACAO so the browser can read the 405.
	rec = do(h, "PUT", "/v1/secrets", "", map[string]string{"Origin": "https://app.example"}, "")
	if rec.Code != 405 || rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("PUT from allowed origin: %d ACAO=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}
