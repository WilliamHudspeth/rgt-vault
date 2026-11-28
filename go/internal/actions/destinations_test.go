package actions

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/policy"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/tlstest"
)

// destEnv runs two TLS servers on loopback: A (listed in the tests) and B
// (the attacker's). Both certificates cover a.test and b.test; a fake
// resolver maps both names to 127.0.0.1, so the port decides which server
// is reached. Connections are counted at the server (ConnState) and at the
// dialer, so "refused before any connection" is checked, not just "no
// request".
type destEnv struct {
	t              *testing.T
	a, b           *httptest.Server
	aPort, bPort   string
	aConns, bConns atomic.Int64
	bAuth          atomic.Int64 // requests at B that carried Authorization
	dials          atomic.Int64
	cfg            Config
	secret         []byte

	mu       sync.Mutex
	audits   []DestinationRefusal
	alerts   []string
	auditErr error
	logs     bytes.Buffer
}

func newDestEnv(t *testing.T) *destEnv {
	t.Helper()
	ca := tlstest.NewCA(t)
	files := ca.Issue(t, "", tlstest.Leaf{Name: "dest", DNSNames: []string{"a.test", "b.test"},
		IPs: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}})
	cert, err := tls.LoadX509KeyPair(files.Cert, files.Key)
	if err != nil {
		t.Fatal(err)
	}
	e := &destEnv{t: t}
	raw := make([]byte, 20)
	_, _ = rand.Read(raw)
	e.secret = []byte("tok_" + hex.EncodeToString(raw))

	start := func(h http.Handler, conns *atomic.Int64) (*httptest.Server, string) {
		s := httptest.NewUnstartedServer(h)
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				conns.Add(1)
			}
		}
		s.StartTLS()
		t.Cleanup(s.Close)
		_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
		return s, port
	}
	e.b, e.bPort = start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			e.bAuth.Add(1)
		}
		_, _ = w.Write([]byte("collected"))
	}), &e.bConns)
	e.a, e.aPort = start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r-off":
			http.Redirect(w, r, "https://b.test:"+e.bPort+"/ok", http.StatusFound)
		case "/r-cross":
			http.Redirect(w, r, "https://a.test:"+e.bPort+"/ok", http.StatusFound)
		case "/r-same":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			_, _ = w.Write([]byte("fine"))
		}
	}), &e.aConns)

	e.cfg = Config{
		AllowPrivateNetwork: true,
		RootCAs:             ca.Pool(),
		Resolver:            &fakeResolver{table: map[string][]string{"a.test": {"127.0.0.1"}, "b.test": {"127.0.0.1"}, "api.openai.com": {"127.0.0.1"}}},
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			e.dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		Logger: slog.New(slog.NewTextHandler(&e.logs, nil)),
	}
	return e
}

// policyYAML fills PORTA/PORTB in src.
func (e *destEnv) policyYAML(src string) string {
	return strings.NewReplacer("PORTA", e.aPort, "PORTB", e.bPort).Replace(src)
}

func (e *destEnv) options(src string, mode DestinationMode) DestinationOptions {
	return DestinationOptions{
		PolicyYAML: e.policyYAML(src),
		Mode:       mode,
		Audit: func(_ context.Context, r DestinationRefusal) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.audits = append(e.audits, r)
			return e.auditErr
		},
		Alert: func(_ context.Context, r DestinationRefusal, suppressed int) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.alerts = append(e.alerts, r.AlertDetail(suppressed))
		},
	}
}

func (e *destEnv) registry(src string, mode DestinationMode, mutate ...func(*Config)) *Registry {
	e.t.Helper()
	p, err := NewDestinationPolicy(e.options(src, mode))
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := e.cfg
	cfg.Destinations = p
	for _, m := range mutate {
		m(&cfg)
	}
	r, err := NewBuiltinRegistry(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

var githubUse = SecretUse{Agent: "coder", Namespace: "github", Name: "GITHUB_TOKEN", Purpose: "ci"}

func (e *destEnv) get(r *Registry, use *SecretUse, rawURL string) (map[string]any, error) {
	ctx := context.Background()
	if use != nil {
		ctx = WithSecretUse(ctx, *use)
	}
	return r.Execute(ctx, "http_get_with_auth", e.secret, map[string]any{"url": rawURL})
}

func (e *destEnv) aURL(path string) string { return "https://a.test:" + e.aPort + path }
func (e *destEnv) bURL(path string) string { return "https://b.test:" + e.bPort + path }

func (e *destEnv) lastAudit() DestinationRefusal {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.audits) == 0 {
		e.t.Fatal("no DESTINATION_REFUSED audit")
	}
	return e.audits[len(e.audits)-1]
}

func (e *destEnv) auditCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.audits)
}

func (e *destEnv) assertBUntouched() {
	e.t.Helper()
	if n := e.bConns.Load(); n != 0 {
		e.t.Fatalf("server B saw %d connection(s); the refusal must come before any connection", n)
	}
	if n := e.bAuth.Load(); n != 0 {
		e.t.Fatalf("server B received the credential %d time(s)", n)
	}
}

func wantRefused(t *testing.T, err error, reason string) {
	t.Helper()
	if !errors.Is(err, ErrDestinationRefused) {
		t.Fatalf("err = %v, want a destination refusal (%s)", err, reason)
	}
	if reason != ReasonNoList && !strings.Contains(err.Error(), "("+reason+")") {
		t.Fatalf("err = %q, want reason %s", err, reason)
	}
}

const allowAllRules = `rules:
  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*"}
`

const githubOnA = allowAllRules + `destinations:
  github/GITHUB_TOKEN: ["a.test:PORTA"]
`

// AC1: the listed host works; the other host is refused before any
// connection, with the exact message, and the credential never leaves.
func TestDestinationListedAndRefused(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(githubOnA, DestinationsEnforce)
	if out, err := e.get(r, &githubUse, e.aURL("/ok")); err != nil || out["body_text"] != "fine" {
		t.Fatalf("listed host: %v %v", out, err)
	}
	_, err := e.get(r, &githubUse, e.bURL("/collect"))
	wantRefused(t, err, ReasonHostNotListed)
	want := "destination b.test:" + e.bPort + " is not allowed for secret github/GITHUB_TOKEN (HOST_NOT_LISTED)"
	if err.Error() != want {
		t.Fatalf("message = %q, want %q", err, want)
	}
	e.assertBUntouched()
	a := e.lastAudit()
	if a.Use != githubUse || a.Action != "http_get_with_auth" || a.Destination != "b.test:"+e.bPort || a.Reason != ReasonHostNotListed || a.Mode != DestinationsEnforce {
		t.Fatalf("audit = %+v", a)
	}
	if e.auditCount() != 1 || len(e.alerts) != 1 {
		t.Fatalf("audits %d alerts %d, want 1 and 1", e.auditCount(), len(e.alerts))
	}
}

// The exact NO_LIST message of the brief.
func TestDestinationNoListMessage(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(allowAllRules+"destinations:\n  other/*: [a.test]\n", DestinationsEnforce)
	_, err := e.get(r, &githubUse, e.aURL("/ok"))
	wantRefused(t, err, ReasonNoList)
	want := `no destination is allowed for secret github/GITHUB_TOKEN: add it under "destinations:" in the policy file`
	if err.Error() != want {
		t.Fatalf("message = %q", err)
	}
	if e.aConns.Load() != 0 || e.lastAudit().Reason != ReasonNoList {
		t.Fatalf("conns %d audit %+v", e.aConns.Load(), e.lastAudit())
	}
}

// Required test 2: unlisted variants, each refused before any connection.
func TestDestinationVariantsRefused(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(githubOnA, DestinationsEnforce)
	for _, c := range []struct{ url, reason string }{
		{"https://127.0.0.1:" + e.bPort + "/", ReasonIPLiteral},
		{"https://[::ffff:127.0.0.1]:" + e.bPort + "/", ReasonIPLiteral},
		{"https://a.test:" + e.bPort + "/", ReasonPortMismatch},
		{"https://A.TEST:" + e.bPort + "/", ReasonPortMismatch},
		{"https://b.test:" + e.bPort + "/", ReasonHostNotListed},
		{"https://x.a.test:" + e.aPort + "/", ReasonHostNotListed},
	} {
		_, err := e.get(r, &githubUse, c.url)
		if strings.Contains(c.url, "::ffff") && err != nil && !errors.Is(err, ErrDestinationRefused) {
			continue // netguard refused it even earlier: also before any connection
		}
		wantRefused(t, err, c.reason)
	}
	e.assertBUntouched()
	if e.dials.Load() != 0 {
		t.Fatalf("%d dial(s) for refused destinations", e.dials.Load())
	}
}

// Required test 3: case and trailing-dot variants of the listed host pass.
func TestDestinationCanonicalVariantsAllowed(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(githubOnA, DestinationsEnforce)
	for _, u := range []string{"https://A.TEST:" + e.aPort + "/ok", "https://a.test.:" + e.aPort + "/ok"} {
		if _, err := e.get(r, &githubUse, u); errors.Is(err, ErrDestinationRefused) {
			t.Fatalf("%s refused: %v", u, err)
		}
	}
	// Port handling on the default port, without a server on 443.
	list := mustList(t, "api.github.com")
	for _, c := range []struct{ url, want string }{
		{"https://API.GITHUB.COM/", ""},
		{"https://api.github.com./", ""},
		{"https://api.github.com.:443/", ""},
		{"https://api.github.com:0443/", ""},
		{"https://api.github.com:8443/", ReasonPortMismatch},
		{"http://api.github.com:443/", ReasonHostNotListed},
	} {
		u, _ := url.Parse(c.url)
		if got := refuseBy(list, targetOf(u)); got != c.want {
			t.Fatalf("%s: %q, want %q", c.url, got, c.want)
		}
	}
}

func mustList(t *testing.T, entries ...string) []Destination {
	t.Helper()
	l, _, err := parseList(entries)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Required test 4: openai_chat checks the final URL (base_url or default).
func TestDestinationOpenAIChat(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(allowAllRules+"destinations:\n  openai/*: [\"a.test:PORTA\"]\n", DestinationsEnforce)
	use := SecretUse{Agent: "coder", Namespace: "openai", Name: "KEY", Purpose: "chat"}
	ctx := WithSecretUse(context.Background(), use)
	msgs := []any{map[string]any{"role": "user", "content": "hi"}}
	_, err := r.Execute(ctx, "openai_chat", e.secret, map[string]any{"model": "m", "messages": msgs, "base_url": "https://b.test:" + e.bPort})
	wantRefused(t, err, ReasonHostNotListed)
	_, err = r.Execute(ctx, "openai_chat", e.secret, map[string]any{"model": "m", "messages": msgs})
	wantRefused(t, err, ReasonHostNotListed)
	if !strings.Contains(err.Error(), "api.openai.com:443") {
		t.Fatalf("default base URL not checked: %v", err)
	}
	e.assertBUntouched()
	if e.dials.Load() != 0 {
		t.Fatalf("%d dial(s)", e.dials.Load())
	}
	// The listed base URL goes through.
	_, err = r.Execute(ctx, "openai_chat", e.secret, map[string]any{"model": "m", "messages": msgs, "base_url": e.aURL("")})
	if errors.Is(err, ErrDestinationRefused) {
		t.Fatalf("listed base_url refused: %v", err)
	}
	// http_post_with_auth is covered by the same check.
	_, err = r.Execute(WithSecretUse(context.Background(), use), "http_post_with_auth", e.secret, map[string]any{"url": e.bURL("/p"), "body": "x"})
	wantRefused(t, err, ReasonHostNotListed)
	e.assertBUntouched()
}

// Required test 5: path, query and fragment never reach the error, the
// audit row, the alert or the log.
func TestDestinationNeverLogsPathOrQuery(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(githubOnA, DestinationsEnforce)
	_, err := e.get(r, &githubUse, e.bURL("/collect?token=leakvalue#frag"))
	wantRefused(t, err, ReasonHostNotListed)
	e.mu.Lock()
	texts := []string{err.Error(), e.audits[0].AuditDetails(), e.alerts[0], e.logs.String()}
	e.mu.Unlock()
	for _, s := range texts {
		for _, bad := range []string{"collect", "token", "leakvalue", "frag", string(e.secret)} {
			if strings.Contains(s, bad) {
				t.Fatalf("%q leaked into %q", bad, s)
			}
		}
	}
}

// Required test 6: redirects with a registry that follows them.
func TestDestinationRedirects(t *testing.T) {
	e := newDestEnv(t)
	follow := func(c *Config) { c.MaxRedirects = 3 }
	// a.test on B's port is listed too: a different origin that IS listed.
	r := e.registry(allowAllRules+"destinations:\n  github/GITHUB_TOKEN: [\"a.test:PORTA\", \"a.test:PORTB\"]\n", DestinationsEnforce, follow)
	if out, err := e.get(r, &githubUse, e.aURL("/r-same")); err != nil || out["body_text"] != "fine" {
		t.Fatalf("same-origin redirect: %v %v", out, err)
	}
	_, err := e.get(r, &githubUse, e.aURL("/r-off"))
	wantRefused(t, err, ReasonRedirectOffList)
	_, err = e.get(r, &githubUse, e.aURL("/r-cross"))
	wantRefused(t, err, ReasonRedirectCrossOrigin)
	e.assertBUntouched()
}

// Required test 7: the server's registry follows no redirects: a 302 from
// A is an error and B is never contacted.
func TestDestinationNoRedirectByDefault(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(githubOnA, DestinationsEnforce)
	_, err := e.get(r, &githubUse, e.aURL("/r-off"))
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("302 not reported: %v", err)
	}
	e.assertBUntouched()
}

// Required test 9: fail closed without identity or without a policy.
func TestDestinationFailClosed(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(githubOnA, DestinationsEnforce)
	_, err := e.get(r, nil, e.aURL("/ok"))
	if !errors.Is(err, ErrDestinationRefused) || err.Error() != errNoIdentity.Error() {
		t.Fatalf("no identity: %v", err)
	}
	reg, err := NewBuiltinRegistry(e.cfg) // no Destinations, not unrestricted
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.get(reg, &githubUse, e.aURL("/ok"))
	if !errors.Is(err, ErrDestinationRefused) || err.Error() != errNoPolicy.Error() {
		t.Fatalf("no policy: %v", err)
	}
	if e.aConns.Load() != 0 || e.dials.Load() != 0 {
		t.Fatalf("connections made: %d %d", e.aConns.Load(), e.dials.Load())
	}
	// An empty policy (no destinations section) refuses everything too.
	r = e.registry(allowAllRules, DestinationsEnforce)
	_, err = e.get(r, &githubUse, e.aURL("/ok"))
	wantRefused(t, err, ReasonNoList)
	// echo sends nothing and is not checked.
	if _, err := r.Execute(context.Background(), "echo", e.secret, nil); err != nil {
		t.Fatal(err)
	}
}

// Required test 12: allowed_hosts on rules only narrows.
func TestDestinationRuleNarrowing(t *testing.T) {
	e := newDestEnv(t)
	twoHosts := "destinations:\n  github/GITHUB_TOKEN: [\"a.test:PORTA\", \"b.test:PORTB\"]\n"
	// Rule list not a subset of the secret list: only the intersection.
	r := e.registry(`rules:
  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*", allowed_hosts: ["b.test:PORTB", "c.test"]}
destinations:
  github/GITHUB_TOKEN: ["a.test:PORTA"]
`, DestinationsEnforce)
	_, err := e.get(r, &githubUse, e.bURL("/"))
	wantRefused(t, err, ReasonHostNotListed) // on the rule list, not on the secret list
	_, err = e.get(r, &githubUse, e.aURL("/ok"))
	wantRefused(t, err, ReasonHostNotListed) // on the secret list, not on the rule list
	// allowed_hosts: [] refuses everything.
	r = e.registry(`rules:
  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*", allowed_hosts: []}
`+twoHosts, DestinationsEnforce)
	_, err = e.get(r, &githubUse, e.aURL("/ok"))
	wantRefused(t, err, ReasonHostNotListed)
	// A rule list without a secret entry grants nothing.
	r = e.registry(`rules:
  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*", allowed_hosts: ["b.test:PORTB"]}
`, DestinationsEnforce)
	_, err = e.get(r, &githubUse, e.bURL("/"))
	wantRefused(t, err, ReasonNoList)
	// Two matching allow rules: narrowing holds in either order.
	narrow := `  - {effect: allow, agent: coder, namespace: github, purpose: "*", action: read, allowed_hosts: ["a.test:PORTA"]}
`
	wide := `  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*"}
`
	for _, rules := range []string{narrow + wide, wide + narrow} {
		r = e.registry("rules:\n"+rules+twoHosts, DestinationsEnforce)
		_, err = e.get(r, &githubUse, e.bURL("/"))
		wantRefused(t, err, ReasonHostNotListed)
		if _, err := e.get(r, &githubUse, e.aURL("/ok")); err != nil {
			t.Fatalf("narrowed host refused: %v", err)
		}
	}
	e.assertBUntouched()
	// A scalar or null allowed_hosts is a load error, not ignored.
	for _, v := range []string{"api.github.com", "null", "~", "[1]"} {
		_, err := NewDestinationPolicy(DestinationOptions{PolicyYAML: "rules:\n  - {effect: allow, allowed_hosts: " + v + "}\n"})
		if !errors.Is(err, policy.ErrInvalid) || !strings.Contains(err.Error(), "allowed_hosts") {
			t.Fatalf("allowed_hosts: %s: %v", v, err)
		}
	}
}

// Required test 13: load-time errors name the key/entry and the reason.
func TestDestinationLoadErrors(t *testing.T) {
	for _, c := range []struct{ yaml, want string }{
		{`github/*: ["*.com"]`, "public suffix"},
		{`github/*: ["*.co.uk"]`, "public suffix"},
		{`github/*: ["*.com.au"]`, "public suffix"},
		{`github/*: ["*.gov.uk"]`, "public suffix"},
		{`github/*: ["*.local"]`, "public suffix"},
		{`github/*: ["*.vercel.app"]`, "shared-hosting"},
		{`github/*: ["*.execute-api.eu-west-1.amazonaws.com"]`, "shared-hosting"},
		{`github/*: ["*.lambda-url.us-east-1.on.aws"]`, "shared-hosting"},
		{`github/*: ["*.10.0.0"]`, "numeric"},
		{`github/*: ["*.1.2.3.4"]`, "IP address"},
		{`github/*: ["127.1"]`, "numeric"},
		{`github/*: ["*"]`, "leftmost"},
		{`github/*: ["a.*.com"]`, "leftmost"},
		{`github/*: ["*foo.com"]`, "leftmost"},
		{`github/*: ["user@host.example"]`, "credentials"},
		{`github/*: ["https://user@host.example"]`, "credentials"},
		{`github/*: ["http://x.example"]`, "only https"},
		{`github/*: ["https://x.example/path"]`, "no path"},
		{`github/*: ["x.example/path"]`, "no path"},
		{`github/*: ["https://x.example?q=1"]`, "no path"},
		{`github/*: ["bücher.example"]`, "non-ASCII"},
		{`github/*: ["a..b"]`, "empty label"},
		{`github/*: [".a.b"]`, "empty label"},
		{`github/*: ["a.example:0"]`, "port"},
		{`github/*: ["a.example:70000"]`, "port"},
		{`github/*: ["a b.example"]`, "whitespace"},
		{`github/*: ["2001:db8::1"]`, "brackets"},
		{`github/*: ["[::ffff:1.2.3.4]"]`, "IPv4-mapped"},
		{`github/*: ["*.1.2.3.4"]`, "IP address"},
		{`github/*: ["a$b.example"]`, "invalid character"},
		{`github/*: [""]`, "empty"},
		{"github/A: [a.example]\n  github/A: [b.example]", "duplicate key"},
		{"<<: {github/A: [a.example]}", "merge"},
		{"github/A: &x [a.example]\n  github/B: *x", "alias"},
		{`github: [a.example]`, `"namespace/name"`},
		{`gi thub/*: [a.example]`, "namespace"},
		{`github/a*b: [a.example]`, "name"},
		{`/x: [a.example]`, "namespace"},
		{`github/A: null`, "list"},
		{`github/A: a.example`, "list"},
		{`github/A: [1]`, "string"},
	} {
		src := allowAllRules + "destinations:\n  " + c.yaml + "\n"
		_, err := NewDestinationPolicy(DestinationOptions{PolicyYAML: src})
		if err == nil || !errors.Is(err, policy.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err = %v, want %q", c.yaml, err, c.want)
		}
	}
	// destinations itself must be a mapping, appear once, and not be merged in.
	for _, src := range []string{
		allowAllRules + "destinations: null\n",
		allowAllRules + "destinations: [a.example]\n",
		allowAllRules + "destinations: {}\ndestinations: {}\n",
		"base: &b {destinations: {github/*: [a.example]}}\n<<: *b\n" + allowAllRules,
		"d: &d {github/*: [a.example]}\ndestinations: *d\n" + allowAllRules,
	} {
		if _, err := NewDestinationPolicy(DestinationOptions{PolicyYAML: src}); !errors.Is(err, policy.ErrInvalid) {
			t.Fatalf("%q: err = %v", src, err)
		}
	}
	// The non-ASCII load error carries its reason code.
	_, err := ParseDestination("bücher.example")
	var de *destError
	if !errors.As(err, &de) || de.Reason != ReasonNonASCIIHost {
		t.Fatalf("non-ASCII: %v", err)
	}
	// Accepted forms.
	for _, ok := range []string{"api.github.com", "API.GitHub.com.", "https://api.github.com", "https://api.github.com/",
		"api.github.com:8443", "*.ci.example.com", "[2001:db8::1]:443", "192.0.2.1", "myco.vercel.app",
		"*.github.io", "xn--bcher-kva.example", "*.example.co.uk"} {
		if _, err := ParseDestination(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}

// Required test 14: a wildcard matches exactly one extra label.
func TestDestinationWildcardDepth(t *testing.T) {
	list := mustList(t, "*.ci.example.com")
	for host, want := range map[string]string{
		"x.ci.example.com":   "",
		"X.CI.example.com.":  "",
		"ci.example.com":     ReasonHostNotListed,
		"a.x.ci.example.com": ReasonHostNotListed,
		"xci.example.com":    ReasonHostNotListed,
	} {
		u, _ := url.Parse("https://" + host + "/")
		if got := refuseBy(list, targetOf(u)); got != want {
			t.Fatalf("%s: %q, want %q", host, got, want)
		}
	}
	// IP literals only by exact canonical match; wildcards never match IPs.
	ips := mustList(t, "[2001:db8:0:0::1]", "192.0.2.1")
	for raw, want := range map[string]string{
		"https://[2001:db8::1]/":     "",
		"https://192.0.2.1/":         "",
		"https://192.0.2.2/":         ReasonIPLiteral,
		"https://[::ffff:192.0.2.1]": ReasonIPLiteral,
	} {
		u, _ := url.Parse(raw)
		if got := refuseBy(ips, targetOf(u)); got != want {
			t.Fatalf("%s: %q, want %q", raw, got, want)
		}
	}
}

// Required test 15: warn mode relaxes only secrets with no entry.
func TestDestinationWarnMode(t *testing.T) {
	e := newDestEnv(t)
	r := e.registry(allowAllRules+"destinations:\n  github/GITHUB_TOKEN: [\"a.test:PORTA\"]\n", DestinationsWarn)
	// No entry: sent, audited with mode=warn, before the send.
	other := SecretUse{Agent: "coder", Namespace: "misc", Name: "OTHER", Purpose: "x"}
	if _, err := e.get(r, &other, e.aURL("/ok")); err != nil {
		t.Fatalf("warn mode refused a secret without an entry: %v", err)
	}
	if a := e.lastAudit(); a.Reason != ReasonNoList || a.Mode != DestinationsWarn || !strings.Contains(a.AuditDetails(), "mode=warn") {
		t.Fatalf("audit = %+v", a)
	}
	// A secret WITH an entry is still enforced.
	_, err := e.get(r, &githubUse, e.bURL("/"))
	wantRefused(t, err, ReasonHostNotListed)
	e.assertBUntouched()
	// A failing audit write means no send.
	before := e.aConns.Load()
	e.mu.Lock()
	e.auditErr = errors.New("disk full")
	e.mu.Unlock()
	_, err = e.get(r, &other, e.aURL("/ok"))
	if err == nil || !strings.Contains(err.Error(), "not sent") {
		t.Fatalf("audit failure: %v", err)
	}
	if e.aConns.Load() != before {
		t.Fatal("sent although the audit row failed")
	}
}

// Required test 16: start-up warnings name namespaces only.
func TestDestinationStartupWarnings(t *testing.T) {
	p, err := NewDestinationPolicy(DestinationOptions{Mode: DestinationsWarn, PolicyYAML: allowAllRules + `destinations:
  github/*: [api.github.com]
  github/GITHUB_TOKN: [api.github.com]
  pages/*: ["*.github.io"]
`})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(p.StartupWarnings([]SecretRef{
		{"github", "GITHUB_TOKEN"}, {"openai", "OPENAI_KEY"}, {"openai", "SECOND_KEY"},
	}), "\n")
	for _, want := range []string{"WARN mode", `namespace "openai" has 2 secret(s) with no destinations entry`,
		`namespace "github" has 1 destinations entry naming no stored secret`, "github.io"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	for _, secretName := range []string{"GITHUB_TOKN", "OPENAI_KEY", "SECOND_KEY", "GITHUB_TOKEN"} {
		if strings.Contains(got, secretName) {
			t.Fatalf("warning names secret %q:\n%s", secretName, got)
		}
	}
	// No section, and a bare-list policy.
	p, _ = NewDestinationPolicy(DestinationOptions{PolicyYAML: allowAllRules})
	if w := strings.Join(p.StartupWarnings(nil), "\n"); !strings.Contains(w, `no "destinations:" section`) {
		t.Fatal(w)
	}
	p, err = NewDestinationPolicy(DestinationOptions{PolicyYAML: "- {effect: allow}\n"})
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(p.StartupWarnings(nil), "\n"); !strings.Contains(w, `convert it to a mapping with "rules:" and "destinations:"`) {
		t.Fatal(w)
	}
}

// Required test 17: alerts are de-duplicated per key per window; the next
// alert carries the suppressed count. Audit rows are not.
func TestDestinationAlertDedup(t *testing.T) {
	e := newDestEnv(t)
	now := time.Unix(1_800_000_000, 0)
	opts := e.options(githubOnA, DestinationsEnforce)
	opts.Now = func() time.Time { return now }
	p, err := NewDestinationPolicy(opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.Destinations = p
	r, _ := NewBuiltinRegistry(cfg)
	for i := 0; i < 50; i++ {
		_, _ = e.get(r, &githubUse, e.bURL("/"))
	}
	if e.auditCount() != 50 || len(e.alerts) != 1 {
		t.Fatalf("audits %d alerts %d, want 50 and 1", e.auditCount(), len(e.alerts))
	}
	// Another key is not suppressed by the first.
	_, _ = e.get(r, &githubUse, "https://127.0.0.1:"+e.bPort+"/")
	if len(e.alerts) != 2 {
		t.Fatalf("alerts %d, want 2", len(e.alerts))
	}
	now = now.Add(time.Minute)
	_, _ = e.get(r, &githubUse, e.bURL("/"))
	if len(e.alerts) != 3 || !strings.HasSuffix(e.alerts[2], "suppressed=49") {
		t.Fatalf("alerts = %q", e.alerts)
	}
	e.assertBUntouched()
}

func TestAlertLimiterBounded(t *testing.T) {
	now := time.Unix(0, 0)
	l := newAlertLimiter(0, func() time.Time { return now })
	for i := 0; i < alertMaxKeys+10; i++ {
		l.admit(fmt.Sprint(i))
	}
	if len(l.m) > alertMaxKeys+1 {
		t.Fatalf("limiter grew to %d keys", len(l.m))
	}
	now = now.Add(2 * time.Minute)
	if send, _ := l.admit("fresh"); !send {
		t.Fatal("expired keys not pruned")
	}
}

// The dial backstop: a context decision is enforced at DialContext even
// when the URL check was bypassed (parser-difference defence).
func TestDestinationDialBackstop(t *testing.T) {
	e := newDestEnv(t)
	p, err := NewDestinationPolicy(e.options(githubOnA, DestinationsEnforce))
	if err != nil {
		t.Fatal(err)
	}
	eff, _ := p.decide(githubUse)
	c := &destCheck{p: p, eff: eff, use: githubUse, action: "http_get_with_auth"}
	port := 0
	_, _ = fmt.Sscan(e.bPort, &port)
	if err := c.CheckDial(context.Background(), "b.test", port); !errors.Is(err, ErrDestinationRefused) {
		t.Fatalf("CheckDial(b) = %v", err)
	}
	_, _ = fmt.Sscan(e.aPort, &port)
	if err := c.CheckDial(context.Background(), "a.test", port); err != nil {
		t.Fatalf("CheckDial(a) = %v", err)
	}
}

func TestDestinationModeParse(t *testing.T) {
	for in, want := range map[string]DestinationMode{"": DestinationsEnforce, "enforce": DestinationsEnforce, "WARN": DestinationsWarn} {
		if got, err := ParseDestinationMode(in); err != nil || got != want {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseDestinationMode("off"); err == nil {
		t.Fatal("off accepted")
	}
	if DestinationsWarn.String() != "warn" || DestinationsEnforce.String() != "enforce" {
		t.Fatal("String")
	}
	d, _ := ParseDestination("*.Example.com:8443")
	if d.String() != "*.example.com:8443" {
		t.Fatal(d.String())
	}
}
