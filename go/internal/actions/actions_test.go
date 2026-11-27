package actions

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "sk-TEST-SECRET-1234567890"

// tlsServer starts an HTTPS test server and returns a Config that trusts it
// and may reach loopback.
func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, Config) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, Config{AllowPrivateNetwork: true, RootCAs: pool}
}

func registry(t *testing.T, cfg Config) *Registry {
	t.Helper()
	r, err := NewBuiltinRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func run(t *testing.T, r *Registry, action string, params map[string]any) (map[string]any, error) {
	t.Helper()
	return r.Execute(context.Background(), action, []byte(testSecret), params)
}

func TestEcho(t *testing.T) {
	r := registry(t, Config{})
	out, err := run(t, r, "echo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true || out["leaked_secret"] != false || out["secret_len"] != len(testSecret) || out["message"] != "lease ok; secret NOT returned" {
		t.Fatalf("echo default: %v", out)
	}
	out, _ = run(t, r, "echo", map[string]any{"message": "hi"})
	if out["message"] != "hi" {
		t.Fatalf("echo message: %v", out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), testSecret) {
		t.Fatal("echo leaked the secret")
	}
}

func TestRegistry(t *testing.T) {
	r := registry(t, Config{})
	var names []string
	for _, s := range r.List() {
		names = append(names, s.Name)
	}
	if got := strings.Join(names, ","); got != "openai_chat,http_get_with_auth,http_post_with_auth,echo" {
		t.Fatalf("registration order: %s", got)
	}
	if err := RegisterBuiltins(r, Config{}); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if err := r.Register(Spec{}); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := r.Register(Spec{Name: "x"}); err == nil {
		t.Fatal("nil Fn accepted")
	}
	_, err := run(t, r, "nope", nil)
	if !errors.Is(err, ErrActionNotFound) || errors.Is(err, ErrActionExecution) {
		t.Fatalf("unknown action: %v", err)
	}
	if !strings.Contains(err.Error(), "Unknown action 'nope'. Registered: ['echo', 'http_get_with_auth', 'http_post_with_auth', 'openai_chat']") {
		t.Fatalf("message: %v", err)
	}
	_, err = run(t, r, "echo", map[string]any{"message": "x", "zzz": 1, "allow_private_network": true})
	if !errors.Is(err, ErrActionExecution) || !strings.Contains(err.Error(), "unknown param(s): ['allow_private_network', 'zzz']. Allowed: ['message']") {
		t.Fatalf("unknown params: %v", err)
	}
	if _, err := r.Get("echo"); err != nil {
		t.Fatal(err)
	}
}

func TestExecute_MasksUnexpectedErrorsAndPanics(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	r := NewRegistry(log)
	_ = r.Register(Spec{Name: "leaky", ParamsSchema: nil, Fn: func(_ context.Context, secret []byte, _ map[string]any) (map[string]any, error) {
		return nil, fmt.Errorf("upstream said: Authorization: Bearer %s", secret)
	}})
	_ = r.Register(Spec{Name: "boom", Fn: func(_ context.Context, secret []byte, _ map[string]any) (map[string]any, error) {
		panic("kaboom " + string(secret))
	}})
	_ = r.Register(Spec{Name: "typed", Fn: func(context.Context, []byte, map[string]any) (map[string]any, error) {
		return nil, execErr("typed failure")
	}})
	for _, name := range []string{"leaky", "boom"} {
		_, err := run(t, r, name, nil)
		if !errors.Is(err, ErrActionExecution) || err.Error() != fmt.Sprintf("Action '%s' failed; see server logs for details.", name) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := run(t, r, "typed", nil); err == nil || err.Error() != "typed failure" {
		t.Fatalf("typed errors pass through: %v", err)
	}
	if strings.Contains(buf.String(), testSecret) || strings.Contains(buf.String(), "kaboom") || strings.Contains(buf.String(), "Bearer") {
		t.Fatalf("log leaked: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "leaky") || !strings.Contains(buf.String(), "boom") {
		t.Fatalf("failures should be logged by action name: %s", buf.String())
	}
}

func TestHTTPGet_EndToEnd(t *testing.T) {
	var gotAuth, gotX, gotHost, gotUA, gotMethod, gotPath string
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotX, gotHost, gotUA = r.Header.Get("Authorization"), r.Header.Get("X-Trace"), r.Host, r.Header.Get("User-Agent")
		gotMethod, gotPath = r.Method, r.URL.RequestURI()
		w.Header().Set("Content-Type", "Application/JSON; charset=utf-8")
		w.Header().Set("X-Reply", "yes")
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	r := registry(t, cfg)
	out, err := run(t, r, "http_get_with_auth", map[string]any{
		"url":     srv.URL + "/v1/models?limit=2",
		"headers": map[string]any{"X-Trace": "t-1", "Host": "evil.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+testSecret || gotX != "t-1" || gotMethod != "GET" || gotPath != "/v1/models?limit=2" {
		t.Fatalf("request: auth=%q x=%q method=%s path=%s", gotAuth, gotX, gotMethod, gotPath)
	}
	if gotHost != strings.TrimPrefix(srv.URL, "https://") {
		t.Fatalf("Host header was pinned by the caller: %q", gotHost)
	}
	if gotUA != "rgt-vault" {
		t.Fatalf("user agent %q", gotUA)
	}
	if out["status"] != 200 || out["body_text"] != `{"ok":true}` || out["content_type"] != "application/json" || out["truncated"] != false {
		t.Fatalf("result: %v", out)
	}
	if h := out["headers"].(map[string]any); h["X-Reply"] != "yes" {
		t.Fatalf("headers: %v", h)
	}
	if _, err := json.Marshal(out); err != nil {
		t.Fatalf("result must be JSON-serialisable: %v", err)
	}
}

func TestHTTPPost_EndToEnd(t *testing.T) {
	type seen struct{ ct, body, auth, method string }
	var s seen
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s = seen{r.Header.Get("Content-Type"), string(b), r.Header.Get("Authorization"), r.Method}
		w.WriteHeader(http.StatusCreated)
	}))
	r := registry(t, cfg)
	cases := []struct {
		name   string
		params map[string]any
		ct     string
		body   string
	}{
		{"json object", map[string]any{"body": map[string]any{"a": 1}}, "application/json", `{"a":1}`},
		{"json list", map[string]any{"body": []any{1, "x"}}, "application/json", `[1,"x"]`},
		{"string", map[string]any{"body": "raw text"}, "application/json", "raw text"},
		{"no body", map[string]any{}, "", ""},
		{"empty string", map[string]any{"body": ""}, "", ""},
		{"caller content-type wins", map[string]any{"body": "a=1", "headers": map[string]any{"content-type": "text/plain"}}, "text/plain", "a=1"},
	}
	for _, c := range cases {
		s = seen{}
		c.params["url"] = srv.URL + "/submit"
		out, err := run(t, r, "http_post_with_auth", c.params)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if out["status"] != 201 {
			t.Fatalf("%s: %v", c.name, out)
		}
		if s.method != "POST" || s.auth != "Bearer "+testSecret || s.ct != c.ct || s.body != c.body {
			t.Fatalf("%s: server saw %+v", c.name, s)
		}
	}
}

func TestOpenAIChat_EndToEnd(t *testing.T) {
	var path, ct string
	var body map[string]any
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ct = r.URL.Path, r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = fmt.Fprint(w, `{"choices":[]}`)
	}))
	r := registry(t, cfg)
	out, err := run(t, r, "openai_chat", map[string]any{
		"base_url":    srv.URL + "/proxy/",
		"model":       "gpt-x",
		"messages":    []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens":  json.Number("128"),
		"temperature": 0.25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/proxy/v1/chat/completions" || ct != "application/json" || out["status"] != 200 {
		t.Fatalf("path=%q ct=%q out=%v", path, ct, out)
	}
	if body["model"] != "gpt-x" || body["max_tokens"] != float64(128) || body["temperature"] != 0.25 {
		t.Fatalf("body: %v", body)
	}
}

func TestOpenAIChat_Validation(t *testing.T) {
	r := registry(t, Config{})
	msgs := []any{map[string]any{"role": "user", "content": "x"}}
	bad := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"model missing", map[string]any{"messages": msgs}, "'model' is required"},
		{"messages missing", map[string]any{"model": "m"}, "'messages' is required and must be a list"},
		{"messages empty", map[string]any{"model": "m", "messages": []any{}}, "'messages' must not be empty"},
		{"message not object", map[string]any{"model": "m", "messages": []any{"x"}}, "'messages[0]' must be a JSON object"},
		{"role empty", map[string]any{"model": "m", "messages": []any{map[string]any{"role": "", "content": "x"}}}, "'messages[0].role'"},
		{"content missing", map[string]any{"model": "m", "messages": []any{map[string]any{"role": "u"}}}, "'messages[0].content'"},
		{"max_tokens string", map[string]any{"model": "m", "messages": msgs, "max_tokens": "5"}, "'max_tokens' must be an integer"},
		{"max_tokens bool", map[string]any{"model": "m", "messages": msgs, "max_tokens": true}, "'max_tokens' must be an integer"},
		{"max_tokens frac", map[string]any{"model": "m", "messages": msgs, "max_tokens": 1.5}, "'max_tokens' must be an integer"},
		{"max_tokens huge", map[string]any{"model": "m", "messages": msgs, "max_tokens": 1e300}, "'max_tokens' must be an integer"},
		{"max_tokens zero", map[string]any{"model": "m", "messages": msgs, "max_tokens": 0}, "between 1 and 1,000,000"},
		{"max_tokens big", map[string]any{"model": "m", "messages": msgs, "max_tokens": 1_000_001}, "between 1 and 1,000,000"},
		{"temperature string", map[string]any{"model": "m", "messages": msgs, "temperature": "1"}, "'temperature' must be a number"},
		{"temperature nan", map[string]any{"model": "m", "messages": msgs, "temperature": nan()}, "'temperature' must be a number"},
		{"temperature high", map[string]any{"model": "m", "messages": msgs, "temperature": 2.5}, "between 0.0 and 2.0"},
		{"temperature low", map[string]any{"model": "m", "messages": msgs, "temperature": -0.5}, "between 0.0 and 2.0"},
		{"base_url int", map[string]any{"model": "m", "messages": msgs, "base_url": 5}, "'base_url' must be a string"},
		{"base_url ssrf", map[string]any{"model": "m", "messages": msgs, "base_url": "https://169.254.169.254"}, "private/internal address"},
		{"base_url query", map[string]any{"model": "m", "messages": msgs, "base_url": "https://api.example.com/?x=1"}, "must not contain a query"},
		{"base_url empty fragment", map[string]any{"model": "m", "messages": msgs, "base_url": "https://api.example.com/v1/files#"}, "must not contain a query"},
		{"base_url empty query", map[string]any{"model": "m", "messages": msgs, "base_url": "https://api.example.com/v1/files?"}, "must not contain a query"},
	}
	for _, c := range bad {
		_, err := run(t, r, "openai_chat", c.params)
		if !errors.Is(err, ErrActionExecution) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v want %q", c.name, err, c.want)
		}
	}
}

func nan() float64 { var z float64; return z / z }

func TestHTTPActions_ParamErrors(t *testing.T) {
	r := registry(t, Config{})
	cases := []struct {
		action string
		params map[string]any
		want   string
	}{
		{"http_get_with_auth", map[string]any{}, "'url' is required"},
		{"http_get_with_auth", map[string]any{"url": 5}, "'url' is required"},
		{"http_get_with_auth", map[string]any{"url": "https://api.example.com/", "headers": "x"}, "'headers' must be a JSON object"},
		{"http_get_with_auth", map[string]any{"url": "https://api.example.com/", "headers": map[string]any{"Authorization": "x"}}, "set by the action"},
		{"http_get_with_auth", map[string]any{"url": "ftp://api.example.com/"}, "is not allowed"},
		{"http_get_with_auth", map[string]any{"url": "https://u:p@api.example.com/"}, "credentials in the URL"},
		{"http_get_with_auth", map[string]any{"url": "https://127.0.0.1/"}, "private/internal address"},
		{"http_get_with_auth", map[string]any{"url": "https://2130706433/"}, "ambiguous numeric"},
		{"http_post_with_auth", map[string]any{}, "'url' is required"},
		{"http_post_with_auth", map[string]any{"url": "https://api.example.com/", "body": nan()}, "not JSON-serialisable"},
		{"http_post_with_auth", map[string]any{"url": "http://api.example.com/", "body": "x"}, "plain http://"},
	}
	for _, c := range cases {
		_, err := run(t, r, c.action, c.params)
		if !errors.Is(err, ErrActionExecution) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: err=%v want %q", c.action, c.params, err, c.want)
		}
	}
	rr := registry(t, Config{MaxRequestBytes: 8})
	_, err := run(t, rr, "http_post_with_auth", map[string]any{"url": "https://api.example.com/", "body": "0123456789"})
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("request cap: %v", err)
	}
}

func TestUpstreamErrors_NeverLeakBodiesOrSecret(t *testing.T) {
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A hostile or buggy backend that reflects the Authorization header
		// and internal details in its error body.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, "invalid key %s; internal host db-7.corp; Authorization: %s", testSecret, r.Header.Get("Authorization"))
	}))
	var logbuf bytes.Buffer
	cfg.Logger = slog.New(slog.NewJSONHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := registry(t, cfg)
	for _, a := range []struct {
		name   string
		params map[string]any
	}{
		{"http_get_with_auth", map[string]any{"url": srv.URL + "/secret-path/abc?api_key=QUERYSECRET"}},
		{"http_post_with_auth", map[string]any{"url": srv.URL + "/p", "body": "x"}},
		{"openai_chat", map[string]any{"base_url": srv.URL, "model": "m", "messages": []any{map[string]any{"role": "u", "content": "x"}}}},
	} {
		_, err := run(t, r, a.name, a.params)
		if err == nil {
			t.Fatalf("%s: 401 must be an error", a.name)
		}
		for _, bad := range []string{testSecret, "db-7.corp", "invalid key", "Bearer", "QUERYSECRET", "secret-path", "api_key"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%s: error leaks %q: %v", a.name, bad, err)
			}
		}
		if !strings.Contains(err.Error(), "returned HTTP 401") {
			t.Errorf("%s: %v", a.name, err)
		}
	}
	for _, bad := range []string{testSecret, "db-7.corp", "Bearer", "QUERYSECRET", "secret-path", "Authorization"} {
		if strings.Contains(logbuf.String(), bad) {
			t.Errorf("log leaks %q:\n%s", bad, logbuf.String())
		}
	}
	if !strings.Contains(logbuf.String(), `"status":401`) {
		t.Errorf("expected a status log line:\n%s", logbuf.String())
	}
}

func TestSecretNeverInErrorsOrLogs_AllFailurePaths(t *testing.T) {
	var logbuf bytes.Buffer
	var failSrv atomic.Bool
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failSrv.Load() {
			// close the connection mid-response
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
			return
		}
		switch r.URL.Path {
		case "/slow":
			time.Sleep(600 * time.Millisecond)
		case "/redir":
			http.Redirect(w, r, "/x?token="+testSecret, http.StatusFound)
		case "/500":
			w.WriteHeader(500)
			_, _ = fmt.Fprint(w, testSecret)
		}
	}))
	cfg.Timeout = 200 * time.Millisecond
	cfg.Logger = slog.New(slog.NewJSONHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := registry(t, cfg)
	var errs []string
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	_, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/slow"})
	collect(err)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("slow: %v", err)
	}
	_, err = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/redir"})
	collect(err)
	if err == nil || !strings.Contains(err.Error(), "returned HTTP 302 (redirects are not followed)") {
		t.Fatalf("redirect: %v", err)
	}
	_, err = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/500"})
	collect(err)
	failSrv.Store(true)
	_, err = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/drop"})
	collect(err)
	_, err = run(t, r, "http_get_with_auth", map[string]any{"url": "https://localhost:1/"}) // refused by the guard (loopback allowed here, so: connection refused)
	collect(err)
	cfg2 := cfg
	cfg2.AllowPrivateNetwork = false
	r2 := registry(t, cfg2)
	_, err = run(t, r2, "http_get_with_auth", map[string]any{"url": srv.URL + "/blocked"})
	collect(err)
	_, err = r.Execute(context.Background(), "http_get_with_auth", []byte("bad\r\nsecret"), map[string]any{"url": srv.URL})
	collect(err)
	_, err = r.Execute(context.Background(), "http_get_with_auth", []byte("naïve-secret-é"), map[string]any{"url": srv.URL})
	collect(err)
	_, err = r.Execute(context.Background(), "http_get_with_auth", []byte{0xff, 0xfe}, map[string]any{"url": srv.URL})
	collect(err)
	_, err = r.Execute(context.Background(), "http_get_with_auth", nil, map[string]any{"url": srv.URL})
	collect(err)

	all := strings.Join(errs, "\n") + "\n" + logbuf.String()
	for _, bad := range []string{testSecret, "naïve-secret", "bad\r\nsecret", "Bearer"} {
		if strings.Contains(all, bad) {
			t.Errorf("secret material %q reached an error or log:\n%s", bad, all)
		}
	}
	if len(errs) < 9 {
		t.Fatalf("expected every path to fail, got %d errors: %v", len(errs), errs)
	}
}

func TestResponseCapAndUTF8(t *testing.T) {
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("a"), 5000))
		case "/exact":
			_, _ = w.Write(bytes.Repeat([]byte("b"), 1000))
		case "/bin":
			_, _ = w.Write([]byte{'o', 'k', 0xff, 0xfe, 'x'})
		case "/noct":
			w.Header()["Content-Type"] = nil
			_, _ = w.Write([]byte("x"))
		case "/badct":
			w.Header().Set("Content-Type", "garbage")
			_, _ = w.Write([]byte("x"))
		}
	}))
	cfg.MaxResponseBytes = 1000
	r := registry(t, cfg)
	out, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/big"})
	if err != nil {
		t.Fatal(err)
	}
	if out["truncated"] != true || len(out["body_text"].(string)) != 1000 {
		t.Fatalf("cap: truncated=%v len=%d", out["truncated"], len(out["body_text"].(string)))
	}
	out, _ = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/exact"})
	if out["truncated"] != false || len(out["body_text"].(string)) != 1000 {
		t.Fatalf("exact cap: %v", out["truncated"])
	}
	out, _ = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/bin"})
	if out["body_text"] != "ok\ufffd\ufffdx" && out["body_text"] != "ok\ufffdx" {
		t.Fatalf("invalid UTF-8 must be replaced: %q", out["body_text"])
	}
	for _, p := range []string{"/noct", "/badct"} {
		out, _ = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + p})
		if out["content_type"] != "text/plain" && p == "/badct" {
			t.Fatalf("%s content_type %v", p, out["content_type"])
		}
	}
}

func TestInsecureHTTP_DefaultRefusedAndOptIn(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "plain")
	}))
	defer srv.Close()
	r := registry(t, Config{AllowPrivateNetwork: true})
	_, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL})
	if err == nil || !strings.Contains(err.Error(), "plain http://") {
		t.Fatalf("http must be refused by default: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("credential-bearing request went out over http")
	}
	r = registry(t, Config{AllowPrivateNetwork: true, AllowInsecureHTTP: true})
	out, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL})
	if err != nil || out["body_text"] != "plain" {
		t.Fatalf("opt-in: %v %v", out, err)
	}
}

func TestPrivateNetworkBlockedByDefault(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	// literal loopback and a name that resolves to loopback: both refused
	r := registry(t, Config{RootCAs: pool, Resolver: &fakeResolver{table: map[string][]string{"internal.example": {"127.0.0.1"}}}})
	for _, u := range []string{srv.URL, "https://internal.example:" + port + "/"} {
		_, err := run(t, r, "http_get_with_auth", map[string]any{"url": u})
		if err == nil || !strings.Contains(err.Error(), "private/internal address") || !strings.Contains(err.Error(), "--allow-private-network") {
			t.Fatalf("%s: got %v", u, err)
		}
		if strings.Contains(err.Error(), "127.0.0.1") && strings.Contains(u, "internal.example") {
			t.Fatalf("refusal must not echo the resolved address: %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("blocked request reached the server")
	}
}

func TestSelfSignedTLSFailsAndNeverSkipsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "x") }))
	defer srv.Close()
	// AllowPrivateNetwork lets the loopback test server be reached; trust is
	// the system pool, which does not contain the test certificate.
	r := registry(t, Config{AllowPrivateNetwork: true})
	_, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL})
	if err == nil || !strings.Contains(err.Error(), "tls certificate verification failed") {
		t.Fatalf("self-signed certificate must fail verification, got %v", err)
	}
	// With the CA pinned it works (custom CA pool option).
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r = registry(t, Config{AllowPrivateNetwork: true, RootCAs: pool})
	if _, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL}); err != nil {
		t.Fatalf("custom CA pool: %v", err)
	}
}

func TestNoInsecureSkipVerifyInSource(t *testing.T) {
	// RGT-252: certificate verification must never be switched off in
	// production code. Scan the non-test sources of both packages.
	for _, dir := range []string{".", "../netguard"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(string(b), "\n") {
				code := strings.TrimSpace(line)
				if strings.HasPrefix(code, "//") {
					continue
				}
				if strings.Contains(code, "InsecureSkipVerify") {
					t.Errorf("%s:%d sets InsecureSkipVerify: %s", f, i+1, code)
				}
			}
		}
	}
}

func TestRedirects_DefaultRefusedFollowedOnlyWhenConfigured(t *testing.T) {
	var landed atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/end", http.StatusFound) })
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		landed.Add(1)
		_, _ = fmt.Fprint(w, r.Header.Get("Authorization"))
	})
	mux.HandleFunc("/to-private", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	srv, cfg := tlsServer(t, mux)
	r := registry(t, cfg)
	_, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/start"})
	if err == nil || !strings.Contains(err.Error(), "redirects are not followed") || landed.Load() != 0 {
		t.Fatalf("default must refuse redirects: err=%v landed=%d", err, landed.Load())
	}
	cfg.MaxRedirects = 2
	r = registry(t, cfg)
	out, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/start"})
	if err != nil || out["body_text"] != "Bearer "+testSecret || landed.Load() != 1 {
		t.Fatalf("configured redirect: %v %v", out, err)
	}
	_, err = run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL + "/to-private"})
	if err == nil || !strings.Contains(err.Error(), "private/internal address") {
		t.Fatalf("redirect to metadata must be refused: %v", err)
	}
}

func TestHostAllowlistPerAction(t *testing.T) {
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "ok") }))
	host := strings.TrimPrefix(srv.URL, "https://") // 127.0.0.1:port
	cfg.HostAllowlist = map[string][]string{
		"http_get_with_auth": {host},
		"*":                  {"api.example.com:443"},
	}
	r := registry(t, cfg)
	if _, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL}); err != nil {
		t.Fatalf("listed host/port: %v", err)
	}
	// wrong port on the same host
	other := strings.Replace(srv.URL, host[strings.LastIndex(host, ":")+1:], "1", 1)
	_, err := run(t, r, "http_get_with_auth", map[string]any{"url": other})
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("port outside the allow-list: %v", err)
	}
	// the other actions fall back to the "*" entry
	_, err = run(t, r, "http_post_with_auth", map[string]any{"url": srv.URL})
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("post must use the * entry: %v", err)
	}
	_, err = run(t, r, "openai_chat", map[string]any{"base_url": srv.URL, "model": "m", "messages": []any{map[string]any{"role": "u", "content": "x"}}})
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("openai_chat must use the * entry: %v", err)
	}
	// header allow-list
	cfg.HostAllowlist = nil
	cfg.HeaderAllowlist = []string{"X-Ok"}
	r = registry(t, cfg)
	if _, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL, "headers": map[string]any{"x-ok": "1"}}); err != nil {
		t.Fatalf("allowed header: %v", err)
	}
	if _, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL, "headers": map[string]any{"X-No": "1"}}); err == nil {
		t.Fatal("header outside the allow-list accepted")
	}
	// bad config is reported at construction time
	if _, err := NewBuiltinRegistry(Config{HostAllowlist: map[string][]string{"echo": {"bad entry"}}}); err == nil {
		// "echo" has no endpoint; only HTTP actions read their list
		t.Log("echo allow-list is ignored (no endpoint)")
	}
	if _, err := NewBuiltinRegistry(Config{HostAllowlist: map[string][]string{"*": {"a b"}}}); err == nil {
		t.Fatal("malformed allow-list entry accepted")
	}
	if _, err := NewBuiltinRegistry(Config{MaxRedirects: 99}); err == nil {
		t.Fatal("excessive redirects accepted")
	}
}

func TestCancelledContext(t *testing.T) {
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	r := registry(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := r.Execute(ctx, "http_get_with_auth", []byte(testSecret), map[string]any{"url": srv.URL})
	if err == nil || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("got %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, err = r.Execute(ctx2, "http_get_with_auth", []byte(testSecret), map[string]any{"url": srv.URL})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancel: %v", err)
	}
}

func TestConversions(t *testing.T) {
	if _, ok := asInt64(1e300); ok {
		t.Error("1e300 accepted as int")
	}
	if n, ok := asInt64(float64(5)); !ok || n != 5 {
		t.Error("5.0")
	}
	if _, ok := asInt64(json.Number("5.0")); ok {
		t.Error("json.Number 5.0 accepted (Python rejects 5.0)")
	}
	if _, ok := asInt64(json.Number("99999999999999999999")); ok {
		t.Error("overflow accepted")
	}
	if n, ok := asInt64(int32(7)); !ok || n != 7 {
		t.Error("int32")
	}
	if _, ok := asInt64("5"); ok {
		t.Error("string accepted")
	}
	if f, ok := asFloat64(int64(2)); !ok || f != 2 {
		t.Error("int64 float")
	}
	if f, ok := asFloat64(json.Number("1e-1")); !ok || f != 0.1 {
		t.Error("json.Number float")
	}
	if _, ok := asFloat64(json.Number("abc")); ok {
		t.Error("bad json.Number")
	}
	if _, ok := asFloat64(true); ok {
		t.Error("bool accepted as number")
	}
	for in, want := range map[any]string{"s": "s", true: "True", false: "False", 5: "5", int64(6): "6", json.Number("7"): "7", 5.0: "5.0", 1.5: "1.5"} {
		if got, ok := headerString(in); !ok || got != want {
			t.Errorf("headerString(%v)=%q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := headerString(nan()); ok {
		t.Error("NaN header")
	}
	if got := sanitizeForMsg(strings.Repeat("a\x01", 50)); len(got) != 40 || strings.ContainsRune(got, 1) {
		t.Errorf("sanitizeForMsg %q", got)
	}
	if _, err := ValidateHeaders(map[string]string{"X-A": "1"}, nil); err != nil {
		t.Error(err)
	}
	if _, err := ValidateHeaders(map[string]any{"X-A": strings.Repeat("v", 4000), "X-B": strings.Repeat("v", 4000), "X-C": strings.Repeat("v", 4000), "X-D": strings.Repeat("v", 4000), "X-E": strings.Repeat("v", 4000)}, nil); err == nil {
		t.Error("total header cap not enforced")
	}
}

func TestRedactAndContentType(t *testing.T) {
	if got := redact("https://api.example.com:8443/bot123:TOKEN/send?key=1#f"); got != "https://api.example.com:8443" {
		t.Errorf("redact: %s", got)
	}
	if redact("::::") != "<url>" || redact("/relative") != "<url>" {
		t.Error("redact fallback")
	}
	if contentType("") != "text/plain" || contentType("text/HTML; charset=x") != "text/html" || contentType("nonsense") != "text/plain" {
		t.Error("contentType")
	}
}

func TestEmptyAllowlistDeniesAndWrappedErrorsAreMasked(t *testing.T) {
	srv, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cfg.HostAllowlist = map[string][]string{"*": {strings.TrimPrefix(srv.URL, "https://")}, "http_get_with_auth": {}}
	r := registry(t, cfg)
	_, err := run(t, r, "http_get_with_auth", map[string]any{"url": srv.URL})
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("an empty per-action list must deny everything: %v", err)
	}
	if _, err := run(t, r, "http_post_with_auth", map[string]any{"url": srv.URL}); err != nil {
		t.Fatalf("other actions keep the * entry: %v", err)
	}

	reg := NewRegistry(nil)
	_ = reg.Register(Spec{Name: "wrap", Fn: func(context.Context, []byte, map[string]any) (map[string]any, error) {
		return nil, fmt.Errorf("db password hunter2: %w", execErr("clean message"))
	}})
	_, err = run(t, reg, "wrap", nil)
	if err == nil || err.Error() != "clean message" {
		t.Fatalf("wrapper text must not reach the caller: %v", err)
	}
}
