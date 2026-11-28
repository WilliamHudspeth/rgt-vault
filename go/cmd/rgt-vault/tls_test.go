package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/tlstest"
	"rgt-vault-server/internal/transport"
	"rgt-vault-server/internal/tui"
)

// tlsBackend serves a minimal vault API over TLS with the real server TLS
// policy. wantToken is the bearer token it insists on.
type tlsBackend struct {
	addr string
	url  string
	ca   *tlstest.CA
}

func newTLSBackend(t *testing.T, clientCA *tlstest.CA) *tlsBackend {
	t.Helper()
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	o := transport.ServerOptions{CertFile: f.Cert, KeyFile: f.Key}
	if clientCA != nil {
		o.ClientCAFile = clientCA.PEMFile
	}
	s, err := transport.NewServerTLS(o)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"status":"ok"}`) })
	mux.HandleFunc("/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tls-test-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"namespace":"default","secrets":[{"name":"db-password","created_at":"2026-11-26T00:00:00Z"}]}`)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, TLSConfig: s.Config(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return &tlsBackend{addr: ln.Addr().String(), url: "https://localhost:" + port, ca: ca}
}

func TestCLIVerifiesServerCertificateByDefault(t *testing.T) {
	isolateEnv(t)
	b := newTLSBackend(t, nil)

	// Self-signed / private CA, no --cacert: refused.
	code, out, errb := runCLI(t, "", "--host", b.url, "status")
	if code == 0 || !strings.Contains(out+errb, "unreachable") || !strings.Contains(errb, "certificate") {
		t.Errorf("default verification: exit %d out %q err %q", code, out, errb)
	}
	// A different CA: refused.
	other := tlstest.NewCA(t)
	if code, _, _ := runCLI(t, "", "--host", b.url, "--cacert", other.PEMFile, "status"); code == 0 {
		t.Error("wrong --cacert accepted")
	}
	// The right CA: works, for status and for an authenticated call.
	if code, out, errb := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "status"); code != 0 || !strings.Contains(out, "Server OK") {
		t.Errorf("status with --cacert: exit %d %q %q", code, out, errb)
	}
	code, out, errb = runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "--token", "tls-test-token", "list")
	if code != 0 || !strings.Contains(out, "db-password") {
		t.Errorf("list with --cacert: exit %d %q %q", code, out, errb)
	}
	if code, _, _ := runCLI(t, "", "--host", b.url, "--token", "tls-test-token", "list"); code == 0 {
		t.Error("list over an unverified TLS connection succeeded")
	}
	// The environment variable is equivalent to the flag.
	t.Setenv(transport.EnvCACert, b.ca.PEMFile)
	if code, out, _ := runCLI(t, "", "--host", b.url, "status"); code != 0 || !strings.Contains(out, "Server OK") {
		t.Errorf("RGT_VAULT_CACERT: exit %d %q", code, out)
	}
	// A broken --cacert is an error, not a silent fallback to the system store.
	if code, _, errb := runCLI(t, "", "--host", b.url, "--cacert", filepath.Join(t.TempDir(), "none"), "status"); code == 0 || !strings.Contains(errb, "cacert") {
		t.Errorf("missing --cacert file: exit %d %q", code, errb)
	}
}

func TestCLIHasNoWayToSkipVerification(t *testing.T) {
	isolateEnv(t)
	for _, flag := range []string{"--insecure-skip-verify", "--insecure", "-k", "--skip-verify", "--no-verify"} {
		code, _, errb := runCLI(t, "", flag, "status")
		if code == 0 || !strings.Contains(errb, "unknown") {
			t.Errorf("%s: exit %d %q (must be an unknown flag)", flag, code, errb)
		}
	}
}

func TestCLIRefusesTokenOverPlainHTTPToRemoteHost(t *testing.T) {
	isolateEnv(t)
	for _, host := range []string{"http://203.0.113.9:8765", "http://vault.example", "ftp://x", "vault.example:8765"} {
		for _, cmd := range [][]string{{"--token", "t", "list"}, {"status"}, {"--token", "t", "mcp"}, {"--token", "t", "tui"}} {
			args := append([]string{"--host", host}, cmd...)
			start := time.Now()
			code, _, errb := runCLI(t, "", args...)
			if code == 0 || !(strings.Contains(errb, "plain http") || strings.Contains(errb, "scheme")) {
				t.Errorf("%v: exit %d %q", args, code, errb)
			}
			if time.Since(start) > 3*time.Second {
				t.Errorf("%v: took %v, a connection was attempted", args, time.Since(start))
			}
		}
	}
	// Loopback plain HTTP stays the default for local use.
	srv, _ := recordingServer(t, 200, `{"secrets":[]}`)
	if code, _, errb := runCLI(t, "", "--host", srv.URL, "--token", "t", "list"); code != 0 {
		t.Errorf("loopback http refused: %q", errb)
	}
}

func TestClientTLSFlagsPrepare(t *testing.T) {
	f := &clientTLSFlags{allowInsecureHTTP: true}
	base, rt, err := f.prepare("http://vault.example:8765/")
	if err != nil || rt == nil || base != "http://vault.example:8765" {
		t.Errorf("--allow-insecure-http: %q %v %v", base, rt, err)
	}
	if _, _, err := (&clientTLSFlags{}).prepare("http://vault.example:8765"); err == nil {
		t.Error("remote plain http accepted without --allow-insecure-http")
	}
	if _, _, err := (&clientTLSFlags{cacert: "/nonexistent"}).prepare("https://v"); err == nil {
		t.Error("bad cacert accepted")
	}
}

func TestCLIMutualTLS(t *testing.T) {
	isolateEnv(t)
	clientCA := tlstest.NewCA(t)
	b := newTLSBackend(t, clientCA)
	good := clientCA.Issue(t, t.TempDir(), tlstest.Leaf{Name: "agent", Client: true})
	rogue := tlstest.NewCA(t).Issue(t, t.TempDir(), tlstest.Leaf{Name: "rogue", Client: true})

	if code, _, _ := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "status"); code == 0 {
		t.Error("server requiring mTLS answered a client without a certificate")
	}
	if code, out, errb := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "--client-cert", good.Cert, "--client-key", good.Key, "status"); code != 0 || !strings.Contains(out, "Server OK") {
		t.Errorf("valid client certificate: exit %d %q %q", code, out, errb)
	}
	if code, _, _ := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "--client-cert", rogue.Cert, "--client-key", rogue.Key, "status"); code == 0 {
		t.Error("certificate from an untrusted CA accepted")
	}
	if code, _, errb := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "--client-cert", good.Cert, "status"); code == 0 || !strings.Contains(errb, "together") {
		t.Errorf("--client-cert without --client-key: exit %d %q", code, errb)
	}
	t.Setenv(transport.EnvClientCert, good.Cert)
	t.Setenv(transport.EnvClientKey, good.Key)
	if code, out, _ := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "status"); code != 0 || !strings.Contains(out, "Server OK") {
		t.Errorf("client certificate from the environment: exit %d %q", code, out)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(good.Key, 0o644)
		if code, _, errb := runCLI(t, "", "--host", b.url, "--cacert", b.ca.PEMFile, "status"); code == 0 || !strings.Contains(errb, "group/other") {
			t.Errorf("group-readable client key: exit %d %q", code, errb)
		}
	}
}

// The MCP and TUI clients use the same transport (their own constructors
// default to the system trust store).
func TestMCPAndTUIUseTheSharedTransport(t *testing.T) {
	b := newTLSBackend(t, nil)
	tr, err := transport.NewTransport(transport.ClientOptions{CACertFile: b.ca.PEMFile})
	if err != nil {
		t.Fatal(err)
	}

	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets","arguments":{"namespace":"default"}}}` + "\n"
	run := func(rt http.RoundTripper) string {
		var out, errb bytes.Buffer
		if err := runMCP(b.url, rt, "tls-test-token", "", strings.NewReader(call), &out, &errb); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if got := run(tr); !strings.Contains(got, "db-password") {
		t.Errorf("mcp over pinned TLS: %s", got)
	}
	if got := run(nil); strings.Contains(got, "db-password") {
		t.Errorf("mcp without the CA reached the backend: %s", got)
	}

	c := tui.NewHTTPClient(b.url, "tls-test-token")
	var se *tui.StatusError
	if _, err := c.ListRequests(); err == nil || errors.As(err, &se) {
		t.Errorf("tui without the CA: %v (want a certificate error)", err)
	}
	c.SetTransport(nil) // nil keeps the default
	c.SetTransport(tr)
	if _, err := c.ListRequests(); err == nil || !errors.As(err, &se) {
		t.Errorf("tui with the CA should get an HTTP status error from the stub, got %v", err)
	}

	var sb strings.Builder
	if err := runStatus(b.url, tr, &sb); err != nil || !strings.Contains(sb.String(), "Server OK") {
		t.Errorf("runStatus: %v %q", err, sb.String())
	}
}

// MED-1 of the H6 security review: a redirect from the https server to a
// plain-http listener must never carry the bearer token (or be followed).
func TestNoClientFollowsRedirectsOrReplaysTheToken(t *testing.T) {
	isolateEnv(t)
	var mu sync.Mutex
	var leaked []string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		fmt.Fprint(w, `{"secrets":[{"name":"stolen"}]}`)
	}))
	defer plain.Close()

	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	s, err := transport.NewServerTLS(transport.ServerOptions{CertFile: f.Cert, KeyFile: f.Key})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	redirector := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Same host NAME, different scheme and port: Go's default policy
			// would re-send Authorization here. 307 keeps method and body.
			_, pport, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))
			http.Redirect(w, r, "http://localhost:"+pport+r.URL.Path, http.StatusTemporaryRedirect)
		}),
		TLSConfig: s.Config(), ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = redirector.ServeTLS(ln, "", "") }()
	defer redirector.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	url := "https://localhost:" + port

	const secretToken = "redirect-test-token"
	// CLI subcommands.
	for _, args := range [][]string{{"list"}, {"status"}} {
		a := append([]string{"--host", url, "--cacert", ca.PEMFile, "--token", secretToken}, args...)
		if code, out, _ := runCLI(t, "", a...); code == 0 || strings.Contains(out, "stolen") {
			t.Errorf("%v followed a redirect: exit %d %q", args, code, out)
		}
	}
	// MCP and TUI clients, and the shared constructor.
	tr, _ := transport.NewTransport(transport.ClientOptions{CACertFile: ca.PEMFile})
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets","arguments":{"namespace":"default"}}}` + "\n"
	var out, errb bytes.Buffer
	if err := runMCP(url, tr, secretToken, "", strings.NewReader(call), &out, &errb); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "stolen") {
		t.Errorf("mcp followed the redirect: %s", out.String())
	}
	c := tui.NewHTTPClient(url, secretToken)
	c.SetTransport(tr)
	if _, err := c.ListRequests(); err == nil {
		t.Error("tui: redirect answer treated as success")
	}
	hc, _ := transport.NewHTTPClient(transport.ClientOptions{CACertFile: ca.PEMFile}, 5*time.Second)
	req, _ := http.NewRequest("GET", url+"/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+secretToken)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("transport.NewHTTPClient: status %d, want the 307 returned as is", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(leaked) != 0 {
		t.Fatalf("the plain-http listener received requests: %v", leaked)
	}
}
