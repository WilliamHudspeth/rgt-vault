package servecmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/tlstest"
	"rgt-vault-server/internal/transport"
	"rgt-vault-server/internal/vault"
)

// syncBuf is a bytes.Buffer safe for the server's goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type tlsRun struct {
	addr, token, db string
	out, logs       *syncBuf
	prov            vault.MasterProvider
	stop            func()
}

// startTLS starts `serve` with args and returns once it is listening. The
// token is the legacy shared token (simplest to read back).
func startTLS(t *testing.T, args ...string) *tlsRun {
	t.Helper()
	r := &tlsRun{out: &syncBuf{}, logs: &syncBuf{}, prov: providerstest.NewMemory()}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "srv.token")
	r.db = filepath.Join(dir, "vault", "vault.db")
	e := map[string]string{"RGT_VAULT_TOKEN_FILE": tokenPath, "RGT_VAULT_DB": r.db}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- execute(ctx, args, Env{
			Getenv: env(e), Stdout: r.out, Logger: log.New(r.logs, "", 0),
			NewProvider: func(string) (vault.MasterProvider, error) { return r.prov, nil },
			Ready:       func(a string) { ready <- a },
		})
	}()
	select {
	case r.addr = <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("serve exited early: %v\nlogs:\n%s", err, r.logs)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("server did not start")
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	r.token = strings.TrimSpace(string(raw))
	var once sync.Once
	r.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("shutdown error: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("shutdown timed out")
			}
		})
	}
	t.Cleanup(r.stop)
	return r
}

// failTLS runs serve expecting a startup error.
func failTLS(t *testing.T, args ...string) error {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "srv.token")
	e := map[string]string{"RGT_VAULT_TOKEN_FILE": tokenPath, "RGT_VAULT_DB": filepath.Join(dir, "v.db")}
	err := execute(context.Background(), args, Env{Getenv: env(e), Logger: log.New(&syncBuf{}, "", 0)})
	if err == nil {
		t.Fatal("serve started but must have been refused")
	}
	if _, serr := os.Stat(tokenPath); serr == nil {
		t.Error("token file was created before the TLS check")
	}
	return err
}

func tlsArgs(f tlstest.Files, more ...string) []string {
	return append([]string{"--port", "0", "--tls-cert", f.Cert, "--tls-key", f.Key}, more...)
}

func httpsClient(t *testing.T, o transport.ClientOptions) *http.Client {
	t.Helper()
	c, err := transport.NewHTTPClient(o, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func localURL(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return "https://localhost:" + port
}

func TestServeTLSEndToEnd(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	r := startTLS(t, tlsArgs(f)...)
	base := localURL(r.addr)
	cl := httpsClient(t, transport.ClientOptions{CACertFile: ca.PEMFile})

	resp, err := cl.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz %d", resp.StatusCode)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("TLS state %+v", resp.TLS)
	}
	if got := resp.Header.Get("Strict-Transport-Security"); got != server.HSTSValue {
		t.Errorf("HSTS = %q", got)
	}
	if !strings.Contains(r.out.String(), "https://"+r.addr+"/healthz") || !strings.Contains(r.out.String(), "TLS: 1.2+") {
		t.Errorf("banner:\n%s", r.out)
	}
	if strings.Contains(r.out.String()+r.logs.String(), r.token) {
		t.Error("the token leaked into the output")
	}
	if strings.Contains(r.logs.String(), "WARNING: listening on non-loopback") {
		t.Errorf("unexpected plain-HTTP warning:\n%s", r.logs)
	}

	// Authenticated call over TLS works with the header ...
	get := func(url, bearer string) int {
		req, _ := http.NewRequest("GET", url, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := get(base+"/v1/actions", r.token); got != 200 {
		t.Errorf("authenticated GET: %d", got)
	}
	// ... and a credential in the URL (GET query) is never accepted (RGT-422).
	if got := get(base+"/v1/actions?token="+r.token+"&access_token="+r.token, ""); got != 401 {
		t.Errorf("token in the query string: %d, want 401", got)
	}

	// Without a CA the self-signed server is refused; so is a wrong CA.
	if _, err := httpsClient(t, transport.ClientOptions{}).Get(base + "/healthz"); err == nil {
		t.Error("private-CA server accepted without --cacert")
	}
	if _, err := httpsClient(t, transport.ClientOptions{CACertFile: tlstest.NewCA(t).PEMFile}).Get(base + "/healthz"); err == nil {
		t.Error("server accepted with the wrong CA")
	}
	// Plain HTTP on the TLS port is not served.
	if resp, err := http.Get("http://" + r.addr + "/healthz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Error("plain HTTP got 200 from the TLS port")
		}
	}
}

func TestServeWarnsWhenCertificateDoesNotCoverHost(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "s", DNSNames: []string{"vault.example"}})
	r := startTLS(t, tlsArgs(f, "--host", "127.0.0.1")...)
	if !strings.Contains(r.logs.String(), "does not cover --host 127.0.0.1") {
		t.Errorf("no SAN/host warning:\n%s", r.logs)
	}
}

func TestServeMTLS(t *testing.T) {
	ca := tlstest.NewCA(t)
	clientCA := tlstest.NewCA(t)
	rogueCA := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	good := clientCA.Issue(t, t.TempDir(), tlstest.Leaf{Name: "good", Client: true})
	rogue := rogueCA.Issue(t, t.TempDir(), tlstest.Leaf{Name: "rogue", Client: true})

	r := startTLS(t, tlsArgs(f, "--tls-client-ca", clientCA.PEMFile)...)
	if !strings.Contains(r.out.String(), "required (mTLS)") {
		t.Errorf("banner lacks mTLS mode:\n%s", r.out)
	}
	base := localURL(r.addr)
	ok := transport.ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: good.Cert, ClientKeyFile: good.Key}
	if resp, err := httpsClient(t, ok).Get(base + "/healthz"); err != nil {
		t.Errorf("valid client certificate: %v", err)
	} else {
		resp.Body.Close()
	}
	if _, err := httpsClient(t, transport.ClientOptions{CACertFile: ca.PEMFile}).Get(base + "/healthz"); err == nil {
		t.Error("connection without a client certificate accepted")
	}
	bad := transport.ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: rogue.Cert, ClientKeyFile: rogue.Key}
	if _, err := httpsClient(t, bad).Get(base + "/healthz"); err == nil {
		t.Error("client certificate from an untrusted CA accepted")
	}
	// mTLS does not replace the bearer token: a valid certificate alone is 401.
	req, _ := http.NewRequest("GET", base+"/v1/actions", nil)
	resp, err := httpsClient(t, ok).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("valid certificate without a bearer token: %d, want 401", resp.StatusCode)
	}
}

func TestServeMTLSVerifyIfGiven(t *testing.T) {
	ca := tlstest.NewCA(t)
	clientCA := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	r := startTLS(t, tlsArgs(f, "--tls-client-ca", clientCA.PEMFile, "--tls-client-auth", "verify-if-given")...)
	if resp, err := httpsClient(t, transport.ClientOptions{CACertFile: ca.PEMFile}).Get(localURL(r.addr) + "/healthz"); err != nil {
		t.Errorf("anonymous client refused in verify-if-given mode: %v", err)
	} else {
		resp.Body.Close()
	}
}

func TestServeRefusesBadTLSMaterial(t *testing.T) {
	ca := tlstest.NewCA(t)
	good := ca.Localhost(t, t.TempDir())
	other := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "o", DNSNames: []string{"localhost"}})
	expired := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "e", DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})

	if err := failTLS(t, "--port", "0", "--tls-cert", good.Cert, "--tls-key", other.Key); !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatched pair: %v", err)
	}
	if err := failTLS(t, tlsArgs(expired)...); !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired certificate: %v", err)
	}
	if err := failTLS(t, "--port", "0", "--tls-cert", good.Cert); !strings.Contains(err.Error(), "together") {
		t.Errorf("cert without key: %v", err)
	}
	if err := failTLS(t, "--port", "0", "--tls-client-ca", ca.PEMFile); !strings.Contains(err.Error(), "need --tls-cert") {
		t.Errorf("client CA without a certificate: %v", err)
	}
	if err := failTLS(t, tlsArgs(good, "--tls-client-ca", filepath.Join(t.TempDir(), "none"))...); !strings.Contains(err.Error(), "client CA") {
		t.Errorf("missing client CA: %v", err)
	}
	if err := failTLS(t, tlsArgs(good, "--tls-client-auth", "sometimes", "--tls-client-ca", ca.PEMFile)...); !strings.Contains(err.Error(), "--tls-client-auth") {
		t.Errorf("bad client auth mode: %v", err)
	}
	if err := failTLS(t, tlsArgs(good, "--tls-reload-interval", "-1s")...); !strings.Contains(err.Error(), "tls-reload-interval") {
		t.Errorf("negative reload interval: %v", err)
	}
}

func TestServeRefusesWorldReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes: on Windows restrict the key ACL (docs/guides/tls.md)")
	}
	ca := tlstest.NewCA(t)
	f := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "s", DNSNames: []string{"localhost"}, KeyMode: 0o640})
	err := failTLS(t, tlsArgs(f)...)
	if !strings.Contains(err.Error(), "accessible by group/other") || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error does not explain the fix: %v", err)
	}
}

func TestServeEnvironmentVariables(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	e := map[string]string{
		"RGT_VAULT_TLS_CERT": f.Cert, "RGT_VAULT_TLS_KEY": f.Key,
		"RGT_VAULT_TLS_CLIENT_CA": ca.PEMFile, "RGT_VAULT_TLS_CLIENT_AUTH": "verify-if-given",
		"RGT_VAULT_HOST": "127.0.0.1", "HOME": t.TempDir(),
	}
	cfg, err := parse(flagsOf(nil), env(e))
	if err != nil {
		t.Fatal(err)
	}
	want := server.TLSSettings{CertFile: f.Cert, KeyFile: f.Key, ClientCAFile: ca.PEMFile, ClientAuth: "verify-if-given"}
	if cfg.tls != want {
		t.Errorf("tls = %+v, want %+v", cfg.tls, want)
	}
	// A flag wins over the environment.
	cfg, err = parse(flagsOf(func(f *Flags) { f.TLSCert, f.TLSKey = "/flag/c", "/flag/k" }), env(e))
	if err != nil || cfg.tls.CertFile != "/flag/c" || cfg.tls.KeyFile != "/flag/k" {
		t.Errorf("flag precedence: %+v, %v", cfg.tls, err)
	}
	// Default: no TLS, no insecure override.
	cfg, err = parse(flagsOf(nil), env(map[string]string{"HOME": t.TempDir()}))
	if err != nil || cfg.tls.Enabled() || cfg.allowInsecure {
		t.Errorf("defaults: %+v, %v", cfg, err)
	}
	// Both spellings of the override.
	for _, mod := range []func(*Flags){
		func(f *Flags) { f.AllowInsecureNonLoopback = true },
		func(f *Flags) { f.AllowNonLoopback = true },
	} {
		cfg, err = parse(flagsOf(mod), env(map[string]string{"HOME": t.TempDir()}))
		if err != nil || !cfg.allowInsecure {
			t.Errorf("override: %+v, %v", cfg, err)
		}
	}
}

func TestNonLoopbackNeedsTLSOrExplicitOverride(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())

	// Plain HTTP on a non-loopback host: refused, and the message says how to fix it.
	err := failTLS(t, "--host", "0.0.0.0", "--port", "0")
	if !strings.Contains(err.Error(), "TLS is not configured") || !strings.Contains(err.Error(), "--tls-cert") {
		t.Errorf("refusal text: %v", err)
	}

	// TLS on a non-loopback host: allowed without any override flag.
	r := startTLS(t, tlsArgs(f, "--host", "0.0.0.0")...)
	if strings.Contains(r.logs.String(), "INSECURE") {
		t.Errorf("a TLS bind was reported insecure:\n%s", r.logs)
	}
	r.stop()
}

func TestInsecureOverrideIsLoudAndAudited(t *testing.T) {
	r := startTLS(t, "--host", "0.0.0.0", "--port", "0", "--allow-insecure-non-loopback")
	logs := r.logs.String()
	if !strings.Contains(logs, "WARNING: INSECURE") || !strings.Contains(logs, "PLAIN HTTP") {
		t.Errorf("no loud warning:\n%s", logs)
	}
	r.stop()

	// The audit chain records the decision.
	stack, err := server.OpenStack(context.Background(), server.StackOptions{DBPath: r.db, MasterProvider: r.prov, KDFParams: testKDF})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	rows, err := stack.Vault.AuditLog(context.Background(), -1)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, row := range rows {
		if row.Action == "server_insecure_bind" && strings.Contains(row.Details.String, "0.0.0.0") {
			found = true
		}
	}
	if !found {
		t.Errorf("no server_insecure_bind audit row in %d rows", len(rows))
	}
	if ok, err := stack.Vault.VerifyAuditChain(context.Background()); err != nil || !ok {
		t.Errorf("audit chain: %v %v", ok, err)
	}
}

func TestDeprecatedAllowNonLoopbackAlias(t *testing.T) {
	r := startTLS(t, "--host", "0.0.0.0", "--port", "0", "--allow-non-loopback")
	if !strings.Contains(r.logs.String(), "WARNING: INSECURE") {
		t.Errorf("alias not treated as the insecure override:\n%s", r.logs)
	}
}

func TestLoopbackPlainHTTPStaysDefault(t *testing.T) {
	r := startTLS(t, "--port", "0")
	if !strings.Contains(r.out.String(), "http://"+r.addr+"/healthz") || strings.Contains(r.out.String(), "TLS:") {
		t.Errorf("banner:\n%s", r.out)
	}
	resp, err := http.Get("http://" + r.addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain HTTP")
	}
	if strings.Contains(r.logs.String(), "INSECURE") {
		t.Errorf("loopback plain HTTP reported as insecure:\n%s", r.logs)
	}
}

// serial returns the serial of the certificate the server presents now.
func serial(t *testing.T, addr string, ca *tlstest.CA) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: ca.Pool(), ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
}

func replaceCert(t *testing.T, ca *tlstest.CA, f tlstest.Files) string {
	t.Helper()
	n := ca.Localhost(t, t.TempDir())
	for src, dst := range map[string]string{n.Cert: f.Cert, n.Key: f.Key} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(dst, 0o600)
	}
	return n.Leaf.SerialNumber.Text(16)
}

func waitSerial(t *testing.T, addr string, ca *tlstest.CA, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if serial(t, addr, ca) == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("certificate %s never served", want)
}

// Rotation by file change (no signal): works on every OS.
func TestServeReloadsChangedCertificateFiles(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	r := startTLS(t, tlsArgs(f, "--tls-reload-interval", "30ms")...)
	first := serial(t, r.addr, ca)
	waitSerial(t, r.addr, ca, replaceCert(t, ca, f))
	if first == serial(t, r.addr, ca) {
		t.Error("certificate unchanged")
	}
	if !strings.Contains(r.logs.String(), "TLS certificate reloaded") {
		t.Errorf("no reload log:\n%s", r.logs)
	}
}
