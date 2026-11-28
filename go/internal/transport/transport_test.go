package transport

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
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

	"github.com/WilliamHudspeth/rgt-vault/go/internal/tlstest"
)

// logSink collects Logf output.
type logSink struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logSink) Logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, f+"\n", a...)
}
func (l *logSink) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// serve runs an HTTPS server with the TLS policy and returns its address.
func serve(t *testing.T, s *ServerTLS, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	}
	srv := &http.Server{Handler: h, TLSConfig: s.Config(), ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func newServer(t *testing.T, ca *tlstest.CA, mod func(*ServerOptions)) (*ServerTLS, tlstest.Files, *logSink) {
	t.Helper()
	f := ca.Localhost(t, t.TempDir())
	logs := &logSink{}
	o := ServerOptions{CertFile: f.Cert, KeyFile: f.Key, Logf: logs.Logf}
	if mod != nil {
		mod(&o)
	}
	s, err := NewServerTLS(o)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, logs
}

func dial(addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	return c, err
}

func clientCfg(ca *tlstest.CA) *tls.Config {
	return &tls.Config{RootCAs: ca.Pool(), ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// legacyVersion is the wire number of SSL 3.0 (minor 0), TLS 1.0 (1) or TLS
// 1.1 (2). It is built at run time: these tests need to SPEAK the old
// protocols to prove the server refuses them, they never configure them.
func legacyVersion(minor byte) uint16 { return uint16(3)<<8 | uint16(minor) }

// rawClientHello is a minimal ClientHello that claims version v and offers
// one ECDHE-RSA AES-GCM suite and no extensions (what a TLS 1.0/1.1 client
// sends).
func rawClientHello(v uint16) []byte {
	body := []byte{}
	body = binary.BigEndian.AppendUint16(body, v)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id length
	body = append(body, 0, 2, 0xc0, 0x2f)    // one cipher suite
	body = append(body, 1, 0)                // null compression
	hs := append([]byte{1, 0, 0, 0}, body...)
	binary.BigEndian.PutUint16(hs[2:], uint16(len(body)))
	rec := []byte{22}
	rec = binary.BigEndian.AppendUint16(rec, v)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestHandshakeFloorRefusesLegacyProtocols(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	for _, minor := range []byte{0, 1, 2} { // SSL 3.0, TLS 1.0, TLS 1.1
		v := legacyVersion(minor)
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(rawClientHello(v)); err != nil {
			t.Fatal(err)
		}
		reply, _ := io.ReadAll(c)
		c.Close()
		// A fatal alert (record type 21), never a ServerHello (22).
		if len(reply) < 7 || reply[0] != 21 || reply[5] != 2 || reply[6] != 70 {
			t.Errorf("version %#04x: reply % x, want fatal alert protocol_version (70)", v, reply)
		}
	}
}

func TestHandshakeAcceptsTLS12AndTLS13(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		cfg := clientCfg(ca)
		cfg.MaxVersion = v
		c, err := dial(addr, cfg)
		if err != nil {
			t.Fatalf("max %#x: %v", v, err)
		}
		st := c.ConnectionState()
		c.Close()
		if st.Version != v {
			t.Errorf("negotiated %#x, want %#x", st.Version, v)
		}
		if !IsSuiteAEAD(st.CipherSuite) {
			t.Errorf("suite %s is not AEAD", tls.CipherSuiteName(st.CipherSuite))
		}
	}
	// Both offered: TLS 1.3 is preferred.
	h2 := clientCfg(ca)
	h2.NextProtos = []string{"h2", "http/1.1"}
	c, err := dial(addr, h2)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ConnectionState().Version != tls.VersionTLS13 {
		t.Errorf("did not prefer TLS 1.3: %#x", c.ConnectionState().Version)
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Errorf("ALPN = %q, want h2 (HTTP/2 allowed)", c.ConnectionState().NegotiatedProtocol)
	}
}

// Every TLS 1.2 suite that is not on the AEAD+ECDHE allow-list must fail.
func TestCipherPolicyRefusesEverythingElse(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	allowed := map[uint16]bool{}
	for _, id := range AEADCipherSuites() {
		allowed[id] = true
	}
	var tried, accepted int
	all := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, cs := range all {
		tls12 := false
		for _, v := range cs.SupportedVersions {
			if v == tls.VersionTLS12 {
				tls12 = true
			}
		}
		if !tls12 {
			continue
		}
		cfg := clientCfg(ca)
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = []uint16{cs.ID}
		c, err := dial(addr, cfg)
		if err == nil {
			c.Close()
		}
		switch {
		case allowed[cs.ID] && strings.Contains(cs.Name, "ECDSA"):
			// The test server certificate is ECDSA: only ECDSA suites can
			// complete; the RSA ones are exercised by TestSuiteLists.
			if err != nil {
				t.Errorf("%s refused: %v", cs.Name, err)
			}
			accepted++
		case allowed[cs.ID]:
			// RSA authentication suite against an ECDSA certificate: no
			// common suite, fails too. Nothing to assert.
		default:
			tried++
			if err == nil {
				t.Errorf("TLS 1.2 suite %s was accepted", cs.Name)
			}
		}
	}
	if tried < 10 || accepted != 3 {
		t.Errorf("tried %d disallowed suites, accepted %d allowed ECDSA suites", tried, accepted)
	}
}

func TestSuiteLists(t *testing.T) {
	for _, id := range AEADCipherSuites() {
		name := tls.CipherSuiteName(id)
		if !strings.HasPrefix(name, "TLS_ECDHE_") || !(strings.Contains(name, "_GCM_") || strings.Contains(name, "CHACHA20_POLY1305")) {
			t.Errorf("%s is not ECDHE+AEAD", name)
		}
		for _, bad := range tls.InsecureCipherSuites() {
			if bad.ID == id {
				t.Errorf("%s is on Go's insecure list", name)
			}
		}
	}
	if len(CurvePreferences()) == 0 || CurvePreferences()[0] != tls.X25519MLKEM768 {
		t.Errorf("curves %v", CurvePreferences())
	}
	if !IsSuiteAEAD(tls.TLS_AES_128_GCM_SHA256) || !IsSuiteAEAD(tls.TLS_CHACHA20_POLY1305_SHA256) {
		t.Error("TLS 1.3 suites are AEAD")
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if IsSuiteAEAD(cs.ID) {
			t.Errorf("%s reported AEAD", cs.Name)
		}
	}
}

func TestConfigPolicy(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, nil)
	cfg := s.Config()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion %#x", cfg.MinVersion)
	}
	if cfg.MaxVersion != 0 {
		t.Errorf("MaxVersion %#x: must stay at the highest supported (TLS 1.3)", cfg.MaxVersion)
	}
	if !cfg.SessionTicketsDisabled {
		t.Error("session tickets must be disabled (policy)")
	}
	if cfg.Renegotiation != tls.RenegotiateNever {
		t.Error("renegotiation must be off")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("client auth %v without --tls-client-ca", cfg.ClientAuth)
	}
	if len(cfg.CipherSuites) != len(AEADCipherSuites()) {
		t.Errorf("cipher suites %v", cfg.CipherSuites)
	}
	if s.ClientAuth() != ClientAuthNone {
		t.Error("client auth mode")
	}
}

// With session tickets off a client with a session cache still does a full
// handshake each time.
func TestNoSessionResumption(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		cfg := clientCfg(ca)
		cfg.MaxVersion = v
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		for i := 0; i < 3; i++ {
			c, err := dial(addr, cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(c, 0))
			resumed := c.ConnectionState().DidResume
			c.Close()
			if resumed {
				t.Fatalf("TLS %#x connection %d resumed a session", v, i)
			}
		}
	}
}

func TestKeyPermissionRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes: on Windows restrict the key ACL (docs/guides/tls.md)")
	}
	ca := tlstest.NewCA(t)
	f := ca.Issue(t, t.TempDir(), tlstest.Leaf{DNSNames: []string{"localhost"}})
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o700 | 0o004} {
		if err := os.Chmod(f.Key, mode); err != nil {
			t.Fatal(err)
		}
		err := CheckKeyFile(f.Key)
		if err == nil || !strings.Contains(err.Error(), "accessible by group/other") || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %04o accepted or unclear error: %v", mode, err)
		}
		if _, err := NewServerTLS(ServerOptions{CertFile: f.Cert, KeyFile: f.Key}); err == nil {
			t.Errorf("NewServerTLS accepted a key with mode %04o", mode)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		_ = os.Chmod(f.Key, mode)
		if err := CheckKeyFile(f.Key); err != nil {
			t.Errorf("mode %04o refused: %v", mode, err)
		}
	}
	// A symlink is judged by its target (Let's Encrypt live/ -> archive/).
	_ = os.Chmod(f.Key, 0o600)
	link := filepath.Join(t.TempDir(), "link.key")
	if err := os.Symlink(f.Key, link); err == nil {
		if err := CheckKeyFile(link); err != nil {
			t.Errorf("symlink to a 0600 key refused: %v", err)
		}
	}
}

func TestCheckKeyFileOtherErrors(t *testing.T) {
	if err := CheckKeyFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing key accepted")
	}
	if err := CheckKeyFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
}

func TestMismatchedPairFailsAtStartup(t *testing.T) {
	ca := tlstest.NewCA(t)
	a := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "a", DNSNames: []string{"localhost"}})
	b := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "b", DNSNames: []string{"localhost"}})
	_, err := NewServerTLS(ServerOptions{CertFile: a.Cert, KeyFile: b.Key})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched pair: %v", err)
	}
}

func TestCertificateValidation(t *testing.T) {
	ca := tlstest.NewCA(t)
	now := time.Now()
	cases := []struct {
		name string
		leaf tlstest.Leaf
		want string // "" = accepted
		warn string
	}{
		{"ok", tlstest.Leaf{DNSNames: []string{"localhost"}}, "", ""},
		{"expired", tlstest.Leaf{DNSNames: []string{"localhost"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)}, "expired on", ""},
		{"not yet valid", tlstest.Leaf{DNSNames: []string{"localhost"}, NotBefore: now.Add(time.Hour), NotAfter: now.Add(48 * time.Hour)}, "not valid before", ""},
		{"expires soon", tlstest.Leaf{DNSNames: []string{"localhost"}, NotAfter: now.Add(48 * time.Hour)}, "", "expires in"},
		{"no SAN", tlstest.Leaf{NoSAN: true}, "Subject Alternative Name", ""},
		{"client cert as server cert", tlstest.Leaf{DNSNames: []string{"localhost"}, Client: true}, "serverAuth", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := ca.Issue(t, t.TempDir(), c.leaf)
			_, info, err := LoadCertificate(f.Cert, f.Key, now)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if c.warn == "" && len(info.Warnings) != 0 {
					t.Errorf("unexpected warnings %v", info.Warnings)
				}
				if c.warn != "" && (len(info.Warnings) != 1 || !strings.Contains(info.Warnings[0], c.warn)) {
					t.Errorf("warnings %v, want %q", info.Warnings, c.warn)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestLoadCertificateInfoAndInputErrors(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Issue(t, t.TempDir(), tlstest.Leaf{DNSNames: []string{"vault.example"}, IPs: []net.IP{net.ParseIP("192.0.2.7")}})
	_, info, err := LoadCertificate(f.Cert, f.Key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.DNSNames) != 1 || len(info.IPs) != 1 || info.IPs[0] != "192.0.2.7" || info.Serial == "" || info.Subject == "" {
		t.Errorf("info %+v", info)
	}
	if _, _, err := LoadCertificate("", f.Key, time.Now()); err == nil {
		t.Error("empty cert path accepted")
	}
	if _, _, err := LoadCertificate(f.Cert, "", time.Now()); err == nil {
		t.Error("empty key path accepted")
	}
	if _, _, err := LoadCertificate(filepath.Join(t.TempDir(), "none"), f.Key, time.Now()); err == nil {
		t.Error("missing cert accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk")
	_ = os.WriteFile(junk, []byte("not pem"), 0o600)
	if _, _, err := LoadCertificate(junk, f.Key, time.Now()); err == nil {
		t.Error("garbage cert accepted")
	}
	if _, _, err := LoadCertificate(f.Cert, junk, time.Now()); err == nil {
		t.Error("garbage key accepted")
	}
	// Unreadable key (exists, mode ok, but a directory is rejected earlier;
	// a missing key is reported by CheckKeyFile).
	if _, _, err := LoadCertificate(f.Cert, filepath.Join(t.TempDir(), "nokey"), time.Now()); err == nil {
		t.Error("missing key accepted")
	}
}

func TestCheckLeafWeakAlgorithms(t *testing.T) {
	now := time.Now()
	base := func() *x509.Certificate {
		return &x509.Certificate{
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
			DNSNames: []string{"x"}, SignatureAlgorithm: x509.ECDSAWithSHA256,
		}
	}
	if _, err := checkLeaf(base(), now); err != nil {
		t.Fatal(err)
	}
	for _, alg := range []x509.SignatureAlgorithm{x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1} {
		c := base()
		c.SignatureAlgorithm = alg
		if _, err := checkLeaf(c, now); err == nil || !strings.Contains(err.Error(), "weak signature algorithm") {
			t.Errorf("%v: %v", alg, err)
		}
	}
	c := base()
	c.PublicKey = &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1500), E: 65537}
	if _, err := checkLeaf(c, now); err == nil || !strings.Contains(err.Error(), "too weak") {
		t.Errorf("weak RSA: %v", err)
	}
	c = base()
	c.PublicKey = &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2100), E: 65537}
	if _, err := checkLeaf(c, now); err != nil {
		t.Errorf("2101-bit RSA refused: %v", err)
	}
	c = base()
	c.IsCA = true
	if _, err := checkLeaf(c, now); err == nil || !strings.Contains(err.Error(), "CA certificate") {
		t.Errorf("CA as leaf: %v", err)
	}
	c = base()
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if _, err := checkLeaf(c, now); err != nil {
		t.Errorf("any EKU refused: %v", err)
	}
}

func TestLoadCAPool(t *testing.T) {
	ca := tlstest.NewCA(t)
	if _, err := LoadCAPool(ca.PEMFile); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCAPool(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing CA file accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk")
	_ = os.WriteFile(junk, []byte("nope"), 0o600)
	if _, err := LoadCAPool(junk); err == nil || !strings.Contains(err.Error(), "no valid PEM") {
		t.Errorf("junk CA: %v", err)
	}
}

// --- certificate rotation -------------------------------------------------

func serialOf(t *testing.T, addr string, cfg *tls.Config) string {
	t.Helper()
	c, err := dial(addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
}

// rotate writes a freshly issued certificate over f's files.
func rotate(t *testing.T, ca *tlstest.CA, f tlstest.Files) string {
	t.Helper()
	n := ca.Issue(t, t.TempDir(), tlstest.Leaf{DNSNames: []string{"localhost"}, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
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

func TestReloadKeepsConnectionsAndServesNewCert(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, f, logs := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	oldSerial := serialOf(t, addr, clientCfg(ca))
	if oldSerial != s.Info().Serial {
		t.Fatalf("serial %s != Info %s", oldSerial, s.Info().Serial)
	}

	// An HTTP/1.1 keep-alive connection that outlives the rotation.
	cfg := clientCfg(ca)
	cfg.NextProtos = []string{"http/1.1"}
	conn, err := dial(addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	get := func() string {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("connection dropped: %v", err)
		}
		return string(buf[:n])
	}
	if !strings.HasPrefix(get(), "HTTP/1.1 200") {
		t.Fatal("first request failed")
	}

	newSerial := rotate(t, ca, f)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(get(), "HTTP/1.1 200") {
		t.Fatal("established connection broke after reload")
	}
	if got := serialOf(t, addr, clientCfg(ca)); got != newSerial || got == oldSerial {
		t.Errorf("new connection served serial %s, want %s (old %s)", got, newSerial, oldSerial)
	}
	if !strings.Contains(logs.String(), "TLS certificate reloaded") {
		t.Errorf("no reload log:\n%s", logs)
	}
}

func TestReloadFailureKeepsOldCertificate(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, f, _ := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	oldSerial := serialOf(t, addr, clientCfg(ca))

	other := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "o", DNSNames: []string{"localhost"}})
	b, _ := os.ReadFile(other.Key)
	if err := os.WriteFile(f.Key, b, 0o600); err != nil { // key of another cert: mismatch
		t.Fatal(err)
	}
	err := s.Reload()
	if err == nil || !strings.Contains(err.Error(), "still serving the previous certificate") {
		t.Fatalf("Reload with a mismatched key: %v", err)
	}
	if got := serialOf(t, addr, clientCfg(ca)); got != oldSerial {
		t.Errorf("serial changed to %s after a failed reload", got)
	}
}

func TestWatchReloadsOnSignalAndOnFileChange(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, f, logs := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	trigger := make(chan struct{})
	done := make(chan struct{})
	go func() { s.Watch(ctx, trigger, 20*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()

	waitSerial := func(want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if serialOf(t, addr, clientCfg(ca)) == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("certificate %s never served\n%s", want, logs)
	}
	// (1) change on disk: picked up by the mtime poll, no signal.
	waitSerial(rotate(t, ca, f))

	// (2) a broken file is reported but the old certificate stays; fixing it
	// and sending the signal (SIGHUP) installs the new one.
	good, _ := os.ReadFile(f.Key)
	_ = os.WriteFile(f.Key, []byte("garbage"), 0o600)
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "ERROR: TLS reload failed") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "ERROR: TLS reload failed") {
		t.Fatalf("no reload error logged:\n%s", logs)
	}
	_ = os.WriteFile(f.Key, good, 0o600)
	_ = os.Chmod(f.Key, 0o600)
	trigger <- struct{}{}
	waitSerial(s.Info().Serial)
}

func TestWatchLogsExpiryOnce(t *testing.T) {
	ca := tlstest.NewCA(t)
	var mu sync.Mutex
	clock := time.Now()
	logs := &logSink{}
	f := ca.Localhost(t, t.TempDir())
	s, err := NewServerTLS(ServerOptions{CertFile: f.Cert, KeyFile: f.Key, Logf: logs.Logf,
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	clock = f.Leaf.NotAfter.Add(time.Minute)
	mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx, nil, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "expired on") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
	if n := strings.Count(logs.String(), "expired on"); n != 1 {
		t.Errorf("expiry logged %d times:\n%s", n, logs)
	}
}

func TestNewServerTLSWarnsAboutExpirySoon(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Issue(t, t.TempDir(), tlstest.Leaf{DNSNames: []string{"localhost"}, NotAfter: time.Now().Add(24 * time.Hour)})
	logs := &logSink{}
	if _, err := NewServerTLS(ServerOptions{CertFile: f.Cert, KeyFile: f.Key, Logf: logs.Logf}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "WARNING: TLS certificate") || !strings.Contains(logs.String(), "SIGHUP") {
		t.Errorf("no expiry warning:\n%s", logs)
	}
}

func TestNewServerTLSOptionErrors(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	if _, err := NewServerTLS(ServerOptions{CertFile: f.Cert, KeyFile: f.Key, ClientAuth: ClientAuthRequire}); err == nil {
		t.Error("client auth without a CA accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk")
	_ = os.WriteFile(junk, []byte("x"), 0o600)
	if _, err := NewServerTLS(ServerOptions{CertFile: f.Cert, KeyFile: f.Key, ClientCAFile: junk}); err == nil {
		t.Error("junk client CA accepted")
	}
	if _, err := NewServerTLS(ServerOptions{}); err == nil {
		t.Error("empty options accepted")
	}
	if m, err := ParseClientAuth(""); err != nil || m != ClientAuthNone {
		t.Error("empty mode")
	}
	for _, s := range []string{"require", "verify-if-given"} {
		if m, err := ParseClientAuth(s); err != nil || string(m) != s {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := ParseClientAuth("optional"); err == nil {
		t.Error("bad mode accepted")
	}
}

// --- mTLS -----------------------------------------------------------------

// peerHandler reports the verified client certificate's CN.
func peerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			fmt.Fprint(w, "client:"+r.TLS.PeerCertificates[0].Subject.CommonName)
			return
		}
		fmt.Fprint(w, "anonymous")
	})
}

func httpGet(t *testing.T, addr string, o ClientOptions) (string, error) {
	t.Helper()
	cl, err := NewHTTPClient(o, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("https://" + strings.Replace(addr, "127.0.0.1", "localhost", 1) + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestMTLSRequire(t *testing.T) {
	ca := tlstest.NewCA(t) // server certificate issuer
	clientCA := tlstest.NewCA(t)
	rogueCA := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, func(o *ServerOptions) { o.ClientCAFile = clientCA.PEMFile }) // mode defaults to require
	if s.ClientAuth() != ClientAuthRequire {
		t.Fatalf("default mode %q", s.ClientAuth())
	}
	addr := serve(t, s, peerHandler())
	dir := t.TempDir()
	good := clientCA.Issue(t, dir, tlstest.Leaf{Name: "good", CN: "agent-7", Client: true})
	rogue := rogueCA.Issue(t, dir, tlstest.Leaf{Name: "rogue", CN: "mallory", Client: true})
	serverAsClient := ca.Issue(t, dir, tlstest.Leaf{Name: "srv", CN: "notaclient", DNSNames: []string{"x"}})

	base := ClientOptions{CACertFile: ca.PEMFile}
	if body, err := httpGet(t, addr, ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: good.Cert, ClientKeyFile: good.Key}); err != nil || body != "client:agent-7" {
		t.Errorf("valid client certificate: %q, %v", body, err)
	}
	if body, err := httpGet(t, addr, base); err == nil {
		t.Errorf("no client certificate was accepted: %q", body)
	}
	if body, err := httpGet(t, addr, ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: rogue.Cert, ClientKeyFile: rogue.Key}); err == nil {
		t.Errorf("certificate from an untrusted CA accepted: %q", body)
	}
	if body, err := httpGet(t, addr, ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: serverAsClient.Cert, ClientKeyFile: serverAsClient.Key}); err == nil {
		t.Errorf("a serverAuth-only certificate worked as a client certificate: %q", body)
	}
}

func TestMTLSVerifyIfGiven(t *testing.T) {
	ca := tlstest.NewCA(t)
	clientCA := tlstest.NewCA(t)
	rogueCA := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, func(o *ServerOptions) {
		o.ClientCAFile = clientCA.PEMFile
		o.ClientAuth = ClientAuthVerifyIfGiven
	})
	addr := serve(t, s, peerHandler())
	dir := t.TempDir()
	good := clientCA.Issue(t, dir, tlstest.Leaf{Name: "good", CN: "agent-7", Client: true})
	rogue := rogueCA.Issue(t, dir, tlstest.Leaf{Name: "rogue", CN: "mallory", Client: true})
	base := ClientOptions{CACertFile: ca.PEMFile}
	if body, err := httpGet(t, addr, base); err != nil || body != "anonymous" {
		t.Errorf("no certificate: %q, %v", body, err)
	}
	if body, err := httpGet(t, addr, ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: good.Cert, ClientKeyFile: good.Key}); err != nil || body != "client:agent-7" {
		t.Errorf("good certificate: %q, %v", body, err)
	}
	if body, err := httpGet(t, addr, ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: rogue.Cert, ClientKeyFile: rogue.Key}); err == nil {
		t.Errorf("a presented but untrusted certificate was accepted: %q", body)
	}
}

func TestMTLSClientCAReload(t *testing.T) {
	ca := tlstest.NewCA(t)
	oldCA := tlstest.NewCA(t)
	newCA := tlstest.NewCA(t)
	caFile := filepath.Join(t.TempDir(), "clients.pem")
	copyFile := func(src string) {
		b, _ := os.ReadFile(src)
		if err := os.WriteFile(caFile, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(oldCA.PEMFile)
	s, _, _ := newServer(t, ca, func(o *ServerOptions) { o.ClientCAFile = caFile })
	addr := serve(t, s, peerHandler())
	dir := t.TempDir()
	oldC := oldCA.Issue(t, dir, tlstest.Leaf{Name: "old", CN: "old", Client: true})
	newC := newCA.Issue(t, dir, tlstest.Leaf{Name: "new", CN: "new", Client: true})
	withCert := func(f tlstest.Files) ClientOptions {
		return ClientOptions{CACertFile: ca.PEMFile, ClientCertFile: f.Cert, ClientKeyFile: f.Key}
	}
	if _, err := httpGet(t, addr, withCert(oldC)); err != nil {
		t.Fatal(err)
	}
	if _, err := httpGet(t, addr, withCert(newC)); err == nil {
		t.Fatal("new CA trusted before the reload")
	}
	copyFile(newCA.PEMFile)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := httpGet(t, addr, withCert(newC)); err != nil {
		t.Errorf("new CA not trusted after reload: %v", err)
	}
	if _, err := httpGet(t, addr, withCert(oldC)); err == nil {
		t.Error("old CA still trusted after reload")
	}
}

// --- client ---------------------------------------------------------------

func TestClientVerifiesByDefaultAndWithCacert(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello") }))
	defer ts.Close()
	// Default: the self-signed httptest certificate is NOT trusted.
	cl, err := NewHTTPClient(ClientOptions{}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Get(ts.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("self-signed server accepted by default: %v", err)
	}
	// A wrong CA fails too.
	other := tlstest.NewCA(t)
	cl, _ = NewHTTPClient(ClientOptions{CACertFile: other.PEMFile}, 5*time.Second)
	if _, err := cl.Get(ts.URL); err == nil {
		t.Fatal("wrong --cacert accepted")
	}
	// Trusting the server's own certificate works.
	pemFile := filepath.Join(t.TempDir(), "srv.pem")
	cert := ts.Certificate()
	if err := os.WriteFile(pemFile, pemOf(cert), 0o644); err != nil {
		t.Fatal(err)
	}
	cl, err = NewHTTPClient(ClientOptions{CACertFile: pemFile}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get(ts.URL)
	if err != nil {
		t.Fatalf("pinned self-signed server refused: %v", err)
	}
	resp.Body.Close()
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("client negotiated %#x", resp.TLS.Version)
	}
}

func pemOf(c *x509.Certificate) []byte {
	const hdr, ftr = "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n"
	b64 := encodeBase64(c.Raw)
	var sb strings.Builder
	sb.WriteString(hdr)
	for len(b64) > 64 {
		sb.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	sb.WriteString(b64 + "\n" + ftr)
	return []byte(sb.String())
}

func TestClientTLSConfigPolicy(t *testing.T) {
	cfg, err := ClientOptions{}.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.InsecureSkipVerify || cfg.RootCAs != nil {
		t.Errorf("client config %+v", cfg)
	}
	if len(cfg.CipherSuites) != len(AEADCipherSuites()) {
		t.Errorf("suites %v", cfg.CipherSuites)
	}
	tr, err := NewTransport(ClientOptions{})
	if err != nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.DialContext == nil || tr.Proxy != nil {
		t.Errorf("transport %+v, %v", tr, err)
	}
}

// A server that only speaks a legacy protocol is refused by the client.
func TestClientRefusesLegacyServer(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	old := legacyVersion(1)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: old, MaxVersion: old})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	cl, _ := NewHTTPClient(ClientOptions{CACertFile: ca.PEMFile}, 5*time.Second)
	_, err = cl.Get("https://" + strings.Replace(ln.Addr().String(), "127.0.0.1", "localhost", 1))
	if err == nil {
		t.Fatal("client talked to a legacy-protocol server")
	}
}

func TestClientOptionErrors(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "c", Client: true})
	if _, err := (ClientOptions{CACertFile: filepath.Join(t.TempDir(), "none")}).TLSConfig(); err == nil {
		t.Error("missing --cacert accepted")
	}
	if _, err := (ClientOptions{ClientCertFile: f.Cert}).TLSConfig(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("cert without key: %v", err)
	}
	if _, err := (ClientOptions{ClientKeyFile: f.Key}).TLSConfig(); err == nil {
		t.Error("key without cert accepted")
	}
	if _, err := (ClientOptions{ClientCertFile: f.Cert, ClientKeyFile: filepath.Join(t.TempDir(), "none")}).TLSConfig(); err == nil {
		t.Error("missing key accepted")
	}
	other := ca.Issue(t, t.TempDir(), tlstest.Leaf{Name: "d", Client: true})
	if _, err := (ClientOptions{ClientCertFile: f.Cert, ClientKeyFile: other.Key}).TLSConfig(); err == nil {
		t.Error("mismatched client pair accepted")
	}
	if _, err := NewTransport(ClientOptions{CACertFile: "/nonexistent"}); err == nil {
		t.Error("NewTransport swallowed the error")
	}
	if _, err := NewHTTPClient(ClientOptions{CACertFile: "/nonexistent"}, time.Second); err == nil {
		t.Error("NewHTTPClient swallowed the error")
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(f.Key, 0o644)
		if _, err := (ClientOptions{ClientCertFile: f.Cert, ClientKeyFile: f.Key}).TLSConfig(); err == nil || !strings.Contains(err.Error(), "group/other") {
			t.Errorf("world-readable client key: %v", err)
		}
	}
}

func TestClientOptionsFromEnv(t *testing.T) {
	env := map[string]string{EnvCACert: "/ca", EnvClientCert: "/c", EnvClientKey: "/k"}
	get := func(k string) string { return env[k] }
	o := ClientOptionsFromEnv(ClientOptions{}, get)
	if o.CACertFile != "/ca" || o.ClientCertFile != "/c" || o.ClientKeyFile != "/k" {
		t.Errorf("%+v", o)
	}
	o = ClientOptionsFromEnv(ClientOptions{CACertFile: "/flag"}, get)
	if o.CACertFile != "/flag" {
		t.Error("flag must win over environment")
	}
	t.Setenv(EnvCACert, "/from-os")
	if o := ClientOptionsFromEnv(ClientOptions{}, nil); o.CACertFile != "/from-os" {
		t.Errorf("os env: %+v", o)
	}
}

func TestCheckBaseURL(t *testing.T) {
	ok := []string{"https://vault.example:8765", "http://127.0.0.1:8765", "http://localhost:8765", "http://[::1]:8765", "HTTPS://Vault.example"}
	for _, u := range ok {
		if _, err := CheckBaseURL(u, false); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	bad := map[string]string{
		"http://vault.example:8765":     "plain http",
		"http://10.0.0.5:8765":          "plain http",
		"http://[2001:db8::1]:8765":     "plain http",
		"ftp://vault.example":           "scheme",
		"vault.example:8765":            "scheme",
		"https://":                      "no host",
		"https://user:pw@vault.example": "credentials in the URL",
		"https://bad host":              "invalid server URL",
	}
	for u, want := range bad {
		if _, err := CheckBaseURL(u, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", u, err, want)
		}
	}
	if _, err := CheckBaseURL("http://vault.example:8765", true); err != nil {
		t.Errorf("--allow-insecure-http refused: %v", err)
	}
	if !IsLoopbackHost("127.0.0.2") || !IsLoopbackHost("[::1]") || !IsLoopbackHost("LOCALHOST") || IsLoopbackHost("0.0.0.0") || IsLoopbackHost("example.com") {
		t.Error("IsLoopbackHost")
	}
}

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestServerNameMustMatchSAN(t *testing.T) {
	ca := tlstest.NewCA(t)
	s, _, _ := newServer(t, ca, nil)
	addr := serve(t, s, nil)
	cfg := clientCfg(ca)
	cfg.ServerName = "other.example"
	if c, err := dial(addr, cfg); err == nil {
		c.Close()
		t.Fatal("a certificate for localhost was accepted for other.example")
	}
	for host, ok := range map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true, "other.example": false,
		"10.9.9.9": false, "0.0.0.0": true, "::": true, "": true} {
		if err := s.CoversHost(host); (err == nil) != ok {
			t.Errorf("CoversHost(%q) = %v, want ok=%v", host, err, ok)
		}
	}
}

// A certificate that is not yet valid when it is installed becomes valid with
// the clock: the poll must retry without a file change (and log once).
func TestWatchRetriesNotYetValidCertificate(t *testing.T) {
	ca := tlstest.NewCA(t)
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	logs := &logSink{}
	f := ca.Localhost(t, t.TempDir())
	s, err := NewServerTLS(ServerOptions{CertFile: f.Cert, KeyFile: f.Key, Logf: logs.Logf, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	old := s.Info().Serial

	// A certificate valid only from an hour from now replaces the files.
	n := ca.Issue(t, t.TempDir(), tlstest.Leaf{DNSNames: []string{"localhost"},
		NotBefore: clock.Add(time.Hour), NotAfter: clock.Add(48 * time.Hour)})
	for src, dst := range map[string]string{n.Cert: f.Cert, n.Key: f.Key} {
		b, _ := os.ReadFile(src)
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx, nil, 10*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "not valid before") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "not valid before") {
		t.Fatalf("no not-yet-valid error:\n%s", logs)
	}
	time.Sleep(100 * time.Millisecond) // many polls: still logged once
	if c := strings.Count(logs.String(), "not valid before"); c != 1 {
		t.Errorf("error logged %d times:\n%s", c, logs)
	}
	if s.Info().Serial != old {
		t.Fatal("a not-yet-valid certificate was installed")
	}
	mu.Lock()
	clock = clock.Add(2 * time.Hour) // the window opens; the files do not change
	mu.Unlock()
	deadline = time.Now().Add(5 * time.Second)
	for s.Info().Serial == old && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Info().Serial != n.Leaf.SerialNumber.Text(16) {
		t.Errorf("the certificate was not installed once valid:\n%s", logs)
	}
}

func TestReadKeyFileChecksTheOpenedDescriptor(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	b, err := ReadKeyFile(f.Key)
	if err != nil || !strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatalf("ReadKeyFile: %v", err)
	}
	if _, err := ReadKeyFile(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing key read")
	}
	if _, err := ReadKeyFile(t.TempDir()); err == nil {
		t.Error("directory read as a key")
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(f.Key, 0o644)
		if b, err := ReadKeyFile(f.Key); err == nil || b != nil {
			t.Errorf("group/other-readable key returned its contents: %v", err)
		}
	}
}

// The rules apply to the Fstat result: exercised for both platform branches
// without needing a Windows host.
func TestCheckKeyInfoPlatformBranches(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o644)
	fi, _ := os.Stat(p)
	if err := checkKeyInfo(p, fi, "windows"); err != nil {
		t.Errorf("windows branch must not judge the mode bits: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := checkKeyInfo(p, fi, "linux"); err == nil {
			t.Error("0644 accepted on the unix branch")
		}
	}
	di, _ := os.Stat(dir)
	if err := checkKeyInfo(dir, di, "windows"); err == nil {
		t.Error("directory accepted")
	}
}

func TestKeyACLNotice(t *testing.T) {
	if n := KeyACLNotice("windows"); !strings.Contains(n, "ACL") || !strings.Contains(n, "NOT checked") {
		t.Errorf("windows notice %q", n)
	}
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		if KeyACLNotice(goos) != "" {
			t.Errorf("%s: unexpected notice", goos)
		}
	}
}
