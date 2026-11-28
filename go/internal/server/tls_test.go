package server

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/tlstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/transport"
)

func TestTLSSettingsValidate(t *testing.T) {
	ok := []TLSSettings{
		{},
		{CertFile: "c", KeyFile: "k"},
		{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"},
		{CertFile: "c", KeyFile: "k", ClientCAFile: "ca", ClientAuth: "require"},
		{CertFile: "c", KeyFile: "k", ClientCAFile: "ca", ClientAuth: "verify-if-given"},
	}
	for i, s := range ok {
		if err := s.Validate(); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	bad := map[string]TLSSettings{
		"together":              {CertFile: "c"},
		"together ":             {KeyFile: "k"},
		"need --tls-cer":        {ClientCAFile: "ca"},
		"need --tls-cer ":       {ClientAuth: "require"},
		"--tls-client-auth":     {CertFile: "c", KeyFile: "k", ClientCAFile: "ca", ClientAuth: "maybe"},
		"needs --tls-client-ca": {CertFile: "c", KeyFile: "k", ClientAuth: "require"},
	}
	for want, s := range bad {
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%+v: err = %v, want %q", s, err, want)
		}
	}
	if (TLSSettings{}).Enabled() || !(TLSSettings{CertFile: "c", KeyFile: "k"}).Enabled() {
		t.Error("Enabled")
	}
}

func TestCheckBind(t *testing.T) {
	// Loopback: always fine, no warning.
	for _, h := range []string{"127.0.0.1", "localhost", "::1", "[::1]"} {
		for _, tlsOn := range []bool{false, true} {
			if w, err := CheckBind(h, tlsOn, false); err != nil || w != "" {
				t.Errorf("%s tls=%v: %q, %v", h, tlsOn, w, err)
			}
		}
	}
	// Non-loopback with TLS: fine.
	if w, err := CheckBind("0.0.0.0", true, false); err != nil || w != "" {
		t.Errorf("0.0.0.0 over TLS: %q, %v", w, err)
	}
	// Non-loopback without TLS: refused, naming every way out.
	for _, h := range []string{"0.0.0.0", "10.1.2.3", "vault.example", "::"} {
		_, err := CheckBind(h, false, false)
		if err == nil || !strings.Contains(err.Error(), "--tls-cert") || !strings.Contains(err.Error(), "--allow-insecure-non-loopback") {
			t.Errorf("%s: %v", h, err)
		}
	}
	// ... unless explicitly overridden, which is loud.
	w, err := CheckBind("0.0.0.0", false, true)
	if err != nil || !strings.Contains(w, "INSECURE") || !strings.Contains(w, "PLAIN HTTP") {
		t.Errorf("override: %q, %v", w, err)
	}
}

type safeLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *safeLog) Logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.WriteString(strings.TrimSpace(strings.ReplaceAll(f, "%", "")) + "\n")
}

func TestNewTLSServeAndHSTS(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	lg := &safeLog{}
	tl, err := NewTLS(TLSSettings{CertFile: f.Cert, KeyFile: f.Key}, lg.Logf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           HSTSHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() { done <- Serve(srv, ln, tl) }()
	defer func() {
		_ = srv.Shutdown(context.Background())
		<-done
	}()

	cl, err := transport.NewHTTPClient(transport.ClientOptions{CACertFile: ca.PEMFile}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get("https://localhost:" + strings.Split(ln.Addr().String(), ":")[1] + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != HSTSValue || !strings.HasPrefix(got, "max-age=") {
		t.Errorf("HSTS = %q", got)
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("TLS version %#x", resp.TLS.Version)
	}
	// Plain HTTP to the TLS port must not be served.
	plain := &http.Client{Timeout: 5 * time.Second}
	if r, err := plain.Get("http://" + ln.Addr().String() + "/"); err == nil {
		defer r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Error("plain HTTP answered 200 on the TLS port")
		}
	}
}

func TestNewTLSErrors(t *testing.T) {
	if _, err := NewTLS(TLSSettings{CertFile: "c"}, nil); err == nil {
		t.Error("cert without key accepted")
	}
	if _, err := NewTLS(TLSSettings{CertFile: "/no/c", KeyFile: "/no/k", ClientAuth: "bogus"}, nil); err == nil {
		t.Error("bad client auth accepted")
	}
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	tl, err := NewTLS(TLSSettings{CertFile: f.Cert, KeyFile: f.Key, ClientCAFile: ca.PEMFile, ClientAuth: "verify-if-given"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tl.ClientAuth() != transport.ClientAuthVerifyIfGiven {
		t.Errorf("mode %q", tl.ClientAuth())
	}
}
