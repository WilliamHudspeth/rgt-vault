package gateway

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/tlstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/transport"
)

func TestCheckListen(t *testing.T) {
	for _, a := range []string{"127.0.0.1:8088", "localhost:8088", "[::1]:8088"} {
		if err := CheckListen(a, false, false); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	if err := CheckListen("0.0.0.0:8088", true, false); err != nil {
		t.Errorf("TLS bind refused: %v", err)
	}
	if err := CheckListen("0.0.0.0:8088", false, true); err != nil {
		t.Errorf("explicit override refused: %v", err)
	}
	err := CheckListen(":8088", false, false)
	if err == nil || !strings.Contains(err.Error(), "-tls-cert") {
		t.Errorf("plain non-loopback: %v", err)
	}
}

func TestValidateBackendURL(t *testing.T) {
	for _, u := range []string{"https://py.internal:8080", "http://localhost:8080", "http://127.0.0.1:8099/"} {
		if err := ValidateBackendURL("python", u, false); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	err := ValidateBackendURL("go", "http://10.0.0.5:8099", false)
	if err == nil || !strings.Contains(err.Error(), "go backend") || !strings.Contains(err.Error(), "plain http") {
		t.Errorf("remote plain http: %v", err)
	}
	if err := ValidateBackendURL("go", "http://10.0.0.5:8099", true); err != nil {
		t.Errorf("override: %v", err)
	}
	if err := ValidateBackendURL("go", "https://x/a/../b", false); err == nil {
		t.Error("path traversal accepted")
	}
	if err := ValidateBackendURL("go", "nonsense", false); err == nil {
		t.Error("nonsense accepted")
	}
}

func TestNewHTTPServerOptions(t *testing.T) {
	srv, tl, err := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler(), TLSOptions{}, nil)
	if err != nil || tl != nil || srv.TLSConfig != nil || srv.ReadHeaderTimeout == 0 {
		t.Errorf("plain: %+v %v %v", srv, tl, err)
	}
	bad := []TLSOptions{{CertFile: "c"}, {KeyFile: "k"}, {ClientCAFile: "ca"}, {ClientAuth: "require"},
		{CertFile: "/no/c", KeyFile: "/no/k", ClientAuth: "bogus"}, {CertFile: "/no/c", KeyFile: "/no/k"}}
	for _, o := range bad {
		if _, _, err := NewHTTPServer("x", nil, o, nil); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

// The gateway serves TLS 1.2+ and proxies to an https backend that the
// transport verifies against the pinned CA.
func TestGatewayTLSListenerAndVerifiedBackend(t *testing.T) {
	ca := tlstest.NewCA(t)
	// An https backend with a certificate from ca.
	bf := ca.Localhost(t, t.TempDir())
	bs, err := transport.NewServerTLS(transport.ServerOptions{CertFile: bf.Cert, KeyFile: bf.Key})
	if err != nil {
		t.Fatal(err)
	}
	bln, _ := net.Listen("tcp", "127.0.0.1:0")
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "from-backend") }),
		TLSConfig: bs.Config(), ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = backend.ServeTLS(bln, "", "") }()
	defer backend.Close()
	_, bport, _ := net.SplitHostPort(bln.Addr().String())
	backendURL := "https://localhost:" + bport

	gw, err := NewGateway(backendURL, backendURL, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Without the CA the proxy cannot verify the backend (no silent fallback).
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code == 200 {
		t.Fatalf("unverified backend served: %d %s", rec.Code, rec.Body)
	}
	tr, err := transport.NewTransport(transport.ClientOptions{CACertFile: ca.PEMFile})
	if err != nil {
		t.Fatal(err)
	}
	gw.SetBackendTransport(nil) // nil keeps the default
	gw.SetBackendTransport(tr)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 200 || rec.Body.String() != "from-backend" {
		t.Fatalf("pinned backend: %d %q", rec.Code, rec.Body)
	}

	// The gateway's own listener over TLS.
	gf := ca.Localhost(t, t.TempDir())
	srv, tl, err := NewHTTPServer("127.0.0.1:0", gw, TLSOptions{CertFile: gf.Cert, KeyFile: gf.Key}, nil)
	if err != nil || tl == nil {
		t.Fatal(err)
	}
	srv.ErrorLog = log.New(io.Discard, "", 0)
	gln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = srv.ServeTLS(gln, "", "") }()
	defer srv.Shutdown(context.Background())
	cl, _ := transport.NewHTTPClient(transport.ClientOptions{CACertFile: ca.PEMFile}, 5*time.Second)
	_, gport, _ := net.SplitHostPort(gln.Addr().String())
	resp, err := cl.Get("https://localhost:" + gport + "/y")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "from-backend" || resp.TLS.Version < 0x0303 {
		t.Errorf("through the TLS gateway: %q tls=%#x", b, resp.TLS.Version)
	}
}
