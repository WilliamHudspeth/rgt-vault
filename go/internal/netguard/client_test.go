package netguard

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// pinDial connects every validated address to a fixed real listener, so the
// tests can give a "public" name/IP an actual server without leaving the
// machine. It records what the guard decided to dial.
func pinDial(target string, seen *recordingDial) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		seen.mu.Lock()
		seen.addrs = append(seen.addrs, address)
		seen.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
}

// publicResolver maps names to public addresses (never really contacted).
func publicResolver() *fakeResolver {
	return newFakeResolver(map[string][][]string{
		"example.com":      {{"93.184.216.34"}},
		"other.example":    {{"93.184.216.35"}},
		"internal.example": {{"10.0.0.5"}},
		"meta.example":     {{"169.254.169.254"}},
	})
}

func hostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
}

func get(t *testing.T, c *http.Client, url string, hdr map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func TestClient_RedirectsRefusedByDefault(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	rd := &recordingDial{}
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))
	resp, err := get(t, g.Client(), "http://example.com/start", map[string]string{"Authorization": "Bearer tok"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want the 302 returned untouched", resp.StatusCode)
	}
	if hits.Load() != 1 || len(rd.got()) != 1 {
		t.Fatalf("hits=%d dials=%v: the redirect target must never be contacted", hits.Load(), rd.got())
	}
}

func TestClient_RedirectHopsAreRevalidated(t *testing.T) {
	cases := []struct {
		name, location string
		reason         Reason
	}{
		{"metadata literal", "http://169.254.169.254/latest/meta-data/", ReasonAddress},
		{"rfc1918 literal", "http://10.0.0.5/admin", ReasonAddress},
		{"loopback literal", "http://127.0.0.1:1/", ReasonAddress},
		{"mapped literal", "http://[::ffff:10.0.0.5]/", ReasonAddress},
		{"hostname resolving to private (rebinding at hop)", "http://internal.example/", ReasonAddress},
		{"hostname resolving to metadata", "http://meta.example/", ReasonAddress},
		{"userinfo", "http://user:pw@example.com/", ReasonUserinfo},
		{"ftp scheme", "ftp://example.com/", ReasonScheme},
		{"numeric host", "http://2130706433/", ReasonHost},
		{"off allow-list", "http://other.example/", ReasonAllowlist},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var other atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/hop" {
					other.Add(1)
				}
				http.Redirect(w, r, c.location, http.StatusFound)
			}))
			defer srv.Close()
			rd := &recordingDial{}
			g := newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(3), WithAllowedHosts("example.com", "internal.example", "meta.example", "10.0.0.5", "127.0.0.1", "169.254.169.254", "[::ffff:10.0.0.5]", "ftp.example"),
				WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))
			if c.name == "off allow-list" {
				g = newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(3), WithAllowedHosts("example.com"),
					WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))
			}
			_, err := get(t, g.Client(), "http://example.com/hop", nil)
			var be *BlockedError
			if !errors.As(err, &be) {
				t.Fatalf("want a guard refusal, got %v", err)
			}
			if be.Reason != c.reason {
				t.Fatalf("reason %s want %s (%v)", be.Reason, c.reason, err)
			}
			if got := rd.got(); len(got) != 1 {
				t.Fatalf("only the first hop may be dialled, got %v", got)
			}
		})
	}
}

func TestClient_FollowsBoundedRedirectsAndStripsCredentials(t *testing.T) {
	var sawAuth, sawCookie []string
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		http.Redirect(w, r, "/c", http.StatusFound)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, "done")
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	mux.HandleFunc("/cross", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example/landing", http.StatusFound)
	})
	mux.HandleFunc("/landing", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = append(sawAuth, "cross:"+r.Header.Get("Authorization"))
		sawCookie = append(sawCookie, r.Header.Get("Cookie"))
		_, _ = fmt.Fprint(w, "landed")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rd := &recordingDial{}
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(3), WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))
	hdr := map[string]string{"Authorization": "Bearer tok", "Cookie": "s=1"}

	resp, err := get(t, g.Client(), "http://example.com/a", hdr)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || len(sawAuth) != 2 || sawAuth[0] != "Bearer tok" || sawAuth[1] != "Bearer tok" {
		t.Fatalf("same-origin hops keep Authorization: status=%d auth=%v", resp.StatusCode, sawAuth)
	}

	sawAuth = nil
	resp, err = get(t, g.Client(), "http://example.com/cross", hdr)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(sawAuth) != 1 || sawAuth[0] != "cross:" || sawCookie[0] != "" {
		t.Fatalf("cross-origin hop must drop Authorization and Cookie: auth=%v cookie=%v", sawAuth, sawCookie)
	}

	_, err = get(t, g.Client(), "http://example.com/loop", nil)
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != ReasonRedirect {
		t.Fatalf("redirect loop must hit the bound: %v", err)
	}
}

func TestClient_RefusesHTTPSToHTTPDowngrade(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/plain", http.StatusFound)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	rd := &recordingDial{}
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(2), WithRootCAs(pool), WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))
	_, err := get(t, g.Client(), "https://example.com/start", nil)
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != ReasonDowngrade {
		t.Fatalf("want downgrade refusal, got %v", err)
	}
}

func TestClient_TLSVerificationIsOn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "secure") }))
	defer srv.Close()
	addr := hostPort(t, srv)

	// 1. self-signed server, system roots: verification FAILS.
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(publicResolver()), WithDialFunc(pinDial(addr, rd)))
	_, err := get(t, g.Client(), "https://example.com/", nil)
	if err == nil {
		t.Fatal("self-signed certificate was accepted: TLS verification is off")
	}
	var unk x509.UnknownAuthorityError
	if !errors.As(err, &unk) {
		t.Fatalf("want x509.UnknownAuthorityError, got %T: %v", err, err)
	}

	// 2. the same server with its certificate in a custom pool: works.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	g = newTestGuard(t, WithRootCAs(pool), WithResolver(publicResolver()), WithDialFunc(pinDial(addr, rd)))
	resp, err := get(t, g.Client(), "https://example.com/", nil)
	if err != nil {
		t.Fatalf("custom CA pool: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// 3. trusted CA but wrong name: hostname verification FAILS.
	_, err = get(t, g.Client(), "https://other.example/", nil)
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("want x509.HostnameError for a name the certificate does not cover, got %T: %v", err, err)
	}

	// 4. the pinned dial really did go to the validated literal addresses.
	for _, a := range rd.got() {
		if !strings.HasPrefix(a, "93.184.216.") {
			t.Fatalf("dialled %s, want only validated public literals", a)
		}
	}
}

func TestClient_TLSConfigFloor(t *testing.T) {
	g := newTestGuard(t)
	tr := g.Client().Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must never be set")
	}
	if tr.TLSClientConfig.MinVersion < 0x0303 { // TLS 1.2
		t.Fatalf("MinVersion %#x below TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
	if tr.Proxy != nil {
		t.Fatal("proxy must be disabled")
	}
	if !tr.DisableKeepAlives || !tr.DisableCompression {
		t.Fatal("keep-alives and compression must be off")
	}
}

func TestClient_IgnoresProxyEnvironment(t *testing.T) {
	// An HTTP(S)_PROXY would move the dial target to the proxy and so bypass
	// the policy. The guard's client must not look at the environment.
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHits.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "direct") }))
	defer srv.Close()
	rd := &recordingDial{}
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))
	resp, err := get(t, g.Client(), "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if proxyHits.Load() != 0 {
		t.Fatal("request went through the environment proxy")
	}
	if got := rd.got(); len(got) != 1 || got[0] != "93.184.216.34:80" {
		t.Fatalf("dialled %v", got)
	}
}

func TestClient_PrivateTargetBlockedOnTheWire(t *testing.T) {
	// A real loopback server: without allowPrivate it must never be contacted.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	g := newTestGuard(t, WithAllowInsecureHTTP(true))
	_, err := get(t, g.Client(), srv.URL, nil)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("want refusal, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("blocked request reached the server")
	}
	gp := newTestGuard(t, WithAllowInsecureHTTP(true), WithAllowPrivate(true))
	resp, err := get(t, gp.Client(), srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("allowPrivate request did not arrive")
	}
}

func TestClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer srv.Close()
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithAllowPrivate(true), WithTimeout(150*time.Millisecond))
	start := time.Now()
	_, err := get(t, g.Client(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not enforced: %v", time.Since(start))
	}
}

func TestOrigin(t *testing.T) {
	mk := func(s string) *http.Request {
		r, _ := http.NewRequest("GET", s, nil)
		return r
	}
	if origin(mk("HTTP://Example.com/x").URL) != "http://example.com:80" {
		t.Error("http default port")
	}
	if origin(mk("https://example.com/x").URL) != "https://example.com:443" {
		t.Error("https default port")
	}
	if origin(mk("https://example.com:8443/").URL) == origin(mk("https://example.com/").URL) {
		t.Error("ports must distinguish origins")
	}
}
