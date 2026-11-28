package netguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

type recordingCheck struct {
	mu        sync.Mutex
	dials     []string
	redirects []string
	refuse    string // host to refuse at dial
	refuseHop bool
}

var errRefusedByCheck = errors.New("refused by host check")

func (c *recordingCheck) CheckDial(_ context.Context, host string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dials = append(c.dials, fmt.Sprintf("%s:%d", host, port))
	if host == c.refuse {
		return errRefusedByCheck
	}
	return nil
}

func (c *recordingCheck) CheckRedirect(_ context.Context, first, next *url.URL) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.redirects = append(c.redirects, first.Host+"->"+next.Host)
	if c.refuseHop {
		return errRefusedByCheck
	}
	return nil
}

// TestHostCheckReachesDialAndRedirect pins that a HostCheck on the request
// context reaches Guard.DialContext and checkRedirect with the Go version in
// use (net/http hands the request context's values to the dialer). RGT-523
// relies on it for its dial and redirect backstops.
func TestHostCheckReachesDialAndRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rd := &recordingDial{}
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(3), WithResolver(publicResolver()), WithDialFunc(pinDial(hostPort(t, srv), rd)))

	do := func(hc HostCheck, u string) error {
		req, _ := http.NewRequestWithContext(WithHostCheck(context.Background(), hc), http.MethodGet, u, nil)
		resp, err := g.Client().Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	hc := &recordingCheck{}
	if err := do(hc, "http://example.com/a"); err != nil {
		t.Fatal(err)
	}
	if len(hc.dials) == 0 || hc.dials[0] != "example.com:80" {
		t.Fatalf("CheckDial not reached: %v", hc.dials)
	}
	if len(hc.redirects) != 1 || hc.redirects[0] != "example.com->example.com" {
		t.Fatalf("CheckRedirect not reached: %v", hc.redirects)
	}
	// A refusal at the dial stops the connection.
	rd.addrs = nil
	if err := do(&recordingCheck{refuse: "example.com"}, "http://example.com/b"); !errors.Is(err, errRefusedByCheck) {
		t.Fatalf("dial refusal: %v", err)
	}
	if len(rd.addrs) != 0 {
		t.Fatalf("dialled %v after a refusal", rd.addrs)
	}
	// A refusal at a hop stops the redirect.
	if err := do(&recordingCheck{refuseHop: true}, "http://example.com/a"); !errors.Is(err, errRefusedByCheck) {
		t.Fatalf("redirect refusal: %v", err)
	}
	// No check on the context: unchanged behaviour.
	if err := do(nil, "http://example.com/a"); err != nil {
		t.Fatal(err)
	}
	if hostCheckFrom(nil) != nil { //nolint:staticcheck // nil context is handled
		t.Fatal("nil ctx")
	}
}
