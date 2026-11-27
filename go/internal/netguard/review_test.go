package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Regression tests for the Neon review findings (RGT-355/361 hardening).

func TestAllowlist_EmptyListDeniesEverything(t *testing.T) {
	g := newTestGuard(t, WithAllowedHosts())
	if _, err := g.CheckURL("https://example.com/"); err == nil {
		t.Fatal("an empty allow-list must fail closed")
	}
	rd := &recordingDial{}
	g2 := newTestGuard(t, WithAllowedHosts(), WithResolver(publicResolver()), WithDialFunc(rd.dial))
	if _, err := g2.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrBlocked) || len(rd.got()) != 0 {
		t.Fatalf("dial must be refused: %v %v", err, rd.got())
	}
}

func TestAllowlist_IPv6CanonicalForms(t *testing.T) {
	for _, entry := range []string{"[2001:4860:4860::8888]:443", "[2001:4860:4860:0:0:0:0:8888]:443"} {
		g := newTestGuard(t, WithAllowedHosts(entry), WithResolver(newFakeResolver(nil)), WithDialFunc((&recordingDial{}).dial))
		for _, u := range []string{"https://[2001:4860:4860::8888]/", "https://[2001:4860:4860:0:0:0:0:8888]/"} {
			if _, err := g.CheckURL(u); err != nil {
				t.Errorf("entry %s url %s: %v", entry, u, err)
			}
		}
		if c, err := g.DialContext(context.Background(), "tcp", "[2001:4860:4860:0:0:0:0:8888]:443"); err != nil {
			t.Errorf("entry %s dial: %v", entry, err)
		} else {
			_ = c.Close()
		}
	}
}

func TestRedirect_CredentialsStayStrippedAfterLeavingOrigin(t *testing.T) {
	// example.com -> sub.example.com -> example.com. Go would re-copy the
	// original Authorization on the last hop (it treats a subdomain as
	// trusted); the guard must not.
	var endAuth, endReferer, midReferer string
	var endSeen bool
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://sub.example.com/mid?token=abc", http.StatusFound)
	})
	mux.HandleFunc("/mid", func(w http.ResponseWriter, r *http.Request) {
		midReferer = r.Header.Get("Referer")
		http.Redirect(w, r, "http://example.com/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		endSeen = true
		endAuth, endReferer = r.Header.Get("Authorization"), r.Header.Get("Referer")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res := newFakeResolver(map[string][][]string{"example.com": {{"93.184.216.34"}}, "sub.example.com": {{"93.184.216.35"}}})
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(3), WithResolver(res), WithDialFunc(pinDial(hostPort(t, srv), &recordingDial{})))
	resp, err := get(t, g.Client(), "http://example.com/start", map[string]string{"Authorization": "Bearer tok"})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !endSeen {
		t.Fatal("chain did not complete")
	}
	if endAuth != "" {
		t.Fatalf("Authorization re-attached after the chain left the origin: %q", endAuth)
	}
	if midReferer != "" || endReferer != "" {
		t.Fatalf("Referer must not carry the previous URL: %q %q", midReferer, endReferer)
	}
}

func TestRedirect_DowngradeAnywhereInChainAndLongLocation(t *testing.T) {
	g := newTestGuard(t, WithAllowInsecureHTTP(true), WithMaxRedirects(5))
	mk := func(s string) *http.Request {
		r, _ := http.NewRequest("GET", s, nil)
		return r
	}
	// http -> https -> http: the second hop is a downgrade even though the
	// first request was plain http.
	err := g.checkRedirect(mk("http://example.com/c"), []*http.Request{mk("http://example.com/a"), mk("https://example.com/b")})
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != ReasonDowngrade {
		t.Fatalf("want downgrade refusal, got %v", err)
	}
	// hop URLs get the same length/character checks as the first request
	long := "https://example.com/" + strings.Repeat("a", MaxURLLength)
	err = g.checkRedirect(mk(long), []*http.Request{mk("https://example.com/a")})
	if !errors.As(err, &be) || be.Reason != ReasonURL {
		t.Fatalf("long redirect target must be refused: %v", err)
	}
}

func TestClient_ResponseHeaderTimeoutFollowsTimeout(t *testing.T) {
	g := newTestGuard(t, WithTimeout(90*time.Second))
	tr := g.Client().Transport.(*http.Transport)
	if tr.ResponseHeaderTimeout != 90*time.Second {
		t.Fatalf("ResponseHeaderTimeout %v must follow WithTimeout, not a hidden 15s cap", tr.ResponseHeaderTimeout)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestDialTimeoutStaysVisibleThroughClientErrors(t *testing.T) {
	g := newTestGuard(t, WithResolver(publicResolver()), WithTimeout(time.Minute),
		WithDialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, timeoutErr{} }))
	_, err := get(t, g.Client(), "https://example.com/", nil)
	var ue *url.Error
	if !errors.As(err, &ue) || !ue.Timeout() {
		t.Fatalf("a dial timeout must still report Timeout() through *url.Error: %v", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("net.Error timeout lost: %v", err)
	}
}
