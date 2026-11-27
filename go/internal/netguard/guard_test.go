package netguard

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// recordingDial captures the addresses the guard decided to connect to and
// returns one end of a pipe.
type recordingDial struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, address)
	r.mu.Unlock()
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	return a, nil
}

func (r *recordingDial) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

func TestDial_ConnectsToTheValidatedIP_NoSecondLookup(t *testing.T) {
	// DNS rebinding: the first answer is public, every later answer would be
	// the metadata address. A guard that validated one lookup and let the
	// dialler resolve again would be handed 169.254.169.254.
	res := newFakeResolver(map[string][][]string{
		"rebind.example": {{"93.184.216.34"}, {"169.254.169.254"}},
	})
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(res), WithDialFunc(rd.dial))
	conn, err := g.DialContext(context.Background(), "tcp", "rebind.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := rd.got(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dialled %v, want the validated literal 93.184.216.34:443", got)
	}
	if n := res.total(); n != 1 {
		t.Fatalf("resolver called %d times; must be exactly once (no second lookup)", n)
	}
}

func TestDial_RebindingAnswerRefusedAtFirstLookup(t *testing.T) {
	// The attacker's server answers private on the lookup the dialler makes.
	res := newFakeResolver(map[string][][]string{
		"evil.example": {{"10.0.0.5"}},
	})
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(res), WithDialFunc(rd.dial))
	_, err := g.DialContext(context.Background(), "tcp", "evil.example:80")
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != ReasonAddress {
		t.Fatalf("want address refusal, got %v", err)
	}
	if len(rd.got()) != 0 {
		t.Fatalf("a connection was attempted to %v", rd.got())
	}
	if strings.Contains(err.Error(), "10.0.0.5") {
		t.Fatalf("refusal must not reveal the resolved IP: %v", err)
	}
}

func TestDial_MixedAnswerRefusesWholeHost(t *testing.T) {
	res := newFakeResolver(map[string][][]string{
		"mixed.example":  {{"93.184.216.34", "127.0.0.1"}},
		"mixed6.example": {{"2606:4700:4700::1111", "fe80::1"}},
	})
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(res), WithDialFunc(rd.dial))
	for _, h := range []string{"mixed.example:443", "mixed6.example:443"} {
		if _, err := g.DialContext(context.Background(), "tcp", h); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want refusal, got %v", h, err)
		}
	}
	// even allowPrivate cannot save the link-local record
	g2 := newTestGuard(t, WithAllowPrivate(true), WithResolver(res), WithDialFunc(rd.dial))
	if _, err := g2.DialContext(context.Background(), "tcp", "mixed6.example:443"); !errors.Is(err, ErrBlocked) {
		t.Errorf("link-local record accepted under allowPrivate: %v", err)
	}
	if len(rd.got()) != 0 {
		t.Fatalf("connections attempted: %v", rd.got())
	}
}

func TestDial_AllowPrivateReachesLoopbackRecord(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"internal.example": {{"127.0.0.1"}}})
	rd := &recordingDial{}
	g := newTestGuard(t, WithAllowPrivate(true), WithResolver(res), WithDialFunc(rd.dial))
	c, err := g.DialContext(context.Background(), "tcp", "internal.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := rd.got(); len(got) != 1 || got[0] != "127.0.0.1:8080" {
		t.Fatalf("dialled %v", got)
	}
}

func TestDial_LiteralIPsAreCheckedWithoutLookup(t *testing.T) {
	res := newFakeResolver(nil)
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(res), WithDialFunc(rd.dial))
	for _, a := range []string{"127.0.0.1:80", "[::1]:80", "10.1.1.1:80", "169.254.169.254:80", "[::ffff:10.0.0.1]:80", "[fe80::1%eth0]:80"} {
		if _, err := g.DialContext(context.Background(), "tcp", a); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want refusal, got %v", a, err)
		}
	}
	c, err := g.DialContext(context.Background(), "tcp4", "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if res.total() != 0 {
		t.Fatal("literal IPs must not trigger DNS lookups")
	}
}

func TestDial_BadInputs(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"empty.example": {{}}, "ok.example": {{"93.184.216.34"}}})
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(res), WithDialFunc(rd.dial))
	cases := []struct {
		net, addr string
		reason    Reason
	}{
		{"udp", "ok.example:53", ReasonNetwork},
		{"unix", "/tmp/x", ReasonNetwork},
		{"tcp", "no-port", ReasonHost},
		{"tcp", "ok.example:0", ReasonPort},
		{"tcp", "ok.example:70000", ReasonPort},
		{"tcp", "ok.example:http", ReasonPort},
		{"tcp", "missing.example:80", ReasonDNS},
		{"tcp", "empty.example:80", ReasonDNS},
		{"tcp", "bad%zone.example:80", ReasonHost},
	}
	for _, c := range cases {
		_, err := g.DialContext(context.Background(), c.net, c.addr)
		var be *BlockedError
		if !errors.As(err, &be) || be.Reason != c.reason {
			t.Errorf("%s %s: want %s, got %v", c.net, c.addr, c.reason, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-resolver-detail") {
			t.Errorf("%s: resolver detail leaked: %v", c.addr, err)
		}
	}
}

func TestDial_AllowlistEnforcedAtDial(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"api.example.com": {{"93.184.216.34"}}, "other.example": {{"93.184.216.34"}}})
	rd := &recordingDial{}
	g := newTestGuard(t, WithResolver(res), WithDialFunc(rd.dial), WithAllowedHosts("api.example.com:443"))
	if c, err := g.DialContext(context.Background(), "tcp", "api.example.com:443"); err != nil {
		t.Fatal(err)
	} else {
		_ = c.Close()
	}
	for _, a := range []string{"other.example:443", "api.example.com:8443"} {
		var be *BlockedError
		if _, err := g.DialContext(context.Background(), "tcp", a); !errors.As(err, &be) || be.Reason != ReasonAllowlist {
			t.Errorf("%s: want allowlist refusal, got %v", a, err)
		}
	}
}

func TestDial_FallsBackAcrossValidatedAddresses(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"two.example": {{"93.184.216.34", "93.184.216.35"}}})
	var tried []string
	g := newTestGuard(t, WithResolver(res), WithDialFunc(func(_ context.Context, _, a string) (net.Conn, error) {
		tried = append(tried, a)
		if strings.HasPrefix(a, "93.184.216.34") {
			return nil, errors.New("refused")
		}
		c, _ := net.Pipe()
		return c, nil
	}))
	c, err := g.DialContext(context.Background(), "tcp", "two.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(tried) != 2 || tried[1] != "93.184.216.35:443" {
		t.Fatalf("tried %v", tried)
	}
	// all addresses failing returns the last dial error
	g2 := newTestGuard(t, WithResolver(res), WithDialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("down")
	}))
	_, err = g2.DialContext(context.Background(), "tcp", "two.example:443")
	if err == nil || strings.Contains(err.Error(), "93.184") || !strings.Contains(err.Error(), "two.example") {
		t.Fatalf("connect failure must name the host, not the resolved IP: %v", err)
	}
	if u := errors.Unwrap(err); u == nil || u.Error() != "down" {
		t.Fatalf("cause must stay reachable via Unwrap: %v", u)
	}
	// a cancelled context stops the fallback loop
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := 0
	g3 := newTestGuard(t, WithResolver(res), WithDialFunc(func(context.Context, string, string) (net.Conn, error) {
		n++
		return nil, errors.New("down")
	}))
	_, _ = g3.DialContext(ctx, "tcp", "two.example:443")
	if n != 1 {
		t.Fatalf("dial attempts after cancel: %d", n)
	}
}

func TestControlCheck_DefenceInDepth(t *testing.T) {
	// The default dialler re-checks the literal address in Control, so even if
	// the resolve step were bypassed the connect would be refused.
	g := newTestGuard(t)
	for _, a := range []string{"127.0.0.1:80", "10.0.0.1:80", "[::1]:80", "169.254.169.254:80"} {
		if err := g.controlCheck(a); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if err := g.controlCheck("93.184.216.34:443"); err != nil {
		t.Errorf("public address refused: %v", err)
	}
	for _, a := range []string{"nonsense", "host.example:80"} {
		if err := g.controlCheck(a); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: %v", a, err)
		}
	}
	// And through a real net.Dialer: dialling loopback with the stock guard
	// fails in Control, before any connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if _, err := g.DialContext(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback dial: %v", err)
	}
	gp := newTestGuard(t, WithAllowPrivate(true))
	c, err := gp.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("allowPrivate loopback dial: %v", err)
	}
	_ = c.Close()
	if err := gp.CheckIP(net.ParseIP("127.0.0.1")); err != nil {
		t.Errorf("CheckIP allowPrivate: %v", err)
	}
	if err := g.CheckIP(net.ParseIP("127.0.0.1")); err == nil {
		t.Error("CheckIP default accepted loopback")
	}
}
