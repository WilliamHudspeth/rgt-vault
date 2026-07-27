package netguard

import (
	"context"
	"net"
	"strings"
	"testing"
)

// startLoopbackListener returns a listener on 127.0.0.1 and its address, so
// tests can dial a real local port through the guarded dialer.
func startLoopbackListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().String()
}

func TestDialer_AllowsLoopbackByDefault(t *testing.T) {
	_, addr := startLoopbackListener(t)
	d := NewDialer(false)
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("expected loopback dial to succeed, got: %v", err)
	}
	conn.Close()
}

func TestDialer_RejectsLinkLocalAlways(t *testing.T) {
	for _, allowRemote := range []bool{false, true} {
		d := NewDialer(allowRemote)
		_, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:80")
		if err == nil {
			t.Fatalf("allowRemote=%v: expected link-local/metadata address to be rejected", allowRemote)
		}
		if !strings.Contains(err.Error(), "link-local") {
			t.Fatalf("allowRemote=%v: expected link-local rejection message, got: %v", allowRemote, err)
		}
	}
}

func TestDialer_RejectsNonLoopbackByDefault(t *testing.T) {
	d := NewDialer(false)
	// 10.x is unroutable from this sandbox regardless, but Control rejects
	// before any connection attempt is made, so this must fail fast with
	// our own error, not a network timeout.
	_, err := d.DialContext(context.Background(), "tcp", "10.255.255.1:80")
	if err == nil {
		t.Fatal("expected non-loopback address to be rejected when allowRemote=false")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected non-loopback rejection message, got: %v", err)
	}
}

func TestDialer_PermitsNonLoopbackWhenAllowed(t *testing.T) {
	_, addr := startLoopbackListener(t)
	// Loopback still succeeds under allowRemote=true (it's a superset).
	d := NewDialer(true)
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("expected loopback dial to succeed under allowRemote=true, got: %v", err)
	}
	conn.Close()
}
