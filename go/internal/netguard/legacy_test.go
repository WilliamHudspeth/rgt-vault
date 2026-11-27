package netguard

import (
	"context"
	"strings"
	"testing"
)

// The original NewDialer API keeps its behaviour (existing callers: TUI, MCP,
// CLI); the only addition is that unspecified and multicast addresses are now
// refused even with allowRemote.
func TestLegacyDialer_UnspecifiedAndMulticastRefused(t *testing.T) {
	for _, allowRemote := range []bool{false, true} {
		d := NewDialer(allowRemote)
		for _, addr := range []string{"0.0.0.0:80", "[::]:80", "224.0.0.1:80", "[ff02::1]:80"} {
			_, err := d.DialContext(context.Background(), "tcp", addr)
			if err == nil {
				t.Fatalf("allowRemote=%v %s: expected refusal", allowRemote, addr)
			}
			if !strings.Contains(err.Error(), "netguard:") {
				t.Fatalf("allowRemote=%v %s: refusal did not come from netguard: %v", allowRemote, addr, err)
			}
		}
	}
}

func TestLegacyDialer_RemoteStillPermittedWhenAllowed(t *testing.T) {
	// RFC1918/CGNAT remain reachable through the legacy dialer when allowRemote
	// is set (a LAN or tailnet vault server). Control runs before connect, so
	// an unroutable target fails with a network error, not a netguard one.
	d := NewDialer(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50_000_000)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "10.255.255.1:80")
	if err != nil && strings.Contains(err.Error(), "netguard:") {
		t.Fatalf("legacy allowRemote dialer must not refuse RFC1918: %v", err)
	}
}
