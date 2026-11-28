package netguard

import (
	"context"
	"net/url"
)

// HostCheck is a per-request destination check that travels on the request
// context (RGT-523). The guard consults it as a backstop at the two points
// where the URL that was validated could differ from what is actually used:
// the dial (host:port the transport asks for) and every redirect hop.
type HostCheck interface {
	// CheckDial is called in DialContext with the host and port the
	// transport is about to connect to, before DNS. A non-nil error refuses
	// the connection.
	CheckDial(ctx context.Context, host string, port int) error
	// CheckRedirect is called for every redirect hop that the guard would
	// otherwise follow, before the guard's own checks. first is the original
	// request URL, next the hop.
	CheckRedirect(ctx context.Context, first, next *url.URL) error
}

type hostCheckKey struct{}

// WithHostCheck returns ctx carrying hc. A nil hc returns ctx unchanged.
func WithHostCheck(ctx context.Context, hc HostCheck) context.Context {
	if hc == nil {
		return ctx
	}
	return context.WithValue(ctx, hostCheckKey{}, hc)
}

func hostCheckFrom(ctx context.Context) HostCheck {
	if ctx == nil {
		return nil
	}
	hc, _ := ctx.Value(hostCheckKey{}).(HostCheck)
	return hc
}
