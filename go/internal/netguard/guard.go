package netguard

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Resolver is the DNS seam. *net.Resolver satisfies it. Tests substitute a
// fake to prove the address that was validated is the address that is dialled
// (no second lookup, hence no DNS rebinding window).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DialFunc is the transport seam under the guard: it receives a literal
// "ip:port" that has already been validated. The default is a net.Dialer
// whose Control hook re-checks the address (defence in depth).
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Guard is a configured outbound policy: URL validation, IP-range policy, an
// optional host:port allow-list, and an *http.Client (see Client) that applies
// the policy at dial time and on every redirect hop. A Guard is immutable
// after NewGuard and safe for concurrent use.
type Guard struct {
	allowPrivate   bool
	allowInsecure  bool
	allow          []allowEntry
	allowSet       bool // WithAllowedHosts was used (an empty list then denies everything)
	resolver       Resolver
	rootCAs        *x509.CertPool
	maxRedirects   int
	timeout        time.Duration
	dialTimeout    time.Duration
	baseDial       DialFunc
	maxHeaderBytes int64
}

// Option configures NewGuard.
type Option func(*Guard) error

// WithAllowPrivate lifts the loopback/RFC1918/CGNAT/ULA/documentation range
// blocks. Link-local (incl. the 169.254.169.254 metadata address), multicast,
// unspecified and reserved space stay blocked regardless.
func WithAllowPrivate(v bool) Option {
	return func(g *Guard) error { g.allowPrivate = v; return nil }
}

// WithAllowInsecureHTTP permits http:// URLs. The default refuses them: a
// guard is used for requests that carry a credential, which must not travel
// in clear text.
func WithAllowInsecureHTTP(v bool) Option {
	return func(g *Guard) error { g.allowInsecure = v; return nil }
}

// WithAllowedHosts restricts requests to an allow-list. Entries are
// "host" (any port), "host:port" (exact), or the same with a leading "*."
// wildcard (any subdomain, not the apex). IPv6 literals are bracketed:
// "[2001:db8::1]:443". The allow-list narrows, it never widens: a listed host
// that resolves to a forbidden range is still refused.
//
// Calling it with no entries installs an empty allow-list, which denies every
// host (fail closed).
func WithAllowedHosts(entries ...string) Option {
	return func(g *Guard) error {
		g.allowSet = true
		for _, e := range entries {
			ent, err := parseAllowEntry(e)
			if err != nil {
				return err
			}
			g.allow = append(g.allow, ent)
		}
		return nil
	}
}

// WithResolver replaces the DNS resolver (test seam).
func WithResolver(r Resolver) Option {
	return func(g *Guard) error {
		if r == nil {
			return errors.New("netguard: nil resolver")
		}
		g.resolver = r
		return nil
	}
}

// WithRootCAs sets the trust pool for TLS verification. nil means the system
// roots. Verification itself can never be disabled.
func WithRootCAs(p *x509.CertPool) Option {
	return func(g *Guard) error { g.rootCAs = p; return nil }
}

// WithMaxRedirects sets how many redirects the client follows. 0 (the
// default) refuses redirects: the 3xx response is returned to the caller
// untouched. Every followed hop is re-validated like the first request.
func WithMaxRedirects(n int) Option {
	return func(g *Guard) error {
		if n < 0 || n > 10 {
			return fmt.Errorf("netguard: max redirects %d out of range 0..10", n)
		}
		g.maxRedirects = n
		return nil
	}
}

// WithTimeout bounds one whole request (dial, TLS, headers and body).
func WithTimeout(d time.Duration) Option {
	return func(g *Guard) error {
		if d <= 0 {
			return errors.New("netguard: timeout must be positive")
		}
		g.timeout = d
		return nil
	}
}

// WithDialFunc replaces the connect step (test seam). It is called with an
// already-validated literal IP address.
func WithDialFunc(f DialFunc) Option {
	return func(g *Guard) error { g.baseDial = f; return nil }
}

// NewGuard builds a Guard. The zero-option guard is the strictest: https
// only, public addresses only, no redirects, 15 s timeout, system roots.
func NewGuard(opts ...Option) (*Guard, error) {
	g := &Guard{
		resolver:       net.DefaultResolver,
		timeout:        15 * time.Second,
		dialTimeout:    10 * time.Second,
		maxHeaderBytes: 64 << 10,
	}
	for _, o := range opts {
		if err := o(g); err != nil {
			return nil, err
		}
	}
	if g.baseDial == nil {
		d := &net.Dialer{
			Timeout: g.dialTimeout,
			Control: func(_, address string, _ syscall.RawConn) error {
				return g.controlCheck(address)
			},
		}
		g.baseDial = d.DialContext
	}
	return g, nil
}

// controlCheck is the last line of defence: whatever the dialer is about to
// connect to must itself pass the range policy.
func (g *Guard) controlCheck(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return blocked(ReasonInternalErr, "", "unparseable dial address")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return blocked(ReasonInternalErr, "", "dial address is not a literal IP")
	}
	return checkAddr(addr, g.allowPrivate, "")
}

// CheckIP applies the guard's range policy to one address.
func (g *Guard) CheckIP(ip net.IP) error { return CheckIP(ip, g.allowPrivate) }

// DialContext resolves host once, validates EVERY returned address against
// the policy (one bad record refuses the whole host, so a mixed answer cannot
// be used to pick the bad address), then connects to a validated literal IP.
// There is no second lookup between validation and connect.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, blocked(ReasonNetwork, "", "only TCP is allowed")
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, blocked(ReasonHost, "", "unparseable dial address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, blocked(ReasonPort, host, "invalid port")
	}
	if !g.hostAllowed(host, port) {
		return nil, blocked(ReasonAllowlist, host, "host:port is not on the allow-list")
	}
	ips, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), portStr)
		conn, derr := g.baseDial(ctx, network, target)
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		return nil, blocked(ReasonDNS, host, "no usable address")
	}
	return nil, &dialError{host: host, cause: lastErr}
}

// dialError reports a failed connect without the resolved address (its text
// is safe to show a caller); the cause stays reachable through Unwrap so
// callers can still tell a timeout from a refusal.
type dialError struct {
	host  string
	cause error
}

func (e *dialError) Error() string { return "netguard: connecting to " + e.host + " failed" }
func (e *dialError) Unwrap() error { return e.cause }

// Timeout lets (*url.Error).Timeout and net.Error checks see through the
// wrapper: url.Error asserts on its direct Err, it does not unwrap.
func (e *dialError) Timeout() bool {
	var ne net.Error
	return errors.As(e.cause, &ne) && ne.Timeout()
}

// resolve returns the validated addresses for host. A literal IP is validated
// without a lookup.
func (g *Guard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if err := checkAddr(a, g.allowPrivate, host); err != nil {
			return nil, err
		}
		return []netip.Addr{a}, nil
	}
	if strings.ContainsRune(host, '%') {
		return nil, blocked(ReasonHost, host, "zone identifiers are not allowed")
	}
	res, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		// The resolver error is dropped on purpose: it can quote the name
		// server's answer. DNS failure is treated as a refusal, never as a
		// licence to retry elsewhere.
		return nil, blocked(ReasonDNS, host, "DNS resolution failed")
	}
	if len(res) == 0 {
		return nil, blocked(ReasonDNS, host, "DNS returned no addresses")
	}
	out := make([]netip.Addr, 0, len(res))
	for _, r := range res {
		a, ok := netip.AddrFromSlice(r.IP)
		if !ok {
			return nil, blocked(ReasonDNS, host, "DNS returned an invalid address")
		}
		if r.Zone != "" {
			return nil, blocked(ReasonAddress, host, "IPv6 zone identifiers are not allowed")
		}
		// A DNS answer in 16-byte form is judged by the IPv4 rules when it is
		// an IPv4 address (Go's resolver returns A records that way).
		a = a.Unmap()
		if err := checkAddr(a, g.allowPrivate, host); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}
