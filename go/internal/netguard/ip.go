package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ErrBlocked is the sentinel every refusal wraps: errors.Is(err, ErrBlocked)
// is true for any request this package refuses (bad URL, forbidden address,
// allow-list miss, redirect policy).
var ErrBlocked = errors.New("netguard: blocked")

// Reason classifies why a request was refused. The set is stable so callers
// (the actions package, tests) can map a refusal to a message without parsing
// error text.
type Reason string

// Refusal reasons.
const (
	ReasonURL         Reason = "url"           // unparseable / malformed URL
	ReasonScheme      Reason = "scheme"        // not http(s), or http without opt-in
	ReasonUserinfo    Reason = "userinfo"      // credentials embedded in the URL
	ReasonHost        Reason = "host"          // malformed or ambiguous host
	ReasonPort        Reason = "port"          // malformed port
	ReasonAddress     Reason = "address"       // resolves to a forbidden IP range
	ReasonAllowlist   Reason = "allowlist"     // host:port not on the allow-list
	ReasonRedirect    Reason = "redirect"      // redirect refused by policy
	ReasonDNS         Reason = "dns"           // resolution failed or returned nothing
	ReasonNetwork     Reason = "network"       // non-TCP network requested
	ReasonDowngrade   Reason = "downgrade"     // https -> http redirect
	ReasonInternalErr Reason = "internal-fail" // should not happen
)

// BlockedError is the concrete refusal error. Its text is safe to show to a
// caller: it names the host (never a resolved IP, which would be an oracle for
// internal network layout) and never carries a secret.
type BlockedError struct {
	Reason Reason
	Host   string // host the refusal is about, "" when not applicable
	Detail string // short, non-sensitive explanation
}

func (e *BlockedError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("netguard: refusing %s for host %q: %s", e.Reason, e.Host, e.Detail)
	}
	return fmt.Sprintf("netguard: refusing %s: %s", e.Reason, e.Detail)
}

// Is makes errors.Is(err, ErrBlocked) true.
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

func blocked(r Reason, host, detail string) error {
	return &BlockedError{Reason: r, Host: host, Detail: detail}
}

// rule is one forbidden prefix. hard rules cannot be lifted by AllowPrivate
// (link-local incl. the cloud metadata address, multicast, unspecified and
// reserved space); soft rules are lifted by AllowPrivate.
type rule struct {
	prefix netip.Prefix
	name   string
	hard   bool
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

var v4Rules = []rule{
	{mustPrefix("0.0.0.0/8"), "unspecified/this-network", true},
	{mustPrefix("10.0.0.0/8"), "RFC1918 private", false},
	{mustPrefix("100.100.100.200/32"), "cloud metadata address (Alibaba)", true}, // inside CGNAT, so it must come first
	{mustPrefix("100.64.0.0/10"), "CGNAT shared address space", false},
	{mustPrefix("127.0.0.0/8"), "loopback", false},
	{mustPrefix("168.63.129.16/32"), "cloud metadata address (Azure wireserver)", true},
	{mustPrefix("169.254.0.0/16"), "link-local/metadata", true},
	{mustPrefix("172.16.0.0/12"), "RFC1918 private", false},
	{mustPrefix("192.0.0.0/24"), "IETF protocol assignments", false},
	{mustPrefix("192.0.2.0/24"), "documentation", false},
	{mustPrefix("192.88.99.0/24"), "6to4 relay anycast", false},
	{mustPrefix("192.168.0.0/16"), "RFC1918 private", false},
	{mustPrefix("198.18.0.0/15"), "benchmarking", false},
	{mustPrefix("198.51.100.0/24"), "documentation", false},
	{mustPrefix("203.0.113.0/24"), "documentation", false},
	{mustPrefix("224.0.0.0/4"), "multicast", true},
	{mustPrefix("240.0.0.0/4"), "reserved/broadcast", true},
}

var v6Rules = []rule{
	{mustPrefix("::1/128"), "loopback", false},
	{mustPrefix("64:ff9b:1::/48"), "local-use NAT64 (may embed a metadata address)", true}, // inside ::/8, so it must come first
	{mustPrefix("::/8"), "unspecified/reserved", true},
	{mustPrefix("100::/64"), "discard-only", false},
	{mustPrefix("2001::/23"), "IETF protocol/Teredo", false},
	{mustPrefix("2001:db8::/32"), "documentation", false},
	{mustPrefix("2002::/16"), "6to4", false},
	{mustPrefix("3fff::/20"), "documentation", false},
	{mustPrefix("5f00::/16"), "SRv6 SIDs", false},
	{mustPrefix("fd00:ec2::/32"), "cloud metadata address (AWS IPv6)", true}, // inside ULA, so it must come first
	{mustPrefix("fc00::/7"), "unique-local (ULA)", false},
	{mustPrefix("fe80::/10"), "link-local", true},
	{mustPrefix("fec0::/10"), "site-local", false},
	{mustPrefix("ff00::/8"), "multicast", true},
}

var (
	nat64WellKnown = mustPrefix("64:ff9b::/96")
	globalUnicast6 = mustPrefix("2000::/3")
	metadataAddr   = netip.MustParseAddr("169.254.169.254")
)

// classify returns the name of the forbidden range addr falls in and whether
// that range is hard (not liftable by AllowPrivate). ok is false when addr is
// globally routable. The caller has already Unmap()ped addr.
func classify(addr netip.Addr) (name string, hard, ok bool) {
	if addr == metadataAddr {
		return "cloud metadata address", true, true
	}
	if addr.Is4() {
		for _, r := range v4Rules {
			if r.prefix.Contains(addr) {
				return r.name, r.hard, true
			}
		}
		return "", false, false
	}
	for _, r := range v6Rules {
		if r.prefix.Contains(addr) {
			return r.name, r.hard, true
		}
	}
	if !globalUnicast6.Contains(addr) {
		return "reserved (outside 2000::/3)", true, true
	}
	return "", false, false
}

// embedded4 returns the IPv4 address carried by an IPv4-mapped (::ffff:a.b.c.d)
// or well-known NAT64 (64:ff9b::a.b.c.d) address.
func embedded4(addr netip.Addr) (netip.Addr, bool) {
	if addr.Is4In6() {
		return addr.Unmap(), true
	}
	if addr.Is6() && nat64WellKnown.Contains(addr) {
		b := addr.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return addr, false
}

// checkAddr applies the range policy to one address. IPv4-mapped and NAT64
// forms are refused outright unless allowPrivate is set (they are how a
// private IPv4 target is smuggled through an IPv6-only filter); with
// allowPrivate the embedded IPv4 address is judged by the IPv4 rules, so
// ::ffff:169.254.169.254 stays blocked.
func checkAddr(addr netip.Addr, allowPrivate bool, host string) error {
	if addr.Zone() != "" {
		return blocked(ReasonAddress, host, "IPv6 zone identifiers are not allowed")
	}
	if emb, ok := embedded4(addr); ok {
		if !allowPrivate {
			return blocked(ReasonAddress, host, "target resolves to a private/internal address (IPv4-mapped/NAT64 form)")
		}
		addr = emb
	}
	name, hard, bad := classify(addr)
	if !bad {
		return nil
	}
	if hard || !allowPrivate {
		return blocked(ReasonAddress, host, "target resolves to a private/internal address ("+name+")")
	}
	return nil
}

// ClassifyIP reports whether ip is in a range this package refuses, and
// whether allowPrivate can lift the refusal. It is exported for tests and for
// callers that want to pre-screen an address.
func ClassifyIP(ip net.IP) (name string, hard, forbidden bool) {
	addr, ok := fromNetIP(ip)
	if !ok {
		return "invalid address", true, true
	}
	if emb, ok := embedded4(addr); ok {
		if n, hard, bad := classify(emb); bad && hard {
			return "embedded " + n, true, true
		}
		return "IPv4-mapped/NAT64 form", false, true
	}
	return classify(addr)
}

// CheckIP returns a *BlockedError when ip is in a forbidden range. With
// allowPrivate the loopback, RFC1918, CGNAT, ULA and documentation ranges are
// permitted; link-local (including 169.254.169.254), multicast, unspecified
// and reserved space never are.
func CheckIP(ip net.IP, allowPrivate bool) error {
	addr, ok := fromNetIP(ip)
	if !ok {
		return blocked(ReasonAddress, "", "invalid IP address")
	}
	return checkAddr(addr, allowPrivate, "")
}

// fromNetIP converts a net.IP, treating the 16-byte form of an IPv4 address as
// IPv4 (net.IP cannot tell "::ffff:a.b.c.d" from a plain IPv4 address).
func fromNetIP(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4)), true
	}
	return netip.AddrFromSlice(ip)
}
