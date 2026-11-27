package netguard

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// allowEntry is one parsed allow-list entry.
type allowEntry struct {
	host     string // lower-case, no brackets, no trailing dot
	wildcard bool   // "*.example.com": any subdomain, not the apex
	port     int    // 0 = any port
}

func parseAllowEntry(e string) (allowEntry, error) {
	raw := e
	e = strings.TrimSpace(e)
	if e == "" {
		return allowEntry{}, fmt.Errorf("netguard: empty allow-list entry")
	}
	var ent allowEntry
	host := e
	if strings.HasPrefix(e, "[") { // bracketed IPv6, optional :port
		end := strings.Index(e, "]")
		if end < 0 {
			return allowEntry{}, fmt.Errorf("netguard: bad allow-list entry %q", raw)
		}
		host = e[1:end]
		rest := e[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return allowEntry{}, fmt.Errorf("netguard: bad allow-list entry %q", raw)
			}
			p, err := parsePort(rest[1:])
			if err != nil {
				return allowEntry{}, fmt.Errorf("netguard: bad allow-list entry %q: %w", raw, err)
			}
			ent.port = p
		}
	} else if h, p, err := net.SplitHostPort(e); err == nil {
		host = h
		pp, perr := parsePort(p)
		if perr != nil {
			return allowEntry{}, fmt.Errorf("netguard: bad allow-list entry %q: %w", raw, perr)
		}
		ent.port = pp
	} else if strings.Count(e, ":") > 0 {
		return allowEntry{}, fmt.Errorf("netguard: bad allow-list entry %q (IPv6 literals need brackets)", raw)
	}
	if strings.HasPrefix(host, "*.") {
		ent.wildcard = true
		host = host[2:]
	}
	host = canonicalHost(host)
	if host == "" || strings.ContainsAny(host, "*/@%?# \t") {
		return allowEntry{}, fmt.Errorf("netguard: bad allow-list entry %q", raw)
	}
	ent.host = host
	return ent, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

// hostAllowed reports whether host:port passes the allow-list. With no
// allow-list configured everything passes this check (the range policy still
// applies).
func (g *Guard) hostAllowed(host string, port int) bool {
	if !g.allowSet {
		return true
	}
	host = canonicalHost(host)
	for _, e := range g.allow {
		if e.port != 0 && e.port != port {
			continue
		}
		if e.wildcard {
			if strings.HasSuffix(host, "."+e.host) {
				return true
			}
			continue
		}
		if host == e.host {
			return true
		}
	}
	return false
}

// canonicalHost lower-cases a host, drops one trailing dot and writes IP
// literals in canonical form, so "2001:4860:4860:0:0:0:0:8888" and
// "2001:4860:4860::8888" compare equal.
func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if a, err := netip.ParseAddr(h); err == nil && a.Zone() == "" {
		return a.String()
	}
	return h
}
