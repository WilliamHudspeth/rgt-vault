package netguard

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// MaxURLLength caps the URL length accepted by CheckURL.
const MaxURLLength = 2048

var numericLabel = regexp.MustCompile(`^(?:0[xX][0-9a-fA-F]*|[0-9]+)$`)

// CheckURL validates raw for use as an outbound target and returns the parsed
// URL. It is purely syntactic (no DNS): the address policy is applied when the
// connection is made (DialContext), so what is validated is what is dialled.
//
// Refused: empty/oversized/non-printable-ASCII URLs; schemes other than https
// (http only with WithAllowInsecureHTTP); embedded userinfo; missing,
// non-ASCII (IDN must be supplied as punycode), percent-encoded or
// zone-qualified hosts; ambiguous numeric IPv4 forms (decimal "2130706433",
// octal "0177.0.0.1", hex "0x7f.1", short "127.1"); malformed ports;
// forbidden IP literals; and hosts missing from the allow-list.
func (g *Guard) CheckURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, blocked(ReasonURL, "", "url is empty")
	}
	if len(raw) > MaxURLLength {
		return nil, blocked(ReasonURL, "", "url is too long")
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= 0x20 || c >= 0x7f {
			return nil, blocked(ReasonURL, "", "url contains whitespace, control or non-ASCII characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		// err quotes the whole URL; drop it.
		return nil, blocked(ReasonURL, "", "url is not parseable")
	}
	return g.checkParsed(u)
}

// checkParsed validates an already-parsed URL (used for redirect hops).
func (g *Guard) checkParsed(u *url.URL) (*url.URL, error) {
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !g.allowInsecure {
			return nil, blocked(ReasonScheme, "", "plain http:// is refused for requests that carry a credential; use https")
		}
	default:
		return nil, blocked(ReasonScheme, "", "scheme "+strconv.Quote(scheme)+" is not allowed; allowed: [https]")
	}
	if u.Opaque != "" {
		return nil, blocked(ReasonURL, "", "opaque URLs are not allowed")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return nil, blocked(ReasonUserinfo, "", "credentials in the URL are not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return nil, blocked(ReasonHost, "", "URL is missing a hostname")
	}
	norm, ip, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	port, err := portOf(u, scheme)
	if err != nil {
		return nil, err
	}
	if !g.hostAllowed(norm, port) {
		return nil, blocked(ReasonAllowlist, norm, "host:port is not on the allow-list")
	}
	if ip.IsValid() {
		if err := checkAddr(ip, g.allowPrivate, norm); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func portOf(u *url.URL, scheme string) (int, error) {
	p := u.Port()
	if p == "" {
		if scheme == "http" {
			return 80, nil
		}
		return 443, nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, blocked(ReasonPort, u.Hostname(), "port must be 1-65535")
	}
	return n, nil
}

// normalizeHost validates the hostname and returns its lower-case form plus
// the parsed address when it is an IP literal.
func normalizeHost(host string) (string, netip.Addr, error) {
	if strings.ContainsRune(host, '%') {
		return "", netip.Addr{}, blocked(ReasonHost, "", "percent-encoded hosts and IPv6 zone identifiers are not allowed")
	}
	if strings.Contains(host, ":") { // IPv6 literal (brackets already stripped)
		a, err := netip.ParseAddr(host)
		if err != nil {
			return "", netip.Addr{}, blocked(ReasonHost, "", "malformed IPv6 literal")
		}
		return strings.ToLower(a.String()), a, nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.String(), a, nil
	}
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed == "" || len(trimmed) > 253 {
		return "", netip.Addr{}, blocked(ReasonHost, "", "hostname has an invalid length")
	}
	labels := strings.Split(trimmed, ".")
	allNumeric := true
	for _, l := range labels {
		if l == "" {
			return "", netip.Addr{}, blocked(ReasonHost, "", "hostname has an empty label")
		}
		if len(l) > 63 {
			return "", netip.Addr{}, blocked(ReasonHost, "", "hostname label is longer than 63 characters")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			case c >= 0x80:
				return "", netip.Addr{}, blocked(ReasonHost, "", "non-ASCII hostnames are not allowed; supply IDNs in punycode (xn--) form")
			default:
				return "", netip.Addr{}, blocked(ReasonHost, "", "hostname contains an invalid character")
			}
		}
		if !numericLabel.MatchString(l) {
			allNumeric = false
		}
	}
	if allNumeric {
		return "", netip.Addr{}, blocked(ReasonHost, "", "ambiguous numeric IPv4 form (decimal/octal/hex/short); use dotted-decimal")
	}
	return strings.ToLower(trimmed), netip.Addr{}, nil
}
