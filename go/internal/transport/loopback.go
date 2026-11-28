package transport

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// IsLoopbackHost reports whether host is "localhost" or a loopback address.
// A bracketed IPv6 literal and a zone are accepted.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	return err == nil && ip.IsLoopback()
}

// CheckBaseURL validates the server URL a client will send credentials to.
// It must be https://, or http:// to a loopback host. Plain http to any
// other host is refused unless allowInsecure is set, because the bearer
// token and every secret would cross the network in clear text (RGT-422).
// The URL is returned unchanged on success.
func CheckBaseURL(raw string, allowInsecure bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("invalid server URL scheme %q: use https:// or http://", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("invalid server URL %q: no host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid server URL: credentials in the URL are not allowed (use a bearer token)")
	}
	if scheme == "http" && !IsLoopbackHost(u.Hostname()) && !allowInsecure {
		return "", fmt.Errorf("refusing to send credentials over plain http to %s: use https:// "+
			"(with --cacert for a private CA), or pass --allow-insecure-http if the network is trusted", u.Host)
	}
	return raw, nil
}
