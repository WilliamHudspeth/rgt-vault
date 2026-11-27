package netguard

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// Client returns an *http.Client that enforces the guard:
//
//   - connections go through Guard.DialContext (resolve once, validate every
//     address, connect to the validated IP);
//   - no proxy is ever used (an env HTTP(S)_PROXY would turn the dial target
//     into the proxy and bypass the policy);
//   - TLS verification is on (TLS 1.2+, system roots or WithRootCAs); there
//     is no way to disable it;
//   - redirects are refused by default (the 3xx response is returned as is);
//     with WithMaxRedirects(n) at most n hops are followed, each re-validated
//     with CheckURL, never downgraded https->http, and the Authorization and
//     Cookie headers are dropped when the hop leaves the original origin;
//   - connections are not reused, and compression is not negotiated.
func (g *Guard) Client() *http.Client {
	tr := &http.Transport{
		Proxy:       nil,
		DialContext: g.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    g.rootCAs,
		},
		TLSHandshakeTimeout:    g.dialTimeout,
		ResponseHeaderTimeout:  g.timeout,
		MaxResponseHeaderBytes: g.maxHeaderBytes,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       g.timeout,
		CheckRedirect: g.checkRedirect,
	}
}

func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		} else {
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func (g *Guard) checkRedirect(req *http.Request, via []*http.Request) error {
	if g.maxRedirects == 0 {
		return http.ErrUseLastResponse
	}
	if len(via) > g.maxRedirects {
		return blocked(ReasonRedirect, "", "too many redirects")
	}
	first := via[0].URL
	// Judge the whole chain, not just this hop: Go re-copies the original
	// request's headers on every hop, so once ANY hop has left the original
	// origin (e.g. an untrusted subdomain or another port) the credentials must
	// stay stripped even if a later hop returns to it.
	leftOrigin := origin(req.URL) != origin(first)
	for _, v := range via {
		if strings.EqualFold(v.URL.Scheme, "https") && strings.EqualFold(req.URL.Scheme, "http") {
			return blocked(ReasonDowngrade, "", "redirect from https to http refused")
		}
		if origin(v.URL) != origin(first) {
			leftOrigin = true
		}
	}
	// Full URL checks (length, characters, scheme, host, allow-list, range).
	if _, err := g.CheckURL(req.URL.String()); err != nil {
		return err
	}
	// The previous URL (path and query may carry tokens) is never sent on.
	req.Header.Del("Referer")
	if leftOrigin {
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
	}
	return nil
}
