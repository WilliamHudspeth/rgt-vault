package actions

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/netguard"
)

// outReq is a fully validated outbound request minus the Authorization header.
type outReq struct {
	method  string
	url     string
	headers map[string]string
	body    []byte
}

// endpoint is one HTTP-capable action's guard and client.
type endpoint struct {
	name   string
	guard  *netguard.Guard
	client *http.Client
}

// bearer validates the secret as a bearer token and returns the header value.
// The error never includes the secret.
func bearer(secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", execErr("The leased secret is empty and cannot be used as a bearer token.")
	}
	if !utf8.Valid(secret) {
		return "", execErr("The leased secret is not valid UTF-8 and cannot be used as a bearer token.")
	}
	for _, c := range secret {
		if c < 0x20 || c >= 0x7f {
			return "", execErr("The leased secret contains characters that cannot be sent in an HTTP header.")
		}
	}
	return "Bearer " + string(secret), nil
}

// redact returns scheme://host[:port] only: paths and queries routinely carry
// tokens (Telegram-style /bot<token>/, ?api_key=) and must not reach errors
// or logs.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<url>"
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

// send runs one validated request and shapes the Python-compatible result.
func (e *endpoint) send(ctx context.Context, cfg *Config, log *slog.Logger, r *outReq, secret []byte) (map[string]any, error) {
	auth, err := bearer(secret)
	if err != nil {
		return nil, err
	}
	u, err := e.guard.CheckURL(r.url)
	if err != nil {
		return nil, e.mapErr(r, err)
	}
	if int64(len(r.body)) > cfg.MaxRequestBytes {
		return nil, execErr("Request body exceeds %d bytes.", cfg.MaxRequestBytes)
	}
	var body io.Reader
	if r.method == http.MethodPost {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, execErr("Upstream %s %s failed.", r.method, redact(r.url))
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", auth)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "rgt-vault")
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, e.mapErr(r, err)
	}
	defer func() { _ = resp.Body.Close() }()
	host := u.Hostname()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxResponseBytes+1))
	if err != nil {
		log.Warn("action upstream read failed", "action", e.name, "host", host, "reason", reasonOf(err))
		return nil, execErr("Upstream %s %s failed (%s).", r.method, redact(r.url), reasonOf(err))
	}
	truncated := int64(len(raw)) > cfg.MaxResponseBytes
	if truncated {
		raw = raw[:cfg.MaxResponseBytes]
	}
	log.Info("action upstream response", "action", e.name, "host", host, "status", resp.StatusCode)

	// Python (urllib) raises on 4xx/5xx and on redirects it cannot follow.
	// The body is read for symmetry but never placed in the error.
	if resp.StatusCode >= 400 {
		return nil, execErr("Upstream %s %s returned HTTP %d.", r.method, redact(r.url), resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return nil, execErr("Upstream %s %s returned HTTP %d (redirects are not followed).", r.method, redact(r.url), resp.StatusCode)
	}
	return map[string]any{
		"status":       resp.StatusCode,
		"headers":      flattenHeaders(resp.Header),
		"body_text":    strings.ToValidUTF8(string(raw), "�"),
		"content_type": contentType(resp.Header.Get("Content-Type")),
		"truncated":    truncated,
	}, nil
}

func flattenHeaders(h http.Header) map[string]any {
	out := make(map[string]any, len(h))
	for k, vs := range h {
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

// contentType mirrors email.message.get_content_type(): the lower-case media
// type, "text/plain" when absent or malformed.
func contentType(v string) string {
	if v == "" {
		return "text/plain"
	}
	mt, _, err := mime.ParseMediaType(v)
	if err != nil || !strings.Contains(mt, "/") {
		return "text/plain"
	}
	return mt
}

// reasonOf classifies a transport error without echoing its text.
func reasonOf(err error) string {
	var (
		unknownCA x509.UnknownAuthorityError
		certInv   x509.CertificateInvalidError
		hostErr   x509.HostnameError
		verifyErr *tls.CertificateVerificationError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &unknownCA), errors.As(err, &certInv), errors.As(err, &hostErr), errors.As(err, &verifyErr):
		return "tls certificate verification failed"
	}
	var tlsRec tls.RecordHeaderError
	if errors.As(err, &tlsRec) {
		return "tls handshake failed"
	}
	return "network error"
}

// mapGuard turns a netguard refusal into a caller-safe error, or nil when err
// is not a refusal.
func mapGuard(err error) error {
	var be *netguard.BlockedError
	if !errors.As(err, &be) {
		return nil
	}
	switch be.Reason {
	case netguard.ReasonAddress:
		return execErr("Refusing to call private/internal address for host %q. Start the server with --allow-private-network if this is intentional.", be.Host)
	case netguard.ReasonDNS:
		return execErr("DNS resolution failed for host %q.", be.Host)
	case netguard.ReasonScheme:
		return execErr("%s", be.Detail)
	case netguard.ReasonAllowlist:
		return execErr("Host %q is not on this action's allow-list.", be.Host)
	default:
		return execErr("Refusing outbound request: %s (%s).", be.Detail, string(be.Reason))
	}
}

// mapErr turns a guard refusal or transport error into a caller-safe error.
func (e *endpoint) mapErr(r *outReq, err error) error {
	if m := mapGuard(err); m != nil {
		return m
	}
	return execErr("Upstream %s %s failed (%s).", r.method, redact(r.url), reasonOf(err))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
