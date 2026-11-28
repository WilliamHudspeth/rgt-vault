package server

// TLS for the HTTP server (batch H6; RGT-251, 422, 455, 456, 458).
//
// The policy itself (protocol floor, AEAD suites, key-file checks, hot
// reload, mTLS) lives in internal/transport so that the cutover gateway and
// every client share it. This file is the server-side glue:
//
//   - TLSSettings / NewTLS: the --tls-* options of `rgt-vault serve`;
//   - CheckBind: the rule that a non-loopback bind needs TLS (or an explicit,
//     audited, loudly warned override);
//   - HSTSHandler: Strict-Transport-Security on every TLS response;
//   - Serve: http.Server.ServeTLS on the live, reloadable configuration.

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"rgt-vault-server/internal/transport"
)

// HSTSValue is the Strict-Transport-Security header the server sends over
// TLS: one year. includeSubDomains is deliberately absent: the server does
// not own the rest of the domain's namespace.
const HSTSValue = "max-age=31536000"

// DefaultTLSReloadInterval is how often the certificate files are checked for
// a change (a SIGHUP reloads immediately).
const DefaultTLSReloadInterval = time.Minute

// TLSSettings are the `serve` TLS options after flag/env resolution.
type TLSSettings struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
	// ClientAuth is "", "require" or "verify-if-given" (see
	// transport.ParseClientAuth). With ClientCAFile set and ClientAuth empty
	// it means "require".
	ClientAuth string
	// ReloadInterval is the file-change poll period; <= 0 disables polling
	// (SIGHUP still works).
	ReloadInterval time.Duration
}

// Enabled reports whether the server terminates TLS itself.
func (s TLSSettings) Enabled() bool { return s.CertFile != "" || s.KeyFile != "" }

// Validate checks the combination of options without touching the files.
func (s TLSSettings) Validate() error {
	if (s.CertFile == "") != (s.KeyFile == "") {
		return errors.New("--tls-cert and --tls-key must be given together")
	}
	if !s.Enabled() {
		if s.ClientCAFile != "" || s.ClientAuth != "" {
			return errors.New("--tls-client-ca / --tls-client-auth need --tls-cert and --tls-key")
		}
		return nil
	}
	if _, err := transport.ParseClientAuth(s.ClientAuth); err != nil {
		return fmt.Errorf("--tls-client-auth: %w", err)
	}
	if s.ClientAuth != "" && s.ClientCAFile == "" {
		return errors.New("--tls-client-auth needs --tls-client-ca")
	}
	return nil
}

// NewTLS validates the settings, loads the certificate and builds the
// reloadable TLS configuration. logf receives warnings and reload results.
func NewTLS(s TLSSettings, logf func(format string, args ...any)) (*transport.ServerTLS, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	mode, err := transport.ParseClientAuth(s.ClientAuth)
	if err != nil {
		return nil, err
	}
	return transport.NewServerTLS(transport.ServerOptions{
		CertFile:     s.CertFile,
		KeyFile:      s.KeyFile,
		ClientCAFile: s.ClientCAFile,
		ClientAuth:   mode,
		Logf:         logf,
	})
}

// CheckBind applies the binding rule. A loopback host is always acceptable.
// Any other host needs TLS (tlsOn); without it the bind is refused unless
// allowInsecure is set, in which case a warning text is returned for the
// caller to log and audit.
func CheckBind(host string, tlsOn, allowInsecure bool) (warning string, err error) {
	if transport.IsLoopbackHost(host) || tlsOn {
		return "", nil
	}
	if !allowInsecure {
		return "", fmt.Errorf("refusing to bind %s: not a loopback address and TLS is not configured. "+
			"Serve TLS (--tls-cert and --tls-key), put a TLS reverse proxy in front and keep this "+
			"daemon on loopback, or - only on a network you fully trust - pass --allow-insecure-non-loopback", host)
	}
	return fmt.Sprintf("INSECURE: listening on non-loopback host %s over PLAIN HTTP (--allow-insecure-non-loopback). "+
		"Bearer tokens and secret values cross the network unencrypted. Use TLS (--tls-cert/--tls-key) "+
		"or a TLS reverse proxy, and firewall the port", host), nil
}

// HSTSHandler adds Strict-Transport-Security to every response. Use it only
// when the connection is TLS.
func HSTSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", HSTSValue)
		next.ServeHTTP(w, r)
	})
}

// Serve runs srv on ln over TLS using t's live configuration, so a reload
// takes effect for new connections without restarting the listener.
func Serve(srv *http.Server, ln net.Listener, t *transport.ServerTLS) error {
	srv.TLSConfig = t.Config()
	return srv.ServeTLS(ln, "", "")
}
