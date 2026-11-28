package gateway

// TLS for the cutover gateway (batch H6, RGT-251/455). The policy is the one
// of internal/transport: TLS 1.2+ with AEAD suites, a key file that group and
// other cannot read, certificate hot reload and optional mutual TLS, for the
// listener; and certificate verification (optionally against --backend-cacert
// only) for the connections to the Python and Go backends.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/transport"
)

// TLSOptions are the gateway's listener TLS flags.
type TLSOptions struct {
	CertFile       string
	KeyFile        string
	ClientCAFile   string
	ClientAuth     string // "", "require" or "verify-if-given"
	ReloadInterval time.Duration
}

// Enabled reports whether the gateway terminates TLS.
func (o TLSOptions) Enabled() bool { return o.CertFile != "" || o.KeyFile != "" }

// CheckListen applies the binding rule: a non-loopback address needs TLS or
// the explicit allowInsecure override (the -allow-non-loopback flag).
func CheckListen(addr string, tlsOn, allowInsecure bool) error {
	if IsLoopbackAddr(addr) || tlsOn || allowInsecure {
		return nil
	}
	return fmt.Errorf("refusing to bind %s: not a loopback address and TLS is not configured "+
		"(use -tls-cert and -tls-key, or -allow-non-loopback for plain HTTP on a trusted network)", addr)
}

// ValidateBackendURL checks a backend URL. The gateway forwards the clients'
// bearer tokens to it, so it must be https://, or http:// to a loopback host
// unless allowInsecure is set.
func ValidateBackendURL(name, raw string, allowInsecure bool) error {
	if _, err := transport.CheckBaseURL(raw, allowInsecure); err != nil {
		return fmt.Errorf("%s backend: %w", name, err)
	}
	u, _ := url.Parse(raw)
	if u.Path != "" && u.Path != "/" && strings.Contains(u.Path, "..") {
		return fmt.Errorf("%s backend: invalid path", name)
	}
	return nil
}

// SetBackendTransport makes both backends use rt (see
// transport.NewTransport). nil keeps the default.
func (g *Gateway) SetBackendTransport(rt http.RoundTripper) {
	if rt == nil {
		return
	}
	g.pythonProxy.Transport = rt
	g.goProxy.Transport = rt
}

// NewHTTPServer builds the gateway's http.Server. With TLS enabled it
// returns the reloadable TLS state (serve it with srv.ServeTLS("", "") and
// call Watch); otherwise the second result is nil.
func NewHTTPServer(addr string, h http.Handler, o TLSOptions, logf func(string, ...any)) (*http.Server, *transport.ServerTLS, error) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	if (o.CertFile == "") != (o.KeyFile == "") {
		return nil, nil, errors.New("-tls-cert and -tls-key must be given together")
	}
	if !o.Enabled() {
		if o.ClientCAFile != "" || o.ClientAuth != "" {
			return nil, nil, errors.New("-tls-client-ca / -tls-client-auth need -tls-cert and -tls-key")
		}
		return srv, nil, nil
	}
	mode, err := transport.ParseClientAuth(o.ClientAuth)
	if err != nil {
		return nil, nil, err
	}
	t, err := transport.NewServerTLS(transport.ServerOptions{
		CertFile: o.CertFile, KeyFile: o.KeyFile, ClientCAFile: o.ClientCAFile, ClientAuth: mode, Logf: logf,
	})
	if err != nil {
		return nil, nil, err
	}
	srv.TLSConfig = t.Config()
	return srv, t, nil
}
