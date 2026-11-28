package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"rgt-vault-server/internal/netguard"
)

// ClientOptions configures the TLS side of an HTTP client. The zero value
// verifies the server against the operating system's trust store.
type ClientOptions struct {
	// CACertFile, if set, REPLACES the system trust store: only the CAs in
	// this PEM bundle are trusted (a private CA, or a pinned self-signed
	// server certificate).
	CACertFile string
	// ClientCertFile and ClientKeyFile (both or neither) present a client
	// certificate for a server that requires mTLS (--tls-client-auth).
	ClientCertFile string
	ClientKeyFile  string
}

// Environment variables the CLI, MCP and TUI read for these options.
const (
	EnvCACert     = "RGT_VAULT_CACERT"
	EnvClientCert = "RGT_VAULT_CLIENT_CERT"
	EnvClientKey  = "RGT_VAULT_CLIENT_KEY"
)

// ClientOptionsFromEnv fills empty fields from the environment.
func ClientOptionsFromEnv(o ClientOptions, getenv func(string) string) ClientOptions {
	if getenv == nil {
		getenv = os.Getenv
	}
	if o.CACertFile == "" {
		o.CACertFile = getenv(EnvCACert)
	}
	if o.ClientCertFile == "" {
		o.ClientCertFile = getenv(EnvClientCert)
	}
	if o.ClientKeyFile == "" {
		o.ClientKeyFile = getenv(EnvClientKey)
	}
	return o
}

// TLSConfig builds the client tls.Config: TLS 1.2 minimum, AEAD suites,
// server verification ON (there is deliberately no way to turn it off).
func (o ClientOptions) TLSConfig() (*tls.Config, error) {
	cfg := baseConfig()
	if o.CACertFile != "" {
		pool, err := LoadCAPool(o.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("--cacert: %w", err)
		}
		cfg.RootCAs = pool
	}
	if (o.ClientCertFile == "") != (o.ClientKeyFile == "") {
		return nil, errors.New("--client-cert and --client-key must be given together")
	}
	if o.ClientCertFile != "" {
		if err := CheckKeyFile(o.ClientKeyFile); err != nil {
			return nil, fmt.Errorf("--client-key: %w", err)
		}
		pair, err := tls.LoadX509KeyPair(o.ClientCertFile, o.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// NewTransport returns the http.Transport every rgt-vault client uses: the
// netguard dialer (no link-local / metadata targets) plus the TLS policy.
func NewTransport(o ClientOptions) (*http.Transport, error) {
	cfg, err := o.TLSConfig()
	if err != nil {
		return nil, err
	}
	tr := newBaseTransport()
	tr.DialContext = netguard.NewDialer(true).DialContext
	tr.TLSClientConfig = cfg
	return tr, nil
}

// NewHTTPClient is NewTransport wrapped in an http.Client with a timeout.
func NewHTTPClient(o ClientOptions, timeout time.Duration) (*http.Client, error) {
	tr, err := NewTransport(o)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}
