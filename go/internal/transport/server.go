package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ClientAuthMode is the mTLS policy of a server.
type ClientAuthMode string

const (
	// ClientAuthNone: no client certificate is requested (the default).
	ClientAuthNone ClientAuthMode = ""
	// ClientAuthRequire: every connection must present a certificate that
	// chains to the client CA.
	ClientAuthRequire ClientAuthMode = "require"
	// ClientAuthVerifyIfGiven: a certificate is optional, but one that is
	// presented must chain to the client CA.
	ClientAuthVerifyIfGiven ClientAuthMode = "verify-if-given"
)

// ParseClientAuth parses the --tls-client-auth value. "" is ClientAuthNone.
func ParseClientAuth(s string) (ClientAuthMode, error) {
	switch ClientAuthMode(s) {
	case ClientAuthNone, ClientAuthRequire, ClientAuthVerifyIfGiven:
		return ClientAuthMode(s), nil
	}
	return "", fmt.Errorf("invalid client auth mode %q: use \"require\" or \"verify-if-given\"", s)
}

// ServerOptions configures NewServerTLS.
type ServerOptions struct {
	CertFile string
	KeyFile  string
	// ClientCAFile (optional) enables mTLS: the PEM bundle of the CAs that
	// may sign client certificates.
	ClientCAFile string
	// ClientAuth is the mTLS mode. With ClientCAFile set and ClientAuth empty
	// the mode defaults to ClientAuthRequire (fail closed).
	ClientAuth ClientAuthMode
	// Logf receives warnings and reload results (default: discarded).
	Logf func(format string, args ...any)
	// Now is the clock (tests); default time.Now.
	Now func() time.Time
}

// ServerTLS is a TLS server configuration whose certificate (and client CA
// bundle) can be replaced at run time without dropping connections:
// established connections keep their handshake state, new handshakes pick up
// the new material through tls.Config.GetCertificate / GetConfigForClient.
type ServerTLS struct {
	opts ServerOptions
	cfg  *tls.Config

	cert     atomic.Pointer[tls.Certificate]
	info     atomic.Pointer[CertInfo]
	clientCA atomic.Pointer[x509.CertPool]

	mu       sync.Mutex // serialises Reload; guards fingerprints
	lastSeen fileStamps
	expired  bool // the "expired while running" error was already logged
}

// NewServerTLS loads and validates the material (see LoadCertificate) and
// builds the tls.Config. Any problem is returned: the server must not start
// with a certificate it cannot serve.
func NewServerTLS(opts ServerOptions) (*ServerTLS, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ClientCAFile == "" && opts.ClientAuth != ClientAuthNone {
		return nil, errors.New("--tls-client-auth needs --tls-client-ca")
	}
	if opts.ClientCAFile != "" && opts.ClientAuth == ClientAuthNone {
		opts.ClientAuth = ClientAuthRequire
	}
	s := &ServerTLS{opts: opts}
	if n := KeyACLNotice(runtime.GOOS); n != "" {
		opts.Logf("WARNING: %s", n)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.cfg = baseConfig()
	s.cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.cert.Load(), nil }
	// Session tickets are off by policy: Go keeps the ticket keys in memory
	// for days, so a memory disclosure would let a recorded TLS 1.2 session
	// (and a TLS 1.3 PSK resumption) be decrypted later. The connection rate
	// of a local vault is far too low for the saved handshake to matter.
	s.cfg.SessionTicketsDisabled = true
	s.cfg.NextProtos = []string{"h2", "http/1.1"}
	if opts.ClientAuth != ClientAuthNone {
		base := s.cfg
		mode := tls.RequireAndVerifyClientCert
		if opts.ClientAuth == ClientAuthVerifyIfGiven {
			mode = tls.VerifyClientCertIfGiven
		}
		s.cfg.ClientAuth = mode
		s.cfg.ClientCAs = s.clientCA.Load()
		// A per-connection copy that carries the CURRENT client CA pool.
		s.cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			c := base.Clone()
			c.ClientCAs = s.clientCA.Load()
			c.GetConfigForClient = nil
			return c, nil
		}
	}
	return s, nil
}

// load reads, validates and installs the material. On any error the
// previously installed material stays in place.
func (s *ServerTLS) load() error {
	// Fingerprint BEFORE reading: a file replaced during the read is seen as
	// changed on the next poll. It is kept even if loading fails, so a broken
	// file is reported once, not on every tick (fix it, which changes its
	// mtime, or send SIGHUP) - except for a validity-window failure (not yet
	// valid / expired), which fixes itself with the clock and is retried.
	prev := s.lastSeen
	s.lastSeen = s.stamps()
	pair, info, err := LoadCertificate(s.opts.CertFile, s.opts.KeyFile, s.opts.Now())
	if err != nil {
		var tw *timeWindowError
		if errors.As(err, &tw) {
			s.lastSeen = prev
		}
		return err
	}
	var pool *x509.CertPool
	if s.opts.ClientCAFile != "" {
		if pool, err = LoadCAPool(s.opts.ClientCAFile); err != nil {
			return fmt.Errorf("client CA: %w", err)
		}
	}
	s.cert.Store(pair)
	s.info.Store(&info)
	if pool != nil {
		s.clientCA.Store(pool)
	}
	s.expired = false
	for _, w := range info.Warnings {
		s.opts.Logf("WARNING: TLS certificate %s: %s", info.Subject, w)
	}
	return nil
}

// Config returns the tls.Config to hand to http.Server.TLSConfig. It is
// shared and live: do not modify it.
func (s *ServerTLS) Config() *tls.Config { return s.cfg }

// Info describes the certificate currently served.
func (s *ServerTLS) Info() CertInfo { return *s.info.Load() }

// CoversHost reports whether the served certificate is valid for host (a DNS
// name or an IP literal, matched against the SAN exactly as a client does).
// Wildcard binds ("", "0.0.0.0", "::") name no host and always pass.
func (s *ServerTLS) CoversHost(host string) error {
	h := strings.Trim(host, "[]")
	if h == "" || h == "0.0.0.0" || h == "::" {
		return nil
	}
	return s.cert.Load().Leaf.VerifyHostname(h)
}

// ClientAuth is the effective mTLS mode.
func (s *ServerTLS) ClientAuth() ClientAuthMode { return s.opts.ClientAuth }

// Reload re-reads the certificate, key and client CA files. If the new
// material is invalid (key mismatch, expired, wrong permissions, ...) the
// old material keeps being served and the error is returned.
func (s *ServerTLS) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return fmt.Errorf("TLS reload failed, still serving the previous certificate: %w", err)
	}
	info := s.info.Load()
	s.opts.Logf("TLS certificate reloaded: %s serial %s valid until %s",
		info.Subject, info.Serial, info.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// Watch reloads the material when trigger fires (SIGHUP) and, if interval is
// positive, whenever the modification time or size of one of the files
// changes (checked every interval). It also logs once when the running
// certificate expires. It returns when ctx is cancelled.
func (s *ServerTLS) Watch(ctx context.Context, trigger <-chan struct{}, interval time.Duration) {
	var tick <-chan time.Time
	if interval > 0 {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	var lastErr string // the poll logs a repeated failure once, not every tick
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			lastErr = ""
			s.reloadLogged(&lastErr)
		case <-tick:
			s.mu.Lock()
			changed := s.stamps() != s.lastSeen
			s.mu.Unlock()
			if changed {
				s.reloadLogged(&lastErr)
			}
			s.checkExpiry()
		}
	}
}

func (s *ServerTLS) reloadLogged(lastErr *string) {
	err := s.Reload()
	switch {
	case err == nil:
		*lastErr = ""
	case err.Error() != *lastErr:
		*lastErr = err.Error()
		s.opts.Logf("ERROR: %v", err)
	}
}

// checkExpiry logs once if the certificate being served has expired.
func (s *ServerTLS) checkExpiry() {
	info := s.info.Load()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.expired && s.opts.Now().After(info.NotAfter) {
		s.expired = true
		s.opts.Logf("ERROR: the TLS certificate %s expired on %s: clients will reject it. Install a new one and send SIGHUP",
			info.Subject, info.NotAfter.UTC().Format(time.RFC3339))
	}
}

// fileStamps is a change-detection fingerprint of the watched files.
type fileStamps [3]string

func (s *ServerTLS) stamps() fileStamps {
	var f fileStamps
	for i, p := range []string{s.opts.CertFile, s.opts.KeyFile, s.opts.ClientCAFile} {
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			f[i] = "missing"
			continue
		}
		f[i] = fmt.Sprintf("%d/%d", fi.ModTime().UnixNano(), fi.Size())
	}
	return f
}
