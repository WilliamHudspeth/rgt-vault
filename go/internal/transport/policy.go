// Package transport is the TLS policy of rgt-vault (batch H6, RGT-251, 422,
// 455-458): one place that decides which protocol versions, cipher suites and
// certificates are acceptable, shared by the server (`rgt-vault serve`), the
// cutover gateway and every HTTP client (CLI, MCP, TUI).
//
// The policy, for both directions:
//
//   - TLS 1.2 is the floor; TLS 1.3 is negotiated whenever the peer supports
//     it (Go always prefers the highest common version).
//   - TLS 1.2 is limited to ECDHE key exchange with AEAD ciphers (AES-GCM,
//     ChaCha20-Poly1305). No CBC, RC4, 3DES or static-RSA key exchange, so
//     every TLS 1.2 session has forward secrecy. TLS 1.3 suites are all AEAD
//     and are not configurable in crypto/tls.
//   - Key exchange groups: the X25519+ML-KEM-768 post-quantum hybrid, X25519,
//     P-256, P-384. crypto/tls has no finite-field Diffie-Hellman, so there
//     are no weak DH parameters to configure, and it implements no TLS
//     compression (CRIME) and no server-side renegotiation.
//   - Certificate verification is always on. There is no code path that sets
//     InsecureSkipVerify (a source-scan test enforces this).
package transport

import (
	"crypto/tls"
	"net/http"
	"time"
)

// AEADCipherSuites are the only TLS 1.2 cipher suites this program offers or
// accepts: ECDHE with AES-GCM or ChaCha20-Poly1305.
func AEADCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// CurvePreferences returns the key-exchange groups, most preferred first.
func CurvePreferences() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
}

// MinVersion is the protocol floor.
const MinVersion = tls.VersionTLS12

// baseConfig is the policy shared by servers and clients.
func baseConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       MinVersion,
		CipherSuites:     AEADCipherSuites(),
		CurvePreferences: CurvePreferences(),
		// crypto/tls never renegotiates on the server; for a client this
		// refuses the (TLS 1.2) renegotiation attack surface outright.
		Renegotiation: tls.RenegotiateNever,
	}
}

// Timeouts for outgoing connections.
const (
	handshakeTimeout = 10 * time.Second
	idleConnTimeout  = 90 * time.Second
)

// IsSuiteAEAD reports whether id is one of the allowed TLS 1.2 suites or a
// TLS 1.3 suite (all of which are AEAD).
func IsSuiteAEAD(id uint16) bool {
	for _, s := range AEADCipherSuites() {
		if s == id {
			return true
		}
	}
	for _, s := range tls.CipherSuites() {
		if s.ID == id {
			for _, v := range s.SupportedVersions {
				if v == tls.VersionTLS13 {
					return true
				}
			}
		}
	}
	return false
}

// newBaseTransport returns the http.Transport settings common to all clients.
func newBaseTransport() *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: handshakeTimeout,
		IdleConnTimeout:     idleConnTimeout,
		MaxIdleConns:        10,
	}
}
