// Package netguard provides an SSRF-safe net.Dialer for outbound HTTP
// clients (RGT-197 — the Go counterpart of the Python SSRF guard added for
// RGT-109 in internal/llm/providers/ollama.py).
//
// A tls.Config.ServerName check alone is not enough: it verifies the
// certificate's name but does nothing to stop the underlying TCP connection
// from being made to a link-local or cloud-metadata address (169.254.0.0/16,
// fe80::/10, including the AWS/GCP metadata endpoint 169.254.169.254) if the
// configured host resolves there. net.Dialer.Control runs after DNS
// resolution but before the connection is established, so it can reject the
// resolved address directly.
package netguard

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// NewDialer returns a *net.Dialer whose Control callback rejects link-local
// and metadata addresses unconditionally, and rejects any other
// non-loopback address unless allowRemote is true. Loopback (127.0.0.0/8,
// ::1) is always permitted, matching the local-first default used
// throughout this codebase.
//
// NOTE (documented limitation, matches the Python-side caveat in
// ollama.py): this checks the address the dialer is about to connect to,
// which closes the SSRF window at the network layer rather than relying on
// a separately-resolved hostname check, but it does not eliminate a
// DNS-rebinding race between an application-level pre-check and the actual
// dial. For this codebase's threat model (a locally configured backend
// host, not arbitrary user-supplied URLs per request) that residual risk is
// accepted.
func NewDialer(allowRemote bool) *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("netguard: cannot parse dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("netguard: dial address %q did not resolve to a literal IP", host)
			}
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return fmt.Errorf("netguard: %s is a link-local/metadata address, forbidden", ip)
			}
			if !allowRemote && !ip.IsLoopback() {
				return fmt.Errorf("netguard: %s is a non-loopback address; remote hosts require an explicit opt-in", ip)
			}
			return nil
		},
	}
}
