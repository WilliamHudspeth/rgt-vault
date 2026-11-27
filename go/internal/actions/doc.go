// Package actions is the Go port of python/server/actions.py: the server-side
// "named actions" a caller can run against a leased secret without ever being
// handed the plaintext.
//
// The four built-ins are echo, http_get_with_auth, http_post_with_auth and
// openai_chat. An action receives the leased secret as a []byte (the vault's
// Lease callback owns it and wipes it afterwards), the caller's params, and
// returns a JSON-serialisable map. Wire it into the vault like this:
//
//	reg, _ := actions.NewBuiltinRegistry(actions.Config{})
//	err := v.Lease(ctx, req, func(secret []byte) error {
//		out, err = reg.Execute(ctx, "http_get_with_auth", secret, params)
//		return err
//	})
//
// # Hardening relative to Python (each is pinned by a test)
//
//   - One resolution per connection: the address that passed the range check
//     is the address that is dialled (netguard.Guard.DialContext), closing the
//     validate-then-urlopen DNS-rebinding gap.
//   - Redirects are refused by default; Config.MaxRedirects > 0 follows a
//     bounded number, re-validating every hop and dropping the bearer token
//     when a hop leaves the original origin. Python's urlopen follows
//     redirects unchecked and re-sends the Authorization header.
//   - https only by default; http:// needs Config.AllowInsecureHTTP because
//     every built-in action carries the secret in a header.
//   - No userinfo, no IDN (punycode only), no ambiguous numeric IPv4 forms,
//     no IPv6 zones, no percent-encoded hosts.
//   - Optional per-action host:port allow-list (Config.HostAllowlist).
//   - Link-local/metadata (169.254.0.0/16, fe80::/10), multicast and
//     unspecified addresses are refused even with AllowPrivateNetwork.
//   - The per-request "allow_private_network" param is NOT accepted (it was
//     already outside Python's params_schema, so the HTTP path rejected it);
//     only the operator-level Config.AllowPrivateNetwork lifts the block, and
//     it applies to openai_chat's base_url too (Python always re-checked
//     base_url as if it were false).
//   - Header names must be RFC 7230 tokens; values are printable ASCII;
//     CR/LF/NUL are refused; hop-by-hop, framing, proxy and forwarding headers
//     and Authorization cannot be set by the caller; count and size are
//     capped; duplicate names (case-insensitively) are refused.
//   - Error text never contains a response body, the secret, the query string,
//     or a resolved IP; log lines carry only action, host and status class.
//   - TLS verification cannot be switched off; Config.RootCAs only changes
//     the trust pool.
//
// The secret must be printable ASCII (it becomes a bearer token). Go strings
// are immutable, so the header copy of the secret cannot be wiped; it lives
// until the request is garbage collected. The []byte the vault owns is wiped
// by the vault as before.
package actions
