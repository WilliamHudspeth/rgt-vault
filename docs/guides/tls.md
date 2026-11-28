# TLS and transport security

Applies to the Go line (`go/`), which is the line of record. Batch H6; issues RGT-251, 422, 455, 456, 457, 458.
Evidence per issue: [`docs/security/asvs/V9-TLS.md`](../security/asvs/V9-TLS.md).

## Choose a deployment

| Deployment | When | How |
|---|---|---|
| **Loopback, plain HTTP** (default) | One machine; agents and the daemon run there. The traffic never leaves the host. | `rgt-vault serve` binds `127.0.0.1:8765`. Nothing to configure. |
| **Daemon terminates TLS** | The daemon must be reachable from other hosts and you want no extra moving part. | `rgt-vault serve --host 0.0.0.0 --tls-cert server.crt --tls-key server.key` |
| **TLS reverse proxy** | You already run nginx/Caddy, want ACME renewal, HSTS, rate limits or a WAF. The daemon stays on loopback. | [`deploy/nginx-rgt-vault.conf`](../../deploy/nginx-rgt-vault.conf), [`deploy/Caddyfile.example`](../../deploy/Caddyfile.example) |

A non-loopback `--host` **without TLS is refused at startup.** The only override is
`--allow-insecure-non-loopback` (the old `--allow-non-loopback` is a deprecated alias for it): it prints
`WARNING: INSECURE ... PLAIN HTTP`, and writes a `server_insecure_bind` row to the audit chain. Use it only on a
network you fully control; bearer tokens and secret values would cross it in clear text.

## `serve` flags

| Flag | Env | Meaning |
|---|---|---|
| `--tls-cert FILE` | `RGT_VAULT_TLS_CERT` | PEM certificate (leaf first, then intermediates). Both `--tls-cert` and `--tls-key`, or neither. |
| `--tls-key FILE` | `RGT_VAULT_TLS_KEY` | PEM private key. **Refused if group or other can read it** (Unix). |
| `--tls-client-ca FILE` | `RGT_VAULT_TLS_CLIENT_CA` | PEM CA bundle: turns on mutual TLS ([below](#mutual-tls-opt-in-rgt-458)). |
| `--tls-client-auth MODE` | `RGT_VAULT_TLS_CLIENT_AUTH` | `require` (default with a client CA) or `verify-if-given`. |
| `--tls-reload-interval D` | | Poll the files for changes, default `1m`; `0` = reload only on SIGHUP. |
| `--allow-insecure-non-loopback` | | Plain HTTP on a non-loopback host. Loud and audited. |

Flag beats environment beats default. Nothing is read from a file path that is not given.

## What the daemon enforces

Implemented once in `go/internal/transport` and used by the server, the cutover gateway and every client.

| Property | Setting |
|---|---|
| Protocol | TLS 1.2 minimum; TLS 1.3 preferred (Go picks the highest common version). SSL 3.0, TLS 1.0 and 1.1 are rejected with a `protocol_version` alert. |
| TLS 1.2 suites | `ECDHE-{ECDSA,RSA}` with `AES-256-GCM`, `AES-128-GCM`, `CHACHA20-POLY1305` only. No CBC, RC4, 3DES, or static-RSA key exchange, so every session is forward secret. TLS 1.3 suites are AEAD by definition. |
| Key exchange groups | `X25519MLKEM768` (post-quantum hybrid), `X25519`, `P-256`, `P-384`. Go has no finite-field DH, so there are no DH parameters to misconfigure. |
| Compression | None: crypto/tls does not implement TLS compression (CRIME). |
| Renegotiation | None: crypto/tls does not renegotiate on the server; clients set `RenegotiateNever`. |
| HTTP/2 | Allowed (ALPN `h2`, then `http/1.1`). |
| Session tickets | **Disabled**, for TLS 1.2 and 1.3. Go keeps ticket keys in process memory for days; a memory disclosure would let recorded sessions be decrypted afterwards. A local vault's connection rate does not need the saved handshake. |
| HSTS | `Strict-Transport-Security: max-age=31536000` on every response served over TLS (no `includeSubDomains`: the daemon does not own the rest of the domain). |
| Certificate checks at startup | Pair must match; leaf inside its validity window (**expired or not-yet-valid refuses to start**); expiry within 14 days is a warning; at least one SAN (the CN is ignored by every client); `serverAuth` key usage; not a CA certificate; no MD2/MD5/SHA-1 signature; RSA keys of at least 2048 bits. A warning if the certificate does not cover `--host`. |
| Key file | Must be a regular file with mode `0600`/`0400`. A key readable by group/other gives `private key ... has mode 0640 ... Restrict it first: chmod 600 ...` and the server does not start. Symlinks are judged by their target. |

### Key file permissions and Windows

On Unix the daemon checks the mode bits. **On Windows Go's mode bits do not reflect the ACL, so the check is skipped**;
the operator must restrict the key's ACL to the service account and `Administrators`:

```powershell
icacls C:\ProgramData\rgt-vault\tls\server.key /inheritance:r /grant:r "NT SERVICE\rgt-vault:(R)" "BUILTIN\Administrators:(F)"
```

The daemon should run as its own unprivileged account that owns the key (`deploy/rgt-vault-go.service` runs as `rgtvault`;
copy the key to e.g. `/etc/rgt-vault/tls/server.key`, `chown rgtvault:rgtvault`, `chmod 600`). A Let's Encrypt
`privkey.pem` is root-only: copy it with a deploy hook rather than loosening its mode.

## Rotating the certificate

The daemon reloads certificate, key and client-CA files **without dropping connections**: established connections keep
running; new handshakes use the new certificate (`tls.Config.GetCertificate`).

- `kill -HUP $(pidof rgt-vault)` or `systemctl reload rgt-vault-go` reloads immediately. With no `--tls-cert`, SIGHUP is ignored and logged.
- Independently the files are checked every `--tls-reload-interval` (modification time and size).
- If the new material is invalid (key mismatch, expired, key permissions, unreadable) the **old certificate keeps being served** and the error is logged. A running certificate that expires is logged once as an `ERROR`.

Certbot hook example (`/etc/letsencrypt/renewal-hooks/deploy/rgt-vault.sh`):

```sh
#!/bin/sh
install -m 0644 -o rgtvault /etc/letsencrypt/live/vault.example.com/fullchain.pem /etc/rgt-vault/tls/server.crt
install -m 0600 -o rgtvault /etc/letsencrypt/live/vault.example.com/privkey.pem   /etc/rgt-vault/tls/server.key
systemctl reload rgt-vault-go
```

## Clients: CLI, MCP, TUI

`rgt-vault --host https://vault.example.com:8765 ...` verifies the server certificate and host name **by default**.

| Flag | Env | Meaning |
|---|---|---|
| `--cacert FILE` | `RGT_VAULT_CACERT` | Trust only the CAs in this PEM file (a private CA, or the server's own self-signed certificate). It *replaces* the system trust store. |
| `--client-cert FILE`, `--client-key FILE` | `RGT_VAULT_CLIENT_CERT`, `RGT_VAULT_CLIENT_KEY` | Present a client certificate to a server that requires mTLS. The key must not be group/other-readable. |
| `--allow-insecure-http` | | Allow `http://` to a **non-loopback** host (trusted network only). |

- There is **no** `--insecure-skip-verify` and no environment variable that disables verification (a wrong CA, an unknown CA or a host-name mismatch is an error). A source-scan test fails the build if `InsecureSkipVerify` or a TLS version below 1.2 appears in production code.
- The client floor is TLS 1.2 with the same AEAD suites as the server.
- `http://` is accepted only for loopback hosts. For any other host the CLI, MCP and TUI refuse **before sending the token**.
- `status`, every HTTP subcommand, `mcp` and `tui` share the one transport (`internal/transport`). Proxy environment variables (`HTTPS_PROXY`) are not used.
- Credentials travel only in the `Authorization` header, never in the URL: a token in the query string is not accepted (`401`).

## Mutual TLS (opt-in, RGT-458)

**Evaluation result:** implemented as an optional transport layer; off by default; the bearer token is **not** replaced.

```sh
rgt-vault serve --host 0.0.0.0 --tls-cert server.crt --tls-key server.key --tls-client-ca clients-ca.pem   # require
rgt-vault serve ... --tls-client-ca clients-ca.pem --tls-client-auth verify-if-given                       # optional cert
rgt-vault --host https://vault:8765 --cacert server-ca.pem --client-cert agent.crt --client-key agent.key status
```

Threat model:

| mTLS adds | mTLS does **not** add |
|---|---|
| Only holders of a certificate from your client CA can open a connection at all: scanners, stolen-token replay from another machine and unauthenticated probing of `/healthz` are cut off before any HTTP is parsed. | Per-agent identity or authorization. The certificate is **not** mapped to an agent id; ABAC and scopes still come from the bearer token (batch H1). A stolen token *and* certificate from the same host still works. |
| A second factor that is bound to a key file, so a leaked token alone is not enough. | Protection from a compromised client host: the certificate key sits next to the token. |
| Certificate-bound revocation through the CA (short-lived client certificates; new CA bundle + SIGHUP). | An OCSP/CRL check: Go does not do revocation. Use certificates that live hours or days, or rotate the client CA bundle and send SIGHUP (the client CA pool is reloaded without a restart). |

When to use it: server-to-server calls over a network you do not control (a build server, a second site, a container
network shared with other tenants), or any deployment where the daemon is reachable by hosts that should not even be
able to attempt authentication. When **not**: a loopback daemon with local agents (nothing to filter; the OS user
boundary is the control), or browsers. `require` also blocks `/healthz` probes without a certificate: give the monitoring
system a client certificate or use `verify-if-given` (and an authenticated check). A reverse proxy can do the same
(`ssl_verify_client` in the nginx example, `client_auth` in Caddy) and then the daemon needs no mTLS flags.

## CAA and revocation (RGT-457: applicability)

The loopback daemon has no public domain and no certificate. These items exist only if **you** expose it under a name,
and they belong to the operator's DNS and CA accounts, not to the program:

1. **CAA record** on the zone that holds the name: `vault.example.com. CAA 0 issue "letsencrypt.org"` (and `0 iodef "mailto:security@example.com"`), listing only the CA(s) you use. Check with `dig CAA vault.example.com`. For ACME with DNS-01 also consider `accounturi=` and `validationmethods=` parameters.
2. **Revocation of the server certificate.** Prefer short-lived certificates (90 days or less; many CAs now offer a few days) over relying on OCSP. If your CA still issues an OCSP responder URL, enable stapling at the reverse proxy (`ssl_stapling` in `deploy/nginx-rgt-vault.conf`; Caddy staples automatically). Go's `crypto/tls` neither staples nor checks revocation, so the daemon terminating TLS itself has no stapling: use the proxy deployment if you need it.
3. **Know how to revoke** at your CA and rotate: generate a new key (never reuse a compromised one), install, `systemctl reload`.
4. **Monitor** certificate transparency for your name (e.g. crt.sh alerts) and expiry (the daemon logs a warning 14 days out).
5. **Client certificates** (mTLS): issue them with a short life from a dedicated CA that signs nothing else.

## Verifying a deployment

```sh
openssl s_client -connect vault.example.com:8765 -tls1_1 </dev/null   # must fail (alert protocol_version)
openssl s_client -connect vault.example.com:8765 -tls1_2 </dev/null | grep -E "Protocol|Cipher"
testssl.sh --protocols --ciphers vault.example.com:8765
```

## Known limits

- The daemon's per-source authentication-failure limiter keys on the TCP peer address. Behind a reverse proxy every client appears as the proxy's address, and the daemon ignores `X-Forwarded-For` on purpose (it is client-controlled). Rate-limit at the proxy (`limit_req` in the nginx example) until a trusted-proxy setting exists.
- Outbound webhooks and built-in actions may still use `http://` URLs chosen by the operator; see the follow-up in `V9-TLS.md`.
- The session-ticket policy trades a few milliseconds per new connection for forward secrecy against memory disclosure.
- Not verified here: the nginx and Caddy files were written against their documentation but not run in CI (no nginx/Caddy on the runner); run `nginx -t` / `caddy validate` before use.
