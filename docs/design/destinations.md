# Destination allow-list for HTTP actions (RGT-523)

Status: design, for review before implementation (Go only; `go/internal/actions`).

## Problem

An agent that the policy allows to *use* a secret chooses the URL the secret
is sent to. `http_get_with_auth` and `http_post_with_auth` take a `url`
parameter, and `openai_chat` takes `base_url`. The vault adds the secret as
`Authorization: Bearer …` and sends the request. netguard limits the request
to https and to public addresses, but any public https host is accepted. An
agent allowed to use `github/GITHUB_TOKEN` can therefore send the token to a
host it controls. The assessment of 2026-11-27 (section C4) showed this.

`actions.Config.HostAllowlist` (keyed by *action*) and
`netguard.WithAllowedHosts` exist, but `server.OpenStack` builds the action
registry with `actions.Config{AllowPrivateNetwork: …}` only, so neither is
used. A per-action list would not help much anyway: the question is where
*this secret* may go, not where `http_get_with_auth` may go.

## Decision

### 1. Where the list lives

A new top-level `destinations:` map in the policy YAML, next to `rules:` and
`honey_capabilities:`:

```yaml
rules:
  - agent: coder
    namespace: github
    action: read
    effect: allow
    allowed_hosts: [api.github.com]      # optional, may only narrow
destinations:
  github/GITHUB_TOKEN: [api.github.com]
  openai/*:            [api.openai.com]
  internal/DEPLOY_KEY: ["https://deploy.example.com:8443", "*.ci.example.com"]
```

- **Key:** `namespace/name` (one secret) or `namespace/*` (every secret in the
  namespace). An exact `namespace/name` entry *replaces* the `namespace/*`
  entry for that secret; the two are not merged. Any other key form (no
  slash, a `*` anywhere else, an empty part) is a load error.
- **Value:** a list of entries. An empty list is allowed and means "this
  secret may not be sent anywhere" (explicit, fail closed). An entry is one of
  - `https://host[:port]` (no path, query, fragment or userinfo),
  - `host[:port]` (https implied),
  - `*.example.com[:port]`.
  `http://` entries are a load error: the HTTP actions refuse plain http
  (netguard), and the policy file must not suggest otherwise.
- **Per-rule narrowing:** an ABAC rule may carry `allowed_hosts:` (same entry
  syntax). When the rule that granted the lease (the allow rule
  `Engine.Evaluate(agent, namespace, purpose, "read")` returns, which is the
  one the lease itself was granted by) has `allowed_hosts`, a destination must
  match **both** the secret's list and the rule's list. The rule list can
  therefore only narrow the effective set (intersection), never widen it: a
  host on the rule list but not on the secret list is refused. A rule list
  without any `destinations:` entry for the secret does not grant anything
  (still `NO_LIST`).
- **Python compatibility:** Python's `ABACPolicyEngine` reads
  `parsed.get("rules", [])` and `rule.get(...)` only, so the extra top-level
  key and the extra rule key are ignored and the file stays readable by the
  Python line. The Go policy engine keeps every rule key already (`Rule.Get`),
  so `simulate`/`explain` show `allowed_hosts` in the matched rule, as Python
  does. The policy hash is the hash of the file text, so it changes when the
  file changes, as for any other edit.
- **Parsing:** `internal/policy` gains `DestinationsFromYAML(policyYAML)` that
  returns the raw map (same YAML hardening as `parseRules`: safe tags, single
  document, bounded node count; last duplicate key wins, as in PyYAML). A
  value that is not a list of strings is an error (fail loud, as for
  `honey_capabilities`).

### 2. Normalisation (one helper, at load and per request)

`actions.ParseDestination(entry)` (load) and `actions.normalizeDestHost(host)`
(request) share one code path:

1. ASCII only. A non-ASCII host is **rejected** (`NON_ASCII_HOST`); IDNs must be
   written in punycode (`xn--…`). No IDNA library: `golang.org/x/net/idna` is
   not a dependency and `golang.org/x/text` has no IDNA package, and v0.4.0
   adds no dependency. netguard already refuses non-ASCII URLs, so the two
   agree.
2. Lowercase; strip **one** trailing dot (`api.github.com.` = `api.github.com`).
3. Reject: userinfo (`user@host`), empty labels (`a..b`, leading dot), labels
   over 63 bytes or a host over 253, characters other than `a-z 0-9 - _`,
   `*` alone, `*` anywhere but as the whole leftmost label (`*foo.com`,
   `a.*.com`), and a wildcard directly over a public suffix: over any single
   label (`*.com`, `*.local`), or over a two-label name whose labels are both
   on a small built-in list (`com net org io dev app co uk de eu info biz cloud
   ai me us`), such as `*.co.uk`. No PSL dependency; the list is a guard
   against obvious mistakes, not a full PSL.
4. **IP literals** match only an entry that is the same literal, compared in
   canonical form (`netip.Addr.String()`; IPv6 in brackets in entries:
   `[2001:db8::1]:443`). A request to an IP literal that is not listed is
   `IP_LITERAL`. Wildcards never match an IP.
5. **Ports:** default 443. A port in an entry or a URL must match exactly; an
   entry without a port means 443, not "any port".
6. **Wildcards:** `*.example.com` matches exactly **one** extra label
   (`api.example.com`), never the apex (`example.com`) and never two labels
   (`a.b.example.com`).

Errors at load name the key and the entry and say why, for example
`destinations: "github/*": "*.com" is a wildcard over a public suffix`.

### 3. Enforcement

- **Identity on the context.** The callers that lease a secret for an action
  put `actions.SecretUse{Agent, Namespace, Name, Purpose}` on the context
  before `Registry.Execute`: `handlers.UseSecret` (POST
  `/v1/secrets/{ns}/{name}/use`) and the `secrets.use` capability
  (`internal/capabilities/builtin.go`, one line; outside the brief's file list,
  but without it the capability path would either bypass the check or always
  fail).
- **Where.** In the HTTP actions (`http_get_with_auth`, `http_post_with_auth`,
  `openai_chat`), after parameter validation and **before** netguard's
  `CheckURL`, any DNS lookup or dial. For `openai_chat` the checked URL is
  `base_url` (or the default `https://api.openai.com`). `echo` sends nothing
  and is not checked.
- **Fail closed.** When the registry was built with a `DestinationPolicy`
  (the server always does) and the context carries no `SecretUse`, the request
  is refused (`NO_LIST`). A registry built without one (library users, the
  existing action tests) behaves as before.
- **netguard stays.** The destination check is in addition to netguard: https
  only, the range policy, resolve-once and dial-the-validated-IP (the DNS
  rebinding defence) all still apply. A listed host that resolves to a
  private address is still refused unless `--allow-private-network`.
- **Redirects.** The server follows no redirects today (`MaxRedirects` is 0,
  so a 3xx is returned as an error). For registries that do follow them, each
  request gets its own `CheckRedirect` that, before netguard's own check:
  re-checks the hop against the same effective list (`REDIRECT_OFF_LIST`
  when it is not on it), and refuses any hop to a different origin (scheme,
  host, port) even when that origin is listed (`REDIRECT_CROSS_ORIGIN`), so
  the credential is never re-sent elsewhere and never silently dropped
  either. Same-origin redirects work as before.

### 4. Default and migration

- **Default: refuse.** A secret with no entry (neither `ns/name` nor `ns/*`)
  is refused with HTTP 403 and the message

  `no destination is allowed for secret <ns>/<name>: add it under "destinations:" in the policy file`

  Other refusals say which `host:port` and why, never the path or query:
  `destination evil.example:443 is not allowed for secret github/GITHUB_TOKEN (HOST_NOT_LISTED)`.
  The error has its own kind, `actions.ErrDestinationRefused`, which the
  handlers map to 403 `DestinationRefusedError` (before the generic
  `ActionExecutionError` 500 rule).
- **Migration flag:** `serve --destinations=enforce|warn` (default `enforce`).
  `warn` sends the request but logs and audits the would-be refusal exactly
  as `enforce` would (the row says `mode=warn`). It is documented as
  temporary: it will be removed in the release after v0.4.0.
- **Start-up warning:** after the vault opens, `serve` logs one warning per
  namespace that has active secrets without an entry, with the count, for
  example `WARNING: destinations: namespace "github" has 2 secret(s) with no
  destinations entry; HTTP actions with them are refused`. The text names the
  namespace only, not the secrets.

### 5. Audit and security event

A refusal (and a would-be refusal in `warn` mode) writes **one** additive audit
row, action `DESTINATION_REFUSED` (new constant
`vault.DestinationRefusedEvent`), with the agent in the `agent_id` column,
`namespace/name` as the secret name, and details

`action=http_get_with_auth destination=evil.example:443 reason=HOST_NOT_LISTED mode=enforce`

Reason codes: `NO_LIST`, `HOST_NOT_LISTED`, `PORT_MISMATCH` (the host is on
the list with another port), `IP_LITERAL`, `NON_ASCII_HOST`,
`REDIRECT_OFF_LIST`, `REDIRECT_CROSS_ORIGIN`. The destination is
`host:port` only: never the path, the query, a header or the body. A
non-ASCII host is written as `<non-ascii>` so the row cannot carry
look-alike text.

It also raises a security event (`approval.EventKind("DESTINATION_REFUSED")`)
through the server's notifier (log line, and the security webhook when set).
It is not marked Critical. The audit hash input, existing actions and
existing row text are unchanged.

Ordering: the destination check runs inside the lease callback, after the
ABAC check, so an agent the policy denies learns nothing about the
destinations configuration and gets the ordinary denial. The lease rows
(`SECRET_LEASED`, `LEASE_RETURNED`) are written as before; the refusal row
sits between them.

### 6. Honey capabilities

Unchanged. A refused destination is not a honey event, and honey answers do
not go through the HTTP actions, so `TestHTTPIndistinguishable` and
`TestVaultIndistinguishable` are not affected.

## Limits (documented in the threat model)

- The list says where a credential may be **sent**; it does not stop a listed
  host from being misused (for example a GitHub token used against a
  repository the operator did not intend). Narrow scopes on the credential
  remain necessary.
- A listed host that serves attacker-controlled content (a shared host, an
  open redirect on another origin) is not covered: cross-origin redirects are
  refused, but a listed origin that proxies requests elsewhere is trusted.
- `warn` mode sends the credential to unlisted hosts; it exists only for
  migration.
- The public-suffix guard is a small built-in list, not the PSL: `*.github.io`
  style entries are accepted and the operator must judge them.

## Rejected options

- **Per-action lists** (`Config.HostAllowlist`): they bind the wrong thing;
  one action carries many secrets.
- **Lists in the rule only:** a new allow rule (or a typo in one) would widen
  where a secret goes. Binding to the secret and letting rules only narrow
  keeps the secret owner in control.
- **IDNA normalisation:** needs `golang.org/x/net` (a new dependency); rejecting
  non-ASCII is safe and simple.
- **`*.x` matching any depth:** looser and rarely needed; list deeper names
  explicitly.
