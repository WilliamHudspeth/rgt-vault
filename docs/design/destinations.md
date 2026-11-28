# Destination allow-list for HTTP actions (RGT-523)

Status: implemented in Go (`go/internal/actions/destinations.go`, wired in
`go/internal/server/stack.go`). Design reviewed 2026-11-28 (Opus, "go with
changes"; the changes are folded in below).

## Problem

An agent that the policy allows to *use* a secret chooses the URL the secret
is sent to. `http_get_with_auth` and `http_post_with_auth` take a `url`
parameter, and `openai_chat` takes `base_url`. The vault adds the secret as
`Authorization: Bearer …` and sends the request. netguard limits the request
to https and to public addresses, but before this change any public https
host was accepted. An agent allowed to use `github/GITHUB_TOKEN` could send
the token to a host it controls (assessment of 2026-11-27, section C4).

`actions.Config.HostAllowlist` (keyed by *action*) and
`netguard.WithAllowedHosts` existed, but `server.OpenStack` built the action
registry with `actions.Config{AllowPrivateNetwork: …}` only, so neither was
used. A per-action list does not help much anyway: the question is where
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
  namespace). Both halves are checked with the vault's own namespace and name
  validation. An exact `namespace/name` entry *replaces* the `namespace/*`
  entry for that secret; the two are not merged.
- **Value:** a list of strings. An empty list means "this secret may not be
  sent anywhere". `null`, a scalar instead of a list, or a non-string entry is
  a load error. An entry is one of
  - `https://host[:port]` (no path other than `/`, no query, fragment or
    userinfo),
  - `host[:port]` (https implied),
  - `*.example.com[:port]`.
  `http://` entries are a load error.
- **Strict YAML under `destinations:`:** a duplicate key inside the map, a
  duplicate top-level `destinations:` key, YAML aliases and `<<` merge keys
  are load errors (not last-wins as for `rules:`): a silently shadowed entry
  would widen or narrow a secret without anyone noticing.
- **List-form policy files** (a bare list of rules) have nowhere to put
  `destinations:`. `serve` says so at start-up: convert the file to a mapping
  with `rules:` and `destinations:`.
- **Per-rule narrowing:** an ABAC rule may carry `allowed_hosts:` (same entry
  syntax, same strictness: `allowed_hosts: api.github.com` as a scalar is a
  load error, not ignored). The check evaluates the policy once for
  `(agent, namespace, purpose, "read")`, the same attributes the lease used,
  and takes **every** matching allow rule that carries `allowed_hosts`. A
  destination must match the secret's list **and** every one of those rule
  lists. That makes narrowing independent of rule order (the engine itself
  reports the *last* matching allow rule), and it means a rule can only
  narrow, never widen. A rule list without a `destinations:` entry for the
  secret grants nothing (`NO_LIST`).
  The agent chooses `purpose`. Narrowing therefore only binds through rules
  the agent cannot avoid matching (rules on `agent`/`namespace`, or with
  `purpose: "*"`). A rule keyed on a specific purpose narrows only requests
  that name that purpose.
- **One source:** `OpenStack` builds the destination policy from the same
  policy text it hands to the vault (no second read from disk), so the two
  cannot disagree.
- **Python compatibility:** Python's `ABACPolicyEngine` reads
  `parsed.get("rules", [])` and `rule.get(...)` only, so both new keys are
  ignored and the file stays readable by the Python line. **The Python line
  does not enforce destinations.**

### 2. Normalisation (one helper, at load and per request)

`actions.ParseDestination(entry)` (load) and the request-side matcher share
one host normaliser:

1. ASCII only. A non-ASCII entry is a load error; IDNs are written in
   punycode (`xn--…`). No IDNA library (`golang.org/x/net/idna` would be a new
   dependency). netguard refuses non-ASCII URLs before the check runs.
2. Lowercase; strip **one** trailing dot.
3. Reject: userinfo, empty labels, labels over 63 bytes or a host over 253,
   characters other than `a-z 0-9 - _`, `*` alone, `*` other than as the whole
   leftmost label, IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`), and port 0.
4. **Wildcards** are refused (load error) over:
   - a single label (`*.com`, `*.local`) or an all-numeric base;
   - two labels both on the built-in list `com net org io dev app co uk de eu
     info biz cloud ai me us` (`*.co.uk`);
   - `<x>.<cc>` where `<cc>` is any two-letter label and `<x>` is one of
     `co com net org ac gov edu ne or go gob mil ltd plc sch nhs`
     (`*.com.au`, `*.ac.uk`, `*.gov.uk`);
   - shared-hosting bases where anyone can get a subdomain: `vercel.app`,
     `netlify.app`, `workers.dev`, `pages.dev`, `herokuapp.com`,
     `azurewebsites.net`, `ngrok-free.app`, `ngrok.io`, `trycloudflare.com`,
     `firebaseapp.com`, `web.app`, `appspot.com`,
     `execute-api.<region>.amazonaws.com`, `lambda-url.<region>.on.aws`.
   `*.github.io` and `*.s3.amazonaws.com` load with a warning. An exact tenant
   name (`myco.vercel.app`) is always fine. No PSL dependency; this is a guard
   against obvious mistakes, not a full PSL.
   `*.example.com` matches exactly **one** extra label: `api.example.com`,
   never `example.com`, never `a.b.example.com`.
5. **IP literals** match only an entry that is the same literal in canonical
   form (`netip.Addr.String()`; IPv6 bracketed in entries). Wildcards never
   match an IP. A request to an unlisted IP literal is `IP_LITERAL`.
6. **Scheme and port:** only `https` matches. Default port 443; ports match
   exactly (an entry without a port means 443, not any port).

### 3. Enforcement

- **Identity on the context.** Callers that lease a secret for an action put
  `actions.SecretUse{Agent, Namespace, Name, Purpose}` on the context:
  `handlers.UseSecret` and the `secrets.use` capability (immediately before
  `act.Run`, built from exactly the values passed to `Lease`).
- **Where.** In `endpoint.send`, right after `u, err := e.guard.CheckURL(r.url)`
  and on that same `u`, which is the URL the request is built from. This
  covers all three HTTP actions and, for `openai_chat`, the final URL
  (`base_url` or the default `https://api.openai.com`, plus
  `/v1/chat/completions`). The check runs before any DNS lookup or dial.
- **Backstops.** The effective decision is also put on the request context and
  re-checked in `Guard.DialContext` (the `host:port` actually dialled) and in
  `checkRedirect` (through `req.Context()`), so a parser difference between
  `net/url` and the transport cannot route the credential elsewhere.
- **Fail closed.** An `actions.Config` without a destination policy refuses
  every HTTP action (`NO_LIST`). Unrestricted sending must be asked for
  explicitly (`Config.UnrestrictedDestinations: true`; only the pre-existing
  action tests set it). A context with no `SecretUse` is refused. When there
  is no policy file, or it has no `destinations:` key, the server still
  installs an empty policy (every secret is `NO_LIST`).
- **netguard stays.** https only, the range policy and resolve-once /
  dial-the-validated-IP (the DNS rebinding defence) all still apply.
- **Redirects.** The server follows none (`MaxRedirects` is 0, so a 3xx is an
  error). For registries that do follow them, `checkRedirect` re-checks every
  hop against the same effective list (`REDIRECT_OFF_LIST`) and refuses any
  hop to a different origin even when that origin is listed
  (`REDIRECT_CROSS_ORIGIN`). Same-origin redirects work.

### 4. Default and migration

- **Default: refuse.** A secret with no entry (neither `ns/name` nor `ns/*`)
  is refused with HTTP 403 `DestinationRefusedError` and the message

  `no destination is allowed for secret <ns>/<name>: add it under "destinations:" in the policy file`

  Other refusals name the `host:port` and the reason, never the path or query:
  `destination evil.example:443 is not allowed for secret github/GITHUB_TOKEN (HOST_NOT_LISTED)`.
- **Migration flag:** `serve --destinations=enforce|warn` (default `enforce`).
  `warn` relaxes **only `NO_LIST`**: a secret with no entry is sent, after a
  `DESTINATION_REFUSED` row with `mode=warn` has been written; if that audit
  write fails the request is not sent. A secret that **has** an entry is
  enforced in both modes. `warn` logs a loud start-up line
  (`destinations: WARN mode: secrets without an entry may be sent to any host`),
  and the mode is shown in the start-up summary. It is temporary and will be
  removed in the release after v0.4.0.
- **Start-up warnings** (namespaces only, never secret names):
  - one per namespace with active secrets that have no entry, with the count;
  - one per namespace where an exact `ns/name` entry matches no stored secret
    (a typo such as `github/GITHUB_TOKN` next to `github/*` would otherwise
    leave the real token on the wider list unnoticed).

### 5. Audit and security event

A refusal (and a relaxed `NO_LIST` in `warn` mode) writes **one** additive
audit row, action `DESTINATION_REFUSED` (`vault.DestinationRefusedEvent`):
agent in `agent_id`, the secret **name** in `secret_name` (so existing name
filters keep working), and details

`namespace=github action=http_get_with_auth destination=evil.example:443 reason=HOST_NOT_LISTED mode=enforce`

Reason codes: `NO_LIST`, `HOST_NOT_LISTED`, `PORT_MISMATCH` (host listed with
another port), `IP_LITERAL`, `REDIRECT_OFF_LIST`, `REDIRECT_CROSS_ORIGIN`
(`NON_ASCII_HOST` exists for load-time errors only). The destination comes from
the validated URL and is `host:port` only: never the path, query, a header or
the body.

It also raises a security event (`DESTINATION_REFUSED`, not Critical) through
the server's notifier. Alerts are de-duplicated per
`(agent, ns/name, host:port, reason)` per minute; the next alert after a quiet
spell carries the number suppressed. Audit rows are not de-duplicated (they
are bounded by the per-agent lease limiter). The audit hash input, existing
actions and existing row text are unchanged.

**Ordering and its cost.** The check runs inside the lease callback, after the
ABAC check, so an agent the policy denies gets the ordinary denial and learns
nothing about the destinations configuration (no `DESTINATION_REFUSED` row).
The cost: a refused request still decrypts the secret and writes the lease
rows; the refusal row sits between `SECRET_LEASED` and `LEASE_RETURNED`.

On the capability path (`secrets.use`) the refusal is passed through with its
own text and 403 class, not wrapped as the generic "action failed".

### 6. Honey capabilities and honeytokens

Unchanged. A refused destination is not a honey event, and honey answers do
not go through the HTTP actions. A honeytoken secret still raises its alarm
at lease time, before the destination check.

## What the control claims, and its limits

The claim "an agent allowed to use a secret cannot make the vault send it to
another host" holds only with per-agent tokens **without** `lease` or
`operator` scope, the legacy shared token off, and `--destinations=enforce`.
Out of reach:

- misuse on a listed host (a GitHub token used against a repository the
  operator did not intend): keep credential scopes narrow;
- listed hosts that forward or reflect requests (an open proxy, a webhook
  relay); cross-origin redirects are refused, but a listed origin is trusted;
- a listed host can reflect the secret back to the agent in response headers
  or `body_text` (follow-up: scrub exact secret bytes from returned data);
- wide lists written by the operator (`*.example.com` on a domain where
  others can get subdomains);
- secrets without an entry in `warn` mode;
- approval prompts do not show the destination (follow-up);
- the Python line, which does not enforce destinations at all.

## Rejected options

- **Per-action lists** (`Config.HostAllowlist`): they bind the wrong thing;
  one action carries many secrets.
- **Lists in the rule only:** a new allow rule (or a typo in one) would widen
  where a secret goes. Binding to the secret and letting rules only narrow
  keeps the secret owner in control.
- **IDNA normalisation:** needs `golang.org/x/net` (a new dependency); rejecting
  non-ASCII is safe and simple.
- **`*.x` matching any depth:** looser and rarely needed.
- **A per-request `http.Client` for redirect checks:** the decision travels on
  the request context instead, which also reaches the dialer.
