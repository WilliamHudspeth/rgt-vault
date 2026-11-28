# Policies

Policies are YAML. Attributes default to `*` (match all). Matching is glob-style (`fnmatch`). **`deny` always wins over `allow`; with no matching `allow`, access is denied.**

```yaml
rules:
  # Block an entire namespace outright.
  - effect: deny
    namespace: production

  # An agent may read its own namespace...
  - effect: allow
    agent: research_agent
    namespace: openai
    action: read

  # ...but never for billing purposes.
  - effect: deny
    agent: research_agent
    purpose: billing

  # Admins can do anything.
  - effect: allow
    agent: admin
    namespace: "*"
    action: "*"
```


## Destinations: where a secret may be sent (Go server, v0.4.0)

The HTTP actions (`http_get_with_auth`, `http_post_with_auth`, `openai_chat`)
add the secret to an outbound request as `Authorization: Bearer …`. The agent
chooses the URL. Without a limit, an agent allowed to *use* a token could send
it to a host it controls. The `destinations:` section binds each secret to the
hosts it may be sent to. The Go server enforces it before any DNS lookup or
connection. Design: [docs/design/destinations.md](../design/destinations.md).

```yaml
rules:
  - effect: allow
    agent: coder
    namespace: github
    action: read
    # Optional: narrows (never widens) where secrets leased under this rule go.
    allowed_hosts: [api.github.com]

destinations:
  github/GITHUB_TOKEN: [api.github.com]          # one secret
  openai/*: [api.openai.com]                     # every secret in a namespace
  internal/DEPLOY_KEY:
    - "https://deploy.example.com:8443"
    - "*.ci.example.com"                         # exactly one extra label
  archive/OLD_KEY: []                            # may be sent nowhere
```

**Keys.** `namespace/name` for one secret, `namespace/*` for a namespace. An
exact entry replaces the namespace entry for that secret (they are not merged).

**Entries.** `host`, `host:port`, `https://host[:port]` or `*.domain[:port]`.
The default port is 443 and ports match exactly. Only https is ever sent.

- Host names are compared lower-case, with one trailing dot removed.
- Non-ASCII host names are refused: write IDNs in punycode (`xn--…`).
- `*.example.com` matches `api.example.com`, but neither `example.com` nor
  `a.b.example.com`.
- Wildcards are refused over public suffixes (`*.com`, `*.co.uk`,
  `*.com.au`) and over shared-hosting domains where anyone can get a name
  (`*.vercel.app`, `*.herokuapp.com`, `*.workers.dev`, …). List the exact
  host instead (`myco.vercel.app` is fine). `*.github.io` loads with a warning.
- IP addresses match only when listed exactly (`192.0.2.10`,
  `[2001:db8::1]:443`). IPv4-mapped IPv6 literals are refused.
- Userinfo, paths, queries, `http://`, port 0, duplicate keys, YAML aliases
  and `<<` merge keys under `destinations:`, and `null` or a scalar instead of
  a list are all start-up errors that name the key and the entry.

**Rules narrow.** When the allow rules that match the lease
(`agent`, `namespace`, `purpose`, action `read`) carry `allowed_hosts`, a
destination must be on the secret's list **and** on every one of those rule
lists. A rule list never adds a host. The agent chooses `purpose`, so
narrowing only binds through rules the agent cannot avoid matching (keyed on
`agent`/`namespace`, or with `purpose: "*"`).

**Default: refused.** A secret with no entry (neither `ns/name` nor `ns/*`)
cannot be used with an HTTP action:

```
403 DestinationRefusedError
no destination is allowed for secret github/GITHUB_TOKEN: add it under "destinations:" in the policy file
```

Any other destination is refused with the `host:port` and a reason, for
example `destination evil.example:443 is not allowed for secret
github/GITHUB_TOKEN (HOST_NOT_LISTED)`. `echo` sends nothing and is not
checked.

**Audit and alerts.** Each refusal writes one `DESTINATION_REFUSED` audit row
(agent, secret name, `namespace=… action=… destination=host:port reason=…
mode=…`) and raises a `DESTINATION_REFUSED` security event through the
server's notifier (log line, security webhook). Alerts are de-duplicated per
agent, secret, destination and reason per minute. Reasons: `NO_LIST`,
`HOST_NOT_LISTED`, `PORT_MISMATCH`, `IP_LITERAL`, `REDIRECT_OFF_LIST`,
`REDIRECT_CROSS_ORIGIN`. Paths, queries and headers are never logged.

**Redirects.** The server follows no redirects (a 3xx is an error). Embedders
that enable redirects get every hop re-checked against the same list, and a
hop to another origin is refused even when that origin is listed.

**Migration: `serve --destinations=warn`** (env `RGT_VAULT_DESTINATIONS`;
default `enforce`). Requests for secrets that have **no** entry are sent, after
a `DESTINATION_REFUSED` row with `mode=warn` has been written (no row, no
send). A secret that **has** an entry is enforced in both modes. The switch is
temporary and will be removed in the release after v0.4.0.

**Start-up lines.** `serve` logs the mode, then one `WARNING: destinations:`
line per namespace with secrets that have no entry, and per namespace with
`ns/name` entries that name no stored secret (a typo would leave the real
secret on the namespace entry). The lines name namespaces only.

**Policy files that are a bare list of rules** have nowhere to put
`destinations:`. Convert them to a mapping with `rules:` and `destinations:`.

The Python line ignores both keys (the file stays readable) and **does not
enforce destinations**.
