# Demo scripts (2026-11-27)

Appendix to [ASSESSMENT.md](ASSESSMENT.md). Two scripts: a 5-minute version that shows the idea, and a
15-minute technical version. Both run on the current master (`5a049d2`) with **no code changes**, given
the prerequisites below. Where the product is missing a command, the script uses a small shell helper;
each helper marks the gap it covers.

## What was tested and what was not

| Part | Tested? |
|---|---|
| `stage.sh` and every command of the 5-minute script | **Yes**, end to end on nitoryu in a throw-away HOME, against a loopback TLS mock of the upstream API (output below is from that run) |
| The same flow on Windows 11 (init, tokens, serve, use, denials, honey trap, rotate, verify, export) | **Yes**, on the lab VM, interactive desktop session, with the `echo` action |
| TUI approval with a typed TOTP code | **Yes** (tmux) |
| MCP `execute_secret` from a scripted JSON-RPC client | **Yes** |
| MCP from Claude Code or Claude Desktop | **No**. Rehearse it before relying on it; the fallback is the shell helper |
| The real `https://api.github.com/user` call with a real token | **No** (I used no real secret and contacted no external API). The code path is the same as the mock: https, bearer header, public host, no flags needed |
| A real Secret Service on nitoryu | **No**: none is installed. I used a fake one on a private bus |

## Prerequisites

1. **A machine where `rgt-vault init` works.** Today that is one of:
   - **the Windows VM, desktop session** (works out of the box, verified), or
   - **a Linux desktop with GNOME Keyring or KWallet running**, or
   - **nitoryu after `sudo apt install gnome-keyring`**, with everything started from one shell inside
     a private session, which is what CI does (`.github/workflows/review-gate.yml`, job `compat`):

     ```bash
     dbus-run-session -- bash          # every demo terminal must be a child of this shell (use tmux inside it)
     echo -n "demo-keyring-password" | gnome-keyring-daemon --unlock --components=secrets
     ```

     I could not verify this on nitoryu (it needs a package install), only that CI does exactly this.
   RGT-522 removes this prerequisite.
2. `rgt-vault` on `PATH` (`cd go && go build -o ~/bin/rgt-vault ./cmd/rgt-vault`), plus `curl` and `python3`.
3. **An upstream to call.** Pick one:
   - **A (recommended for an audience):** a throw-away, fine-grained, read-only GitHub token saved in
     `gh.pat` (mode 0600), and `U=https://api.github.com`. Revoke the token after the demo.
   - **B (offline):** a local HTTPS mock. It needs `SERVE_EXTRA=--allow-private-network` and
     `SSL_CERT_FILE=<mock CA>` in the server's environment (Linux only). Use B as the fallback when the
     network is down.
4. An authenticator app (or `oathtool`) for the TOTP step. `enroll-2fa` prints the `otpauth://` URI once
   when run on a terminal. There is no QR code; `qrencode -t ansiutf8 "<uri>"` makes one.
5. Two terminal panes side by side: **left = the agent**, **right = the operator** (`rgt-vault tui --namespace github`).
   A third small pane with `tail -f ~/rgt-demo/serve.log` makes the honey trap visible.

**Safety:** use a dedicated OS user or the VM. The keyring provider keeps one master secret per OS user
for all vaults, so never run `rotate --target master` in a demo on an account that has another vault
(run log, section I: the other vault becomes unreadable).

## Files

### `stage.sh` (run once, before the audience; takes about 2 seconds)

```bash
#!/usr/bin/env bash
# Stage the demo. Needs: rgt-vault on PATH, curl, python3, a working keyring.
# usage: ./stage.sh <file with the upstream credential>
set -euo pipefail
DEMO=${DEMO:-$HOME/rgt-demo}; mkdir -p "$DEMO"; cd "$DEMO"; umask 077
CFG=$HOME/.config/rgt-vault
rgt-vault init --harness-key-file "$CFG/harness.key"
[ -f "$CFG/totp.secret" ] || rgt-vault enroll-2fa --account "$USER-demo"     # prints the otpauth:// URI once
cat > policy.yaml <<'YAML'
honey_capabilities:
  - github.admin.delete_org
rules:
  - {effect: allow, agent: operator, namespace: "*", action: "*"}
  - {effect: allow, agent: coder, namespace: github, purpose: "ci*", action: read}
  - {effect: deny,  agent: intern-bot, namespace: github}
YAML
[ -f coder.token ]  || rgt-vault token mint --agent coder      --out coder.token
[ -f intern.token ] || rgt-vault token mint --agent intern-bot --out intern.token
# shellcheck disable=SC2086
nohup rgt-vault serve --policy policy.yaml --require-approval \
      --totp-secret-file "$CFG/totp.secret" --approval-timeout 90s \
      --harness-key-file "$CFG/harness.key" ${SERVE_EXTRA:-} > serve.log 2>&1 &
echo $! > serve.pid; sleep 1.5; rgt-vault status
rgt-vault set GITHUB_TOKEN --namespace github --purpose setup --as-operator --value-file "$1"
# A second copy that needs a TOTP code to approve. GAP: `set` has no --require-2fa flag (RGT-525).
python3 - "$1" <<'PY' > .body.json
import json, sys
print(json.dumps({"name": "GITHUB_ADMIN_TOKEN", "namespace": "github", "purpose": "setup", "require_2fa": True,
                  "note": "org admin; needs TOTP", "value": open(sys.argv[1]).read().strip()}))
PY
curl -sS -H @<(printf 'Authorization: Bearer %s' "$(cat "$CFG/operator.token")") -H 'Content-Type: application/json' \
     -d @.body.json http://127.0.0.1:8765/v1/secrets; echo; rm -f .body.json
rgt-vault token list
```

### `lib.sh` (source it in the agent pane and the operator pane)

```bash
# GAPS these helpers cover: no `rgt-vault use`, no `rgt-vault requests approve|deny` (RGT-525),
# no readable `rgt-vault audit` (RGT-527).
cd "${DEMO:-$HOME/rgt-demo}"
# as <token-file> <METHOD> <path> [json]  -- call the API as that token; the token never appears in argv
as() { curl -sS -m 120 -X "$2" -H @<(printf 'Authorization: Bearer %s' "$(cat "$1")") \
       ${4:+-H 'Content-Type: application/json' -d "$4"} "http://127.0.0.1:8765$3"; echo; }
# use <token-file> <secret> <purpose> <url>  -- the agent asks the vault to call <url> with the secret
use() { as "$1" POST "/v1/secrets/github/$2/use" "{\"action\":\"http_get_with_auth\",\"purpose\":\"$3\",\"params\":{\"url\":\"$4\"}}"; }
pending() { as ~/.config/rgt-vault/operator.token GET /v1/requests; }
approve() { as ~/.config/rgt-vault/operator.token POST "/v1/requests/$1/approve" "{${2:+\"totp_code\":\"$2\"}}"; }
deny()    { as ~/.config/rgt-vault/operator.token POST "/v1/requests/$1/deny" "{\"reason\":\"${2:-denied in demo}\"}"; }
auditlog() { rgt-vault audit --limit "${1:-25}" | python3 -c '
import json, sys
for e in reversed(json.load(sys.stdin)["entries"]):
    if e["action"].startswith(("HOOK_", "HTTP_")): continue
    print("%4d %s %-26s %-10s %-20s %s" % (e["id"], e["timestamp"][11:19], e["action"], e["agent_id"] or "-", e["secret_name"] or "-", (e["details"] or "")[:90]))'; }
```

Do not put an `operator` name in the approve or deny body: the server refuses a name that differs from
the token's agent with "agent does not match the authenticated token".

### `.mcp.json` for Claude Code (optional; not verified with a real client)

```json
{
  "mcpServers": {
    "rgt-vault": {
      "command": "rgt-vault",
      "args": ["mcp"],
      "env": { "RGT_VAULT_TOKEN_FILE": "/home/will/rgt-demo/coder.token" }
    }
  }
}
```

The MCP server exposes `execute_secret`, `list_secrets`, `lease_secret`, `revoke_secret`,
`execute_capability` and `list_capabilities`. A denied call reaches the model only as
"backend error: 403 Forbidden"; the reason is on the MCP server's stderr (RGT-536).

---

## Script 1: five minutes, "the agent never holds the token"

Story: an AI coding agent needs GitHub. It gets the *result* of a GitHub call, after a human says yes.
It never gets the token. A second agent that goes looking for more is caught.

| Time | Pane | Do | Say |
|---|---|---|---|
| 0:00 | operator | `rgt-vault token list` | "Three identities: me, the coding agent, an intern bot. The agents hold a vault token, not a GitHub token." |
| 0:30 | agent | Ask the agent (prompt below), or run `use coder.token GITHUB_TOKEN ci-check $U/user` | "The agent asks the vault to call GitHub on its behalf. Nothing happens yet." |
| 1:00 | operator | TUI: `tab` shows the pending request (agent, secret, purpose). Press `a` | "I see who is asking, for which secret and why. I approve." |
| 1:15 | agent | The call returns the GitHub JSON | "The agent has the answer. The token went from the vault to GitHub and nowhere else." |
| 1:45 | agent | "Print the token": `as coder.token POST /v1/secrets/github/GITHUB_TOKEN/lease '{"purpose":"ci-check"}'` | "It cannot read the token: its vault token has no lease scope." |
| 2:15 | agent | `use coder.token GITHUB_TOKEN billing $U/user` | "Same secret, a purpose the policy does not allow: denied, and logged." |
| 2:45 | agent then operator | `use coder.token GITHUB_ADMIN_TOKEN ci-check $U/user`; TUI: `tab`, `a`, **type** the 6-digit code, `enter` | "The admin token is marked 2FA. My approval needs a code from my phone." |
| 3:30 | agent (as intern) | `as intern.token POST /v1/capabilities/execute '{"capability":"aws.admin.full","agent_id":"intern-bot","capability_token":"x.y","payload":{}}'` | "The intern bot tries a capability called aws.admin.full. It gets an ordinary refusal." |
| 3:45 | log pane | the `HONEY_CAPABILITY_TRIGGERED` line appears | "That name is a decoy. Nobody legitimate ever asks for it, so the vault raised a critical event." |
| 4:10 | operator | `rgt-vault token revoke <intern id>`, then the intern retries | "I revoke the bot. Its next call is 401. No restart." |
| 4:30 | operator | `auditlog 60`, then `rgt-vault verify-audit` | "Every step is in a hash-chained log. If anyone edits a row, verification names the row." |

Agent prompt for the MCP variant:

> Use the rgt-vault tools. Call `execute_secret` with namespace `github`, name `GITHUB_TOKEN`, action
> `http_get_with_auth`, purpose `ci-check` and params `{"url": "https://api.github.com/user"}`. Tell me the
> `login` from the response. Then try to obtain the token value itself and tell me what happened.

**Type the TOTP code; do not paste it.** The TUI ignores pasted digits (RGT-528).

### Expected output (from my run; upstream B, request ids shortened)

```text
# 1. agent asks; request waits for the human
$ pending
{"requests":[{"action":"read","agent":"coder","namespace":"github","purpose":"ci-check","request_id":"e4c03666-…","require_2fa":false,"secret_name":"GITHUB_TOKEN"}]}
$ approve e4c03666-…
{"decision":"approved","ok":true,"request_id":"e4c03666-…"}
(agent) {"action":"http_get_with_auth","ok":true,"result":{"body_text":"{\"authenticated\": true, … \"login\": \"octo-demo\" …}","content_type":"application/json","status":200,"truncated":false, …}}

# 2. agent tries to read the token itself, then another purpose
{"error":"AuthorizationError","detail":"insufficient scope for this route","incident_id":"f1068765a4a1f458"}
{"error":"PolicyDeniedError","detail":"Agent 'coder' denied read access to 'GITHUB_TOKEN' (github/billing)","incident_id":"cb71d1c7db715e15"}

# 3. admin token: approve without a code, then with one
{"error":"ApprovalError","detail":"approval error: invalid or missing 2FA code","incident_id":"db48ad561759d2bf"}
{"decision":"approved","ok":true,"request_id":"fda72e39-…"}

# 4. rogue agent explores
{"error":"PolicyDeniedError","detail":"capability token rejected: token base64 decode failed","incident_id":"5dcc23ae1823796a"}
serve.log: WARNING: security event HONEY_CAPABILITY_TRIGGERED request="" agent="intern-bot" operator="" detail="honey capability \"aws.admin.full\" probed via capability.execute (version 1, token presented: true)"

# 5. revoke
revoked id tok_<id>  agent intern-bot  scopes agent  expires never
{"error":"ServerAuthError","detail":"invalid credentials","incident_id":"de48568dde965716"}

# 6. audit
  14 04:03:29 APPROVAL_APPROVED          operator   -                    request=e4c03666-… token=tok_<id> ip=127.0.0.1
  16 04:03:29 LEASE_GRANTED              -          GITHUB_TOKEN         Agent: coder
  18 04:03:30 AUTHZ_DENIED               coder      -                    … POST /v1/secrets/github/GITHUB_TOKEN/lease reason=missing scope agent+lease
  21 04:03:30 POLICY_DENIED              -          GITHUB_TOKEN         Action: read, Agent: coder, Namespace: github, Reason: No matching allow rule (default deny)
  26 04:03:31 APPROVAL_BAD_CODE          operator   -                    request=fda72e39-… attempt=1/5
  28 04:03:31 APPROVAL_APPROVED          operator   -                    request=fda72e39-…
  33 04:03:32 HONEY_CAPABILITY_TRIGGERED -          -                    {"agent": "intern-bot", "capability": "aws.admin.full", … "severity": "critical" …}
  38 04:03:32 TOKEN_REVOKED              intern-bot -                    token=tok_<id> …
  39 04:03:32 AUTH_FAILED                -          -                    ip=127.0.0.1 POST /v1/secrets/github/GITHUB_TOKEN/use reason=invalid token=ebaf82fc
OK
```

### Fallbacks

| If this fails | Do this |
|---|---|
| The MCP client does not connect, or the tool call times out while waiting for approval | Use the `use …` helper in the agent pane and say "this is the HTTP call the MCP tool makes" |
| The network is down (upstream A) | Restart the server with upstream B (`SERVE_EXTRA=--allow-private-network`, `SSL_CERT_FILE`) and `U=https://127.0.0.1:18443` |
| The TUI misbehaves | `pending`, `approve <id> [code]`, `deny <id>` in the operator pane |
| The TOTP code is refused | Wait for the next 30-second step (a code is single-use). Bad codes are counted (`attempt=1/5` in the log); do not burn five |
| An approval times out (90 s) | The agent gets "approval timed out after 1m30s". Say "it fails closed", and ask again |
| `init` fails on the keyring | Switch to the Windows VM, which works without setup |

### What not to say or show (today)

- **Do not claim the token can only go to GitHub.** An agent that may use a secret can name any https
  host as the target, and the vault will send the credential there (run log C4). Until RGT-523 lands, the
  honest sentence is "the agent never sees the token; which hosts it may be sent to is the next control
  we are adding". If asked directly, say so.
- Do not press `P` ("panic lock") in the TUI and call it a kill switch: it only closes the TUI.
- Do not run `rgt-vault audit` raw: it prints one line of JSON. Use `auditlog` or the TUI's `a` view.
- Do not show `get` / `lease_secret` succeeding while saying "the secret never leaves the vault". A token
  with the `lease` scope does get plaintext, by design. Say that if it comes up.
- Do not show `/v1/capabilities/list` (returns an empty list), capability tokens (nothing mints them),
  Ed25519 tokens (not wired), the policy `ttl` (not enforced), the top-level README (Python-era), or the
  release page (the only Go release is a draft of the old in-memory stub).

---

## Script 2: fifteen minutes, technical

Run Script 1 first (minutes 0 to 5), then continue. All commands below were run during the assessment;
the section in brackets is where the output is in [run-log.md](run-log.md).

| Time | Topic | Commands | Point to make |
|---|---|---|---|
| 5:00 | From nothing | `cat ~/rgt-demo/policy.yaml`; `rgt-vault status --offline`; `ls -l ~/.secure-vault ~/.config/rgt-vault` | One static binary, SQLite + `keychain.json`, token store holds hashes only, everything 0600 [A, A2] |
| 6:00 | Policy is deny by default | `RGT_VAULT_TOKEN_FILE=coder.token rgt-vault simulate --namespace github --purpose ci-build --action read`, then `--purpose billing` | ABAC on agent, namespace, purpose, action; explicit deny wins [C2] |
| 7:00 | Identity cannot be spoofed | `as coder.token POST /v1/secrets/github/GITHUB_TOKEN/use '{"action":"echo","purpose":"ci-check","agent":"operator"}'` | The subject comes from the token: "agent does not match the authenticated token" [C3] |
| 7:45 | SSRF guard | `use coder.token GITHUB_TOKEN ci-check https://169.254.169.254/latest/meta-data/` and `http://example.com/` (run the server without `--allow-private-network` for this part) | Private, loopback and metadata addresses and plain http are refused and the credential is not sent [E2]. With approval on, approve the request first: the URL is checked when the action runs |
| 8:30 | Approval fails closed | ask, approve nobody, wait | "approval timed out after …" [D3'] |
| 9:15 | TOTP misuse | approve with `000000`, then reuse a good code on a second request | `APPROVAL_BAD_CODE attempt=1/5`, `2FA code already used`; both are security events [D2''] |
| 10:15 | Rotation | `rgt-vault rotate --target dek`; `rgt-vault status --offline` (epoch goes up); the agent's next call still works | The key epoch goes up and nothing breaks for the agent [E] |
| 11:00 | Backup | `rgt-vault export --out backup.b64`; `rgt-vault revoke GITHUB_TOKEN --namespace github --as-operator`; stop the server; `rgt-vault import --in backup.b64 --yes`; start it again | Ciphertext-only export, bound to this vault's id and key [E3] |
| 12:15 | Tamper evidence | stop the server; `sqlite3 ~/.secure-vault/vault.db "update audit_logs set details='Agent: someone_else' where id=16"`; `rgt-vault verify-audit --offline` | `TAMPERED … first invalid entry: audit_logs id 16`, exit code 2 [C9]. Restore the row afterwards or re-stage |
| 13:15 | Crypto self-check | `rgt-vault crypto-audit` | AES-256-GCM, Argon2id 256 MiB, known-answer test, live probes: `Overall: PASS` [E4] |
| 14:00 | Windows | Repeat `init`, `serve`, one `use`, `verify-audit` on the VM desktop | Same binary, Credential Manager instead of the Secret Service [Windows VM run] |
| 14:30 | Close | `rgt-vault token revoke`, `auditlog`, questions | |

Notes for this script:

- The master rotation (`--target master`) is deliberately left out: see the safety note in the prerequisites.
- `sqlite3` may not be installed; `python3 -c "import sqlite3; …"` does the same (run log C9).
- For the Windows part, start the binary from the desktop PowerShell, not over SSH: under a
  non-interactive session the keyring call fails with "A specified logon session does not exist".
  Token files there are protected only by the profile's inherited ACL, not by an owner-only ACL.

## What is missing for a smoother demo (all tracked)

| Gap seen while scripting | Issue |
|---|---|
| nitoryu cannot `init` at all without installing a keyring daemon | RGT-522 |
| Nothing restricts the destination host of a credential | RGT-523 |
| Needs `curl` helpers for `use`, approve, deny, and a 2FA-required secret | RGT-525 |
| CLI errors say only "HTTP 403" | RGT-526 |
| `audit` is raw JSON; the audit rows of a `use` do not name the action or the destination | RGT-527 |
| TUI ignores a pasted TOTP code; "panic lock" label | RGT-528 |
| No demo kit in the repository; the Python examples are the only "see it in 30 seconds" | RGT-529 |
| MCP not rehearsed with a real client; denials are opaque to the model | RGT-536 |
