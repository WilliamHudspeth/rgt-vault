# rgt-vault MCP server

Serves the rgt-vault secret store as MCP tools over stdio (JSON-RPC 2.0 with newline-delimited messages).

## Prerequisites

A running rgt-vault backend must be available. Start one with:

```
rgt-vault init
rgt-vault serve --policy policy.yaml
```

## Running

```
rgt-vault mcp
```

The command speaks JSON-RPC on stdin/stdout and is normally launched by an MCP client (e.g. Claude Desktop), not invoked directly.
It connects to the backend at `--host` (default `http://127.0.0.1:8765`) and reads the bearer token from `--token`, the environment variable `RGT_VAULT_TOKEN`, the file named by `RGT_VAULT_TOKEN_FILE`, or `~/.config/rgt-vault/operator.token` / the legacy `server.token` (in that order). Give the MCP server **a token minted for its own agent** (`rgt-vault token mint --agent my_agent [--scope agent,lease] --out my_agent.token`, then `RGT_VAULT_TOKEN_FILE=my_agent.token`): the vault server acts as that agent, `lease_secret` needs the `lease` scope, and no agent label is sent (`--agent` / `RGT_VAULT_MCP_AGENT` is only for a legacy shared-token server; with per-agent tokens a different label is refused). See [agent-identity-migration.md](agent-identity-migration.md).

## Configure Claude Desktop

Add the following entry to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rgt-vault": {
      "command": "rgt-vault",
      "args": ["mcp", "--host", "http://127.0.0.1:8765"]
    }
  }
}
```

Config file locations:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Without `--token`, the token is read from `RGT_VAULT_TOKEN_FILE` or `~/.config/rgt-vault/operator.token` (then the legacy `server.token`) when present; prefer a dedicated per-agent token over the operator one.

## Tools

| Tool            | Arguments                             | Description                                |
|-----------------|---------------------------------------|--------------------------------------------|
| `list_secrets`  | `namespace` (string)                  | List all secret names in a namespace       |
| `lease_secret`  | `namespace` (string), `name` (string) | Retrieve and return the plaintext secret   |
| `revoke_secret` | `namespace` (string), `name` (string) | Soft-delete a secret from the namespace    |

## Security note

`lease_secret` returns the secret's plaintext value to the MCP client. Only enable this MCP server for trusted clients.
`revoke_secret` performs a soft-delete; the secret can be recovered until the backend permanently purges it.
