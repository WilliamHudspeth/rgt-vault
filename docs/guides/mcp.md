# rgt-vault MCP server

Serves the rgt-vault secret store as MCP tools over stdio (JSON-RPC 2.0 with newline-delimited messages).

## Prerequisites

A running rgt-vault backend must be available. Start one with:

```
rgt-vault init
rgt-vault serve --addr :8080
```

## Running

```
rgt-vault mcp
```

The command speaks JSON-RPC on stdin/stdout and is normally launched by an MCP client (e.g. Claude Desktop), not invoked directly.
It connects to the backend at `--host` (default `http://localhost:8080`) and reads the bearer token from `--token`, the environment variable `RGT_VAULT_TOKEN`, or the file `~/.config/rgt-vault/server.token` (in that order).

## Configure Claude Desktop

Add the following entry to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rgt-vault": {
      "command": "rgt-vault",
      "args": ["mcp", "--host", "http://localhost:8080"]
    }
  }
}
```

Config file locations:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

The token is read automatically from `~/.config/rgt-vault/server.token` when present.

## Tools

| Tool            | Arguments                             | Description                                |
|-----------------|---------------------------------------|--------------------------------------------|
| `list_secrets`  | `namespace` (string)                  | List all secret names in a namespace       |
| `lease_secret`  | `namespace` (string), `name` (string) | Retrieve and return the plaintext secret   |
| `revoke_secret` | `namespace` (string), `name` (string) | Soft-delete a secret from the namespace    |

## Security note

`lease_secret` returns the secret's plaintext value to the MCP client. Only enable this MCP server for trusted clients.
`revoke_secret` performs a soft-delete; the secret can be recovered until the backend permanently purges it.
