# RGT Vault

RGT Vault is a capability-based security boundary that lets AI agents perform approved actions without ever receiving the underlying secrets.

## Why RGT Vault Exists

**Problem:** Agents require secrets to interact with the world.
**Traditional Model:** Agents receive secrets directly.
**Result:** Compromised agents can arbitrarily abuse those secrets.

RGT Vault solves this by keeping secrets securely inside the vault. Instead of requesting a secret, an agent requests a *capability*. The vault evaluates the policy, executes the approved capability on behalf of the agent, and returns the result. This dramatically limits the blast radius of compromised agents and eliminates secret exposure.

## How It Works

```text
Agent
  ↓
Requests Capability (e.g., "github.read_repo")
  ↓
Vault Evaluates Policy & Executes Action
  ↓
Returns Result
```

The underlying secret never leaves the vault.

## Key Features

* **Capability Execution Layer:** Agents invoke actions, not secrets.
* **Local-First Security:** Powered by secure local storage (TPM, macOS Keychain, Windows DPAPI).
* **Zero Secret Exposure:** Memory-hardened execution environments for capabilities.
* **Granular Policies:** Attribute-based access control (ABAC) for strict scoping.
* **Audit Trails:** Immutable, cryptographically signed execution logs.

## Quick Start

```bash
# Install the CLI
pip install rgt-vault

# Initialize the local vault
rgt-vault init

# Add a secret to the vault
rgt-vault set github_token --value "ghp_..."

# Configure a capability policy
rgt-vault policy create github.read_repo --allow-agent "my-agent"

# Start the MCP server to expose capabilities to your agent
rgt-vault mcp start
```

## Architecture

RGT Vault explicitly separates the capability execution model from the underlying cryptographic storage. For a layered explanation of how the system processes requests, see the [Architecture Overview](docs/architecture/overview.md).

## Security Model

The security model assumes the agent is entirely untrusted. For detailed analysis of the threat landscape and mitigation strategies, read the [Threat Model](docs/concepts/threat-model.md).

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](docs/getting-started/installation.md) | Installation and quickstart guides |
| [Concepts](docs/concepts/) | Capabilities, security model, and threat model |
| [Architecture](docs/architecture/) | Execution flow and cryptographic details |
| [Guides](docs/guides/) | API usage, policies, and migration |
| [Reference](docs/reference/) | CLI and configuration references |

## Status

RGT Vault is currently in active development.
