# RGT Vault

RGT Vault is a capability-based security boundary that lets AI agents perform approved actions without ever receiving the underlying secrets.

## Why RGT Vault Exists

**Problem:** Agents require secrets to interact with the world.
**Traditional Model:** Agents receive secrets directly.
**Result:** Compromised agents can arbitrarily abuse those secrets.

RGT Vault solves this by keeping secrets securely inside the vault. Instead of requesting a secret, an agent requests a *capability*. The vault evaluates the policy, executes the approved capability on behalf of the agent, and returns the result. This dramatically limits the blast radius of compromised agents and eliminates secret exposure.

## Before vs. After

**Traditional Secret Access**
```text
Agent
  ↓
Receives GitHub Token
  ↓
Calls GitHub API
  ↓
Can perform any action allowed by that token
```

**Capability-Based Access**
```text
Agent
  ↓
Requests github.read_repo
  ↓
Vault verifies policy
  ↓
Vault performs action internally
  ↓
Returns repository data

Secret never leaves the vault.
```

## Who Is This For?

RGT Vault is designed for teams building:

- AI agents
- MCP servers
- Autonomous workflows
- Multi-agent systems
- LLM-powered internal tools

If your application never grants credentials to autonomous systems, a traditional secrets manager may be sufficient.

## What Makes This Different?

Traditional secret managers focus on protecting *secrets*. RGT Vault focuses on protecting *secret usage*.

| Traditional Vault | RGT Vault |
|------------------|------------|
| Returns secrets | Executes capabilities |
| Secret reaches caller | Secret stays inside vault |
| Access control around retrieval | Access control around execution |
| Designed for applications | Designed for autonomous agents |

## What Does a Capability Look Like?

**Traditional**
```python
token = get_secret("github_token")
github.get_repo(token, "org/repo")
```

**RGT Vault**
```python
vault.execute_capability(
    "github.read_repo",
    {
        "repo": "org/repo"
    }
)
```
*Result: Repository metadata returned. GitHub token never exposed.*

## Key Features

* **✓ Capability-Based Execution**
  Execute approved actions without exposing credentials.
* **✓ Local-First Secret Storage**
  Uses platform-native secure storage where available.
* **✓ Fine-Grained Authorization**
  Capability tokens and ABAC policies limit what agents can do.
* **✓ Auditable Operations**
  Every capability execution is recorded and traceable.
* **✓ Agent-Oriented Security Model**
  Designed specifically for autonomous systems and LLM agents.

## See it in 30 seconds

```bash
git clone https://github.com/WilliamHudspeth/rgt-vault
cd rgt-vault
python bootstrap.py

# Watch an agent file a GitHub issue without ever seeing the token:
python examples/github_issue_demo.py
```

The agent requests a capability, a human approves it (with a TOTP code) in
the Approval Center, the vault uses the secret internally, and the agent
gets back only the result — never the credential. The same story for other
services:

```bash
python examples/openai_demo.py    # agent calls OpenAI, never holds sk-...
python examples/slack_demo.py     # agent posts to Slack, never holds the webhook
python examples/demo_policy.py    # the full policy + approval story, 7 checks
```

These run offline and deterministically (the outbound call is stubbed). See
[the trust boundary doc](docs/concepts/trust-boundary.md) for what is and
isn't actually guaranteed.

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

## Security Goals

RGT Vault is designed to reduce the impact of:

- Credential leakage
- Prompt injection
- Tool misuse
- Excessive agent permissions
- Agent compromise

It is not designed to defend against:

- Full host compromise
- Kernel compromise
- Physical attacks

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](docs/getting-started/installation.md) | Installation and quickstart guides |
| [Concepts](docs/concepts/) | Capabilities, security model, and threat model |
| [Architecture](docs/architecture/) | Execution flow and cryptographic details |
| [Guides](docs/guides/) | API usage, policies, and migration |
| [Reference](docs/reference/) | CLI and configuration references |

## Windows Users

Windows Smart App Control may block the installer because the binary
is not code-signed (certificates cost ~$300/yr, not justified for a
proof of concept).

To run it: right-click the `.exe` → Properties → check **Unblock** → OK,
then run normally. Or in the SmartScreen dialog click **More info** →
**Run anyway**.

This is standard for unsigned open-source tools. All source is in this
repo if you prefer to build from source.

## Status

Current State: **Security Preview**

Recommended for:
- Evaluation
- Prototyping
- Security research

Not yet recommended for:
- Production secret storage
- High-assurance environments

The **Go implementation** is the primary development line (v0.3.x+).
The **Python implementation** remains in maintenance mode (EOL: 2026-12-22).
