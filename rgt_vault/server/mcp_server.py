from __future__ import annotations

import logging
from typing import Any

from fastmcp import Context, FastMCP

from rgt_vault.auth import ABACPolicyEngine
from rgt_vault.hooks.log_redaction import LogRedactionHook

# rgt-vault internals
from rgt_vault.vault import VaultManager

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("rgt-vault-mcp")


# 1. wire VaultManager exactly as in v0.2.0
# The vault instance will be retrieved dynamically when tools are called,
# or we can assume it's created here for the MCP server.
def get_vault() -> VaultManager:
    policy = ABACPolicyEngine(policy_yaml="rules: []")
    vault = VaultManager(auth=policy)
    vault._hooks.append(LogRedactionHook())
    return vault


# 2. create MCP server
mcp = FastMCP("rgt-vault")


@mcp.tool()
async def vault_execute(
    agent_id: str,
    capability_id: str,
    version: str = "1.0",
    parameters: dict[str, Any] = None,
    ctx: Context = None,
) -> dict[str, Any]:
    """
    Execute a vault capability via the Agent Capability Platform.
    All parameters are audited and redacted by LogRedactionHook.
    """
    vault = get_vault()
    parameters = parameters or {}
    if ctx:
        await ctx.info(f"request {capability_id} v{version} for {agent_id}")

    try:
        result = vault.execute_capability(
            agent_id=agent_id,
            capability_id=capability_id,
            version=version,
            parameters=parameters,
        )
        return {"ok": True, "result": result}
    except PermissionError as e:
        if ctx:
            await ctx.error(str(e))
        return {"ok": False, "error": "unauthorized"}
    except Exception as e:
        log.exception("vault_execute failed")
        if ctx:
            await ctx.error(f"{e.__class__.__name__}")
        return {"ok": False, "error": "execution_failed"}


@mcp.tool()
def vault_list_capabilities() -> list[str]:
    """List capability IDs available to agents."""
    return []


@mcp.resource("vault://policy")
def get_policy_summary() -> dict:
    """Expose non-sensitive policy metadata."""
    vault = get_vault()
    return {"rules": len(vault.auth.rules), "default_ttl": 300}


if __name__ == "__main__":
    mcp.run()
