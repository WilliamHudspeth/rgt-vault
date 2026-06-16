"""Local HTTP server for the rgt-vault.

This module is **optional** — importing the rest of ``rgt_vault`` does not
require FastAPI or uvicorn. The server is a thin layer over ``VaultManager``
that lets local clients (LLM agents running in Ollama/llama.cpp/vLLM, scripts,
or other non-Python processes) call into the vault over loopback HTTP.

Design constraints, in order of importance:

1. The server is bound to ``127.0.0.1`` by default and requires a bearer
   token in the ``Authorization`` header. No anonymous access.
2. Plaintext secrets **never** cross the HTTP boundary. The ``/use`` endpoint
   leases the secret into a server-side buffer, hands that buffer to a
   registered action callable, and returns only the action's result.
3. Every request is policy-gated through the existing ``ABACPolicyEngine``
   via the underlying ``VaultManager`` methods. The server adds no new
   authorization surface — it just translates HTTP into existing method calls.
4. The server logs every request (caller token id, source IP, action, secret
   name) to the existing hash-chained audit log so an audit chain check
   covers both API and CLI usage.
"""

from .actions import ActionRegistry, register_builtin_actions
from .app import build_app
from .auth import TokenStore, generate_token, load_or_create_token

__all__ = [
    "ActionRegistry",
    "TokenStore",
    "build_app",
    "generate_token",
    "load_or_create_token",
    "register_builtin_actions",
]
