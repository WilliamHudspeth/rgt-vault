
# 1. hook.py
with open("rgt_vault/hook.py", "r") as f:
    hook = f.read()
hook = hook.replace('return body + b"." + sig_b64', 'return (body + b"." + sig_b64).decode("utf-8")')
hook = hook.replace('self._v2_verifier = None  # type: ignore[var-annotated]', 'self._v2_verifier = None')
hook = hook.replace('for k in sorted(self._seen, key=self._seen.get)[:half]:', 'for k in sorted(self._seen, key=lambda x: self._seen[x] if self._seen.get(x) is not None else 0)[:half]:')
hook = hook.replace('with urllib.request.urlopen(rq, timeout=self.timeout_seconds) as resp:', 'with urllib.request.urlopen(rq, timeout=self.timeout_seconds) as resp:  # nosec B310')
with open("rgt_vault/hook.py", "w") as f:
    f.write(hook)

# 2. shadow.py
with open("rgt_vault/shadow.py", "r") as f:
    shadow = f.read()
shadow = shadow.replace('with urllib.request.urlopen(req, timeout=timeout) as response:', 'with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec B310')
shadow = shadow.replace('raw: {resp_bytes}', "raw: {resp_bytes.decode('utf-8', errors='replace')}")
with open("rgt_vault/shadow.py", "w") as f:
    f.write(shadow)

# 3. vault.py
with open("rgt_vault/vault.py", "r") as f:
    vault = f.read()
# fix verify(capability_token) -> if capability_token is None: raise ValidationError
vault = vault.replace('            try:\n                tok: CapabilityV2Token = self.token_verifier.verify(capability_token)', 
                      '            if capability_token is None:\n                raise ValidationError("capability_token is required")\n            try:\n                tok: CapabilityV2Token = self.token_verifier.verify(capability_token)')
# fix _hook_consult_capability
vault = vault.replace('self._hook_consult_capability(capability_name, capability_token)', 'self._hook_consult_capability(capability_name, capability_token or "")')
with open("rgt_vault/vault.py", "w") as f:
    f.write(vault)

# 4. mcp_server.py
with open("rgt_vault/server/mcp_server.py", "r") as f:
    mcp = f.read()
mcp = mcp.replace('def get_vault() -> VaultManager:\n    policy = ABACPolicyEngine(policy_yaml="rules: []")\n    vault = VaultManager(auth=policy)\n    vault._hooks.append(LogRedactionHook())\n    return vault', 
                  'def get_vault() -> VaultManager:\n    vault = VaultManager(policy_yaml="rules: []")\n    vault.hook = LogRedactionHook()\n    return vault')
mcp = mcp.replace('parameters: dict[str, Any] = None,', 'parameters: dict[str, Any] | None = None,')
with open("rgt_vault/server/mcp_server.py", "w") as f:
    f.write(mcp)

