# CLI Guide

```bash
rgt-vault simulate --policy policy.yaml --agent research_agent \
    --namespace openai --purpose inference --action read
# -> ALLOWED / DENIED + reason

# Store a secret. The plaintext value is read from stdin (or use
# --value-file PATH); it is never accepted as an argv positional because
# argv is visible to other local users via /proc/<pid>/cmdline.
echo "sk-..." | rgt-vault --db ~/.secure-vault/vault.db --policy policy.yaml \
    set OPENAI_API_KEY - --namespace openai --agent admin
```

