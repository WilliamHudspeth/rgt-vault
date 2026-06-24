# Policies

Policies are YAML. Attributes default to `*` (match all). Matching is glob-style (`fnmatch`). **`deny` always wins over `allow`; with no matching `allow`, access is denied.**

```yaml
rules:
  # Block an entire namespace outright.
  - effect: deny
    namespace: production

  # An agent may read its own namespace...
  - effect: allow
    agent: research_agent
    namespace: openai
    action: read

  # ...but never for billing purposes.
  - effect: deny
    agent: research_agent
    purpose: billing

  # Admins can do anything.
  - effect: allow
    agent: admin
    namespace: "*"
    action: "*"
```

