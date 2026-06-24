import fnmatch
from typing import Any, Dict, List

import yaml

from rgt_vault.exceptions import ValidationError


class ABACPolicyEngine:
    def __init__(self, policy_yaml: str):
        """
        Initialize the policy engine with a YAML policy string.
        """
        if not isinstance(policy_yaml, str):
            raise ValidationError("policy_yaml must be a string.")
        if len(policy_yaml) > 1024 * 1024:
            raise ValidationError("policy_yaml exceeds the maximum allowed size of 1MB.")
            
        self.rules: List[Dict[str, Any]] = []
        if policy_yaml and policy_yaml.strip():
            try:
                parsed = yaml.safe_load(policy_yaml)
                if isinstance(parsed, dict) and 'rules' in parsed:
                    self.rules = parsed.get('rules', [])
                elif isinstance(parsed, list):
                    self.rules = parsed
            except yaml.YAMLError as e:
                raise ValueError(f"Failed to parse policy YAML: {e}")

    def evaluate(self, agent: str, namespace: str, purpose: str, action: str) -> Dict[str, Any]:
        """
        Evaluate the ABAC policy for the given attributes.
        Returns a dictionary with 'allowed', 'reason', and 'matched_rule'.
        Explicit 'deny' ALWAYS takes precedence over 'allow'.
        """
        if not isinstance(agent, str) or not isinstance(namespace, str) or not isinstance(purpose, str) or not isinstance(action, str):
            raise ValidationError("agent, namespace, purpose, and action must be strings.")
            
        allowed = False
        matched_allow_rule = None
        
        for rule in self.rules:
            if self._matches(rule, agent, namespace, purpose, action):
                effect = str(rule.get('effect', '')).lower()
                if effect == 'deny':
                    # Explicit deny immediately overrides any allow
                    return {"allowed": False, "reason": "Explicit deny rule matched", "matched_rule": rule}
                elif effect == 'allow':
                    allowed = True
                    matched_allow_rule = rule
                    
        if allowed:
            return {"allowed": True, "reason": "Allow rule matched", "matched_rule": matched_allow_rule}
        else:
            return {"allowed": False, "reason": "No matching allow rule (default deny)", "matched_rule": None}

    def get_lease_ttl(self, agent: str, capability_name: str) -> int:
        """
        RGT-29: parse policy for optional ttl.
        Matching order: exact agent+action > wildcard agent.
        Defaults to 300 seconds.
        """
        candidates = []
        for r in self.rules:
            # capability_name maps to 'action' in our rules
            if r.get("action") != capability_name and r.get("action") != "*":
                continue
            if r.get("agent") not in (agent, "*", None):
                continue
            candidates.append(r)

        # most specific first (exact agent first, exact action first)
        candidates.sort(key=lambda r: (
            r.get("agent") != agent,
            r.get("action") != capability_name,
        ))

        if candidates and "ttl" in candidates[0]:
            try:
                return max(1, int(candidates[0]["ttl"]))
            except (ValueError, TypeError):
                pass
        return 300 # safe default

    def _matches(self, rule: Dict[str, Any], agent: str, namespace: str, purpose: str, action: str) -> bool:
        """
        Helper to determine if a rule matches the provided attributes.
        Missing attributes in a rule default to '*' (match anything).
        """
        def match_attr(value: str, pattern: str) -> bool:
            # Using fnmatchcase for consistent case-sensitive matching across platforms
            return fnmatch.fnmatchcase(value, pattern)

        if not match_attr(agent, rule.get('agent', '*')):
            return False
        if not match_attr(namespace, rule.get('namespace', '*')):
            return False
        if not match_attr(purpose, rule.get('purpose', '*')):
            return False
        if not match_attr(action, rule.get('action', '*')):
            return False

        return True
