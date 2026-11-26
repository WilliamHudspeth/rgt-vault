package vault

import (
	"context"
	"database/sql"
	"fmt"

	"rgt-vault-server/internal/policy"
)

// Simulate evaluates the ABAC policy without touching any secret (python
// simulate): validation, hook "simulate", a SIMULATION_RUN audit row, then
// the decision. An empty action means "read" (Python's default).
func (v *Vault) Simulate(ctx context.Context, agent, namespace, purpose, action string) (policy.Decision, error) {
	if err := validateParams(pAgent(agent), pNamespace(namespace), pPurpose(purpose, true)); err != nil {
		return policy.Decision{}, err
	}
	if action == "" {
		action = "read"
	}
	if err := v.rlock(); err != nil {
		return policy.Decision{}, err
	}
	defer v.mu.RUnlock()
	if err := v.hookConsult(ctx, OpSimulate, agent, namespace, purpose, nil); err != nil {
		return policy.Decision{}, err
	}
	if err := v.logAudit(ctx, "SIMULATION_RUN", sql.NullString{},
		fmt.Sprintf("Agent: %s, Namespace: %s, Action: %s", agent, namespace, action)); err != nil {
		return policy.Decision{}, err
	}
	return v.engine.Evaluate(agent, namespace, purpose, action), nil
}

// Explain is Simulate rendered as Python's explain text:
// "Access: ALLOWED|DENIED\nReason: ...\nMatched Rule: <json>|None".
func (v *Vault) Explain(ctx context.Context, agent, namespace, purpose, action string) (string, error) {
	d, err := v.Simulate(ctx, agent, namespace, purpose, action)
	if err != nil {
		return "", err
	}
	return d.Explain(), nil
}
