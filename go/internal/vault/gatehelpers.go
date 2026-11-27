package vault

import "context"

// Requires2FA reports whether the ACTIVE version of (namespace, name) is
// flagged require_2fa. A missing secret reports false. The server uses it to
// decide whether an approval request for a write or revoke must carry a
// TOTP code.
func (v *Vault) Requires2FA(ctx context.Context, namespace, name string) (bool, error) {
	var req bool
	err := v.withR(func() error {
		var e error
		req, e = v.store.Requires2FA(ctx, namespace, name)
		return e
	})
	return req, err
}

// PolicyAllows reports whether the ABAC policy allows the action, without
// writing an audit row or consulting the hook. It is a pre-check only: the
// real operation re-evaluates the policy and audits a denial. The server
// uses it so a request the policy would refuse anyway never reaches the
// operator's approval queue. A closed vault allows nothing.
func (v *Vault) PolicyAllows(agent, namespace, purpose, action string) bool {
	allowed := false
	if err := v.withR(func() error {
		allowed = v.engine.Evaluate(agent, namespace, purpose, action).Allowed
		return nil
	}); err != nil {
		return false
	}
	return allowed
}

// ValidateRequestFields applies the vault's own input validation (names,
// namespace, agent id, purpose) to fields that are about to be shown to an
// operator in an approval request. The vault validates again when the
// operation runs; this runs first so that attacker-chosen text (control
// characters, over-long values) never reaches the operator's screen. An
// empty purpose is allowed.
func ValidateRequestFields(namespace, name, agent, purpose string) error {
	return validateParams(pName(name), pNamespace(namespace), pAgent(agent), pPurpose(purpose, true))
}
