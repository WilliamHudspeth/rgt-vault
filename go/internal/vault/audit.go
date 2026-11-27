package vault

import (
	"context"

	"rgt-vault-server/internal/store"
)

// AuditLog returns the newest limit audit rows, newest first (python
// get_audit_log). A negative limit means no limit.
func (v *Vault) AuditLog(ctx context.Context, limit int) ([]store.AuditRow, error) {
	if err := v.rlock(); err != nil {
		return nil, err
	}
	defer v.mu.RUnlock()
	return v.store.GetAuditLog(ctx, limit)
}

// VerifyAuditChain recomputes the whole hash chain oldest-first and reports
// whether every link matches (python verify_audit_chain, via
// internal/audit). An empty log verifies. It detects inserted, modified and
// deleted rows, but not a wholesale replacement of the log by someone with
// file access (see SECURITY.md, Audit Chain Limitations).
func (v *Vault) VerifyAuditChain(ctx context.Context) (bool, error) {
	if err := v.rlock(); err != nil {
		return false, err
	}
	defer v.mu.RUnlock()
	return v.store.VerifyAuditChain(ctx)
}
