package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/hooks"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/servecmd"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/store"
)

// Audit events written by the token commands (batch H2, RGT-279 / RGT-296):
// a credential being created, replaced or removed is a security event that
// the audit chain and the operator's terminal must show.
const (
	auditTokenMinted   = "TOKEN_MINTED"
	auditTokenRotated  = "TOKEN_ROTATED"
	auditTokenRevoked  = "TOKEN_REVOKED"
	auditTokenImported = "TOKEN_IMPORTED"
)

// Environment of the CLI's security notification (the server has flags).
const (
	envSecurityWebhook      = "RGT_VAULT_SECURITY_WEBHOOK_URL"
	envSecurityWebhookAllow = "RGT_VAULT_SECURITY_WEBHOOK_ALLOW_REMOTE"
)

// notifyWebhook sends the event to $RGT_VAULT_SECURITY_WEBHOOK_URL when it is
// set (loopback only unless $RGT_VAULT_SECURITY_WEBHOOK_ALLOW_REMOTE=1) and
// waits for the answer, because the process exits right after. A delivery
// problem is a warning on stderr: the audit row and the terminal warning
// already exist, and a dead webhook must not block an operator.
func notifyWebhook(ctx context.Context, stderr io.Writer, kind approval.EventKind, agent, detail string) {
	raw := os.Getenv(envSecurityWebhook)
	if raw == "" {
		return
	}
	wh, err := hooks.NewEventWebhook(raw, os.Getenv(envSecurityWebhookAllow) == "1")
	if err != nil {
		fmt.Fprintf(stderr, "WARNING: %s: %v\n", envSecurityWebhook, err)
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := wh.Deliver(ctx, approval.Event{Kind: kind, Agent: agent, Operator: cliUser(), Detail: detail}); err != nil {
		fmt.Fprintf(stderr, "WARNING: security webhook delivery of %s failed: %v\n", kind, err)
	}
}

// tokenAuditor records token-store changes. It opens only the database file
// (no master secret, no keyring): the audit chain needs the SQLite store, not
// the keys. When no vault exists at --db there is no chain to write to and a
// notice says so.
type tokenAuditor struct {
	vf     *servecmd.VaultFlags
	stderr io.Writer
}

// cliUser names the OS account running the command, for the audit row.
func cliUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

// describeAudit is the token's public description for a row: ids, agent,
// scopes, expiry. Never the token or its hash.
func describeAudit(info auth.TokenInfo) string {
	exp := "never"
	if info.ExpiresAt != nil {
		exp = info.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("token=%s agent=%s scopes=%s expires=%s", info.ID, info.Agent, joinScopes(info.Scopes), exp)
}

// record logs a WARNING line and appends the audit row. An error means the
// row could not be written although a vault exists: the caller must undo the
// change (an unaudited credential must not stay active).
func (a tokenAuditor) record(ctx context.Context, event string, info auth.TokenInfo, extra string) error {
	details := describeAudit(info)
	if extra != "" {
		details += " " + extra
	}
	details += " by=" + cliUser()
	fmt.Fprintf(a.stderr, "WARNING: %s %s\n", event, details)
	notifyWebhook(ctx, a.stderr, approval.EventKind(event), info.Agent, details)

	res, err := a.vf.Resolve(os.Getenv)
	if err != nil {
		return err
	}
	if !vaultFileExists(res.DB) {
		fmt.Fprintf(a.stderr, "notice: no vault at %s, so this is not audited\n", res.DB)
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	st, err := store.Open(ctx, res.DB)
	if err != nil {
		return fmt.Errorf("cannot record %s in the audit log: %w", event, err)
	}
	defer st.Close()
	if err := st.LogAudit(ctx, store.AuditEvent{
		Action:  event,
		Details: details,
		AgentID: store.Name(strings.TrimSpace(info.Agent)),
	}); err != nil {
		return fmt.Errorf("cannot record %s in the audit log: %w", event, err)
	}
	return nil
}
