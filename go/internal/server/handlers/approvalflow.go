package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/vault"
)

// Approval hardening (batch H2). The operator endpoints write one audit row
// per refused code and notify (log line, optional webhook); an approval can
// never come from the token that made the request; set / rotate / revoke can
// be put behind the same approval broker as reads.
//
// Audit event names (details never contain a TOTP code, a token or a value).
const (
	// EventApprovalApproved: an operator approved a request.
	EventApprovalApproved = "APPROVAL_APPROVED"
	// EventApprovalDenied is written by the vault for a denied read; the
	// handlers write it for a denied gated set / rotate / revoke.
	EventApprovalDenied = "APPROVAL_DENIED"
)

// gatedOps is the set of mutating operations that need approval.
type gatedOps map[approval.GatedOp]bool

// SetGatedOps configures which of set, rotate and revoke wait for operator
// approval before they run (--require-approval-for). Call it before serving.
// The server stack guarantees a Broker whenever the list is not empty; if one
// is missing anyway, every gated operation is refused (fail closed).
func (h *Handlers) SetGatedOps(ops []approval.GatedOp) {
	h.gated = gatedOps{}
	for _, o := range ops {
		h.gated[o] = true
	}
}

// notify delivers a security event: the configured Notifier, else a log line.
func (h *Handlers) notify(ctx context.Context, e approval.Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	n := h.Notifier
	if n == nil {
		n = approval.LogNotifier{}
	}
	n.Notify(ctx, e)
}

// safeID returns id for an audit row or log line when it is a plain request
// id (letters, digits, '-', '_', at most 64), else a fixed placeholder: the id
// comes from the URL.
func safeID(id string) string {
	if id == "" || len(id) > 64 {
		return "<invalid>"
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "<invalid>"
		}
	}
	return id
}

func agentCol(p auth.Principal) sql.NullString {
	if p.Agent == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: p.Agent, Valid: true}
}

// auditEvent writes an audit row and logs (never fails the caller) when it
// cannot: the refusal being reported has already happened.
func (h *Handlers) auditEvent(r *http.Request, event string, secret sql.NullString, details string, agent sql.NullString) {
	if h.Vault == nil {
		return
	}
	// A client that hangs up must not cancel the record of a security event.
	if err := h.Vault.Audit(context.WithoutCancel(r.Context()), event, secret, details, agent); err != nil {
		log.Printf("ERROR: writing %s audit row: %s", event, LogSafe(err.Error()))
	}
}

// reportApprovalFailure audits and notifies a refused approve call and
// returns the error to answer with (after setting Retry-After when throttled).
func (h *Handlers) reportApprovalFailure(w http.ResponseWriter, r *http.Request, p auth.Principal, id string, err error) error {
	base := "request=" + safeID(id) + " token=" + p.TokenID + " ip=" + ClientIP(r)
	ev := approval.Event{RequestID: safeID(id), Operator: p.TokenID}
	row := func(kind approval.EventKind, extra string) {
		ev.Kind, ev.Detail = kind, base+extra
		h.auditEvent(r, string(kind), sql.NullString{}, ev.Detail, agentCol(p))
		h.notify(context.WithoutCancel(r.Context()), ev)
	}

	var ce *approval.CodeError
	var te *approval.ThrottleError
	switch {
	case errors.As(err, &ce):
		kind := approval.EventBadCode
		if ce.Replay {
			kind = approval.EventCodeReplay
		}
		row(kind, fmt.Sprintf(" attempt=%d/%d", ce.Attempt, ce.Limit))
		if ce.RequestDenied {
			row(approval.EventAutoDenied, fmt.Sprintf(" reason=%d invalid codes", ce.Attempt))
		}
		if ce.OperatorLocked {
			row(approval.EventLockout, " reason=operator reached the bad-code limit")
		}
	case errors.As(err, &te):
		w.Header().Set("Retry-After", strconv.Itoa(int(te.RetryAfter.Seconds())+1))
		row(approval.EventThrottled, " reason=operator locked out")
	case errors.Is(err, approval.ErrSeparationOfDuties):
		row(approval.EventSeparation, " reason=requester cannot approve its own request")
	case errors.Is(err, approval.ErrInvalidTOTP):
		row(approval.EventBadCode, " reason=code missing")
	}
	return err
}

// gate puts a mutating operation behind the approval broker when it is
// configured for it. It returns false after writing the response.
//
// Order: only requests the ABAC policy would allow reach the operator (a
// denied one falls through so the vault denies and audits it as usual), then
// the broker is consulted with the request pinned to the calling token.
// require2FA makes the operator supply a TOTP code (the secret's flag, or
// the new version's). A denial, a timeout and a cancelled request are all 403.
func (h *Handlers) gate(w http.ResponseWriter, r *http.Request, op approval.GatedOp, agent, namespace, name, purpose string, require2FA bool, abacPurpose, abacAction string) bool {
	if !h.gated[op] {
		return true
	}
	if h.Broker == nil {
		writeError(w, r, newAppError(http.StatusConflict, "Conflict", "approval is required for "+string(op)+" but no approval broker is active"))
		return false
	}
	// Validate before anything reaches the operator's queue: the request
	// fields are shown on the operator's screen.
	if err := vault.ValidateRequestFields(namespace, name, agent, purpose); err != nil {
		writeError(w, r, err)
		return false
	}
	if abacAction != "" && !h.Vault.PolicyAllows(agent, namespace, abacPurpose, abacAction) {
		return true // the vault refuses and audits it
	}
	d := h.Broker.Consult(r.Context(), approval.NewRequest(agent, namespace, name, purpose,
		approval.WithAction(string(op)), approval.With2FA(require2FA)))
	if d.Allowed {
		return true
	}
	h.auditEvent(r, EventApprovalDenied, store.Name(name),
		fmt.Sprintf("Agent: %s, Namespace: %s, Action: %s, Reason: %s", agent, namespace, op, d.Reason), sql.NullString{String: agent, Valid: agent != ""})
	writeError(w, r, newAppError(http.StatusForbidden, "PolicyDeniedError",
		fmt.Sprintf("approval denied for %s of '%s' (%s): %s", op, name, namespace, d.Reason)))
	return false
}
