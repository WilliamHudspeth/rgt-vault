package approval

import (
	"context"
	"log"
	"strconv"
	"time"
)

// EventKind names a security event. The values double as the audit-log
// action the server writes for the event.
type EventKind string

// Security events raised around approvals, TOTP enrolment and token minting.
const (
	// EventBadCode: an approval carried a wrong TOTP code.
	EventBadCode EventKind = "APPROVAL_BAD_CODE"
	// EventCodeReplay: an already-used (or older) TOTP code was presented.
	EventCodeReplay EventKind = "APPROVAL_CODE_REPLAY"
	// EventAutoDenied: too many bad codes denied the request.
	EventAutoDenied EventKind = "APPROVAL_AUTO_DENIED"
	// EventLockout: an operator hit the bad-code limit and is throttled.
	EventLockout EventKind = "APPROVAL_LOCKOUT"
	// EventThrottled: an approval attempt was refused while locked out.
	EventThrottled EventKind = "APPROVAL_THROTTLED"
	// EventSeparation: the requesting token tried to approve its own request.
	EventSeparation EventKind = "APPROVAL_SOD_DENIED"
	// EventQueueFull: a request was refused because the pending-request cap
	// was reached.
	EventQueueFull EventKind = "APPROVAL_QUEUE_FULL"
	// EventTOTPReplaced: the TOTP secret (authenticator) was replaced.
	EventTOTPReplaced EventKind = "TOTP_SECRET_REPLACED"
	// EventTokenMinted: a bearer token was minted, rotated, revoked or imported.
	EventTokenMinted EventKind = "TOKEN_MINTED"
	// EventHoneyCapability: a honey (decoy) capability was invoked or probed
	// (RGT-30, internal/honeycap). Critical.
	EventHoneyCapability EventKind = "HONEY_CAPABILITY_TRIGGERED"
)

// Critical reports whether the event is one a flood of ordinary events must
// never hide: a lockout, an auto-denied request, a self-approval attempt.
// Delivery channels keep capacity for these.
func (k EventKind) Critical() bool {
	switch k {
	case EventLockout, EventAutoDenied, EventSeparation, EventHoneyCapability:
		return true
	}
	return false
}

// Event is one security event. Detail is a short server-built description;
// it NEVER carries a TOTP code, a token or a secret value.
type Event struct {
	Kind      EventKind
	RequestID string
	// Agent is the agent whose request is concerned (may be empty).
	Agent string
	// Operator is the acting token id (may be empty).
	Operator string
	Detail   string
	Time     time.Time
}

// Notifier receives security events (log line, webhook, ...). Notify must
// not block for long and must never panic the caller; implementations
// swallow their own delivery errors.
type Notifier interface {
	Notify(ctx context.Context, e Event)
}

// NotifierFunc adapts a function to Notifier.
type NotifierFunc func(ctx context.Context, e Event)

// Notify implements Notifier.
func (f NotifierFunc) Notify(ctx context.Context, e Event) { f(ctx, e) }

// LogNotifier writes every event as one WARNING log line. All values are
// quoted (strconv.Quote), so a request-derived field can never forge or
// split a log line.
type LogNotifier struct {
	// Logf defaults to log.Printf.
	Logf func(format string, args ...any)
}

// Notify implements Notifier.
func (l LogNotifier) Notify(_ context.Context, e Event) {
	logf := l.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf("WARNING: security event %s request=%s agent=%s operator=%s detail=%s",
		string(e.Kind), strconv.Quote(e.RequestID), strconv.Quote(e.Agent),
		strconv.Quote(e.Operator), strconv.Quote(e.Detail))
}

// Multi fans an event out to every notifier, in order.
type Multi []Notifier

// Notify implements Notifier.
func (m Multi) Notify(ctx context.Context, e Event) {
	for _, n := range m {
		if n != nil {
			n.Notify(ctx, e)
		}
	}
}
