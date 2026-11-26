// Package approval ports python/approval.py: a live human-in-the-loop gate
// for agent secret requests. The static ABAC policy decides what an agent
// may ask for; the Broker adds an interactive second gate. An agent request
// is parked as pending and blocks until an operator approves or denies it
// (optionally with a TOTP code when the request has Require2FA), or until it
// times out or the caller's context ends. Every non-approval is a denial
// (fail closed).
//
// The package is stdlib-only and never imports totp: TOTP verification is
// injected as func(code string) bool (a totp.ReplayGuardedVerifier's Verify
// method value fits), so the broker never holds the TOTP secret.
//
// Deliberate differences from the Python broker (all fail-closed):
//   - the first decision wins; a later Approve/Deny of the same request
//     returns ErrAlreadyDecided instead of silently overwriting it (Python
//     could flip a recorded approval into a denial or the reverse);
//   - a duplicate request id is denied instead of orphaning the earlier waiter;
//   - the agent side also honours context cancellation.
package approval

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// DefaultTimeout is the Python broker's default wait before auto-deny.
const DefaultTimeout = 120 * time.Second

// Request is an agent's pending request to use a secret.
type Request struct {
	Agent      string
	Namespace  string
	SecretName string
	Purpose    string
	Action     string // "read" by default
	Require2FA bool
	RequestID  string
	CreatedAt  time.Time
}

// RequestOption customises NewRequest.
type RequestOption func(*Request)

// WithAction sets the request action (default "read").
func WithAction(a string) RequestOption { return func(r *Request) { r.Action = a } }

// With2FA marks the request as requiring a TOTP code to approve.
func With2FA(required bool) RequestOption { return func(r *Request) { r.Require2FA = required } }

// WithRequestID overrides the generated request id.
func WithRequestID(id string) RequestOption { return func(r *Request) { r.RequestID = id } }

// WithCreatedAt overrides the creation time.
func WithCreatedAt(t time.Time) RequestOption { return func(r *Request) { r.CreatedAt = t } }

// NewRequest builds a Request with Python's defaults: action "read", a
// random uuid4 request id and CreatedAt = now.
func NewRequest(agent, namespace, secretName, purpose string, opts ...RequestOption) Request {
	r := Request{
		Agent: agent, Namespace: namespace, SecretName: secretName, Purpose: purpose,
		Action: "read", RequestID: newUUID(), CreatedAt: time.Now(),
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

// Decision is the outcome of an approval request.
type Decision struct {
	Allowed   bool
	Reason    string
	DecidedBy string
}

// Gate is the seam the vault consults before unsealing a secret.
type Gate interface {
	Consult(ctx context.Context, req Request) Decision
}

// AutoAllowGate approves everything: the default when no broker is wired.
type AutoAllowGate struct{}

// Consult implements Gate.
func (AutoAllowGate) Consult(context.Context, Request) Decision {
	return Decision{Allowed: true, Reason: "auto-allow", DecidedBy: "system"}
}

// Operator-side errors. All match ErrApproval with errors.Is.
var (
	// ErrApproval matches every operator-side approval error
	// (Python ApprovalError).
	ErrApproval = errors.New("approval error")
	// ErrUnknownRequest: no pending request with that id.
	ErrUnknownRequest = fmt.Errorf("%w: unknown request", ErrApproval)
	// ErrAlreadyDecided: the request already has a decision.
	ErrAlreadyDecided = fmt.Errorf("%w: already decided", ErrApproval)
	// ErrExpired: the request's wait deadline has passed (fail-closed: no
	// approval can be recorded after the timeout).
	ErrExpired = fmt.Errorf("%w: request expired", ErrApproval)
	// ErrTOTPNotConfigured: the request requires 2FA but the broker has no
	// verifier.
	ErrTOTPNotConfigured = fmt.Errorf("%w: requires 2FA but no TOTP verifier is configured", ErrApproval)
	// ErrInvalidTOTP: the TOTP code is missing or wrong.
	ErrInvalidTOTP = fmt.Errorf("%w: invalid or missing 2FA code", ErrApproval)
)

type pending struct {
	req      Request
	seq      uint64
	deadline time.Time
	done     chan struct{}
	decision *Decision
}

// Broker pairs blocking agent requests with operator decisions. It is safe
// for concurrent use.
type Broker struct {
	timeout time.Duration
	totp    func(code string) bool

	mu      sync.Mutex
	pending map[string]*pending
	seq     uint64
}

var _ Gate = (*Broker)(nil)

// BrokerOption configures NewBroker.
type BrokerOption func(*Broker)

// WithTimeout sets how long an agent request waits before auto-deny
// (default DefaultTimeout; <= 0 denies immediately unless already decided).
func WithTimeout(d time.Duration) BrokerOption { return func(b *Broker) { b.timeout = d } }

// WithTOTPVerifier sets the TOTP check used when a request requires 2FA. It
// is called with the broker lock held, so it must not call back into the
// broker. Pass (*totp.ReplayGuardedVerifier).Verify.
func WithTOTPVerifier(v func(code string) bool) BrokerOption { return func(b *Broker) { b.totp = v } }

// NewBroker returns a broker with the given options.
func NewBroker(opts ...BrokerOption) *Broker {
	b := &Broker{timeout: DefaultTimeout, pending: map[string]*pending{}}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Ticket is the agent-side handle of a submitted request.
type Ticket struct {
	b      *Broker
	p      *pending
	once   sync.Once
	result Decision
}

// ID returns the request id operators use with Approve and Deny.
func (t *Ticket) ID() string { return t.p.req.RequestID }

// Submit parks req as pending and returns immediately. The caller must call
// Ticket.Wait (Consult does) so the entry is removed; until then an expired
// entry is merely hidden from List and refused by Approve/Deny. An empty RequestID is
// replaced with a fresh uuid4; a duplicate id returns an error.
func (b *Broker) Submit(req Request) (*Ticket, error) {
	if req.RequestID == "" {
		req.RequestID = newUUID()
	}
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.pending[req.RequestID]; dup {
		return nil, fmt.Errorf("%w: duplicate request id %q", ErrApproval, req.RequestID)
	}
	b.seq++
	p := &pending{req: req, seq: b.seq, deadline: time.Now().Add(b.timeout), done: make(chan struct{})}
	b.pending[req.RequestID] = p
	return &Ticket{b: b, p: p}, nil
}

// Wait blocks until an operator decides, the timeout elapses (measured from
// Submit) or ctx ends, then removes the request. Only a recorded decision
// approves; timeout and cancellation are denials with DecidedBy "system".
// Wait may be called more than once; later calls return the same Decision.
func (t *Ticket) Wait(ctx context.Context) Decision {
	t.once.Do(func() { t.result = t.wait(ctx) })
	return t.result
}

func (t *Ticket) wait(ctx context.Context) Decision {
	b := t.b
	timer := time.NewTimer(time.Until(t.p.deadline))
	defer timer.Stop()
	cancelled := error(nil)
	select {
	case <-t.p.done:
	case <-timer.C:
	case <-ctx.Done():
		cancelled = ctx.Err()
	}
	// The recorded decision is the single source of truth: read and remove
	// it under the lock. If an operator decided in the instant between the
	// wake-up and this point, honour it; only a genuinely absent decision is
	// a (fail-closed) denial.
	b.mu.Lock()
	if b.pending[t.p.req.RequestID] == t.p {
		delete(b.pending, t.p.req.RequestID)
	}
	d := t.p.decision
	b.mu.Unlock()
	if d != nil {
		return *d
	}
	if cancelled != nil {
		return Decision{Allowed: false, Reason: "approval cancelled: " + cancelled.Error(), DecidedBy: "system"}
	}
	return Decision{
		Allowed:   false,
		Reason:    fmt.Sprintf("approval timed out after %.0fs", b.timeout.Seconds()),
		DecidedBy: "system",
	}
}

// Consult parks req and blocks until it is decided (Python consult()).
// Failing to register (duplicate id) is a denial.
func (b *Broker) Consult(ctx context.Context, req Request) Decision {
	t, err := b.Submit(req)
	if err != nil {
		return Decision{Allowed: false, Reason: err.Error(), DecidedBy: "system"}
	}
	return t.Wait(ctx)
}

// List returns a snapshot of the waiting requests, oldest first.
func (b *Broker) List() []Request {
	b.mu.Lock()
	ps := make([]*pending, 0, len(b.pending))
	now := time.Now()
	for _, p := range b.pending {
		if p.decision == nil && now.Before(p.deadline) {
			ps = append(ps, p)
		}
	}
	b.mu.Unlock()
	sort.Slice(ps, func(i, j int) bool {
		if !ps[i].req.CreatedAt.Equal(ps[j].req.CreatedAt) {
			return ps[i].req.CreatedAt.Before(ps[j].req.CreatedAt)
		}
		return ps[i].seq < ps[j].seq
	})
	out := make([]Request, len(ps))
	for i, p := range ps {
		out[i] = p.req
	}
	return out
}

func (b *Broker) lookup(id string) (*pending, error) {
	p := b.pending[id]
	if p == nil {
		return nil, fmt.Errorf("%w: no pending request with id %q", ErrUnknownRequest, id)
	}
	if p.decision != nil {
		return nil, fmt.Errorf("%w: request %q", ErrAlreadyDecided, id)
	}
	if !time.Now().Before(p.deadline) {
		return nil, fmt.Errorf("%w: request %q", ErrExpired, id)
	}
	return p, nil
}

// Approve approves a pending request. When the request requires 2FA the
// broker must have a TOTP verifier and totpCode must satisfy it, otherwise
// ErrTOTPNotConfigured / ErrInvalidTOTP is returned and the request stays
// pending. An empty operator defaults to "operator".
func (b *Broker) Approve(requestID, totpCode, operator string) error {
	if operator == "" {
		operator = "operator"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p, err := b.lookup(requestID)
	if err != nil {
		return err
	}
	if p.req.Require2FA {
		if b.totp == nil {
			return ErrTOTPNotConfigured
		}
		if totpCode == "" || !b.totp(totpCode) {
			return ErrInvalidTOTP
		}
	}
	p.decision = &Decision{Allowed: true, Reason: "approved", DecidedBy: operator}
	close(p.done)
	return nil
}

// Deny denies a pending request. Empty reason defaults to "denied by
// operator", empty operator to "operator".
func (b *Broker) Deny(requestID, reason, operator string) error {
	if reason == "" {
		reason = "denied by operator"
	}
	if operator == "" {
		operator = "operator"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p, err := b.lookup(requestID)
	if err != nil {
		return err
	}
	p.decision = &Decision{Allowed: false, Reason: reason, DecidedBy: operator}
	close(p.done)
	return nil
}

// newUUID returns a random (version 4) UUID string.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("approval: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
