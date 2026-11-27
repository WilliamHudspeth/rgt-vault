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
// Hardening beyond Python (batch H2, all fail-closed):
//   - separation of duties: a request remembers the token that made it
//     (Request.Requester); the same token, or a token of the same agent,
//     can never approve it, even with the operator scope;
//   - attempt caps: bad TOTP codes are counted per request (the request is
//     denied at the cap) and per operator (the operator is throttled for a
//     window), see WithAttemptLimits;
//   - a replayed TOTP code is reported as ErrCodeReplayed, distinct from a
//     wrong one, so the caller can audit and notify it.
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
	// Requester is the authenticated identity that made the request (set by
	// Consult from the context, see WithRequester). The broker refuses to
	// let it approve its own request.
	Requester Identity
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
	// ErrCodeReplayed: the TOTP code is genuine but was already used (or is
	// older than the last accepted one). It matches ErrInvalidTOTP too.
	ErrCodeReplayed = fmt.Errorf("%w: 2FA code already used", ErrInvalidTOTP)
	// ErrTooManyAttempts: the request reached its bad-code cap and was denied.
	ErrTooManyAttempts = fmt.Errorf("%w: too many invalid 2FA codes, request denied", ErrApproval)
	// ErrTooManyPending: the pending-request cap (global or per agent) is
	// reached; the request is refused, not queued.
	ErrTooManyPending = fmt.Errorf("%w: too many pending approval requests", ErrApproval)
	// ErrThrottled: the operator hit the bad-code limit and is locked out
	// for a while; no code is checked until it passes.
	ErrThrottled = fmt.Errorf("%w: too many invalid 2FA codes, operator throttled", ErrApproval)
	// ErrSeparationOfDuties: the approver is the requester (same token, or
	// the same agent), or cannot prove it is not.
	ErrSeparationOfDuties = fmt.Errorf("%w: separation of duties: the requester cannot approve its own request", ErrApproval)
)

// CodeError is returned for a refused TOTP code. It matches ErrInvalidTOTP
// (and ErrCodeReplayed for a reuse), ErrTooManyAttempts once the request was
// denied for it, and carries the counters the caller audits. It never holds
// the code.
type CodeError struct {
	// Replay: the code was a reuse of a consumed step.
	Replay bool
	// Missing: no code was sent (counted like a wrong one).
	Missing bool
	// Attempt is the bad-code count of this request, Limit its cap.
	Attempt, Limit int
	// RequestDenied: this attempt reached the cap and denied the request.
	RequestDenied bool
	// OperatorLocked: this attempt reached the per-operator limit.
	OperatorLocked bool
}

func (e *CodeError) Error() string {
	switch {
	case e.RequestDenied:
		return ErrTooManyAttempts.Error()
	case e.Replay:
		return ErrCodeReplayed.Error()
	}
	return ErrInvalidTOTP.Error()
}

// Is implements errors.Is for the sentinels above.
func (e *CodeError) Is(target error) bool {
	switch target {
	case ErrApproval, ErrInvalidTOTP:
		return true
	case ErrCodeReplayed:
		return e.Replay
	case ErrTooManyAttempts:
		return e.RequestDenied
	}
	return false
}

// ThrottleError is returned while an operator is locked out.
type ThrottleError struct{ RetryAfter time.Duration }

func (e *ThrottleError) Error() string {
	return fmt.Sprintf("%s (retry in %ds)", ErrThrottled.Error(), int(e.RetryAfter.Seconds())+1)
}

// Is makes errors.Is(err, ErrThrottled) work.
func (e *ThrottleError) Is(target error) bool { return target == ErrThrottled || target == ErrApproval }

// CodeResult is the outcome of a TOTP check (see WithTOTPChecker).
type CodeResult int

const (
	// CodeInvalid: malformed or wrong.
	CodeInvalid CodeResult = iota
	// CodeOK: valid and consumed.
	CodeOK
	// CodeReplay: genuine but already used.
	CodeReplay
)

// Default attempt limits (see WithAttemptLimits).
const (
	DefaultMaxCodeAttempts  = 5
	DefaultMaxOperatorFails = 10
	DefaultOperatorLockout  = 5 * time.Minute
	maxTrackedOperators     = 1024
	// DefaultMaxPending / DefaultMaxPendingPerAgent cap parked requests
	// (see WithPendingLimits).
	DefaultMaxPending         = 512
	DefaultMaxPendingPerAgent = 64
)

type pending struct {
	req      Request
	seq      uint64
	deadline time.Time
	done     chan struct{}
	decision *Decision
	badCodes int
}

// operatorState is one operator's recent refused attempts: a SLIDING window
// (the last maxOperatorFails timestamps), so a burst straddling a window
// edge cannot double the budget.
type operatorState struct {
	fails       []time.Time
	lockedUntil time.Time
}

// Broker pairs blocking agent requests with operator decisions. It is safe
// for concurrent use.
type Broker struct {
	timeout time.Duration
	totp    func(code string) CodeResult

	maxCodeAttempts  int
	maxOperatorFails int
	maxPending       int
	maxPendingAgent  int
	lockout          time.Duration
	now              func() time.Time // attempt/lockout clock only

	mu        sync.Mutex
	pending   map[string]*pending
	seq       uint64
	operators map[string]*operatorState
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
func WithTOTPVerifier(v func(code string) bool) BrokerOption {
	return func(b *Broker) {
		if v == nil {
			b.totp = nil
			return
		}
		b.totp = func(code string) CodeResult {
			if v(code) {
				return CodeOK
			}
			return CodeInvalid
		}
	}
}

// WithTOTPChecker sets a TOTP check that tells a replayed code from a wrong
// one (pass an adapter over (*totp.ReplayGuardedVerifier).VerifyResult).
// Like WithTOTPVerifier it is called with the broker lock held.
func WithTOTPChecker(v func(code string) CodeResult) BrokerOption {
	return func(b *Broker) { b.totp = v }
}

// WithAttemptLimits sets the bad-code caps: perRequest bad codes deny that
// request; perOperator bad codes within one lockout window throttle the
// operator for lockout. A value <= 0 keeps the default.
func WithAttemptLimits(perRequest, perOperator int, lockout time.Duration) BrokerOption {
	return func(b *Broker) {
		if perRequest > 0 {
			b.maxCodeAttempts = perRequest
		}
		if perOperator > 0 {
			b.maxOperatorFails = perOperator
		}
		if lockout > 0 {
			b.lockout = lockout
		}
	}
}

// WithPendingLimits caps parked requests: at most global in the whole broker
// and perAgent for one requester agent. A Submit over a cap fails with
// ErrTooManyPending (fail closed), so one token cannot bury the operator's
// queue or grow memory without bound. A value <= 0 keeps the default.
func WithPendingLimits(global, perAgent int) BrokerOption {
	return func(b *Broker) {
		if global > 0 {
			b.maxPending = global
		}
		if perAgent > 0 {
			b.maxPendingAgent = perAgent
		}
	}
}

// WithAttemptClock overrides the clock used for operator lockouts (tests).
// Request deadlines always use the real clock.
func WithAttemptClock(now func() time.Time) BrokerOption { return func(b *Broker) { b.now = now } }

// NewBroker returns a broker with the given options.
func NewBroker(opts ...BrokerOption) *Broker {
	b := &Broker{
		timeout:          DefaultTimeout,
		pending:          map[string]*pending{},
		operators:        map[string]*operatorState{},
		maxCodeAttempts:  DefaultMaxCodeAttempts,
		maxOperatorFails: DefaultMaxOperatorFails,
		maxPending:       DefaultMaxPending,
		maxPendingAgent:  DefaultMaxPendingPerAgent,
		lockout:          DefaultOperatorLockout,
		now:              time.Now,
	}
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
	if len(b.pending) >= b.maxPending {
		return nil, ErrTooManyPending
	}
	who := requesterAgent(req)
	n := 0
	for _, p := range b.pending {
		if requesterAgent(p.req) == who {
			n++
		}
	}
	if n >= b.maxPendingAgent {
		return nil, ErrTooManyPending
	}
	b.seq++
	p := &pending{req: req, seq: b.seq, deadline: time.Now().Add(b.timeout), done: make(chan struct{})}
	b.pending[req.RequestID] = p
	return &Ticket{b: b, p: p}, nil
}

// requesterAgent is the agent a request counts against: the authenticated
// requester when known, else the agent named in the request.
func requesterAgent(r Request) string {
	if r.Requester.Agent != "" {
		return r.Requester.Agent
	}
	return r.Agent
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
	if req.Requester.IsZero() {
		if id, ok := RequesterFrom(ctx); ok {
			req.Requester = id
		}
	}
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

// Approve approves a pending request on behalf of an operator with no
// authenticated identity (embedding, tests). It cannot prove separation of
// duties, so it refuses a request whose requester is known; use ApproveBy.
// When the request requires 2FA the broker must have a TOTP verifier and
// totpCode must satisfy it, otherwise ErrTOTPNotConfigured / ErrInvalidTOTP
// is returned and the request stays pending. An empty operator defaults to
// "operator".
func (b *Broker) Approve(requestID, totpCode, operator string) error {
	return b.ApproveBy(requestID, totpCode, Approver{Name: operator})
}

// ApproveBy is Approve with the approver's authenticated identity.
//
// Order: unknown / decided / expired, then separation of duties, then (for
// a 2FA request) the lockout, then the code. Bad codes are counted per
// request and per operator: at the request cap the request is denied
// (ErrTooManyAttempts, DecidedBy "system"); at the operator limit the
// operator is throttled (ErrThrottled) and no further code is even
// checked until the lockout passes. A correct code clears the operator's
// count. Every refusal leaves the request pending (except the cap).
func (b *Broker) ApproveBy(requestID, totpCode string, who Approver) error {
	if who.Name == "" {
		who.Name = "operator"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p, err := b.lookup(requestID)
	if err != nil {
		return err
	}
	if err := separation(p.req.Requester, who.Identity); err != nil {
		return err
	}
	if p.req.Require2FA {
		if b.totp == nil {
			return ErrTOTPNotConfigured
		}
		key := operatorKey(who)
		if wait := b.lockedFor(key); wait > 0 {
			return &ThrottleError{RetryAfter: wait}
		}
		if b.tableFull(key) {
			// Fail closed: more live operator keys than the table holds.
			return &ThrottleError{RetryAfter: b.lockout}
		}
		// A missing code is an attempt like any other (it is what a flood
		// of empty calls looks like); it just never reaches the verifier.
		res := CodeInvalid
		if totpCode != "" {
			res = b.totp(totpCode)
		}
		if res != CodeOK {
			return b.badCode(p, key, res == CodeReplay, totpCode == "")
		}
	}
	p.decision = &Decision{Allowed: true, Reason: "approved", DecidedBy: who.Name}
	close(p.done)
	return nil
}

// separation enforces that the approving identity is not the requesting one.
func separation(req, appr Identity) error {
	if req.IsZero() {
		return nil // no authenticated requester (embedding, tests)
	}
	if appr.IsZero() || appr.TokenID == "" {
		return ErrSeparationOfDuties // cannot prove who approves
	}
	if req.TokenID != "" && appr.TokenID == req.TokenID {
		return ErrSeparationOfDuties
	}
	if req.Agent != "" && appr.Agent == req.Agent {
		return ErrSeparationOfDuties
	}
	return nil
}

// operatorKey names the budget an attempt is charged to: the OPERATOR
// identity (its agent), so a second token of the same operator shares the
// budget instead of getting a fresh one. A token with no agent is keyed by
// the token id, an anonymous caller by its label.
func operatorKey(who Approver) string {
	switch {
	case who.Agent != "":
		return "agent:" + who.Agent
	case who.TokenID != "":
		return "token:" + who.TokenID
	}
	return "name:" + who.Name
}

// lockedFor returns how long the operator stays locked out (0 = not).
func (b *Broker) lockedFor(key string) time.Duration {
	st := b.operators[key]
	if st == nil {
		return 0
	}
	if wait := st.lockedUntil.Sub(b.now()); wait > 0 {
		return wait
	}
	return 0
}

// tableFull reports whether key is unknown and the table has no room even
// after dropping idle entries: such a caller is refused rather than left
// unmetered.
func (b *Broker) tableFull(key string) bool {
	if _, ok := b.operators[key]; ok || len(b.operators) < maxTrackedOperators {
		return false
	}
	b.pruneOperators(b.now())
	_, ok := b.operators[key]
	return !ok && len(b.operators) >= maxTrackedOperators
}

// badCode records a refused attempt and returns the error to report. The
// broker lock is held.
func (b *Broker) badCode(p *pending, key string, replay, missing bool) error {
	now := b.now()
	ce := &CodeError{Replay: replay, Missing: missing, Limit: b.maxCodeAttempts}

	st := b.operators[key]
	if st == nil {
		st = &operatorState{}
		b.operators[key] = st // tableFull ran first: there is room
	}
	// Sliding window: keep only the failures inside the last `lockout`.
	kept := st.fails[:0]
	for _, t := range st.fails {
		if now.Sub(t) < b.lockout {
			kept = append(kept, t)
		}
	}
	st.fails = append(kept, now)
	if len(st.fails) >= b.maxOperatorFails {
		st.lockedUntil = now.Add(b.lockout)
		ce.OperatorLocked = true
	}

	p.badCodes++
	ce.Attempt = p.badCodes
	if p.badCodes >= b.maxCodeAttempts {
		p.decision = &Decision{
			Allowed:   false,
			Reason:    fmt.Sprintf("denied: %d invalid 2FA codes", p.badCodes),
			DecidedBy: "system",
		}
		close(p.done)
		ce.RequestDenied = true
	}
	return ce
}

func (b *Broker) pruneOperators(now time.Time) {
	for k, st := range b.operators {
		if now.Before(st.lockedUntil) {
			continue
		}
		recent := false
		for _, t := range st.fails {
			if now.Sub(t) < b.lockout {
				recent = true
				break
			}
		}
		if !recent {
			delete(b.operators, k)
		}
	}
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
