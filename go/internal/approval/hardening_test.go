package approval

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedCodes is a TOTP checker with a fixed set of good codes; a good
// code works once, a used one is a replay.
type scriptedCodes struct {
	mu   sync.Mutex
	good map[string]bool
	used map[string]bool
}

func newCodes(good ...string) *scriptedCodes {
	c := &scriptedCodes{good: map[string]bool{}, used: map[string]bool{}}
	for _, g := range good {
		c.good[g] = true
	}
	return c
}

func (c *scriptedCodes) check(code string) CodeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case !c.good[code]:
		return CodeInvalid
	case c.used[code]:
		return CodeReplay
	}
	c.used[code] = true
	return CodeOK
}

var (
	reqID  = Identity{TokenID: "tok-agent", Agent: "alice"}
	opID   = Approver{Name: "op", Identity: Identity{TokenID: "tok-op", Agent: "ops"}}
	otherO = Approver{Name: "op2", Identity: Identity{TokenID: "tok-op2", Agent: "ops2"}}
)

func submit2FA(t *testing.T, b *Broker, id string) *Ticket {
	t.Helper()
	tk, err := b.Submit(Request{Agent: "alice", Namespace: "ns", SecretName: "s", RequestID: id, Require2FA: true, Requester: reqID})
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func TestBadCodesDenyTheRequestAtTheCap(t *testing.T) {
	codes := newCodes("111111")
	b := NewBroker(WithTOTPChecker(codes.check), WithAttemptLimits(3, 100, time.Minute), WithTimeout(time.Minute))
	tk := submit2FA(t, b, "r1")

	for i := 1; i <= 2; i++ {
		err := b.ApproveBy("r1", "000000", opID)
		var ce *CodeError
		if !errors.As(err, &ce) || !errors.Is(err, ErrInvalidTOTP) || errors.Is(err, ErrTooManyAttempts) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if ce.Attempt != i || ce.Limit != 3 || ce.RequestDenied || ce.Replay {
			t.Fatalf("attempt %d: %+v", i, ce)
		}
	}
	// The third bad code denies the request.
	err := b.ApproveBy("r1", "000000", opID)
	var ce *CodeError
	if !errors.As(err, &ce) || !ce.RequestDenied || !errors.Is(err, ErrTooManyAttempts) || !errors.Is(err, ErrApproval) {
		t.Fatalf("cap attempt: %v", err)
	}
	if strings.Contains(err.Error(), "000000") {
		t.Fatalf("error leaks the code: %v", err)
	}
	d := tk.Wait(context.Background())
	if d.Allowed || d.DecidedBy != "system" || !strings.Contains(d.Reason, "invalid 2FA codes") {
		t.Fatalf("decision = %+v", d)
	}
	// Even the right code can no longer approve: the request is decided.
	if err := b.ApproveBy("r1", "111111", opID); !errors.Is(err, ErrUnknownRequest) && !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("approve after denial = %v", err)
	}
}

func TestGoodCodeApprovesBeforeTheCap(t *testing.T) {
	codes := newCodes("111111")
	b := NewBroker(WithTOTPChecker(codes.check), WithAttemptLimits(3, 100, time.Minute))
	tk := submit2FA(t, b, "r1")
	_ = b.ApproveBy("r1", "000000", opID)
	_ = b.ApproveBy("r1", "000001", opID)
	if err := b.ApproveBy("r1", "111111", opID); err != nil {
		t.Fatal(err)
	}
	if d := tk.Wait(context.Background()); !d.Allowed || d.DecidedBy != "op" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestOperatorThrottledAcrossRequests(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	codes := newCodes("111111", "222222")
	b := NewBroker(WithTOTPChecker(codes.check), WithAttemptLimits(100, 3, time.Minute),
		WithAttemptClock(clock), WithTimeout(time.Hour))
	for i := 0; i < 5; i++ {
		submit2FA(t, b, "r"+string(rune('a'+i)))
	}
	// Three bad codes spread over three different requests lock the operator.
	var last error
	for i, id := range []string{"ra", "rb", "rc"} {
		last = b.ApproveBy(id, "000000", opID)
		var ce *CodeError
		if !errors.As(last, &ce) {
			t.Fatalf("attempt %d: %v", i, last)
		}
		if ce.OperatorLocked != (i == 2) {
			t.Fatalf("attempt %d: OperatorLocked = %v", i, ce.OperatorLocked)
		}
	}
	// Locked: even the correct code is not checked.
	err := b.ApproveBy("rd", "111111", opID)
	var te *ThrottleError
	if !errors.As(err, &te) || !errors.Is(err, ErrThrottled) || te.RetryAfter <= 0 || te.RetryAfter > time.Minute {
		t.Fatalf("locked approve = %v", err)
	}
	if codes.used["111111"] {
		t.Fatal("the code was consumed while the operator was locked out")
	}
	// Another operator is unaffected.
	if err := b.ApproveBy("rd", "111111", otherO); err != nil {
		t.Fatalf("other operator: %v", err)
	}
	// After the lockout the operator can approve again.
	advance(61 * time.Second)
	if err := b.ApproveBy("re", "222222", opID); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
}

func TestOperatorWindowResetsAndSuccessClearsCount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	codes := newCodes("111111", "222222")
	b := NewBroker(WithTOTPChecker(codes.check), WithAttemptLimits(100, 3, time.Minute), WithAttemptClock(clock))
	submit2FA(t, b, "r1")
	submit2FA(t, b, "r2")
	_ = b.ApproveBy("r1", "000000", opID)
	_ = b.ApproveBy("r1", "000000", opID)
	// A success clears the count: two more bad codes do not lock.
	if err := b.ApproveBy("r1", "111111", opID); err != nil {
		t.Fatal(err)
	}
	_ = b.ApproveBy("r2", "000000", opID)
	_ = b.ApproveBy("r2", "000000", opID)
	if err := b.ApproveBy("r2", "222222", opID); err != nil {
		t.Fatalf("count was not cleared by the success: %v", err)
	}
	// Failures older than the window do not add up.
	submit2FA(t, b, "r3")
	_ = b.ApproveBy("r3", "000000", opID)
	_ = b.ApproveBy("r3", "000000", opID)
	now = now.Add(2 * time.Minute)
	_ = b.ApproveBy("r3", "000000", opID)
	var te *ThrottleError
	if err := b.ApproveBy("r3", "000000", opID); errors.As(err, &te) {
		t.Fatalf("stale failures were counted: %v", err)
	}
}

func TestMissingCodeIsNotCounted(t *testing.T) {
	b := NewBroker(WithTOTPChecker(newCodes("111111").check), WithAttemptLimits(2, 2, time.Minute))
	submit2FA(t, b, "r1")
	for i := 0; i < 5; i++ {
		if err := b.ApproveBy("r1", "", opID); !errors.Is(err, ErrInvalidTOTP) {
			t.Fatalf("missing code = %v", err)
		}
	}
	if err := b.ApproveBy("r1", "111111", opID); err != nil {
		t.Fatalf("empty codes must not lock or deny: %v", err)
	}
}

func TestReplayedCodeIsReportedAsReplay(t *testing.T) {
	codes := newCodes("111111")
	b := NewBroker(WithTOTPChecker(codes.check))
	submit2FA(t, b, "r1")
	submit2FA(t, b, "r2")
	if err := b.ApproveBy("r1", "111111", opID); err != nil {
		t.Fatal(err)
	}
	err := b.ApproveBy("r2", "111111", opID)
	var ce *CodeError
	if !errors.As(err, &ce) || !ce.Replay || !errors.Is(err, ErrCodeReplayed) || !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("replay = %v", err)
	}
	if ce.Attempt != 1 {
		t.Fatalf("a replay counts as an attempt: %+v", ce)
	}
}

func TestPlainBoolVerifierStillWorks(t *testing.T) {
	b := NewBroker(WithTOTPVerifier(func(c string) bool { return c == "123456" }))
	submit2FA(t, b, "r1")
	if err := b.ApproveBy("r1", "999999", opID); !errors.Is(err, ErrInvalidTOTP) || errors.Is(err, ErrCodeReplayed) {
		t.Fatalf("bad = %v", err)
	}
	if err := b.ApproveBy("r1", "123456", opID); err != nil {
		t.Fatal(err)
	}
	// nil clears the verifier: fail closed.
	b2 := NewBroker(WithTOTPVerifier(func(string) bool { return true }), WithTOTPVerifier(nil))
	submit2FA(t, b2, "r1")
	if err := b2.ApproveBy("r1", "1", opID); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("nil verifier = %v", err)
	}
}

func TestSeparationOfDuties(t *testing.T) {
	cases := []struct {
		name string
		who  Approver
		ok   bool
	}{
		{"same token id", Approver{Name: "x", Identity: Identity{TokenID: "tok-agent", Agent: "someone"}}, false},
		{"same agent, other token", Approver{Name: "x", Identity: Identity{TokenID: "tok-9", Agent: "alice"}}, false},
		{"no identity", Approver{Name: "x"}, false},
		{"agent only, no token id", Approver{Name: "x", Identity: Identity{Agent: "ops"}}, false},
		{"a different token and agent", opID, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewBroker(WithTimeout(time.Minute))
			tk, err := b.Submit(Request{Agent: "alice", RequestID: "r1", Requester: reqID})
			if err != nil {
				t.Fatal(err)
			}
			err = b.ApproveBy("r1", "", c.who)
			if c.ok {
				if err != nil {
					t.Fatalf("approve: %v", err)
				}
				if d := tk.Wait(context.Background()); !d.Allowed {
					t.Fatalf("decision = %+v", d)
				}
				return
			}
			if !errors.Is(err, ErrSeparationOfDuties) || !errors.Is(err, ErrApproval) {
				t.Fatalf("approve = %v, want separation of duties", err)
			}
			// The request stays pending and an honest operator can still approve it.
			if got := b.List(); len(got) != 1 {
				t.Fatalf("pending = %d", len(got))
			}
			if err := b.ApproveBy("r1", "", opID); err != nil {
				t.Fatalf("honest approve: %v", err)
			}
		})
	}
}

func TestSeparationApplies2FAFirstCheckNotCounted(t *testing.T) {
	// A self-approval attempt is refused before any code is checked or counted.
	codes := newCodes("111111")
	b := NewBroker(WithTOTPChecker(codes.check), WithAttemptLimits(1, 1, time.Minute))
	submit2FA(t, b, "r1")
	self := Approver{Name: "x", Identity: reqID}
	for i := 0; i < 3; i++ {
		if err := b.ApproveBy("r1", "000000", self); !errors.Is(err, ErrSeparationOfDuties) {
			t.Fatalf("self approve = %v", err)
		}
	}
	if err := b.ApproveBy("r1", "111111", opID); err != nil {
		t.Fatalf("request was damaged by the self-approval attempts: %v", err)
	}
}

func TestLegacyApproveCannotApproveARequestWithKnownRequester(t *testing.T) {
	b := NewBroker()
	_, _ = b.Submit(Request{RequestID: "known", Requester: reqID})
	_, _ = b.Submit(Request{RequestID: "anon"})
	if err := b.Approve("known", "", "op"); !errors.Is(err, ErrSeparationOfDuties) {
		t.Fatalf("Approve of a known requester = %v", err)
	}
	if err := b.Approve("anon", "", "op"); err != nil {
		t.Fatalf("Approve without requester: %v", err)
	}
	// Deny never needs a proof: refusing is always safe.
	if err := b.Deny("known", "no", "op"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
}

func TestConsultPinsTheRequesterFromContext(t *testing.T) {
	b := NewBroker(WithTimeout(time.Minute))
	ctx := WithRequester(context.Background(), reqID)
	got, ok := RequesterFrom(ctx)
	if !ok || got != reqID {
		t.Fatalf("RequesterFrom = %+v %v", got, ok)
	}
	if _, ok := RequesterFrom(context.Background()); ok {
		t.Fatal("empty context has a requester")
	}
	go b.Consult(ctx, Request{Agent: "alice", RequestID: "r1"})
	reqs := waitPending(t, b, 1)
	if reqs[0].Requester != reqID {
		t.Fatalf("requester = %+v", reqs[0].Requester)
	}
	if err := b.ApproveBy("r1", "", Approver{Identity: reqID}); !errors.Is(err, ErrSeparationOfDuties) {
		t.Fatalf("self approval through Consult = %v", err)
	}
	if err := b.ApproveBy("r1", "", opID); err != nil {
		t.Fatal(err)
	}
}

func TestRequestExpiryFailsClosedWithIdentity(t *testing.T) {
	b := NewBroker(WithTimeout(30 * time.Millisecond))
	tk, _ := b.Submit(Request{RequestID: "r1", Requester: reqID})
	time.Sleep(60 * time.Millisecond)
	if err := b.ApproveBy("r1", "", opID); !errors.Is(err, ErrExpired) {
		t.Fatalf("approve after expiry = %v", err)
	}
	if d := tk.Wait(context.Background()); d.Allowed || d.DecidedBy != "system" || !strings.Contains(d.Reason, "timed out") {
		t.Fatalf("decision = %+v", d)
	}
}

func TestOperatorTableIsBounded(t *testing.T) {
	b := NewBroker(WithTOTPChecker(newCodes().check), WithAttemptLimits(1000, 1000, time.Hour))
	submit2FA(t, b, "r1")
	for i := 0; i < maxTrackedOperators+50; i++ {
		who := Approver{Identity: Identity{TokenID: "t" + strings.Repeat("x", i%7) + string(rune('A'+i%26)) + itoa(i), Agent: "ops"}}
		_ = b.ApproveBy("r1", "000000", who)
	}
	b.mu.Lock()
	n := len(b.operators)
	b.mu.Unlock()
	if n > maxTrackedOperators {
		t.Fatalf("operator table grew to %d", n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}

func TestPruneOperatorsDropsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := NewBroker(WithTOTPChecker(newCodes().check), WithAttemptLimits(1000, 2, time.Minute), WithAttemptClock(func() time.Time { return now }))
	submit2FA(t, b, "r1")
	_ = b.ApproveBy("r1", "000000", opID)
	_ = b.ApproveBy("r1", "000000", opID) // locked
	b.mu.Lock()
	b.pruneOperators(now)
	live := len(b.operators)
	b.mu.Unlock()
	if live != 1 {
		t.Fatalf("a locked operator was pruned: %d", live)
	}
	b.mu.Lock()
	b.pruneOperators(now.Add(2 * time.Minute))
	left := len(b.operators)
	b.mu.Unlock()
	if left != 0 {
		t.Fatalf("expired operator state kept: %d", left)
	}
}

func TestNotifiers(t *testing.T) {
	var lines []string
	ln := LogNotifier{Logf: func(f string, a ...any) { lines = append(lines, f) }}
	var got []Event
	rec := NotifierFunc(func(_ context.Context, e Event) { got = append(got, e) })
	m := Multi{ln, nil, rec}
	m.Notify(context.Background(), Event{Kind: EventCodeReplay, RequestID: "r\n1", Detail: "x"})
	if len(lines) != 1 || len(got) != 1 || got[0].Kind != EventCodeReplay {
		t.Fatalf("lines=%v got=%v", lines, got)
	}
	// The default logger quotes request-derived fields (no raw newline).
	var raw string
	LogNotifier{Logf: func(f string, a ...any) { raw = fmt.Sprintf(f, a...) }}.Notify(context.Background(), Event{Kind: EventBadCode, RequestID: "a\nFORGED", Agent: "x\r\ny"})
	if strings.ContainsAny(raw, "\r\n") || !strings.Contains(raw, `a\nFORGED`) {
		t.Fatalf("log line not escaped: %q", raw)
	}
	LogNotifier{}.Notify(context.Background(), Event{Kind: EventBadCode}) // default sink must not panic
}

func TestParseGatedOps(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"", "", false},
		{"set", "set", false},
		{" Set , rotate,SET ", "rotate,set", false},
		{"all", "revoke,rotate,set", false},
		{"revoke,all", "revoke,rotate,set", false},
		{"read", "", true},
		{"set,delete", "", true},
	}
	for _, c := range cases {
		got, err := ParseGatedOps(c.in)
		if (err != nil) != c.err {
			t.Fatalf("%q: err = %v", c.in, err)
		}
		var names []string
		for _, o := range got {
			names = append(names, string(o))
		}
		if strings.Join(names, ",") != c.want {
			t.Fatalf("%q: got %v, want %q", c.in, names, c.want)
		}
	}
	if NewBroker().HasTOTP() || !NewBroker(WithTOTPVerifier(func(string) bool { return true })).HasTOTP() {
		t.Fatal("HasTOTP wrong")
	}
}
