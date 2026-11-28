package approval

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
)

func waitPending(t *testing.T, b *Broker, n int) []Request {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if l := b.List(); len(l) >= n {
			return l
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending requests", n)
	return nil
}

func consultAsync(b *Broker, req Request) <-chan Decision {
	ch := make(chan Decision, 1)
	go func() { ch <- b.Consult(context.Background(), req) }()
	return ch
}

func TestNewRequestDefaults(t *testing.T) {
	r := NewRequest("agent", "ns", "key", "why")
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if r.Action != "read" || r.Require2FA || !uuidRe.MatchString(r.RequestID) || time.Since(r.CreatedAt) > time.Second {
		t.Fatalf("%+v", r)
	}
	ts := time.Unix(100, 0)
	r = NewRequest("a", "n", "s", "p", WithAction("write"), With2FA(true), WithRequestID("id-1"), WithCreatedAt(ts))
	if r.Action != "write" || !r.Require2FA || r.RequestID != "id-1" || !r.CreatedAt.Equal(ts) {
		t.Fatalf("%+v", r)
	}
	if NewRequest("a", "n", "s", "p").RequestID == NewRequest("a", "n", "s", "p").RequestID {
		t.Error("ids must be unique")
	}
}

func TestAutoAllowGate(t *testing.T) {
	var g Gate = AutoAllowGate{}
	d := g.Consult(context.Background(), NewRequest("a", "n", "s", "p"))
	if !d.Allowed || d.Reason != "auto-allow" || d.DecidedBy != "system" {
		t.Fatalf("%+v", d)
	}
}

func TestApproveFlow(t *testing.T) {
	b := NewBroker()
	req := NewRequest("agent", "ns", "key", "deploy", WithRequestID("r1"))
	ch := consultAsync(b, req)
	l := waitPending(t, b, 1)
	if l[0].RequestID != "r1" || l[0].Agent != "agent" {
		t.Fatalf("%+v", l)
	}
	if err := b.Approve("r1", "", "alice"); err != nil {
		t.Fatal(err)
	}
	d := <-ch
	if !d.Allowed || d.Reason != "approved" || d.DecidedBy != "alice" {
		t.Fatalf("%+v", d)
	}
	if len(b.List()) != 0 {
		t.Error("request must be removed after the agent consumed the decision")
	}
	if err := b.Approve("r1", "", ""); !errors.Is(err, ErrUnknownRequest) || !errors.Is(err, ErrApproval) {
		t.Errorf("after consume: %v", err)
	}
}

func TestDenyFlowAndDefaults(t *testing.T) {
	b := NewBroker()
	ch := consultAsync(b, NewRequest("a", "n", "s", "p", WithRequestID("r2")))
	waitPending(t, b, 1)
	if err := b.Deny("r2", "", ""); err != nil {
		t.Fatal(err)
	}
	d := <-ch
	if d.Allowed || d.Reason != "denied by operator" || d.DecidedBy != "operator" {
		t.Fatalf("%+v", d)
	}
	ch = consultAsync(b, NewRequest("a", "n", "s", "p", WithRequestID("r3")))
	waitPending(t, b, 1)
	_ = b.Deny("r3", "too risky", "bob")
	if d := <-ch; d.Allowed || d.Reason != "too risky" || d.DecidedBy != "bob" {
		t.Fatalf("%+v", d)
	}
	if err := b.Deny("nope", "", ""); !errors.Is(err, ErrUnknownRequest) {
		t.Error(err)
	}
}

func TestTimeoutFailsClosed(t *testing.T) {
	b := NewBroker(WithTimeout(30 * time.Millisecond))
	start := time.Now()
	d := b.Consult(context.Background(), NewRequest("a", "n", "s", "p"))
	if d.Allowed || d.DecidedBy != "system" || d.Reason != "approval timed out after 0s" {
		t.Fatalf("%+v", d)
	}
	if time.Since(start) < 25*time.Millisecond {
		t.Error("returned before the timeout")
	}
	if len(b.List()) != 0 {
		t.Error("timed-out request must be removed")
	}
	d = NewBroker(WithTimeout(0)).Consult(context.Background(), NewRequest("a", "n", "s", "p"))
	if d.Allowed {
		t.Error("zero timeout must deny")
	}
	// Python formats the timeout with :.0f
	d = NewBroker(WithTimeout(1500*time.Millisecond)).Consult(context.Background(), NewRequest("a", "n", "s", "p"))
	if d.Reason != "approval timed out after 2s" {
		t.Errorf("reason %q", d.Reason)
	}
}

func TestContextCancelFailsClosed(t *testing.T) {
	b := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Decision, 1)
	go func() { done <- b.Consult(ctx, NewRequest("a", "n", "s", "p", WithRequestID("c1"))) }()
	waitPending(t, b, 1)
	cancel()
	d := <-done
	if d.Allowed || !strings.HasPrefix(d.Reason, "approval cancelled") || d.DecidedBy != "system" {
		t.Fatalf("%+v", d)
	}
	if len(b.List()) != 0 {
		t.Error("cancelled request must be removed")
	}
	if err := b.Approve("c1", "", ""); err == nil {
		t.Error("approve after cancel must fail")
	}
}

func TestDecisionRecordedBeforeWakeIsHonoured(t *testing.T) {
	// Operator decides, then the agent's context is already cancelled: the
	// recorded decision still wins (single source of truth).
	b := NewBroker()
	tk, err := b.Submit(NewRequest("a", "n", "s", "p", WithRequestID("w1")))
	if err != nil {
		t.Fatal(err)
	}
	if tk.ID() != "w1" {
		t.Fatal(tk.ID())
	}
	if err := b.Approve("w1", "", "op"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := tk.Wait(ctx)
	if !d.Allowed || d.DecidedBy != "op" {
		t.Fatalf("%+v", d)
	}
	if again := tk.Wait(context.Background()); again != d {
		t.Errorf("second Wait differs: %+v", again)
	}
}

func TestFirstDecisionWins(t *testing.T) {
	b := NewBroker()
	tk, _ := b.Submit(NewRequest("a", "n", "s", "p", WithRequestID("f1")))
	if err := b.Approve("f1", "", "op"); err != nil {
		t.Fatal(err)
	}
	if err := b.Deny("f1", "late", "op2"); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("deny after approve: %v", err)
	}
	if err := b.Approve("f1", "", "op2"); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("second approve: %v", err)
	}
	if d := tk.Wait(context.Background()); !d.Allowed || d.DecidedBy != "op" {
		t.Fatalf("%+v", d)
	}

	tk, _ = b.Submit(NewRequest("a", "n", "s", "p", WithRequestID("f2")))
	_ = b.Deny("f2", "no", "op")
	if err := b.Approve("f2", "", "evil"); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("approve after deny must not flip the decision: %v", err)
	}
	if d := tk.Wait(context.Background()); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestDuplicateRequestID(t *testing.T) {
	b := NewBroker(WithTimeout(time.Second))
	first, err := b.Submit(NewRequest("a", "n", "s", "p", WithRequestID("dup")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Submit(NewRequest("evil", "n", "s", "p", WithRequestID("dup"))); !errors.Is(err, ErrApproval) {
		t.Errorf("duplicate accepted: %v", err)
	}
	d := b.Consult(context.Background(), NewRequest("evil", "n", "s", "p", WithRequestID("dup")))
	if d.Allowed || !strings.Contains(d.Reason, "duplicate") {
		t.Fatalf("%+v", d)
	}
	// The original request is untouched.
	if l := b.List(); len(l) != 1 || l[0].Agent != "a" {
		t.Fatalf("%+v", l)
	}
	_ = b.Approve("dup", "", "")
	if d := first.Wait(context.Background()); !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestSubmitFillsEmptyIDAndTime(t *testing.T) {
	b := NewBroker()
	tk, err := b.Submit(Request{Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	l := b.List()
	if len(l) != 1 || l[0].RequestID == "" || l[0].RequestID != tk.ID() || l[0].CreatedAt.IsZero() {
		t.Fatalf("%+v", l)
	}
	_ = b.Deny(tk.ID(), "", "")
	tk.Wait(context.Background())
}

func TestListOrderOldestFirst(t *testing.T) {
	b := NewBroker()
	base := time.Unix(1000, 0)
	mk := func(id string, off int) {
		if _, err := b.Submit(NewRequest("a", "n", "s", "p", WithRequestID(id), WithCreatedAt(base.Add(time.Duration(off)*time.Second)))); err != nil {
			t.Fatal(err)
		}
	}
	mk("late", 10)
	mk("early", 0)
	mk("tie-a", 5)
	mk("tie-b", 5)
	var ids []string
	for _, r := range b.List() {
		ids = append(ids, r.RequestID)
	}
	if got := strings.Join(ids, ","); got != "early,tie-a,tie-b,late" {
		t.Fatalf("order %s", got)
	}
}

func TestExpiredEntryIsHiddenAndRefused(t *testing.T) {
	b := NewBroker(WithTimeout(10 * time.Millisecond))
	tk, _ := b.Submit(NewRequest("a", "n", "s", "p", WithRequestID("e1")))
	time.Sleep(25 * time.Millisecond)
	if len(b.List()) != 0 {
		t.Error("expired request listed")
	}
	if err := b.Approve("e1", "", ""); !errors.Is(err, ErrExpired) {
		t.Errorf("approve after deadline: %v", err)
	}
	if err := b.Deny("e1", "", ""); !errors.Is(err, ErrExpired) {
		t.Errorf("deny after deadline: %v", err)
	}
	if d := tk.Wait(context.Background()); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestTwoFactor(t *testing.T) {
	secret, err := totp.GenerateSecret(totp.DefaultSecretLength)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := totp.NewReplayGuardedVerifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBroker(WithTOTPVerifier(guard.Verify))

	run := func(id string, code string) (error, Decision) {
		ch := consultAsync(b, NewRequest("a", "n", "s", "p", WithRequestID(id), With2FA(true)))
		waitPending(t, b, 1)
		err := b.Approve(id, code, "op")
		if err != nil {
			// request stays pending after a failed approval; deny to release the agent
			if lst := b.List(); len(lst) != 1 {
				t.Errorf("request must stay pending after a rejected approval: %+v", lst)
			}
			_ = b.Deny(id, "cleanup", "op")
		}
		return err, <-ch
	}

	if err, d := run("t1", ""); !errors.Is(err, ErrInvalidTOTP) || d.Allowed {
		t.Errorf("missing code: %v %+v", err, d)
	}
	if err, d := run("t2", "000000"); !errors.Is(err, ErrInvalidTOTP) || d.Allowed {
		t.Errorf("wrong code: %v %+v", err, d)
	}
	code, _ := totp.Generate(secret, time.Now())
	if err, d := run("t3", code); err != nil || !d.Allowed {
		t.Errorf("good code: %v %+v", err, d)
	}
	// The same code must not approve a second request (replay guard).
	if err, d := run("t4", code); !errors.Is(err, ErrInvalidTOTP) || d.Allowed {
		t.Errorf("replayed code: %v %+v", err, d)
	}
	// A request that does not require 2FA ignores the code.
	ch := consultAsync(b, NewRequest("a", "n", "s", "p", WithRequestID("t5")))
	waitPending(t, b, 1)
	if err := b.Approve("t5", "", "op"); err != nil || !(<-ch).Allowed {
		t.Error("no-2FA request needs no code")
	}
}

func TestTwoFactorWithoutVerifierFailsClosed(t *testing.T) {
	b := NewBroker()
	ch := consultAsync(b, NewRequest("a", "n", "s", "p", WithRequestID("n1"), With2FA(true)))
	waitPending(t, b, 1)
	if err := b.Approve("n1", "123456", "op"); !errors.Is(err, ErrTOTPNotConfigured) || !errors.Is(err, ErrApproval) {
		t.Fatalf("%v", err)
	}
	_ = b.Deny("n1", "", "")
	if d := <-ch; d.Allowed {
		t.Fatalf("%+v", d)
	}
}

// Many agents and several operators at once; run with -race.
func TestConcurrentStress(t *testing.T) {
	b := NewBroker(WithTimeout(5 * time.Second))
	const n = 100
	var allowed, denied atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := b.Consult(context.Background(), NewRequest(fmt.Sprintf("agent-%d", i), "n", "s", "p"))
			if d.Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}(i)
	}
	var ops sync.WaitGroup
	var decided atomic.Int32
	for o := 0; o < 4; o++ {
		ops.Add(1)
		go func(o int) {
			defer ops.Done()
			for decided.Load() < n {
				for _, r := range b.List() {
					var err error
					if r.Agent[len(r.Agent)-1]%2 == 0 {
						err = b.Approve(r.RequestID, "", fmt.Sprintf("op%d", o))
					} else {
						err = b.Deny(r.RequestID, "", fmt.Sprintf("op%d", o))
					}
					if err == nil {
						decided.Add(1)
					}
				}
				time.Sleep(time.Millisecond)
			}
		}(o)
	}
	wg.Wait()
	ops.Wait()
	if allowed.Load()+denied.Load() != n || decided.Load() != n {
		t.Fatalf("allowed=%d denied=%d decided=%d", allowed.Load(), denied.Load(), decided.Load())
	}
	if len(b.List()) != 0 {
		t.Error("pending left over")
	}
}

func TestRacingApprovals(t *testing.T) {
	b := NewBroker()
	tk, _ := b.Submit(NewRequest("a", "n", "s", "p", WithRequestID("race")))
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			if i%2 == 0 {
				err = b.Approve("race", "", "approver")
			} else {
				err = b.Deny("race", "", "denier")
			}
			if err == nil {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d decisions recorded for one request", ok.Load())
	}
	d := tk.Wait(context.Background())
	if (d.Allowed && d.DecidedBy != "approver") || (!d.Allowed && d.DecidedBy != "denier") {
		t.Fatalf("inconsistent decision %+v", d)
	}
}
