package totp

import (
	"sync"
	"testing"
)

func TestVerifyResultDistinguishesReplayFromInvalid(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	g, err := NewReplayGuardedVerifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	const now = 1_700_000_000
	code, err := Generate(secret, at(now))
	if err != nil {
		t.Fatal(err)
	}
	if r := g.VerifyResultAt("000000x", at(now)); r != ResultInvalid {
		t.Fatalf("malformed code = %v, want invalid", r)
	}
	if r := g.VerifyResultAt(code, at(now)); r != ResultOK {
		t.Fatalf("first use = %v, want ok", r)
	}
	// Same code, same step, a moment later: a reuse.
	if r := g.VerifyResultAt(code, at(now+5)); r != ResultReplay {
		t.Fatalf("reuse = %v, want replay", r)
	}
	// Reuse inside the +/-1 step window is still a replay, never ok.
	if r := g.VerifyResultAt(code, at(now+30)); r != ResultReplay {
		t.Fatalf("reuse one step later = %v, want replay", r)
	}
	// A wrong code stays invalid, not replay.
	wrong := "000000"
	if wrong == code {
		wrong = "000001"
	}
	if r := g.VerifyResultAt(wrong, at(now)); r != ResultInvalid {
		t.Fatalf("wrong code = %v, want invalid", r)
	}
	// An older step than the last accepted one is refused as replay too.
	older, _ := Generate(secret, at(now-30))
	if r := g.VerifyResultAt(older, at(now)); r != ResultReplay {
		t.Fatalf("older step = %v, want replay", r)
	}
	// A later step is accepted again.
	next, _ := Generate(secret, at(now+60))
	if r := g.VerifyResultAt(next, at(now+60)); r != ResultOK {
		t.Fatalf("next step = %v, want ok", r)
	}
	for r, want := range map[Result]string{ResultOK: "ok", ResultInvalid: "invalid", ResultReplay: "replay"} {
		if r.String() != want {
			t.Errorf("%d.String() = %q, want %q", r, r.String(), want)
		}
	}
}

func TestVerifyResultWallClockMethods(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	g, _ := NewReplayGuardedVerifier(secret)
	if g.VerifyResult("") != ResultInvalid {
		t.Fatal("empty code accepted")
	}
	if g.Verify("12") {
		t.Fatal("bad code accepted")
	}
}

func TestVerifyResultConcurrentExactlyOneOK(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	g, _ := NewReplayGuardedVerifier(secret)
	const now = 1_700_000_000
	code, _ := Generate(secret, at(now))
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[Result]int{}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := g.VerifyResultAt(code, at(now))
			mu.Lock()
			counts[r]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts[ResultOK] != 1 || counts[ResultReplay] != 31 {
		t.Fatalf("counts = %v, want exactly one ok and 31 replay", counts)
	}
}
