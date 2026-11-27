package totp

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestStateFileSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "totp.state")
	secret := b32Secret("12345678901234567890")
	const now = 1_700_000_000
	code, _ := Generate(secret, at(now))

	v1, err := NewReplayGuardedVerifier(secret, WithStateFile(state))
	if err != nil {
		t.Fatal(err)
	}
	if r := v1.VerifyResultAt(code, at(now)); r != ResultOK {
		t.Fatalf("first use = %v", r)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("state file %v %v", fi, err)
		}
	}
	// A "restart": a new verifier over the same file still refuses the code.
	v2, err := NewReplayGuardedVerifier(secret, WithStateFile(state))
	if err != nil {
		t.Fatal(err)
	}
	if r := v2.VerifyResultAt(code, at(now+3)); r != ResultReplay {
		t.Fatalf("after restart = %v, want replay", r)
	}
	next, _ := Generate(secret, at(now+60))
	if r := v2.VerifyResultAt(next, at(now+60)); r != ResultOK {
		t.Fatalf("next step after restart = %v", r)
	}
	// Without the state file the replay window would be open again.
	v3, _ := NewReplayGuardedVerifier(secret)
	if r := v3.VerifyResultAt(code, at(now)); r != ResultOK {
		t.Fatal("control: in-memory verifier should accept")
	}
	// State of another (replaced) secret is ignored.
	other := b32Secret("abcdefghijklmnopqrst")
	v4, err := NewReplayGuardedVerifier(other, WithStateFile(state))
	if err != nil {
		t.Fatal(err)
	}
	oc, _ := Generate(other, at(now+60))
	if r := v4.VerifyResultAt(oc, at(now+60)); r != ResultOK {
		t.Fatalf("new secret with an old secret's state = %v", r)
	}
}

func TestStateFileErrors(t *testing.T) {
	dir := t.TempDir()
	secret := b32Secret("12345678901234567890")
	bad := filepath.Join(dir, "bad")
	for name, content := range map[string]string{"junk": "hello", "bad number": "v1 abcd12ef xx", "bad version": "v2 abcd12ef 5"} {
		if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewReplayGuardedVerifier(secret, WithStateFile(bad)); err == nil {
			t.Errorf("%s: corrupt state accepted", name)
		}
	}
	// A directory where the file should be: unreadable.
	if _, err := NewReplayGuardedVerifier(secret, WithStateFile(dir)); err == nil {
		t.Error("directory as a state file accepted")
	}
	// An unwritable location fails at construction.
	if _, err := NewReplayGuardedVerifier(secret, WithStateFile(filepath.Join(dir, "nodir", "state"))); err == nil {
		t.Error("state file in a missing directory accepted")
	}
	// If the state cannot be written when a code arrives, the code is refused.
	state := filepath.Join(dir, "state")
	v, err := NewReplayGuardedVerifier(secret, WithStateFile(state))
	if err != nil {
		t.Fatal(err)
	}
	const now = 1_700_000_000
	code, _ := Generate(secret, at(now))
	v.p.stateFile = filepath.Join(dir, "gone", "state")
	if r := v.VerifyResultAt(code, at(now)); r != ResultInvalid {
		t.Fatalf("code accepted although its step could not be recorded: %v", r)
	}
	v.p.stateFile = state
	if r := v.VerifyResultAt(code, at(now)); r != ResultOK {
		t.Fatalf("the refused code must still be usable once state works: %v", r)
	}
}
