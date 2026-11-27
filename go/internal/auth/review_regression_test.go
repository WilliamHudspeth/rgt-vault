package auth

// Regression tests from the independent security review of PR #53 (H1):
// store concurrency across two Store values (= two processes), the
// stale-lock break, fail-closed corruption, import edge cases and the
// BeforeCommit hook.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReviewConcurrentMintRevokeTwoStores(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tokens.json")
	var wg sync.WaitGroup
	toks := make([]string, 40)
	ids := make([]string, 40)
	for i := range toks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := OpenStore(p) // a separate Store == a separate process
			tok, info, err := s.Mint(MintOptions{Agent: "a" + string(rune('a'+i%26)), Scopes: []Scope{ScopeAgent}})
			if err != nil {
				t.Errorf("mint %d: %v", i, err)
				return
			}
			toks[i], ids[i] = tok, info.ID
		}(i)
	}
	wg.Wait()
	s := OpenStore(p)
	for i := 0; i < 40; i += 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := OpenStore(p).Revoke(ids[i]); err != nil {
				t.Errorf("revoke %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	for i := range toks {
		_, err := s.Authenticate("Bearer " + toks[i])
		if (i%2 == 0) != (err != nil) {
			t.Errorf("token %d: revoked=%v err=%v", i, i%2 == 0, err)
		}
	}
}

// A leftover lock file from a dead writer and many concurrent writers: no
// lost update (review L2; with OS locks there is nothing stale to break).
func TestReviewStaleLockRace(t *testing.T) {
	for round := 0; round < 30; round++ {
		p := filepath.Join(t.TempDir(), "tokens.json")
		old := time.Now().Add(-2 * time.Minute)
		_ = os.WriteFile(p+".lock", []byte("dead-writer"), 0o600)
		_ = os.Chtimes(p+".lock", old, old)
		var wg sync.WaitGroup
		const n = 12
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, _, err := OpenStore(p).Mint(MintOptions{Agent: "x", Scopes: []Scope{ScopeAgent}}); err != nil {
					t.Errorf("mint: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		infos, err := OpenStore(p).List()
		if err != nil || len(infos) != n {
			t.Fatalf("round %d: lost updates: %d of %d tokens (err=%v)", round, len(infos), n, err)
		}
		if ents := nonLockEntries(t, filepath.Dir(p)); len(ents) != 1 {
			t.Fatalf("round %d: temp files left: %v", round, ents)
		}
	}
}

// The OS lock is exclusive between handles (goroutines or processes), an
// unlock releases only the caller's own lock, and closing the handle (a
// crashed holder) releases it.
func TestLockIsExclusiveAndReleasedOnClose(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	oldTimeout := lockTimeout
	t.Cleanup(func() { lockTimeout = oldTimeout })
	lockTimeout = 50 * time.Millisecond
	unlockA, err := lockFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(p); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second holder got the lock: %v", err)
	}
	unlockA()
	unlockB, err := lockFile(p)
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	unlockB()
	// A holder that dies: the OS drops its lock with the handle.
	f, err := os.OpenFile(p, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := tryLock(f); err != nil {
		t.Fatal(err)
	}
	_ = f.Close() // no unlock call, like a crash
	unlockC, err := lockFile(p)
	if err != nil {
		t.Fatalf("lock not released by close: %v", err)
	}
	unlockC()
}

func TestReviewCorruptionFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tokens.json")
	s := OpenStore(p)
	tok, _, _ := s.Mint(MintOptions{Agent: "a", Scopes: []Scope{ScopeAgent}})
	if _, err := s.Authenticate("Bearer " + tok); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"", "{", `{"version":2,"tokens":[]}`, `{"version":1,"tokens":[{"id":"x"}]}`, strings.Repeat("A", 100)} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Authenticate("Bearer " + tok); err == nil {
			t.Errorf("corrupt store %q still authenticates a cached token", content)
		}
	}
}

func TestReviewImportEdgeCases(t *testing.T) {
	s := OpenStore(filepath.Join(t.TempDir(), "tokens.json"))
	for _, tk := range []string{"", "   ", "\n", "Bearer abc", "a\tb"} {
		if _, err := s.Import(tk, MintOptions{Agent: "a", Scopes: []Scope{ScopeOperator}}); err == nil {
			t.Errorf("Import(%q) accepted a token that can never be presented", tk)
		}
	}
	// (Strength checks are the CLI's job: `token import` runs ValidateToken.)
	if infos, _ := s.List(); len(infos) != 0 {
		t.Errorf("refused imports stored %d tokens", len(infos))
	}
}

// BeforeCommit (review L3): an error aborts the change; on success the hook
// saw the very token that was stored.
func TestBeforeCommitHook(t *testing.T) {
	s := newStore(t)
	boom := errors.New("disk full")
	if _, _, err := s.Mint(MintOptions{Agent: "bot", Scopes: []Scope{ScopeAgent}, BeforeCommit: func(string) error { return boom }}); !errors.Is(err, boom) {
		t.Fatalf("mint hook error: %v", err)
	}
	if infos, _ := s.List(); len(infos) != 0 {
		t.Fatal("an aborted mint stored a token")
	}
	var seen string
	tok, info, err := s.Mint(MintOptions{Agent: "bot", Scopes: []Scope{ScopeAgent}, BeforeCommit: func(t string) error { seen = t; return nil }})
	if err != nil || seen != tok {
		t.Fatalf("mint hook: %v (saw the token: %v)", err, seen == tok)
	}
	if _, _, err := s.RotateWith(info.ID, 0, func(string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("rotate hook error: %v", err)
	}
	if _, err := s.Authenticate(tok); err != nil {
		t.Fatalf("an aborted rotate killed the old token: %v", err)
	}
	seen = ""
	fresh, _, err := s.RotateWith(info.ID, 0, func(t string) error { seen = t; return nil })
	if err != nil || seen != fresh {
		t.Fatalf("rotate hook: %v", err)
	}
	if _, err := s.Authenticate(tok); err == nil {
		t.Error("old token alive after rotate")
	}
}
