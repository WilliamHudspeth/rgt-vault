package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	return OpenStore(filepath.Join(t.TempDir(), "cfg", "tokens.json"))
}

func mustMint(t *testing.T, s *Store, agent string, scopes ...Scope) (string, TokenInfo) {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []Scope{ScopeAgent}
	}
	tok, info, err := s.Mint(MintOptions{Agent: agent, Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	return tok, info
}

func TestParseScopes(t *testing.T) {
	got, err := ParseScopes(" lease, AGENT ,agent,,")
	if err != nil || len(got) != 2 || got[0] != ScopeAgent || got[1] != ScopeLease {
		t.Fatalf("ParseScopes = %v %v", got, err)
	}
	for _, bad := range []string{"", " , ", "root", "agent,admin"} {
		if _, err := ParseScopes(bad); err == nil {
			t.Errorf("ParseScopes(%q) accepted", bad)
		}
	}
}

func TestPrincipalHas(t *testing.T) {
	op := Principal{Scopes: []Scope{ScopeOperator}}
	if !op.Has(ScopeOperator) || !op.Has(ScopeAudit) || op.Has(ScopeAgent) || op.Has(ScopeLease) {
		t.Error("operator scope semantics")
	}
	au := Principal{Scopes: []Scope{ScopeAudit}}
	if au.Has(ScopeOperator) || !au.Has(ScopeAudit) {
		t.Error("audit scope semantics")
	}
}

func TestMintAuthenticateAndFileFormat(t *testing.T) {
	s := newStore(t)
	tok, info := mustMint(t, s, "bot", ScopeAgent, ScopeLease)
	if !strings.HasPrefix(info.ID, "tok_") || len(info.ID) != 20 || info.Agent != "bot" || info.ExpiresAt != nil {
		t.Fatalf("info = %+v", info)
	}
	for _, h := range []string{"Bearer " + tok, "bearer   " + tok + "  ", tok} {
		p, err := s.Authenticate(h)
		if err != nil || p.Agent != "bot" || p.TokenID != info.ID || !p.Has(ScopeLease) || p.Legacy {
			t.Errorf("Authenticate(%q) = %+v %v", h[:6], p, err)
		}
	}
	for h, want := range map[string]error{"": ErrMissingAuth, "Bearer ": ErrEmptyToken, "Bearer nope": ErrInvalidToken, "Bearer " + tok + "x": ErrInvalidToken} {
		if _, err := s.Authenticate(h); !errors.Is(err, want) {
			t.Errorf("Authenticate(%q) = %v, want %v", h, err, want)
		}
	}

	// On disk: hashes only, never the token; 0600.
	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), tok) {
		t.Fatal("the plaintext token is in the store file")
	}
	d := sha256.Sum256([]byte(tok))
	if !strings.Contains(string(raw), hex.EncodeToString(d[:])) {
		t.Error("the store does not hold the sha256 of the token")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(s.Path()); fi.Mode().Perm() != 0o600 {
			t.Errorf("store mode %o", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Dir(s.Path())); fi.Mode().Perm() != 0o700 {
			t.Errorf("store dir mode %o", fi.Mode().Perm())
		}
	}
	if ents, _ := os.ReadDir(filepath.Dir(s.Path())); len(ents) != 1 {
		t.Errorf("temp or lock files left: %v", ents)
	}
}

func TestMintValidation(t *testing.T) {
	s := newStore(t)
	for _, o := range []MintOptions{
		{Agent: "", Scopes: []Scope{ScopeAgent}},
		{Agent: "has space", Scopes: []Scope{ScopeAgent}},
		{Agent: "bot"},
		{Agent: "bot", Scopes: []Scope{"root"}},
		{Agent: "bot", Scopes: []Scope{ScopeAgent}, TTL: -time.Second},
	} {
		if _, _, err := s.Mint(o); err == nil {
			t.Errorf("Mint(%+v) accepted", o)
		}
	}
	if s.Exists() {
		t.Error("a refused mint created the store")
	}
}

func TestExpiry(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	tok, info, err := s.Mint(MintOptions{Agent: "bot", Scopes: []Scope{ScopeAgent}, TTL: time.Hour})
	if err != nil || info.ExpiresAt == nil || !info.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("mint: %+v %v", info, err)
	}
	if _, err := s.Authenticate(tok); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour) // exactly at expiry: expired
	p, err := s.Authenticate(tok)
	if !errors.Is(err, ErrExpiredToken) || p.TokenID != info.ID || len(p.Scopes) != 0 {
		t.Fatalf("expired: %+v %v", p, err)
	}
	if !info.Expired(now) || info.Expired(now.Add(-time.Second)) {
		t.Error("TokenInfo.Expired")
	}
}

func TestRevokeRotateImport(t *testing.T) {
	s := newStore(t)
	tok, info := mustMint(t, s, "bot")
	if _, err := s.Revoke("tok_0000000000000000"); !errors.Is(err, ErrUnknownTokenID) {
		t.Errorf("revoke unknown: %v", err)
	}
	gone, err := s.Revoke(info.ID)
	if err != nil || gone.ID != info.ID {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked token: %v", err)
	}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	old, oi, err := s.Mint(MintOptions{Agent: "ops", Scopes: []Scope{ScopeOperator, ScopeAudit}, TTL: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	fresh, ni, err := s.Rotate(oi.ID, 0)
	if err != nil || fresh == old || ni.ID == oi.ID || ni.Agent != "ops" || len(ni.Scopes) != 2 {
		t.Fatalf("rotate: %+v %v", ni, err)
	}
	if !ni.ExpiresAt.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("rotate kept lifetime? %v", ni.ExpiresAt)
	}
	if _, err := s.Authenticate(old); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("old token after rotate: %v", err)
	}
	if p, err := s.Authenticate(fresh); err != nil || p.Agent != "ops" {
		t.Errorf("new token: %+v %v", p, err)
	}
	if _, ni2, err := s.Rotate(ni.ID, 5*time.Minute); err != nil || !ni2.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Errorf("rotate with ttl: %+v %v", ni2, err)
	}
	if _, _, err := s.Rotate("tok_ffffffffffffffff", 0); !errors.Is(err, ErrUnknownTokenID) {
		t.Errorf("rotate unknown: %v", err)
	}

	legacy, _ := GenerateToken()
	ii, err := s.Import("  "+legacy+"\n", MintOptions{Agent: "importer", Scopes: []Scope{ScopeAgent}})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.Authenticate(legacy); err != nil || p.TokenID != ii.ID {
		t.Errorf("imported token: %+v %v", p, err)
	}
	if _, err := s.Import(legacy, MintOptions{Agent: "x", Scopes: []Scope{ScopeAgent}}); !errors.Is(err, ErrDuplicateToken) {
		t.Errorf("duplicate import: %v", err)
	}
	if _, err := s.Import(" ", MintOptions{Agent: "x", Scopes: []Scope{ScopeAgent}}); !errors.Is(err, ErrEmptyToken) {
		t.Errorf("empty import: %v", err)
	}
	if got, ok, err := s.Contains(legacy); err != nil || !ok || got.ID != ii.ID {
		t.Errorf("Contains = %+v %v %v", got, ok, err)
	}
	if _, ok, _ := s.Contains("nope"); ok {
		t.Error("Contains(nope)")
	}
}

// List exposes metadata only: no hash, no token, in any encoding.
func TestListNeverLeaksSecrets(t *testing.T) {
	s := newStore(t)
	var toks []string
	for _, a := range []string{"a", "b", "c"} {
		tok, _ := mustMint(t, s, a, ScopeAgent, ScopeAudit)
		toks = append(toks, tok)
	}
	infos, err := s.List()
	if err != nil || len(infos) != 3 {
		t.Fatalf("List = %v %v", infos, err)
	}
	raw, _ := json.Marshal(infos)
	for _, tok := range toks {
		d := sha256.Sum256([]byte(tok))
		if strings.Contains(string(raw), tok) || strings.Contains(string(raw), hex.EncodeToString(d[:])) {
			t.Fatalf("List leaks a token or its hash: %s", raw)
		}
	}
	if strings.Contains(string(raw), "sha256") || strings.Contains(string(raw), "hash") {
		t.Errorf("List has a hash field: %s", raw)
	}
}

// A second Store on the same file (another process: `rgt-vault token
// revoke` next to a running server) sees changes at its next read.
func TestReloadOnExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	server, cli := OpenStore(path), OpenStore(path)
	if p, err := server.Authenticate("Bearer x"); !errors.Is(err, ErrInvalidToken) || p.Agent != "" {
		t.Fatalf("absent store: %v", err)
	}
	tok, info := mustMint(t, cli, "bot")
	if _, err := server.Authenticate(tok); err != nil {
		t.Fatalf("server did not see the mint: %v", err)
	}
	if _, err := cli.Revoke(info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Authenticate(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("server did not see the revoke: %v", err)
	}
	// Rotate replaces a record with one of identical size: still noticed.
	tok2, info2 := mustMint(t, cli, "bot")
	if _, err := server.Authenticate(tok2); err != nil {
		t.Fatal(err)
	}
	tok3, _, err := cli.Rotate(info2.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Authenticate(tok2); !errors.Is(err, ErrInvalidToken) {
		t.Error("server still accepts the rotated-out token")
	}
	if _, err := server.Authenticate(tok3); err != nil {
		t.Errorf("server rejects the rotated-in token: %v", err)
	}
	// The file disappears: fail closed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Authenticate(tok3); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("deleted store still authenticates: %v", err)
	}
}

func TestCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	good, _ := GenerateToken()
	d := sha256.Sum256([]byte(good))
	h := hex.EncodeToString(d[:])
	rec := func(id, hash, agent, scopes string) string {
		return `{"id":"` + id + `","sha256":"` + hash + `","agent_id":"` + agent + `","scopes":` + scopes + `,"created_at":"2026-01-01T00:00:00Z"}`
	}
	cases := map[string]string{
		"not json":       "{",
		"bad version":    `{"version":2,"tokens":[]}`,
		"unknown field":  `{"version":1,"tokens":[],"admin":true}`,
		"bad id":         `{"version":1,"tokens":[` + rec("x", h, "bot", `["agent"]`) + `]}`,
		"bad hash":       `{"version":1,"tokens":[` + rec("tok_0123456789abcdef", "zz", "bot", `["agent"]`) + `]}`,
		"upper hash":     `{"version":1,"tokens":[` + rec("tok_0123456789abcdef", strings.ToUpper(h), "bot", `["agent"]`) + `]}`,
		"bad agent":      `{"version":1,"tokens":[` + rec("tok_0123456789abcdef", h, "a b", `["agent"]`) + `]}`,
		"no scopes":      `{"version":1,"tokens":[` + rec("tok_0123456789abcdef", h, "bot", `[]`) + `]}`,
		"unknown scope":  `{"version":1,"tokens":[` + rec("tok_0123456789abcdef", h, "bot", `["root"]`) + `]}`,
		"duplicate hash": `{"version":1,"tokens":[` + rec("tok_0123456789abcdef", h, "bot", `["agent"]`) + `,` + rec("tok_0123456789abcdee", h, "bot", `["agent"]`) + `]}`,
		"too big":        strings.Repeat(" ", MaxStoreBytes+1),
	}
	for name, content := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s := OpenStore(p)
		_, err := s.Authenticate("Bearer " + good)
		if err == nil || errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: Authenticate = %v, want a store error", name, err)
		}
		if strings.Contains(fmt2(err), good) {
			t.Errorf("%s: error echoes the token", name)
		}
		if _, err := s.List(); err == nil {
			t.Errorf("%s: List accepted", name)
		}
		if _, _, err := s.Mint(MintOptions{Agent: "x", Scopes: []Scope{ScopeAgent}}); err == nil {
			t.Errorf("%s: Mint overwrote a corrupt store", name)
		}
		if b, _ := os.ReadFile(p); string(b) != content {
			t.Errorf("%s: corrupt store was rewritten", name)
		}
	}
	// A valid hand-written record works.
	p := filepath.Join(dir, "ok.json")
	_ = os.WriteFile(p, []byte(`{"version":1,"tokens":[`+rec("tok_0123456789abcdef", h, "bot", `["agent"]`)+`]}`), 0o600)
	if pr, err := OpenStore(p).Authenticate(good); err != nil || pr.Agent != "bot" {
		t.Errorf("valid record: %+v %v", pr, err)
	}
}

func fmt2(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestLocking(t *testing.T) {
	s := newStore(t)
	mustMint(t, s, "bot")
	lock := s.Path() + ".lock"
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oldTimeout, oldStale := lockTimeout, staleLock
	t.Cleanup(func() { lockTimeout, staleLock = oldTimeout, oldStale })
	lockTimeout, staleLock = 50*time.Millisecond, time.Hour
	if _, _, err := s.Mint(MintOptions{Agent: "b2", Scopes: []Scope{ScopeAgent}}); !errors.Is(err, ErrStoreLocked) {
		t.Errorf("held lock: %v", err)
	}
	// A stale lock (crashed writer) is broken.
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(lock, old, old)
	if _, _, err := s.Mint(MintOptions{Agent: "b2", Scopes: []Scope{ScopeAgent}}); err != nil {
		t.Errorf("stale lock not broken: %v", err)
	}
	if _, err := os.Stat(lock); err == nil {
		t.Error("lock file left behind")
	}
	// Reads never take the lock.
	_ = os.WriteFile(lock, nil, 0o600)
	if infos, err := s.List(); err != nil || len(infos) != 2 {
		t.Errorf("List under a held lock: %v %v", infos, err)
	}
}

func TestUnwritableStoreDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := OpenStore(filepath.Join(blocker, "tokens.json"))
	if _, _, err := s.Mint(MintOptions{Agent: "bot", Scopes: []Scope{ScopeAgent}}); err == nil {
		t.Error("mint under a file succeeded")
	}
	// Reading through a path whose parent is a file fails closed. On Unix
	// stat says ENOTDIR (a store error); on Windows it says "path not
	// found", which is an absent store: no token is valid either way.
	if p, err := s.Authenticate("Bearer x"); err == nil || p.Agent != "" {
		t.Errorf("Authenticate = %+v %v", p, err)
	}
}

// Concurrent mints from many goroutines (and two Store values, like two
// processes) all land; concurrent authentication is race-free.
func TestConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	a, b := OpenStore(path), OpenStore(path)
	const n = 24
	toks := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			tok, _, err := s.Mint(MintOptions{Agent: "bot", Scopes: []Scope{ScopeAgent}})
			if err != nil {
				t.Error(err)
				return
			}
			toks[i] = tok
			for j := 0; j < 5; j++ {
				if _, err := a.Authenticate(tok); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	infos, err := a.List()
	if err != nil || len(infos) != n {
		t.Fatalf("%d tokens after %d concurrent mints (%v)", len(infos), n, err)
	}
	for _, tok := range toks {
		if _, err := b.Authenticate(tok); err != nil {
			t.Error(err)
		}
	}
}

func TestPresentedID(t *testing.T) {
	if PresentedID("") != "" || PresentedID("Bearer ") != "" {
		t.Error("PresentedID of nothing")
	}
	if got := PresentedID("Bearer secret-token"); got != TokenID("secret-token") || strings.Contains(got, "secret") {
		t.Errorf("PresentedID = %q", got)
	}
}
