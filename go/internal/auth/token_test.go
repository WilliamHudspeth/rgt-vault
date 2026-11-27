package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The legacy shared token file (--legacy-shared-token).
func TestLegacyTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "server.token")
	ts := NewTokenStore(p)
	if ts.Exists() {
		t.Fatal("exists before creation")
	}
	if _, err := ts.Read(); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("Read missing: %v", err)
	}
	if _, err := ts.Verify("Bearer x"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("Verify missing: %v", err)
	}
	if err := ts.Write(""); err == nil {
		t.Error("empty token written")
	}
	path, tok, err := LoadOrCreateToken(p)
	if err != nil || path != p || len(tok) < 43 || !ts.Exists() {
		t.Fatalf("LoadOrCreateToken = %q %v", path, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %o", fi.Mode().Perm())
		}
	}
	if _, again, err := LoadOrCreateToken(p); err != nil || again != tok {
		t.Errorf("second load = %v (changed: %v)", err, again != tok)
	}
	id, err := ts.Verify("Bearer " + tok)
	if err != nil || id != TokenID(tok) || len(id) != 8 {
		t.Errorf("Verify = %q %v", id, err)
	}
	if _, err := ts.Verify(tok); err != nil {
		t.Errorf("raw token: %v", err)
	}
	for h, want := range map[string]error{"": ErrMissingAuth, "Bearer   ": ErrEmptyToken, "Bearer " + tok + "x": ErrInvalidToken, "Bearer short": ErrInvalidToken} {
		if _, err := ts.Verify(h); !errors.Is(err, want) {
			t.Errorf("Verify(%q) = %v, want %v", h, err, want)
		}
	}
	// A path under a regular file cannot be created.
	blocker := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(blocker, nil, 0o600)
	if _, _, err := LoadOrCreateToken(filepath.Join(blocker, "t")); err == nil {
		t.Error("created a token under a file")
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
