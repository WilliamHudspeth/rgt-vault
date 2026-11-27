package vault

// Regression tests for the Gemini 4 Neon review findings on the G7 diff.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/keychain"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/store"
)

// A 2FA-flagged version must not be leasable by version without the second
// factor after it was revoked or superseded by a non-2FA version.
func TestRequire2FAOnVersionLease(t *testing.T) {
	ctx := context.Background()
	gate := &testGate{dec: approval.Decision{Allowed: true}}
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy, Approval: gate})
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "root", Namespace: "prod", Agent: SystemAgent, Value: []byte("v1"), Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	set(t, v, "prod", "root", "v2") // successor without 2FA
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "gone", Namespace: "prod", Agent: SystemAgent, Value: []byte("g"), Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	if err := v.RevokeSecret(ctx, "prod", "gone", SystemAgent); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		version int64
		want    bool
	}{{"root", 1, true}, {"root", 2, false}, {"root", 0, false}, {"gone", 1, true}, {"gone", 9, false}} {
		gate.reqs = nil
		_, _ = get(t, v, "prod", c.name, c.version)
		if len(gate.reqs) != 1 || gate.reqs[0].Require2FA != c.want {
			t.Errorf("%s v%d: approval requests %+v, want Require2FA=%v", c.name, c.version, gate.reqs, c.want)
		}
	}
	if _, err := get(t, v, "prod", "root", -1); !errors.Is(err, ErrValidation) {
		t.Fatalf("negative version: %v", err)
	}
	if _, err := v.Fingerprint(ctx, "prod", "root", -1); !errors.Is(err, ErrValidation) {
		t.Fatalf("negative fingerprint version: %v", err)
	}
}

// callbackHook calls back into the vault from Consult.
type callbackHook struct {
	v *Vault
}

func (h *callbackHook) ID() string   { return "callback" }
func (h *callbackHook) Frozen() bool { return false }
func (h *callbackHook) Consult(ctx context.Context, r HookRequest) (HookResponse, error) {
	if h.v != nil {
		_ = h.v.KeyEpoch()
		_, _ = h.v.VerifyAuditChain(ctx)
	}
	return HookResponse{Decision: HookAllow, Reason: "ok"}, nil
}

// A hook that calls back into the vault must not deadlock, also during a
// rotation, and a blocking approval must not stall a rotation.
func TestHookCallbackAndBlockingApprovalNoDeadlock(t *testing.T) {
	ctx := context.Background()
	hook := &callbackHook{}
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	gate := gateFunc(func(context.Context, approval.Request) approval.Decision {
		entered <- struct{}{}
		<-release
		return approval.Decision{Allowed: true}
	})
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(),
		PolicyYAML: allowAllPolicy, Hook: hook, Approval: gate})
	hook.v = v
	set(t, v, "n", "s", "v")

	leaseDone := make(chan error, 1)
	go func() {
		_, err := get(t, v, "n", "s", 0)
		leaseDone <- err
	}()
	<-entered // the lease is parked in the approval gate

	rotated := make(chan error, 1)
	go func() {
		err := v.RotateDEK(ctx)
		if err == nil {
			err = v.RotateMaster(ctx)
		}
		rotated <- err
	}()
	select {
	case err := <-rotated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("rotation blocked behind a pending approval (or a hook callback deadlocked)")
	}
	close(release)
	if err := <-leaseDone; err != nil {
		t.Fatalf("lease after rotation: %v", err)
	}
	mustVerify(t, v)
}

type gateFunc func(context.Context, approval.Request) approval.Decision

func (f gateFunc) Consult(ctx context.Context, r approval.Request) approval.Decision {
	return f(ctx, r)
}

type frozenPanicHook struct{}

func (frozenPanicHook) ID() string   { return "fp" }
func (frozenPanicHook) Frozen() bool { panic("freeze file unreadable") }
func (frozenPanicHook) Consult(context.Context, HookRequest) (HookResponse, error) {
	return HookResponse{Decision: HookAllow}, nil
}

func TestFrozenPanicFailsClosed(t *testing.T) {
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy, Hook: frozenPanicHook{}})
	err := v.SetSecret(context.Background(), SetSecretRequest{Name: "s", Namespace: "n", Agent: SystemAgent, Value: []byte("v")})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "hook raised panic: freeze file unreadable") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigAndSimulateValidation(t *testing.T) {
	ctx := context.Background()
	for _, cfg := range []Config{{RateLimit: -1}, {RateWindow: -time.Second}} {
		cfg.DBPath, cfg.Provider = filepath.Join(t.TempDir(), "vault.db"), memProv()
		if _, err := Open(ctx, cfg); err == nil {
			t.Fatalf("negative rate config accepted: %+v", cfg)
		}
	}
	if r := NewRateLimiter(1, 0); r.window != DefaultRateWindow {
		t.Fatal("zero window must not fail open")
	}
	v, _ := newVault(t, allowAllPolicy)
	for _, bad := range []string{"re\nad", "a\xffb", strings.Repeat("x", MaxPurposeChars+1)} {
		if _, err := v.Simulate(ctx, "a", "n", "", bad); !errors.Is(err, ErrValidation) {
			t.Errorf("action %q: %v", bad, err)
		}
	}
	if len(auditRows(t, v)) != 0 {
		t.Fatal("invalid action reached the audit chain")
	}
	// RotateMaster on a closed vault reports ErrClosed even when the
	// provider cannot rotate.
	f := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: providerstest.Fixed{Secret: make([]byte, 32)}})
	_ = f.Close()
	if err := f.RotateMaster(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed RotateMaster: %v", err)
	}
}

func TestRotateDEKCancelledAndCorruptActive(t *testing.T) {
	v, _ := newVault(t, allowAllPolicy)
	set(t, v, "n", "s", "v")
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.RotateDEK(cctx); !errors.Is(err, context.Canceled) || v.KeyEpoch() != 1 {
		t.Fatalf("cancelled rotation: %v epoch %d", err, v.KeyEpoch())
	}
	// Cancellation during the rewrite rolls back.
	ctx, cancel2 := context.WithCancel(context.Background())
	v.testRewriteRow = func(int) error { cancel2(); return nil }
	if err := v.RotateDEK(ctx); err == nil || v.KeyEpoch() != 1 {
		t.Fatalf("cancel mid-rewrite: %v epoch %d", err, v.KeyEpoch())
	}
	v.testRewriteRow = nil
	if _, err := os.Stat(v.KeychainPath() + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".new left after an aborted rotation")
	}

	// An ACTIVE row whose ciphertext was tampered with aborts the rotation.
	kc0, _ := os.ReadFile(v.KeychainPath())
	if _, err := v.aux.Exec("UPDATE secrets SET ciphertext = zeroblob(40) WHERE name = 's'"); err != nil {
		t.Fatal(err)
	}
	if err := v.RotateDEK(context.Background()); err == nil || !strings.Contains(err.Error(), "decrypt n/s") {
		t.Fatalf("corrupt active row: %v", err)
	}
	if kc, _ := os.ReadFile(v.KeychainPath()); string(kc) != string(kc0) || v.KeyEpoch() != 1 {
		t.Fatal("a failed rotation changed the keychain or epoch")
	}
}

// RotateMaster interrupted after the provider switched masters but before
// the epoch commit: Open completes it from keychain.json.new.
func TestRotateMasterInterruptedRecovery(t *testing.T) {
	ctx := context.Background()
	dir, prov, v := newFileVault(t)
	set(t, v, "n", "s", "v")
	v.testMasterPreCommit = func() error { return errors.New("power cut") }
	if err := v.RotateMaster(ctx); err == nil || !strings.Contains(err.Error(), "re-open the vault") {
		t.Fatalf("got %v", err)
	}
	_ = v.Close()
	v = openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, PolicyYAML: allowAllPolicy})
	if v.KeyEpoch() != 2 {
		t.Fatalf("epoch %d, want 2", v.KeyEpoch())
	}
	if got, err := get(t, v, "n", "s", 0); err != nil || got != "v" {
		t.Fatalf("after recovery %q %v", got, err)
	}

	// After the commit, before the rename: also recovered.
	v.testBeforeSwap = func() error { return errors.New("crash") }
	if err := v.RotateMaster(ctx); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("got %v", err)
	}
	if v.dek != nil {
		t.Fatal("broken vault kept its DEK")
	}
	_ = v.Close()
	v = openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, PolicyYAML: allowAllPolicy})
	if v.KeyEpoch() != 3 {
		t.Fatalf("epoch %d, want 3", v.KeyEpoch())
	}
	if got, err := get(t, v, "n", "s", 0); err != nil || got != "v" {
		t.Fatalf("after recovery %q %v", got, err)
	}
	mustVerify(t, v)
}

func TestMissingKeychainCases(t *testing.T) {
	ctx := context.Background()
	// Only a REVOKED version left: still refused.
	v, prov := newVault(t, allowAllPolicy)
	set(t, v, "n", "s", "v")
	if err := v.RevokeSecret(ctx, "n", "s", SystemAgent); err != nil {
		t.Fatal(err)
	}
	db := v.store.Path()
	_ = v.Close()
	_ = os.Remove(filepath.Join(filepath.Dir(db), "keychain.json"))
	if _, err := Open(ctx, Config{DBPath: db, Provider: prov, KDFParams: testParams}); !errors.Is(err, ErrKeychainMissing) {
		t.Fatalf("revoked-only vault: %v", err)
	}

	// keychain.json missing but keychain.json.new committed: recovered.
	dir, fprov, fv := newFileVault(t)
	set(t, fv, "n", "s", "v")
	fv.testBeforeSwap = func() error { return errors.New("crash") }
	_ = fv.RotateDEK(ctx)
	_ = fv.Close()
	_ = os.Remove(filepath.Join(dir, "keychain.json"))
	fv = openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: fprov, PolicyYAML: allowAllPolicy})
	if got, err := get(t, fv, "n", "s", 0); err != nil || got != "v" {
		t.Fatalf("recovery with keychain.json missing: %q %v", got, err)
	}
}

// Paths with characters that are special in SQLite URIs still rotate.
func TestRotateWithSpecialPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "env#1 %41 x")
	v := openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy})
	set(t, v, "n", "s", "v")
	if err := v.RotateDEK(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := get(t, v, "n", "s", 0); err != nil || got != "v" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.db")); err != nil {
		t.Fatal(err)
	}
}

func TestPyB64DecodePadding(t *testing.T) {
	for in, want := range map[string]string{"AA==": "\x00", "AA===": "\x00", "AA==AAAA": "\x00", "QUJD": "ABC", "QU\nJD\n": "ABC"} {
		got, err := pyB64Decode([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

// Round 2: a stale keychain.json.new from a RotateDEK that crashed before
// its commit must never be installed, even when keychain.json is damaged.
func TestStaleDEKPendingNeverInstalled(t *testing.T) {
	dir, prov, v := newFileVault(t)
	setMany(t, v, 20)
	_ = v.Close()
	runCrash(t, dir, "rewrite", 5)
	if _, err := os.Stat(filepath.Join(dir, "keychain.json.new")); err != nil {
		t.Fatalf("expected the crashed rotation's .new: %v", err)
	}
	// Damage keychain.json so it no longer unwraps (wrong tag).
	kc := filepath.Join(dir, "keychain.json")
	b, _ := os.ReadFile(kc)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	w := []byte(doc["wrapped_dek"].(string))
	if w[0] == 'A' {
		w[0] = 'B'
	} else {
		w[0] = 'A'
	}
	doc["wrapped_dek"] = string(w)
	nb, _ := json.Marshal(doc)
	if err := os.WriteFile(kc, nb, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, KDFParams: testParams})
	if !errors.Is(err, keychain.ErrUnwrapFailed) {
		t.Fatalf("want the original unwrap error, got %v", err)
	}
	if b2, _ := os.ReadFile(kc); string(b2) != string(nb) {
		t.Fatal("the stale .new was installed over keychain.json")
	}
	st, _ := store.Open(context.Background(), filepath.Join(dir, "vault.db"))
	defer func() { _ = st.Close() }()
	if e, _ := st.KeyEpoch(context.Background()); e != 1 {
		t.Fatalf("epoch bumped to %d", e)
	}
}

func TestRotateMasterProviderFailureInsideTx(t *testing.T) {
	ctx := context.Background()
	v, prov := newVault(t, allowAllPolicy)
	set(t, v, "n", "s", "v")
	prov.RotateErr = errors.New("keyring locked")
	if err := v.RotateMaster(ctx); err == nil || errors.Is(err, ErrInconsistent) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(v.KeychainPath() + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".new left behind")
	}
	if got, err := get(t, v, "n", "s", 0); err != nil || got != "v" || v.KeyEpoch() != 1 {
		t.Fatalf("vault unusable after a clean provider failure: %q %v", got, err)
	}
}

// The approval gate runs unlocked; a write flagging 2FA while the request
// waits is honoured before decryption.
func TestRequire2FAChangedDuringApproval(t *testing.T) {
	var v *Vault
	gate := gateFunc(func(ctx context.Context, r approval.Request) approval.Decision {
		if !r.Require2FA {
			_ = v.SetSecret(ctx, SetSecretRequest{Name: r.SecretName, Namespace: r.Namespace, Agent: SystemAgent,
				Value: []byte("now-2fa"), Require2FA: true})
		}
		return approval.Decision{Allowed: true}
	})
	v = openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy, Approval: gate})
	set(t, v, "n", "s", "plain")
	_, err := get(t, v, "n", "s", 0)
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "flag changed during approval") {
		t.Fatalf("got %v", err)
	}
	if r := lastAudit(t, v, 1)[0]; r.Action != "APPROVAL_DENIED" {
		t.Fatalf("last row %s", r.Action)
	}
}

// A rotate hook that writes a secret over the threshold must not deadlock.
type writingRotateHook struct{ v *Vault }

func (h *writingRotateHook) ID() string   { return "w" }
func (h *writingRotateHook) Frozen() bool { return false }
func (h *writingRotateHook) Consult(ctx context.Context, r HookRequest) (HookResponse, error) {
	if r.Operation == OpRotate && h.v != nil {
		_ = h.v.SetSecret(ctx, SetSecretRequest{Name: "from-hook", Namespace: "n", Agent: SystemAgent, Value: []byte("x")})
	}
	return HookResponse{Decision: HookAllow}, nil
}

func TestRotateHookWritingDoesNotDeadlock(t *testing.T) {
	h := &writingRotateHook{}
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy, Hook: h})
	h.v = v
	v.dekMaxEncryptions = 1
	done := make(chan error, 1)
	go func() {
		done <- v.SetSecret(context.Background(), SetSecretRequest{Name: "s", Namespace: "n", Agent: SystemAgent, Value: []byte("v")})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: rotate hook wrote a secret during auto-rotation")
	}
	if v.KeyEpoch() != 2 {
		t.Fatalf("epoch %d", v.KeyEpoch())
	}
}

func TestClosedVaultDoesNotConsultHook(t *testing.T) {
	h := &testHook{id: "t", resp: HookResponse{Decision: HookAllow}}
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy, Hook: h})
	_ = v.Close()
	_ = v.SetSecret(context.Background(), SetSecretRequest{Name: "s", Namespace: "n", Agent: SystemAgent, Value: []byte("v")})
	if len(h.reqs) != 0 {
		t.Fatal("hook consulted on a closed vault")
	}
}

func TestPyJSONNumberValidation(t *testing.T) {
	if got := pyDumps([]any{json.Number("-1.5e+3"), json.Number("+1"), json.Number("1_000"), json.Number("")}); got != `[-1.5e+3, "+1", "1_000", ""]` {
		t.Fatal(got)
	}
}
