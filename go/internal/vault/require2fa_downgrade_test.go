package vault

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func downgradeVault(t *testing.T) *Vault {
	t.Helper()
	return openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy})
}

func auditActions(t *testing.T, v *Vault) []string {
	t.Helper()
	var out []string
	for _, r := range auditRows(t, v) {
		out = append(out, r.Action)
	}
	return out
}

func countAction(acts []string, a string) int {
	n := 0
	for _, x := range acts {
		if x == a {
			n++
		}
	}
	return n
}

// RGT-348 / RGT-350: a write must not strip the second factor.
func TestRequire2FADowngradeDeniedAndAudited(t *testing.T) {
	ctx := context.Background()
	v := downgradeVault(t)
	mk := func(val string, f bool, allow bool) error {
		return v.SetSecret(ctx, SetSecretRequest{Name: "root", Namespace: "prod", Agent: "mallory",
			Value: []byte(val), Require2FA: f, AllowRequire2FADowngrade: allow})
	}
	if err := mk("v1", true, false); err != nil {
		t.Fatal(err)
	}
	// Dropping the flag (explicitly or by omission) is refused and audited.
	err := mk("v2-evil", false, false)
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "require_2fa") {
		t.Fatalf("downgrade = %v, want a policy denial", err)
	}
	acts := auditActions(t, v)
	if countAction(acts, "REQUIRE_2FA_DOWNGRADE_DENIED") != 1 || countAction(acts, "REQUIRE_2FA_DOWNGRADED") != 0 {
		t.Fatalf("audit actions = %v", acts)
	}
	// The denial row names the agent and never the value.
	last := lastAudit(t, v, 1)[0]
	if last.Action != "REQUIRE_2FA_DOWNGRADE_DENIED" || !strings.Contains(last.Details.String, "mallory") || strings.Contains(last.Details.String, "v2-evil") {
		t.Fatalf("denial row = %+v", last)
	}
	// Nothing was written: the flag is still on, the version unchanged.
	if on, err := v.store.Requires2FA(ctx, "prod", "root"); err != nil || !on {
		t.Fatalf("Requires2FA = %v, %v", on, err)
	}
	if fp, err := v.Fingerprint(ctx, "prod", "root", 2); err == nil {
		t.Fatalf("a second version was written (fp %s)", fp)
	}
	// Keeping the flag is fine for anyone.
	if err := mk("v2", true, false); err != nil {
		t.Fatalf("keeping require_2fa: %v", err)
	}
	// The operator can drop it, and that is audited.
	if err := mk("v3", false, true); err != nil {
		t.Fatalf("operator downgrade: %v", err)
	}
	acts = auditActions(t, v)
	if countAction(acts, "REQUIRE_2FA_DOWNGRADED") != 1 {
		t.Fatalf("audit actions = %v", acts)
	}
	if on, _ := v.store.Requires2FA(ctx, "prod", "root"); on {
		t.Fatal("flag still on after the operator downgrade")
	}
	// Once downgraded, plain writes are allowed again (nothing to protect).
	if err := mk("v4", false, false); err != nil {
		t.Fatalf("write to a non-2FA secret: %v", err)
	}
	mustVerify(t, v)
}

func TestRequire2FADowngradeAfterRevokeStillDenied(t *testing.T) {
	ctx := context.Background()
	v := downgradeVault(t)
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "k", Namespace: "prod", Agent: SystemAgent, Value: []byte("a"), Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	if err := v.RevokeSecret(ctx, "prod", "k", SystemAgent); err != nil {
		t.Fatal(err)
	}
	// Revoking removes the ACTIVE row; re-creating it without 2FA is still a downgrade.
	err := v.SetSecret(ctx, SetSecretRequest{Name: "k", Namespace: "prod", Agent: SystemAgent, Value: []byte("b")})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("recreate after revoke = %v, want denial", err)
	}
	if countAction(auditActions(t, v), "REQUIRE_2FA_DOWNGRADE_DENIED") != 1 {
		t.Fatal("no denial row")
	}
}

func TestNoDowngradeCheckForOrdinarySecrets(t *testing.T) {
	ctx := context.Background()
	v := downgradeVault(t)
	for i := 0; i < 3; i++ {
		if err := v.SetSecret(ctx, SetSecretRequest{Name: "plain", Namespace: "prod", Agent: SystemAgent, Value: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	// Raising the flag is always allowed.
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "plain", Namespace: "prod", Agent: SystemAgent, Value: []byte("x"), Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	acts := auditActions(t, v)
	if countAction(acts, "REQUIRE_2FA_DOWNGRADE_DENIED")+countAction(acts, "REQUIRE_2FA_DOWNGRADED") != 0 {
		t.Fatalf("spurious downgrade rows: %v", acts)
	}
}

func TestGateHelpers(t *testing.T) {
	ctx := context.Background()
	v := downgradeVault(t)
	if on, err := v.Requires2FA(ctx, "prod", "nope"); err != nil || on {
		t.Fatalf("missing secret: %v %v", on, err)
	}
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "k", Namespace: "prod", Agent: SystemAgent, Value: []byte("a"), Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	if on, err := v.Requires2FA(ctx, "prod", "k"); err != nil || !on {
		t.Fatalf("flagged secret: %v %v", on, err)
	}
	before := len(auditRows(t, v))
	if !v.PolicyAllows("anyone", "prod", "p", "write") {
		t.Fatal("allow-all policy refused")
	}
	if len(auditRows(t, v)) != before {
		t.Fatal("PolicyAllows wrote an audit row")
	}
	nopol := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "v.db"), Provider: memProv()})
	if nopol.PolicyAllows("anyone", "prod", "p", "write") {
		t.Fatal("no policy must deny")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if v.PolicyAllows("anyone", "prod", "p", "write") {
		t.Fatal("closed vault allowed")
	}
	if _, err := v.Requires2FA(ctx, "prod", "k"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed vault: %v", err)
	}
}
