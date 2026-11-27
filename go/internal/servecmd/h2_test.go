package servecmd

import (
	"strings"
	"testing"
	"time"

	"rgt-vault-server/internal/approval"
)

// Batch H2 flags: --require-approval-for, --security-webhook-url.

func TestRequireApprovalForParsing(t *testing.T) {
	home := map[string]string{"HOME": t.TempDir()}
	cfg, err := parse(flagsOf(nil), env(home))
	if err != nil || len(cfg.gatedOps) != 0 || cfg.approvalActive() {
		t.Fatalf("default: %+v %v", cfg.gatedOps, err)
	}
	cfg, err = parse(flagsOf(func(f *Flags) { f.RequireApprovalFor = "set, revoke" }), env(home))
	if err != nil || len(cfg.gatedOps) != 2 || cfg.gatedOps[0] != approval.OpRevoke || cfg.gatedOps[1] != approval.OpSet || !cfg.approvalActive() {
		t.Fatalf("flag: %+v %v", cfg.gatedOps, err)
	}
	// The environment is the fallback, the flag wins.
	e := map[string]string{"HOME": home["HOME"], "RGT_VAULT_REQUIRE_APPROVAL_FOR": "all"}
	if cfg, err = parse(flagsOf(nil), env(e)); err != nil || len(cfg.gatedOps) != 3 {
		t.Fatalf("env: %+v %v", cfg.gatedOps, err)
	}
	if cfg, err = parse(flagsOf(func(f *Flags) { f.RequireApprovalFor = "rotate" }), env(e)); err != nil || len(cfg.gatedOps) != 1 {
		t.Fatalf("flag over env: %+v %v", cfg.gatedOps, err)
	}
	// A typo must not silently leave an operation ungated.
	for _, bad := range []string{"sett", "read", "set,delete"} {
		if _, err := parse(flagsOf(func(f *Flags) { f.RequireApprovalFor = bad }), env(home)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestGatedOpsImplyApprovalRules(t *testing.T) {
	home := map[string]string{"HOME": t.TempDir()}
	// A TOTP file now also works with --require-approval-for alone.
	if _, err := parse(flagsOf(func(f *Flags) { f.TOTPSecretFile = "/x"; f.RequireApprovalFor = "set" }), env(home)); err != nil {
		t.Fatalf("totp with gated ops: %v", err)
	}
	if _, err := parse(flagsOf(func(f *Flags) { f.TOTPSecretFile = "/x" }), env(home)); err == nil || !strings.Contains(err.Error(), "--require-approval") {
		t.Fatalf("totp without approval: %v", err)
	}
	// Legacy mode needs a separate operator token for gated operations too:
	// otherwise the agent token could approve its own request.
	_, err := parse(flagsOf(func(f *Flags) { f.LegacySharedToken = true; f.RequireApprovalFor = "set" }), env(home))
	if err == nil || !strings.Contains(err.Error(), "--operator-token-file") {
		t.Fatalf("legacy gated ops without operator token: %v", err)
	}
	// The response write deadline must outlast an approval wait.
	cfg := config{gatedOps: []approval.GatedOp{approval.OpSet}, approvalTimeout: 120 * time.Second}
	if got := writeTimeout(cfg); got != 180*time.Second {
		t.Fatalf("writeTimeout with gated ops = %v", got)
	}
}

func TestSecurityWebhookFlags(t *testing.T) {
	home := map[string]string{"HOME": t.TempDir()}
	cfg, err := parse(flagsOf(func(f *Flags) { f.SecurityWebhookURL = "http://127.0.0.1:9/hook" }), env(home))
	if err != nil || cfg.securityWebhook != "http://127.0.0.1:9/hook" || cfg.securityWebhookRem {
		t.Fatalf("flag: %+v %v", cfg, err)
	}
	e := map[string]string{"HOME": home["HOME"], "RGT_VAULT_SECURITY_WEBHOOK_URL": "http://127.0.0.1:1/x"}
	if cfg, err = parse(flagsOf(nil), env(e)); err != nil || cfg.securityWebhook != "http://127.0.0.1:1/x" {
		t.Fatalf("env: %+v %v", cfg, err)
	}
	if _, err = parse(flagsOf(func(f *Flags) { f.SecurityWebhookAllowRemote = true }), env(home)); err == nil {
		t.Fatal("--security-webhook-allow-remote without a URL accepted")
	}
}

func TestH2FlagsRegistered(t *testing.T) {
	cmd := NewCommand(Env{}, nil)
	for _, name := range []string{"require-approval-for", "security-webhook-url", "security-webhook-allow-remote"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s missing", name)
		}
	}
}

func TestSecurityWebhookFlagIsDeprecated(t *testing.T) {
	cmd := NewCommand(Env{}, nil)
	f := cmd.Flags().Lookup("security-webhook-url")
	if f == nil || f.Deprecated == "" || !strings.Contains(f.Deprecated, "RGT_VAULT_SECURITY_WEBHOOK_URL") || !f.Hidden {
		t.Fatalf("flag = %+v", f)
	}
}
