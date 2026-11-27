package hooks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rgt-vault-server/internal/validation"
	"rgt-vault-server/internal/vault"
)

// Every hook type must satisfy Hook.
var (
	_ Hook = (*OffHook)(nil)
	_ Hook = (*LogHook)(nil)
	_ Hook = (*TwoFactorHook)(nil)
	_ Hook = (*WebhookHook)(nil)
	_ Hook = (*LogRedactionHook)(nil)
)

func TestOffAndLogHooks(t *testing.T) {
	ctx := context.Background()
	off := NewOffHook()
	if r, _ := off.Consult(ctx, vault.HookRequest{}); r.Decision != vault.HookAllow || r.Reason != "hook disabled" || off.ID() != "off" {
		t.Fatalf("off: %+v", r)
	}
	lh := NewLogHook()
	name := "db"
	r, _ := lh.Consult(ctx, vault.HookRequest{Operation: "read", Agent: "a", Namespace: "n", Purpose: "p", SecretName: &name, RequestID: "r1", CapabilityToken: "TOKEN"})
	if r.Reason != "log mode: not enforced" || lh.ID() != "log" {
		t.Fatalf("log: %+v", r)
	}
	name = "changed"
	c := lh.Consultations()
	if len(c) != 1 || *c[0].SecretName != "db" || c[0].RequestID != "r1" || c[0].TS.IsZero() {
		t.Fatalf("consultations = %+v", c)
	}
	lh.maxN = 3
	for i := 0; i < 5; i++ {
		_, _ = lh.Consult(ctx, vault.HookRequest{Operation: "list", RequestID: string(rune('a' + i))})
	}
	c = lh.Consultations()
	if len(c) != 3 || c[2].RequestID != "e" || c[0].RequestID != "c" {
		t.Fatalf("bounded consultations = %+v", c)
	}
}

func TestFreezeFlagFileAndCallback(t *testing.T) {
	h := NewOffHook()
	var events []string
	h.OnFreezeChange(func(f bool, reason string) {
		if f {
			events = append(events, "freeze:"+reason)
		} else {
			events = append(events, "unfreeze:"+reason)
		}
	})
	if h.Frozen() {
		t.Fatal("frozen at start")
	}
	h.Freeze("admin")
	if !h.Frozen() {
		t.Fatal("not frozen after Freeze")
	}
	h.Unfreeze("admin")
	if h.Frozen() {
		t.Fatal("frozen after Unfreeze")
	}
	ff := filepath.Join(t.TempDir(), "freeze")
	h.SetFreezeFile(ff)
	if h.FreezeFile() != ff || h.Frozen() {
		t.Fatal("absent freeze file must not freeze")
	}
	if err := os.WriteFile(ff, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !h.Frozen() {
		t.Fatal("present freeze file must freeze")
	}
	h.Unfreeze("x")
	if !h.Frozen() {
		t.Fatal("Unfreeze must not override the freeze file")
	}
	_ = os.Remove(ff)
	if h.Frozen() {
		t.Fatal("removing the freeze file must unfreeze")
	}
	if strings.Join(events, ",") != "freeze:admin,unfreeze:admin,unfreeze:x" {
		t.Fatalf("events = %v", events)
	}
}

// TestFrozenHookDeniesThroughVault checks the kill switch end to end on the
// secret path: a freeze file makes every lease fail with "vault frozen by
// hook" and a HOOK_READ freeze row.
func TestFrozenHookDeniesThroughVault(t *testing.T) {
	h := NewOffHook()
	ff := filepath.Join(t.TempDir(), "freeze")
	h.SetFreezeFile(ff)
	v := openVault(t, h, nil, nil)
	ctx := context.Background()
	if err := v.SetSecret(ctx, vault.SetSecretRequest{Name: "db", Namespace: "default", Agent: "system", Value: []byte("pw")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ff, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := v.Lease(ctx, vault.LeaseRequest{Name: "db", Namespace: "default", Agent: "bot", Purpose: "t"}, func([]byte) error { return nil })
	if !errors.Is(err, vault.ErrPolicyDenied) || !strings.Contains(err.Error(), "vault frozen by hook") {
		t.Fatalf("lease while frozen: %v", err)
	}
	rows, _ := v.AuditLog(ctx, 1)
	if rows[0].Action != "HOOK_READ" || !strings.Contains(rows[0].Details.String, `"decision": "freeze"`) {
		t.Fatalf("audit row = %+v", rows[0])
	}
}

func TestFreezeWatcher(t *testing.T) {
	ff := filepath.Join(t.TempDir(), "freeze")
	h := NewOffHook()
	w := FreezeOnFile(h, ff, 5*time.Millisecond)
	w.Start()
	w.Start() // idempotent
	time.Sleep(20 * time.Millisecond)
	if w.IsFrozen() || h.Frozen() {
		t.Fatal("frozen before the file exists")
	}
	if err := os.WriteFile(ff, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not fire")
	}
	if !w.IsFrozen() {
		t.Fatal("watcher not frozen")
	}
	_ = os.Remove(ff)
	if !h.Frozen() {
		t.Fatal("callback must have frozen the hook in memory")
	}
	w.Stop()

	// A panicking callback is swallowed; Stop before Start returns.
	var called atomic.Bool
	w2 := NewFreezeWatcher(ff, 0, func() { called.Store(true); panic("x") })
	if w2.interval != time.Second {
		t.Fatal("default interval")
	}
	_ = os.WriteFile(ff, nil, 0o600)
	w2.Start()
	<-w2.Done()
	if !called.Load() || !w2.IsFrozen() {
		t.Fatal("callback not called")
	}
	w3 := NewFreezeWatcher(filepath.Join(t.TempDir(), "never"), time.Millisecond, nil)
	w3.Stop()
	w4 := NewFreezeWatcher(filepath.Join(t.TempDir(), "never"), time.Millisecond, nil)
	w4.Start()
	w4.Stop()
	w4.Stop()
	w5 := NewFreezeWatcher(ff, time.Millisecond, nil)
	w5.Start()
	<-w5.Done()
}

func TestFromConfig(t *testing.T) {
	env := map[string]string{"HARNESS_KEY": "0123456789abcdef0123456789abcdef"}
	getenv := func(k string) string { return env[k] }
	ff := filepath.Join(t.TempDir(), "freeze")
	for _, c := range []struct {
		cfg    Config
		wantID string
		err    string
	}{
		{Config{}, "off", ""},
		{Config{Mode: "OFF", FreezeFile: ff}, "off", ""},
		{Config{Mode: "log"}, "log", ""},
		{Config{Mode: "webhook", Webhook: &WebhookConfig{URL: "http://127.0.0.1:9/hook", TimeoutSeconds: 1}}, "webhook:http://127.0.0.1:9", ""},
		{Config{Mode: "webhook", Webhook: &WebhookConfig{URL: "https://user:pw@harness.example/h"}}, "webhook:https://harness.example", ""},
		{Config{Mode: "webhook"}, "", "webhook hook requires config['webhook']['url']"},
		{Config{Mode: "webhook", Webhook: &WebhookConfig{URL: "ftp://x"}}, "", "webhook hook url must be an absolute http(s) URL"},
		{Config{Mode: "webhook", Webhook: &WebhookConfig{URL: "http://x", TimeoutSeconds: -1}}, "", "webhook timeout_seconds must be between 0 and 3600"},
		{Config{Mode: "webhook", Webhook: &WebhookConfig{URL: "http://x", TimeoutSeconds: 1e300}}, "", "webhook timeout_seconds must be between 0 and 3600"},
		{Config{Mode: "two_factor", TwoFactor: &TwoFactorConfig{SharedSecretEnv: "HARNESS_KEY"}}, "two_factor", ""},
		{Config{Mode: "two_factor", TwoFactor: &TwoFactorConfig{SharedSecret: "short"}}, "", "shared_secret must be at least 32 bytes of random material."},
		{Config{Mode: "two_factor", TwoFactor: &TwoFactorConfig{SharedSecretEnv: "MISSING"}}, "", "two_factor hook requires a shared_secret (config or env var)."},
		{Config{Mode: "two_factor"}, "", "two_factor hook requires a shared_secret (config or env var)."},
		{Config{Mode: "soar"}, "", "hook mode 'soar' has been removed; SOAR products integrate through 'webhook' mode"},
		{Config{Mode: "magic"}, "", "unknown hook mode 'magic'"},
	} {
		h, err := fromConfig(c.cfg, getenv)
		if c.err != "" {
			if err == nil || err.Error() != c.err || !errors.Is(err, validation.ErrValidation) {
				t.Errorf("%+v: err = %v, want %q", c.cfg, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%+v: %v", c.cfg, err)
			continue
		}
		if h.ID() != c.wantID {
			t.Errorf("%+v: id %q want %q", c.cfg, h.ID(), c.wantID)
		}
		if h.FreezeFile() != c.cfg.FreezeFile {
			t.Errorf("freeze file %q", h.FreezeFile())
		}
	}
	tf, _ := fromConfig(Config{Mode: "two_factor", TwoFactor: &TwoFactorConfig{SharedSecret: string(testKey), MaxTTLSeconds: 10}}, getenv)
	if tf.(*TwoFactorHook).maxTTL != 10 {
		t.Fatal("max ttl not applied")
	}
	if h, err := FromConfig(Config{}); err != nil || h.ID() != "off" {
		t.Fatal(h, err)
	}
}

func TestRedact(t *testing.T) {
	in := map[string]any{
		"api_key":  "abc",
		"Password": "x",
		"user":     "alice",
		"nested":   map[string]any{"refresh_token": "t", "n": 1, "list": []any{"short", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"}},
		"blob":     []byte("raw"),
		"strs":     []string{"0123456789abcdef0123456789abcdef"},
		"hdrs":     map[string]string{"Authorization": "Bearer x", "accept": "json"},
		"html":     "<script>alert(1)</script>",
	}
	out := Redact(in).(map[string]any)
	if out["api_key"] != Redacted || out["Password"] != Redacted || out["user"] != "alice" {
		t.Fatalf("top level: %v", out)
	}
	n := out["nested"].(map[string]any)
	if n["refresh_token"] != Redacted || n["n"] != 1 {
		t.Fatalf("nested: %v", n)
	}
	l := n["list"].([]any)
	if l[0] != "short" || l[1] != Redacted {
		t.Fatalf("list: %v", l)
	}
	if out["blob"] != "<3 bytes redacted>" || out["strs"].([]any)[0] != Redacted {
		t.Fatalf("blob/strs: %v %v", out["blob"], out["strs"])
	}
	if h := out["hdrs"].(map[string]any); h["Authorization"] != Redacted || h["accept"] != "json" {
		t.Fatalf("hdrs: %v", h)
	}
	if out["html"] != "<script>alert(1)</script>" {
		t.Fatalf("html must pass through unchanged (it is not secret-like): %v", out["html"])
	}
	if in["api_key"] != "abc" {
		t.Fatal("Redact mutated its input")
	}
	if IsHighEntropy(strings.Repeat("a", 24)) || !IsHighEntropy(strings.Repeat("a", 25)) || IsHighEntropy(strings.Repeat("a", 30)+" ") {
		t.Fatal("IsHighEntropy boundaries")
	}
	if Redact(42) != 42 {
		t.Fatal("scalar")
	}
}

func TestLogRedactionHook(t *testing.T) {
	var buf bytes.Buffer
	h := NewLogRedactionHook(slog.New(slog.NewTextHandler(&buf, nil)))
	if NewLogRedactionHook(nil).log == nil || h.ID() != "log_redaction" {
		t.Fatal("constructor")
	}
	c := RequestContext{AgentID: "a", CapabilityID: "c", Version: "1", TimestampNS: 5, Nonce: []byte{1}}
	// Python: blake2b(digest_size=32) over b"a" b"c" b"1" b"5" b"\x01".
	if got := c.ContextHash(); got != "c987b212979cdc26d260d8339aadad1717fec924401d08f6af10ed717335ff2f" {
		t.Fatalf("context hash = %s", got)
	}
	secretValue := "s3cr3t-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	resp, err := h.Consult(context.Background(), vault.HookRequest{
		Operation: vault.OpCapability, Agent: "a", Capability: "c", CapabilityVersion: 1,
		Payload: map[string]any{"password": "hunter2", "q": secretValue}, CapabilityToken: "TOKEN-VALUE",
	})
	if err != nil || resp.Decision != vault.HookAllow {
		t.Fatal(resp, err)
	}
	name := "db"
	_, _ = h.Consult(context.Background(), vault.HookRequest{Operation: "read", Agent: "a", SecretName: &name})
	_, _ = h.Consult(context.Background(), vault.HookRequest{Operation: "list", Agent: "a"})
	h.OnCapabilityGrant(c, 30)
	e1, e2 := "token invalid: abc", "plain failure"
	h.OnCapabilityComplete(c, false, &e1)
	h.OnCapabilityComplete(c, false, &e2)
	h.OnCapabilityComplete(c, true, nil)
	out := buf.String()
	for _, leak := range []string{"hunter2", secretValue, "TOKEN-VALUE", "token invalid"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaked %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{"capability_request: agent=a cap=c ver=1", "'password': '[REDACTED]'",
		"secret_access: agent=a secret_id=db op=read", "capability_grant: agent=a cap=c ttl=30",
		"success=False error=[REDACTED]", "error=plain failure", "success=True error=None"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}
