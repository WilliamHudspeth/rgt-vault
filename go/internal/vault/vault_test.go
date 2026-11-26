package vault

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/store"
)

const offHookAllow = `{"hook_id": "off", "decision": "allow", "reason": "hook disabled"}`

type wantRow struct {
	action, name, details string
	nullName              bool
}

func checkRows(t *testing.T, got []store.AuditRow, want []wantRow) {
	t.Helper()
	if len(got) != len(want) {
		for _, r := range got {
			t.Logf("row %s %q %q", r.Action, r.SecretName.String, r.Details.String)
		}
		t.Fatalf("got %d rows, want %d", len(got), len(want))
	}
	for i, w := range want {
		r := got[i]
		if r.Action != w.action {
			t.Errorf("row %d action %q, want %q", i, r.Action, w.action)
		}
		if w.nullName {
			if r.SecretName.Valid {
				t.Errorf("row %d (%s) secret_name %q, want NULL", i, w.action, r.SecretName.String)
			}
		} else if r.SecretName.String != w.name || !r.SecretName.Valid {
			t.Errorf("row %d (%s) secret_name %q, want %q", i, w.action, r.SecretName.String, w.name)
		}
		if w.details != "*" && r.Details.String != w.details {
			t.Errorf("row %d (%s) details\n got %q\nwant %q", i, w.action, r.Details.String, w.details)
		}
	}
}

type testHook struct {
	id     string
	frozen bool
	resp   HookResponse
	err    error
	panicV any

	mu   sync.Mutex
	reqs []HookRequest
}

func (h *testHook) ID() string   { return h.id }
func (h *testHook) Frozen() bool { return h.frozen }
func (h *testHook) Consult(_ context.Context, r HookRequest) (HookResponse, error) {
	h.mu.Lock()
	h.reqs = append(h.reqs, r)
	h.mu.Unlock()
	if h.panicV != nil {
		panic(h.panicV)
	}
	return h.resp, h.err
}

type testGate struct {
	dec  approval.Decision
	mu   sync.Mutex
	reqs []approval.Request
}

func (g *testGate) Consult(_ context.Context, r approval.Request) approval.Decision {
	g.mu.Lock()
	g.reqs = append(g.reqs, r)
	g.mu.Unlock()
	return g.dec
}

func TestFreshVaultBootstrapAndReopen(t *testing.T) {
	ctx := context.Background()
	prov := memProv()
	db := filepath.Join(t.TempDir(), "nested", "vault.db")
	v := openT(t, Config{DBPath: db, Provider: prov, PolicyYAML: allowAllPolicy})
	if prov.Bootstraps != 1 {
		t.Fatalf("bootstrap calls = %d, want 1", prov.Bootstraps)
	}
	if v.KeyEpoch() != 1 || v.VaultID() == "" || v.KeychainPath() != filepath.Join(filepath.Dir(db), "keychain.json") {
		t.Fatalf("epoch %d id %q path %q", v.KeyEpoch(), v.VaultID(), v.KeychainPath())
	}
	if st, err := os.Stat(v.KeychainPath()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("keychain mode: %v %v", st, err)
	}
	set(t, v, "default", "a", "alpha")
	id := v.VaultID()
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	v2 := openT(t, Config{DBPath: db, Provider: prov, PolicyYAML: allowAllPolicy})
	if prov.Bootstraps != 1 {
		t.Fatalf("bootstrap must not run for an existing keychain (calls = %d)", prov.Bootstraps)
	}
	if v2.VaultID() != id {
		t.Fatal("vault id changed")
	}
	if got, err := get(t, v2, "default", "a", 0); err != nil || got != "alpha" {
		t.Fatalf("after reopen: %q %v", got, err)
	}
	if v2.Policy() == nil || v2.HookID() != "off" || v2.Store() == nil || v2.RateLimiter() == nil || v2.AuthFailureLimiter() == nil {
		t.Fatal("accessors")
	}
	_ = ctx
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, Config{DBPath: filepath.Join(t.TempDir(), "vault.db")}); err == nil {
		t.Fatal("no provider accepted")
	}
	if _, err := Open(ctx, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: "rules: [unclosed"}); err == nil {
		t.Fatal("bad policy accepted")
	}
	if _, err := Open(ctx, Config{DBPath: filepath.Join(t.TempDir(), "x?y.db"), Provider: memProv()}); err == nil {
		t.Fatal("bad db path accepted")
	}
	failing := memProv()
	failing.GetErr = errors.New("provider down")
	if _, err := Open(ctx, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: failing, KDFParams: testParams}); err == nil || !strings.Contains(err.Error(), "provider down") {
		t.Fatalf("provider error not surfaced: %v", err)
	}

	// keychain.json missing although the vault holds secrets: refuse.
	v, prov := newVault(t, allowAllPolicy)
	set(t, v, "default", "a", "alpha")
	db := v.store.Path()
	_ = v.Close()
	if err := os.Remove(filepath.Join(filepath.Dir(db), "keychain.json")); err != nil {
		t.Fatal(err)
	}
	_, err := Open(ctx, Config{DBPath: db, Provider: prov, KDFParams: testParams})
	if !errors.Is(err, ErrKeychainMissing) {
		t.Fatalf("want ErrKeychainMissing, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(db), "keychain.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a new keychain was written over a non-empty vault")
	}
}

func TestSetLeaseAuditTrailAndWipe(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	if err := v.SetSecret(ctx, SetSecretRequest{
		Name: "db", Namespace: "prod", Agent: "deployer", Purpose: "seed", Value: []byte("s3cret"),
		Note: "Ünïcöde nöte", Require2FA: true,
	}); err != nil {
		t.Fatal(err)
	}
	var held []byte
	err := v.Lease(ctx, LeaseRequest{Name: "db", Namespace: "prod", Agent: "ci-bot", Purpose: "deploy"}, func(b []byte) error {
		if string(b) != "s3cret" {
			t.Errorf("plaintext %q", b)
		}
		held = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range held {
		if c != 0 {
			t.Fatal("lease buffer was not wiped after the callback")
		}
	}
	checkRows(t, auditRows(t, v), []wantRow{
		{action: "HOOK_WRITE", name: "db", details: offHookAllow},
		{action: "SET_SECRET", name: "db", details: "*"},
		{action: "HOOK_READ", name: "db", details: offHookAllow},
		{action: "GET_SECRET", name: "db", details: "*"},
		{action: "LEASE_GRANTED", name: "db", details: "Agent: ci-bot"},
		{action: "LEASE_RETURNED", name: "db", details: "Agent: ci-bot"},
	})
	for _, r := range auditRows(t, v) {
		if r.PolicyHash.String != v.PolicyHash() || v.PolicyHash() == "" {
			t.Fatalf("row %s policy_hash %q, want %q", r.Action, r.PolicyHash.String, v.PolicyHash())
		}
	}
	list, err := v.ListSecrets(ctx, ListRequest{Namespace: "prod", Agent: "ci-bot"})
	if err != nil || len(list) != 1 || list[0].Note != "Ünïcöde nöte" || !list[0].Require2FA || list[0].LatestVersion != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	count, nbytes, err := v.store.DEKUsage(ctx)
	if err != nil || count != 1 || nbytes != 6 {
		t.Fatalf("DEK usage = %d/%d %v", count, nbytes, err)
	}
	mustVerify(t, v)

	// The callback's error is returned and the lease is still closed.
	boom := errors.New("callback failed")
	if err := v.Lease(ctx, LeaseRequest{Name: "db", Namespace: "prod", Agent: "ci-bot", Purpose: "deploy"},
		func([]byte) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("callback error = %v", err)
	}
	if r := lastAudit(t, v, 1)[0]; r.Action != "LEASE_RETURNED" {
		t.Fatalf("last row %s", r.Action)
	}
	// A panicking callback still wipes and returns the lease.
	func() {
		defer func() { _ = recover() }()
		_ = v.Lease(ctx, LeaseRequest{Name: "db", Namespace: "prod", Agent: "ci-bot", Purpose: "deploy"},
			func(b []byte) error { held = b; panic("boom") })
	}()
	if held[0] != 0 || lastAudit(t, v, 1)[0].Action != "LEASE_RETURNED" {
		t.Fatal("panicking callback: buffer not wiped or lease not returned")
	}
}

func TestPolicyDenials(t *testing.T) {
	ctx := context.Background()
	pol := `rules:
  - {effect: allow, agent: "*", action: "*"}
  - {effect: deny, agent: intruder}
`
	v, _ := newVault(t, pol)
	set(t, v, "prod", "db", "x")
	n := len(auditRows(t, v))

	err := v.SetSecret(ctx, SetSecretRequest{Name: "db", Namespace: "prod", Agent: "intruder", Purpose: "p", Value: []byte("y")})
	if !errors.Is(err, ErrPolicyDenied) || err.Error() != "Agent 'intruder' denied write access to 'db' (prod/p)" {
		t.Fatalf("write: %v", err)
	}
	err = v.Lease(ctx, LeaseRequest{Name: "db", Namespace: "prod", Agent: "intruder", Purpose: "p"}, func([]byte) error { return nil })
	if !errors.Is(err, ErrPolicyDenied) || err.Error() != "Agent 'intruder' denied read access to 'db' (prod/p)" {
		t.Fatalf("read: %v", err)
	}
	_, err = v.ListSecrets(ctx, ListRequest{Namespace: "prod", Agent: "intruder"})
	if !errors.Is(err, ErrPolicyDenied) || err.Error() != "Unauthorized to access namespace 'prod'" {
		t.Fatalf("list: %v", err)
	}
	err = v.RevokeSecret(ctx, "prod", "db", "intruder")
	if !errors.Is(err, ErrPolicyDenied) || err.Error() != "Unauthorized to revoke secret." {
		t.Fatalf("revoke: %v", err)
	}
	reason := "Explicit deny rule matched"
	checkRows(t, auditRows(t, v)[n:], []wantRow{
		{action: "HOOK_WRITE", name: "db", details: offHookAllow},
		{action: "POLICY_DENIED", name: "db", details: "Action: write, Agent: intruder, Namespace: prod, Reason: " + reason},
		{action: "HOOK_READ", name: "db", details: offHookAllow},
		{action: "POLICY_DENIED", name: "db", details: "Action: read, Agent: intruder, Namespace: prod, Reason: " + reason},
		{action: "HOOK_LIST", nullName: true, details: offHookAllow},
		{action: "POLICY_DENIED", nullName: true, details: "Action: list, Agent: intruder, Namespace: prod, Reason: " + reason},
		{action: "HOOK_REVOKE", name: "db", details: offHookAllow},
		{action: "POLICY_DENIED", name: "db", details: "Action: revoke, Agent: intruder, Namespace: prod, Reason: " + reason},
	})

	// Empty policy: default deny, and an empty policy_hash in the chain.
	empty, _ := newVault(t, "")
	err = empty.SetSecret(ctx, SetSecretRequest{Name: "a", Namespace: "n", Agent: SystemAgent, Value: []byte("v")})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("empty policy write: %v", err)
	}
	r := lastAudit(t, empty, 1)[0]
	if r.Details.String != "Action: write, Agent: system, Namespace: n, Reason: No matching allow rule (default deny)" || r.PolicyHash.String != "" {
		t.Fatalf("default deny row %q / %q", r.Details.String, r.PolicyHash.String)
	}
	mustVerify(t, v)
	mustVerify(t, empty)
}

func TestRateLimitHoneytokenApproval(t *testing.T) {
	ctx := context.Background()
	gate := &testGate{dec: approval.Decision{Allowed: true}}
	v := openT(t, Config{
		DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy,
		RateLimit: 2, Approval: gate,
	})
	set(t, v, "prod", "db", "x")
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "otp", Namespace: "prod", Agent: SystemAgent, Value: []byte("y"), Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	lease := func(agent, name string) error {
		return v.Lease(ctx, LeaseRequest{Name: name, Namespace: "prod", Agent: agent, Purpose: "p"}, func([]byte) error { return nil })
	}
	if err := lease("a", "db"); err != nil {
		t.Fatal(err)
	}
	if err := lease("a", "otp"); err != nil {
		t.Fatal(err)
	}
	if len(gate.reqs) != 2 || gate.reqs[0].Require2FA || !gate.reqs[1].Require2FA || gate.reqs[1].Action != "read" ||
		gate.reqs[1].Agent != "a" || gate.reqs[1].SecretName != "otp" || gate.reqs[1].Purpose != "p" {
		t.Fatalf("approval requests %+v", gate.reqs)
	}
	err := lease("a", "db")
	if !errors.Is(err, ErrRateLimited) || !errors.Is(err, ErrPermission) || err.Error() != "Rate limit exceeded for agent 'a'" {
		t.Fatalf("rate limit: %v", err)
	}
	checkRows(t, lastAudit(t, v, 2), []wantRow{
		{action: "HOOK_READ", name: "db", details: offHookAllow},
		{action: "RATE_LIMITED", name: "db", details: "Agent: a"},
	})

	// Approval denied: nothing is read.
	gate.dec = approval.Decision{Allowed: false, Reason: "operator said no"}
	err = lease("b", "db")
	if !errors.Is(err, ErrPolicyDenied) || err.Error() != "Agent 'b' approval denied for 'db' (prod/p): operator said no" {
		t.Fatalf("approval: %v", err)
	}
	checkRows(t, lastAudit(t, v, 2), []wantRow{
		{action: "HOOK_READ", name: "db", details: offHookAllow},
		{action: "APPROVAL_DENIED", name: "db", details: "Agent: b, Namespace: prod, Reason: operator said no"},
	})

	// Honeytoken: lease and fingerprint both trigger, before the policy.
	if err := v.store.AddHoneytoken(ctx, "prod", "AWS_ROOT_KEY"); err != nil {
		t.Fatal(err)
	}
	err = lease("c", "AWS_ROOT_KEY")
	if !errors.Is(err, ErrHoneytoken) || err.Error() != "Honeytoken access detected: prod/AWS_ROOT_KEY" {
		t.Fatalf("honeytoken lease: %v", err)
	}
	if _, err := v.Fingerprint(ctx, "prod", "AWS_ROOT_KEY", 0); !errors.Is(err, ErrHoneytoken) {
		t.Fatalf("honeytoken fingerprint: %v", err)
	}
	checkRows(t, lastAudit(t, v, 3), []wantRow{
		{action: "HOOK_READ", name: "AWS_ROOT_KEY", details: offHookAllow},
		{action: "HONEYTOKEN_TRIGGERED", name: "AWS_ROOT_KEY",
			details: `{"severity": "critical", "agent": "c", "namespace": "prod", "purpose": "p"}`},
		{action: "HONEYTOKEN_TRIGGERED", name: "AWS_ROOT_KEY",
			details: `{"severity": "critical", "agent": "system", "namespace": "prod", "purpose": "fingerprint"}`},
	})
	mustVerify(t, v)
}

func TestHookDecisions(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		hook    *testHook
		details string
		errMsg  string
	}{
		{"deny", &testHook{id: "test", resp: HookResponse{Decision: HookDeny, Reason: "nope"}},
			`{"hook_id": "test", "decision": "deny", "reason": "nope"}`,
			"hook 'test' denied write for agent 'system': nope"},
		{"deny-no-reason", &testHook{id: "test", resp: HookResponse{Decision: HookDeny}},
			`{"hook_id": "test", "decision": "deny", "reason": ""}`,
			"hook 'test' denied write for agent 'system': no reason given"},
		{"frozen", &testHook{id: "fz", frozen: true, resp: HookResponse{Decision: HookAllow}},
			`{"hook_id": "fz", "decision": "freeze", "reason": "vault frozen by hook"}`,
			"hook 'fz' denied write for agent 'system': vault frozen by hook"},
		{"error", &testHook{id: "e", err: errors.New("boom")},
			`{"hook_id": "e", "decision": "deny", "reason": "hook raised error: boom"}`,
			"hook 'e' denied write for agent 'system': hook raised error: boom"},
		{"panic", &testHook{id: "p", panicV: "kaboom"},
			`{"hook_id": "p", "decision": "deny", "reason": "hook raised panic: kaboom"}`,
			"hook 'p' denied write for agent 'system': hook raised panic: kaboom"},
		{"unknown", &testHook{id: "u", resp: HookResponse{Decision: "maybe"}},
			`{"hook_id": "u", "decision": "deny", "reason": "hook returned unknown decision \"maybe\""}`,
			`hook 'u' denied write for agent 'system': hook returned unknown decision "maybe"`},
		{"allow-extra", &testHook{id: "x", resp: HookResponse{Decision: HookAllow, Reason: "ok",
			Extra: map[string]any{"z": 1, "a": "é", "capability_token": "SECRET"}}},
			`{"hook_id": "x", "decision": "allow", "reason": "ok", "extra": "{\"a\": \"\\u00e9\", \"z\": 1}"}`, ""},
		{"allow-only-token-extra", &testHook{id: "x", resp: HookResponse{Decision: HookAllow, Reason: "ok",
			Extra: map[string]any{"capability_token": "SECRET"}}},
			`{"hook_id": "x", "decision": "allow", "reason": "ok"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(),
				PolicyYAML: allowAllPolicy, Hook: c.hook})
			err := v.SetSecret(ctx, SetSecretRequest{Name: "s", Namespace: "n", Agent: SystemAgent, Purpose: "pp", Value: []byte("v")})
			if c.errMsg == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrPolicyDenied) || err.Error() != c.errMsg {
				t.Fatalf("err = %v, want %q", err, c.errMsg)
			}
			rows := auditRows(t, v)
			if rows[0].Action != "HOOK_WRITE" || rows[0].Details.String != c.details {
				t.Fatalf("hook row %s %q\nwant %q", rows[0].Action, rows[0].Details.String, c.details)
			}
			if !c.hook.frozen && c.hook.panicV == nil {
				r := c.hook.reqs[0]
				if r.Operation != OpWrite || r.Agent != SystemAgent || r.Namespace != "n" || r.Purpose != "pp" ||
					r.SecretName == nil || *r.SecretName != "s" || len(r.RequestID) != 36 || r.IsCapability() {
					t.Fatalf("hook request %+v", r)
				}
			}
			if strings.Contains(rows[0].Details.String, "SECRET") {
				t.Fatal("capability_token leaked into the audit chain")
			}
		})
	}

	// Every operation consults the hook with Python's operation names.
	h := &testHook{id: "rec", resp: HookResponse{Decision: HookAllow}}
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: memProv(), PolicyYAML: allowAllPolicy, Hook: h})
	set(t, v, "n", "s", "v")
	_, _ = get(t, v, "n", "s", 0)
	_, _ = v.ListSecrets(ctx, ListRequest{Namespace: "n", Agent: "a"})
	_, _ = v.Simulate(ctx, "a", "n", "", "")
	_ = v.RevokeSecret(ctx, "n", "s", "a")
	_ = v.RotateDEK(ctx)
	_ = v.RotateMaster(ctx)
	var ops []string
	for _, r := range h.reqs {
		ops = append(ops, r.Operation+":"+r.Purpose)
	}
	want := "write::read:test:list::simulate::revoke::rotate:rotate_dek:rotate:rotate_master_key"
	if got := strings.Join(ops, ":"); got != want {
		t.Fatalf("ops %s\nwant %s", got, want)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	ok := SetSecretRequest{Name: "n", Namespace: "ns", Agent: "a", Value: []byte("v")}
	mod := func(f func(*SetSecretRequest)) SetSecretRequest { r := ok; f(&r); return r }
	bad := map[string]SetSecretRequest{
		"'name' cannot be empty or just whitespace.":                        mod(func(r *SetSecretRequest) { r.Name = "  " }),
		"'namespace' cannot be empty or just whitespace.":                   mod(func(r *SetSecretRequest) { r.Namespace = "" }),
		"'agent' cannot be empty or just whitespace.":                       mod(func(r *SetSecretRequest) { r.Agent = "" }),
		"'name' exceeds the maximum allowed length of 256 characters.":      mod(func(r *SetSecretRequest) { r.Name = strings.Repeat("a", 257) }),
		"'namespace' exceeds the maximum allowed length of 128 characters.": mod(func(r *SetSecretRequest) { r.Namespace = strings.Repeat("a", 129) }),
		"'note' exceeds the maximum allowed length of 512 characters.":      mod(func(r *SetSecretRequest) { r.Note = strings.Repeat("a", 513) }),
		"'value' cannot be empty or whitespace.":                            mod(func(r *SetSecretRequest) { r.Value = []byte(" \t\n") }),
		"'value' exceeds 1048576 bytes.":                                    mod(func(r *SetSecretRequest) { r.Value = make([]byte, MaxValueBytes+1); r.Value[0] = 'x' }),
		"'name' must be valid UTF-8.":                                       mod(func(r *SetSecretRequest) { r.Name = "a\xffb" }),
		"trailing newline (deliberate deviation: Python accepts it)":        mod(func(r *SetSecretRequest) { r.Name = "abc\n" }),
		"namespace with slash":                                              mod(func(r *SetSecretRequest) { r.Namespace = "prod/app" }),
		"agent with space":                                                  mod(func(r *SetSecretRequest) { r.Agent = "bad agent" }),
		"purpose with control char":                                         mod(func(r *SetSecretRequest) { r.Purpose = "a\x00b" }),
	}
	for name, req := range bad {
		err := v.SetSecret(ctx, req)
		if !errors.Is(err, ErrValidation) {
			t.Errorf("%s: want validation error, got %v", name, err)
			continue
		}
		if strings.HasPrefix(name, "'") && err.Error() != name {
			t.Errorf("message %q, want %q", err.Error(), name)
		}
	}
	if len(auditRows(t, v)) != 0 {
		t.Fatal("rejected input must not reach the hook or the audit chain")
	}
	// The exact-limit value is accepted.
	big := make([]byte, MaxValueBytes)
	for i := range big {
		big[i] = 'b'
	}
	if err := v.SetSecret(ctx, mod(func(r *SetSecretRequest) { r.Value = big })); err != nil {
		t.Fatalf("1 MiB value: %v", err)
	}

	if err := v.Lease(ctx, LeaseRequest{Name: "n", Namespace: "ns", Agent: "a", Purpose: "p"}, nil); !errors.Is(err, ErrValidation) ||
		err.Error() != "The provided callback must be a callable object." {
		t.Fatalf("nil callback: %v", err)
	}
	if err := v.Lease(ctx, LeaseRequest{Name: "n", Namespace: "ns", Agent: "a"}, func([]byte) error { return nil }); !errors.Is(err, ErrValidation) {
		t.Fatalf("lease without purpose: %v", err)
	}
	if _, err := v.ListSecrets(ctx, ListRequest{Namespace: "ns", Agent: "a", Offset: -1}); !errors.Is(err, ErrValidation) {
		t.Fatalf("negative offset: %v", err)
	}
	if _, err := v.Fingerprint(ctx, "ns", "", 0); !errors.Is(err, ErrValidation) {
		t.Fatalf("fingerprint: %v", err)
	}
	if err := v.RevokeSecret(ctx, "ns", "n", ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := v.Simulate(ctx, "", "ns", "", ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("simulate: %v", err)
	}
	if _, err := v.Explain(ctx, "a", "ns/x", "", ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("explain: %v", err)
	}
}

func TestNotFoundRevokeListFingerprint(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	if _, err := get(t, v, "ns", "missing", 0); !errors.Is(err, ErrNotFound) || !errors.Is(err, store.ErrNotFound) ||
		err.Error() != "Secret 'ns/missing' not found." {
		t.Fatalf("missing: %v", err)
	}
	set(t, v, "ns", "a", "one")
	set(t, v, "ns", "a", "two")
	set(t, v, "ns", "b", "bee")
	if err := v.RevokeSecret(ctx, "ns", "b", SystemAgent); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, v, "ns", "b", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked latest: %v", err)
	}
	if got, err := get(t, v, "ns", "b", 1); err != nil || got != "bee" {
		t.Fatalf("revoked by version: %q %v", got, err)
	}
	if got, err := get(t, v, "ns", "a", 1); err != nil || got != "one" {
		t.Fatalf("superseded by version: %q %v", got, err)
	}
	if _, err := get(t, v, "ns", "a", 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	list, err := v.ListSecrets(ctx, ListRequest{Namespace: "ns", Agent: "a", Purpose: "audit"})
	if err != nil || len(list) != 1 || list[0].Name != "a" || list[0].LatestVersion != 2 {
		t.Fatalf("list %+v %v", list, err)
	}
	if list, err := v.ListSecrets(ctx, ListRequest{Namespace: "ns", Agent: "a", Limit: 1, Offset: 1}); err != nil || len(list) != 0 {
		t.Fatalf("offset list %+v %v", list, err)
	}
	fp1, err := v.Fingerprint(ctx, "ns", "a", 1)
	if err != nil || len(fp1) != 8 {
		t.Fatal(fp1, err)
	}
	fp2, _ := v.Fingerprint(ctx, "ns", "a", 0)
	if fp1 == fp2 {
		t.Fatal("versions share a fingerprint")
	}
	if _, err := v.Fingerprint(ctx, "ns", "nope", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fingerprint missing: %v", err)
	}
	mustVerify(t, v)
}

func TestSimulateExplainAuditAPI(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	d, err := v.Simulate(ctx, "intruder", "prod", "", "")
	if err != nil || d.Allowed || d.Reason != "Explicit deny rule matched" {
		t.Fatalf("simulate %+v %v", d, err)
	}
	text, err := v.Explain(ctx, "ci-bot", "prod", "deploy", "write")
	want := "Access: ALLOWED\nReason: Allow rule matched\nMatched Rule: " +
		`{"effect": "allow", "agent": "*", "namespace": "*", "purpose": "*", "action": "*"}`
	if err != nil || text != want {
		t.Fatalf("explain %q %v", text, err)
	}
	checkRows(t, auditRows(t, v), []wantRow{
		{action: "HOOK_SIMULATE", nullName: true, details: offHookAllow},
		{action: "SIMULATION_RUN", nullName: true, details: "Agent: intruder, Namespace: prod, Action: read"},
		{action: "HOOK_SIMULATE", nullName: true, details: offHookAllow},
		{action: "SIMULATION_RUN", nullName: true, details: "Agent: ci-bot, Namespace: prod, Action: write"},
	})
	if err := v.Audit(ctx, "CUSTOM", store.Name("x"), "d", store.Name("agent-1")); err != nil {
		t.Fatal(err)
	}
	if err := v.Audit(ctx, "CUSTOM2", sql.NullString{}, "d2", sql.NullString{}); err != nil {
		t.Fatal(err)
	}
	rows, err := v.AuditLog(ctx, 2)
	if err != nil || len(rows) != 2 || rows[0].Action != "CUSTOM2" || rows[1].AgentID.String != "agent-1" {
		t.Fatalf("audit log %+v %v", rows, err)
	}
	mustVerify(t, v)
}

func TestClosedVault(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	set(t, v, "n", "s", "v")
	_ = v.Close()
	checks := map[string]error{
		"set":         v.SetSecret(ctx, SetSecretRequest{Name: "s", Namespace: "n", Agent: "a", Value: []byte("v")}),
		"lease":       v.Lease(ctx, LeaseRequest{Name: "s", Namespace: "n", Agent: "a", Purpose: "p"}, func([]byte) error { return nil }),
		"revoke":      v.RevokeSecret(ctx, "n", "s", "a"),
		"rotate-dek":  v.RotateDEK(ctx),
		"rotate-mstr": v.RotateMaster(ctx),
		"import":      v.Import(ctx, []byte("e30=")),
		"audit":       v.Audit(ctx, "X", sql.NullString{}, "", sql.NullString{}),
	}
	_, checks["list"] = v.ListSecrets(ctx, ListRequest{Namespace: "n", Agent: "a"})
	_, checks["fingerprint"] = v.Fingerprint(ctx, "n", "s", 0)
	_, checks["simulate"] = v.Simulate(ctx, "a", "n", "", "")
	_, checks["export"] = v.Export(ctx)
	_, checks["verify"] = v.VerifyAuditChain(ctx)
	_, checks["auditlog"] = v.AuditLog(ctx, 1)
	for op, err := range checks {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s after Close: %v", op, err)
		}
	}
}

func TestUnsupportedDEKVersionRow(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	if _, err := v.store.SetSecret(ctx, store.SetSecretParams{Namespace: "n", Name: "future", Ciphertext: []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), DEKVersion: 2}); err != nil {
		t.Fatal(err)
	}
	_, err := get(t, v, "n", "future", 0)
	if !errors.Is(err, ErrUnsupportedDEKVersion) || !errors.Is(err, ErrValidation) || err.Error() != "Unsupported DEK version 2" {
		t.Fatalf("got %v", err)
	}
	// An ACTIVE row the rotation cannot read aborts it; nothing changes.
	epoch := v.KeyEpoch()
	if err := v.RotateDEK(ctx); err == nil || !strings.Contains(err.Error(), "unsupported dek_version 2") {
		t.Fatalf("rotate: %v", err)
	}
	if v.KeyEpoch() != epoch {
		t.Fatal("epoch changed by a failed rotation")
	}
}

func TestProviderSeams(t *testing.T) {
	// The vault interfaces are satisfied structurally by the providers.
	var _ MasterProvider = providerstest.File{}
	var _ Rotator = providerstest.File{}
	var _ MasterProvider = providerstest.Fixed{}
	var _ Bootstrapper = providerstest.NewMemory()
	var _ Rotator = providerstest.NewMemory()
	if _, ok := any(providerstest.Fixed{}).(Rotator); ok {
		t.Fatal("Fixed must not rotate")
	}
}
