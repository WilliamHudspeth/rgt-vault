// Package asvs holds test-only ASVS verification suites for the Go line of rgt-vault.
//
// This file covers ASVS V7 (Error Handling and Logging) plus V1.7 logging
// architecture items (RGT-247, 248, 409-411, 413-416, 418-421, 428-432);
// the corresponding matrix is docs/security/asvs/V7.md.
package asvs

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/actions"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/audit"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/logging"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server/handlers"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/store"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

var fastKDF = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

const v7PolicyYAML = `rules:
  - effect: allow
    agent: "agent-ok"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: allow
    agent: "system"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: allow
    agent: "operator"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: deny
    agent: "intruder"
    namespace: "*"
    purpose: "*"
    action: "*"
`

type tokenCarryingHook struct {
	capToken string
}

func (tokenCarryingHook) ID() string   { return "test-hook" }
func (tokenCarryingHook) Frozen() bool { return false }
func (h tokenCarryingHook) Consult(_ context.Context, _ vault.HookRequest) (vault.HookResponse, error) {
	return vault.HookResponse{
		Decision:        vault.HookAllow,
		Reason:          "ok",
		CapabilityToken: h.capToken,
		Extra: map[string]any{
			"capability_token": h.capToken,
			"trace":            "hook-pass",
		},
	}, nil
}

type deny2FAGate struct{}

func (deny2FAGate) Consult(_ context.Context, req approval.Request) approval.Decision {
	if req.Require2FA {
		return approval.Decision{Allowed: false, Reason: "invalid TOTP second factor"}
	}
	return approval.Decision{Allowed: true, Reason: "auto-approved"}
}

type twoFAOnlyGate struct {
	broker *approval.Broker
}

func (g twoFAOnlyGate) Consult(ctx context.Context, req approval.Request) approval.Decision {
	if !req.Require2FA {
		return approval.Decision{Allowed: true, Reason: "auto-allow", DecidedBy: "system"}
	}
	return g.broker.Consult(ctx, req)
}

// TestVaultBoundaryRejectsHostileNamesAndAgentsBeforeAudit proves that CRLF,
// TAB, ANSI escape sequences, and NUL bytes in secret_name, namespace, agent,
// note, and purpose are rejected at the vault boundary by internal/validation
// before any secret or audit row is written (RGT-415).
func TestVaultBoundaryRejectsHostileNamesAndAgentsBeforeAudit(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "vault", "vault.db")
	v, err := vault.Open(ctx, vault.Config{
		DBPath:     dbPath,
		Provider:   providerstest.NewMemory(),
		PolicyYAML: v7PolicyYAML,
		KDFParams:  fastKDF,
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	hostileIdentifiers := []string{
		"secret\r\nFAKE_AUDIT_ROW",
		"secret\ninjected",
		"secret\rcarriage",
		"secret\ttabbed",
		"secret\x1b[31mred",
		"secret\x00nul",
	}

	for _, bad := range hostileIdentifiers {
		if err := v.SetSecret(ctx, vault.SetSecretRequest{
			Name: bad, Namespace: "default", Agent: "agent-ok", Purpose: "test", Value: []byte("v"),
		}); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Name=%q) err = %v, want ErrValidation", bad, err)
		}
		if err := v.Lease(ctx, vault.LeaseRequest{
			Name: bad, Namespace: "default", Agent: "agent-ok", Purpose: "test",
		}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("Lease(Name=%q) err = %v, want ErrValidation", bad, err)
		}
		if _, err := v.Fingerprint(ctx, "default", bad, 0); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("Fingerprint(Name=%q) err = %v, want ErrValidation", bad, err)
		}
		if err := v.RevokeSecret(ctx, "default", bad, "agent-ok"); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("RevokeSecret(Name=%q) err = %v, want ErrValidation", bad, err)
		}

		if err := v.SetSecret(ctx, vault.SetSecretRequest{
			Name: "ok-name", Namespace: "default", Agent: bad, Purpose: "test", Value: []byte("v"),
		}); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Agent=%q) err = %v, want ErrValidation", bad, err)
		}
		if err := v.Lease(ctx, vault.LeaseRequest{
			Name: "ok-name", Namespace: "default", Agent: bad, Purpose: "test",
		}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("Lease(Agent=%q) err = %v, want ErrValidation", bad, err)
		}
		if _, err := v.ListSecrets(ctx, vault.ListRequest{
			Namespace: "default", Agent: bad,
		}); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("ListSecrets(Agent=%q) err = %v, want ErrValidation", bad, err)
		}
		if err := v.RevokeSecret(ctx, "default", "ok-name", bad); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("RevokeSecret(Agent=%q) err = %v, want ErrValidation", bad, err)
		}
		if _, err := v.Simulate(ctx, bad, "default", "test", "read"); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("Simulate(Agent=%q) err = %v, want ErrValidation", bad, err)
		}

		if err := v.SetSecret(ctx, vault.SetSecretRequest{
			Name: "ok-name", Namespace: bad, Agent: "agent-ok", Value: []byte("v"),
		}); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Namespace=%q) err = %v, want ErrValidation", bad, err)
		}
		if err := v.SetSecret(ctx, vault.SetSecretRequest{
			Name: "ok-name", Namespace: "default", Agent: "agent-ok", Note: bad, Value: []byte("v"),
		}); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Note=%q) err = %v, want ErrValidation", bad, err)
		}
		if err := v.Lease(ctx, vault.LeaseRequest{
			Name: "ok-name", Namespace: "default", Agent: "agent-ok", Purpose: bad,
		}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrValidation) {
			t.Errorf("Lease(Purpose=%q) err = %v, want ErrValidation", bad, err)
		}
	}

	count, err := v.Store().AuditLogCount(ctx)
	if err != nil {
		t.Fatalf("AuditLogCount: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 audit rows after rejected hostile inputs, got %d", count)
	}
}

// TestStoreAndVaultDirectAuditSanitizationAndFrozenFormatResidual proves exact
// audit-row sanitization behavior when callers invoke store.LogAudit or
// vault.Audit directly without going through Vault's identifier allowlists:
//   - action and details ARE sanitized (\r, \n, \t -> \r, \n, \t) by audit.Sanitize;
//   - secret_name and agent_id are NOT sanitized in audit_logs because the
//     Python-compatible chain hash format is frozen;
//   - internal/logging encodes CR/LF/TAB when forwarding such rows to JSON logs.
func TestStoreAndVaultDirectAuditSanitizationAndFrozenFormatResidual(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "direct", "vault.db")
	v, err := vault.Open(ctx, vault.Config{
		DBPath:     dbPath,
		Provider:   providerstest.NewMemory(),
		PolicyYAML: v7PolicyYAML,
		KDFParams:  fastKDF,
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	hostileAction := "CUSTOM\r\nEVENT\t1"
	hostileDetails := "detail line 1\r\nFORGED_ACTION\tcol"
	hostileSecretName := "raw-name\r\ninjected"
	hostileAgentID := "raw-agent\r\ninjected"

	if err := v.Audit(ctx, hostileAction, store.Name(hostileSecretName), hostileDetails, store.Name(hostileAgentID)); err != nil {
		t.Fatalf("vault.Audit: %v", err)
	}

	rows, err := v.Store().IterAuditLog(ctx)
	if err != nil {
		t.Fatalf("IterAuditLog: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]

	if row.Action != `CUSTOM\r\nEVENT\t1` {
		t.Errorf("row.Action = %q, want escaped CR/LF/TAB", row.Action)
	}
	if row.Details.String != `detail line 1\r\nFORGED_ACTION\tcol` {
		t.Errorf("row.Details = %q, want escaped CR/LF/TAB", row.Details.String)
	}
	if row.SecretName.String != hostileSecretName {
		t.Errorf("row.SecretName = %q, want verbatim %q (frozen chain format)", row.SecretName.String, hostileSecretName)
	}
	if row.AgentID.String != hostileAgentID {
		t.Errorf("row.AgentID = %q, want verbatim %q", row.AgentID.String, hostileAgentID)
	}
	ok, err := v.VerifyAuditChain(ctx)
	if err != nil || !ok {
		t.Fatalf("VerifyAuditChain = (%v, %v), want (true, nil)", ok, err)
	}

	var logBuf bytes.Buffer
	logger, err := logging.New(logging.WithWriter(&logBuf))
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("audit_forward",
		slog.String(logging.FieldEvent, row.Action),
		slog.String(logging.FieldSecretName, row.SecretName.String),
		slog.String(logging.FieldAgent, row.AgentID.String),
	)
	trimmed := strings.TrimSuffix(logBuf.String(), "\n")
	if strings.ContainsAny(trimmed, "\r\n") {
		t.Fatalf("operational JSON log contains unencoded newline: %q", logBuf.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		t.Fatalf("invalid JSON from logger: %v", err)
	}
	if gotName, _ := parsed[logging.FieldSecretName].(string); strings.ContainsAny(gotName, "\r\n") {
		t.Errorf("decoded secret_name still has raw CR/LF: %q", gotName)
	}
	if gotAgent, _ := parsed[logging.FieldAgent].(string); strings.ContainsAny(gotAgent, "\r\n") {
		t.Errorf("decoded agent still has raw CR/LF: %q", gotAgent)
	}
}

// TestVaultOperationsNeverWriteSecretsOrKeysIntoAuditRows exercises Vault
// operations (set, lease, policy denial, approval/2FA denial, 2FA downgrade
// denial, honeytoken, missing secret, rate limit, list, fingerprint, simulate,
// revoke, DEK and master rotation) and proves that secret values, master keys,
// and capability tokens never appear in audit_logs rows or metadata (RGT-409,
// RGT-410, RGT-411, RGT-414, RGT-428).
func TestVaultOperationsNeverWriteSecretsOrKeysIntoAuditRows(t *testing.T) {
	ctx := context.Background()
	const (
		secretV1  = "VAULT_PLAINTEXT_SECRET_ALPHA_7731"
		secretV2  = "VAULT_PLAINTEXT_SECRET_BETA_8842"
		secret2FA = "VAULT_PLAINTEXT_2FA_OMEGA_9953"
		capTok    = "v2_cap_tok_SENSITIVE_HARNESS_CREDENTIAL_001122"
	)

	prov := providerstest.NewMemory()
	dbPath := filepath.Join(t.TempDir(), "ops", "vault.db")
	v, err := vault.Open(ctx, vault.Config{
		DBPath:     dbPath,
		Provider:   prov,
		PolicyYAML: v7PolicyYAML,
		Hook:       tokenCarryingHook{capToken: capTok},
		Approval:   deny2FAGate{},
		RateLimit:  3,
		RateWindow: time.Hour,
		KDFParams:  fastKDF,
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	masterBefore, err := prov.GetMasterSecret()
	if err != nil {
		t.Fatalf("GetMasterSecret: %v", err)
	}

	for _, req := range []vault.SetSecretRequest{
		{Name: "api-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "deploy", Note: "rotatable", Value: []byte(secretV1)},
		{Name: "api-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "deploy", Note: "v2", Value: []byte(secretV2)},
		{Name: "root-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "admin", Require2FA: true, Value: []byte(secret2FA)},
	} {
		if err := v.SetSecret(ctx, req); err != nil {
			t.Fatalf("SetSecret(%s): %v", req.Name, err)
		}
	}

	// Unprivileged 2FA downgrade attempt -> REQUIRE_2FA_DOWNGRADE_DENIED.
	if err := v.SetSecret(ctx, vault.SetSecretRequest{
		Name: "root-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "admin",
		Require2FA: false, AllowRequire2FADowngrade: false, Value: []byte(secretV1),
	}); !errors.Is(err, vault.ErrPolicyDenied) {
		t.Fatalf("2FA downgrade err = %v, want ErrPolicyDenied", err)
	}

	var leased string
	if err := v.Lease(ctx, vault.LeaseRequest{
		Name: "api-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "deploy",
	}, func(b []byte) error {
		leased = string(b)
		return nil
	}); err != nil || leased != secretV2 {
		t.Fatalf("Lease = (%q, %v), want %q", leased, err, secretV2)
	}

	if err := v.Lease(ctx, vault.LeaseRequest{
		Name: "api-cred", Namespace: "prod", Agent: "intruder", Purpose: "exfil",
	}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrPolicyDenied) {
		t.Fatalf("intruder Lease err = %v, want ErrPolicyDenied", err)
	}

	if err := v.Lease(ctx, vault.LeaseRequest{
		Name: "root-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "admin",
	}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrPolicyDenied) {
		t.Fatalf("2FA Lease err = %v, want ErrPolicyDenied", err)
	}

	if err := v.Lease(ctx, vault.LeaseRequest{
		Name: "missing-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "deploy",
	}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("missing Lease err = %v, want ErrNotFound", err)
	}

	if err := v.Lease(ctx, vault.LeaseRequest{
		Name: "api-cred", Namespace: "prod", Agent: "agent-ok", Purpose: "deploy",
	}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrRateLimited) {
		t.Fatalf("rate-limited Lease err = %v, want ErrRateLimited", err)
	}

	if err := v.Store().AddHoneytoken(ctx, "prod", "canary-key"); err != nil {
		t.Fatalf("AddHoneytoken: %v", err)
	}
	if err := v.Lease(ctx, vault.LeaseRequest{
		Name: "canary-key", Namespace: "prod", Agent: "system", Purpose: "probe",
	}, func([]byte) error { return nil }); !errors.Is(err, vault.ErrHoneytoken) {
		t.Fatalf("honeytoken Lease err = %v, want ErrHoneytoken", err)
	}

	if _, err := v.Fingerprint(ctx, "prod", "api-cred", 0); err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	infos, err := v.ListSecrets(ctx, vault.ListRequest{Namespace: "prod", Agent: "agent-ok"})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if _, err := v.Simulate(ctx, "agent-ok", "prod", "deploy", "read"); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if err := v.RotateDEK(ctx); err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}
	if err := v.RotateMaster(ctx); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	if err := v.RevokeSecret(ctx, "prod", "api-cred", "agent-ok"); err != nil {
		t.Fatalf("RevokeSecret: %v", err)
	}

	masterAfter, err := prov.GetMasterSecret()
	if err != nil {
		t.Fatalf("GetMasterSecret after rotate: %v", err)
	}

	forbidden := []string{
		secretV1,
		secretV2,
		secret2FA,
		capTok,
		hex.EncodeToString(masterBefore),
		base64.StdEncoding.EncodeToString(masterBefore),
		hex.EncodeToString(masterAfter),
		base64.StdEncoding.EncodeToString(masterAfter),
	}

	infosJSON, _ := json.Marshal(infos)
	for _, secret := range forbidden {
		if strings.Contains(string(infosJSON), secret) {
			t.Errorf("ListSecrets metadata leaked sensitive material %q", secret)
		}
	}

	rows, err := v.Store().IterAuditLog(ctx)
	if err != nil {
		t.Fatalf("IterAuditLog: %v", err)
	}
	seenActions := map[string]bool{}
	for _, r := range rows {
		seenActions[r.Action] = true
		blob := strings.Join([]string{
			r.Action,
			r.SecretName.String,
			r.Timestamp,
			r.Details.String,
			r.PrevHash.String,
			r.EntryHash,
			r.PolicyHash.String,
			r.AgentID.String,
		}, " | ")
		for _, secret := range forbidden {
			if secret != "" && strings.Contains(blob, secret) {
				t.Errorf("audit row %d (%s) leaked sensitive material %q: %s", r.ID, r.Action, secret, blob)
			}
		}
	}

	for _, wantEvent := range []string{
		"SET_SECRET", "GET_SECRET", "GET_SECRET_FAILED", "LEASE_GRANTED", "LEASE_RETURNED",
		"POLICY_DENIED", "APPROVAL_DENIED", "REQUIRE_2FA_DOWNGRADE_DENIED",
		"RATE_LIMITED", "HONEYTOKEN_TRIGGERED",
		"LIST_SECRETS", "SIMULATION_RUN", "ROTATE", "REVOKE_SECRET",
		"HOOK_WRITE", "HOOK_READ", "HOOK_LIST", "HOOK_SIMULATE", "HOOK_ROTATE", "HOOK_REVOKE",
	} {
		if !seenActions[wantEvent] {
			t.Errorf("expected Go audit event %q was not recorded (seen: %v)", wantEvent, seenActions)
		}
	}

	if ok, err := v.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("VerifyAuditChain = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestAuditChainTamperDetectionAndUnkeyedLimitation proves both what the Go
// audit chain protects today (0600 DB mode on POSIX, detection of modified
// fields and deleted middle rows) and its honest architectural boundary (the
// chain is unkeyed SHA-256 and omits agent_id, so a caller with direct DB
// write access can mutate agent_id or recompute hashes; RGT-416).
func TestAuditChainTamperDetectionAndUnkeyedLimitation(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "chain")
	dbPath := filepath.Join(dir, "vault.db")

	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	if runtime.GOOS != "windows" {
		if dInfo, err := os.Stat(dir); err != nil || dInfo.Mode().Perm() != 0o700 {
			t.Errorf("vault dir mode = %v (err %v), want 0700", dInfo.Mode().Perm(), err)
		}
		if fInfo, err := os.Stat(dbPath); err != nil || fInfo.Mode().Perm() != 0o600 {
			t.Errorf("vault.db mode = %v (err %v), want 0600", fInfo.Mode().Perm(), err)
		}
	}

	for i := 1; i <= 3; i++ {
		if err := st.LogAudit(ctx, store.AuditEvent{
			Action:     "SET_SECRET",
			SecretName: store.Name(fmt.Sprintf("k%d", i)),
			Details:    fmt.Sprintf("Version 1 created in ns%d", i),
			PolicyHash: "0123456789abcdef",
			AgentID:    store.Name("agent-1"),
		}); err != nil {
			t.Fatalf("LogAudit %d: %v", i, err)
		}
	}
	if ok, err := st.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("initial VerifyAuditChain = (%v, %v), want true", ok, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rawDB.Close() }()

	checkVerify := func() bool {
		t.Helper()
		reopened, err := store.Open(ctx, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reopened.Close() }()
		ok, err := reopened.VerifyAuditChain(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// 1. Naive modification of details is detected.
	if _, err := rawDB.Exec(`UPDATE audit_logs SET details = 'forged' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if checkVerify() {
		t.Fatal("VerifyAuditChain returned true after tampering details on row 2")
	}

	if _, err := rawDB.Exec(`UPDATE audit_logs SET details = 'Version 1 created in ns2' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if !checkVerify() {
		t.Fatal("VerifyAuditChain failed after restoring original details")
	}

	// 2. Documented limitation A: agent_id is not part of the frozen hash input.
	if _, err := rawDB.Exec(`UPDATE audit_logs SET agent_id = 'forged-agent' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if !checkVerify() {
		t.Fatal("expected frozen-format agent_id mutation to remain undetected (RGT-416)")
	}

	// 3. Delete middle row -> detected because row 3's entry_hash depends on row 2's hash.
	if _, err := rawDB.Exec(`DELETE FROM audit_logs WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if checkVerify() {
		t.Fatal("VerifyAuditChain returned true after deleting middle row 2")
	}

	// 4. Documented limitation B (RGT-416 / N4): unkeyed SHA-256 can be
	// recomputed from genesis by any caller with DB write access.
	reopened, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reopened.IterAuditLog(ctx)
	_ = reopened.Close()
	if err != nil {
		t.Fatal(err)
	}
	prev := ""
	for _, r := range rows {
		forgedHash := audit.EntryHash(prev, r.Timestamp, r.Action, r.SecretName.String, r.Details.String, r.PolicyHash.String)
		if _, err := rawDB.Exec(`UPDATE audit_logs SET prev_hash = ?, entry_hash = ? WHERE id = ?`, prev, forgedHash, r.ID); err != nil {
			t.Fatal(err)
		}
		prev = forgedHash
	}
	if !checkVerify() {
		t.Fatal("expected unkeyed SHA-256 chain recomputation by DB writer to verify (documents why RGT-416 stays Refs for N4)")
	}
}

// TestRealServerAuthAuthzSeparationInjectionAndErrorSanitization exercises the
// production Go HTTP server stack (server.New over vault.Vault + auth.Store +
// approval.Broker + totp.ReplayGuardedVerifier + actions.Registry) to verify:
//   - RGT-409 / RGT-428: bearer tokens, secret values, and TOTP codes never
//     appear in HTTP logs or audit_logs;
//   - RGT-410: query strings, headers, and bodies are absent from HTTP logs;
//   - RGT-411 / RGT-413 / RGT-414: HTTP_API, AUTH_FAILED, AUTHZ_DENIED,
//     APPROVAL_BAD_CODE, and deserialization ValidationError warnings are logged;
//   - RGT-415: percent-encoded CR/LF in request paths is rejected (400) and
//     encoded in server logs (zero forged lines);
//   - RGT-420 / RGT-421: panics and unexpected action/store errors are caught
//     and never leak stack traces, internal file paths, or struct internals;
//   - RGT-431: audit viewing requires ScopeAudit/ScopeOperator and an
//     audit-only token cannot touch secrets, approvals, or key rotation.
func TestRealServerAuthAuthzSeparationInjectionAndErrorSanitization(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	const (
		secretValue = "HTTP_VAULT_SECRET_PAYLOAD_NEVER_LOG_554433"
		badBearer   = "bad_bearer_token_DO_NOT_LOG_778899"
		wrongTOTP   = "948372"
		queryPII    = "alice.pii@example.com"
	)

	totpSecret, err := totp.GenerateSecret(20)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := totp.NewReplayGuardedVerifier(totpSecret)
	if err != nil {
		t.Fatal(err)
	}
	broker := approval.NewBroker(
		approval.WithTimeout(5*time.Second),
		approval.WithTOTPChecker(func(code string) approval.CodeResult {
			switch verifier.VerifyResult(code) {
			case totp.ResultOK:
				return approval.CodeOK
			case totp.ResultReplay:
				return approval.CodeReplay
			default:
				return approval.CodeInvalid
			}
		}),
	)

	dbPath := filepath.Join(t.TempDir(), "srvvault", "vault.db")
	v, err := vault.Open(ctx, vault.Config{
		DBPath:     dbPath,
		Provider:   providerstest.NewMemory(),
		PolicyYAML: v7PolicyYAML,
		Approval:   twoFAOnlyGate{broker: broker},
		KDFParams:  fastKDF,
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	tokStore := auth.OpenStore(filepath.Join(t.TempDir(), "private-tok-dir", "tokens.json"))
	agentTok, _, err := tokStore.Mint(auth.MintOptions{Agent: "agent-ok", Scopes: []auth.Scope{auth.ScopeAgent}})
	if err != nil {
		t.Fatal(err)
	}
	auditorTok, _, err := tokStore.Mint(auth.MintOptions{Agent: "auditor", Scopes: []auth.Scope{auth.ScopeAudit}})
	if err != nil {
		t.Fatal(err)
	}
	operatorTok, _, err := tokStore.Mint(auth.MintOptions{
		Agent:  "operator",
		Scopes: []auth.Scope{auth.ScopeOperator, auth.ScopeAudit, auth.ScopeAgent},
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredTok, _, err := tokStore.Mint(auth.MintOptions{
		Agent: "agent-ok", Scopes: []auth.Scope{auth.ScopeAgent}, TTL: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	actReg, err := actions.NewBuiltinRegistry(actions.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := actReg.Register(actions.Spec{
		Name:        "boom_err",
		Description: "returns internal path error",
		Fn: func(_ context.Context, secret []byte, _ map[string]any) (map[string]any, error) {
			return nil, fmt.Errorf("open /etc/shadow with secret %s: permission denied", string(secret))
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := actReg.Register(actions.Spec{
		Name:        "boom_panic",
		Description: "panics inside action",
		Fn: func(_ context.Context, secret []byte, _ map[string]any) (map[string]any, error) {
			panic("action panic with secret " + string(secret))
		},
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := server.New(server.Config{
		Vault:   v,
		Tokens:  tokStore,
		Broker:  broker,
		Actions: actReg,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	send := func(h http.Handler, method, target, bearer, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:54321"
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1. Authenticated secret set + list + echo use (with PII in query string).
	if rec := send(srv, "POST", "/v1/secrets?email="+queryPII, agentTok,
		`{"name":"api-cred","value":"`+secretValue+`","namespace":"prod","purpose":"deploy"}`); rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/secrets = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := send(srv, "POST", "/v1/secrets", agentTok,
		`{"name":"twofa-cred","value":"`+secretValue+`","namespace":"prod","purpose":"deploy","require_2fa":true}`); rec.Code != http.StatusOK {
		t.Fatalf("POST 2fa secret = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := send(srv, "GET", "/v1/secrets?namespace=prod&email="+queryPII, agentTok, ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/secrets = %d", rec.Code)
	}
	if rec := send(srv, "POST", "/v1/secrets/prod/api-cred/use", agentTok,
		`{"action":"echo","purpose":"deploy"}`); rec.Code != http.StatusOK {
		t.Fatalf("use echo = %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Authentication failures (missing, invalid, expired) -> 401 + AUTH_FAILED.
	if rec := send(srv, "GET", "/v1/actions", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing auth = %d, want 401", rec.Code)
	}
	if rec := send(srv, "GET", "/v1/actions", badBearer, ""); rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), badBearer) {
		t.Errorf("bad token = %d %q", rec.Code, rec.Body.String())
	}
	if rec := send(srv, "GET", "/v1/actions", expiredTok, ""); rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), expiredTok) {
		t.Errorf("expired token = %d %q", rec.Code, rec.Body.String())
	}

	// 3. Spoofed agent -> 403 + AUTHZ_DENIED.
	if rec := send(srv, "POST", "/v1/secrets", agentTok,
		`{"name":"x","value":"y","namespace":"prod","agent":"intruder"}`); rec.Code != http.StatusForbidden {
		t.Errorf("spoofed agent = %d, want 403", rec.Code)
	}

	// 4. Separation of duties on audit logs (RGT-431):
	//    - agent token cannot read or verify audit logs (403);
	//    - auditor token CAN read and verify audit logs (200);
	//    - auditor token CANNOT write secrets, rotate keys, or list approvals (403).
	if rec := send(srv, "GET", "/v1/audit", agentTok, ""); rec.Code != http.StatusForbidden {
		t.Errorf("agent GET /v1/audit = %d, want 403", rec.Code)
	}
	if rec := send(srv, "POST", "/v1/audit/verify", agentTok, ""); rec.Code != http.StatusForbidden {
		t.Errorf("agent POST /v1/audit/verify = %d, want 403", rec.Code)
	}
	if rec := send(srv, "GET", "/v1/audit?limit=20", auditorTok, ""); rec.Code != http.StatusOK {
		t.Errorf("auditor GET /v1/audit = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := send(srv, "POST", "/v1/audit/verify", auditorTok, ""); rec.Code != http.StatusOK {
		t.Errorf("auditor POST /v1/audit/verify = %d: %s", rec.Code, rec.Body.String())
	}
	for _, deniedRoute := range []struct{ method, path, body string }{
		{"POST", "/v1/secrets", `{"name":"a","value":"b"}`},
		{"POST", "/v1/rotate", `{"target":"dek"}`},
		{"GET", "/v1/requests", ""},
	} {
		if rec := send(srv, deniedRoute.method, deniedRoute.path, auditorTok, deniedRoute.body); rec.Code != http.StatusForbidden {
			t.Errorf("auditor %s %s = %d, want 403", deniedRoute.method, deniedRoute.path, rec.Code)
		}
	}

	// 5. 2FA approval bad code -> APPROVAL_BAD_CODE without logging wrongTOTP.
	doneUse := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		doneUse <- send(srv, "POST", "/v1/secrets/prod/twofa-cred/use", agentTok, `{"action":"echo","purpose":"deploy"}`)
	}()
	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pending := broker.List(); len(pending) > 0 {
			reqID = pending[0].RequestID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("timed out waiting for pending 2FA request")
	}
	if rec := send(srv, "POST", "/v1/requests/"+reqID+"/approve", operatorTok,
		`{"totp_code":"`+wrongTOTP+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong TOTP status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	_ = broker.Deny(reqID, "abort test", "operator")
	<-doneUse

	// 6. Deserialization failure -> generic 400 with incident_id, logged as ValidationError.
	rec400 := send(srv, "POST", "/v1/secrets", agentTok, `{"name":"a","value":"b","hidden_struct_field":true}`)
	if rec400.Code != http.StatusBadRequest || strings.Contains(rec400.Body.String(), "hidden_struct_field") {
		t.Errorf("unknown field 400 = %d %q", rec400.Code, rec400.Body.String())
	}

	// 7. CRLF path injection -> 400 from PathMiddleware, encoded in server logs.
	recCRLF := send(srv, "GET", "/v1/secrets/prod/bad%0d%0aFORGED_LOG_ENTRY", agentTok, "")
	if recCRLF.Code != http.StatusBadRequest {
		t.Errorf("CRLF path = %d, want 400", recCRLF.Code)
	}

	// 8. Action error & action panic & router handler panic & unreadable token store
	//    never expose stack traces, internal paths, or secret values (RGT-420, RGT-421).
	for _, act := range []string{"boom_err", "boom_panic"} {
		recAct := send(srv, "POST", "/v1/secrets/prod/api-cred/use", agentTok, `{"action":"`+act+`","purpose":"deploy"}`)
		if recAct.Code != http.StatusInternalServerError {
			t.Errorf("action %s = %d, want 500", act, recAct.Code)
		}
		for _, leak := range []string{"/etc/shadow", secretValue, "goroutine ", ".go:", "action panic"} {
			if strings.Contains(recAct.Body.String(), leak) {
				t.Errorf("action %s response leaked %q: %s", act, leak, recAct.Body.String())
			}
		}
	}

	// Global RecoverMiddleware on handler nil-Vault panic.
	panicRouter := server.NewRouter(&handlers.Handlers{}, server.NewStoreMiddleware(tokStore))
	recPanic := send(panicRouter, "GET", "/healthz", "", "")
	if recPanic.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", recPanic.Code)
	}
	var panicJSON map[string]string
	if err := json.Unmarshal(recPanic.Body.Bytes(), &panicJSON); err != nil {
		t.Fatalf("panic body invalid JSON: %v", err)
	}
	if len(panicJSON["incident_id"]) != 16 || panicJSON["detail"] != "internal server error" {
		t.Errorf("unexpected panic body: %v", panicJSON)
	}
	for _, leak := range []string{"goroutine ", ".go:", "runtime/debug"} {
		if strings.Contains(recPanic.Body.String(), leak) {
			t.Errorf("panic response leaked %q: %s", leak, recPanic.Body.String())
		}
	}

	// Corrupt token store -> generic 500 without leaking file path.
	corruptDir := filepath.Join(t.TempDir(), "secret-fs-location")
	if err := os.MkdirAll(corruptDir, 0o700); err != nil {
		t.Fatal(err)
	}
	corruptPath := filepath.Join(corruptDir, "tokens.json")
	if err := os.WriteFile(corruptPath, []byte("{not-valid-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptRouter, err := server.New(server.Config{Vault: v, Tokens: auth.OpenStore(corruptPath)})
	if err != nil {
		t.Fatal(err)
	}
	recCorrupt := send(corruptRouter, "GET", "/v1/actions", "any-token", "")
	if recCorrupt.Code != http.StatusInternalServerError || strings.Contains(recCorrupt.Body.String(), "secret-fs-location") {
		t.Errorf("corrupt token store leaked path: %d %q", recCorrupt.Code, recCorrupt.Body.String())
	}

	// 9. Verify server logs contain zero credentials, secrets, TOTP codes, query PII, or forged lines.
	serverLogs := logBuf.String()
	for _, forbidden := range []string{
		agentTok, auditorTok, operatorTok, expiredTok, badBearer,
		secretValue, totpSecret, wrongTOTP, queryPII,
		"\nFORGED_LOG_ENTRY", "\rFORGED_LOG_ENTRY",
	} {
		if strings.Contains(serverLogs, forbidden) {
			t.Errorf("HTTP server log leaked %q:\n%s", forbidden, serverLogs)
		}
	}
	if !strings.Contains(serverLogs, "error=ValidationError") {
		t.Errorf("expected deserialization ValidationError warning in server logs:\n%s", serverLogs)
	}

	// 10. Verify audit_logs recorded HTTP_API, AUTH_FAILED, AUTHZ_DENIED, and
	//     APPROVAL_BAD_CODE, with zero leaked secrets/tokens/TOTP codes.
	auditRows, err := v.Store().IterAuditLog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seenAudit := map[string]bool{}
	for _, r := range auditRows {
		seenAudit[r.Action] = true
		blob := r.Action + "|" + r.SecretName.String + "|" + r.Details.String + "|" + r.AgentID.String
		for _, forbidden := range []string{
			agentTok, auditorTok, operatorTok, expiredTok, badBearer,
			secretValue, totpSecret, wrongTOTP,
		} {
			if strings.Contains(blob, forbidden) {
				t.Errorf("audit row %d leaked %q: %s", r.ID, forbidden, blob)
			}
		}
	}
	for _, want := range []string{"HTTP_API", "HTTP_OPERATOR", "AUTH_FAILED", "AUTHZ_DENIED", "APPROVAL_BAD_CODE"} {
		if !seenAudit[want] {
			t.Errorf("missing expected server audit event %q (seen: %v)", want, seenAudit)
		}
	}
	if ok, err := v.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("VerifyAuditChain = (%v, %v), want true", ok, err)
	}
}

// TestDeployLogRotationAndJournaldConfigs parses the INI sections and logrotate
// directives in deploy/ (rather than substring matching) to pin exact
// ReadWritePaths sets, journald retention/size caps, and copytruncate/mode
// invariants without SIGHUP hazards (Refs RGT-429, RGT-430, RGT-512).
func TestDeployLogRotationAndJournaldConfigs(t *testing.T) {
	// Self-check on parser helpers (#8): prove `ReadWritePaths=/var/lib/rgt-vault /var/log`
	// and multi-line `ReadWritePaths=` are distinguished from `/var/lib/rgt-vault` alone.
	badINI := parseINI("[Service]\nProtectSystem=strict\nReadWritePaths=/var/lib/rgt-vault /var/log\n")
	if got := extractSystemdPaths(badINI["Service"]["ReadWritePaths"]); reflect.DeepEqual(got, []string{"/var/lib/rgt-vault"}) {
		t.Fatalf("INI parser failed to catch extra /var/log token in ReadWritePaths: %v", got)
	}

	deployDir := filepath.Join("..", "..", "..", "deploy")

	// 1. Parse deploy/rgt-vault-go.service as structured INI.
	unitRaw, err := os.ReadFile(filepath.Join(deployDir, "rgt-vault-go.service"))
	if err != nil {
		t.Fatalf("read rgt-vault-go.service: %v", err)
	}
	unitINI := parseINI(string(unitRaw))
	svc := unitINI["Service"]
	if svc == nil {
		t.Fatal("rgt-vault-go.service missing [Service] section")
	}
	wantServiceExact := map[string][]string{
		"User":               {"rgtvault"},
		"Group":              {"rgtvault"},
		"StateDirectoryMode": {"0700"},
		"UMask":              {"0077"},
		"ProtectSystem":      {"strict"},
	}
	for k, want := range wantServiceExact {
		if got := svc[k]; !reflect.DeepEqual(got, want) {
			t.Errorf("rgt-vault-go.service [Service] %s = %v, want %v", k, got, want)
		}
	}
	if rwPaths := extractSystemdPaths(svc["ReadWritePaths"]); !reflect.DeepEqual(rwPaths, []string{"/var/lib/rgt-vault"}) {
		t.Errorf("rgt-vault-go.service ReadWritePaths = %v, want exact [/var/lib/rgt-vault]", rwPaths)
	}

	// 2. Parse deploy/journald.conf.d/rgt-vault.conf as structured INI.
	journaldRaw, err := os.ReadFile(filepath.Join(deployDir, "journald.conf.d", "rgt-vault.conf"))
	if err != nil {
		t.Fatalf("read journald drop-in: %v", err)
	}
	jdINI := parseINI(string(journaldRaw))
	jSec := jdINI["Journal"]
	if jSec == nil {
		t.Fatal("journald drop-in missing [Journal] section")
	}
	wantJournalExact := map[string][]string{
		"Storage":              {"persistent"},
		"Compress":             {"yes"},
		"Seal":                 {"yes"},
		"MaxFileSec":           {"1day"},
		"MaxRetentionSec":      {"90day"},
		"SystemMaxUse":         {"1G"},
		"SystemKeepFree":       {"2G"},
		"RateLimitIntervalSec": {"30s"},
		"RateLimitBurst":       {"10000"},
	}
	for k, want := range wantJournalExact {
		if got := jSec[k]; !reflect.DeepEqual(got, want) {
			t.Errorf("journald [Journal] %s = %v, want %v", k, got, want)
		}
	}

	// 3. Parse deploy/logrotate.d/rgt-vault stanza directives and scripts.
	logrotateRaw, err := os.ReadFile(filepath.Join(deployDir, "logrotate.d", "rgt-vault"))
	if err != nil {
		t.Fatalf("read logrotate config: %v", err)
	}
	targets, directives, scripts, err := parseLogrotateStanza(string(logrotateRaw))
	if err != nil {
		t.Fatalf("parse logrotate config: %v", err)
	}
	if !reflect.DeepEqual(targets, []string{"/var/log/rgt-vault/*.log"}) {
		t.Errorf("logrotate targets = %v, want [/var/log/rgt-vault/*.log]", targets)
	}
	for _, flagDir := range []string{"daily", "compress", "delaycompress", "copytruncate", "missingok", "notifempty"} {
		if vals, ok := directives[flagDir]; !ok || !reflect.DeepEqual(vals, []string{""}) {
			t.Errorf("logrotate directive %q = %v (present=%v), want bare directive", flagDir, vals, ok)
		}
	}
	if !reflect.DeepEqual(directives["rotate"], []string{"90"}) {
		t.Errorf("logrotate rotate = %v, want [90]", directives["rotate"])
	}
	if !reflect.DeepEqual(directives["maxage"], []string{"90"}) {
		t.Errorf("logrotate maxage = %v, want [90]", directives["maxage"])
	}
	if !reflect.DeepEqual(directives["su"], []string{"rgtvault adm"}) {
		t.Errorf("logrotate su = %v, want [rgtvault adm] (never root in a daemon-owned directory)", directives["su"])
	}

	createVals := directives["create"]
	if len(createVals) != 1 {
		t.Fatalf("logrotate create = %v, want single directive", createVals)
	}
	createFields := strings.Fields(createVals[0])
	if len(createFields) != 3 || createFields[1] != "rgtvault" || createFields[2] != "adm" {
		t.Fatalf("logrotate create fields = %v, want [<mode> rgtvault adm]", createFields)
	}
	createMode, err := strconv.ParseUint(createFields[0], 8, 32)
	if err != nil || createMode != 0o640 || createMode&0o027 != 0 {
		t.Errorf("logrotate create mode = %q (%04o, err=%v), want 0640 (no group-write or world bits)", createFields[0], createMode, err)
	}

	// The directory is writable by rgtvault, so no root-run script may touch it
	// (symlink planting) and nothing may signal the daemon (RGT-512).
	if len(scripts["postrotate"]) != 0 || len(scripts["prerotate"]) != 0 || len(scripts["firstaction"]) != 0 || len(scripts["lastaction"]) != 0 {
		t.Errorf("logrotate must define no root-run scripts: %v", scripts)
	}
}

// parseINI parses systemd-style INI files (supporting `#`/`;` comment lines,
// trailing `\` line continuations, and repeated keys per section).
func parseINI(raw string) map[string]map[string][]string {
	sections := map[string]map[string][]string{}
	curSection := ""
	var continued strings.Builder

	flushLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			return
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			curSection = strings.TrimSpace(line[1 : len(line)-1])
			if sections[curSection] == nil {
				sections[curSection] = map[string][]string{}
			}
			return
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return
		}
		if sections[curSection] == nil {
			sections[curSection] = map[string][]string{}
		}
		sections[curSection][strings.TrimSpace(k)] = append(sections[curSection][strings.TrimSpace(k)], strings.TrimSpace(v))
	}

	for _, rawLine := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if continued.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";")) {
			continue
		}
		if strings.HasSuffix(trimmed, `\`) {
			continued.WriteString(strings.TrimSuffix(trimmed, `\`))
			continued.WriteByte(' ')
			continue
		}
		if continued.Len() > 0 {
			continued.WriteString(trimmed)
			flushLine(continued.String())
			continued.Reset()
			continue
		}
		flushLine(trimmed)
	}
	if continued.Len() > 0 {
		flushLine(continued.String())
	}
	return sections
}

func extractSystemdPaths(values []string) []string {
	var out []string
	for _, v := range values {
		for _, tok := range strings.Fields(v) {
			out = append(out, strings.TrimPrefix(tok, "-"))
		}
	}
	return out
}

func parseLogrotateStanza(raw string) (targets []string, directives map[string][]string, scripts map[string][]string, err error) {
	directives = map[string][]string{}
	scripts = map[string][]string{}

	inStanza := false
	inScript := ""
	closed := false

	for _, rawLine := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !inStanza {
			header, _, ok := strings.Cut(line, "{")
			if !ok {
				return nil, nil, nil, fmt.Errorf("unexpected line outside stanza: %q", line)
			}
			targets = strings.Fields(header)
			inStanza = true
			continue
		}
		if inScript != "" {
			if line == "endscript" {
				inScript = ""
				continue
			}
			scripts[inScript] = append(scripts[inScript], line)
			continue
		}
		if line == "}" {
			closed = true
			inStanza = false
			continue
		}
		if line == "postrotate" || line == "prerotate" || line == "firstaction" || line == "lastaction" {
			inScript = line
			continue
		}
		fields := strings.Fields(line)
		key := fields[0]
		rest := strings.TrimSpace(strings.TrimPrefix(line, key))
		directives[key] = append(directives[key], rest)
	}
	if !closed || len(targets) == 0 {
		return nil, nil, nil, errors.New("incomplete logrotate stanza")
	}
	return targets, directives, scripts, nil
}
