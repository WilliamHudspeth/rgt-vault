package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/store"
)

// Batch H2: re-enrolment of the authenticator and token changes are
// operator actions: warned, audited, and (for --force) gated on the
// operator scope.

func auditActions(t *testing.T, e *vaultEnv, action string) []store.AuditRow {
	t.Helper()
	stack := e.open()
	defer stack.Close()
	rows, err := stack.Vault.AuditLog(context.Background(), -1)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditRow
	for _, r := range rows {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func mintTokens(t *testing.T, storePath string) (agentTok, opTok string) {
	t.Helper()
	st := auth.OpenStore(storePath)
	a, _, err := st.Mint(auth.MintOptions{Agent: "bot", Scopes: []auth.Scope{auth.ScopeAgent}})
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := st.Mint(auth.MintOptions{Agent: "ops", Scopes: []auth.Scope{auth.ScopeOperator}})
	if err != nil {
		t.Fatal(err)
	}
	return a, o
}

func TestEnrollForceNeedsOperatorAndRecordsFingerprint(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "k", "v")
	storePath := filepath.Join(e.dir, "tokens.json")
	t.Setenv("RGT_VAULT_TOKEN_STORE", storePath)
	out := filepath.Join(e.dir, "totp.secret")
	e.mustCLI("", "enroll-2fa", "--out", out) // first enrolment: nothing to replace
	old := strings.TrimSpace(string(mustRead(t, out)))
	sum := sha256.Sum256([]byte(old))
	wantFP := hex.EncodeToString(sum[:])[:8]

	agentTok, opTok := mintTokens(t, storePath)
	opID := ""
	infos, _ := auth.OpenStore(storePath).List()
	for _, in := range infos {
		if in.Agent == "ops" {
			opID = in.ID
		}
	}

	// No token, an unknown token and a non-operator token are all refused,
	// and the secret is untouched.
	for name, args := range map[string][]string{
		"no token":        {"enroll-2fa", "--out", out, "--force"},
		"agent token":     {"--token", agentTok, "enroll-2fa", "--out", out, "--force"},
		"garbage token":   {"--token", "nope-nope-nope", "enroll-2fa", "--out", out, "--force"},
		"unreadable list": nil,
	} {
		if args == nil {
			continue
		}
		code, _, stderr := e.cli("", args...)
		if code != 1 || !strings.Contains(stderr, "operator") {
			t.Errorf("%s: exit %d err %q", name, code, stderr)
		}
		if got := strings.TrimSpace(string(mustRead(t, out))); got != old {
			t.Fatalf("%s: the secret was replaced", name)
		}
	}
	if rows := auditActions(t, e, auditTOTPReplaced); len(rows) != 0 {
		t.Fatalf("refused attempts wrote %d replacement rows", len(rows))
	}

	// An operator token replaces it: warning on stderr, one audit row with
	// the old fingerprint and the operator token id, never a secret.
	code, _, stderr := e.cli("", "--token", opTok, "enroll-2fa", "--out", out, "--force")
	if code != 0 {
		t.Fatalf("operator --force: exit %d %s", code, stderr)
	}
	if !strings.Contains(stderr, "WARNING: replacing the TOTP secret") || !strings.Contains(stderr, wantFP) || strings.Contains(stderr, old) {
		t.Fatalf("stderr = %q", stderr)
	}
	fresh := strings.TrimSpace(string(mustRead(t, out)))
	if fresh == old {
		t.Fatal("secret not replaced")
	}
	assertMode0600(t, out)
	rows := auditActions(t, e, auditTOTPReplaced)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	d := rows[0].Details.String
	if !strings.Contains(d, "old_secret_fingerprint="+wantFP) || !strings.Contains(d, "operator_token="+opID) ||
		strings.Contains(d, old) || strings.Contains(d, fresh) || strings.Contains(d, opTok) {
		t.Fatalf("details = %q", d)
	}
	if len(wantFP) != 8 {
		t.Fatal("fingerprint is not an 8-digit prefix")
	}
}

func TestEnrollForceFailsClosedWithoutAnOperatorToCheck(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "k", "v")
	out := filepath.Join(e.dir, "totp.secret")
	e.mustCLI("", "enroll-2fa", "--out", out)
	old := string(mustRead(t, out))
	unchanged := func(what string) {
		t.Helper()
		if string(mustRead(t, out)) != old {
			t.Fatalf("%s: the secret was replaced", what)
		}
	}

	// An explicitly named store that does not exist is an error, with or
	// without the acknowledgement (the review's bypass: a path nobody checks).
	for _, args := range [][]string{
		{"--token-store", filepath.Join(e.dir, "nonexistent.json")},
		{"--token-store", filepath.Join(e.dir, "nonexistent.json"), "--i-am-offline-operator"},
	} {
		code, _, stderr := e.cli("", append([]string{"enroll-2fa", "--out", out, "--force"}, args...)...)
		if code != 1 || !strings.Contains(stderr, "does not exist") {
			t.Fatalf("%v: exit %d err %q", args, code, stderr)
		}
		unchanged(strings.Join(args, " "))
	}
	t.Setenv("RGT_VAULT_TOKEN_STORE", filepath.Join(e.dir, "absent.json"))
	if code, _, stderr := e.cli("", "enroll-2fa", "--out", out, "--force", "--i-am-offline-operator"); code != 1 || !strings.Contains(stderr, "does not exist") {
		t.Fatalf("explicit env store: exit %d err %q", code, stderr)
	}
	unchanged("env store")

	// The same bypass against a store that DOES hold an operator token.
	storePath := filepath.Join(e.dir, "tokens.json")
	mintTokens(t, storePath)
	t.Setenv("RGT_VAULT_TOKEN_STORE", storePath)
	for _, args := range [][]string{
		{},
		{"--i-am-offline-operator"}, // the acknowledgement never replaces a real operator check
		{"--token-store", filepath.Join(e.dir, "nonexistent.json")},
	} {
		code, _, stderr := e.cli("", append([]string{"enroll-2fa", "--out", out, "--force"}, args...)...)
		if code != 1 {
			t.Fatalf("%v: exit %d err %q", args, code, stderr)
		}
		unchanged(strings.Join(args, " "))
	}

	// No store at the DEFAULT location: refused until acknowledged.
	t.Setenv("RGT_VAULT_TOKEN_STORE", "")
	code, _, stderr := e.cli("", "enroll-2fa", "--out", out, "--force")
	if code != 1 || !strings.Contains(stderr, "--i-am-offline-operator") {
		t.Fatalf("default store missing: exit %d err %q", code, stderr)
	}
	unchanged("default store missing")
	code, _, stderr = e.cli("", "enroll-2fa", "--out", out, "--force", "--i-am-offline-operator")
	if code != 0 || !strings.Contains(stderr, "on your own say-so") || !strings.Contains(stderr, "operator token offline-ack") {
		t.Fatalf("acknowledged: exit %d err %q", code, stderr)
	}
	// A store holding agent tokens only: same rule.
	agentsOnly := filepath.Join(e.dir, "agents.json")
	if _, _, err := auth.OpenStore(agentsOnly).Mint(auth.MintOptions{Agent: "bot", Scopes: []auth.Scope{auth.ScopeAgent}}); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = e.cli("", "enroll-2fa", "--out", out, "--force", "--token-store", agentsOnly)
	if code != 1 || !strings.Contains(stderr, "has no operator token") {
		t.Fatalf("agent-only store: exit %d err %q", code, stderr)
	}
	code, _, stderr = e.cli("", "enroll-2fa", "--out", out, "--force", "--token-store", agentsOnly, "--i-am-offline-operator")
	if code != 0 {
		t.Fatalf("agent-only store, acknowledged: exit %d err %q", code, stderr)
	}
	rows := auditActions(t, e, auditTOTPReplaced)
	if len(rows) != 2 || !strings.Contains(rows[0].Details.String, "operator_token=offline-ack") {
		t.Fatalf("audit rows = %+v", rows)
	}
}

func TestEnrollForceCorruptStoreRefuses(t *testing.T) {
	e := newVaultEnv(t)
	out := filepath.Join(e.dir, "totp.secret")
	e.mustCLI("", "enroll-2fa", "--out", out)
	bad := filepath.Join(e.dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, out)
	code, _, stderr := e.cli("", "enroll-2fa", "--out", out, "--force", "--i-am-offline-operator", "--token-store", bad)
	if code != 1 || !strings.Contains(stderr, "token store") {
		t.Fatalf("corrupt store: exit %d err %q", code, stderr)
	}
	if string(mustRead(t, out)) != string(before) {
		t.Fatal("secret replaced although the token store could not be read")
	}
}

func TestSecretFingerprintLabels(t *testing.T) {
	dir := t.TempDir()
	if got := secretFingerprint(filepath.Join(dir, "none")); got != "unreadable" {
		t.Errorf("missing file = %q", got)
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte(" \n"), 0o600)
	if got := secretFingerprint(empty); got != "empty" {
		t.Errorf("empty file = %q", got)
	}
}

// --- token events ----------------------------------------------------------

func TestTokenEventsAreAuditedAndWarned(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "k", "v")
	storePath := filepath.Join(e.dir, "tokens.json")
	t.Setenv("RGT_VAULT_TOKEN_STORE", storePath)

	code, out, stderr := e.cli("", "token", "mint", "--agent", "bot", "--scope", "agent,operator")
	if code != 0 {
		t.Fatalf("mint: %d %s", code, stderr)
	}
	tok := tokenLine(t, out)
	if !strings.Contains(stderr, "WARNING: TOKEN_MINTED") || !strings.Contains(stderr, "agent=bot") || strings.Contains(stderr, tok) {
		t.Fatalf("mint stderr = %q", stderr)
	}
	rows := auditActions(t, e, auditTokenMinted)
	if len(rows) != 1 {
		t.Fatalf("TOKEN_MINTED rows = %d", len(rows))
	}
	infos, _ := auth.OpenStore(storePath).List()
	if len(infos) != 1 {
		t.Fatalf("tokens = %d", len(infos))
	}
	id := infos[0].ID
	d := rows[0].Details.String
	if !strings.Contains(d, "token="+id) || !strings.Contains(d, "agent=bot") || !strings.Contains(d, "scopes=agent,operator") ||
		!strings.Contains(d, "by=") || strings.Contains(d, tok) || rows[0].AgentID.String != "bot" {
		t.Fatalf("details = %q (agent %q)", d, rows[0].AgentID.String)
	}

	// rotate, import, revoke each leave a row.
	code, out, stderr = e.cli("", "token", "rotate", id)
	if code != 0 || !strings.Contains(stderr, "WARNING: TOKEN_ROTATED") {
		t.Fatalf("rotate: %d %q", code, stderr)
	}
	newTok := tokenLine(t, out)
	rot := auditActions(t, e, auditTokenRotated)
	if len(rot) != 1 || !strings.Contains(rot[0].Details.String, "replaces="+id) || strings.Contains(rot[0].Details.String, newTok) {
		t.Fatalf("rotate rows = %+v", rot)
	}
	impFile := filepath.Join(e.dir, "legacy.token")
	legacyTok, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(impFile, []byte(legacyTok+"\n"), 0o600)
	if code, _, stderr = e.cli("", "token", "import", "--file", impFile, "--agent", "old"); code != 0 || !strings.Contains(stderr, "WARNING: TOKEN_IMPORTED") {
		t.Fatalf("import: %d %q", code, stderr)
	}
	infos, _ = auth.OpenStore(storePath).List()
	var revID string
	for _, in := range infos {
		if in.Agent == "old" {
			revID = in.ID
		}
	}
	if code, _, stderr = e.cli("", "token", "revoke", revID); code != 0 || !strings.Contains(stderr, "WARNING: TOKEN_REVOKED") {
		t.Fatalf("revoke: %d %q", code, stderr)
	}
	for _, a := range []string{auditTokenImported, auditTokenRevoked} {
		if n := len(auditActions(t, e, a)); n != 1 {
			t.Errorf("%s rows = %d", a, n)
		}
	}
	stack := e.open()
	defer stack.Close()
	if ok, _ := stack.Vault.VerifyAuditChain(context.Background()); !ok {
		t.Fatal("the audit chain broke")
	}
}

func TestTokenMintWithoutVaultIsNotAudited(t *testing.T) {
	isolateEnv(t)
	t.Setenv("RGT_VAULT_TOKEN_STORE", filepath.Join(t.TempDir(), "tokens.json"))
	code, _, stderr := runCLI(t, "", "--db", filepath.Join(t.TempDir(), "none", "vault.db"), "token", "mint", "--agent", "bot")
	if code != 0 || !strings.Contains(stderr, "WARNING: TOKEN_MINTED") || !strings.Contains(stderr, "not audited") {
		t.Fatalf("mint without a vault: %d %q", code, stderr)
	}
}

func TestTokenMintUndoneWhenAuditFails(t *testing.T) {
	isolateEnv(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	t.Setenv("RGT_VAULT_TOKEN_STORE", storePath)
	// A "vault" that exists but is not a database: the row cannot be written.
	db := filepath.Join(dir, "vault.db")
	_ = os.WriteFile(db, []byte("this is not sqlite"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "keychain.json"), []byte("{}"), 0o600)
	outFile := filepath.Join(dir, "bot.token")
	code, out, stderr := runCLI(t, "", "--db", db, "token", "mint", "--agent", "bot", "--out", outFile)
	if code != 1 || !strings.Contains(stderr, "audit log") || !strings.Contains(stderr, "revoked again") {
		t.Fatalf("exit %d err %q", code, stderr)
	}
	if strings.Contains(out, "minted") {
		t.Fatalf("success message after a failed audit: %q", out)
	}
	if _, err := os.Stat(outFile); err == nil {
		t.Fatal("the token file of an unaudited mint was left behind")
	}
	infos, _ := auth.OpenStore(storePath).List()
	for _, in := range infos {
		t.Fatalf("an unaudited token stays active: %+v", in)
	}
}

func TestCLISecurityWebhookNotifiesTokenAndTOTPChanges(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "k", "v")
	t.Setenv("RGT_VAULT_TOKEN_STORE", filepath.Join(e.dir, "tokens.json"))
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	t.Setenv(envSecurityWebhook, srv.URL+"/hook?key=SECRETKEY")

	code, out, stderr := e.cli("", "token", "mint", "--agent", "bot")
	if code != 0 {
		t.Fatalf("mint: %d %s", code, stderr)
	}
	tok := tokenLine(t, out)
	secretOut := filepath.Join(e.dir, "totp.secret")
	e.mustCLI("", "enroll-2fa", "--out", secretOut)
	oldSecret := strings.TrimSpace(string(mustRead(t, secretOut)))
	if code, _, stderr = e.cli("", "enroll-2fa", "--out", secretOut, "--force", "--i-am-offline-operator"); code != 0 {
		t.Fatalf("force: %d %s", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"event":"TOKEN_MINTED"`) || !strings.Contains(bodies[1], `"event":"TOTP_SECRET_REPLACED"`) {
		t.Fatalf("webhook bodies = %v", bodies)
	}
	for _, b := range bodies {
		if strings.Contains(b, tok) || strings.Contains(b, oldSecret) || strings.Contains(b, "SECRETKEY") {
			t.Fatalf("webhook body leaks a secret: %s", b)
		}
	}
}

func TestCLISecurityWebhookFailuresAreWarningsOnly(t *testing.T) {
	isolateEnv(t)
	t.Setenv("RGT_VAULT_TOKEN_STORE", filepath.Join(t.TempDir(), "tokens.json"))
	dbArgs := []string{"--db", filepath.Join(t.TempDir(), "none", "vault.db")}

	t.Setenv(envSecurityWebhook, "ftp://nonsense")
	code, _, stderr := runCLI(t, "", append(dbArgs, "token", "mint", "--agent", "a")...)
	if code != 0 || !strings.Contains(stderr, envSecurityWebhook) {
		t.Fatalf("invalid URL: %d %q", code, stderr)
	}
	// A dead endpoint: warning, no failure, and the URL (it may hold a key) is not printed.
	t.Setenv(envSecurityWebhook, "http://127.0.0.1:1/hook?key=SECRETKEY")
	code, _, stderr = runCLI(t, "", append(dbArgs, "token", "mint", "--agent", "b")...)
	if code != 0 || !strings.Contains(stderr, "delivery of TOKEN_MINTED failed") || strings.Contains(stderr, "SECRETKEY") {
		t.Fatalf("dead endpoint: %d %q", code, stderr)
	}
	// No webhook configured: nothing happens.
	t.Setenv(envSecurityWebhook, "")
	if code, _, stderr = runCLI(t, "", append(dbArgs, "token", "mint", "--agent", "c")...); code != 0 || strings.Contains(stderr, "webhook") {
		t.Fatalf("no webhook: %d %q", code, stderr)
	}
}
