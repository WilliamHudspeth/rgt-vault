package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/totp"
	"rgt-vault-server/internal/vault"
)

func TestMain(m *testing.M) {
	// Error paths log incident ids; keep test output readable.
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

var testKDF = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

// testPolicy allows everything except: "intruder" (denied everything) and
// "limited" (denied the secrets.use capability).
const testPolicy = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: deny
    agent: intruder
    action: "*"
  - effect: deny
    agent: limited
    action: secrets.use
`

type envOpts struct {
	policy      string // "" = testPolicy; "-" = no policy (default deny)
	approval    bool
	operator    bool // separate operator token
	totp        bool
	harness     bool
	rateLimit   int
	provider    vault.MasterProvider
	maxBody     int64
	origins     []string
	approvalTTL int // seconds
}

type testEnv struct {
	t          *testing.T
	dir        string
	stack      *Stack
	h          http.Handler
	agentTok   string
	opTok      string
	totpSecret string
	signer     *captoken.HMACTokenVerifier
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newToken(t *testing.T, path string) (*auth.TokenStore, string) {
	t.Helper()
	tok, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenStore(path)
	if err := ts.Write(tok); err != nil {
		t.Fatal(err)
	}
	return ts, tok
}

func newEnv(t *testing.T, o envOpts) *testEnv {
	t.Helper()
	dir := t.TempDir()
	e := &testEnv{t: t, dir: dir}
	so := StackOptions{
		DBPath:          filepath.Join(dir, "vault", "vault.db"),
		MasterProvider:  o.provider,
		RequireApproval: o.approval,
		RateLimit:       o.rateLimit,
		KDFParams:       testKDF,
	}
	if so.MasterProvider == nil {
		so.MasterProvider = providerstest.NewMemory()
	}
	switch o.policy {
	case "":
		so.PolicyFile = writeFile(t, filepath.Join(dir, "policy.yaml"), testPolicy)
	case "-":
	default:
		so.PolicyFile = writeFile(t, filepath.Join(dir, "policy.yaml"), o.policy)
	}
	if o.approvalTTL > 0 {
		so.ApprovalTimeout = durationSeconds(o.approvalTTL)
	}
	if o.totp {
		secret, err := totp.GenerateSecret(20)
		if err != nil {
			t.Fatal(err)
		}
		e.totpSecret = secret
		so.TOTPSecretFile = writeFile(t, filepath.Join(dir, "totp.secret"), secret+"\n")
	}
	if o.harness {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		hexKey := hex.EncodeToString(key)
		so.HarnessKeyFile = writeFile(t, filepath.Join(dir, "harness.key"), hexKey+"\n")
		signer, err := captoken.NewHMACTokenVerifier([]byte(hexKey))
		if err != nil {
			t.Fatal(err)
		}
		e.signer = signer
	}
	stack, err := OpenStack(context.Background(), so)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	e.stack = stack

	agentStore, agentTok := newToken(t, filepath.Join(dir, "agent.token"))
	e.agentTok = agentTok
	cfg := Config{
		Vault: stack.Vault, AgentTokens: agentStore, Broker: stack.Broker,
		Actions: stack.Actions, Capabilities: stack.Capabilities,
		MaxBodyBytes: o.maxBody, AllowedOrigins: o.origins,
	}
	if o.operator {
		opStore, opTok := newToken(t, filepath.Join(dir, "operator.token"))
		cfg.OperatorTokens, e.opTok = opStore, opTok
	} else {
		e.opTok = agentTok
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

// call performs a request against the handler and decodes the JSON body.
func (e *testEnv) call(method, path, token string, body any) (int, map[string]any, *httptest.ResponseRecorder) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m, rec
}

func (e *testEnv) agent(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	code, m, _ := e.call(method, path, e.agentTok, body)
	return code, m
}

func (e *testEnv) mustOK(method, path string, body any) map[string]any {
	e.t.Helper()
	code, m, rec := e.call(method, path, e.agentTok, body)
	if code != http.StatusOK {
		e.t.Fatalf("%s %s: status %d body %s", method, path, code, rec.Body.String())
	}
	return m
}

func (e *testEnv) set(ns, name, value string, extra map[string]any) {
	e.t.Helper()
	body := map[string]any{"name": name, "value": value, "namespace": ns, "agent": "bot", "purpose": "ci"}
	for k, v := range extra {
		body[k] = v
	}
	e.mustOK("POST", "/v1/secrets", body)
}

// sign mints a v2 capability token with the harness key.
func (e *testEnv) sign(agent, capability string, version int) string {
	e.t.Helper()
	tok, err := e.signer.Sign(agent, capability, version, nil, 300)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// auditRows returns GET /v1/audit entries (newest first).
func (e *testEnv) auditRows(query string) []map[string]any {
	e.t.Helper()
	m := e.mustOK("GET", "/v1/audit?limit=1000"+query, nil)
	raw, _ := m["entries"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

// rawDB opens a second connection to the vault database (tamper tests).
func (e *testEnv) rawDB() *sql.DB {
	e.t.Helper()
	db, err := sql.Open("sqlite", e.stack.DBPath)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	return db
}

func hasAction(rows []map[string]any, action string) bool {
	for _, r := range rows {
		if r["action"] == action {
			return true
		}
	}
	return false
}
