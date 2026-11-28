package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/capabilities"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

func durationSeconds(n int) time.Duration { return time.Duration(n) * time.Second }

// --- health, auth ---------------------------------------------------------

func TestHealthCheck(t *testing.T) {
	e := newEnv(t, envOpts{operator: true})

	// Unauthenticated: exactly {"status":"ok"}, nothing about the vault.
	code, _, rec := e.call("GET", "/healthz", "", nil)
	if code != 200 || rec.Body.String() != minimalHealthBody {
		t.Fatalf("unauthenticated healthz: %d %q, want 200 %q", code, rec.Body.String(), minimalHealthBody)
	}

	// With the operator token: the full detailed body, version included.
	var names []string
	for _, s := range e.stack.Actions.List() {
		names = append(names, s.Name)
	}
	want := &healthWant{vaultID: e.stack.Vault.VaultID(), keyEpoch: int(e.stack.Vault.KeyEpoch()), actions: names}
	_, _, rec = e.call("GET", "/healthz", e.opTok, nil)
	wantDetailed(t, "operator token", rec, want)

	// APP_ENV=production has no extra effect any more: same two answers.
	t.Setenv("APP_ENV", "production")
	_, _, rec = e.call("GET", "/healthz", "", nil)
	wantMinimal(t, "production, unauthenticated", rec)
	_, _, rec = e.call("GET", "/healthz", e.opTok, nil)
	wantDetailed(t, "production, operator token", rec, want)
}

func TestAuthRejectsMissingAndWrongTokens(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, tok := range []string{"", "wrong-token"} {
		code, m, rec := e.call("GET", "/v1/secrets?namespace=default", tok, nil)
		if code != 401 || m["error"] != "ServerAuthError" || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: %d %v", tok, code, m)
		}
	}
	// Unauthenticated requests write no HTTP_API row.
	for _, r := range e.auditRows("") {
		if r["action"] == "HTTP_API" && strings.Contains(fmt.Sprint(r["details"]), "GET /v1/secrets ") {
			// only the authed audit call itself may appear
			t.Errorf("unauthenticated request audited: %v", r)
		}
	}
}

func TestNewRequiresVaultAndTokens(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("nil vault accepted")
	}
	e := newEnv(t, envOpts{})
	if _, err := New(Config{Vault: e.stack.Vault}); err == nil {
		t.Error("nil token store accepted")
	}
}

// --- secrets lifecycle ----------------------------------------------------

func TestSecretLifecycle(t *testing.T) {
	e := newEnv(t, envOpts{})
	const value = "s3cr3t-SENTINEL-value"
	m := e.mustOK("POST", "/v1/secrets", map[string]any{
		"name": "api-key", "value": value, "namespace": "prod", "agent": "bot", "purpose": "ci",
		"note": "rotate monthly", "require_2fa": false,
	})
	if m["ok"] != true || m["namespace"] != "prod" || m["name"] != "api-key" {
		t.Fatalf("set: %v", m)
	}

	// list: metadata only, Python's SecretInfo fields
	_, _, rec := e.call("GET", "/v1/secrets?namespace=prod&agent=bot", e.agentTok, nil)
	if strings.Contains(rec.Body.String(), value) || strings.Contains(rec.Body.String(), `"value"`) {
		t.Fatalf("list leaks a value: %s", rec.Body.String())
	}
	m = e.mustOK("GET", "/v1/secrets?namespace=prod&agent=bot", nil)
	secrets := m["secrets"].([]any)
	if len(secrets) != 1 {
		t.Fatalf("list: %v", m)
	}
	s0 := secrets[0].(map[string]any)
	for _, k := range []string{"secret_id", "name", "latest_version", "created_at", "updated_at", "status", "note", "require_2fa"} {
		if _, ok := s0[k]; !ok {
			t.Errorf("list item lacks %q: %v", k, s0)
		}
	}
	if s0["note"] != "rotate monthly" || s0["status"] != "ACTIVE" {
		t.Errorf("list item = %v", s0)
	}

	// fingerprint (RGT-502): 8 hex digits, equal to the vault's, no value
	fp := e.mustOK("GET", "/v1/secrets/prod/api-key", nil)
	want, err := e.stack.Vault.Fingerprint(context.Background(), "prod", "api-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	if fp["fingerprint"] != want || !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(want) {
		t.Errorf("fingerprint = %v, want %s", fp, want)
	}
	if _, leaked := fp["value"]; leaked {
		t.Error("fingerprint route returned a value")
	}
	if fpv := e.mustOK("GET", "/v1/secrets/prod/api-key?version=1", nil); fpv["fingerprint"] != want {
		t.Errorf("fingerprint v1 = %v", fpv)
	}

	// use: lease server-side, run echo, never return the value
	code, m, rec := e.call("POST", "/v1/secrets/prod/api-key/use", e.agentTok,
		map[string]any{"action": "echo", "agent": "bot", "purpose": "ci", "params": map[string]any{}})
	if code != 200 || m["ok"] != true || m["action"] != "echo" || strings.Contains(rec.Body.String(), value) {
		t.Fatalf("use: %d %s", code, rec.Body.String())
	}
	rows := e.auditRows("")
	for _, a := range []string{"SET_SECRET", "LIST_SECRETS", "GET_SECRET", "LEASE_GRANTED", "LEASE_RETURNED", "HTTP_API"} {
		if !hasAction(rows, a) {
			t.Errorf("audit lacks %s", a)
		}
	}

	// revoke (agent defaults to "system"), then gone everywhere
	if m := e.mustOK("POST", "/v1/secrets/prod/api-key/revoke", "{}"); m["ok"] != true {
		t.Fatalf("revoke: %v", m)
	}
	if m := e.mustOK("GET", "/v1/secrets?namespace=prod", nil); len(m["secrets"].([]any)) != 0 {
		t.Errorf("list after revoke: %v", m)
	}
	if code, m := e.agent("GET", "/v1/secrets/prod/api-key", nil); code != 404 || m["error"] != "SecretNotFoundError" {
		t.Errorf("fingerprint after revoke: %d %v", code, m)
	}
	// but the revoked version is still addressable by number
	if code, _ := e.agent("GET", "/v1/secrets/prod/api-key?version=1", nil); code != 200 {
		t.Errorf("fingerprint of revoked v1: %d", code)
	}
	if ok := e.mustOK("POST", "/v1/audit/verify", nil); ok["ok"] != true {
		t.Errorf("chain does not verify: %v", ok)
	}
}

// --- error -> status mapping ----------------------------------------------

func TestErrorStatusMapping(t *testing.T) {
	e := newEnv(t, envOpts{harness: true, rateLimit: 3})
	e.set("default", "k", "v", nil)
	noVerifier := newEnv(t, envOpts{})
	fixed := newEnv(t, envOpts{provider: providerstest.Fixed{Secret: []byte("0123456789abcdef0123456789abcdef")}})

	type tc struct {
		name   string
		env    *testEnv
		method string
		path   string
		token  string // "" = agent token, "-" = none
		body   any
		status int
		errTyp string
	}
	cases := []tc{
		{"401 no token", e, "GET", "/v1/audit", "-", nil, 401, "ServerAuthError"},
		{"400 bad name", e, "POST", "/v1/secrets", "", map[string]any{"name": "bad name!", "value": "x"}, 400, "ValidationError"},
		{"400 bad version", e, "GET", "/v1/secrets/default/k?version=0", "", nil, 400, "ValidationError"},
		{"400 audit limit 0", e, "GET", "/v1/audit?limit=0", "", nil, 400, "ValidationError"},
		{"400 audit limit big", e, "GET", "/v1/audit?limit=5000", "", nil, 400, "ValidationError"},
		{"400 list limit", e, "GET", "/v1/secrets?limit=0", "", nil, 400, "ValidationError"},
		{"400 list offset", e, "GET", "/v1/secrets?offset=-1", "", nil, 400, "ValidationError"},
		{"400 rotate target", e, "POST", "/v1/rotate", "", map[string]any{"target": "everything"}, 400, "ValidationError"},
		{"400 rotate unsupported", fixed, "POST", "/v1/rotate", "", map[string]any{"target": "master"}, 400, "RotateNotSupportedError"},
		{"400 use bad params", e, "POST", "/v1/secrets/default/k/use", "", map[string]any{"action": "echo", "agent": "bot", "purpose": "p", "params": map[string]any{"zzz": 1}}, 400, "ValidationError"},
		{"400 use empty purpose", e, "POST", "/v1/secrets/default/k/use", "", map[string]any{"action": "echo", "agent": "bot"}, 400, "ValidationError"},
		{"400 no verifier", noVerifier, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": "x.y"}, 400, "ValidationError"},
		{"400 capability_version 0", e, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": "x.y", "capability_version": 0}, 400, "ValidationError"},
		{"400 capability version", e, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": e.sign("bot", "secrets.echo", 2), "capability_version": 2}, 400, "CapabilityVersionError"},
		{"403 policy list", e, "GET", "/v1/secrets?namespace=default&agent=intruder", "", nil, 403, "PolicyDeniedError"},
		{"403 policy use", e, "POST", "/v1/secrets/default/k/use", "", map[string]any{"action": "echo", "agent": "intruder", "purpose": "p"}, 403, "PolicyDeniedError"},
		{"403 policy revoke", e, "POST", "/v1/secrets/default/k/revoke?agent=intruder", "", nil, 403, "PolicyDeniedError"},
		{"403 token forged", e, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": "eyJ4IjoxfQ.AAAA"}, 403, "PolicyDeniedError"},
		{"403 token agent mismatch", e, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "secrets.echo", "agent_id": "mallory", "capability_token": e.sign("bot", "secrets.echo", 1)}, 403, "PolicyDeniedError"},
		{"404 secret", e, "POST", "/v1/secrets/default/missing/use", "", map[string]any{"action": "echo", "agent": "bot", "purpose": "p"}, 404, "SecretNotFoundError"},
		{"404 fingerprint", e, "GET", "/v1/secrets/default/missing", "", nil, 404, "SecretNotFoundError"},
		{"404 action", e, "POST", "/v1/secrets/default/k/use", "", map[string]any{"action": "nope", "agent": "bot", "purpose": "p"}, 404, "ActionNotFoundError"},
		{"404 capability", e, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "no.such", "agent_id": "bot", "capability_token": e.sign("bot", "no.such", 1)}, 404, "CapabilityNotFoundError"},
		{"409 no broker", e, "GET", "/v1/requests", "", nil, 409, "Conflict"},
		{"409 no broker approve", e, "POST", "/v1/requests/abc/approve", "", nil, 409, "Conflict"},
		{"422 set missing value", e, "POST", "/v1/secrets", "", map[string]any{"name": "x"}, 422, "RequestValidationError"},
		{"422 set name type", e, "POST", "/v1/secrets", "", map[string]any{"name": 5, "value": "x"}, 422, "RequestValidationError"},
		{"422 use missing agent", e, "POST", "/v1/secrets/default/k/use", "", map[string]any{"action": "echo"}, 422, "RequestValidationError"},
		{"422 simulate missing namespace", e, "POST", "/v1/policy/simulate", "", map[string]any{"agent": "bot"}, 422, "RequestValidationError"},
		{"422 rotate missing target", e, "POST", "/v1/rotate", "", "{}", 422, "RequestValidationError"},
		{"422 execute missing token", e, "POST", "/v1/capabilities/execute", "", map[string]any{"capability": "secrets.echo", "agent_id": "bot"}, 422, "RequestValidationError"},
		{"422 list limit not int", e, "GET", "/v1/secrets?limit=abc", "", nil, 422, "RequestValidationError"},
		{"422 audit limit not int", e, "GET", "/v1/audit?limit=1.5", "", nil, 422, "RequestValidationError"},
		{"422 capabilities/list agent", e, "GET", "/v1/capabilities/list", "", nil, 422, "RequestValidationError"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := c.env.agentTok
			switch c.token {
			case "-":
				tok = ""
			case "":
			default:
				tok = c.token
			}
			code, m, rec := c.env.call(c.method, c.path, tok, c.body)
			if code != c.status || m["error"] != c.errTyp {
				t.Fatalf("got %d %s, want %d %s", code, rec.Body.String(), c.status, c.errTyp)
			}
			// RGT-418/419: EVERY error answer carries an incident id, 401 too.
			if id, _ := m["incident_id"].(string); len(id) != 16 {
				t.Errorf("no incident_id on %d: %v", code, m)
			}
		})
	}

	// 429: the per-agent lease limiter (RateLimit 3).
	t.Run("429 rate limited", func(t *testing.T) {
		var last int
		var m map[string]any
		for i := 0; i < 5; i++ {
			last, m = e.agent("POST", "/v1/secrets/default/k/use", map[string]any{"action": "echo", "agent": "burst", "purpose": "p"})
		}
		if last != http.StatusTooManyRequests || m["error"] != "PermissionError" {
			t.Fatalf("got %d %v", last, m)
		}
		if !hasAction(e.auditRows(""), "RATE_LIMITED") {
			t.Error("RATE_LIMITED not audited")
		}
	})

	// 403 honeytoken (PermissionError).
	t.Run("403 honeytoken", func(t *testing.T) {
		if err := e.stack.Vault.Store().AddHoneytoken(context.Background(), "default", "trap"); err != nil {
			t.Skipf("no honeytoken seam: %v", err)
		}
		code, m := e.agent("GET", "/v1/secrets/default/trap", nil)
		if code != 403 || m["error"] != "PermissionError" {
			t.Fatalf("got %d %v", code, m)
		}
	})

	// 503 after the vault is closed.
	t.Run("503 closed", func(t *testing.T) {
		x := newEnv(t, envOpts{})
		_ = x.stack.Vault.Close()
		code, m := x.agent("GET", "/v1/secrets/default/k", nil)
		if code != 503 || m["error"] != "VaultUnavailable" {
			t.Fatalf("got %d %v", code, m)
		}
	})
}

// A handler's own error text never reaches the client (Python P0-2).
func TestCapabilityHandlerFailureIsSanitized(t *testing.T) {
	e := newEnv(t, envOpts{harness: true})
	if err := e.stack.Capabilities.Register(capabilities.Spec{
		Name: "test.boom", Description: "fails", Versions: []int{1},
		Handler: func(context.Context, map[string]any, vault.CapabilityContext) (any, error) {
			return nil, errors.New("upstream said sk-LEAKED-SECRET")
		},
	}); err != nil {
		t.Fatal(err)
	}
	code, m, rec := e.call("POST", "/v1/capabilities/execute", e.agentTok, map[string]any{
		"capability": "test.boom", "agent_id": "bot", "capability_token": e.sign("bot", "test.boom", 1),
	})
	if code != 500 || m["error"] != "ActionExecutionError" || strings.Contains(rec.Body.String(), "LEAKED") {
		t.Fatalf("got %d %s", code, rec.Body.String())
	}
	if m["detail"] != "capability 'test.boom' failed; see server logs for details" {
		t.Errorf("detail = %v", m["detail"])
	}
	if !hasAction(e.auditRows(""), "CAPABILITY_FAILED") {
		t.Error("CAPABILITY_FAILED not audited")
	}
}

// --- capabilities ---------------------------------------------------------

func TestCapabilityExecuteEndToEnd(t *testing.T) {
	e := newEnv(t, envOpts{harness: true})
	tok := e.sign("bot", "secrets.echo", 1)
	code, m, rec := e.call("POST", "/v1/capabilities/execute", e.agentTok, map[string]any{
		"capability": "secrets.echo", "agent_id": "bot", "capability_token": tok,
		"payload": map[string]any{"message": "hi"},
	})
	if code != 200 || m["ok"] != true || m["capability"] != "secrets.echo" {
		t.Fatalf("execute: %d %s", code, rec.Body.String())
	}
	res := m["result"].(map[string]any)
	if res["message"] != "hi" || res["agent_id"] != "bot" || res["capability"] != "secrets.echo" || res["token_id"] == "" {
		t.Errorf("result = %v", res)
	}
	if strings.Contains(rec.Body.String(), tok) {
		t.Error("response echoes the capability token")
	}

	// secrets.use through the capability path runs the same actions as /use.
	const value = "cap-SENTINEL"
	e.set("prod", "db", value, nil)
	code, m, rec = e.call("POST", "/v1/capabilities/execute", e.agentTok, map[string]any{
		"capability": "secrets.use", "agent_id": "bot", "capability_token": e.sign("bot", "secrets.use", 1),
		"payload": map[string]any{"secret_name": "db", "namespace": "prod", "action": "echo"},
	})
	if code != 200 || m["ok"] != true || strings.Contains(rec.Body.String(), value) {
		t.Fatalf("secrets.use: %d %s", code, rec.Body.String())
	}

	// A token is bound to its capability.
	code, m = e.agent("POST", "/v1/capabilities/execute", map[string]any{
		"capability": "secrets.use", "agent_id": "bot", "capability_token": e.sign("bot", "secrets.echo", 1),
	})
	if code != 403 || !strings.Contains(fmt.Sprint(m["detail"]), "token authorizes") {
		t.Errorf("capability mismatch: %d %v", code, m)
	}
	rows := e.auditRows("")
	for _, a := range []string{"CAPABILITY_EXECUTED", "CAPABILITY_DENIED", "HOOK_CAPABILITY"} {
		if !hasAction(rows, a) {
			t.Errorf("audit lacks %s", a)
		}
	}
	for _, r := range rows {
		if strings.Contains(fmt.Sprint(r["details"]), tok) {
			t.Errorf("capability token recorded in audit row %v", r)
		}
	}
}

func TestCapabilityListing(t *testing.T) {
	e := newEnv(t, envOpts{})
	m := e.mustOK("GET", "/v1/capabilities", nil)
	caps := m["capabilities"].([]any)
	if len(caps) != 2 {
		t.Fatalf("capabilities = %v", m)
	}
	first := caps[0].(map[string]any)
	if first["name"] != "secrets.echo" || fmt.Sprint(first["supported_versions"]) != "[1]" ||
		fmt.Sprint(first["params_schema"]) != "[message]" {
		t.Errorf("secrets.echo view = %v", first)
	}

	names := func(agent string) []string {
		m := e.mustOK("GET", "/v1/capabilities/list?agent="+agent, nil)
		if m["agent"] != agent {
			t.Errorf("agent = %v", m["agent"])
		}
		var out []string
		for _, c := range m["capabilities"].([]any) {
			out = append(out, c.(map[string]any)["name"].(string))
		}
		return out
	}
	if got := fmt.Sprint(names("bot")); got != "[secrets.echo secrets.use]" {
		t.Errorf("bot = %s", got)
	}
	if got := fmt.Sprint(names("limited")); got != "[secrets.echo]" {
		t.Errorf("limited = %s", got)
	}
	if got := fmt.Sprint(names("intruder")); got != "[]" {
		t.Errorf("intruder = %s", got)
	}

	// Default-deny vault: nothing is authorized.
	d := newEnv(t, envOpts{policy: "-"})
	if m := d.mustOK("GET", "/v1/capabilities/list?agent=bot", nil); len(m["capabilities"].([]any)) != 0 {
		t.Errorf("default deny lists %v", m)
	}

	// /v1/actions lists the real registry.
	acts := e.mustOK("GET", "/v1/actions", nil)["actions"].([]any)
	if len(acts) != 4 {
		t.Errorf("actions = %v", acts)
	}
}

// --- audit ----------------------------------------------------------------

func TestAuditEndpoint(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.set("default", "a", "1", nil)
	e.set("default", "b", "2", nil)
	rows := e.auditRows("")
	if len(rows) < 4 {
		t.Fatalf("rows = %v", rows)
	}
	// newest first, Python column set
	if rows[0]["id"].(float64) < rows[len(rows)-1]["id"].(float64) {
		t.Error("audit not newest first")
	}
	for _, k := range []string{"id", "action", "secret_name", "timestamp", "details", "prev_hash", "entry_hash", "policy_hash", "agent_id"} {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("row lacks %q: %v", k, rows[0])
		}
	}
	// HTTP_API rows: token id + ip + method + path, never the token
	found := false
	for _, r := range rows {
		d := fmt.Sprint(r["details"])
		if strings.Contains(d, e.agentTok) {
			t.Fatalf("token in audit row: %v", r)
		}
		if r["action"] == "HTTP_API" && regexp.MustCompile(`^token=[0-9a-f]{8} ip=127\.0\.0\.1 POST /v1/secrets$`).MatchString(d) {
			found = true
		}
	}
	if !found {
		t.Errorf("no HTTP_API row for POST /v1/secrets: %v", rows)
	}
	if m := e.mustOK("GET", "/v1/audit?limit=2", nil); len(m["entries"].([]any)) != 2 {
		t.Errorf("limit=2: %v", m)
	}
	if m := e.mustOK("GET", "/v1/audit", nil); len(m["entries"].([]any)) == 0 {
		t.Error("default limit returned nothing")
	}
}

// RGT-166: GET /v1/audit?capability=NAME keeps only that capability's rows.
func TestAuditCapabilityFilter(t *testing.T) {
	e := newEnv(t, envOpts{harness: true})
	exec := func(capability, agent string, payload map[string]any) int {
		code, _ := e.agent("POST", "/v1/capabilities/execute", map[string]any{
			"capability": capability, "agent_id": agent, "capability_token": e.sign(agent, capability, 1), "payload": payload,
		})
		return code
	}
	if exec("secrets.echo", "bot", nil) != 200 || exec("secrets.echo", "bot", map[string]any{"message": "2"}) != 200 {
		t.Fatal("echo failed")
	}
	if code := exec("secrets.use", "bot", map[string]any{"secret_name": "missing", "action": "nope"}); code != 500 {
		t.Fatalf("failing secrets.use: %d", code)
	}

	check := func(capability string, want map[string]int) {
		t.Helper()
		got := map[string]int{}
		for _, r := range e.auditRows("&capability=" + capability) {
			got[r["action"].(string)]++
			if !strings.Contains(fmt.Sprint(r["details"]), `"capability": "`+capability+`"`) {
				t.Errorf("row for another capability: %v", r)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("capability=%s: %v, want %v", capability, got, want)
		}
	}
	check("secrets.echo", map[string]int{"CAPABILITY_EXECUTED": 2, "HOOK_CAPABILITY": 2})
	check("secrets.use", map[string]int{"CAPABILITY_FAILED": 1, "HOOK_CAPABILITY": 1})
	check("no.such", map[string]int{})

	// limit counts matching rows only
	if m := e.mustOK("GET", "/v1/audit?capability=secrets.echo&limit=1", nil); len(m["entries"].([]any)) != 1 {
		t.Errorf("limit=1: %v", m)
	}
}

func TestAuditVerifyDetectsTampering(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.set("default", "a", "1", nil)
	if m := e.mustOK("POST", "/v1/audit/verify", nil); m["ok"] != true {
		t.Fatalf("fresh chain: %v", m)
	}
	db := e.rawDB()
	if _, err := db.Exec("UPDATE audit_logs SET details = 'forged' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if m := e.mustOK("POST", "/v1/audit/verify", nil); m["ok"] != false {
		t.Errorf("tampered chain verifies: %v", m)
	}
}

// --- rotation -------------------------------------------------------------

func TestRotateEndpoints(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.set("default", "k", "before-rotation", nil)
	fp0 := e.mustOK("GET", "/v1/secrets/default/k", nil)["fingerprint"]
	epoch0 := e.stack.Vault.KeyEpoch()

	m := e.mustOK("POST", "/v1/rotate", map[string]any{"target": "dek"})
	if m["ok"] != true || m["target"] != "dek" || int64(m["key_epoch"].(float64)) != epoch0+1 {
		t.Fatalf("rotate dek: %v", m)
	}
	if fp := e.mustOK("GET", "/v1/secrets/default/k", nil)["fingerprint"]; fp == fp0 {
		t.Error("DEK rotation did not re-encrypt (fingerprint unchanged)")
	}
	m = e.mustOK("POST", "/v1/rotate", map[string]any{"target": "master"})
	if int64(m["key_epoch"].(float64)) != epoch0+2 {
		t.Fatalf("rotate master: %v", m)
	}
	// still readable through the vault after both rotations
	if m := e.mustOK("POST", "/v1/secrets/default/k/lease", map[string]any{"agent": "bot", "purpose": "ci"}); m["value"] != "before-rotation" {
		t.Errorf("after rotation: %v", m)
	}
	if m := e.mustOK("POST", "/v1/audit/verify", nil); m["ok"] != true {
		t.Error("chain broken by rotation")
	}
	if !hasAction(e.auditRows(""), "ROTATE") {
		t.Error("rotation not audited")
	}
}

// --- policy simulate ------------------------------------------------------

func TestPolicySimulate(t *testing.T) {
	e := newEnv(t, envOpts{})
	m := e.mustOK("POST", "/v1/policy/simulate", map[string]any{"agent": "bot", "namespace": "prod", "purpose": "ci"})
	if m["allowed"] != true || m["reason"] != "Allow rule matched" || m["matched_rule"] == nil {
		t.Errorf("allow: %v", m)
	}
	m = e.mustOK("POST", "/v1/policy/simulate", map[string]any{"agent": "intruder", "namespace": "prod", "action": "write"})
	if m["allowed"] != false || m["reason"] != "Explicit deny rule matched" {
		t.Errorf("deny: %v", m)
	}
	d := newEnv(t, envOpts{policy: "-"})
	m = d.mustOK("POST", "/v1/policy/simulate", map[string]any{"agent": "bot", "namespace": "prod"})
	if m["allowed"] != false || m["matched_rule"] != nil {
		t.Errorf("default deny: %v", m)
	}
	if !hasAction(e.auditRows(""), "SIMULATION_RUN") {
		t.Error("SIMULATION_RUN not audited")
	}
}

// --- approval flow with TOTP ----------------------------------------------

func waitPending(t *testing.T, e *testEnv, n int) []any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		code, m, rec := e.call("GET", "/v1/requests", e.opTok, nil)
		if code != 200 {
			t.Fatalf("list requests: %d %s", code, rec.Body.String())
		}
		if reqs := m["requests"].([]any); len(reqs) >= n {
			return reqs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %d pending request(s)", n)
	return nil
}

func TestApprovalFlowWithTOTP(t *testing.T) {
	e := newEnv(t, envOpts{approval: true, operator: true, totp: true, approvalTTL: 30})
	e.set("prod", "guarded", "2fa-SENTINEL", map[string]any{"require_2fa": true})

	type result struct {
		code int
		body map[string]any
	}
	use := func() chan result {
		ch := make(chan result, 1)
		go func() {
			code, m, _ := e.call("POST", "/v1/secrets/prod/guarded/use", e.agentTok,
				map[string]any{"action": "echo", "agent": "bot", "purpose": "deploy"})
			ch <- result{code, m}
		}()
		return ch
	}

	done := use()
	reqs := waitPending(t, e, 1)
	r0 := reqs[0].(map[string]any)
	if r0["agent"] != "bot" || r0["namespace"] != "prod" || r0["secret_name"] != "guarded" ||
		r0["purpose"] != "deploy" || r0["action"] != "read" || r0["require_2fa"] != true || r0["created_at"].(float64) < 1e9 {
		t.Fatalf("pending request = %v", r0)
	}
	if strings.Contains(fmt.Sprint(reqs), "2fa-SENTINEL") {
		t.Fatal("pending request carries the value")
	}
	id := r0["request_id"].(string)

	// Scopes: the agent token cannot approve, the operator token cannot use the agent API.
	if code, _, _ := e.call("GET", "/v1/requests", e.agentTok, nil); code != 401 {
		t.Errorf("agent token on /v1/requests: %d", code)
	}
	if code, _, _ := e.call("POST", "/v1/requests/"+id+"/approve", e.agentTok, map[string]any{}); code != 401 {
		t.Errorf("agent token approves: %d", code)
	}
	if code, _, _ := e.call("GET", "/v1/secrets?namespace=prod", e.opTok, nil); code != 401 {
		t.Errorf("operator token on agent API: %d", code)
	}

	// Missing and wrong codes are refused and the request stays pending.
	for _, body := range []any{nil, map[string]any{"totp_code": "000000"}} {
		code, m, _ := e.call("POST", "/v1/requests/"+id+"/approve", e.opTok, body)
		if code != 400 || m["error"] != "ApprovalError" {
			t.Fatalf("approve %v: %d %v", body, code, m)
		}
	}
	code, m, _ := e.call("POST", "/v1/requests/"+id+"/approve", e.opTok, map[string]any{"totp_code": "123"})
	if code != 400 {
		t.Fatalf("short code: %d %v", code, m)
	}
	now := time.Now()
	good, err := totp.Generate(e.totpSecret, now)
	if err != nil {
		t.Fatal(err)
	}
	if good == "000000" {
		t.Skip("TOTP code collides with the wrong-code probe")
	}
	code, m, _ = e.call("POST", "/v1/requests/"+id+"/approve", e.opTok, map[string]any{"totp_code": good, "operator": "alice"})
	if code != 200 || m["decision"] != "approved" || m["request_id"] != id {
		t.Fatalf("approve: %d %v", code, m)
	}
	if res := <-done; res.code != 200 || res.body["ok"] != true {
		t.Fatalf("agent after approval: %d %v", res.code, res.body)
	}
	// Deciding twice fails.
	if code, _, _ := e.call("POST", "/v1/requests/"+id+"/deny", e.opTok, nil); code != 400 {
		t.Errorf("second decision: %d", code)
	}

	// A replayed code is refused (replay-guarded verifier).
	done = use()
	id2 := waitPending(t, e, 1)[0].(map[string]any)["request_id"].(string)
	if code, _, _ := e.call("POST", "/v1/requests/"+id2+"/approve", e.opTok, map[string]any{"totp_code": good}); code != 400 {
		t.Errorf("replayed TOTP accepted: %d", code)
	}
	// Deny: the agent gets a 403 and an APPROVAL_DENIED row.
	code, m, _ = e.call("POST", "/v1/requests/"+id2+"/deny", e.opTok, map[string]any{"reason": "not today", "operator": "alice"})
	if code != 200 || m["decision"] != "denied" {
		t.Fatalf("deny: %d %v", code, m)
	}
	if res := <-done; res.code != 403 || res.body["error"] != "PolicyDeniedError" || !strings.Contains(fmt.Sprint(res.body["detail"]), "not today") {
		t.Fatalf("agent after deny: %d %v", res.code, res.body)
	}
	if code, _, _ := e.call("POST", "/v1/requests/unknown/approve", e.opTok, nil); code != 400 {
		t.Errorf("unknown id: %d", code)
	}
	rows := e.auditRows("")
	if !hasAction(rows, "APPROVAL_DENIED") || !hasAction(rows, "HTTP_OPERATOR") {
		t.Error("approval audit rows missing")
	}
}

// Without --operator-token-file the agent token still reaches /v1/requests
// (Python), but since H2 it can no longer approve its OWN request:
// separation of duties refuses it, and the request stays pending.
func TestApprovalOperatorFallbackAndNo2FA(t *testing.T) {
	e := newEnv(t, envOpts{approval: true, approvalTTL: 30})
	e.set("prod", "plain", "v", nil)
	done := make(chan int, 1)
	go func() {
		code, _, _ := e.call("POST", "/v1/secrets/prod/plain/use", e.agentTok,
			map[string]any{"action": "echo", "agent": "bot", "purpose": "p"})
		done <- code
	}()
	id := waitPending(t, e, 1)[0].(map[string]any)["request_id"].(string)
	code, m, _ := e.call("POST", "/v1/requests/"+id+"/approve", e.agentTok, nil)
	if code != 403 || m["error"] != "SeparationOfDutiesError" {
		t.Fatalf("self-approval: %d %v", code, m)
	}
	// Refusing is always allowed: the agent's request is denied.
	if code, _, _ := e.call("POST", "/v1/requests/"+id+"/deny", e.agentTok, nil); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	if code := <-done; code != 403 {
		t.Fatalf("use: %d", code)
	}
}

// --- plaintext lease route (RGT-504; legacy mode here, scopes in authz_test) --

func TestLeaseRoute(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.set("ns", "k", "v1-value", nil)
	e.set("ns", "other", "v2-value", nil)

	code, m, rec := e.call("POST", "/v1/secrets/ns/k/lease", e.agentTok, map[string]any{"agent": "bot", "purpose": "ci"})
	if code != 200 || m["value"] != "v1-value" || strings.Contains(fmt.Sprint(m), "v2-value") {
		t.Fatalf("lease = %d %v", code, m)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("lease response is cacheable")
	}
	// audited as a lease and as an HTTP plaintext read
	rows := e.auditRows("")
	var read map[string]any
	for _, r := range rows {
		if r["action"] == "SECRET_READ" {
			read = r
			break
		}
	}
	if read == nil || read["secret_name"] != "k" || read["agent_id"] != "bot" ||
		!strings.Contains(fmt.Sprint(read["details"]), "Purpose: ci") {
		t.Errorf("SECRET_READ row = %v", read)
	}
	if !hasAction(rows, "LEASE_GRANTED") {
		t.Error("no LEASE_GRANTED")
	}
	// ABAC applies
	if code, m := e.agent("POST", "/v1/secrets/ns/k/lease", map[string]any{"agent": "intruder"}); code != 403 {
		t.Errorf("intruder: %d %v", code, m)
	}
	// missing: 404
	if code, m := e.agent("POST", "/v1/secrets/ns/missing/lease", map[string]any{"agent": "bot", "purpose": "ci"}); code != 404 {
		t.Errorf("missing = %d %v", code, m)
	}
	// unknown body fields are refused (mass assignment, RGT-352)
	if code, _ := e.agent("POST", "/v1/secrets/ns/k/lease", map[string]any{"agent": "bot", "admin": true}); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
	// a non-UTF-8 value cannot be returned as JSON
	if err := e.stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
		Name: "bin", Namespace: "ns", Agent: "bot", Purpose: "p", Value: []byte{0xff, 0xfe, 0x01},
	}); err != nil {
		t.Fatal(err)
	}
	if code, m := e.agent("POST", "/v1/secrets/ns/bin/lease", map[string]any{"agent": "bot", "purpose": "ci"}); code != 400 {
		t.Errorf("binary value: %d %v", code, m)
	}
	// the removed ?name= lookup answers 400 and never a value
	if code, m := e.agent("GET", "/v1/secrets?namespace=ns&name=k", nil); code != 400 || strings.Contains(fmt.Sprint(m), "v1-value") {
		t.Errorf("?name= = %d %v", code, m)
	}
}

// --- concurrency (run with -race) -----------------------------------------

func TestConcurrentRequests(t *testing.T) {
	e := newEnv(t, envOpts{harness: true})
	var wg sync.WaitGroup
	errs := make(chan string, 256)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				name := fmt.Sprintf("k%d-%d", g, i)
				steps := []struct {
					method, path string
					body         any
				}{
					{"POST", "/v1/secrets", map[string]any{"name": name, "value": "v", "namespace": "c", "agent": "bot"}},
					{"GET", "/v1/secrets?namespace=c&agent=bot", nil},
					{"GET", "/v1/secrets/c/" + name, nil},
					{"POST", "/v1/secrets/c/" + name + "/use", map[string]any{"action": "echo", "agent": fmt.Sprintf("a%d", g), "purpose": "p"}},
					{"POST", "/v1/capabilities/execute", map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": e.sign("bot", "secrets.echo", 1)}},
					{"GET", "/v1/audit?limit=10", nil},
				}
				for _, s := range steps {
					if code, m, _ := e.call(s.method, s.path, e.agentTok, s.body); code != 200 {
						errs <- fmt.Sprintf("%s %s: %d %v", s.method, s.path, code, m)
					}
				}
			}
		}(g)
	}
	// A DEK rotation in the middle of the traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if code, m, _ := e.call("POST", "/v1/rotate", e.agentTok, map[string]any{"target": "dek"}); code != 200 {
			errs <- fmt.Sprintf("rotate: %d %v", code, m)
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if m := e.mustOK("POST", "/v1/audit/verify", nil); m["ok"] != true {
		t.Error("chain does not verify after concurrent traffic")
	}
}

// --- stack / helpers ------------------------------------------------------

func TestOpenStackErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := dir + "/v/vault.db"
	mem := providerstest.NewMemory()
	cases := map[string]StackOptions{
		"bad provider":       {DBPath: db, Provider: "nope"},
		"missing policy":     {DBPath: db, MasterProvider: mem, PolicyFile: dir + "/none.yaml"},
		"totp w/o approval":  {DBPath: db, MasterProvider: mem, TOTPSecretFile: writeFile(t, dir+"/t", "JBSWY3DPEHPK3PXP")},
		"empty totp file":    {DBPath: db, MasterProvider: mem, RequireApproval: true, TOTPSecretFile: writeFile(t, dir+"/e", "\n")},
		"bad totp secret":    {DBPath: db, MasterProvider: mem, RequireApproval: true, TOTPSecretFile: writeFile(t, dir+"/b", "!!!")},
		"short harness key":  {DBPath: db, MasterProvider: mem, HarnessKeyFile: writeFile(t, dir+"/h", "short")},
		"missing harness":    {DBPath: db, MasterProvider: mem, HarnessKeyFile: dir + "/nokey"},
		"bad policy yaml":    {DBPath: db, MasterProvider: mem, PolicyFile: writeFile(t, dir+"/p.yaml", "rules: [")},
		"unreadable db path": {DBPath: writeFile(t, dir+"/file", "x") + "/vault.db", MasterProvider: mem, KDFParams: testKDF},
	}
	for name, o := range cases {
		o.KDFParams = testKDF
		if s, err := OpenStack(ctx, o); err == nil {
			_ = s.Close()
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := NewProvider("keyring"); err != nil {
		t.Error(err)
	}
}

func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for in, want := range map[string]string{
		"~":                 home,
		"~/.secure-vault/x": home + "/.secure-vault/x",
		"/abs/path":         "/abs/path",
		"rel":               "rel",
		"~user/x":           "~user/x",
	} {
		got, err := ExpandHome(in)
		if err != nil || filepathToSlash(got) != filepathToSlash(want) {
			t.Errorf("ExpandHome(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func filepathToSlash(p string) string { return strings.ReplaceAll(p, "\\", "/") }

func TestFingerprintMatchesCiphertextHash(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.set("default", "k", "v", nil)
	var ct []byte
	if err := e.rawDB().QueryRow(
		"SELECT ciphertext FROM secrets WHERE namespace='default' AND name='k'").Scan(&ct); err != nil {
		t.Skipf("schema probe: %v", err)
	}
	sum := sha256.Sum256(ct)
	if fp := e.mustOK("GET", "/v1/secrets/default/k", nil)["fingerprint"]; fp != hex.EncodeToString(sum[:])[:8] {
		t.Errorf("fingerprint %v != sha256(ciphertext)[:8]", fp)
	}
}

// --- headers / XML policy stubs (RGT-452, RGT-437) -------------------------

func TestServerHeaderStrippedAndSecurityHeaders(t *testing.T) {
	e := newEnv(t, envOpts{})
	_, _, rec := e.call("GET", "/healthz", "", nil)
	if rec.Header().Get("Server") != "" || rec.Header().Get("X-Powered-By") != "" {
		t.Errorf("metadata headers leak: %v", rec.Header())
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
	} {
		if rec.Header().Get(k) != want {
			t.Errorf("%s = %q", k, rec.Header().Get(k))
		}
	}
}

func TestXMLPoliciesCacheDisabled(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, path := range []string{"/crossdomain.xml", "/clientaccesspolicy.xml"} {
		code, _, rec := e.call("GET", path, "", nil)
		if code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `permitted-cross-domain-policies="none"`) {
			t.Errorf("%s: %d %s", path, code, rec.Body.String())
		}
		for k, want := range map[string]string{
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0",
		} {
			if rec.Header().Get(k) != want {
				t.Errorf("%s %s = %q", path, k, rec.Header().Get(k))
			}
		}
	}
}

func TestTokenIDFromContext(t *testing.T) {
	e := newEnv(t, envOpts{})
	var got string
	mw := NewMiddleware(auth.NewTokenStore(e.dir + "/agent.token"))
	h := mw.AuthMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = TokenIDFromContext(r.Context()) }))
	req := httptest.NewRequest("GET", "/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+e.agentTok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != auth.TokenID(e.agentTok) {
		t.Errorf("token id = %q", got)
	}
}
