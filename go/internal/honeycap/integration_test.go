package honeycap_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/honeycap"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/vault"
)

const allowAll = `honey_capabilities:
  - payments.wire.unrestricted
rules:
  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*"}
`

var testKDF = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

type recorder struct {
	mu     sync.Mutex
	events []approval.Event
}

func (r *recorder) Notify(_ context.Context, e approval.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) count(kind approval.EventKind) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func (r *recorder) all() []approval.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]approval.Event(nil), r.events...)
}

func signer(t *testing.T) *captoken.HMACTokenVerifier {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	v, err := captoken.NewHMACTokenVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type vaultEnv struct {
	v     *vault.Vault
	reg   *capabilities.Registry
	sign  *captoken.HMACTokenVerifier
	notes *recorder
	honey *honeycap.Set
}

func openVault(t *testing.T, honey bool) *vaultEnv {
	t.Helper()
	e := &vaultEnv{reg: capabilities.NewDefault(nil), sign: signer(t), notes: &recorder{}}
	cfg := vault.Config{
		DBPath:        filepath.Join(t.TempDir(), "v", "vault.db"),
		Provider:      providerstest.NewMemory(),
		PolicyYAML:    allowAll,
		Capabilities:  e.reg,
		TokenVerifier: e.sign,
		RateLimit:     1_000_000,
		KDFParams:     testKDF,
	}
	if honey {
		s, err := honeycap.FromPolicyYAML(allowAll, honeycap.WithNotifier(e.notes))
		if err != nil {
			t.Fatal(err)
		}
		e.honey = s
		cfg.HoneyCapabilities = s
	}
	v, err := vault.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	e.v = v
	return e
}

func (e *vaultEnv) rows(t *testing.T) []store.AuditRow {
	t.Helper()
	rows, err := e.v.AuditLog(context.Background(), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows
}

func actions(rows []store.AuditRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Action)
	}
	return out
}

func countAction(rows []store.AuditRow, action string) int {
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

// probes are the ways an attacker can call a capability by name.
type probe struct {
	label string
	token func(e *vaultEnv, name string) string
}

var probes = []probe{
	{"garbage token", func(*vaultEnv, string) string { return "not-a-token" }},
	{"well-formed forged token", func(_ *vaultEnv, name string) string {
		other := signerFor()
		tok, _ := other.Sign("mallory", name, 1, nil, 60)
		return tok
	}},
	{"stolen token for another capability", func(e *vaultEnv, _ string) string {
		tok, _ := e.sign.Sign("mallory", "secrets.echo", 1, nil, 60)
		return tok
	}},
	{"genuine token for the name itself", func(e *vaultEnv, name string) string {
		tok, _ := e.sign.Sign("mallory", name, 1, nil, 60)
		return tok
	}},
}

var otherSigner *captoken.HMACTokenVerifier

func signerFor() *captoken.HMACTokenVerifier {
	if otherSigner == nil {
		otherSigner, _ = captoken.NewHMACTokenVerifier([]byte("an-unrelated-32-byte-test-key!!!"))
	}
	return otherSigner
}

// TestVaultIndistinguishable: for every probe, a honey name gets the same
// error (sentinels and message, modulo the name) as an ordinary unregistered
// name, and only the honey call writes HONEY_CAPABILITY_TRIGGERED.
func TestVaultIndistinguishable(t *testing.T) {
	const honeyName, plainName = "aws.admin.full", "billing.reports"
	kinds := []error{vault.ErrPolicyDenied, vault.ErrCapabilityNotFound, vault.ErrValidation, vault.ErrCapabilityVersion}
	for _, p := range probes {
		t.Run(p.label, func(t *testing.T) {
			e := openVault(t, true)
			call := func(name string) error {
				_, err := e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{
					Capability: name, Agent: "mallory", Token: p.token(e, name), Payload: map[string]any{"k": "v"},
				})
				return err
			}
			before := len(e.rows(t))
			errPlain := call(plainName)
			plainRows := e.rows(t)[before:]
			before = len(e.rows(t))
			errHoney := call(honeyName)
			honeyRows := e.rows(t)[before:]
			if errPlain == nil || errHoney == nil {
				t.Fatalf("plain=%v honey=%v: both must be denied", errPlain, errHoney)
			}
			if got, want := strings.ReplaceAll(errHoney.Error(), honeyName, "X"), strings.ReplaceAll(errPlain.Error(), plainName, "X"); got != want {
				t.Fatalf("oracle: honey error %q != ordinary error %q", got, want)
			}
			for _, k := range kinds {
				if errors.Is(errHoney, k) != errors.Is(errPlain, k) {
					t.Fatalf("oracle: errors.Is(%v) differs", k)
				}
			}
			if countAction(plainRows, honeycap.Event) != 0 {
				t.Fatal("ordinary name tripped the trap")
			}
			if countAction(honeyRows, honeycap.Event) != 1 {
				t.Fatalf("honey rows = %v", actions(honeyRows))
			}
			// Apart from the honey row, the audit trail is the ordinary one.
			if got, want := strings.Join(actions(honeyRows[1:]), ","), strings.Join(actions(plainRows), ","); honeyRows[0].Action != honeycap.Event || got != want {
				t.Fatalf("audit trail %v vs ordinary %v", actions(honeyRows), actions(plainRows))
			}
			if e.notes.count(approval.EventHoneyCapability) != 1 {
				t.Fatalf("alerts = %d", e.notes.count(approval.EventHoneyCapability))
			}
		})
	}
}

// TestHoneyAuditRowShape pins the stable event name and the row contents,
// and that neither the row nor the alert carries the token or payload values.
func TestHoneyAuditRowShape(t *testing.T) {
	e := openVault(t, true)
	const secretValue = "AKIA-super-secret-value-123"
	tok, _ := e.sign.Sign("mallory", "payments.wire.unrestricted", 1, nil, 60)
	_, err := e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{
		Capability: "Payments.Wire.Unrestricted", Version: 2, Agent: "mallory", Token: tok,
		Payload: map[string]any{"password": secretValue, "b": 1},
	})
	if err == nil {
		t.Fatal("honey capability ran")
	}
	var row *store.AuditRow
	for _, r := range e.rows(t) {
		if r.Action == "HONEY_CAPABILITY_TRIGGERED" {
			r := r
			row = &r
		}
	}
	if row == nil {
		t.Fatal("no HONEY_CAPABILITY_TRIGGERED row")
	}
	want := `{"agent": "mallory", "capability": "Payments.Wire.Unrestricted", "capability_version": 2, "severity": "critical", "source": "capability.execute", "token_presented": true, "payload_keys": 2, "probes_in_window": 1}`
	if row.Details.String != want || row.SecretName.Valid {
		t.Fatalf("details = %s", row.Details.String)
	}
	ev := e.notes.all()
	if len(ev) != 1 {
		t.Fatalf("events = %v", ev)
	}
	for _, s := range []string{row.Details.String, ev[0].Detail, ev[0].Agent, ev[0].Operator, ev[0].RequestID} {
		if strings.Contains(s, secretValue) || strings.Contains(s, tok) || strings.Contains(s, strings.Split(tok, ".")[1]) {
			t.Fatalf("secret material leaked: %q", s)
		}
	}
	if ok, err := e.v.VerifyAuditChain(context.Background()); err != nil || !ok {
		t.Fatalf("audit chain: %v %v", ok, err)
	}
}

// TestNoDetectorNoRow: without a detector the vault behaves as before.
func TestNoDetectorNoRow(t *testing.T) {
	e := openVault(t, false)
	_, _ = e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: "aws.admin.full", Agent: "m", Token: "x"})
	if countAction(e.rows(t), honeycap.Event) != 0 {
		t.Fatal("row without a detector")
	}
}

// lookupOnly is a registry without Names/ReserveNames: the vault can only
// check it by exact Lookup at Open, so a later addition must still never run.
type lookupOnly struct {
	mu sync.Mutex
	m  map[string]vault.CapabilitySpec
}

func (l *lookupOnly) Lookup(name string) (vault.CapabilitySpec, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.m[name]; ok {
		return s, nil
	}
	return nil, vault.ErrCapabilityNotFound
}

// TestHoneyNeverRuns: a honey name that appears in a registry after Open is
// still never executed, even with a genuine token.
func TestHoneyNeverRuns(t *testing.T) {
	sign := signer(t)
	reg := &lookupOnly{m: map[string]vault.CapabilitySpec{}}
	v, err := vault.Open(context.Background(), vault.Config{
		DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: providerstest.NewMemory(), PolicyYAML: allowAll,
		Capabilities: reg, TokenVerifier: sign, HoneyCapabilities: honeycap.Default(honeycap.WithNotifier(&recorder{})), KDFParams: testKDF,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ran := false
	spec := &capabilities.Spec{Name: "aws.admin.full", Versions: []int{1}, Handler: func(context.Context, map[string]any, vault.CapabilityContext) (any, error) {
		ran = true
		return "pwned", nil
	}}
	reg.mu.Lock()
	reg.m["aws.admin.full"] = spec
	reg.mu.Unlock()
	tok, _ := sign.Sign("mallory", "aws.admin.full", 1, nil, 60)
	res, err := v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: "aws.admin.full", Agent: "mallory", Token: tok})
	if ran || res != nil || !errors.Is(err, vault.ErrCapabilityNotFound) {
		t.Fatalf("ran=%v res=%v err=%v", ran, res, err)
	}
}

// TestRegisterRefusesHoneyAfterOpen: the real registry refuses a honey name
// (in any spelling) once a vault with traps has opened on it.
func TestRegisterRefusesHoneyAfterOpen(t *testing.T) {
	e := openVault(t, true)
	h := func(context.Context, map[string]any, vault.CapabilityContext) (any, error) { return nil, nil }
	for _, n := range []string{"aws.admin.full", "AWS.Admin.Full", " iam.root.assume", "Payments.Wire.Unrestricted"} {
		if err := e.reg.Register(capabilities.Spec{Name: n, Handler: h}); !errors.Is(err, capabilities.ErrRegistration) {
			t.Errorf("%q: %v", n, err)
		}
	}
	if err := e.reg.Register(capabilities.Spec{Name: "billing.reports", Handler: h}); err != nil {
		t.Fatalf("ordinary name refused: %v", err)
	}
}

// TestOpenRefusesNormalizedCollision (review MED-2): a registered capability
// that differs from a honey name only in case or whitespace must stop
// startup, not be silently shadowed by the trap.
func TestOpenRefusesNormalizedCollision(t *testing.T) {
	h := func(context.Context, map[string]any, vault.CapabilityContext) (any, error) { return nil, nil }
	for _, c := range []struct {
		name, policy, register string
	}{
		{"policy honey shadows built-in", "honey_capabilities: [Secrets.Echo]\nrules: []\n", ""},
		{"registered case variant", "", "Aws.Admin.Full"},
		{"registered exact", "", "iam.root.assume"},
	} {
		t.Run(c.name, func(t *testing.T) {
			reg := capabilities.NewDefault(nil)
			if c.register != "" {
				if err := reg.Register(capabilities.Spec{Name: c.register, Handler: h}); err != nil {
					t.Fatal(err)
				}
			}
			set, err := honeycap.FromPolicyYAML(c.policy)
			if err != nil {
				t.Fatal(err)
			}
			_, err = vault.Open(context.Background(), vault.Config{
				DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: providerstest.NewMemory(),
				Capabilities: reg, HoneyCapabilities: set, KDFParams: testKDF,
			})
			if err == nil || !strings.Contains(err.Error(), "matches a honey capability name") {
				t.Fatalf("Open = %v", err)
			}
		})
	}
	// The same through the server stack: startup fails.
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("honey_capabilities: [Secrets.Echo]\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath: filepath.Join(dir, "v", "vault.db"), PolicyFile: p, MasterProvider: providerstest.NewMemory(), KDFParams: testKDF,
	}); err == nil || !strings.Contains(err.Error(), "secrets.echo") {
		t.Fatalf("OpenStack = %v", err)
	}
}

// TestHoneyAuditFloodCapped (review MED-1b): a flood from one agent writes
// HoneyAuditPerAgent rows, then one per power of two, each with the count.
func TestHoneyAuditFloodCapped(t *testing.T) {
	e := openVault(t, true)
	for i := 0; i < 300; i++ {
		_, _ = e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: "aws.admin.full", Agent: "mallory", Token: "x.y"})
	}
	_, _ = e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: "aws.admin.full", Agent: "eve", Token: "x.y"})
	var mallory, eve []string
	for _, r := range e.rows(t) {
		if r.Action != honeycap.Event {
			continue
		}
		if strings.Contains(r.Details.String, `"agent": "mallory"`) {
			mallory = append(mallory, r.Details.String)
		} else {
			eve = append(eve, r.Details.String)
		}
	}
	if len(mallory) != vault.HoneyAuditPerAgent+3 || len(eve) != 1 { // 1..32, 64, 128, 256
		t.Fatalf("rows: mallory=%d eve=%d", len(mallory), len(eve))
	}
	if !strings.Contains(mallory[len(mallory)-1], `"probes_in_window": 256`) {
		t.Fatalf("last row = %s", mallory[len(mallory)-1])
	}
	if e.notes.count(approval.EventHoneyCapability) != 2 { // one per agent
		t.Fatalf("alerts = %d", e.notes.count(approval.EventHoneyCapability))
	}
}

// TestHoneyOversizeNameClipped (review MED-1a): whitespace padding still
// trips the trap but cannot blow up the audit row or the alert.
func TestHoneyOversizeNameClipped(t *testing.T) {
	e := openVault(t, true)
	name := strings.Repeat(" ", 200_000) + "aws.admin.full"
	_, err := e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: name, Agent: "mallory", Token: "x.y"})
	if err == nil {
		t.Fatal("ran")
	}
	// (The ordinary CAPABILITY_DENIED row echoes the requested name as it
	// always has for any name; only the honey row is new here.)
	found := false
	for _, r := range e.rows(t) {
		if r.Action != honeycap.Event {
			continue
		}
		found = true
		if len(r.Details.String) > 1024 || !strings.Contains(r.Details.String, "(+199886 bytes)") {
			t.Fatalf("honey row %d bytes: %.300s", len(r.Details.String), r.Details.String)
		}
	}
	if !found {
		t.Fatal("no honey row")
	}
	ev := e.notes.all()
	if len(ev) != 1 || len(ev[0].Detail) > 512 || !strings.Contains(ev[0].Detail, "(+199886 bytes)") {
		t.Fatalf("alert = %+v", ev)
	}
}

func TestOpenRefusesRegisteredHoney(t *testing.T) {
	reg := capabilities.NewDefault(nil)
	if err := reg.Register(capabilities.Spec{Name: "iam.root.assume", Handler: func(context.Context, map[string]any, vault.CapabilityContext) (any, error) { return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	_, err := vault.Open(context.Background(), vault.Config{
		DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: providerstest.NewMemory(),
		Capabilities: reg, HoneyCapabilities: honeycap.Default(), KDFParams: testKDF,
	})
	if err == nil || !strings.Contains(err.Error(), "iam.root.assume") {
		t.Fatalf("Open = %v", err)
	}
}

// TestHoneyRace: concurrent probes each write exactly one row and one alert,
// and the hash chain stays valid.
func TestHoneyRace(t *testing.T) {
	e := openVault(t, true)
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := honeycap.DefaultNames[i%len(honeycap.DefaultNames)]
			if i%2 == 0 {
				name = "billing.reports" // ordinary traffic interleaved
			}
			_, _ = e.v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: name, Agent: "mallory", Token: "x.y"})
		}(i)
	}
	wg.Wait()
	if got := countAction(e.rows(t), honeycap.Event); got != n/2 {
		t.Fatalf("honey rows = %d, want %d", got, n/2)
	}
	// Alerts are de-duplicated per (agent, name): one per default name.
	if e.honey.Trips() != n/2 || e.notes.count(approval.EventHoneyCapability) != len(honeycap.DefaultNames) {
		t.Fatalf("trips = %d alerts = %d", e.honey.Trips(), e.notes.count(approval.EventHoneyCapability))
	}
	if ok, err := e.v.VerifyAuditChain(context.Background()); err != nil || !ok {
		t.Fatalf("chain: %v %v", ok, err)
	}
}

// ---- HTTP: the attacker's actual view, through the real stack wiring ----

type httpEnv struct {
	h     http.Handler
	stack *server.Stack
	tok   string
	sign  *captoken.HMACTokenVerifier
	notes *recorder
}

func openHTTP(t *testing.T) *httpEnv {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	hexKey := hex.EncodeToString(key)
	notes := &recorder{}
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath:         filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:     write("policy.yaml", allowAll),
		MasterProvider: providerstest.NewMemory(),
		HarnessKeyFile: write("harness.key", hexKey+"\n"),
		Notifier:       notes,
		KDFParams:      testKDF,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	tokens := auth.OpenStore(filepath.Join(dir, "tokens.json"))
	bearer, _, err := tokens.Mint(auth.MintOptions{Agent: "mallory", Scopes: []auth.Scope{auth.ScopeAgent}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.New(server.Config{Vault: stack.Vault, Tokens: tokens, Notifier: notes, Actions: stack.Actions, Capabilities: stack.Capabilities})
	if err != nil {
		t.Fatal(err)
	}
	sign, err := captoken.NewHMACTokenVerifier([]byte(hexKey))
	if err != nil {
		t.Fatal(err)
	}
	return &httpEnv{h: h, stack: stack, tok: bearer, sign: sign, notes: notes}
}

func (e *httpEnv) exec(t *testing.T, name, capToken string) (int, string, time.Duration) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"capability": name, "capability_token": capToken, "payload": map[string]any{"k": "v"}})
	req := httptest.NewRequest("POST", "/v1/capabilities/execute", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("Authorization", "Bearer "+e.tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	start := time.Now()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), time.Since(start)
}

// normalizeBody drops per-request ids and replaces the probed name.
func normalizeBody(t *testing.T, body, name string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	delete(m, "request_id")
	delete(m, "incident_id") // random per response, for honey and ordinary alike
	raw, _ := json.Marshal(m)
	return strings.ReplaceAll(string(raw), name, "X")
}

func TestHTTPIndistinguishable(t *testing.T) {
	e := openHTTP(t)
	const plain = "billing.reports"
	honeyNames := append([]string{"payments.wire.unrestricted"}, honeycap.DefaultNames...) // policy-file name too
	// Tokens are single-use (replay guard) and Sign is deterministic per
	// second, so every genuine token gets its own TTL to stay unique.
	ttl := 60
	next := func() int { ttl++; return ttl }
	for _, honey := range honeyNames {
		for _, mk := range []struct {
			label string
			tok   func(name string) string
		}{
			{"garbage", func(string) string { return "garbage" }},
			{"other capability", func(string) string { s, _ := e.sign.Sign("mallory", "secrets.echo", 1, nil, next()); return s }},
			{"genuine", func(n string) string { s, _ := e.sign.Sign("mallory", n, 1, nil, next()); return s }},
		} {
			pc, pb, _ := e.exec(t, plain, mk.tok(plain))
			hc, hb, _ := e.exec(t, honey, mk.tok(honey))
			if pc != hc || normalizeBody(t, pb, plain) != normalizeBody(t, hb, honey) {
				t.Fatalf("%s/%s oracle:\n ordinary %d %s\n honey    %d %s", honey, mk.label, pc, pb, hc, hb)
			}
			if pc < 400 {
				t.Fatalf("%s/%s: not denied (%d)", honey, mk.label, pc)
			}
		}
	}
	rows, err := e.stack.Vault.AuditLog(context.Background(), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	want := len(honeyNames) * 3
	if got := countAction(rows, honeycap.Event); got != want {
		t.Fatalf("honey rows = %d, want %d", got, want)
	}
	// One alert per (agent, honey name) per window.
	if got := e.notes.count(approval.EventHoneyCapability); got != len(honeyNames) {
		t.Fatalf("alerts through the stack notifier = %d, want %d", got, len(honeyNames))
	}
}

// TestStackRejectsBadHoneyConfig: a malformed honey list fails startup.
func TestStackRejectsBadHoneyConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("honey_capabilities: oops\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath: filepath.Join(dir, "v", "vault.db"), PolicyFile: p, MasterProvider: providerstest.NewMemory(), KDFParams: testKDF,
	})
	if !errors.Is(err, honeycap.ErrConfig) {
		t.Fatalf("OpenStack = %v", err)
	}
}

var _ = sql.NullString{}
