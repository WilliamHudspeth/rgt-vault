package capabilities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/hooks"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

const allowAll = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
`

func noop(context.Context, map[string]any, vault.CapabilityContext) (any, error) { return nil, nil }

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Spec{Name: "a.b", Handler: noop, Versions: []int{2, 1, 2}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		spec Spec
		want string
	}{
		{Spec{Name: "a.b", Handler: noop}, "capability 'a.b' is already registered"},
		{Spec{Handler: noop}, "capability name must be a non-empty string"},
		{Spec{Name: "x"}, "capability handler must be callable"},
		{Spec{Name: "x", Handler: noop, Versions: []int{0}}, "supported_versions must be positive ints"},
	} {
		err := r.Register(c.spec)
		if !errors.Is(err, ErrRegistration) || err.Error() != c.want {
			t.Errorf("%+v: %v", c.spec, err)
		}
	}
	s, err := r.Get("a.b")
	if err != nil || fmt.Sprint(s.SupportedVersions()) != "[1 2]" || !s.SupportsVersion(2) || s.SupportsVersion(3) {
		t.Fatalf("spec = %+v, %v", s, err)
	}
	if err := r.Register(Spec{Name: "c", Handler: noop}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.List()[1].Versions) != "[1]" || len(r.List()) != 2 || !r.Has("c") {
		t.Fatal("default version / list")
	}
	_, err = r.Lookup("zzz")
	if !errors.Is(err, vault.ErrCapabilityNotFound) || err.Error() != "unknown capability 'zzz'. Registered: ['a.b', 'c']" {
		t.Fatalf("lookup: %v", err)
	}
	if err := r.CheckVersion("a.b", 3); !errors.Is(err, vault.ErrCapabilityVersion) ||
		err.Error() != "capability 'a.b' version 3 is not supported; supported versions: [1, 2]" {
		t.Fatalf("check version: %v", err)
	}
	if r.CheckVersion("a.b", 1) != nil || r.CheckVersion("nope", 1) == nil {
		t.Fatal("check version")
	}
	r.Unregister("a.b")
	r.Unregister("a.b")
	if r.Has("a.b") || len(r.List()) != 1 {
		t.Fatal("unregister")
	}
	if err = RegisterBuiltins(NewDefault(nil), nil); !errors.Is(err, ErrRegistration) {
		t.Fatalf("builtins twice: %v", err)
	}
	var e *Error
	if errors.As(err, &e); e == nil || e.PyClass() != "ValueError" || e.Unwrap() != nil {
		t.Fatal("error type")
	}
	if (&Spec{}).ValidatePayload(map[string]any{"x": 1}) != nil {
		t.Fatal("nil schema must accept anything")
	}
}

func TestRegistryConcurrent(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- r.Register(Spec{Name: fmt.Sprintf("c%d", i%8), Handler: noop})
			_, _ = r.Lookup("c1")
			_ = r.List()
		}(i)
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 8 {
		t.Fatalf("%d registrations succeeded, want 8 (one per name)", ok)
	}
}

func TestParamList(t *testing.T) {
	p := ParamList{"message", "message"}
	if p.Validate("secrets.echo", map[string]any{"message": "<script>"}) != nil {
		t.Fatal("allowed param")
	}
	err := p.Validate("secrets.echo", map[string]any{"message": "x", "z'": 1, "a\n": 2})
	want := `capability 'secrets.echo' got unknown param(s): ['a\n', "z'"]. Allowed: ['message']`
	if !errors.Is(err, vault.ErrValidation) || err.Error() != want {
		t.Fatalf("got %v\nwant %s", err, want)
	}
	if (ParamList{}).Validate("x", map[string]any{"any": 1}) != nil {
		t.Fatal("empty list accepts anything")
	}
}

func TestJSONSchema(t *testing.T) {
	s := JSONSchema{
		"type":     "object",
		"required": []any{"url", "count"},
		"properties": map[string]any{
			"url":   map[string]any{"type": "string"},
			"count": map[string]any{"type": "integer"},
			"flag":  map[string]any{"type": "boolean"},
			"opts":  map[string]any{"type": "object"},
			"tags":  map[string]any{"type": "array"},
			"score": map[string]any{"type": "number"},
		},
		"additionalProperties": false,
	}
	ok := map[string]any{"url": "https://x/<script>alert(1)</script>", "count": 3.0, "flag": true,
		"opts": map[string]any{}, "tags": []any{"a"}, "score": "not checked"}
	if err := s.Validate("c", ok); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		payload map[string]any
		want    string
	}{
		{map[string]any{"count": 1}, "Payload validation failed: Missing required field 'url'"},
		{map[string]any{"url": "u"}, "Payload validation failed: Missing required field 'count'"},
		{map[string]any{"url": 1, "count": 1}, "Payload validation failed: 'url' must be a string"},
		{map[string]any{"url": "u", "count": 1.5}, "Payload validation failed: 'count' must be an integer"},
		{map[string]any{"url": "u", "count": "1"}, "Payload validation failed: 'count' must be an integer"},
		{map[string]any{"url": "u", "count": 1, "flag": "true"}, "Payload validation failed: 'flag' must be a boolean"},
		{map[string]any{"url": "u", "count": 1, "opts": []any{}}, "Payload validation failed: 'opts' must be a dict"},
		{map[string]any{"url": "u", "count": 1, "tags": "a"}, "Payload validation failed: 'tags' must be a list"},
		{map[string]any{"url": "u", "count": 1, "'; DROP TABLE x;--": 1}, "Payload validation failed: Additional properties not allowed ''; DROP TABLE x;--'"},
	} {
		err := s.Validate("c", c.payload)
		if !errors.Is(err, vault.ErrValidation) || err.Error() != c.want {
			t.Errorf("%v: got %v, want %q", c.payload, err, c.want)
		}
	}
	// Python: isinstance(True, int) is True; json.Number integer literals.
	for _, v := range []any{true, 1, int64(2), uint8(3), jsonNum("4"), jsonNum("-5")} {
		if !isPyInt(v) {
			t.Errorf("isPyInt(%#v) = false", v)
		}
	}
	for _, v := range []any{jsonNum("1.0"), jsonNum("-"), nil, "1"} {
		if isPyInt(v) {
			t.Errorf("isPyInt(%#v) = true", v)
		}
	}
	// Extra keys allowed without additionalProperties:false; []string forms.
	loose := JSONSchema{"required": []string{"a"}, "properties": map[string]any{"l": map[string]any{"type": "array"}, "m": map[string]any{"type": "object"}}}
	if err := loose.Validate("c", map[string]any{"a": 1, "zz": 2, "l": []string{"x"}, "m": map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if stringList(42) != nil {
		t.Fatal("stringList")
	}
}

type fetchArgs struct {
	URL     string `json:"url"`
	Retries int    `json:"retries"`
}

func (a *fetchArgs) Validate() error {
	if !strings.HasPrefix(a.URL, "https://") {
		return errors.New("url must be https")
	}
	return nil
}

func TestStructSchema(t *testing.T) {
	s := Struct[fetchArgs]()
	if err := s.Validate("c", map[string]any{"url": "https://ok", "retries": 2}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		payload map[string]any
		want    string
	}{
		{map[string]any{"url": "http://<script>"}, "Payload validation failed: url must be https"},
		{map[string]any{"url": "https://x", "evil": 1}, `Payload validation failed: unknown field "evil"`},
		{map[string]any{"url": 5}, "Payload validation failed: cannot unmarshal number into Go struct field fetchArgs.url of type string"},
		{map[string]any{"url": make(chan int)}, "Payload validation failed: json: unsupported type: chan int"},
	} {
		err := s.Validate("c", c.payload)
		if !errors.Is(err, vault.ErrValidation) || err.Error() != c.want {
			t.Errorf("%v: got %v, want %q", c.payload, err, c.want)
		}
	}
	got, err := DecodePayload[fetchArgs](map[string]any{"url": "https://a", "retries": 1})
	if err != nil || got.Retries != 1 {
		t.Fatal(got, err)
	}
}

// --- built-ins on a real vault --------------------------------------------

type fakeAction struct {
	mu      sync.Mutex
	seen    []string
	failRun bool
	badArgs bool
}

func (a *fakeAction) ValidateParams(p map[string]any) error {
	if a.badArgs {
		return &Error{msg: "bad params", kinds: []error{vault.ErrValidation}, pyClass: "ValidationError"}
	}
	return nil
}

func (a *fakeAction) Run(_ context.Context, secret []byte, p map[string]any) (any, error) {
	a.mu.Lock()
	a.seen = append(a.seen, string(secret))
	a.mu.Unlock()
	if a.failRun {
		return nil, errors.New("upstream said: " + string(secret))
	}
	return map[string]any{"status": 200, "len": len(secret), "q": p["q"]}, nil
}

type fakeActions map[string]Action

func (f fakeActions) Action(name string) (Action, error) {
	if a, ok := f[name]; ok {
		return a, nil
	}
	names := make([]string, 0, len(f))
	for n := range f {
		names = append(names, n)
	}
	return nil, ActionNotFound(name, names)
}

func openVault(t *testing.T, h vault.Hook, reg vault.CapabilityRegistry, ver captoken.TokenVerifier) *vault.Vault {
	t.Helper()
	if h == nil {
		h = hooks.NewOffHook()
	}
	v, err := vault.Open(context.Background(), vault.Config{
		DBPath:        filepath.Join(t.TempDir(), "v", "vault.db"),
		Provider:      providerstest.NewMemory(),
		PolicyYAML:    allowAll,
		Hook:          h,
		Capabilities:  reg,
		TokenVerifier: ver,
		RateLimit:     1_000_000,
		KDFParams:     kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func fixedVerifier(t *testing.T) *captoken.HMACTokenVerifier {
	t.Helper()
	v, err := captoken.NewHMACTokenVerifier(testKey, captoken.WithClock(func() time.Time { return time.Unix(1_900_000_000, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func execCap(t *testing.T, v *vault.Vault, ver captoken.TokenVerifier, capability, agent string, payload, bindings map[string]any) (any, error) {
	t.Helper()
	tok, err := ver.Sign(agent, capability, 1, bindings, 60)
	if err != nil {
		t.Fatal(err)
	}
	return v.ExecuteCapability(context.Background(), vault.CapabilityRequest{
		Capability: capability, Agent: agent, Token: tok, Payload: payload,
	})
}

func TestEcho(t *testing.T) {
	ver := fixedVerifier(t)
	v := openVault(t, nil, NewDefault(nil), ver)
	res, err := execCap(t, v, ver, EchoCapability, "agent-1", map[string]any{"message": 1.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["ok"] != true || m["message"] != "1.0" || m["agent_id"] != "agent-1" || m["capability"] != EchoCapability || m["token_id"] == "" {
		t.Fatalf("echo = %v", m)
	}
	res, _ = execCap(t, v, ver, EchoCapability, "agent-1", nil, nil)
	if res.(map[string]any)["message"] != "" {
		t.Fatal("missing message must echo empty string")
	}
	_, err = execCap(t, v, ver, EchoCapability, "agent-1", map[string]any{"message": "x", "secret": "y"}, nil)
	if !errors.Is(err, vault.ErrValidation) || !strings.Contains(err.Error(), "got unknown param(s): ['secret']") {
		t.Fatalf("unknown param: %v", err)
	}
}

func TestSecretsUse(t *testing.T) {
	ver := fixedVerifier(t)
	act := &fakeAction{}
	lh := hooks.NewLogHook()
	v := openVault(t, lh, NewDefault(fakeActions{"http_get": act}), ver)
	ctx := context.Background()
	if err := v.SetSecret(ctx, vault.SetSecretRequest{Name: "gh", Namespace: "prod", Agent: "system", Value: []byte("tok-123")}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret(ctx, vault.SetSecretRequest{Name: "gh", Namespace: "default", Agent: "system", Value: []byte("dflt")}); err != nil {
		t.Fatal(err)
	}
	res, err := execCap(t, v, ver, UseCapability, "bot", map[string]any{
		"secret_name": "gh", "namespace": "prod", "action": "http_get", "params": map[string]any{"q": "<x>"},
	}, map[string]any{"secret_name": "gh"})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	inner := m["result"].(map[string]any)
	if m["ok"] != true || m["action"] != "http_get" || inner["len"] != 7 || inner["q"] != "<x>" {
		t.Fatalf("use = %v", m)
	}
	if strings.Contains(fmt.Sprint(m), "tok-123") {
		t.Fatal("secret leaked into the result")
	}
	// Default namespace, falsy params.
	if _, err := execCap(t, v, ver, UseCapability, "bot", map[string]any{"secret_name": "gh", "action": "http_get", "params": nil}, nil); err != nil {
		t.Fatal(err)
	}
	if act.seen[1] != "dflt" {
		t.Fatalf("default namespace not used: %v", act.seen)
	}
	// The lease runs with purpose capability:secrets.use (seen by the hook).
	found := false
	for _, c := range lh.Consultations() {
		if c.Operation == "read" && c.Purpose == "capability:secrets.use" && c.Agent == "bot" && c.Namespace == "prod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lease purpose not seen: %+v", lh.Consultations())
	}

	before, _ := v.AuditLog(ctx, -1)
	act.failRun = true
	_, err = execCap(t, v, ver, UseCapability, "bot", map[string]any{"secret_name": "gh", "namespace": "prod", "action": "http_get"}, nil)
	if !errors.Is(err, vault.ErrCapabilityFailed) || !errors.Is(err, ErrActionExecution) ||
		err.Error() != "action 'http_get' failed; see server logs for details" {
		t.Fatalf("failing action: %v", err)
	}
	after, _ := v.AuditLog(ctx, -1)
	for _, r := range after[:len(after)-len(before)] {
		if strings.Contains(r.Details.String, "tok-123") || strings.Contains(r.Details.String, "upstream said") {
			t.Fatalf("secret or action error text in audit: %s", r.Details.String)
		}
		if r.Action == "CAPABILITY_FAILED" && !strings.Contains(r.Details.String, `"reason": "handler: ActionExecutionError"`) {
			t.Fatalf("failed row: %s", r.Details.String)
		}
	}
	act.failRun = false

	for _, c := range []struct {
		payload map[string]any
		kind    error
		msg     string
	}{
		{map[string]any{"action": "http_get"}, ErrActionExecution, "'secret_name' is required"},
		{map[string]any{"secret_name": 5, "action": "http_get"}, ErrActionExecution, "'secret_name' is required"},
		{map[string]any{"secret_name": "gh"}, ErrActionExecution, "'action' is required"},
		{map[string]any{"secret_name": "gh", "action": "http_get", "params": []any{1}}, ErrActionExecution, "'params' must be a dict"},
		{map[string]any{"secret_name": "gh", "action": "http_get", "namespace": nil}, vault.ErrValidation, "'namespace' must be a string. Got NoneType."},
		{map[string]any{"secret_name": "gh", "action": "rm_rf"}, ErrActionNotFound, "Unknown action 'rm_rf'. Registered: ['http_get']"},
		{map[string]any{"secret_name": "missing", "action": "http_get"}, vault.ErrNotFound, ""},
	} {
		_, err := execCap(t, v, ver, UseCapability, "bot", c.payload, nil)
		if !errors.Is(err, c.kind) || !errors.Is(err, vault.ErrCapabilityFailed) || (c.msg != "" && err.Error() != c.msg) {
			t.Errorf("%v: %v", c.payload, err)
		}
	}
	act.badArgs = true
	if _, err := execCap(t, v, ver, UseCapability, "bot", map[string]any{"secret_name": "gh", "action": "http_get"}, nil); !errors.Is(err, vault.ErrValidation) {
		t.Fatalf("bad params: %v", err)
	}
	if len(act.seen) != 3 {
		t.Fatalf("action ran %d times; it must not run when params are invalid", len(act.seen))
	}

	// No action registry: every action is unknown.
	v2 := openVault(t, nil, NewDefault(nil), ver)
	if _, err := execCap(t, v2, ver, UseCapability, "bot", map[string]any{"secret_name": "gh", "action": "x"}, nil); !errors.Is(err, ErrActionNotFound) {
		t.Fatalf("nil actions: %v", err)
	}
	// A handler called without a vault (direct use).
	h := useHandler(fakeActions{"a": act})
	act.badArgs = false
	if _, err := h(context.Background(), map[string]any{"secret_name": "s", "action": "a"}, vault.CapabilityContext{}); !errors.Is(err, ErrActionExecution) {
		t.Fatalf("no vault: %v", err)
	}
	if pyTruthy(jsonNum("0")) || !pyTruthy(jsonNum("0.5")) || pyTruthy("") || !pyTruthy("x") || pyTruthy(0.0) || !pyTruthy(1) || pyTruthy(0) || pyTruthy([]any{}) || pyTruthy(false) {
		t.Fatal("pyTruthy")
	}
	for v, want := range map[any]string{true: "bool", 1.5: "float", 1: "int", "s": "object"} {
		if pyTypeName(v) != want {
			t.Errorf("pyTypeName(%v)", v)
		}
	}
	if pyTypeName(map[string]any{}) != "dict" || pyTypeName([]any{}) != "list" {
		t.Fatal("pyTypeName")
	}
}

// TestTwoFactorHookOnCapabilityPath wires the real TwoFactorHook as the
// vault hook, sharing its verifier: the first execution passes, a replay of
// the same token is denied by the hook's replay cache (HOOK_CAPABILITY deny).
func TestTwoFactorHookOnCapabilityPath(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	h, err := hooks.NewTwoFactorHook(testKey, hooks.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	v := openVault(t, h, NewDefault(nil), h.Verifier())
	tok, err := h.IssueV2("agent-1", EchoCapability, 1, map[string]any{"message": "hi"}, 60)
	if err != nil {
		t.Fatal(err)
	}
	req := vault.CapabilityRequest{Capability: EchoCapability, Agent: "agent-1", Token: tok, Payload: map[string]any{"message": "hi"}}
	if _, err := v.ExecuteCapability(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	_, err = v.ExecuteCapability(context.Background(), req)
	if !errors.Is(err, vault.ErrPolicyDenied) || !strings.Contains(err.Error(), "capability_token replay detected") {
		t.Fatalf("replay: %v", err)
	}
	rows, _ := v.AuditLog(context.Background(), 1)
	if rows[0].Action != "HOOK_CAPABILITY" || !strings.Contains(rows[0].Details.String, `"reason": "capability_token replay detected"`) {
		t.Fatalf("row = %v", rows[0])
	}
	if strings.Contains(rows[0].Details.String, tok) {
		t.Fatal("token in audit row")
	}
	// Freeze via the hook: the capability path stops before verification.
	h.Freeze("incident")
	_, err = v.ExecuteCapability(context.Background(), req)
	if !errors.Is(err, vault.ErrPolicyDenied) || err.Error() != "vault frozen" {
		t.Fatalf("frozen: %v", err)
	}
}

func TestReviewFixes(t *testing.T) {
	// Nested JSONSchema values are honoured.
	s := JSONSchema{"properties": JSONSchema{"count": JSONSchema{"type": "integer"}}}
	if err := s.Validate("c", map[string]any{"count": "not-an-int"}); err == nil {
		t.Fatal("nested JSONSchema ignored")
	}
	if asMap(42) != nil {
		t.Fatal("asMap")
	}
	// secrets.use checks the action before the namespace (Python order).
	ver := fixedVerifier(t)
	v := openVault(t, nil, NewDefault(fakeActions{"a": &fakeAction{}}), ver)
	_, err := execCap(t, v, ver, UseCapability, "bot", map[string]any{"secret_name": "s", "action": "missing", "namespace": 123}, nil)
	if !errors.Is(err, ErrActionNotFound) {
		t.Fatalf("order: %v", err)
	}
	_, err = execCap(t, v, ver, UseCapability, "bot", map[string]any{"secret_name": "s", "action": "a", "namespace": jsonNum("123")}, nil)
	if err == nil || err.Error() != "'namespace' must be a string. Got int." {
		t.Fatalf("json.Number namespace: %v", err)
	}
	for _, c := range []struct {
		v    any
		want string
	}{{jsonNum("1.5"), "float"}, {jsonNum("10000000000000000000"), "int"}, {int64(1), "int"}, {float32(1), "float"}} {
		if pyTypeName(c.v) != c.want {
			t.Errorf("pyTypeName(%#v)", c.v)
		}
	}
	for _, f := range []any{int64(0), uint8(0), jsonNum("0e0"), jsonNum("0.00"), float32(0)} {
		if pyTruthy(f) {
			t.Errorf("pyTruthy(%#v) = true", f)
		}
	}
	if !pyTruthy(int64(2)) || !pyTruthy(jsonNum("bogus")) || !pyTruthy(struct{}{}) {
		t.Fatal("pyTruthy truthy values")
	}
}

// TestJSONSchemaMultiErrorOutcome: with several violations, Go's sorted key
// order may name a different violation than Python's insertion order, but
// the outcome is identical (rejected, ValidationError) for every order the
// payload could have arrived in, and the named violation is deterministic.
func TestJSONSchemaMultiErrorOutcome(t *testing.T) {
	s := JSONSchema{
		"required": []any{"id"},
		"properties": map[string]any{
			"id": map[string]any{"type": "integer"}, "name": map[string]any{"type": "string"},
			"tags": map[string]any{"type": "array"},
		},
		"additionalProperties": false,
	}
	// Each JSON document is the same set of violations in a different key
	// order (what Python would iterate).
	docs := []string{
		`{"id": "x", "name": 5, "tags": "t", "zzz": 1}`,
		`{"zzz": 1, "tags": "t", "name": 5, "id": "x"}`,
		`{"name": 5, "zzz": 1, "id": "x", "tags": "t"}`,
	}
	var first string
	for _, d := range docs {
		var p map[string]any
		if err := json.Unmarshal([]byte(d), &p); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ { // map iteration order varies run to run
			err := s.Validate("c", p)
			if !errors.Is(err, vault.ErrValidation) {
				t.Fatalf("%s: not rejected: %v", d, err)
			}
			if first == "" {
				first = err.Error()
			}
			if err.Error() != first {
				t.Fatalf("non-deterministic message: %q vs %q", err.Error(), first)
			}
		}
	}
	if first != "Payload validation failed: 'id' must be an integer" {
		t.Fatalf("first violation in sorted order = %q", first)
	}
	// Missing required fields are reported before any type error, as in Python.
	err := s.Validate("c", map[string]any{"name": 5})
	if err == nil || err.Error() != "Payload validation failed: Missing required field 'id'" {
		t.Fatalf("required first: %v", err)
	}
}
