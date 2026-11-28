package vault

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
)

var capKey = []byte("0123456789abcdef0123456789abcdef-test-key")

// fakeSpec / fakeRegistry stand in for internal/capabilities (which imports
// this package, so it cannot be used from an internal test).
type fakeSpec struct {
	versions []int
	validate func(map[string]any) error
	invoke   func(context.Context, map[string]any, CapabilityContext) (any, error)
}

func (s *fakeSpec) SupportsVersion(v int) bool {
	for _, x := range s.versions {
		if x == v {
			return true
		}
	}
	return false
}
func (s *fakeSpec) SupportedVersions() []int { return s.versions }
func (s *fakeSpec) ValidatePayload(p map[string]any) error {
	if s.validate != nil {
		return s.validate(p)
	}
	return nil
}
func (s *fakeSpec) Invoke(ctx context.Context, p map[string]any, c CapabilityContext) (any, error) {
	return s.invoke(ctx, p, c)
}

type fakeRegistry map[string]CapabilitySpec

func (r fakeRegistry) Lookup(name string) (CapabilitySpec, error) {
	if s, ok := r[name]; ok {
		return s, nil
	}
	return nil, newErr([]error{ErrCapabilityNotFound}, nil, "unknown capability %s. Registered: []", pyRepr(name))
}

func echoSpec() *fakeSpec {
	return &fakeSpec{versions: []int{1}, invoke: func(_ context.Context, p map[string]any, c CapabilityContext) (any, error) {
		return map[string]any{"ok": true, "agent_id": c.AgentID, "token_id": c.TokenID, "message": p["message"]}, nil
	}}
}

// scriptedHook returns a fixed response; frozenAfter > 0 makes Frozen true
// from the frozenAfter-th call on.
type scriptedHook struct {
	resp        HookResponse
	err         error
	frozen      bool
	frozenAfter int32
	calls       atomic.Int32
	seen        []HookRequest
}

func (h *scriptedHook) ID() string { return "scripted" }
func (h *scriptedHook) Frozen() bool {
	n := h.calls.Add(1)
	return h.frozen || (h.frozenAfter > 0 && n >= h.frozenAfter)
}
func (h *scriptedHook) Consult(_ context.Context, r HookRequest) (HookResponse, error) {
	h.seen = append(h.seen, r)
	return h.resp, h.err
}

func newCapVault(t *testing.T, hook Hook, reg CapabilityRegistry, verifier captoken.TokenVerifier) *Vault {
	t.Helper()
	return openT(t, Config{
		DBPath:        filepath.Join(t.TempDir(), "v", "vault.db"),
		Provider:      memProv(),
		PolicyYAML:    allowAllPolicy,
		Hook:          hook,
		Capabilities:  reg,
		TokenVerifier: verifier,
	})
}

func verifierAt(t *testing.T, now time.Time) *captoken.HMACTokenVerifier {
	t.Helper()
	v, err := captoken.NewHMACTokenVerifier(capKey, captoken.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func signT(t *testing.T, v captoken.TokenVerifier, agent, capability string, version int, bindings map[string]any) string {
	t.Helper()
	tok, err := v.Sign(agent, capability, version, bindings, 60)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type capRow struct{ action, details string }

func capRows(t *testing.T, v *Vault, since int) []capRow {
	t.Helper()
	rows := auditRows(t, v)
	var out []capRow
	for _, r := range rows[since:] {
		out = append(out, capRow{r.Action, r.Details.String})
	}
	return out
}

// TestExecuteCapabilityOrderMatrix drives every failing stage of
// ExecuteCapability, in Python's order, and checks the error kind and the
// exact audit rows (python/vault.py execute_capability).
func TestExecuteCapabilityOrderMatrix(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	ver := verifierAt(t, now)
	base := `{"agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, `
	tokOK := signT(t, ver, "agent-1", "secrets.echo", 1, map[string]any{"repo": "org/a"})
	okPayload := map[string]any{"repo": "org/a", "message": "hi"}
	allowHook := func() *scriptedHook {
		return &scriptedHook{resp: HookResponse{Decision: HookAllow, Reason: "ok"}}
	}
	reg := func() fakeRegistry { return fakeRegistry{"secrets.echo": echoSpec()} }
	other := signT(t, verifierAt(t, now), "agent-1", "secrets.echo", 1, map[string]any{"repo": "org/a"})
	_ = other

	type tc struct {
		name     string
		hook     Hook
		reg      CapabilityRegistry
		verifier captoken.TokenVerifier
		prep     func(v *Vault)
		req      CapabilityRequest
		wantErr  []error
		wantMsg  string
		wantRows []capRow
	}
	expiredVer := verifierAt(t, now.Add(-time.Hour))
	expiredTok := signT(t, expiredVer, "agent-1", "secrets.echo", 1, nil)
	wrongKey, _ := captoken.NewHMACTokenVerifier([]byte("another-key-another-key-another-key!!"),
		captoken.WithClock(func() time.Time { return now }))
	badSig := signT(t, wrongKey, "agent-1", "secrets.echo", 1, nil)
	req := func(tok string, payload map[string]any) CapabilityRequest {
		return CapabilityRequest{Capability: "secrets.echo", Agent: "agent-1", Token: tok, Payload: payload}
	}
	cases := []tc{
		{
			name: "1 frozen", hook: &scriptedHook{frozen: true}, reg: reg(), verifier: ver,
			req: req(tokOK, okPayload), wantErr: []error{ErrPolicyDenied}, wantMsg: "vault frozen",
			wantRows: []capRow{{"CAPABILITY_DENIED", base + `"reason": "vault frozen"}`}},
		},
		{
			name: "2 no verifier", hook: allowHook(), reg: reg(), verifier: nil,
			req: req(tokOK, okPayload), wantErr: []error{ErrNoTokenVerifier, ErrValidation},
			wantRows: []capRow{{"CAPABILITY_DENIED", base + `"reason": "no token verifier configured"}`}},
		},
		{
			name: "3 failed-credential cap", hook: allowHook(), reg: reg(), verifier: ver,
			prep: func(v *Vault) {
				for i := 0; i < AuthFailureLimit; i++ {
					v.authFailureLimiter.Record("agent-1")
				}
			},
			req: req(tokOK, okPayload), wantErr: []error{ErrPolicyDenied},
			wantMsg:  "agent 'agent-1' locked out: too many failed credential attempts",
			wantRows: []capRow{{"CAPABILITY_DENIED", base + `"reason": "too many failed credential verifications"}`}},
		},
		{
			name: "4 bad signature", hook: allowHook(), reg: reg(), verifier: ver,
			req: req(badSig, nil), wantErr: []error{ErrPolicyDenied},
			wantMsg:  "capability token rejected: token signature did not verify",
			wantRows: []capRow{{"CAPABILITY_DENIED", base + `"reason": "token: TokenSignatureError"}`}},
		},
		{
			name: "4 expired", hook: allowHook(), reg: reg(), verifier: ver,
			req: req(expiredTok, nil), wantErr: []error{ErrPolicyDenied},
			wantRows: []capRow{{"CAPABILITY_DENIED", base + `"reason": "token: TokenExpiredError"}`}},
		},
		{
			name: "4 malformed", hook: allowHook(), reg: reg(), verifier: ver,
			req: req("not-a-token", nil), wantErr: []error{ErrPolicyDenied},
			wantRows: []capRow{{"CAPABILITY_DENIED", base + `"reason": "token: TokenMalformedError"}`}},
		},
		{
			name: "5 agent mismatch", hook: allowHook(), reg: reg(), verifier: ver,
			req:     CapabilityRequest{Capability: "secrets.echo", Agent: "agent-2", Token: tokOK, Payload: okPayload},
			wantErr: []error{ErrPolicyDenied}, wantMsg: "token bound to agent 'agent-1', caller claimed 'agent-2'",
			wantRows: []capRow{{"CAPABILITY_DENIED",
				`{"agent": "agent-2", "capability": "secrets.echo", "capability_version": 1, "reason": "agent mismatch"}`}},
		},
		{
			name: "5 capability mismatch", hook: allowHook(), reg: reg(), verifier: ver,
			req:     CapabilityRequest{Capability: "secrets.use", Agent: "agent-1", Token: tokOK, Payload: okPayload},
			wantErr: []error{ErrPolicyDenied}, wantMsg: "token authorizes 'secrets.echo', request asked for 'secrets.use'",
			wantRows: []capRow{{"CAPABILITY_DENIED",
				`{"agent": "agent-1", "capability": "secrets.use", "capability_version": 1, "reason": "capability mismatch", "token_capability": "secrets.echo"}`}},
		},
		{
			name: "5 version mismatch", hook: allowHook(), reg: reg(), verifier: ver,
			req:     CapabilityRequest{Capability: "secrets.echo", Version: 2, Agent: "agent-1", Token: tokOK, Payload: okPayload},
			wantErr: []error{ErrPolicyDenied}, wantMsg: "token capability_version=1, request asked for 2",
			wantRows: []capRow{{"CAPABILITY_DENIED",
				`{"agent": "agent-1", "capability": "secrets.echo", "capability_version": 2, "reason": "version mismatch", "token_version": 1}`}},
		},
		{
			name: "6 binding mismatch", hook: allowHook(), reg: reg(), verifier: ver,
			req:     req(tokOK, map[string]any{"repo": "evil/<script>"}),
			wantErr: []error{ErrPolicyDenied, captoken.ErrBinding},
			wantMsg: "capability 'secrets.echo' context binding failed for 'repo': expected 'org/a', got 'evil/<script>'",
			wantRows: []capRow{{"CAPABILITY_DENIED", base +
				`"reason": "context binding: capability 'secrets.echo' context binding failed for 'repo': expected 'org/a', got 'evil/<script>'"}`}},
		},
		{
			name: "6 binding missing", hook: allowHook(), reg: reg(), verifier: ver,
			req: req(tokOK, nil), wantErr: []error{ErrPolicyDenied, captoken.ErrBinding},
			wantRows: []capRow{{"CAPABILITY_DENIED", base +
				`"reason": "context binding: capability 'secrets.echo' requires context key 'repo' in the request"}`}},
		},
		{
			name: "7 hook deny", hook: &scriptedHook{resp: HookResponse{Decision: HookDeny, Reason: "nope"}}, reg: reg(), verifier: ver,
			req: req(tokOK, okPayload), wantErr: []error{ErrPolicyDenied},
			wantMsg: "hook 'scripted' denied capability 'secrets.echo' for agent 'agent-1': nope",
			wantRows: []capRow{{"HOOK_CAPABILITY",
				`{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "deny", "reason": "nope"}`}},
		},
		{
			name: "7 hook error", hook: &scriptedHook{err: errors.New("boom")}, reg: reg(), verifier: ver,
			req: req(tokOK, okPayload), wantErr: []error{ErrPolicyDenied},
			wantRows: []capRow{{"HOOK_CAPABILITY",
				`{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "deny", "reason": "hook raised error: boom"}`}},
		},
		{
			name: "7 hook frozen between checks", hook: &scriptedHook{frozenAfter: 2}, reg: reg(), verifier: ver,
			req: req(tokOK, okPayload), wantErr: []error{ErrPolicyDenied}, wantMsg: "vault frozen by hook",
			wantRows: []capRow{{"HOOK_CAPABILITY",
				`{"hook_id": "scripted", "decision": "freeze", "reason": "vault frozen by hook", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1}`}},
		},
		{
			name: "8 unknown capability (no row)", hook: allowHook(), reg: fakeRegistry{}, verifier: ver,
			req: req(tokOK, okPayload), wantErr: []error{ErrCapabilityNotFound},
			wantMsg: "unknown capability 'secrets.echo'. Registered: []",
			wantRows: []capRow{{"HOOK_CAPABILITY",
				`{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`}},
		},
		{
			name: "8 nil registry", hook: allowHook(), reg: nil, verifier: ver,
			req: req(tokOK, okPayload), wantErr: []error{ErrCapabilityNotFound},
		},
		{
			name: "9 version unsupported", hook: allowHook(),
			reg:      fakeRegistry{"secrets.echo": &fakeSpec{versions: []int{3, 2}}},
			verifier: ver, req: req(tokOK, okPayload), wantErr: []error{ErrCapabilityVersion},
			wantMsg: "capability 'secrets.echo' does not support version 1; supported: [2, 3]",
			wantRows: []capRow{
				{"HOOK_CAPABILITY", `{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`},
				{"CAPABILITY_DENIED", base + `"reason": "version not supported by registered handler", "supported_versions": [2, 3]}`},
			},
		},
		{
			name: "10 payload invalid", hook: allowHook(),
			reg: fakeRegistry{"secrets.echo": &fakeSpec{versions: []int{1}, validate: func(map[string]any) error {
				return validationErr("Payload validation failed: '<b>' must be a string")
			}}},
			verifier: ver, req: req(tokOK, okPayload), wantErr: []error{ErrValidation},
			wantRows: []capRow{
				{"HOOK_CAPABILITY", `{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`},
				{"CAPABILITY_DENIED", base + `"reason": "payload: Payload validation failed: '<b>' must be a string"}`},
			},
		},
		{
			name: "11 rate limited", hook: allowHook(), reg: reg(), verifier: ver,
			prep: func(v *Vault) { v.rateLimiter = NewRateLimiter(0, time.Hour) },
			req:  req(tokOK, okPayload), wantErr: []error{ErrRateLimited, ErrPermission},
			wantMsg: "Rate limit exceeded for agent 'agent-1'",
			wantRows: []capRow{
				{"HOOK_CAPABILITY", `{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`},
				{"CAPABILITY_DENIED", base + `"reason": "rate limited"}`},
			},
		},
		{
			name: "12 handler error", hook: allowHook(),
			reg: fakeRegistry{"secrets.echo": &fakeSpec{versions: []int{1}, invoke: func(context.Context, map[string]any, CapabilityContext) (any, error) {
				return nil, validationErr("secret value must not leak: hunter2")
			}}},
			verifier: ver, req: req(tokOK, okPayload), wantErr: []error{ErrCapabilityFailed, ErrValidation},
			wantRows: []capRow{
				{"HOOK_CAPABILITY", `{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`},
				{"CAPABILITY_FAILED", base + `"reason": "handler: ValidationError", "context_hash": "` + ContextHash(okPayload) + `"}`},
			},
		},
		{
			name: "12 handler panic", hook: allowHook(),
			reg: fakeRegistry{"secrets.echo": &fakeSpec{versions: []int{1}, invoke: func(context.Context, map[string]any, CapabilityContext) (any, error) {
				panic("kaboom")
			}}},
			verifier: ver, req: req(tokOK, okPayload), wantErr: []error{ErrCapabilityFailed},
			wantRows: []capRow{
				{"HOOK_CAPABILITY", `{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`},
				{"CAPABILITY_FAILED", base + `"reason": "handler: panic", "context_hash": "` + ContextHash(okPayload) + `"}`},
			},
		},
		{
			name: "13 executed", hook: allowHook(), reg: reg(), verifier: ver,
			req: req(tokOK, okPayload),
			wantRows: []capRow{
				{"HOOK_CAPABILITY", `{"hook_id": "scripted", "agent": "agent-1", "capability": "secrets.echo", "capability_version": 1, "decision": "allow", "reason": "ok"}`},
				{"CAPABILITY_EXECUTED", base + `"hook": "scripted", "allowed": true, "context_hash": "` + ContextHash(okPayload) + `"}`},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newCapVault(t, c.hook, c.reg, c.verifier)
			if c.prep != nil {
				c.prep(v)
			}
			start := len(auditRows(t, v))
			res, err := v.ExecuteCapability(ctx, c.req)
			if len(c.wantErr) == 0 {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				m := res.(map[string]any)
				if m["agent_id"] != "agent-1" || m["message"] != "hi" || m["token_id"] == "" {
					t.Fatalf("result = %v", m)
				}
			} else {
				if err == nil {
					t.Fatalf("want error %v, got result %v", c.wantErr, res)
				}
				for _, k := range c.wantErr {
					if !errors.Is(err, k) {
						t.Errorf("errors.Is(%v, %v) = false", err, k)
					}
				}
				if c.wantMsg != "" && err.Error() != c.wantMsg {
					t.Errorf("message\n got %q\nwant %q", err.Error(), c.wantMsg)
				}
			}
			if c.wantRows != nil {
				got := capRows(t, v, start)
				if !reflect.DeepEqual(got, c.wantRows) {
					t.Errorf("audit rows\n got %q\nwant %q", got, c.wantRows)
				}
			}
			mustVerify(t, v)
		})
	}
}

func TestExecuteCapabilityRecordsFailures(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	v := newCapVault(t, nil, fakeRegistry{"secrets.echo": echoSpec()}, verifierAt(t, now))
	for i := 0; i < 3; i++ {
		_, err := v.ExecuteCapability(context.Background(), CapabilityRequest{Capability: "secrets.echo", Agent: "a", Token: "x.y"})
		if !errors.Is(err, ErrPolicyDenied) {
			t.Fatal(err)
		}
	}
	if n := v.AuthFailureLimiter().Count("a"); n != 3 {
		t.Fatalf("auth failures = %d, want 3", n)
	}
}

func TestExecuteCapabilityHookSeesCapabilityRequest(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	ver := verifierAt(t, now)
	h := &scriptedHook{resp: HookResponse{Decision: HookAllow, Extra: map[string]any{"capability_token": "SECRET", "k": 1}}}
	v := newCapVault(t, h, fakeRegistry{"secrets.echo": echoSpec()}, ver)
	tok := signT(t, ver, "a", "secrets.echo", 1, map[string]any{"n": 1})
	start := len(auditRows(t, v))
	if _, err := v.ExecuteCapability(context.Background(), CapabilityRequest{
		Capability: "secrets.echo", Agent: "a", Token: tok, Payload: map[string]any{"n": 1.0},
	}); err != nil {
		t.Fatal(err)
	}
	if len(h.seen) != 1 {
		t.Fatalf("hook consulted %d times", len(h.seen))
	}
	r := h.seen[0]
	if !r.IsCapability() || r.CapabilityToken != tok || r.CapabilityVersion != 1 || r.RequestID == "" {
		t.Fatalf("hook request = %+v", r)
	}
	md := r.TokenMetadata.(map[string]any)
	if md["token_id"] == "" || md["exp"].(int64) != now.Unix()+60 {
		t.Fatalf("token metadata = %v", md)
	}
	rows := capRows(t, v, start)
	if strings.Contains(rows[0].details, "SECRET") || !strings.Contains(rows[0].details, `"extra": "{\"k\": 1}"`) {
		t.Fatalf("hook row = %s", rows[0].details)
	}
}

func TestExecuteCapabilityValidation(t *testing.T) {
	v := newCapVault(t, nil, nil, verifierAt(t, time.Now()))
	ctx := context.Background()
	for _, c := range []struct {
		req  CapabilityRequest
		want string
	}{
		{CapabilityRequest{Capability: " \t", Agent: "a", Token: "t"}, "capability_name must be a non-empty string"},
		{CapabilityRequest{Capability: "c", Agent: "　", Token: "t"}, "agent_id must be a non-empty string"},
		{CapabilityRequest{Capability: "c", Agent: "a"}, "capability_token is required"},
	} {
		start := len(auditRows(t, v))
		_, err := v.ExecuteCapability(ctx, c.req)
		if !errors.Is(err, ErrValidation) || err.Error() != c.want {
			t.Errorf("%+v: err = %v", c.req, err)
		}
		if n := len(auditRows(t, v)) - start; n != 0 {
			t.Errorf("validation failure wrote %d audit rows", n)
		}
	}
	_ = v.Close()
	if _, err := v.ExecuteCapability(ctx, CapabilityRequest{Capability: "c", Agent: "a", Token: "t"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed vault: %v", err)
	}
}

func TestContextHashMatchesPython(t *testing.T) {
	// Values computed with Python:
	// hashlib.sha256(json.dumps(p, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()[:16]
	for _, c := range []struct {
		p    map[string]any
		want string
	}{
		{map[string]any{}, "44136fa355b3678a"},
		{map[string]any{"repo": "org/a", "message": "hi"}, "249ae3f806d46d72"},
		{map[string]any{"z": []any{1, "é", nil, true}, "a": map[string]any{"y": 1.5, "x": "<&>"}}, "4fc621350c553b76"},
	} {
		if got := ContextHash(c.p); got != c.want {
			t.Errorf("ContextHash(%v) = %s, want %s", c.p, got, c.want)
		}
	}
}

func TestErrorClass(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{validationErr("x"), "ValidationError"},
		{deniedErr("x"), "PolicyDeniedError"},
		{notFoundErr("a", "b", nil), "SecretNotFoundError"},
		{rateLimitedErr("a"), "PermissionError"},
		{errors.New("x"), "errorString"},
		{&handlerPanic{value: 1}, "panic"},
		{newErr(nil, nil, "x"), "Error"},
	} {
		if got := errorClass(c.err); got != c.want {
			t.Errorf("errorClass(%T) = %q, want %q", c.err, got, c.want)
		}
	}
	if (&handlerPanic{value: errors.New("e")}).Unwrap() == nil {
		t.Fatal("panic with an error value must unwrap to it")
	}
}

// TestExecuteCapabilityNoBypass is the RGT-423 guard: Python's
// execute_capability accepted bypass_verification=True, which skipped the
// token entirely. The Go API has no such parameter: ExecuteCapability takes
// (ctx, CapabilityRequest) and CapabilityRequest has no field that could
// disable verification; no identifier in this package mentions a bypass.
func TestExecuteCapabilityNoBypass(t *testing.T) {
	m, ok := reflect.TypeOf((*Vault)(nil)).MethodByName("ExecuteCapability")
	if !ok {
		t.Fatal("ExecuteCapability missing")
	}
	ft := m.Type
	if ft.NumIn() != 3 || ft.In(1) != reflect.TypeOf((*context.Context)(nil)).Elem() || ft.In(2) != reflect.TypeOf(CapabilityRequest{}) {
		t.Fatalf("ExecuteCapability signature changed: %v", ft)
	}
	if ft.IsVariadic() {
		t.Fatal("ExecuteCapability must not be variadic")
	}
	rt := reflect.TypeOf(CapabilityRequest{})
	want := []string{"Capability", "Version", "Agent", "Token", "Payload"}
	if rt.NumField() != len(want) {
		t.Fatalf("CapabilityRequest has %d fields, want exactly %v", rt.NumField(), want)
	}
	for i, n := range want {
		f := rt.Field(i)
		if f.Name != n {
			t.Fatalf("CapabilityRequest field %d = %s, want %s", i, f.Name, n)
		}
		if f.Type.Kind() == reflect.Bool {
			t.Fatalf("CapabilityRequest.%s is a bool flag", f.Name)
		}
	}
	// AST: no identifier (not comment) in the vault package spells bypass,
	// skip-verify or insecure.
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{"bypass", "skipverif", "noverif", "insecure", "unverified"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				l := strings.ToLower(x.Name)
				for _, b := range bad {
					if strings.Contains(l, b) {
						t.Errorf("%s: identifier %q", fset.Position(x.Pos()), x.Name)
					}
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && strings.Contains(strings.ToLower(x.Value), "bypass") {
					t.Errorf("%s: string literal %s", fset.Position(x.Pos()), x.Value)
				}
			}
			return true
		})
	}
}

type nilVerifier struct{}

func (nilVerifier) Sign(string, string, int, map[string]any, int) (string, error) { return "", nil }
func (nilVerifier) Verify(string) (*captoken.CapabilityV2Token, error)            { return nil, nil }

type errRegistry struct{}

func (errRegistry) Lookup(string) (CapabilitySpec, error) { return nil, errors.New("backend down") }

// closingHook closes the vault from inside Consult, so the HOOK_CAPABILITY
// audit write fails: the call must fail (closed), never run the handler.
type closingHook struct{ v *Vault }

func (closingHook) ID() string   { return "closing" }
func (closingHook) Frozen() bool { return false }
func (h closingHook) Consult(context.Context, HookRequest) (HookResponse, error) {
	_ = h.v.Close()
	return HookResponse{Decision: HookAllow}, nil
}

func TestExecuteCapabilityEdgeCases(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	ver := verifierAt(t, now)
	tok := signT(t, ver, "a", "secrets.echo", 1, nil)
	req := CapabilityRequest{Capability: "secrets.echo", Agent: "a", Token: tok}

	v := newCapVault(t, nil, fakeRegistry{"secrets.echo": echoSpec()}, nilVerifier{})
	if _, err := v.ExecuteCapability(ctx, req); !errors.Is(err, ErrPolicyDenied) || !errors.Is(err, ErrTokenVerifier) ||
		err.Error() != "capability token rejected: token verifier returned no token" {
		t.Fatalf("nil token from verifier: %v", err)
	}
	if rows := lastAudit(t, v, 1); rows[0].Details.String !=
		`{"agent": "a", "capability": "secrets.echo", "capability_version": 1, "reason": "token: TokenVerifierError"}` {
		t.Fatalf("row = %s", rows[0].Details.String)
	}
	if n := v.AuthFailureLimiter().Count("a"); n != 0 {
		t.Fatalf("a verifier fault must not count as the agent's failure: %d", n)
	}
	if v.TokenVerifier() == nil || v.Capabilities() == nil {
		t.Fatal("accessors")
	}

	v = newCapVault(t, nil, fakeRegistry{}, &captoken.Ed25519Verifier{})
	if _, err := v.ExecuteCapability(ctx, req); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("ed25519 stub: %v", err)
	}
	if rows := lastAudit(t, v, 1); !strings.Contains(rows[0].Details.String, `"reason": "token: NotImplementedError"`) {
		t.Fatalf("row = %s", rows[0].Details.String)
	}

	v = newCapVault(t, nil, errRegistry{}, ver)
	if _, err := v.ExecuteCapability(ctx, req); !errors.Is(err, ErrCapabilityNotFound) || err.Error() != "backend down" {
		t.Fatalf("registry error: %v", err)
	}

	v = newCapVault(t, nil, fakeRegistry{"secrets.echo": &fakeSpec{versions: []int{1},
		validate: func(map[string]any) error { return errors.New("plain") }}}, ver)
	if _, err := v.ExecuteCapability(ctx, signedReq(t, ver, req)); !errors.Is(err, ErrValidation) || err.Error() != "plain" {
		t.Fatalf("non-validation schema error: %v", err)
	}

	v = newCapVault(t, nil, fakeRegistry{"secrets.echo": echoSpec()}, ver)
	v.hook = closingHook{v: v}
	if _, err := v.ExecuteCapability(ctx, signedReq(t, ver, req)); !errors.Is(err, ErrClosed) {
		t.Fatalf("audit write after close: %v", err)
	}
	// Audit write failures on the deny path and on the frozen hook path.
	v = newCapVault(t, &scriptedHook{frozen: true}, nil, ver)
	_ = v.Close()
	v.closed = false // usable for the entry check, but the store is closed
	if _, err := v.ExecuteCapability(ctx, req); err == nil || errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("deny with failing audit must return the audit error: %v", err)
	}
	v.closed = true
}

func signedReq(t *testing.T, ver captoken.TokenVerifier, r CapabilityRequest) CapabilityRequest {
	t.Helper()
	r.Token = signT(t, ver, r.Agent, r.Capability, 1, nil)
	return r
}

func TestPyCompactSorted(t *testing.T) {
	var b strings.Builder
	pyCompactSorted(&b, map[string]any{
		"s": []string{"x", "é"}, "m": map[string]string{"b": "1", "a": "2"},
		"n": json.Number("10"), "bad": json.Number("x1"), "i": 7, "f": 2.5, "nil": nil, "t": true,
	})
	// Python: json.dumps({...}, sort_keys=True, separators=(",", ":"))
	want := `{"bad":"x1","f":2.5,"i":7,"m":{"a":"2","b":"1"},"n":10,"nil":null,"s":["x","` + `\u00e9` + `"],"t":true}`
	if b.String() != want {
		t.Fatalf("got  %s\nwant %s", b.String(), want)
	}
}

type nilSpecRegistry struct{}

func (nilSpecRegistry) Lookup(string) (CapabilitySpec, error) { return nil, nil }

func TestExecuteCapabilityReviewFixes(t *testing.T) {
	ctx := context.Background()
	ver := verifierAt(t, time.Unix(1_900_000_000, 0))
	v := newCapVault(t, nil, nilSpecRegistry{}, ver)
	req := CapabilityRequest{Capability: "secrets.echo", Agent: "a"}
	if _, err := v.ExecuteCapability(ctx, signedReq(t, ver, req)); !errors.Is(err, ErrCapabilityNotFound) {
		t.Fatalf("nil spec: %v", err)
	}
	// A panic value (which may hold a secret) never reaches the error text.
	v = newCapVault(t, nil, fakeRegistry{"secrets.echo": &fakeSpec{versions: []int{1},
		invoke: func(context.Context, map[string]any, CapabilityContext) (any, error) { panic("hunter2") }}}, ver)
	_, err := v.ExecuteCapability(ctx, signedReq(t, ver, req))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("panic leaked: %v", err)
	}
}

// TestAuthFailureLockoutBoundary pins Python's RGT-277 boundary
// (python/vault.py: `if self.auth_failure_limiter.count(agent_id) >=
// self.auth_failure_limiter.max_requests` before verifying, record() after a
// failed verify): AuthFailureLimit failed verifications are allowed in the
// window, the next attempt is refused without being verified, and a valid
// token does not lift the lockout.
func TestAuthFailureLockoutBoundary(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0)
	ver := verifierAt(t, now)
	v := newCapVault(t, nil, fakeRegistry{"secrets.echo": echoSpec()}, ver)
	bad := CapabilityRequest{Capability: "secrets.echo", Agent: "a", Token: "x.y"}
	for i := 0; i < AuthFailureLimit-1; i++ {
		v.authFailureLimiter.Record("a")
	}
	// Failure number AuthFailureLimit is still verified (and recorded).
	if _, err := v.ExecuteCapability(ctx, bad); !errors.Is(err, ErrPolicyDenied) {
		t.Fatal(err)
	}
	if rows := lastAudit(t, v, 1); !strings.Contains(rows[0].Details.String, `"reason": "token: TokenMalformedError"`) {
		t.Fatalf("attempt %d must be verified: %s", AuthFailureLimit, rows[0].Details.String)
	}
	if n := v.AuthFailureLimiter().Count("a"); n != AuthFailureLimit {
		t.Fatalf("count = %d, want %d", n, AuthFailureLimit)
	}
	// The next attempt is refused before verification, even with a valid token.
	good := CapabilityRequest{Capability: "secrets.echo", Agent: "a", Token: signT(t, ver, "a", "secrets.echo", 1, nil)}
	for _, r := range []CapabilityRequest{bad, good} {
		_, err := v.ExecuteCapability(ctx, r)
		if err == nil || err.Error() != "agent 'a' locked out: too many failed credential attempts" {
			t.Fatalf("locked-out attempt: %v", err)
		}
		if rows := lastAudit(t, v, 1); !strings.Contains(rows[0].Details.String, `"reason": "too many failed credential verifications"`) {
			t.Fatalf("row = %s", rows[0].Details.String)
		}
	}
	if n := v.AuthFailureLimiter().Count("a"); n != AuthFailureLimit {
		t.Fatalf("a refused attempt must not be recorded again: %d", n)
	}
	// Another agent is unaffected.
	other := CapabilityRequest{Capability: "secrets.echo", Agent: "b", Token: signT(t, ver, "b", "secrets.echo", 1, nil)}
	if _, err := v.ExecuteCapability(ctx, other); err != nil {
		t.Fatalf("other agent: %v", err)
	}
}
