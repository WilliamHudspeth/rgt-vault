package hooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

const allowAll = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
`

func openVault(t *testing.T, h vault.Hook, reg vault.CapabilityRegistry, ver captoken.TokenVerifier) *vault.Vault {
	t.Helper()
	v, err := vault.Open(context.Background(), vault.Config{
		DBPath:        filepath.Join(t.TempDir(), "v", "vault.db"),
		Provider:      providerstest.NewMemory(),
		PolicyYAML:    allowAll,
		Hook:          h,
		Capabilities:  reg,
		TokenVerifier: ver,
		KDFParams:     kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

type harness struct {
	mu     sync.Mutex
	bodies []map[string]any
	auth   []string
	reply  func(w http.ResponseWriter)
}

func (h *harness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	h.mu.Lock()
	h.bodies = append(h.bodies, m)
	h.auth = append(h.auth, r.Header.Get("Authorization"))
	reply := h.reply
	h.mu.Unlock()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	reply(w)
}

func replyJSON(s string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = io.WriteString(w, s) }
}

func TestWebhookDecisions(t *testing.T) {
	h := &harness{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	wh, err := NewWebhookHook(srv.URL+"/hook", WithBearerToken("bt"), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name := "db"
	legacy := vault.HookRequest{Operation: "read", Agent: "a", Namespace: "n", Purpose: "p", SecretName: &name, RequestID: "r1", CapabilityToken: "TOKEN"}
	for _, c := range []struct {
		reply    string
		decision vault.HookDecision
		reason   string
		extra    string
	}{
		{`{"decision": "allow", "reason": "ok", "ticket": 7}`, vault.HookAllow, "ok", "7"},
		{`{"decision": "ALLOW"}`, vault.HookAllow, "", ""},
		{`{"decision": "freeze", "reason": "incident"}`, vault.HookFreeze, "incident", ""},
		{`{"decision": "deny", "reason": 5}`, vault.HookDeny, "5", ""},
		{`{"decision": true}`, vault.HookDeny, "", ""},
		{`{"reason": "<script>x</script>"}`, vault.HookDeny, "<script>x</script>", ""},
		{`not json`, vault.HookDeny, "hook response not valid JSON", ""},
		{`{"decision": "allow"} trailing`, vault.HookDeny, "hook response not valid JSON", ""},
	} {
		h.reply = replyJSON(c.reply)
		r, err := wh.Consult(ctx, legacy)
		if err != nil {
			t.Fatalf("%s: %v", c.reply, err)
		}
		if r.Decision != c.decision || r.Reason != c.reason {
			t.Errorf("%s: got %s %q", c.reply, r.Decision, r.Reason)
		}
		if c.extra != "" && r.Extra["ticket"].(json.Number).String() != c.extra {
			t.Errorf("extra = %v", r.Extra)
		}
	}
	h.reply = replyJSON(`[1, 2]`)
	if _, err := wh.Consult(ctx, legacy); err == nil || !strings.Contains(err.Error(), "array") {
		t.Fatalf("non-object response must be an error (deny via preOpCheck): %v", err)
	}
	h.reply = replyJSON(`"x"`)
	if _, err := wh.Consult(ctx, legacy); err == nil {
		t.Fatal("string response")
	}
	h.reply = func(w http.ResponseWriter) { http.Error(w, "nope", http.StatusForbidden) }
	if r, _ := wh.Consult(ctx, legacy); r.Decision != vault.HookDeny || r.Reason != "hook URL unreachable: Forbidden" {
		t.Fatalf("403: %+v", r)
	}
	h.reply = func(w http.ResponseWriter) {
		_, _ = io.WriteString(w, `{"decision":"allow","pad":"`+strings.Repeat("x", 70*1024)+`"}`)
	}
	if r, _ := wh.Consult(ctx, legacy); r.Reason != "hook response not valid JSON" {
		t.Fatalf("oversized response must be truncated and rejected: %+v", r)
	}

	body := h.bodies[0]
	if body["operation"] != "read" || body["secret_name"] != "db" || body["request_id"] != "r1" {
		t.Fatalf("legacy body = %v", body)
	}
	if _, ok := body["capability"]; ok {
		t.Fatal("legacy body must omit capability fields")
	}
	for _, b := range h.bodies {
		for k, v := range b {
			if s, ok := v.(string); ok && strings.Contains(s, "TOKEN") {
				t.Fatalf("token sent to webhook in %q", k)
			}
		}
	}
	if h.auth[0] != "Bearer bt" {
		t.Fatalf("auth header = %q", h.auth[0])
	}

	h.reply = replyJSON(`{"decision":"allow"}`)
	capReq := vault.HookRequest{Operation: vault.OpCapability, Agent: "a", Capability: "c.x", CapabilityVersion: 2,
		Payload: map[string]any{"q": "<b>"}, TokenMetadata: map[string]any{"token_id": "tid"}, RequestID: "r2"}
	if r, _ := wh.Consult(ctx, capReq); r.Decision != vault.HookAllow {
		t.Fatal(r)
	}
	cb := h.bodies[len(h.bodies)-1]
	if cb["capability"] != "c.x" || cb["capability_version"].(float64) != 2 || cb["payload"].(map[string]any)["q"] != "<b>" ||
		cb["token_metadata"].(map[string]any)["token_id"] != "tid" || cb["secret_name"] != nil {
		t.Fatalf("capability body = %v", cb)
	}
}

func TestWebhookUnreachableAndNetguard(t *testing.T) {
	ctx := context.Background()
	// Closed port on loopback.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	wh, _ := NewWebhookHook(url, WithTimeout(time.Second))
	r, err := wh.Consult(ctx, vault.HookRequest{Operation: "list"})
	if err != nil || r.Decision != vault.HookDeny || !strings.HasPrefix(r.Reason, "hook URL unreachable: ") {
		t.Fatalf("closed port: %+v %v", r, err)
	}
	// Metadata / link-local addresses are always refused by netguard, even
	// with AllowRemote.
	wh, _ = NewWebhookHook("http://169.254.169.254/latest", WithAllowRemote(true), WithTimeout(time.Second))
	r, _ = wh.Consult(ctx, vault.HookRequest{Operation: "list"})
	if r.Decision != vault.HookDeny || !strings.Contains(r.Reason, "netguard") {
		t.Fatalf("metadata address: %+v", r)
	}
	// A non-loopback address needs AllowRemote.
	wh, _ = NewWebhookHook("http://192.0.2.1/hook", WithTimeout(time.Second))
	r, _ = wh.Consult(ctx, vault.HookRequest{Operation: "list"})
	if r.Decision != vault.HookDeny || !strings.Contains(r.Reason, "non-loopback") {
		t.Fatalf("remote without opt-in: %+v", r)
	}
	if _, err := NewWebhookHook("::bad"); err == nil {
		t.Fatal("bad url accepted")
	}
	if wh, _ := NewWebhookHook("http://127.0.0.1/", WithTimeout(0)); wh.timeout != DefaultWebhookTimeout {
		t.Fatal("zero timeout must keep the default")
	}
	// Cancelled context.
	h := &harness{reply: replyJSON(`{"decision":"allow"}`)}
	srv2 := httptest.NewServer(h)
	defer srv2.Close()
	wh, _ = NewWebhookHook(srv2.URL)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if r, _ := wh.Consult(cctx, vault.HookRequest{Operation: "list"}); r.Decision != vault.HookDeny {
		t.Fatalf("cancelled: %+v", r)
	}
	if jsonKind(nil) != "null" || jsonKind(true) != "boolean" || jsonKind(json.Number("1")) != "number" {
		t.Fatal("jsonKind")
	}
}

// TestWebhookThroughVault: a harness denial reaches the caller as a policy
// denial with the hook id and reason, and the audit row records it.
func TestWebhookThroughVault(t *testing.T) {
	h := &harness{reply: replyJSON(`{"decision":"deny","reason":"change freeze"}`)}
	srv := httptest.NewServer(h)
	defer srv.Close()
	wh, _ := NewWebhookHook(srv.URL)
	v := openVault(t, wh, nil, nil)
	ctx := context.Background()
	_, err := v.ListSecrets(ctx, vault.ListRequest{Namespace: "default", Agent: "bot"})
	if err == nil || !strings.Contains(err.Error(), "change freeze") || !strings.Contains(err.Error(), "webhook:"+srv.URL) {
		t.Fatalf("list: %v", err)
	}
	h.reply = replyJSON(`[]`)
	_, err = v.ListSecrets(ctx, vault.ListRequest{Namespace: "default", Agent: "bot"})
	if err == nil || !strings.Contains(err.Error(), "hook raised error") {
		t.Fatalf("non-object reply must deny: %v", err)
	}
	ok, err := v.VerifyAuditChain(ctx)
	if !ok || err != nil {
		t.Fatal("audit chain", ok, err)
	}
}
