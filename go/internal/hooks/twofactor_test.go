package hooks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/validation"
	"rgt-vault-server/internal/vault"
)

const vectorsDir = "../../testdata/pyvault/vectors"

type vecRequest struct {
	Operation         string         `json:"operation"`
	Agent             string         `json:"agent"`
	Namespace         string         `json:"namespace"`
	Capability        *string        `json:"capability"`
	CapabilityVersion int            `json:"capability_version"`
	Payload           map[string]any `json:"payload"`
	Token             string         `json:"token"`
}

type vecExpect struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type vecCase struct {
	Name     string       `json:"name"`
	Now      int64        `json:"now"`
	Requests []vecRequest `json:"requests"`
	Expect   []vecExpect  `json:"expect"`
}

func loadVec(t *testing.T, file string, sub func(raw map[string]json.RawMessage) json.RawMessage) (key []byte, cases []vecCase) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	src := raw
	if sub != nil {
		if err := json.Unmarshal(sub(raw), &src); err != nil {
			t.Fatal(err)
		}
	}
	var keyHex string
	if err := json.Unmarshal(src["key_hex"], &keyHex); err != nil {
		t.Fatal(err)
	}
	if key, err = hex.DecodeString(keyHex); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(src["cases"], &cases); err != nil {
		t.Fatal(err)
	}
	return key, cases
}

// pyReasonDiffers lists the vector cases where Go's reason legitimately
// differs from Python's (the vectors pin the decision; the reason is
// Python's wording): Python's urlsafe_b64decode silently drops invalid
// characters, so its bad_base64 case reaches the signature check, while Go
// decodes strictly.
var pyReasonDiffers = map[string]string{
	"bad_base64": "capability_token base64 decode failed",
}

func runVectors(t *testing.T, key []byte, cases []vecCase) {
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			now := time.Unix(c.Now, 0)
			h, err := NewTwoFactorHook(key, WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatal(err)
			}
			for i, r := range c.Requests {
				req := vault.HookRequest{
					Operation: r.Operation, Agent: r.Agent, Namespace: r.Namespace,
					CapabilityVersion: r.CapabilityVersion, CapabilityToken: r.Token, RequestID: "rid",
				}
				if r.Capability != nil {
					req.Capability = *r.Capability
				}
				if r.Payload != nil {
					req.Payload = r.Payload
				}
				resp, err := h.Consult(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				want := c.Expect[i]
				if string(resp.Decision) != want.Decision {
					t.Fatalf("request %d: decision %s (%s), want %s (%s)", i, resp.Decision, resp.Reason, want.Decision, want.Reason)
				}
				wantReason := want.Reason
				if alt, ok := pyReasonDiffers[c.Name]; ok {
					wantReason = alt
				}
				if resp.Reason != wantReason {
					t.Errorf("request %d: reason %q, want %q", i, resp.Reason, wantReason)
				}
				if resp.Decision == vault.HookAllow && resp.Extra["token_id"] == "" {
					t.Errorf("allow without token_id extra")
				}
			}
		})
	}
}

func TestTwoFactorV1Vectors(t *testing.T) {
	key, cases := loadVec(t, "tokens_v1.json", nil)
	runVectors(t, key, cases)
}

func TestTwoFactorV2Vectors(t *testing.T) {
	key, cases := loadVec(t, "tokens_v2.json", func(raw map[string]json.RawMessage) json.RawMessage { return raw["hook_v2"] })
	runVectors(t, key, cases)
}

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestTwoFactorIssueSignsWithSharedSecret(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	h, err := NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }), WithMaxTTL(120))
	if err != nil {
		t.Fatal(err)
	}
	tok, ct, err := h.Issue("agent", "prod", []string{"read"}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if ct.ExpiresAt != now.Unix()+60 || ct.TokenID == "" {
		t.Fatalf("claims = %+v", ct)
	}
	// Python's to_compact() signs with an empty key: that token is rejected.
	pyTok, _ := ct.ToCompact(nil)
	if pyTok == tok {
		t.Fatal("Issue must not reproduce the empty-key signature")
	}
	resp, _ := h.Consult(context.Background(), vault.HookRequest{Operation: "read", Agent: "agent", Namespace: "prod", CapabilityToken: pyTok})
	if resp.Decision != vault.HookDeny || resp.Reason != "capability_token signature invalid" {
		t.Fatalf("empty-key token: %+v", resp)
	}
	resp, _ = h.Consult(context.Background(), vault.HookRequest{Operation: "read", Agent: "agent", Namespace: "prod", CapabilityToken: tok})
	if resp.Decision != vault.HookAllow {
		t.Fatalf("issued token: %+v", resp)
	}
	resp, _ = h.Consult(context.Background(), vault.HookRequest{Operation: "read", Agent: "agent", Namespace: "prod", CapabilityToken: tok})
	if resp.Reason != "capability_token replay detected" {
		t.Fatalf("replay: %+v", resp)
	}
	if _, _, err := h.Issue("a", "n", nil, 121); !errors.Is(err, captoken.ErrValidation) {
		t.Fatalf("ttl over max: %v", err)
	}
	if _, err := NewTwoFactorHook(make([]byte, 31)); !errors.Is(err, validation.ErrValidation) {
		t.Fatalf("short secret: %v", err)
	}
}

func TestTwoFactorV2IssueAndReasons(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	h, _ := NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }))
	if h.Verifier() == nil {
		t.Fatal("no verifier")
	}
	tok, err := h.IssueV2("a", "cap.x", 1, map[string]any{"k": "v"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	capReq := func(token string, payload any) vault.HookRequest {
		return vault.HookRequest{Operation: vault.OpCapability, Agent: "a", Capability: "cap.x",
			CapabilityVersion: 1, Payload: payload, CapabilityToken: token}
	}
	resp, _ := h.Consult(context.Background(), capReq(tok, nil))
	if resp.Reason != "v2 token context binding failed: capability 'cap.x' requires context key 'k' in the request" {
		t.Fatalf("nil payload: %+v", resp)
	}
	// v2 envelope with an unsupported version / non-JSON body.
	resp, _ = h.Consult(context.Background(), capReq("eyJ2IjoyfQ.AAAA", nil))
	if resp.Decision != vault.HookDeny {
		t.Fatalf("bad v2: %+v", resp)
	}
	other, _ := captoken.NewHMACTokenVerifier([]byte("ffffffffffffffffffffffffffffffff"))
	forged, _ := other.Sign("a", "cap.x", 1, nil, 30)
	resp, _ = h.Consult(context.Background(), capReq(forged, nil))
	if resp.Reason != "v2 token signature invalid" {
		t.Fatalf("forged: %+v", resp)
	}
	resp, _ = h.Consult(context.Background(), capReq("eyJ2IjoyLCJhIjoxfQ.c2ln", nil))
	if resp.Reason != "v2 token signature invalid" && resp.Reason[:17] != "v2 token malforme" {
		t.Fatalf("garbage: %+v", resp)
	}
}

func TestTwoFactorReplayCacheEviction(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	h, _ := NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }), WithReplayCacheSize(1))
	if h.maxCache != 2 {
		t.Fatalf("min cache = %d", h.maxCache)
	}
	h, _ = NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }), WithReplayCacheSize(4))
	for i := 0; i < 4; i++ {
		if r := h.accept(fmt.Sprintf("id-%d", i), int64(100+i), "ok"); r.Decision != vault.HookAllow {
			t.Fatal(r)
		}
	}
	// Full: the two earliest-expiring ids are evicted, then id-4 inserted.
	if r := h.accept("id-4", 200, "ok"); r.Decision != vault.HookAllow {
		t.Fatal(r)
	}
	if r := h.accept("id-0", 100, "ok"); r.Decision != vault.HookAllow {
		t.Fatalf("evicted id must be accepted again: %+v", r)
	}
	if r := h.accept("id-3", 103, "ok"); r.Reason != "capability_token replay detected" {
		t.Fatalf("id-3 should still be cached: %+v", r)
	}
}

func TestTwoFactorConcurrentReplay(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	h, _ := NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }))
	tok, _, _ := h.Issue("a", "ns", []string{"*"}, 60)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := h.Consult(context.Background(), vault.HookRequest{Operation: "read", Agent: "a", Namespace: "ns", CapabilityToken: tok})
			if r.Decision == vault.HookAllow {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatalf("token accepted %d times, want exactly once", allowed)
	}
}
