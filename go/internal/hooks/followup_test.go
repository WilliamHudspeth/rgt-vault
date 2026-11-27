package hooks

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rgt-vault-server/internal/vault"
)

// Follow-ups to the review of PR #45.

// Redact never shows any part of a secret-looking value (Python shows the
// first four characters; Go deliberately does not).
func TestRedactNoPrefix(t *testing.T) {
	for _, s := range []string{
		"sk-live-ABCDEFGHIJKLMNOPQRSTUVWX",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		strings.Repeat("f", 64),
	} {
		got := Redact(map[string]any{"q": s, "l": []any{s}}).(map[string]any)
		if got["q"] != Redacted || got["l"].([]any)[0] != Redacted {
			t.Fatalf("%s -> %v", s, got)
		}
		for _, v := range []string{got["q"].(string), got["l"].([]any)[0].(string)} {
			if strings.Contains(v, s[:4]) {
				t.Fatalf("prefix of %q leaked: %q", s, v)
			}
		}
	}
	var buf bytes.Buffer
	h := NewLogRedactionHook(slog.New(slog.NewTextHandler(&buf, nil)))
	secret := "zq9X" + strings.Repeat("A", 30)
	h.OnCapabilityRequest(RequestContext{AgentID: "a"}, map[string]any{"query": secret})
	if strings.Contains(buf.String(), "zq9X") {
		t.Fatalf("log contains a secret prefix: %s", buf.String())
	}
}

// Webhook hook ids (audit rows, denial messages) and deny reasons never
// contain userinfo (whatever its form), the query, fragment or path.
func TestWebhookHookIDNeverContainsUserinfo(t *testing.T) {
	for _, raw := range []string{
		"https://user:hunter2@soar.example/hook",
		"https://user:@soar.example/hook",
		"https://hunter2@soar.example/hook",               // token as user name
		"https://us%40er:hun%3Ater2%2F@soar.example/hook", // percent-encoded
		"https://user:hunter2@soar.example:8443/hook?k=hunter2#hunter2",
		"http://user:hunter2@[::1]:9/hook",
		"https://hooks.slack.example/services/T000/B000/hunter2", // secret in the path
	} {
		wh, err := NewWebhookHook(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		id := wh.ID()
		for _, leak := range []string{"hunter2", "hun%3Ater2", "user", "us%40er", "@"} {
			if strings.Contains(id, leak) {
				t.Errorf("%s: hook id %q contains %q", raw, id, leak)
			}
		}
		if !strings.HasPrefix(id, "webhook:http") || strings.Count(id, "/") != 2 {
			t.Errorf("%s: hook id %q is not scheme://host", raw, id)
		}
	}
	// The unreachable reason never carries the URL (or its password) either.
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.Listener.Addr().String()
	srv.Close()
	wh, _ := NewWebhookHook("http://user:hunter2@"+addr+"/hook", WithTimeout(time.Second))
	r, _ := wh.Consult(context.Background(), vault.HookRequest{Operation: "list"})
	if r.Decision != vault.HookDeny || strings.Contains(r.Reason, "hunter2") {
		t.Fatalf("reason = %q", r.Reason)
	}
	// And the denial a vault returns names only the redacted id.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"no"}`))
	}))
	defer srv2.Close()
	wh, _ = NewWebhookHook(strings.Replace(srv2.URL, "http://", "http://user:hunter2@", 1))
	v := openVault(t, wh, nil, nil)
	_, err := v.ListSecrets(context.Background(), vault.ListRequest{Namespace: "default", Agent: "bot"})
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("denial: %v", err)
	}
	rows, _ := v.AuditLog(context.Background(), -1)
	for _, row := range rows {
		if strings.Contains(row.Details.String, "hunter2") {
			t.Fatalf("audit row leaks the password: %s", row.Details.String)
		}
	}
}

// Expired ids are purged on every accept, not only when the cache is full.
func TestReplayCachePurgesExpiredOnEveryAccept(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	clock := now
	h, _ := NewTwoFactorHook(testKey, WithClock(func() time.Time { return clock }))
	for i, exp := range []int64{now.Unix() + 10, now.Unix() + 20, 0} {
		if r := h.accept(string(rune('a'+i)), exp, "ok"); r.Decision != vault.HookAllow {
			t.Fatal(r)
		}
	}
	clock = now.Add(15 * time.Second) // "a" expired, "b" live, "c" never expires
	if r := h.accept("d", now.Unix()+100, "ok"); r.Decision != vault.HookAllow {
		t.Fatal(r)
	}
	if _, ok := h.seen["a"]; ok {
		t.Fatal("expired id not purged on a non-full cache")
	}
	for _, id := range []string{"b", "c", "d"} {
		if _, ok := h.seen[id]; !ok {
			t.Fatalf("live id %s purged", id)
		}
	}
	// A still-live id stays a replay.
	if r := h.accept("b", now.Unix()+20, "ok"); r.Reason != "capability_token replay detected" {
		t.Fatalf("replay after purge: %+v", r)
	}
	// An expired v1 token cannot come back once its id is purged: its own
	// expiry check rejects it first.
	issue, _ := NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }))
	tok, _, _ := issue.Issue("a", "ns", []string{"read"}, 5)
	h2, _ := NewTwoFactorHook(testKey, WithClock(func() time.Time { return now }))
	req := vault.HookRequest{Operation: "read", Agent: "a", Namespace: "ns", CapabilityToken: tok}
	if r, _ := h2.Consult(context.Background(), req); r.Decision != vault.HookAllow {
		t.Fatal(r)
	}
	h2.now = func() time.Time { return now.Add(time.Minute) }
	_ = h2.accept("other", now.Unix()+3600, "ok") // triggers the purge
	if r, _ := h2.Consult(context.Background(), req); r.Decision != vault.HookDeny {
		t.Fatalf("expired token accepted after purge: %+v", r)
	}
}
