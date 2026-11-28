package hooks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
)

func TestEventWebhookDeliversJSON(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m["_ct"] = r.Header.Get("Content-Type")
		got <- m
	}))
	defer srv.Close()
	w, err := NewEventWebhook(srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	w.Notify(context.Background(), approval.Event{Kind: approval.EventCodeReplay, RequestID: "r1", Agent: "alice", Operator: "tok1", Detail: "request=r1 attempt=1/5"})
	select {
	case m := <-got:
		if m["event"] != "APPROVAL_CODE_REPLAY" || m["request_id"] != "r1" || m["agent"] != "alice" || m["operator"] != "tok1" ||
			m["_ct"] != "application/json" || m["time"] == "" {
			t.Fatalf("body = %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery")
	}
}

func TestEventWebhookValidationAndGuards(t *testing.T) {
	for _, bad := range []string{"", "ftp://x/y", "http://", "not a url", "/relative"} {
		if _, err := NewEventWebhook(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A non-loopback host is refused at dial time unless allowRemote.
	var mu sync.Mutex
	var logs []string
	w, err := NewEventWebhook("http://203.0.113.9:9/hook?token=SUPERSECRET", false, WithEventTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	w.done = make(chan struct{}, 1)
	w.logf = func(f string, a ...any) { mu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); mu.Unlock() }
	w.Notify(context.Background(), approval.Event{Kind: approval.EventBadCode})
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery attempt did not finish")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 1 || !strings.Contains(logs[0], "failed") || strings.Contains(logs[0], "SUPERSECRET") {
		t.Fatalf("logs = %v", logs)
	}
}

func TestEventWebhookNon2xxAndRedirect(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	for _, path := range []string{"/boom", "/redir"} {
		var logs []string
		w, _ := NewEventWebhook(srv.URL+path, false)
		w.done = make(chan struct{}, 1)
		w.logf = func(f string, a ...any) { mu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); mu.Unlock() }
		w.Notify(context.Background(), approval.Event{Kind: approval.EventLockout})
		<-w.done
		mu.Lock()
		if len(logs) != 1 || !strings.Contains(logs[0], "HTTP") {
			t.Fatalf("%s: logs = %v", path, logs)
		}
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 2 {
		t.Fatalf("hits = %d: a redirect must not be followed", hits)
	}
}

func TestEventWebhookDropsWhenBusy(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	w, _ := NewEventWebhook(srv.URL, false, WithEventTimeout(10*time.Second))
	var mu sync.Mutex
	dropped := 0
	w.logf = func(f string, a ...any) {
		if strings.Contains(f, "dropped") {
			mu.Lock()
			dropped++
			mu.Unlock()
		}
	}
	for i := 0; i < maxEventsInFlight+3; i++ {
		w.Notify(context.Background(), approval.Event{Kind: approval.EventBadCode})
	}
	mu.Lock()
	defer mu.Unlock()
	if dropped != 3 {
		t.Fatalf("dropped = %d, want 3", dropped)
	}
}

func TestEventWebhookDeliverSync(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	w, _ := NewEventWebhook(srv.URL, false)
	if err := w.Deliver(context.Background(), approval.Event{Kind: approval.EventTokenMinted, Detail: "token=abc"}); err != nil {
		t.Fatal(err)
	}
	if b := <-got; !strings.Contains(b, `"event":"TOKEN_MINTED"`) || !strings.Contains(b, "token=abc") {
		t.Fatalf("body = %s", b)
	}
	srv.Close()
	// A dead endpoint is an error without the URL.
	w2, _ := NewEventWebhook(srv.URL+"/secret-path", false, WithEventTimeout(time.Second))
	err := w2.Deliver(context.Background(), approval.Event{Kind: approval.EventTokenMinted})
	if err == nil || strings.Contains(err.Error(), "secret-path") {
		t.Fatalf("err = %v", err)
	}
	// A 500 is an error too.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	w3, _ := NewEventWebhook(bad.URL, false)
	if err := w3.Deliver(context.Background(), approval.Event{Kind: approval.EventTokenMinted}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500 = %v", err)
	}
}

// A slow receiver plus a flood of ordinary events must not hide a lockout.
func TestEventWebhookReservesCapacityForCriticalEvents(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var kinds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		kinds = append(kinds, fmt.Sprint(m["event"]))
		mu.Unlock()
		<-release
	}))
	defer srv.Close()
	w, _ := NewEventWebhook(srv.URL, false, WithEventTimeout(10*time.Second))
	dropped := map[string]int{}
	var dmu sync.Mutex
	w.logf = func(f string, a ...any) {
		if strings.Contains(f, "dropped") {
			dmu.Lock()
			dropped[fmt.Sprint(a[0])]++
			dmu.Unlock()
		}
	}
	for i := 0; i < 100; i++ { // the flood
		w.Notify(context.Background(), approval.Event{Kind: approval.EventBadCode})
	}
	for _, k := range []approval.EventKind{approval.EventLockout, approval.EventAutoDenied, approval.EventSeparation} {
		w.Notify(context.Background(), approval.Event{Kind: k})
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(kinds)
		mu.Unlock()
		if n >= maxEventsInFlight+3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	mu.Lock()
	defer mu.Unlock()
	got := map[string]int{}
	for _, k := range kinds {
		got[k]++
	}
	for _, k := range []string{"APPROVAL_LOCKOUT", "APPROVAL_AUTO_DENIED", "APPROVAL_SOD_DENIED"} {
		if got[k] != 1 {
			t.Errorf("critical event %s delivered %d times (all kinds: %v)", k, got[k], got)
		}
	}
	dmu.Lock()
	defer dmu.Unlock()
	if dropped["APPROVAL_LOCKOUT"]+dropped["APPROVAL_AUTO_DENIED"]+dropped["APPROVAL_SOD_DENIED"] != 0 {
		t.Errorf("critical events were dropped: %v", dropped)
	}
	if dropped["APPROVAL_BAD_CODE"] != 100-maxEventsInFlight {
		t.Errorf("ordinary drops = %d, want %d", dropped["APPROVAL_BAD_CODE"], 100-maxEventsInFlight)
	}
}

// The dial-time guard is what keeps the webhook on loopback: without
// allowRemote a private address is refused by netguard.
func TestEventWebhookRemoteRefusedWithoutAllowRemote(t *testing.T) {
	w, _ := NewEventWebhook("http://10.0.0.5:9/", false, WithEventTimeout(time.Second))
	err := w.Deliver(context.Background(), approval.Event{Kind: approval.EventBadCode})
	if err == nil || !strings.Contains(err.Error(), "netguard") {
		t.Fatalf("allowRemote=false to a private address: %v", err)
	}
	// The cloud metadata address is refused even WITH allowRemote.
	w2, _ := NewEventWebhook("http://169.254.169.254/latest/meta-data/", true, WithEventTimeout(time.Second))
	err = w2.Deliver(context.Background(), approval.Event{Kind: approval.EventBadCode})
	if err == nil || !strings.Contains(err.Error(), "netguard") {
		t.Fatalf("metadata address with allowRemote: %v", err)
	}
	// allowRemote lifts the loopback-only rule (the dial then fails or
	// times out on its own, but not in netguard).
	w3, _ := NewEventWebhook("http://10.255.255.1:9/", true, WithEventTimeout(300*time.Millisecond))
	err = w3.Deliver(context.Background(), approval.Event{Kind: approval.EventBadCode})
	if err != nil && strings.Contains(err.Error(), "netguard") {
		t.Fatalf("allowRemote=true was still refused by netguard: %v", err)
	}
}
