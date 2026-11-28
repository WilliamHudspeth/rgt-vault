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

	"rgt-vault-server/internal/approval"
)

// TestEventWebhookHoneyFloodCannotStarveCritical (RGT-30 review MED-1c): a
// blocked receiver and a flood of honey-capability events (attacker-driven)
// must not cost a later lockout / auto-denied / separation-of-duties alert
// its delivery slot.
func TestEventWebhookHoneyFloodCannotStarveCritical(t *testing.T) {
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
		<-release // the receiver hangs
	}))
	defer srv.Close()
	defer close(release)
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
	for i := 0; i < 50; i++ {
		w.Notify(context.Background(), approval.Event{Kind: approval.EventHoneyCapability})
	}
	crit := []approval.EventKind{approval.EventLockout, approval.EventAutoDenied, approval.EventSeparation}
	for _, k := range crit {
		w.Notify(context.Background(), approval.Event{Kind: k})
	}
	want := maxHoneyInFlight + len(crit)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(kinds)
		mu.Unlock()
		if n >= want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := map[string]int{}
	for _, k := range kinds {
		got[k]++
	}
	mu.Unlock()
	for _, k := range crit {
		if got[string(k)] != 1 {
			t.Errorf("%s delivered %d times during a honey flood (all: %v)", k, got[string(k)], got)
		}
	}
	if got["HONEY_CAPABILITY_TRIGGERED"] != maxHoneyInFlight {
		t.Errorf("honey deliveries = %d, want %d", got["HONEY_CAPABILITY_TRIGGERED"], maxHoneyInFlight)
	}
	dmu.Lock()
	defer dmu.Unlock()
	if dropped["HONEY_CAPABILITY_TRIGGERED"] != 50-maxHoneyInFlight {
		t.Errorf("honey drops = %d", dropped["HONEY_CAPABILITY_TRIGGERED"])
	}
	for _, k := range crit {
		if dropped[string(k)] != 0 {
			t.Errorf("%s dropped", k)
		}
	}
}
