package handlers

import (
	"strings"
	"testing"
	"time"
)

func TestEventLimiterCoalesces(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := &eventLimiter{now: func() time.Time { return now }}
	if emit, n := l.allow("t1|X"); !emit || n != 0 {
		t.Fatalf("first = %v %d", emit, n)
	}
	for i := 0; i < 5; i++ {
		if emit, _ := l.allow("t1|X"); emit {
			t.Fatal("repeat inside the window emitted")
		}
	}
	// A different key (another token or kind) is independent.
	if emit, _ := l.allow("t2|X"); !emit {
		t.Fatal("other key suppressed")
	}
	if emit, _ := l.allow("t1|Y"); !emit {
		t.Fatal("other kind suppressed")
	}
	// After the window the next one is emitted and carries the count.
	now = now.Add(eventCoalesceWindow + time.Second)
	emit, n := l.allow("t1|X")
	if !emit || n != 5 {
		t.Fatalf("after window = %v suppressed=%d, want true/5", emit, n)
	}
	if got := suppressedSuffix(5); got != " suppressed=5" || suppressedSuffix(0) != "" {
		t.Fatalf("suffix %q", got)
	}
}

func TestEventLimiterTableIsBoundedAndNeverHidesAnAlert(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := &eventLimiter{now: func() time.Time { return now }}
	for i := 0; i < maxCoalesceKeys; i++ {
		l.allow("k" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + itoa(i))
	}
	// Full of live keys: a new key is still EMITTED (an alert is never lost),
	// just not tracked.
	if emit, _ := l.allow("brand-new"); !emit {
		t.Fatal("alert suppressed by a full table")
	}
	if len(l.m) > maxCoalesceKeys {
		t.Fatalf("table grew to %d", len(l.m))
	}
	// Once the window passes, stale keys are dropped to make room.
	now = now.Add(2 * eventCoalesceWindow)
	if emit, _ := l.allow("another"); !emit {
		t.Fatal("not emitted")
	}
	if len(l.m) >= maxCoalesceKeys {
		t.Fatalf("stale keys kept: %d", len(l.m))
	}
}

func TestSafeID(t *testing.T) {
	for in, want := range map[string]string{
		"abc-123_X": "abc-123_X", "": "<invalid>", "a b": "<invalid>", "x\ny": "<invalid>",
		strings.Repeat("a", 65): "<invalid>", strings.Repeat("a", 64): strings.Repeat("a", 64),
	} {
		if got := safeID(in); got != want {
			t.Errorf("safeID(%q) = %q, want %q", in, got, want)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}
