package vault

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHoneyLimiterCapAndPowersOfTwo(t *testing.T) {
	l := newHoneyLimiter()
	now := time.Unix(1_900_000_000, 0)
	l.now = func() time.Time { return now }
	var written []uint64
	for i := 0; i < 1000; i++ {
		if n, ok := l.admit("mallory"); ok {
			written = append(written, n)
		}
	}
	// 1..32, then 64, 128, 256, 512.
	if len(written) != HoneyAuditPerAgent+4 || written[HoneyAuditPerAgent] != 64 || written[len(written)-1] != 512 {
		t.Fatalf("written = %v", written)
	}
	if n, ok := l.admit("bob"); n != 1 || !ok {
		t.Fatal("per-agent budget")
	}
	now = now.Add(HoneyAuditWindow)
	if n, ok := l.admit("mallory"); n != 1 || !ok {
		t.Fatalf("window reset: %d %v", n, ok)
	}
}

func TestHoneyLimiterBounded(t *testing.T) {
	l := newHoneyLimiter()
	now := time.Unix(1_900_000_000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < honeyMaxAgents+500; i++ {
		l.admit("agent-" + strconv.Itoa(i))
	}
	if len(l.m) > honeyMaxAgents+1 {
		t.Fatalf("limiter grew to %d", len(l.m))
	}
	if w := l.m[honeyOverflowKey]; w == nil || w.n != 500 {
		t.Fatalf("overflow bucket = %+v", w)
	}
	now = now.Add(HoneyAuditWindow)
	if n, ok := l.admit("fresh"); n != 1 || !ok || l.m["fresh"] == nil {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestClipHoneyName(t *testing.T) {
	if ClipHoneyName("short") != "short" {
		t.Fatal("short")
	}
	c := ClipHoneyName(strings.Repeat(" ", 200_000) + "aws.admin.full")
	if len(c) > HoneyNameClip+32 || !strings.HasSuffix(c, "(+199886 bytes)") {
		t.Fatalf("clip = %q", c)
	}
	e := ClipHoneyName(strings.Repeat("é", 100))
	if strings.ContainsRune(e, '�') || !strings.HasSuffix(e, "(+72 bytes)") {
		t.Fatalf("rune clip = %q", e)
	}
}
