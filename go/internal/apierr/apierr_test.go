package apierr

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	b, ok := Parse([]byte(`{"error":"E","detail":" why ","incident_id":"i"}`))
	if !ok || b.Error != "E" || b.IncidentID != "i" {
		t.Fatalf("Parse = %+v, %v", b, ok)
	}
	for _, bad := range []string{``, `<html>`, `{}`, `{"detail":"  "}`, `{"detail":5}`, `[1]`} {
		if _, ok := Parse([]byte(bad)); ok {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestSafeText(t *testing.T) {
	if got := SafeText("a\x1b[2Jb\nc‮d e\x9bf\xff", 50); got != "a?[2Jb?c?d?e?f?" {
		t.Errorf("SafeText = %q", got)
	}
	if got := SafeText(strings.Repeat("é", 10), 4); got != "éééé…" {
		t.Errorf("cap = %q", got)
	}
	if got := SafeText("abc", 3); got != "abc" {
		t.Errorf("exact cap = %q", got)
	}
}
