package policy

import (
	"errors"
	"testing"
)

func TestMatchSemantics(t *testing.T) {
	type c struct {
		v, p string
		want bool
	}
	for _, tc := range []c{
		// '*' crosses '/' (unlike path.Match) and newlines; case-sensitive.
		{"a/b/c", "a*c", true}, {"a/b/c", "*", true}, {"a\nb", "a*b", true}, {"a\nb", "a?b", true},
		{"ABC", "abc", false}, {"", "*", true}, {"", "?", false}, {"ab", "a**b", true},
		{"deploy/app", "deploy*", true}, {"/prod", "*/prod", true},
		// character classes
		{"b", "[a-c]", true}, {"d", "[a-c]", false}, {"d", "[!a-c]", true}, {"]", "[]]", true},
		{"a", "[!]]", true}, {"-", "[a-]", true}, {"!", "[!]", false}, {"a", "[]", false},
		{"[", "[", true}, {"[", "[[]", true}, {"^", "[\\^]", true}, {"\\", "[\\^]", true}, {"a", "[\\^]", false},
	} {
		got, err := Match(tc.v, tc.p)
		if err != nil || got != tc.want {
			t.Errorf("Match(%q,%q) = %v,%v want %v", tc.v, tc.p, got, err, tc.want)
		}
	}
}

func TestPatternReuse(t *testing.T) {
	p, err := CompilePattern("a*[0-9]?")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Match("abc1x") || p.Match("abc") {
		t.Fatal("unexpected match results")
	}
}

// Python's translator never raises for these in practice (checked by
// brute force over short sets), so the defensive error branches are
// exercised directly.
func TestDefensiveBranches(t *testing.T) {
	// empty chunk -> IndexError in Python
	if _, err := buildStuff([]rune("[a-x]"), 1, 4); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	if _, err := parseClass([]rune("z-a")); !errors.Is(err, ErrBadPattern) {
		t.Fatalf("bad range: %v", err)
	}
	if tk, err := parseClass([]rune("a-")); err != nil || len(tk.single) != 2 {
		t.Fatalf("trailing dash literal: %+v %v", tk, err)
	}
	if tk, err := parseClass([]rune(`\\`)); err != nil || len(tk.single) != 1 || tk.single[0] != '\\' {
		t.Fatalf("escaped backslash: %+v %v", tk, err)
	}
	if tk, err := parseClass([]rune(`\`)); err != nil || len(tk.single) != 1 {
		t.Fatalf("lone backslash: %+v %v", tk, err)
	}
	if findRune([]rune("abc"), 'c', -3, 10) != 2 {
		t.Fatal("findRune clamps")
	}
	if findRune([]rune("abc"), 'x', 0, 3) != -1 {
		t.Fatal("findRune miss")
	}
	var empty token
	empty.kind = tokNever
	if empty.matches('a') {
		t.Fatal("never matches")
	}
	// chunk repair that empties chunks: both a and b of length 1 -> merged empty, still fine
	if got, err := Match("b", "[a--b]"); err != nil || !got {
		t.Fatalf("[a--b] should match b: %v %v", got, err)
	}
	// a merged-to-empty middle chunk triggers the IndexError branch
	pat := []rune("[xa-b-c--b]")
	if _, err := buildStuff(pat, 1, len(pat)-1); err != nil && !errors.Is(err, ErrBadPattern) {
		t.Fatalf("unexpected error type: %v", err)
	}
	if _, err := CompilePattern("[z-a-]"); err != nil {
		t.Fatalf("python accepts this: %v", err)
	}
	if _, err := Match("x", "[\x00-\x01-\x00]"); err != nil && !errors.Is(err, ErrBadPattern) {
		t.Fatalf("error kind: %v", err)
	}
}

func FuzzMatchTerminates(f *testing.F) {
	f.Add("a/b", "a*b")
	f.Add("]", "[]]")
	f.Fuzz(func(t *testing.T, v, p string) {
		if len(v) > 64 || len(p) > 64 {
			return
		}
		_, _ = Match(v, p)
	})
}
