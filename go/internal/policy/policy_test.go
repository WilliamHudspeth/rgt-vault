package policy

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, y string) *Engine {
	t.Helper()
	e, err := Parse(y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return e
}

func TestDefaultDeny(t *testing.T) {
	for _, y := range []string{"", "  \n", "# c\n", "foo: 1\n", "hello\n", "[]\n"} {
		e := mustParse(t, y)
		d := e.Evaluate("a", "n", "p", "read")
		if d.Allowed || d.Reason != "No matching allow rule (default deny)" || d.MatchedRule != nil {
			t.Errorf("%q: %+v", y, d)
		}
		if e.RuleCount() != 0 {
			t.Errorf("%q: rule count %d", y, e.RuleCount())
		}
	}
}

func TestExplainNone(t *testing.T) {
	got := mustParse(t, "").Explain("a", "n", "p", "read")
	want := "Access: DENIED\nReason: No matching allow rule (default deny)\nMatched Rule: None"
	if got != want {
		t.Fatalf("%q", got)
	}
}

func TestDenyWinsOverAllowAnyOrder(t *testing.T) {
	for _, y := range []string{
		"- {effect: allow}\n- {effect: deny, agent: x}\n",
		"- {effect: deny, agent: x}\n- {effect: allow}\n",
	} {
		e := mustParse(t, y)
		if d := e.Evaluate("x", "n", "p", "a"); d.Allowed || d.Reason != "Explicit deny rule matched" {
			t.Errorf("%q: %+v", y, d)
		}
		if d := e.Evaluate("y", "n", "p", "a"); !d.Allowed {
			t.Errorf("%q: other agent should be allowed: %+v", y, d)
		}
	}
}

func TestLastAllowRuleReported(t *testing.T) {
	e := mustParse(t, "- {effect: allow, agent: '*', note: first}\n- {effect: allow, agent: '*', note: second}\n")
	d := e.Evaluate("a", "n", "p", "r")
	if n, _ := d.MatchedRule.Get("note"); n != "second" {
		t.Fatalf("python keeps the last matching allow rule, got %v", n)
	}
}

func TestSizeCap(t *testing.T) {
	big := "# " + strings.Repeat("a", MaxPolicyChars) + "\n"
	if _, err := Parse(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	// Multi-byte characters: the cap is in characters, not bytes.
	ok := "# " + strings.Repeat("é", MaxPolicyChars-4) + "\n"
	if len(ok) <= MaxPolicyChars {
		t.Fatal("test setup: expected more bytes than characters")
	}
	if _, err := Parse(ok); err != nil {
		t.Fatalf("under the character cap but rejected: %v", err)
	}
	exact := strings.Repeat("#", MaxPolicyChars)
	if _, err := Parse(exact); err != nil {
		t.Fatalf("exactly the cap must be accepted: %v", err)
	}
	if _, err := Parse(exact + "#"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("cap+1 must be rejected: %v", err)
	}
}

func TestInvalidUTF8(t *testing.T) {
	if _, err := Parse("- {effect: allow, agent: \xff}"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestMalformedPolicies(t *testing.T) {
	cases := map[string]string{
		"rules scalar":     "rules: 5\n",
		"rules null":       "rules:\n",
		"rules map":        "rules: {a: 1}\n",
		"rule scalar":      "- allow\n",
		"rule null":        "- ~\n",
		"rule list":        "- [a, b]\n",
		"agent int":        "- {effect: allow, agent: 5}\n",
		"namespace list":   "- {effect: allow, namespace: [a]}\n",
		"purpose null":     "- {effect: allow, purpose: ~}\n",
		"action bool":      "- {effect: allow, action: [x]}\n",
		"complex key":      "- {? [a, b] : c}\n",
		"bad yaml":         "- {unclosed\n",
		"multi doc":        "- effect: allow\n---\n- effect: deny\n",
		"merge bad":        "- {<<: 5, effect: allow}\n",
		"decode scalar nd": "- {effect: allow, x: !!int abc}\n",
	}
	for name, y := range cases {
		if _, err := Parse(y); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestDuplicateRulesKeyLastWins(t *testing.T) {
	e := mustParse(t, "rules: 5\nrules:\n  - {effect: allow}\n")
	if e.RuleCount() != 1 {
		t.Fatalf("rule count = %d", e.RuleCount())
	}
}

func TestMergeKeysAndAliases(t *testing.T) {
	y := `
base: &base {effect: allow, namespace: shared, purpose: from-base}
other: &other {action: read}
rules:
  - <<: *base
    purpose: explicit
  - <<: [*base, *other]
    agent: svc
  - *base
`
	e := mustParse(t, y)
	rules := e.Rules()
	if len(rules) != 3 {
		t.Fatalf("rules = %d", len(rules))
	}
	if p, _ := rules[0].Get("purpose"); p != "explicit" {
		t.Errorf("explicit key must win over merge: %v", p)
	}
	if a, _ := rules[1].Get("action"); a != "read" {
		t.Errorf("merged key missing: %v", a)
	}
	if got := rules[0].Keys(); len(got) != 3 || got[0] != "purpose" {
		t.Errorf("keys = %v", got)
	}
	if rules[0].Len() != 3 {
		t.Errorf("len = %d", rules[0].Len())
	}
}

func TestDuplicateKeyInRuleLastWins(t *testing.T) {
	e := mustParse(t, "- {effect: allow, agent: a, agent: b}\n")
	if !e.Evaluate("b", "n", "p", "x").Allowed || e.Evaluate("a", "n", "p", "x").Allowed {
		t.Fatal("last duplicate key must win (PyYAML)")
	}
}

func TestEffectCaseInsensitiveAndNonString(t *testing.T) {
	e := mustParse(t, "- {effect: ALLOW, agent: a}\n- {effect: [allow], agent: b}\n- {effect: 5, agent: c}\n- {agent: d}\n")
	if !e.Evaluate("a", "n", "p", "x").Allowed {
		t.Error("ALLOW should allow")
	}
	for _, a := range []string{"b", "c", "d"} {
		if e.Evaluate(a, "n", "p", "x").Allowed {
			t.Errorf("agent %s: non-allow effect must not allow", a)
		}
	}
	if (&Rule{}).Len() != 0 {
		t.Error("zero Rule")
	}
	if _, ok := e.Rules()[3].Get("effect"); ok {
		t.Error("missing effect reported present")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(p, []byte("- {effect: allow, agent: a}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(p)
	if err != nil || !e.Evaluate("a", "n", "p", "x").Allowed {
		t.Fatalf("Load: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file should error")
	}
	huge := filepath.Join(dir, "huge.yaml")
	if err := os.WriteFile(huge, []byte(strings.Repeat("a", 4*MaxPolicyChars+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(huge); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("reading a directory should error")
	}
}

func TestHashPolicy(t *testing.T) {
	if HashPolicy("") != "" {
		t.Error("empty policy must hash to empty string")
	}
	// Whitespace-only text still hashes (Python tests `if policy_yaml`).
	if h := HashPolicy(" "); len(h) != 16 {
		t.Errorf("hash length %d", len(h))
	}
	if mustParse(t, "").Hash() != "" {
		t.Error("Engine.Hash on empty policy")
	}
}

func TestMarshalJSONOrdered(t *testing.T) {
	e := mustParse(t, "- {effect: allow, zeta: 1, alpha: [1, {k: v}], mm: {x: 1}, s: 'é'}\n")
	b, err := json.Marshal(e.Evaluate("a", "n", "p", "x"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"allowed":true,"reason":"Allow rule matched","matched_rule":{"effect":"allow","zeta":1,"alpha":[1,{"k":"v"}],"mm":{"x":1},"s":"é"}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	b, _ = json.Marshal(mustParse(t, "").Evaluate("a", "n", "p", "x"))
	if string(b) != `{"allowed":false,"reason":"No matching allow rule (default deny)","matched_rule":null}` {
		t.Fatalf("nil rule json: %s", b)
	}
}

func TestJSONSafeNonStringKeys(t *testing.T) {
	e := mustParse(t, "- {effect: allow, m: {1: a, true: b, x: c}}\n")
	d := e.Evaluate("a", "n", "p", "x")
	if _, err := json.Marshal(d); err != nil {
		t.Fatalf("marshal with non-string nested keys: %v", err)
	}
	if !strings.Contains(d.Explain(), `"m": {`) {
		t.Fatalf("explain: %s", d.Explain())
	}
}

func TestLeaseTTLDetails(t *testing.T) {
	y := `
- {effect: allow, agent: exact, action: read, ttl: 11}
- {effect: allow, agent: "*", action: read, ttl: 22}
- {effect: allow, action: read, ttl: 33}
- {effect: allow, agent: exact, action: "*", ttl: 44}
- {effect: allow, agent: other, action: read, ttl: 55}
- {effect: allow, agent: "*", action: "*", ttl: 66}
- {effect: allow, agent: nottl, action: read}
- {effect: allow, agent: floaty, action: read, ttl: 3.99}
- {effect: allow, agent: huge, action: read, ttl: 1.0e+30}
- {effect: allow, agent: nan, action: read, ttl: .nan}
- {effect: allow, agent: inf, action: read, ttl: .inf}
- {effect: allow, agent: lst, action: read, ttl: [1]}
- {effect: allow, agent: neghuge, action: read, ttl: "-99999999999999999999"}
- {effect: allow, agent: pos, action: read, ttl: "99999999999999999999"}
- {effect: allow, agent: sp, action: read, ttl: "_1"}
- {effect: allow, agent: sp2, action: read, ttl: "1_"}
- {effect: allow, agent: sp3, action: read, ttl: "+"}
- {effect: allow, agent: sp4, action: read, ttl: ""}
- {effect: allow, agent: sp5, action: read, ttl: "٣"}
- {effect: allow, agent: sp6, action: read, ttl: 0x1F}
- {effect: allow, agent: neg, action: read, ttl: -9}
`
	e := mustParse(t, y)
	want := map[string]int{
		"exact": 11, "someone": 22, "other": 55, "nottl": DefaultLeaseTTL, "floaty": 3,
		"huge": math.MaxInt, "nan": DefaultLeaseTTL, "inf": DefaultLeaseTTL, "lst": DefaultLeaseTTL,
		"neghuge": 1, "pos": math.MaxInt, "sp": DefaultLeaseTTL, "sp2": DefaultLeaseTTL, "sp3": DefaultLeaseTTL,
		"sp4": DefaultLeaseTTL, "sp5": DefaultLeaseTTL, "sp6": 31, "neg": 1,
	}
	for agent, ttl := range want {
		if got := e.LeaseTTL(agent, "read"); got != ttl {
			t.Errorf("LeaseTTL(%s, read) = %d, want %d", agent, got, ttl)
		}
	}
	if got := e.LeaseTTL("exact", "write"); got != 44 {
		t.Errorf("exact agent + wildcard action: %d", got)
	}
	if got := e.LeaseTTL("zzz", "write"); got != 66 {
		t.Errorf("wildcard/wildcard: %d", got)
	}
	if got := mustParse(t, "").LeaseTTL("a", "b"); got != DefaultLeaseTTL {
		t.Errorf("empty policy: %d", got)
	}
}

func TestPyIntOfTypes(t *testing.T) {
	cases := []struct {
		in   any
		want int64
		ok   bool
	}{
		{true, 1, true}, {false, 0, true}, {int(7), 7, true}, {int64(-3), -3, true},
		{uint64(math.MaxUint64), math.MaxInt64, true}, {uint64(5), 5, true},
		{float64(2.9), 2, true}, {float64(-2.9), -2, true}, {math.NaN(), 0, false}, {math.Inf(1), 0, false},
		{1e300, math.MaxInt64, true}, {-1e300, math.MinInt64, true},
		{" 12 ", 12, true}, {"1_2", 12, true}, {"abc", 0, false}, {nil, 0, false}, {[]any{1}, 0, false},
		{"-99999999999999999999", math.MinInt64, true},
	}
	for _, c := range cases {
		n, ok := pyIntOf(c.in)
		if ok != c.ok || (ok && n != c.want) {
			t.Errorf("pyIntOf(%v) = %d,%v want %d,%v", c.in, n, ok, c.want, c.ok)
		}
	}
}

func TestPyJSONHelpers(t *testing.T) {
	cases := map[string]any{
		"null": nil, "true": true, "false": false, `"x"`: "x", "5": 5, "-5": int64(-5),
		"18446744073709551615": uint64(math.MaxUint64), "[1, 2]": []any{1, 2},
		`{"a": 1, "b": 2}`:             map[string]any{"b": 2, "a": 1},
		`{"1": "x"}`:                   map[any]any{1: "x"},
		"\"\\u00e9\\ud83d\\ude00\\n\"": "é😀\n",
		"1.0":                          1.0, "1e-05": 1e-5, "1e+16": 1e16, "123456789.125": 123456789.125,
		"0.0": 0.0, "-0.0": math.Copysign(0, -1), "NaN": math.NaN(), "Infinity": math.Inf(1), "-Infinity": math.Inf(-1),
		"0.001": 0.001, "1.5e+300": 1.5e300, "100.0": 100.0, "1234567890123456.0": 1234567890123456.0,
	}
	for want, in := range cases {
		if got := pyJSON(in); got != want {
			t.Errorf("pyJSON(%#v) = %s want %s", in, got, want)
		}
	}
	type odd struct{ A int }
	if got := pyJSON(odd{1}); got != `"{1}"` {
		t.Errorf("fallback: %s", got)
	}
}
