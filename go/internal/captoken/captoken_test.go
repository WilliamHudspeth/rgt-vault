package captoken

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

var testKey = bytes.Repeat([]byte{0xAB}, 32)

func newVerifier(t *testing.T, opts ...Option) *HMACTokenVerifier {
	t.Helper()
	v, err := NewHMACTokenVerifier(testKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPyFloatRepr(t *testing.T) {
	cases := map[float64]string{
		1.0: "1.0", 0.5: "0.5", 1e21: "1e+21", 1e-7: "1e-07", 123456789.123: "123456789.123",
		1e22: "1e+22", 9007199254740993.0: "9007199254740992.0", 0.00001234: "1.234e-05",
		1e16: "1e+16", 1e15: "1000000000000000.0", 12345678901234567890.0: "1.2345678901234567e+19",
		-2.5: "-2.5", 0.001: "0.001", 0.0001: "0.0001", 0.00012345: "0.00012345", 1.5e-10: "1.5e-10",
		100.0: "100.0", math.Pow(2, 70): "1.1805916207174113e+21", -1e-05: "-1e-05",
		3.141592653589793: "3.141592653589793", 0: "0.0", math.Copysign(0, -1): "-0.0",
	}
	for f, want := range cases {
		got, err := pyFloatRepr(f)
		if err != nil || got != want {
			t.Errorf("pyFloatRepr(%v) = %q, %v; want %q", f, got, err, want)
		}
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := pyFloatRepr(bad); !errors.Is(err, ErrValidation) {
			t.Errorf("pyFloatRepr(%v) err = %v", bad, err)
		}
	}
}

func TestCanonicalJSON(t *testing.T) {
	type s struct{ A int }
	cases := []struct {
		in   any
		want string
	}{
		{nil, `null`},
		{true, `true`},
		{"a<b>&\u00e9\U0001f600\x7f\x00\"\\/", `"a<b>&\u00e9\ud83d\ude00\u007f\u0000\"\\/"`},
		{int8(-3), `-3`},
		{uint64(math.MaxUint64), `18446744073709551615`},
		{float32(0.5), `0.5`},
		{json.Number("1.0"), `1.0`},
		{json.Number("1E2"), `100.0`},
		{json.Number("-12345678901234567890123"), `-12345678901234567890123`},
		{[]string{"b", "a"}, `["b","a"]`},
		{[2]int{1, 2}, `[1,2]`},
		{[]int(nil), `[]`},
		{map[string]any{"b": 1, "a": []any{nil, map[string]string{"y": "1", "x": "2"}}}, `{"a":[null,{"x":"2","y":"1"}],"b":1}`},
		{(*int)(nil), `null`},
		{func() *int { i := 5; return &i }(), `5`},
	}
	for _, c := range cases {
		got, err := canonicalJSON(c.in)
		if err != nil || string(got) != c.want {
			t.Errorf("canonicalJSON(%#v) = %s, %v; want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []any{map[int]int{1: 1}, struct{}{}, "\xff", math.NaN(), json.Number("abc"), json.Number("1e999"), json.Number("--1"), make(chan int)} {
		if _, err := canonicalJSON(bad); err == nil {
			t.Errorf("canonicalJSON(%#v) should fail", bad)
		}
	}
	if _, err := canonicalJSON(map[string]any{"k": []any{math.Inf(1)}}); err == nil {
		t.Error("nested Inf accepted")
	}
	if _, err := canonicalJSON(map[string]any{"k\xff": 1}); err == nil {
		t.Error("bad key accepted")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v := newVerifier(t, WithClock(func() time.Time { return now }))
	tokStr, err := v.Sign("agent", "github.read_repo", 2, map[string]any{"repo": "org/x"}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(tokStr, "=+/") || strings.Count(tokStr, ".") != 1 {
		t.Fatalf("envelope shape: %q", tokStr)
	}
	tok, err := v.Verify(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt != now.Unix()+60 || tok.AgentID != "agent" || len(tok.TokenID) != 16 {
		t.Fatalf("%+v", tok)
	}
	if err := tok.Authorize("agent", "github.read_repo", 2, map[string]any{"repo": "org/x", "extra": 1}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		agent, cap string
		ver        int
		ctx        map[string]any
		want       error
	}{
		{"other", "github.read_repo", 2, nil, ErrAudience},
		{"agent", "github.write_issue", 2, nil, ErrAudience},
		{"agent", "github.read_repo", 3, nil, ErrAudience},
		{"agent", "github.read_repo", 2, map[string]any{"repo": "evil"}, ErrBinding},
		{"agent", "github.read_repo", 2, nil, ErrBinding},
	} {
		if err := tok.Authorize(c.agent, c.cap, c.ver, c.ctx); !errors.Is(err, c.want) || !errors.Is(err, ErrToken) {
			t.Errorf("Authorize(%v) = %v, want %v", c, err, c.want)
		}
	}

	// Expiry boundary: valid at exp, expired at exp+1 (Python: now > exp).
	atExp := newVerifier(t, WithClock(func() time.Time { return now.Add(60 * time.Second) }))
	if _, err := atExp.Verify(tokStr); err != nil {
		t.Errorf("at exp: %v", err)
	}
	past := newVerifier(t, WithClock(func() time.Time { return now.Add(61 * time.Second) }))
	if _, err := past.Verify(tokStr); !errors.Is(err, ErrExpired) {
		t.Errorf("past exp: %v", err)
	}
	// Different secret: bad signature.
	other, _ := NewHMACTokenVerifier(bytes.Repeat([]byte{1}, 32))
	if _, err := other.Verify(tokStr); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong key: %v", err)
	}
	// Error text never embeds the token.
	if _, err := other.Verify(tokStr); err != nil && strings.Contains(err.Error(), tokStr[:20]) {
		t.Error("error leaks token")
	}
	// Default clock works too.
	real := newVerifier(t)
	rs, _ := real.Sign("a", "c", 1, nil, 30)
	if _, err := real.Verify(rs); err != nil {
		t.Fatal(err)
	}
}

func TestSignValidation(t *testing.T) {
	v := newVerifier(t)
	for name, f := range map[string]func() (string, error){
		"ttl0":    func() (string, error) { return v.Sign("a", "c", 1, nil, 0) },
		"ttl-neg": func() (string, error) { return v.Sign("a", "c", 1, nil, -1) },
		"agent":   func() (string, error) { return v.Sign("", "c", 1, nil, 1) },
		"cap":     func() (string, error) { return v.Sign("a", "", 1, nil, 1) },
		"version": func() (string, error) { return v.Sign("a", "c", 0, nil, 1) },
		"nan":     func() (string, error) { return v.Sign("a", "c", 1, map[string]any{"x": math.NaN()}, 1) },
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: expected error", name)
		} else if errors.Is(err, ErrToken) {
			t.Errorf("%s: validation error must not be a token error: %v", name, err)
		}
	}
	if _, err := NewHMACTokenVerifier(make([]byte, 31)); !errors.Is(err, ErrValidation) {
		t.Errorf("short secret: %v", err)
	}
	// The verifier must copy its secret.
	sec := bytes.Repeat([]byte{7}, 32)
	cv, _ := NewHMACTokenVerifier(sec)
	tk, _ := cv.Sign("a", "c", 1, nil, 60)
	sec[0] ^= 0xff
	if _, err := cv.Verify(tk); err != nil {
		t.Errorf("secret aliasing: %v", err)
	}
}

func TestErrorTaxonomy(t *testing.T) {
	kinds := []*Error{ErrExpired, ErrSignature, ErrMalformed, ErrVersion, ErrBinding, ErrAudience}
	for _, k := range kinds {
		e := newErr(k.kind, "detail")
		if !errors.Is(e, k) || !errors.Is(e, ErrToken) {
			t.Errorf("%v: Is failed", k)
		}
		if e.Error() == "" || k.Error() == "" {
			t.Error("empty message")
		}
		for _, o := range kinds {
			if o != k && errors.Is(e, o) {
				t.Errorf("%v wrongly matches %v", k, o)
			}
		}
	}
	for _, k := range []*Error{ErrNotImplemented, ErrValidation} {
		if errors.Is(k, ErrToken) {
			t.Errorf("%v must not match ErrToken", k)
		}
	}
	if errors.Is(errors.New("x"), ErrToken) || (&Error{kind: kindExpired}).Is(errors.New("x")) {
		t.Error("foreign error matched")
	}
	if (&Error{kind: kindExpired}).Is(&Error{kind: kindExpired, msg: "m"}) {
		t.Error("message-bearing target must not match")
	}
	if Kind(99).String() != "token error" || kindAny.String() != "token error" {
		t.Error("default kind string")
	}
}

func TestVerifyMalformedShapes(t *testing.T) {
	v := newVerifier(t)
	for _, s := range []string{"", ".", "a", "a.b.c", "!!!.AAAA", "AAAA.!!!", "AAAA=.AAAA", "AAAA.", ".AAAA", "AA\nAA.AAAA"} {
		if _, err := v.Verify(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("Verify(%q) = %v, want ErrMalformed", s, err)
		}
	}
}

func TestParsePayloadBranches(t *testing.T) {
	v := newVerifier(t, WithClock(func() time.Time { return time.Unix(1000, 0) }))
	mk := func(payload string) string {
		p := []byte(payload)
		return envelope(p, v.mac(p))
	}
	ok := `{"v":2,"agent_id":"a","capability":"c","capability_version":1,"exp":2000`
	good := map[string]string{
		"float-exp":        ok[:len(ok)-4] + `2000.0}`,
		"bindings-obj":     ok + `,"context_bindings":{"k":[1,2.5,"x",null,true,{"z":1e2}]}}`,
		"bindings-null":    ok + `,"context_bindings":null}`,
		"bindings-0.0":     ok + `,"context_bindings":0.0}`,
		"bindings-false":   ok + `,"context_bindings":false}`,
		"bindings-empty":   ok + `,"context_bindings":""}`,
		"bindings-emptyo":  ok + `,"context_bindings":{}}`,
		"bindings-big-int": ok + `,"context_bindings":{"n":123456789012345678901234567890}}`,
	}
	for name, p := range good {
		if _, err := v.Verify(mk(p)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]error{
		"v-null":          ErrMalformed,
		"agent-null":      ErrMalformed,
		"cap-version-big": ErrMalformed,
		"bindings-1":      ErrMalformed,
		"bindings-num":    ErrMalformed,
		"bad-float":       ErrMalformed,
		"exp-huge":        ErrMalformed,
	}
	payloads := map[string]string{
		"v-null":          `{"v":null,"agent_id":"a","capability":"c","capability_version":1,"exp":2000}`,
		"agent-null":      `{"v":2,"agent_id":null,"capability":"c","capability_version":1,"exp":2000}`,
		"cap-version-big": `{"v":2,"agent_id":"a","capability":"c","capability_version":99999999999999999999999,"exp":2000}`,
		"bindings-1":      ok + `,"context_bindings":[1]}`,
		"bindings-num":    ok + `,"context_bindings":5}`,
		"bad-float":       `{"v":2,"agent_id":"a","capability":"c","capability_version":1,"exp":1e999}`,
		"exp-huge":        `{"v":2,"agent_id":"a","capability":"c","capability_version":1,"exp":1e300}`,
	}
	for name, want := range bad {
		if _, err := v.Verify(mk(payloads[name])); !errors.Is(err, want) {
			t.Errorf("%s: %v want %v", name, err, want)
		}
	}
}

func TestPyFalsy(t *testing.T) {
	falsy := []any{nil, false, "", int64(0), float64(0), json.Number("0.0"), []any{}, map[string]any{}}
	for _, f := range falsy {
		if !pyFalsy(f) {
			t.Errorf("%#v should be falsy", f)
		}
	}
	for _, f := range []any{true, "x", int64(1), 0.5, json.Number("5"), json.Number("x"), []any{1}, map[string]any{"a": 1}, struct{}{}} {
		if pyFalsy(f) {
			t.Errorf("%#v should be truthy", f)
		}
	}
}

func TestIsExpiredAndNoBindings(t *testing.T) {
	tk := &CapabilityV2Token{ExpiresAt: 100}
	if tk.IsExpired(time.Unix(100, 0)) || !tk.IsExpired(time.Unix(101, 0)) {
		t.Error("boundary")
	}
	for _, e := range []int64{0, -1} {
		if (&CapabilityV2Token{ExpiresAt: e}).IsExpired(time.Unix(1<<40, 0)) {
			t.Errorf("exp=%d must never expire (as Python)", e)
		}
	}
	if err := tk.CheckContext(map[string]any{"any": 1}); err != nil {
		t.Error(err)
	}
	// Unnormalisable request value fails closed.
	b := &CapabilityV2Token{Capability: "c", ContextBindings: map[string]any{"k": "v"}}
	if err := b.CheckContext(map[string]any{"k": math.NaN()}); !errors.Is(err, ErrBinding) {
		t.Error(err)
	}
}

func TestValuesEqual(t *testing.T) {
	d := func(s string) any {
		v, err := decodeJSON([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	same := [][2]string{
		{`1`, `1.0`}, {`1e2`, `100`}, {`"a"`, `"a"`}, {`null`, `null`}, {`true`, `true`},
		{`[1,[2]]`, `[1.0,[2]]`}, {`{"a":{"b":1}}`, `{"a":{"b":1.0}}`}, {`123456789012345678901234567890`, `123456789012345678901234567890`},
		{`0.1`, `0.1`},
	}
	for _, c := range same {
		if !valuesEqual(d(c[0]), d(c[1])) {
			t.Errorf("%s != %s", c[0], c[1])
		}
	}
	diff := [][2]string{
		{`1`, `2`}, {`"1"`, `1`}, {`null`, `0`}, {`true`, `1`}, {`[1]`, `[1,2]`}, {`[1]`, `{"a":1}`},
		{`{"a":1}`, `{"b":1}`}, {`{"a":1}`, `{"a":1,"b":2}`}, {`{"a":1}`, `[1]`}, {`[1,2]`, `[2,1]`}, {`"a"`, `"b"`},
		{`123456789012345678901234567890`, `123456789012345678901234567891`}, {`false`, `true`}, {`[]`, `{}`},
	}
	for _, c := range diff {
		if valuesEqual(d(c[0]), d(c[1])) {
			t.Errorf("%s == %s", c[0], c[1])
		}
	}
	if valuesEqual(struct{ a int }{1}, struct{ a int }{2}) {
		t.Error("fallback DeepEqual")
	}
	if !valuesEqual(struct{ a int }{1}, struct{ a int }{1}) {
		t.Error("fallback DeepEqual same")
	}
	if _, ok := numRat(math.Inf(1)); ok {
		t.Error("inf is not a number")
	}
	if _, ok := numRat("x"); ok {
		t.Error("string is not a number")
	}
	if _, ok := numRat(json.Number("zz")); ok {
		t.Error("bad number text")
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, s := range []string{``, `{`, `{} {}`, `[1]`, `{"a":1e999}`, `{"a":[1e999]}`, `{"a":{"b":1e999}}`, `   `} {
		if _, err := decodeObject([]byte(s)); err == nil {
			t.Errorf("decodeObject(%q) should fail", s)
		}
	}
	if _, err := normalize(make(chan int)); err == nil {
		t.Error("normalize(chan)")
	}
	if got, ok := intField(map[string]any{"x": 1e300}, "x", false); ok {
		t.Errorf("huge float accepted: %v", got)
	}
	if got, ok := intField(map[string]any{"x": 1.5}, "x", false); ok {
		t.Errorf("fractional accepted: %v", got)
	}
	if got, ok := intField(map[string]any{}, "x", true); !ok || got != 0 {
		t.Error("missing allowed")
	}
	if _, ok := intField(map[string]any{}, "x", false); ok {
		t.Error("missing not allowed")
	}
	if _, ok := intField(map[string]any{"x": "1"}, "x", false); ok {
		t.Error("string accepted")
	}
}

// TestEd25519ZeroValue: the RGT-35 placeholder became the real verifier
// (RGT-46); an unconfigured zero value still fails closed.
func TestEd25519ZeroValue(t *testing.T) {
	if v, err := NewEd25519Verifier(nil); v != nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("%v %v", v, err)
	}
	var tv TokenVerifier = &Ed25519Verifier{}
	if _, err := tv.Sign("a", "c", 1, nil, 1); !errors.Is(err, ErrNotImplemented) {
		t.Error(err)
	}
	if _, err := tv.Verify("x.y"); !errors.Is(err, ErrNotImplemented) {
		t.Error(err)
	}
	if errors.Is(ErrNotImplemented, ErrToken) {
		t.Error("not-implemented is not a verification failure")
	}
}

func TestV1IssueAndFlow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, ttl := range []int{0, -1, DefaultMaxTTLSeconds + 1} {
		if _, err := IssueCapabilityToken("a", "ns", []string{"read"}, ttl, DefaultMaxTTLSeconds, now); !errors.Is(err, ErrValidation) {
			t.Errorf("ttl %d: %v", ttl, err)
		}
	}
	caps := []string{"write", "read"}
	tk, err := IssueCapabilityToken("agent", "ns", caps, 60, DefaultMaxTTLSeconds, now)
	if err != nil {
		t.Fatal(err)
	}
	caps[0] = "mutated"
	if tk.Capabilities[0] != "write" {
		t.Error("capabilities must be copied")
	}
	if len(tk.TokenID) != 32 || tk.TokenID[12] != '4' || tk.TokenID == NewTokenID() {
		t.Errorf("token id %q", tk.TokenID)
	}
	if tk.IssuedAt != now.Unix() || tk.ExpiresAt != now.Unix()+60 {
		t.Errorf("%+v", tk)
	}
	str, err := tk.ToCompact(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := TokenFormat(str); err != nil || f != 1 {
		t.Errorf("format %d %v", f, err)
	}
	got, err := ParseV1(str, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities[0] != "read" { // wire form is sorted
		t.Errorf("caps %v", got.Capabilities)
	}
	if !got.Covers("read", "ns", now) || !got.Covers("write", "ns", now.Add(60*time.Second)) {
		t.Error("covers")
	}
	for _, c := range []struct {
		op, ns string
		at     time.Time
	}{
		{"delete", "ns", now}, {"read", "other", now}, {"read", "ns", now.Add(-time.Second)}, {"read", "ns", now.Add(61 * time.Second)},
	} {
		if got.Covers(c.op, c.ns, c.at) {
			t.Errorf("should not cover %+v", c)
		}
	}
	star := &CapabilityToken{Namespace: "*", Capabilities: []string{"*"}, IssuedAt: 0, ExpiresAt: 10}
	if !star.Covers("anything", "any-ns", time.Unix(5, 0)) {
		t.Error("wildcards")
	}
	if _, err := ParseV1(str, bytes.Repeat([]byte{9}, 32)); !errors.Is(err, ErrSignature) {
		t.Error(err)
	}
}

func TestParseV1Malformed(t *testing.T) {
	sign := func(p string) string {
		pb := []byte(p)
		return envelope(pb, hmacSum(testKey, pb))
	}
	for name, s := range map[string]string{
		"no-dot":    "abc",
		"bad-b64":   "!!.AAAA",
		"bad-sig64": "AAAA.!!",
		"not-obj":   sign(`[1]`),
		"missing":   sign(`{"a":"x"}`),
		"caps-str":  sign(`{"a":"x","n":"n","c":"read","i":1,"x":2,"t":"t"}`),
		"caps-item": sign(`{"a":"x","n":"n","c":[1],"i":1,"x":2,"t":"t"}`),
		"i-str":     sign(`{"a":"x","n":"n","c":[],"i":"1","x":2,"t":"t"}`),
	} {
		if _, err := ParseV1(s, testKey); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := TokenFormat("nodot"); !errors.Is(err, ErrMalformed) {
		t.Error(err)
	}
	if f, _ := TokenFormat("!!!.x"); f != 1 {
		t.Error("undecodable peek falls through to v1")
	}
	if f, _ := TokenFormat(sign(`{"v":"2"}`)); f != 1 {
		t.Error("string v is not v2")
	}
}

func hmacSum(key, p []byte) []byte {
	v, _ := NewHMACTokenVerifier(key)
	return v.mac(p)
}
