package pyfmt

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"rgt-vault-server/internal/captoken"
)

var negZero = math.Copysign(0, -1)

func TestReprStrings(t *testing.T) {
	for _, c := range pyStrRepr {
		if got := Repr(c.in); got != c.want {
			t.Errorf("Repr(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestFloatRepr(t *testing.T) {
	for _, c := range pyFloatRepr {
		if got := FloatRepr(c.in); got != c.want {
			t.Errorf("FloatRepr(%v) = %s, want %s", c.in, got, c.want)
		}
	}
	for f, want := range map[float64]string{math.Inf(1): "inf", math.Inf(-1): "-inf", math.NaN(): "nan"} {
		if got := FloatRepr(f); got != want {
			t.Errorf("FloatRepr(%v) = %s", f, got)
		}
	}
}

func TestReprComposite(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		// Python: repr([1, 'a', None, True, False, {'a': [1.5], 'b': 2}])
		{[]any{1, "a", nil, true, false, map[string]any{"b": 2, "a": []any{1.5}}}, "[1, 'a', None, True, False, {'a': [1.5], 'b': 2}]"},
		{[]string{"x", "y'"}, `['x', "y'"]`},
		{json.Number("12"), "12"},
		{json.Number("-0"), "0"},
		{json.Number("1.50"), "1.5"},
		{json.Number("1e2"), "100.0"},
		{json.Number("bogus"), "'bogus'"},
		{int64(-3), "-3"},
		{uint8(7), "7"},
		{float32(0.5), "0.5"},
		{struct{ A int }{1}, "'{1}'"},
		{map[string]any{}, "{}"},
		{[]any{}, "[]"},
	} {
		if got := Repr(c.in); got != c.want {
			t.Errorf("Repr(%#v) = %s, want %s", c.in, got, c.want)
		}
	}
	if Str("plain") != "plain" || Str(1.0) != "1.0" || Str(nil) != "None" {
		t.Fatal("Str")
	}
	if SortedIntsRepr([]int{3, 1}) != "[1, 3]" || SortedStringsRepr(nil) != "[]" {
		t.Fatal("sorted reprs")
	}
	if Repr("\xff") != `'\udcff'` {
		t.Fatalf("invalid utf-8: %s", Repr("\xff"))
	}
}

func TestCheckContextMessages(t *testing.T) {
	tok := &captoken.CapabilityV2Token{Capability: "github.read_repo", ContextBindings: map[string]any{
		"b": "x", "a": json.Number("1"),
	}}
	if err := CheckContext(tok, map[string]any{"a": 1.0, "b": "x", "extra": true}); err != nil {
		t.Fatal(err)
	}
	err := CheckContext(tok, map[string]any{"b": "x"})
	if err == nil || err.Error() != "capability 'github.read_repo' requires context key 'a' in the request" {
		t.Fatalf("missing: %v", err)
	}
	if !errors.Is(err, captoken.ErrBinding) {
		t.Fatal("must unwrap to ErrBinding")
	}
	// Python: f"... expected {expected!r}, got {got!r}"
	err = CheckContext(tok, map[string]any{"a": 1, "b": "<img src=x onerror=alert(1)>'"})
	want := `capability 'github.read_repo' context binding failed for 'b': expected 'x', got "<img src=x onerror=alert(1)>'"`
	if err == nil || err.Error() != want {
		t.Fatalf("mismatch:\n got %v\nwant %s", err, want)
	}
}

func TestTokenErrorHelpers(t *testing.T) {
	v, _ := captoken.NewHMACTokenVerifier([]byte("0123456789abcdef0123456789abcdef"))
	_, err := v.Verify("a.b")
	if TokenErrorClass(err) == "TokenError" {
		t.Fatalf("class for %v", err)
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{captoken.ErrExpired, "TokenExpiredError"},
		{captoken.ErrSignature, "TokenSignatureError"},
		{captoken.ErrMalformed, "TokenMalformedError"},
		{captoken.ErrVersion, "TokenVersionError"},
		{captoken.ErrBinding, "TokenBindingError"},
		{errors.New("x"), "TokenError"},
	} {
		if got := TokenErrorClass(c.err); got != c.want {
			t.Errorf("%v: %s", c.err, got)
		}
	}
	_, err = v.Verify("abc")
	if TokenErrorMessage(err) != "token must be 'payload.signature'" && TokenErrorMessage(err) == err.Error() {
		t.Fatalf("prefix not stripped: %q", TokenErrorMessage(err))
	}
	if TokenErrorMessage(errors.New("plain")) != "plain" || TokenErrorMessage(captoken.ErrExpired) != "token expired" {
		t.Fatal("TokenErrorMessage")
	}
}
