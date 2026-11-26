package validation

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Vectors are generated from python/input_validation.py by
// testdata/gen_vectors.py; Python is the reference.

type verdict struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error"`
	Result json.RawMessage `json:"result"`
}

type strCase struct {
	Value string `json:"value"`
	verdict
}

type vectors struct {
	Name      []strCase `json:"name"`
	Namespace []strCase `json:"namespace"`
	Agent     []strCase `json:"agent"`
	IntBound  []struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
		Min   *int64          `json:"min"`
		Max   *int64          `json:"max"`
		verdict
	} `json:"int_bound"`
	FreeText []struct {
		Value  string `json:"value"`
		MaxLen *int   `json:"max_len"`
		verdict
	} `json:"free_text"`
	Normalize []strCase `json:"normalize"`
	Regex     []struct {
		Pattern string    `json:"pattern"`
		Text    string    `json:"text"`
		Match   *[]string `json:"match"`
	} `json:"regex"`
}

func load(t *testing.T) *vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/validation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

// pythonAcceptsTrailingNewline reports whether Python's `^...+$` accepted
// value only thanks to `$` matching before one trailing newline.
func trailingNewlineQuirk(value string) bool {
	return strings.HasSuffix(value, "\n") && !strings.Contains(strings.TrimSuffix(value, "\n"), "\n")
}

func checkStrCases(t *testing.T, label string, cases []strCase, fn func(string) (string, error)) {
	t.Helper()
	if len(cases) < 15 {
		t.Fatalf("%s: too few vectors (%d)", label, len(cases))
	}
	diverged := 0
	for _, c := range cases {
		got, err := fn(c.Value)
		switch {
		case c.OK && trailingNewlineQuirk(c.Value) && !isBlankPy(c.Value):
			// Documented deliberate divergence: Go rejects a trailing newline.
			diverged++
			if err == nil || !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "not permitted by the allowlist") {
				t.Errorf("%s(%q): Go must reject the trailing-newline quirk, got %q,%v", label, c.Value, got, err)
			}
		case c.OK:
			if err != nil || got != c.Value {
				t.Errorf("%s(%q): python accepted, Go got %q,%v", label, c.Value, got, err)
			}
		default:
			if err == nil {
				t.Errorf("%s(%q): python rejected (%s), Go accepted", label, c.Value, c.Error)
			} else if err.Error() != c.Error || !errors.Is(err, ErrValidation) {
				t.Errorf("%s(%q): message\n got: %s\nwant: %s", label, c.Value, err, c.Error)
			}
		}
	}
	if label != "ValidateName" && label != "ValidateNamespace" && label != "ValidateAgent" {
		return
	}
	if diverged == 0 {
		t.Errorf("%s: expected the trailing-newline divergence vectors to be present", label)
	}
}

func isBlankPy(s string) bool { return isBlank(s) }

func TestVectorsName(t *testing.T) { checkStrCases(t, "ValidateName", load(t).Name, ValidateName) }
func TestVectorsNamespace(t *testing.T) {
	checkStrCases(t, "ValidateNamespace", load(t).Namespace, ValidateNamespace)
}
func TestVectorsAgent(t *testing.T) { checkStrCases(t, "ValidateAgent", load(t).Agent, ValidateAgent) }

func TestVectorsIntBound(t *testing.T) {
	v := load(t)
	if len(v.IntBound) < 60 {
		t.Fatalf("too few int vectors: %d", len(v.IntBound))
	}
	for i, c := range v.IntBound {
		var val any
		var big0 *big.Int
		switch c.Type {
		case "int":
			var s string
			_ = json.Unmarshal(c.Value, &s)
			b, _ := new(big.Int).SetString(s, 10)
			big0 = b
			if b.IsInt64() {
				val = b.Int64()
			} else {
				val = b
			}
		case "bool":
			var b bool
			_ = json.Unmarshal(c.Value, &b)
			val = b
		case "float":
			var s string
			_ = json.Unmarshal(c.Value, &s)
			f, _ := strconv.ParseFloat(s, 64)
			val = f
		case "str":
			val = "5"
		case "none":
			val = nil
		case "list":
			val = []any{}
		case "dict":
			val = map[string]any{}
		}
		lo, hi := NoLimit, NoLimit
		if c.Min != nil {
			lo = Limit(*c.Min)
		}
		if c.Max != nil {
			hi = Limit(*c.Max)
		}
		got, err := ValidateIntBound("limit", val, lo, hi)
		switch {
		case c.OK && big0 != nil && !big0.IsInt64():
			// Python ints are unbounded; Go reports an overflow error.
			if err == nil || !strings.Contains(err.Error(), "outside the supported integer range") {
				t.Errorf("%d: out-of-range int accepted by python; Go: %d,%v", i, got, err)
			}
		case c.OK:
			var want int64
			_ = json.Unmarshal(c.Result, &want)
			if err != nil || got != want {
				t.Errorf("%d (%s %s): got %d,%v want %d", i, c.Type, c.Value, got, err, want)
			}
		default:
			if err == nil || err.Error() != c.Error {
				t.Errorf("%d (%s %s [%v,%v]): got %v want %s", i, c.Type, c.Value, c.Min, c.Max, err, c.Error)
			}
		}
	}
}

func TestVectorsFreeText(t *testing.T) {
	v := load(t)
	if len(v.FreeText) < 40 {
		t.Fatalf("too few free-text vectors: %d", len(v.FreeText))
	}
	for i, c := range v.FreeText {
		max := DefaultFreeTextMax
		if c.MaxLen != nil {
			max = *c.MaxLen
		}
		got, err := ValidateFreeText(c.Value, max)
		if c.OK {
			var want string
			_ = json.Unmarshal(c.Result, &want)
			if err != nil || got != want {
				t.Errorf("%d (%q): got %q,%v want %q", i, c.Value, got, err, want)
			}
			continue
		}
		if err == nil || err.Error() != c.Error || !errors.Is(err, ErrValidation) {
			t.Errorf("%d (%q): got %v want %q", i, c.Value, err, c.Error)
		}
	}
}

func TestVectorsNormalize(t *testing.T) {
	for i, c := range load(t).Normalize {
		got, err := NormalizeUnicode(c.Value)
		if c.OK {
			var want string
			_ = json.Unmarshal(c.Result, &want)
			if err != nil || got != want {
				t.Errorf("%d (%q): got %q,%v want %q", i, c.Value, got, err, want)
			}
		} else if err == nil || err.Error() != c.Error {
			t.Errorf("%d (%q): got %v want %q", i, c.Value, err, c.Error)
		}
	}
}

func TestVectorsRegex(t *testing.T) {
	v := load(t)
	if len(v.Regex) < 8 {
		t.Fatal("too few regex vectors")
	}
	for i, c := range v.Regex {
		got, err := SafeRegexMatch(regexp.MustCompile(c.Pattern), c.Text, 0)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if (got == nil) != (c.Match == nil) {
			t.Errorf("%d (%s on %q): got %v want %v", i, c.Pattern, c.Text, got, c.Match)
			continue
		}
		if got == nil {
			continue
		}
		// Python reports an unmatched optional group as None; Go as "".
		want := *c.Match
		if len(got) != len(want) {
			t.Errorf("%d: group count %d want %d", i, len(got), len(want))
			continue
		}
		for j := range want {
			if got[j] != want[j] {
				t.Errorf("%d: group %d = %q want %q", i, j, got[j], want[j])
			}
		}
	}
}

func TestMessagesAreCategorised(t *testing.T) {
	_, err := ValidateName("")
	var ve *Error
	if !errors.As(err, &ve) || !errors.Is(err, ErrValidation) {
		t.Fatalf("not a *Error: %v", err)
	}
	if errors.Is(err, errors.New("other")) {
		t.Fatal("Is should only match ErrValidation")
	}
}

func TestIdentifierBoundaries(t *testing.T) {
	if _, err := ValidateName(strings.Repeat("a", MaxNameLen)); err != nil {
		t.Error(err)
	}
	if _, err := ValidateName(strings.Repeat("a", MaxNameLen+1)); err == nil {
		t.Error("257 chars accepted")
	}
	// Length is counted in characters, not bytes: a non-ASCII char is
	// reported as an allowlist failure, never as a length failure.
	if _, err := ValidateNamespace(strings.Repeat("é", 129)); err == nil || !strings.Contains(err.Error(), "maximum allowed length") {
		t.Errorf("length is checked before the allowlist: %v", err)
	}
	for _, bad := range []string{"a\nb", "abc\n", "a\x00", "\x1c", "a b"} {
		if _, err := ValidateNamespace(bad); err == nil {
			t.Errorf("namespace %q accepted", bad)
		}
	}
	if _, err := ValidateAgent("alice@example.com"); err != nil {
		t.Error(err)
	}
	if _, err := ValidateName("name with spaces.v1-2_3"); err != nil {
		t.Error(err)
	}
}

func TestIntBoundTypes(t *testing.T) {
	ok := []any{int(1), int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1),
		big.NewInt(1), json.Number("1")}
	for _, v := range ok {
		if n, err := ValidateIntBound("n", v, Limit(0), Limit(5)); err != nil || n != 1 {
			t.Errorf("%T: %d,%v", v, n, err)
		}
	}
	bad := map[string]any{
		"NoneType": nil, "bool": true, "str": "1", "float": 1.5, "bytes": []byte("1"),
		"list": []any{}, "dict": map[any]any{},
	}
	for name, v := range bad {
		_, err := ValidateIntBound("n", v, NoLimit, NoLimit)
		if err == nil || !strings.HasSuffix(err.Error(), "got "+name+".") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ValidateIntBound("n", json.Number("1.5"), NoLimit, NoLimit); err == nil || !strings.HasSuffix(err.Error(), "got float.") {
		t.Errorf("json.Number fraction: %v", err)
	}
	if _, err := ValidateIntBound("n", struct{}{}, NoLimit, NoLimit); err == nil {
		t.Error("struct accepted")
	}
	var nilBig *big.Int
	if _, err := ValidateIntBound("n", nilBig, NoLimit, NoLimit); err == nil {
		t.Error("nil *big.Int accepted")
	}
	if _, err := ValidateIntBound("n", uint64(math.MaxUint64), NoLimit, Limit(10)); err == nil || err.Error() != "'n' must be <= 10; got 18446744073709551615." {
		t.Errorf("huge uint64 over max: %v", err)
	}
	if _, err := ValidateIntBound("n", uint64(math.MaxUint64), NoLimit, NoLimit); err == nil {
		t.Error("huge uint64 without bound should overflow")
	}
}

func TestNormalizeForms(t *testing.T) {
	for _, f := range []Form{NFC, NFD, NFKC, NFKD} {
		if _, err := NormalizeUnicodeForm("abc", f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	// NFD splits é into e + U+0301 (a Mn mark), which the category allowlist rejects.
	if _, err := NormalizeUnicodeForm("é", NFD); err == nil || !strings.Contains(err.Error(), "category 'Mn'") {
		t.Errorf("NFD: %v", err)
	}
	if got, err := NormalizeUnicodeForm("ﬁ", NFKC); err != nil || got != "fi" {
		t.Errorf("NFKC: %q %v", got, err)
	}
	if _, err := NormalizeUnicodeForm("x", Form("NFX")); err == nil {
		t.Error("unknown form accepted")
	}
	if _, err := NormalizeUnicode("bad\xffutf8"); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
	if _, err := ValidateFreeText("bad\xff", 10); err == nil {
		t.Error("invalid UTF-8 accepted by free text")
	}
}

func TestCategoryOf(t *testing.T) {
	cases := map[rune]string{'A': "Lu", 'a': "Ll", '1': "Nd", '\t': "Cc", '​': "Cf", '': "Co",
		'͸': "Cn", '́': "Mn", ' ': "Zl", ' ': "Zs", '😀': "So"}
	for r, want := range cases {
		if got := categoryOf(r); got != want {
			t.Errorf("categoryOf(%U) = %s want %s", r, got, want)
		}
	}
}

func TestPyIsSpace(t *testing.T) {
	for _, r := range []rune{' ', '\t', '\n', '\x1c', '\x1f', ' ', ' ', '　', '\x85'} {
		if !pyIsSpace(r) {
			t.Errorf("%U should be space", r)
		}
	}
	for _, r := range []rune{'a', '\x00', '​', '-'} {
		if pyIsSpace(r) {
			t.Errorf("%U should not be space", r)
		}
	}
}

func TestSafeRegexMatchTimeout(t *testing.T) {
	release := make(chan struct{})
	slow := func() []int {
		<-release
		return nil
	}
	start := time.Now()
	_, err := safeRegexMatch(slow, "a", 50*time.Millisecond)
	close(release)
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("expected timeout error, got %v", err)
	}
	want := "Regex match aborted: exceeded 1s timeout. The input may be causing catastrophic backtracking."
	if err.Error() != want {
		t.Errorf("message %q", err.Error())
	}
	if time.Since(start) > 2*time.Second {
		t.Error("timeout not honoured")
	}
}

func TestSafeRegexMatchBasics(t *testing.T) {
	re := regexp.MustCompile(`(\d+)-(\d+)`)
	if m, err := SafeRegexMatch(re, "12-34x", time.Second); err != nil || len(m) != 3 || m[1] != "12" {
		t.Fatalf("%v %v", m, err)
	}
	// Match must be anchored at the start, like Python's pattern.match.
	if m, _ := SafeRegexMatch(re, "x12-34", time.Second); m != nil {
		t.Fatalf("non-anchored match returned: %v", m)
	}
	// Linear time: the classic catastrophic pattern returns immediately.
	evil := regexp.MustCompile(`^(a+)+$`)
	if m, err := SafeRegexMatch(evil, strings.Repeat("a", 5000)+"!", time.Second); err != nil || m != nil {
		t.Fatalf("evil pattern: %v %v", m, err)
	}
	// Longer timeout path.
	if m, err := SafeRegexMatch(re, "1-2", 3*time.Second); err != nil || m == nil {
		t.Fatalf("%v %v", m, err)
	}
}

func TestHugeInputsAreRejectedCheaply(t *testing.T) {
	huge := "a" + strings.Repeat(" ", 4*MaxNamespaceLen)
	_, err := ValidateNamespace(huge)
	if err == nil || !strings.Contains(err.Error(), "maximum allowed length of 128") {
		t.Fatalf("got %v", err)
	}
	// Exactly 128 two-byte runes is within the rune limit (then fails the allowlist, not length).
	_, err = ValidateNamespace(strings.Repeat("é", 128))
	if err == nil || !strings.Contains(err.Error(), "not permitted by the allowlist") {
		t.Fatalf("got %v", err)
	}
}

func TestSafeRegexMatchAnchoringAndNil(t *testing.T) {
	if _, err := SafeRegexMatch(nil, "a", time.Second); err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("nil regexp: %v", err)
	}
	re := regexp.MustCompile("abc")
	// A non-matching prefix fails at offset 0 without scanning the rest.
	start := time.Now()
	m, err := SafeRegexMatch(re, "x"+strings.Repeat("y", 20_000_000), time.Second)
	if err != nil || m != nil {
		t.Fatalf("%v %v", m, err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("anchored search scanned the whole text (%v)", time.Since(start))
	}
	// Inline flags survive anchoring; alternation is grouped correctly.
	if m, _ := SafeRegexMatch(regexp.MustCompile(`(?i)a|b`), "Bx", time.Second); len(m) != 1 || m[0] != "B" {
		t.Errorf("flags/alternation: %v", m)
	}
	if m, _ := SafeRegexMatch(regexp.MustCompile(`a|b`), "xb", time.Second); m != nil {
		t.Errorf("alternation must not match past offset 0: %v", m)
	}
	// Cache bound: many distinct patterns do not grow it past the limit.
	for i := 0; i < anchoredCacheMax+10; i++ {
		_, _ = SafeRegexMatch(regexp.MustCompile("a"+strings.Repeat("b", i%7)), "a", time.Second)
	}
	anchoredMu.Lock()
	n := len(anchoredCache)
	anchoredMu.Unlock()
	if n > anchoredCacheMax {
		t.Errorf("cache size %d", n)
	}
}

func TestIntBoundJSONNumber(t *testing.T) {
	for _, in := range []string{"+5", "007", "5.0", "1e3", "bad", ""} {
		_, err := ValidateIntBound("limit", json.Number(in), Limit(1), Limit(10))
		if err == nil || !strings.HasPrefix(err.Error(), "'limit' must be an integer; got ") {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := ValidateIntBound("limit", json.Number("bad"), NoLimit, NoLimit); err == nil || !strings.HasSuffix(err.Error(), "got str.") {
		t.Errorf("bad: %v", err)
	}
	if n, err := ValidateIntBound("limit", json.Number("-7"), NoLimit, NoLimit); err != nil || n != -7 {
		t.Errorf("-7: %d %v", n, err)
	}
	// Huge integers are rejected without quadratic work or message amplification.
	big500 := json.Number(strings.Repeat("9", 500_000))
	start := time.Now()
	_, err := ValidateIntBound("limit", big500, Limit(1), Limit(100))
	if err == nil || len(err.Error()) > 200 || time.Since(start) > time.Second {
		t.Fatalf("huge json.Number: len=%d err=%v took %v", len(err.Error()), err, time.Since(start))
	}
	// A big.Int above the bound reports without printing every digit.
	huge := new(big.Int).Lsh(big.NewInt(1), 4000)
	_, err = ValidateIntBound("limit", huge, NoLimit, Limit(100))
	if err == nil || !strings.Contains(err.Error(), "a very large integer") {
		t.Fatalf("%v", err)
	}
	if _, err := ValidateIntBound("limit", huge, NoLimit, NoLimit); err == nil || !strings.Contains(err.Error(), "outside the supported") {
		t.Fatalf("%v", err)
	}
}
