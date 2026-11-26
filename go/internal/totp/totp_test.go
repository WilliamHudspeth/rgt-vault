package totp

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func at(sec int64) time.Time { return time.Unix(sec, 0) }

func b32Secret(key string) string {
	return strings.TrimRight(b32.EncodeToString([]byte(key)), "=")
}

// RFC 6238 Appendix B test vectors (8 digits).
func TestRFC6238Vectors(t *testing.T) {
	keys := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	want := map[string][]string{
		"SHA1":   {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
		"SHA256": {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
		"SHA512": {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"},
	}
	for algo, key := range keys {
		secret := b32Secret(key)
		for i, ts := range times {
			got, err := Generate(secret, at(ts), WithDigits(8), WithAlgorithm(algo))
			if err != nil || got != want[algo][i] {
				t.Errorf("%s t=%d: got %q err %v want %s", algo, ts, got, err, want[algo][i])
			}
			if !Verify(secret, want[algo][i], at(ts), WithDigits(8), WithAlgorithm(algo), WithWindow(0)) {
				t.Errorf("%s t=%d: Verify rejected the RFC code", algo, ts)
			}
		}
	}
}

// RFC 4226 Appendix D HOTP values (6 digits).
func TestRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for c, w := range want {
		got, err := HOTP([]byte("12345678901234567890"), uint64(c), 6, "SHA1")
		if err != nil || got != w {
			t.Errorf("counter %d: %q %v want %s", c, got, err, w)
		}
	}
}

type genVec struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Time      int64  `json:"time"`
	Code      string `json:"code"`
}

type verifyVec struct {
	Secret    string         `json:"secret"`
	Code      string         `json:"code"`
	Time      int64          `json:"time"`
	Window    int            `json:"window"`
	Algorithm string         `json:"algorithm"`
	Digits    int            `json:"digits"`
	Period    int            `json:"period"`
	Python    map[string]any `json:"python"`
}

type replayVec struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Steps  []struct {
		Now    int64  `json:"now"`
		Code   string `json:"code"`
		Python bool   `json:"python"`
	} `json:"steps"`
}

type uriVec struct {
	Secret  string         `json:"secret"`
	Account string         `json:"account"`
	Kwargs  map[string]any `json:"kwargs"`
	URI     string         `json:"uri"`
}

type decodeVec struct {
	Secret string         `json:"secret"`
	Python map[string]any `json:"python"`
}

type vectors struct {
	Generate     []genVec    `json:"generate"`
	Verify       []verifyVec `json:"verify"`
	Replay       []replayVec `json:"replay"`
	URI          []uriVec    `json:"uri"`
	SecretDecode []decodeVec `json:"secret_decode"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPythonGenerateVectors(t *testing.T) {
	v := load(t)
	if len(v.Generate) < 500 {
		t.Fatalf("only %d vectors", len(v.Generate))
	}
	for _, c := range v.Generate {
		got, err := Generate(c.Secret, at(c.Time), WithDigits(c.Digits), WithPeriod(c.Period), WithAlgorithm(c.Algorithm))
		if err != nil || got != c.Code {
			t.Fatalf("%+v: got %q err %v", c, got, err)
		}
	}
}

func TestPythonVerifyVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Verify {
		got := Verify(c.Secret, c.Code, at(c.Time), WithWindow(c.Window), WithAlgorithm(c.Algorithm), WithDigits(c.Digits), WithPeriod(c.Period))
		if _, raised := c.Python["error"]; raised {
			// Python raised TypeError (non-ASCII "digits"); Go returns false.
			if got {
				t.Errorf("%+v: Go accepted a code Python crashed on", c)
			}
			continue
		}
		if want := c.Python["ok"].(bool); got != want {
			t.Errorf("secret=%q code=%q t=%d window=%d: go=%v python=%v", c.Secret, c.Code, c.Time, c.Window, got, want)
		}
	}
}

func TestPythonReplayVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Replay {
		g, err := NewReplayGuardedVerifier(c.Secret)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range c.Steps {
			if got := g.VerifyAt(s.Code, at(s.Now)); got != s.Python {
				t.Errorf("%s step %d: go=%v python=%v", c.Name, i, got, s.Python)
			}
		}
	}
}

func TestPythonProvisioningURIs(t *testing.T) {
	v := load(t)
	for _, c := range v.URI {
		var opts []Option
		for k, val := range c.Kwargs {
			switch k {
			case "issuer":
				opts = append(opts, WithIssuer(val.(string)))
			case "digits":
				opts = append(opts, WithDigits(int(val.(float64))))
			case "period":
				opts = append(opts, WithPeriod(int(val.(float64))))
			case "algorithm":
				opts = append(opts, WithAlgorithm(val.(string)))
			default:
				t.Fatalf("unknown kwarg %s", k)
			}
		}
		got, err := ProvisioningURI(c.Secret, c.Account, opts...)
		if err != nil || got != c.URI {
			t.Errorf("account %q\n go: %s\n py: %s\n err %v", c.Account, got, c.URI, err)
		}
	}
}

func TestPythonSecretDecoding(t *testing.T) {
	v := load(t)
	for _, c := range v.SecretDecode {
		code, err := Generate(c.Secret, at(1700000000))
		if want, ok := c.Python["ok"].(string); ok {
			if strings.TrimSpace(c.Secret) == "" {
				// Python derives a code from an EMPTY key; Go refuses.
				if err == nil {
					t.Errorf("%q: empty secret accepted", c.Secret)
				}
				continue
			}
			if err != nil || code != want {
				t.Errorf("%q: go %q %v, python %s", c.Secret, code, err, want)
			}
		} else if err == nil {
			t.Errorf("%q: Python rejected, Go produced %q", c.Secret, code)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	s, err := GenerateSecret(DefaultSecretLength)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 || strings.Contains(s, "=") || s != strings.ToUpper(s) {
		t.Errorf("secret %q", s)
	}
	key, err := DecodeSecret(s)
	if err != nil || len(key) != 20 {
		t.Errorf("decode: %v %d", err, len(key))
	}
	s2, _ := GenerateSecret(DefaultSecretLength)
	if s == s2 {
		t.Error("secrets must differ")
	}
	if _, err := GenerateSecret(0); err == nil {
		t.Error("length 0 accepted")
	}
	long, _ := GenerateSecret(32)
	if _, err := Generate(long, time.Now(), WithAlgorithm("SHA256")); err != nil {
		t.Error(err)
	}
}

func TestOptionValidation(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	bad := [][]Option{
		{WithDigits(0)}, {WithDigits(11)}, {WithPeriod(0)}, {WithPeriod(-5)}, {WithAlgorithm("MD5")}, {WithAlgorithm("sha1")}, {WithWindow(-1)},
	}
	for i, o := range bad {
		if _, err := Generate(secret, at(59), o...); err == nil {
			t.Errorf("case %d: Generate accepted", i)
		}
		if Verify(secret, "123456", at(59), o...) {
			t.Errorf("case %d: Verify accepted", i)
		}
		if _, err := NewReplayGuardedVerifier(secret, o...); err == nil {
			t.Errorf("case %d: NewReplayGuardedVerifier accepted", i)
		}
		if _, err := ProvisioningURI(secret, "a", o...); err == nil {
			t.Errorf("case %d: ProvisioningURI accepted", i)
		}
	}
	if _, err := NewReplayGuardedVerifier("not base32!!"); err == nil {
		t.Error("bad secret accepted")
	}
	if _, err := Generate("", at(59)); err == nil {
		t.Error("empty secret accepted")
	}
	if _, err := HOTP([]byte("k"), 1, 6, "MD5"); err == nil {
		t.Error("HOTP bad algorithm")
	}
	if _, err := HOTP([]byte("k"), 1, 0, "SHA1"); err == nil {
		t.Error("HOTP bad digits")
	}
}

func TestEpochEdges(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	// Before the epoch there is no counter.
	if _, err := Generate(secret, at(-1)); err == nil {
		t.Error("pre-epoch Generate")
	}
	if stepAt(at(-1), 30) != -1 || stepAt(at(-30), 30) != -1 || stepAt(at(-31), 30) != -2 || stepAt(at(29), 30) != 0 {
		t.Error("floor division")
	}
	// Time 0 with window 1: counter -1 is skipped (Python raised struct.error).
	code, _ := Generate(secret, at(0))
	if !Verify(secret, code, at(0)) {
		t.Error("counter 0 must verify at t=0")
	}
	g, _ := NewReplayGuardedVerifier(secret)
	if !g.VerifyAt(code, at(0)) {
		t.Error("guard at t=0")
	}
	if g.VerifyAt(code, at(0)) {
		t.Error("guard replay at t=0")
	}
}

func TestReplayGuardSemantics(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	now := int64(1700000000)
	g, _ := NewReplayGuardedVerifier(secret)
	code, _ := Generate(secret, at(now))
	if g.VerifyAt("000000", at(now)) || g.VerifyAt("", at(now)) || g.VerifyAt("12x456", at(now)) {
		t.Error("junk accepted")
	}
	if !g.VerifyAt(" "+code+" ", at(now)) {
		t.Error("first use must pass (whitespace trimmed)")
	}
	if g.VerifyAt(code, at(now)) {
		t.Error("replay accepted")
	}
	// Verify() uses the wall clock and works as func(string) bool.
	var f func(string) bool
	g2, _ := NewReplayGuardedVerifier(secret)
	f = g2.Verify
	c2, _ := Generate(secret, time.Now())
	if !f(c2) || f(c2) {
		t.Error("wall-clock Verify once-only")
	}
}

// 50 goroutines race to use one code; exactly one may win.
func TestReplayGuardConcurrent(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	g, _ := NewReplayGuardedVerifier(secret)
	code, _ := Generate(secret, at(1700000000))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.VerifyAt(code, at(1700000000)) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d goroutines consumed the same code", wins.Load())
	}
}

func TestDecodeSecretEdges(t *testing.T) {
	for _, bad := range []string{"", "   ", "A", "1", "AAAA\nAAAA", "AAAA\rAAAA", "AAAA=AAA"} {
		if _, err := DecodeSecret(bad); err == nil {
			t.Errorf("DecodeSecret(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"jbswy3dp", " JBSW Y3DP ", "JBSWY3DP\t"} {
		if _, err := DecodeSecret(ok); err != nil {
			t.Errorf("DecodeSecret(%q): %v", ok, err)
		}
	}
}

func TestVerifyCodeShape(t *testing.T) {
	secret := b32Secret("12345678901234567890")
	code, _ := Generate(secret, at(59))
	for _, bad := range []string{"", "  ", code + "0", code[:5], "٣٣٣٣٣٣", "12345²", "+" + code[1:]} {
		if Verify(secret, bad, at(59)) {
			t.Errorf("Verify accepted %q", bad)
		}
	}
	if Verify("!!!", code, at(59)) {
		t.Error("bad secret accepted")
	}
}

func TestPyQuote(t *testing.T) {
	cases := map[string]string{
		"abc-._~/XYZ019": "abc-._~/XYZ019",
		"a b":            "a%20b",
		"a+b&c=d:e?f#g%": "a%2Bb%26c%3Dd%3Ae%3Ff%23g%25",
		"é":              "%C3%A9",
		"\U0001f600":     "%F0%9F%98%80",
		"":               "",
	}
	for in, want := range cases {
		if got := pyQuote(in); got != want {
			t.Errorf("pyQuote(%q) = %q want %q", in, got, want)
		}
	}
}
