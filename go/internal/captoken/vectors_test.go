package captoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"time"
)

var updateGoVectors = flag.Bool("update-go-vectors", false, "rewrite testdata/go_signed.json")

type signedVec struct {
	Name              string         `json:"name"`
	AgentID           string         `json:"agent_id"`
	Capability        string         `json:"capability"`
	CapabilityVersion int            `json:"capability_version"`
	ContextBindings   map[string]any `json:"context_bindings"`
	TTL               int            `json:"ttl"`
	Token             string         `json:"token"`
	Payload           string         `json:"payload"`
	TokenID           string         `json:"token_id"`
}

type edgeVec struct {
	Name           string         `json:"name"`
	Token          string         `json:"token"`
	Python         map[string]any `json:"python"`
	GoStrictReject bool           `json:"go_strict_reject"`
}

type ctxVec struct {
	Bindings map[string]any `json:"bindings"`
	Request  map[string]any `json:"request"`
	PythonOK bool           `json:"python_ok"`
}

type v1Vec struct {
	Name              string                       `json:"name"`
	Agent             string                       `json:"agent"`
	Namespace         string                       `json:"namespace"`
	Capabilities      []string                     `json:"capabilities"`
	IssuedAt          int64                        `json:"issued_at"`
	ExpiresAt         int64                        `json:"expires_at"`
	TokenID           string                       `json:"token_id"`
	ToCompactEmptyKey string                       `json:"to_compact_empty_key"`
	ToCompactSigned   string                       `json:"to_compact_signed"`
	Hook              map[string]map[string]string `json:"hook"`
}

type peekVec struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Format int    `json:"format"`
}

type vectors struct {
	KeyHex     string      `json:"key_hex"`
	SignNow    int64       `json:"sign_now"`
	FarFuture  int64       `json:"far_future"`
	Signed     []signedVec `json:"signed"`
	Edge       []edgeVec   `json:"edge"`
	Context    []ctxVec    `json:"context"`
	V1         []v1Vec     `json:"v1"`
	FormatPeek []peekVec   `json:"format_peek"`
}

func loadVectors(t *testing.T) (*vectors, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 2**70 and 1e+16 exactly as Python wrote them
	var v vectors
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	key := mustHex(t, v.KeyHex)
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
	return &v, key
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var x byte
		for _, c := range []byte(s[2*i : 2*i+2]) {
			x <<= 4
			switch {
			case c >= '0' && c <= '9':
				x |= c - '0'
			case c >= 'a' && c <= 'f':
				x |= c - 'a' + 10
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = x
	}
	return b
}

func clockAt(sec int64) Option {
	return WithClock(func() time.Time { return time.Unix(sec, 0) })
}

func payloadOf(t *testing.T, token string) string {
	t.Helper()
	p, _, err := openEnvelope(token)
	if err != nil {
		t.Fatal(err)
	}
	return string(p)
}

// Python-signed tokens verify in Go, and Go re-signing the same inputs with
// the same clock produces the identical token string (so the signed bytes,
// including ensure_ascii escaping and Python float repr, match).
func TestPythonSignedVectors(t *testing.T) {
	v, key := loadVectors(t)
	ver, err := NewHMACTokenVerifier(key, clockAt(v.SignNow))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Signed {
		t.Run(c.Name, func(t *testing.T) {
			tok, err := ver.Verify(c.Token)
			if err != nil {
				t.Fatalf("Verify(python token): %v", err)
			}
			if tok.AgentID != c.AgentID || tok.Capability != c.Capability || tok.CapabilityVersion != c.CapabilityVersion {
				t.Fatalf("claims mismatch: %+v", tok)
			}
			if tok.TokenID != c.TokenID {
				t.Fatalf("token_id %s != python %s", tok.TokenID, c.TokenID)
			}
			if tok.ExpiresAt != v.FarFuture {
				t.Fatalf("exp %d", tok.ExpiresAt)
			}
			want, _ := normalize(orEmpty(c.ContextBindings))
			got, _ := normalize(tok.ContextBindings)
			if !valuesEqual(want, got) {
				t.Fatalf("bindings %v != %v", got, want)
			}
			if err := tok.CheckContext(orEmpty(c.ContextBindings)); err != nil {
				t.Fatalf("own bindings must satisfy themselves: %v", err)
			}

			signed, err := ver.Sign(c.AgentID, c.Capability, c.CapabilityVersion, c.ContextBindings, c.TTL)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if got := payloadOf(t, signed); got != c.Payload {
				t.Fatalf("payload bytes differ\n go: %s\n py: %s", got, c.Payload)
			}
			if signed != c.Token {
				t.Fatalf("token differs\n go: %s\n py: %s", signed, c.Token)
			}
		})
	}
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func pyErrKind(name string) error {
	switch name {
	case "TokenExpiredError":
		return ErrExpired
	case "TokenSignatureError":
		return ErrSignature
	case "TokenMalformedError":
		return ErrMalformed
	case "TokenVersionError":
		return ErrVersion
	case "TokenBindingError":
		return ErrBinding
	}
	return nil
}

// Python's verdict for each adversarial token must be Go's verdict.
func TestEdgeVectors(t *testing.T) {
	v, key := loadVectors(t)
	ver, _ := NewHMACTokenVerifier(key, clockAt(v.SignNow))
	for _, c := range v.Edge {
		t.Run(c.Name, func(t *testing.T) {
			tok, err := ver.Verify(c.Token)
			if errName, bad := c.Python["error"].(string); bad {
				want := pyErrKind(errName)
				if want == nil {
					t.Fatalf("unexpected python error %q", errName)
				}
				if err == nil || !errors.Is(err, want) || !errors.Is(err, ErrToken) {
					t.Fatalf("want %v, got %v", want, err)
				}
				if tok != nil {
					t.Fatal("token returned with error")
				}
				return
			}
			if c.GoStrictReject {
				// Python accepts a lenient encoding / type coercion; Go is
				// deliberately stricter (fail closed).
				if err == nil || !errors.Is(err, ErrMalformed) {
					t.Fatalf("Go must reject lenient token with ErrMalformed, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("python accepted, Go rejected: %v", err)
			}
			if tok.AgentID != c.Python["agent_id"] || tok.Capability != c.Python["capability"] || tok.TokenID != c.Python["token_id"] {
				t.Fatalf("claims differ: %+v vs %v", tok, c.Python)
			}
			if exp, _ := c.Python["expires_at"].(json.Number).Int64(); exp != tok.ExpiresAt {
				t.Fatalf("exp %d vs %d", tok.ExpiresAt, exp)
			}
		})
	}
}

func TestContextVectors(t *testing.T) {
	v, _ := loadVectors(t)
	for i, c := range v.Context {
		tok := &CapabilityV2Token{Capability: "cap", ContextBindings: c.Bindings}
		err := tok.CheckContext(c.Request)
		if (err == nil) != c.PythonOK {
			t.Errorf("case %d: bindings=%v request=%v python_ok=%v go err=%v", i, c.Bindings, c.Request, c.PythonOK, err)
		}
		if err != nil && !errors.Is(err, ErrBinding) {
			t.Errorf("case %d: wrong kind %v", i, err)
		}
	}
	// Python: True == 1 passes a binding of 1. Deliberately stricter in Go.
	tok := &CapabilityV2Token{Capability: "cap", ContextBindings: map[string]any{"n": int64(1)}}
	if err := tok.CheckContext(map[string]any{"n": true}); !errors.Is(err, ErrBinding) {
		t.Errorf("bool must not satisfy a numeric binding, got %v", err)
	}
	// Go-typed request values normalise through JSON.
	if err := tok.CheckContext(map[string]any{"n": 1}); err != nil {
		t.Errorf("int 1: %v", err)
	}
	tok = &CapabilityV2Token{Capability: "cap", ContextBindings: map[string]any{"l": []any{int64(1), "a"}}}
	if err := tok.CheckContext(map[string]any{"l": []any{1, "a"}}); err != nil {
		t.Errorf("list: %v", err)
	}
}

func TestV1Vectors(t *testing.T) {
	v, key := loadVectors(t)
	now := time.Now()
	for _, c := range v.V1 {
		t.Run(c.Name, func(t *testing.T) {
			tk := &CapabilityToken{Agent: c.Agent, Namespace: c.Namespace, Capabilities: c.Capabilities,
				IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, TokenID: c.TokenID}
			signed, err := tk.ToCompact(key)
			if err != nil {
				t.Fatal(err)
			}
			if signed != c.ToCompactSigned {
				t.Fatalf("signed v1 differs\n go: %s\n py: %s", signed, c.ToCompactSigned)
			}
			empty, err := tk.ToCompact(nil)
			if err != nil {
				t.Fatal(err)
			}
			if empty != c.ToCompactEmptyKey {
				t.Fatalf("empty-key v1 differs (Python to_compact placeholder)\n go: %s\n py: %s", empty, c.ToCompactEmptyKey)
			}

			got, err := ParseV1(c.ToCompactSigned, key)
			if err != nil {
				t.Fatal(err)
			}
			if got.Agent != c.Agent || got.Namespace != c.Namespace || got.IssuedAt != c.IssuedAt ||
				got.ExpiresAt != c.ExpiresAt || got.TokenID != c.TokenID || len(got.Capabilities) != len(c.Capabilities) {
				t.Fatalf("round trip: %+v", got)
			}
			if _, err := ParseV1(c.ToCompactEmptyKey, key); !errors.Is(err, ErrSignature) {
				t.Fatalf("empty-key token must fail the shared-secret check, got %v", err)
			}

			// Replay Python's TwoFactorHook._consult_v1 decisions for the signed token.
			for k, want := range c.Hook {
				var label, op, ns, agent string
				parts := splitN(k, '|', 4)
				label, op, ns, agent = parts[0], parts[1], parts[2], parts[3]
				tokStr := c.ToCompactSigned
				if label == "empty_key" {
					tokStr = c.ToCompactEmptyKey
				}
				allow := goV1Decision(tokStr, key, op, ns, agent, now)
				if allow != (want["decision"] == "allow") {
					t.Errorf("%s: go allow=%v python=%v (%s)", k, allow, want["decision"], want["reason"])
				}
			}
		})
	}
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// goV1Decision is the v1 half of TwoFactorHook.consult built from the
// package's primitives (replay cache and reasons are the hook's concern).
func goV1Decision(token string, key []byte, op, ns, agent string, now time.Time) bool {
	tk, err := ParseV1(token, key)
	if err != nil {
		return false
	}
	if tk.Agent != agent {
		return false
	}
	return tk.Covers(op, ns, now)
}

func TestFormatPeekVectors(t *testing.T) {
	v, _ := loadVectors(t)
	for _, c := range v.FormatPeek {
		got, err := TokenFormat(c.Token)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if got != c.Format {
			t.Errorf("%s: format %d, python %d", c.Name, got, c.Format)
		}
	}
}

// Go -> Python direction. testdata/go_signed.json is produced here and
// verified by testdata/verify_go_tokens.py using the repo's Python.
// Regenerate: go test ./internal/captoken -run TestGoSignedVectors -update-go-vectors
func TestGoSignedVectors(t *testing.T) {
	v, key := loadVectors(t)
	ver, _ := NewHMACTokenVerifier(key, clockAt(v.SignNow))
	type goCase struct {
		Name       string         `json:"name"`
		Agent      string         `json:"agent_id"`
		Capability string         `json:"capability"`
		Version    int            `json:"capability_version"`
		Bindings   map[string]any `json:"context_bindings"`
		Token      string         `json:"token"`
	}
	cases := []goCase{
		{Name: "go-plain", Agent: "go-agent", Capability: "go.cap", Version: 1},
		{Name: "go-html", Agent: "<a&b>", Capability: "x.\"y\"", Version: 3, Bindings: map[string]any{"q": "<&>", "n": 7, "l": []any{"a", 1, nil, true}}},
		{Name: "go-unicode", Agent: "é☃\U0001f600", Capability: "c\x00\x7f", Version: 2, Bindings: map[string]any{"ké": "日本", "f": 0.5, "g": 1e21, "h": 1.0}},
		{Name: "go-key-order", Agent: "o", Capability: "o.o", Version: 1, Bindings: map[string]any{"b": 1, "a": 2, "é": 3, "Z": 4, "\U0001f600": 5}},
	}
	for i := range cases {
		tok, err := ver.Sign(cases[i].Agent, cases[i].Capability, cases[i].Version, cases[i].Bindings, v.TTLSeconds())
		if err != nil {
			t.Fatal(err)
		}
		cases[i].Token = tok
	}
	type v1Case struct {
		Name      string   `json:"name"`
		Agent     string   `json:"agent"`
		Namespace string   `json:"namespace"`
		Caps      []string `json:"capabilities"`
		IssuedAt  int64    `json:"issued_at"`
		ExpiresAt int64    `json:"expires_at"`
		TokenID   string   `json:"token_id"`
		Token     string   `json:"token"`
	}
	var v1s []v1Case
	for _, s := range []struct {
		name, agent, ns string
		caps            []string
	}{
		{"go-v1-basic", "agent-go", "ns", []string{"write", "read"}},
		{"go-v1-unicode", "é<&>", "☃", []string{"*"}},
	} {
		tk := &CapabilityToken{Agent: s.agent, Namespace: s.ns, Capabilities: s.caps, IssuedAt: 1700000000, ExpiresAt: v.FarFuture, TokenID: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"}
		str, err := tk.ToCompact(key)
		if err != nil {
			t.Fatal(err)
		}
		v1s = append(v1s, v1Case{s.name, s.agent, s.ns, s.caps, tk.IssuedAt, tk.ExpiresAt, tk.TokenID, str})
	}
	out, err := json.MarshalIndent(map[string]any{"key_hex": v.KeyHex, "v2": cases, "v1": v1s}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *updateGoVectors {
		if err := os.WriteFile("testdata/go_signed.json", out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile("testdata/go_signed.json")
	if err != nil {
		t.Fatalf("missing testdata/go_signed.json (run with -update-go-vectors): %v", err)
	}
	if !bytes.Equal(have, out) {
		t.Fatal("testdata/go_signed.json is stale; run with -update-go-vectors and rerun verify_go_tokens.py")
	}
}

// TTLSeconds exposes the vector TTL (fixed at 3600 by the generator).
func (v *vectors) TTLSeconds() int { return 3600 }

var _ = base64.RawURLEncoding
