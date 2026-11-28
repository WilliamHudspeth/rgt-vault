package captoken

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var v3Now = time.Unix(1_900_000_000, 0)

func v3Clock() time.Time { return v3Now }

// testSeed derives a deterministic key at test time (no key in the repo).
func testSeed(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("rgt-vault captoken v3 test seed: " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

func newPair(t *testing.T, label string) (*Ed25519Signer, *Ed25519Verifier) {
	t.Helper()
	s, err := NewEd25519Signer(testSeed(label), "", WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewEd25519Verifier(map[string]ed25519.PublicKey{s.KeyID(): s.PublicKey()}, WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

func mustSign(t *testing.T, s interface {
	Sign(string, string, int, map[string]any, int) (string, error)
}, bindings map[string]any) string {
	t.Helper()
	tok, err := s.Sign("agent-1", "secrets.echo", 1, bindings, 60)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// reseal re-encodes a token from (payload, sig).
func reseal(payload, sig []byte) string { return envelope(payload, sig) }

func split(t *testing.T, tok string) ([]byte, []byte) {
	t.Helper()
	p, s, err := openEnvelope(tok)
	if err != nil {
		t.Fatal(err)
	}
	return p, s
}

func TestV3RoundTrip(t *testing.T) {
	s, v := newPair(t, "a")
	tok := mustSign(t, s, map[string]any{"namespace": "prod", "n": 3})
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	payload, sig := split(t, tok)
	sum := sha256.Sum256(payload)
	if got.AgentID != "agent-1" || got.Capability != "secrets.echo" || got.CapabilityVersion != 1 ||
		got.ExpiresAt != v3Now.Unix()+60 || got.KeyID != s.KeyID() || got.TokenID != hex.EncodeToString(sum[:])[:16] ||
		got.ContextBindings["namespace"] != "prod" {
		t.Fatalf("claims = %+v", got)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatal("sig size")
	}
	// The signature covers the domain-separation prefix, not the bare payload.
	if ed25519.Verify(s.PublicKey(), payload, sig) || !ed25519.Verify(s.PublicKey(), append([]byte(SigningContextV3), payload...), sig) {
		t.Fatal("signing input is not SigningContextV3 || payload")
	}
	if s.KeyID() != KeyID(s.PublicKey()) || len(s.KeyID()) != 16 {
		t.Fatalf("kid = %q", s.KeyID())
	}
	if ids := v.KeyIDs(); len(ids) != 1 || ids[0] != s.KeyID() {
		t.Fatalf("KeyIDs = %v", ids)
	}
}

// TestV3Vector freezes the v3 wire format (payload bytes and signature) for
// a deterministic key, clock and claim set. Ed25519 is deterministic.
func TestV3Vector(t *testing.T) {
	s, err := NewEd25519Signer(testSeed("vector"), "k1", WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Sign("agent-é", "secrets.use", 2, map[string]any{"url": "https://x/?a=1&b=<2>"}, 300)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := split(t, tok)
	wantPayload := `{"agent_id":"agent-\u00e9","capability":"secrets.use","capability_version":2,` +
		`"context_bindings":{"url":"https://x/?a=1&b=<2>"},"exp":1900000300,"kid":"k1","v":3}`
	if string(payload) != wantPayload {
		t.Fatalf("payload = %s", payload)
	}
	if tok != v3VectorToken {
		t.Fatalf("v3 vector changed:\n got %s\nwant %s", tok, v3VectorToken)
	}
}

// TestV3CanonicalMatchesV2Encoder: the v3 payload is the v2 canonical claim
// set plus "kid" and "v": 3, from the same encoder. Removing kid and setting
// v back to 2 gives byte-for-byte the payload HMACTokenVerifier signs.
func TestV3CanonicalMatchesV2Encoder(t *testing.T) {
	bindings := map[string]any{"z": []any{1, 2.5, nil, true}, "a": "<&> 😀", "m": map[string]any{"b": 1, "a": 2}}
	v3, err := canonicalPayloadV3("ag", "cap", 7, bindings, 123, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := canonicalPayload("ag", "cap", 7, bindings, 123)
	if err != nil {
		t.Fatal(err)
	}
	stripped := bytes.Replace(v3, []byte(`,"kid":"kid-1","v":3}`), []byte(`,"v":2}`), 1)
	if !bytes.Equal(stripped, v2) {
		t.Fatalf("v3 %s\nv2 %s", v3, v2)
	}
	// And the HMAC verifier's own signature input is still exactly v2.
	h, _ := NewHMACTokenVerifier(bytes.Repeat([]byte{7}, 32), WithClock(func() time.Time { return time.Unix(63, 0) }))
	tok, _ := h.Sign("ag", "cap", 7, bindings, 60)
	p, sig := split(t, tok)
	if !bytes.Equal(p, v2) || !hmac.Equal(sig, h.mac(v2)) {
		t.Fatal("v2 HMAC envelope changed")
	}
}

func TestV3WrongKey(t *testing.T) {
	a, _ := newPair(t, "a")
	b, _ := newPair(t, "b")
	// Verifier trusts B's public key under A's kid: A's signature must fail.
	v, err := NewEd25519Verifier(map[string]ed25519.PublicKey{a.KeyID(): b.PublicKey()}, WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(mustSign(t, a, nil)); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestV3KeyIDMismatch(t *testing.T) {
	a, va := newPair(t, "a")
	b, _ := newPair(t, "b")
	// Unknown kid.
	if _, err := va.Verify(mustSign(t, b, nil)); !errors.Is(err, ErrSignature) {
		t.Fatalf("unknown kid: %v", err)
	}
	// Both keys trusted; relabel A's token with B's kid: the kid is signed,
	// and B's key does not verify A's signature either.
	both, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{a.KeyID(): a.PublicKey(), b.KeyID(): b.PublicKey()}, WithEd25519Clock(v3Clock))
	payload, sig := split(t, mustSign(t, a, nil))
	relabelled := bytes.Replace(payload, []byte(a.KeyID()), []byte(b.KeyID()), 1)
	if _, err := both.Verify(reseal(relabelled, sig)); !errors.Is(err, ErrSignature) {
		t.Fatalf("relabelled kid: %v", err)
	}
	// Signature valid for the payload but kid points at another trusted key.
	other, _ := NewEd25519Signer(testSeed("a"), b.KeyID(), WithEd25519Clock(v3Clock))
	if _, err := both.Verify(mustSign(t, other, nil)); !errors.Is(err, ErrSignature) {
		t.Fatalf("kid of another trusted key: %v", err)
	}
}

func TestV3BadSignatures(t *testing.T) {
	s, v := newPair(t, "a")
	tok := mustSign(t, s, nil)
	payload, sig := split(t, tok)
	flip := func(b []byte, i int) []byte { c := append([]byte(nil), b...); c[i] ^= 1; return c }
	// A genuinely signed token that is only too long.
	oversized, err := s.Sign("agent-1", "secrets.echo", 1, map[string]any{"pad": strings.Repeat("a", MaxTokenLen)}, 60)
	if err != nil {
		t.Fatal(err)
	}
	garbage := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(garbage)
	for _, c := range []struct {
		name string
		tok  string
		want *Error
	}{
		{"truncated sig", reseal(payload, sig[:63]), ErrMalformed},
		{"long sig", reseal(payload, append(append([]byte(nil), sig...), 0)), ErrMalformed},
		{"hmac-sized sig", reseal(payload, sig[:32]), ErrMalformed},
		{"garbage sig", reseal(payload, garbage), ErrSignature},
		{"zero sig", reseal(payload, make([]byte, 64)), ErrSignature},
		{"flipped sig first", reseal(payload, flip(sig, 0)), ErrSignature},
		{"flipped sig last", reseal(payload, flip(sig, 63)), ErrSignature},
		{"tampered payload", reseal(bytes.Replace(payload, []byte("agent-1"), []byte("agent-2"), 1), sig), ErrSignature},
		{"added alg claim", reseal(bytes.Replace(payload, []byte(`{`), []byte(`{"alg":"HS256",`), 1), sig), ErrSignature},
		{"no dot", strings.ReplaceAll(tok, ".", ""), ErrMalformed},
		{"three parts", tok + ".x", ErrMalformed},
		{"padding", tok + "=", ErrMalformed},
		{"empty", "", ErrMalformed},
		{"not json", reseal([]byte("hello"), sig), ErrMalformed},
		{"oversized", oversized, ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := v.Verify(c.tok); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestV3PayloadHeaderChecks(t *testing.T) {
	s, v := newPair(t, "a")
	sign := func(p string) string {
		return reseal([]byte(p), ed25519.Sign(s.priv, signingInputV3([]byte(p))))
	}
	base := `"agent_id":"a","capability":"c","capability_version":1,"context_bindings":{},"exp":1900000060`
	for _, c := range []struct {
		name, payload string
		want          *Error
	}{
		{"no v", `{` + base + `,"kid":"` + s.KeyID() + `"}`, ErrVersion},
		{"v2", `{` + base + `,"kid":"` + s.KeyID() + `","v":2}`, ErrVersion},
		{"v string", `{` + base + `,"kid":"` + s.KeyID() + `","v":"3"}`, ErrMalformed},
		{"no kid", `{` + base + `,"v":3}`, ErrMalformed},
		{"kid int", `{` + base + `,"kid":1,"v":3}`, ErrMalformed},
		{"kid bad chars", `{` + base + `,"kid":"a/b","v":3}`, ErrMalformed},
		{"kid too long", `{` + base + `,"kid":"` + strings.Repeat("k", MaxKeyIDLen+1) + `","v":3}`, ErrMalformed},
		{"missing exp", `{"agent_id":"a","capability":"c","capability_version":1,"kid":"` + s.KeyID() + `","v":3}`, ErrMalformed},
		{"not object", `[1]`, ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := v.Verify(sign(c.payload)); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	// A hand-built but well-formed payload verifies.
	if _, err := v.Verify(sign(`{` + base + `,"kid":"` + s.KeyID() + `","v":3}`)); err != nil {
		t.Fatal(err)
	}
}

// TestAlgorithmConfusion: neither verifier accepts the other's tokens, and
// the HMAC key can never be a public key.
func TestAlgorithmConfusion(t *testing.T) {
	s, ed := newPair(t, "a")
	pubDER, err := x509.MarshalPKIXPublicKey(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// 1. HMAC keyed with the (public) PEM is refused outright.
	if _, err := NewHMACTokenVerifier(pubPEM); !errors.Is(err, ErrValidation) {
		t.Fatalf("HMAC keyed with a public key PEM: %v", err)
	}
	if _, err := NewHMACTokenVerifier(append([]byte("  \n"), pubPEM...)); !errors.Is(err, ErrValidation) {
		t.Fatalf("HMAC keyed with an indented PEM: %v", err)
	}

	// 2. HMAC v2 token presented to the Ed25519 verifier: version refusal,
	// no signature attempt with the wrong algorithm.
	h, _ := NewHMACTokenVerifier(bytes.Repeat([]byte{9}, 32), WithClock(v3Clock))
	v2tok, _ := h.Sign("agent-1", "secrets.echo", 1, nil, 60)
	if _, err := ed.Verify(v2tok); !errors.Is(err, ErrVersion) {
		t.Fatalf("v2 to Ed25519: %v", err)
	}

	// 3. An attacker who knows the public key HMACs a v3 payload with it
	// (the classic RS256->HS256 confusion): refused (32-byte MAC is not an
	// Ed25519 signature; a 64-byte one would not verify).
	payload, _ := split(t, mustSign(t, s, nil))
	forged := hmac.New(sha256.New, s.PublicKey())
	forged.Write(payload)
	if _, err := ed.Verify(reseal(payload, forged.Sum(nil))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("HMAC-with-public-key forgery: %v", err)
	}
	mac := forged.Sum(nil)
	if _, err := ed.Verify(reseal(payload, append(mac, mac...))); !errors.Is(err, ErrSignature) {
		t.Fatalf("64-byte HMAC forgery: %v", err)
	}

	// 4. v3 token presented to the HMAC verifier, even one keyed with the
	// raw public-key bytes padded to 32: signature refusal.
	v3tok := mustSign(t, s, nil)
	if _, err := h.Verify(v3tok); !errors.Is(err, ErrSignature) {
		t.Fatalf("v3 to HMAC: %v", err)
	}
	hp, err := NewHMACTokenVerifier(s.PublicKey(), WithClock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hp.Verify(v3tok); !errors.Is(err, ErrSignature) {
		t.Fatalf("v3 to HMAC keyed with the public key: %v", err)
	}
	// 5. ...and a v3 payload correctly HMAC'd with a key the HMAC verifier
	// holds is still refused by version.
	if _, err := h.Verify(reseal(payload, h.mac(payload))); !errors.Is(err, ErrVersion) {
		t.Fatalf("v3 payload under HMAC: %v", err)
	}
	// 6. A v3 Ed25519 token is not taken for v2 by the format sniffer.
	if f, err := TokenFormat(v3tok); err != nil || f == 2 {
		t.Fatalf("TokenFormat(v3) = %d, %v", f, err)
	}
}

func TestV3Expiry(t *testing.T) {
	s, _ := newPair(t, "a")
	tok := mustSign(t, s, nil) // exp = now + 60
	for _, c := range []struct {
		at   time.Time
		want error
	}{
		{v3Now.Add(60 * time.Second), nil},
		{v3Now.Add(61 * time.Second), ErrExpired},
		{v3Now.Add(time.Hour), ErrExpired},
	} {
		v, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{s.KeyID(): s.PublicKey()}, WithEd25519Clock(func() time.Time { return c.at }))
		_, err := v.Verify(tok)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Fatalf("at %v: %v", c.at, err)
		}
	}
}

func TestV3VerifierOnlyAndSigner(t *testing.T) {
	s, v := newPair(t, "a")
	if _, err := v.Sign("a", "c", 1, nil, 60); !errors.Is(err, ErrNoSigningKey) || errors.Is(err, ErrToken) {
		t.Fatalf("verifier-only Sign: %v", err)
	}
	keys := map[string]ed25519.PublicKey{s.KeyID(): s.PublicKey()}
	vs, err := NewEd25519Verifier(keys, WithSigner(s), WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := vs.Sign("agent-1", "secrets.echo", 1, nil, 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Verify(tok); err != nil {
		t.Fatal(err)
	}
	other, _ := NewEd25519Signer(testSeed("b"), s.KeyID())
	if _, err := NewEd25519Verifier(keys, WithSigner(other)); !errors.Is(err, ErrValidation) {
		t.Fatalf("untrusted signer: %v", err)
	}
	stranger, _ := NewEd25519Signer(testSeed("b"), "")
	if _, err := NewEd25519Verifier(keys, WithSigner(stranger)); !errors.Is(err, ErrValidation) {
		t.Fatalf("signer kid not trusted: %v", err)
	}
	for _, c := range []struct {
		agent, capability string
		version, ttl      int
	}{{"", "c", 1, 1}, {"a", "", 1, 1}, {"a", "c", 0, 1}, {"a", "c", 1, 0}} {
		if _, err := s.Sign(c.agent, c.capability, c.version, nil, c.ttl); !errors.Is(err, ErrValidation) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if _, err := s.Sign("a", "c", 1, map[string]any{"f": func() {}}, 1); err == nil {
		t.Error("unencodable binding accepted")
	}
}

func TestV3ConstructorValidation(t *testing.T) {
	pub := testSeed("a").Public().(ed25519.PublicKey)
	for _, c := range []struct {
		name string
		keys map[string]ed25519.PublicKey
	}{
		{"empty", map[string]ed25519.PublicKey{}},
		{"bad kid", map[string]ed25519.PublicKey{"a b": pub}},
		{"empty kid", map[string]ed25519.PublicKey{"": pub}},
		{"short key", map[string]ed25519.PublicKey{"k": pub[:31]}},
	} {
		if _, err := NewEd25519Verifier(c.keys); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := NewEd25519Signer(testSeed("a")[:63], ""); !errors.Is(err, ErrValidation) {
		t.Error("short private key")
	}
	if _, err := NewEd25519Signer(testSeed("a"), "bad kid!"); !errors.Is(err, ErrValidation) {
		t.Error("bad signer kid")
	}
	// Keys are copied: mutating the caller's slices changes nothing.
	s, _ := NewEd25519Signer(testSeed("a"), "", WithEd25519Clock(v3Clock))
	p := s.PublicKey()
	keys := map[string]ed25519.PublicKey{s.KeyID(): p}
	v, _ := NewEd25519Verifier(keys, WithEd25519Clock(v3Clock))
	p[0] ^= 0xff
	if _, err := v.Verify(mustSign(t, s, nil)); err != nil {
		t.Fatalf("verifier aliased the caller's key: %v", err)
	}
}

func TestV3Rotation(t *testing.T) {
	oldS, _ := newPair(t, "old")
	newS, _ := newPair(t, "new")
	oldTok, newTok := mustSign(t, oldS, nil), mustSign(t, newS, nil)
	both, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{oldS.KeyID(): oldS.PublicKey(), newS.KeyID(): newS.PublicKey()}, WithEd25519Clock(v3Clock))
	for _, tok := range []string{oldTok, newTok} {
		if _, err := both.Verify(tok); err != nil {
			t.Fatalf("overlap window: %v", err)
		}
	}
	retired, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{newS.KeyID(): newS.PublicKey()}, WithEd25519Clock(v3Clock))
	if _, err := retired.Verify(oldTok); !errors.Is(err, ErrSignature) {
		t.Fatalf("retired key still trusted: %v", err)
	}
	if _, err := retired.Verify(newTok); err != nil {
		t.Fatal(err)
	}
}

func TestV3ReplayGuardComposes(t *testing.T) {
	s, v := newPair(t, "a")
	g := NewReplayGuard(v, WithReplayClock(v3Clock))
	tok := mustSign(t, s, nil)
	if _, err := g.Verify(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Verify(tok); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
}

func TestV3Race(t *testing.T) {
	s, v := newPair(t, "a")
	vs, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{s.KeyID(): s.PublicKey()}, WithSigner(s), WithEd25519Clock(v3Clock))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tok, err := vs.Sign("agent", "cap", 1, map[string]any{"i": i, "j": j}, 60)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := v.Verify(tok); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// ---- key files ----

func writeKey(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func pemOf(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestKeyFiles(t *testing.T) {
	priv := testSeed("files")
	pub := priv.Public().(ed25519.PublicKey)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPubDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	ecPrivDER, _ := x509.MarshalPKCS8PrivateKey(ec)

	// Good loads.
	for _, c := range []struct {
		name string
		data []byte
	}{{"pub.pem", pemOf(t, "PUBLIC KEY", pubDER)}} {
		got, err := LoadEd25519PublicKeyFile(writeKey(t, c.name, c.data, 0o644))
		if err != nil || !got.Equal(pub) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	for _, c := range []struct {
		name string
		data []byte
	}{{"priv.pem", pemOf(t, "PRIVATE KEY", privDER)}, {"priv.raw", priv.Seed()}} {
		got, err := LoadEd25519PrivateKeyFile(writeKey(t, c.name, c.data, 0o600))
		if err != nil || !got.Equal(priv) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}

	// Refusals.
	pubBad := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"private key in public file", pemOf(t, "PRIVATE KEY", privDER), 0o600},
		{"ecdsa public", pemOf(t, "PUBLIC KEY", ecPubDER), 0o644},
		{"garbage DER", pemOf(t, "PUBLIC KEY", []byte{1, 2, 3}), 0o644},
		{"cert block", pemOf(t, "CERTIFICATE", []byte{1}), 0o644},
		{"trailing data", append(pemOf(t, "PUBLIC KEY", pubDER), "junk"...), 0o644},
		{"raw 32 bytes (could be a private seed)", pub, 0o600},
		{"raw 33 bytes", append(append([]byte(nil), pub...), '\n'), 0o644},
		{"hex text", []byte(hex.EncodeToString(pub)), 0o644},
		{"too large", bytes.Repeat([]byte{'a'}, maxKeyFile+1), 0o644},
	}
	if runtime.GOOS != "windows" {
		pubBad = append(pubBad, struct {
			name string
			data []byte
			mode os.FileMode
		}{"world-writable public", pemOf(t, "PUBLIC KEY", pubDER), 0o666})
	}
	for _, c := range pubBad {
		if _, err := LoadEd25519PublicKeyFile(writeKey(t, "k", c.data, c.mode)); !errors.Is(err, ErrValidation) {
			t.Errorf("public %s: %v", c.name, err)
		}
	}
	privBad := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"public key in private file", pemOf(t, "PUBLIC KEY", pubDER), 0o600},
		{"ecdsa private", pemOf(t, "PRIVATE KEY", ecPrivDER), 0o600},
		{"garbage DER", pemOf(t, "PRIVATE KEY", []byte{1, 2, 3}), 0o600},
		{"trailing data", append(pemOf(t, "PRIVATE KEY", privDER), "junk"...), 0o600},
		{"raw 31 bytes", priv.Seed()[:31], 0o600},
	}
	if runtime.GOOS != "windows" {
		for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
			privBad = append(privBad, struct {
				name string
				data []byte
				mode os.FileMode
			}{"mode " + m.String(), pemOf(t, "PRIVATE KEY", privDER), m})
		}
	}
	for _, c := range privBad {
		_, err := LoadEd25519PrivateKeyFile(writeKey(t, "k", c.data, c.mode))
		if !errors.Is(err, ErrValidation) {
			t.Errorf("private %s: %v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), hex.EncodeToString(priv.Seed())[:8]) {
			t.Errorf("error leaks key bytes: %v", err)
		}
	}
	if _, err := LoadEd25519PublicKeyFile(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrValidation) {
		t.Error("missing file")
	}
	if _, err := LoadEd25519PrivateKeyFile(t.TempDir()); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	if _, err := LoadEd25519PrivateKeyFile(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrValidation) {
		t.Error("missing private file")
	}

	// From files: trusted under KeyID.
	v, err := NewEd25519VerifierFromFiles([]string{writeKey(t, "p", pemOf(t, "PUBLIC KEY", pubDER), 0o644)}, WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewEd25519Signer(priv, "", WithEd25519Clock(v3Clock))
	if _, err := v.Verify(mustSign(t, s, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEd25519VerifierFromFiles([]string{filepath.Join(t.TempDir(), "nope")}); !errors.Is(err, ErrValidation) {
		t.Error("missing file in set")
	}
	if _, err := NewEd25519VerifierFromFiles(nil); !errors.Is(err, ErrValidation) {
		t.Error("empty set")
	}
}

func TestCheckKeyMode(t *testing.T) {
	if checkKeyMode(0o644, 0o077, "windows") != nil {
		t.Error("windows: mode bits are not the ACL")
	}
	if checkKeyMode(0o600, 0o077, "linux") != nil || checkKeyMode(0o400, 0o077, "darwin") != nil {
		t.Error("0600/0400 must pass")
	}
	for _, m := range []os.FileMode{0o601, 0o610, 0o700 | 0o004} {
		if checkKeyMode(m, 0o077, "linux") == nil {
			t.Errorf("%#o accepted for a private key", m)
		}
	}
	if checkKeyMode(0o644, 0o022, "linux") != nil || checkKeyMode(0o664, 0o022, "linux") == nil {
		t.Error("public key mode rule")
	}
}

func FuzzEd25519Verify(f *testing.F) {
	s, _ := NewEd25519Signer(testSeed("fuzz"), "", WithEd25519Clock(v3Clock))
	tok, _ := s.Sign("a", "c", 1, nil, 60)
	f.Add(tok)
	f.Add("x.y")
	f.Add(".")
	v, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{s.KeyID(): s.PublicKey()}, WithEd25519Clock(v3Clock))
	f.Fuzz(func(t *testing.T, in string) {
		got, err := v.Verify(in)
		if err == nil && in != tok {
			// Ed25519 signatures are not malleable in Go (canonical S);
			// only the genuine token verifies.
			t.Fatalf("accepted a token that was not minted: %q (%+v)", in, got)
		}
	})
}

// v3VectorToken was cross-checked with Python's cryptography Ed25519
// (same seed, json.dumps(sort_keys=True, separators=(",", ":")) payload,
// SigningContextV3 prefix): see docs/design/asymmetric-tokens.md.
const v3VectorToken = "eyJhZ2VudF9pZCI6ImFnZW50LVx1MDBlOSIsImNhcGFiaWxpdHkiOiJzZWNyZXRzLnVzZSIsImNhcGFiaWxpdHlfdmVyc2lvbiI6MiwiY29udGV4dF9iaW5kaW5ncyI6eyJ1cmwiOiJodHRwczovL3gvP2E9MSZiPTwyPiJ9LCJleHAiOjE5MDAwMDAzMDAsImtpZCI6ImsxIiwidiI6M30.hPAd_eckxbdji095r-6wquU14EsZ8ZV_ACMZXvkyOdRgx2a2S5-nkCgUR1C0ZbYbTNQKrXSvNtgSm0XLOpqABQ"

// TestRejectWeakPublicKeys (review MED-3): every small-order and
// non-canonical encoding is refused by the constructor and the loader, and
// the identity key really would have accepted a forgery.
func TestRejectWeakPublicKeys(t *testing.T) {
	var weak [][]byte
	weak = append(weak, smallOrderKeys...)
	// Non-canonical y >= p, with and without the sign bit.
	for _, lo := range []byte{0xed, 0xee, 0xf0, 0xff} {
		for _, hi := range []byte{0x7f, 0xff} {
			k := bytes.Repeat([]byte{0xff}, 32)
			k[0], k[31] = lo, hi
			weak = append(weak, k)
		}
	}
	if len(smallOrderKeys) != 10 {
		t.Fatalf("blocklist has %d entries", len(smallOrderKeys))
	}
	for _, k := range weak {
		if _, err := NewEd25519Verifier(map[string]ed25519.PublicKey{"k": k}); !errors.Is(err, ErrValidation) {
			t.Errorf("weak key %x accepted: %v", k, err)
		}
		// Through a PEM file as well (x509 accepts any 32 bytes).
		der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(k))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadEd25519PublicKeyFile(writeKey(t, "w.pem", pemOf(t, "PUBLIC KEY", der), 0o644)); !errors.Is(err, ErrValidation) {
			t.Errorf("weak key %x loaded from PEM: %v", k, err)
		}
	}
	// Boundary: y = p - 1 (ec ff.. 7f) is the order-2 point (listed);
	// y = p - 2 is canonical and not small order, so it passes the check.
	edge := bytes.Repeat([]byte{0xff}, 32)
	edge[0], edge[31] = 0xeb, 0x7f
	if nonCanonicalY(edge) || checkPublicKey(edge) != nil {
		t.Fatal("y = p-2 wrongly refused")
	}
	// Why it matters: with the identity key, R = identity and S = 0 is a
	// valid signature for ANY message under Go's verifier.
	identity := ed25519.PublicKey(smallOrderKeys[0])
	sig := append(append([]byte(nil), smallOrderKeys[0]...), make([]byte, 32)...)
	if !ed25519.Verify(identity, []byte("anything"), sig) {
		t.Skip("this Go version rejects the identity forgery itself; the check is still required for other small-order keys")
	}
	zero := ed25519.PublicKey(make([]byte, 32))
	if !ed25519.Verify(zero, []byte("x"), make([]byte, 64)) {
		t.Log("all-zero forgery not accepted by this Go version")
	}
	// Real keys never trip the check.
	for i := 0; i < 200; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		if err := checkPublicKey(pub); err != nil {
			t.Fatalf("generated key refused: %v", err)
		}
	}
}

// TestV3UntrustedKidSignedByTrustedKey (review LOW-1): a token signed by a
// trusted private key but carrying a kid the verifier does not trust is
// refused; the kid is never ignored or defaulted.
func TestV3UntrustedKidSignedByTrustedKey(t *testing.T) {
	_, v := newPair(t, "a")
	rogue, err := NewEd25519Signer(testSeed("a"), "not-trusted", WithEd25519Clock(v3Clock))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(mustSign(t, rogue, nil)); !errors.Is(err, ErrSignature) {
		t.Fatalf("untrusted kid: %v", err)
	}
}

// TestV3Strictness (review LOW-5): v3 refuses duplicate keys and exp <= 0;
// v2 keeps Python's behaviour byte for byte.
func TestV3Strictness(t *testing.T) {
	s, v := newPair(t, "a")
	sign := func(p string) string { return reseal([]byte(p), ed25519.Sign(s.priv, signingInputV3([]byte(p)))) }
	kid := `"kid":"` + s.KeyID() + `"`
	base := `"agent_id":"a","capability":"c","capability_version":1,"context_bindings":{},` + kid + `,"v":3`
	for _, c := range []struct{ name, payload string }{
		{"duplicate top-level key", `{"agent_id":"b",` + base + `,"exp":1900000060}`},
		{"duplicate exp", `{` + base + `,"exp":1,"exp":1900000060}`},
		{"duplicate nested key", `{"agent_id":"a","capability":"c","capability_version":1,"context_bindings":{"x":1,"x":2},` + kid + `,"v":3,"exp":1900000060}`},
		{"duplicate via escape", `{"agent_id":"a","agent\u005fid":"b","capability":"c","capability_version":1,"context_bindings":{},` + kid + `,"v":3,"exp":1900000060}`},
		{"duplicate in array object", `{"agent_id":"a","capability":"c","capability_version":1,"context_bindings":{"l":[{"k":1,"k":2}]},` + kid + `,"v":3,"exp":1900000060}`},
		{"exp zero", `{` + base + `,"exp":0}`},
		{"exp negative", `{` + base + `,"exp":-5}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := v.Verify(sign(c.payload)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if _, err := v.Verify(sign(`{` + base + `,"exp":1900000060,"context_bindings2":{"l":[{"k":1},{"k":2}]}}`)); err != nil {
		t.Fatalf("same key in sibling objects is not a duplicate: %v", err)
	}
	// v2 unchanged: duplicate keys still parse last-wins, exp 0 still never expires.
	h, _ := NewHMACTokenVerifier(bytes.Repeat([]byte{3}, 32), WithClock(v3Clock))
	p2 := []byte(`{"agent_id":"x","agent_id":"a","capability":"c","capability_version":1,"context_bindings":{},"exp":0,"v":2}`)
	tok, err := h.Verify(reseal(p2, h.mac(p2)))
	if err != nil || tok.AgentID != "a" || tok.ExpiresAt != 0 {
		t.Fatalf("v2 behaviour changed: %+v %v", tok, err)
	}
}
