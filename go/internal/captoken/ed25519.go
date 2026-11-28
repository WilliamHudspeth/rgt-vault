package captoken

// Ed25519 capability tokens: format v3 (RGT-35 design, RGT-46).
// Design: docs/design/asymmetric-tokens.md.
//
// v3 is a NEW, additive format. The v2 HMAC format, its envelope and its
// canonical payload are unchanged; HMACTokenVerifier never accepts a v3
// token and Ed25519Verifier never accepts a v2 (or v1) token.
//
// Wire format v3:
//
//	base64url(payload_json) + "." + base64url(ed25519_sig)     (no padding)
//
// payload_json is the v2 claim set plus "kid", with "v": 3, rendered by the
// same canonical encoder as v2 (Python json.dumps(sort_keys=True,
// separators=(",", ":")), ensure_ascii=True):
//
//	{"agent_id":..,"capability":..,"capability_version":..,
//	 "context_bindings":{..},"exp":..,"kid":"<key id>","v":3}
//
// ed25519_sig = Ed25519(private_key, SigningContextV3 || payload_json): the
// signature covers a fixed domain-separation prefix, so a v3 signing key
// signs nothing that could be mistaken for another protocol's message.
//
// There is no "alg" field. The algorithm is fixed by the version, and the
// version a verifier accepts is fixed by its type (configuration), never
// by the token. "kid" only selects among the verifier's own trusted public
// keys, and it is covered by the signature.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// TokenFormatVersionEd25519 is the v3 payload "v" value (Ed25519).
const TokenFormatVersionEd25519 = 3

// SigningContextV3 is prepended to the payload before signing/verifying.
const SigningContextV3 = "rgt-vault/captoken/v3/ed25519\x00"

// MaxTokenLen bounds a v3 token before any decoding (DoS guard; a v3 token
// with ordinary bindings is a few hundred bytes).
const MaxTokenLen = 16 * 1024

// MaxKeyIDLen bounds a key id.
const MaxKeyIDLen = 64

// ErrNoSigningKey: Sign was called on a verifier that holds public keys
// only (the verifier-only deployment). It is not a token failure.
var ErrNoSigningKey = &Error{kind: kindNoSigningKey}

// KeyID is the default key id of an Ed25519 public key: the first 16 hex
// characters of sha256(public key). It is public and safe to log.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

func validKeyID(kid string) bool {
	if kid == "" || len(kid) > MaxKeyIDLen {
		return false
	}
	for _, c := range kid {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// Ed25519Option configures an Ed25519Signer or Ed25519Verifier.
type Ed25519Option func(*ed25519Opts)

type ed25519Opts struct {
	now    func() time.Time
	signer *Ed25519Signer
}

// WithEd25519Clock overrides the time source (tests, vectors).
func WithEd25519Clock(now func() time.Time) Ed25519Option {
	return func(o *ed25519Opts) { o.now = now }
}

// WithSigner lets an Ed25519Verifier also Sign (an issuer that verifies its
// own tokens, tests). The signer's public key must be one of the
// verifier's trusted keys under the signer's key id.
func WithSigner(s *Ed25519Signer) Ed25519Option {
	return func(o *ed25519Opts) { o.signer = s }
}

// Ed25519Signer mints v3 tokens with one private key (the issuer / harness
// side). The verifier side needs only the public key.
type Ed25519Signer struct {
	kid  string
	priv ed25519.PrivateKey
	now  func() time.Time
}

// NewEd25519Signer returns a signer for priv. kid "" means KeyID(public
// key). The key is copied.
func NewEd25519Signer(priv ed25519.PrivateKey, kid string, opts ...Ed25519Option) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, newErr(kindValidation, "ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if kid == "" {
		kid = KeyID(pub)
	}
	if !validKeyID(kid) {
		return nil, newErr(kindValidation, "key id must be 1-%d characters of [A-Za-z0-9._-]", MaxKeyIDLen)
	}
	o := ed25519Opts{now: time.Now}
	for _, f := range opts {
		f(&o)
	}
	return &Ed25519Signer{kid: kid, priv: append(ed25519.PrivateKey(nil), priv...), now: o.now}, nil
}

// KeyID returns the signer's key id.
func (s *Ed25519Signer) KeyID() string { return s.kid }

// PublicKey returns a copy of the signer's public key.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.priv.Public().(ed25519.PublicKey)...)
}

// Sign mints a v3 token. Arguments are validated exactly as
// HMACTokenVerifier.Sign validates them.
func (s *Ed25519Signer) Sign(agentID, capability string, capabilityVersion int, contextBindings map[string]any, ttlSeconds int) (string, error) {
	if err := validateSignArgs(agentID, capability, capabilityVersion, ttlSeconds); err != nil {
		return "", err
	}
	payload, err := canonicalPayloadV3(agentID, capability, capabilityVersion, contextBindings, s.now().Unix()+int64(ttlSeconds), s.kid)
	if err != nil {
		return "", err
	}
	return envelope(payload, ed25519.Sign(s.priv, signingInputV3(payload))), nil
}

func validateSignArgs(agentID, capability string, capabilityVersion, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		return newErr(kindValidation, "ttl_seconds must be > 0")
	}
	if agentID == "" {
		return newErr(kindValidation, "agent_id is required")
	}
	if capability == "" {
		return newErr(kindValidation, "capability is required")
	}
	if capabilityVersion < 1 {
		return newErr(kindValidation, "capability_version must be a positive int")
	}
	return nil
}

func canonicalPayloadV3(agentID, capability string, capabilityVersion int, bindings map[string]any, expiresAt int64, kid string) ([]byte, error) {
	if bindings == nil {
		bindings = map[string]any{}
	}
	return canonicalJSON(map[string]any{
		"v":                  TokenFormatVersionEd25519,
		"kid":                kid,
		"agent_id":           agentID,
		"capability":         capability,
		"capability_version": capabilityVersion,
		"context_bindings":   bindings,
		"exp":                expiresAt,
	})
}

func signingInputV3(payload []byte) []byte {
	m := make([]byte, 0, len(SigningContextV3)+len(payload))
	return append(append(m, SigningContextV3...), payload...)
}

// Ed25519Verifier verifies v3 tokens against a set of trusted public keys
// indexed by key id. It never holds a private key unless WithSigner is
// given; without one, Sign returns ErrNoSigningKey. Rotation: trust the new
// key alongside the old one, switch the issuer, and drop the old key once
// its last token has expired (at most the issuer's maximum TTL).
//
// The zero value is unconfigured and fails closed (ErrNotImplemented, as the
// RGT-35 placeholder did).
type Ed25519Verifier struct {
	keys   map[string]ed25519.PublicKey
	signer *Ed25519Signer
	now    func() time.Time
}

var _ TokenVerifier = (*Ed25519Verifier)(nil)

// NewEd25519Verifier returns a verifier trusting keys (key id -> public
// key). At least one key is required; key ids must be valid and keys 32
// bytes. Keys are copied.
func NewEd25519Verifier(keys map[string]ed25519.PublicKey, opts ...Ed25519Option) (*Ed25519Verifier, error) {
	if len(keys) == 0 {
		return nil, newErr(kindValidation, "an Ed25519 verifier needs at least one trusted public key")
	}
	o := ed25519Opts{now: time.Now}
	for _, f := range opts {
		f(&o)
	}
	v := &Ed25519Verifier{keys: make(map[string]ed25519.PublicKey, len(keys)), now: o.now}
	for kid, pub := range keys {
		if !validKeyID(kid) {
			return nil, newErr(kindValidation, "key id must be 1-%d characters of [A-Za-z0-9._-]", MaxKeyIDLen)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, newErr(kindValidation, "ed25519 public key %s must be %d bytes", kid, ed25519.PublicKeySize)
		}
		v.keys[kid] = append(ed25519.PublicKey(nil), pub...)
	}
	if o.signer != nil {
		pub, ok := v.keys[o.signer.kid]
		if !ok || !pub.Equal(o.signer.priv.Public()) {
			return nil, newErr(kindValidation, "the signer's public key is not trusted under its key id")
		}
		v.signer = o.signer
	}
	return v, nil
}

// KeyIDs returns the trusted key ids, sorted.
func (v *Ed25519Verifier) KeyIDs() []string {
	out := make([]string, 0, len(v.keys))
	for k := range v.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Sign implements TokenVerifier. A verifier-only deployment (no
// WithSigner) returns ErrNoSigningKey.
func (v *Ed25519Verifier) Sign(agentID, capability string, capabilityVersion int, contextBindings map[string]any, ttlSeconds int) (string, error) {
	if v.keys == nil {
		return "", newErr(kindNotImplemented, "Ed25519Verifier is not configured; use NewEd25519Verifier")
	}
	if v.signer == nil {
		return "", newErr(kindNoSigningKey, "this verifier holds public keys only; tokens are minted by the issuer")
	}
	return v.signer.Sign(agentID, capability, capabilityVersion, contextBindings, ttlSeconds)
}

// Verify implements TokenVerifier for v3 tokens. Order: size, envelope,
// signature length, version and key id (unverified, used only to pick a
// trusted key), Ed25519 signature over SigningContextV3||payload, claims,
// expiry. A v1/v2 token is ErrVersion (or ErrMalformed), never a crypto
// attempt with the wrong algorithm.
func (v *Ed25519Verifier) Verify(token string) (*CapabilityV2Token, error) {
	if v.keys == nil {
		return nil, newErr(kindNotImplemented, "Ed25519Verifier is not configured; use NewEd25519Verifier")
	}
	if len(token) > MaxTokenLen {
		return nil, newErr(kindMalformed, "token exceeds %d bytes", MaxTokenLen)
	}
	payload, sig, err := openEnvelope(token)
	if err != nil {
		return nil, err
	}
	// Pre-signature header read. Only "v" and "kid" are looked at, and only
	// to refuse early or to choose one of OUR keys.
	data, err := decodeObject(payload)
	if err != nil {
		return nil, newErr(kindMalformed, "token payload not valid JSON object")
	}
	version, ok := intField(data, "v", true)
	if !ok {
		return nil, newErr(kindMalformed, "token payload field v is not an integer")
	}
	if version != TokenFormatVersionEd25519 {
		return nil, newErr(kindVersion, "token format version %d not supported; this verifier only handles v%d", version, TokenFormatVersionEd25519)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, newErr(kindMalformed, "ed25519 signature must be %d bytes", ed25519.SignatureSize)
	}
	kid, ok := data["kid"].(string)
	if !ok || !validKeyID(kid) {
		return nil, newErr(kindMalformed, "token payload missing or invalid field: 'kid'")
	}
	pub, ok := v.keys[kid]
	if !ok {
		// Same class as a bad signature: an unknown key id is a token we
		// cannot authenticate.
		return nil, newErr(kindSignature, "token signature did not verify")
	}
	if !ed25519.Verify(pub, signingInputV3(payload), sig) {
		return nil, newErr(kindSignature, "token signature did not verify")
	}
	tok, err := parsePayloadVersion(payload, TokenFormatVersionEd25519)
	if err != nil {
		return nil, err
	}
	tok.KeyID = kid
	if tok.IsExpired(v.now()) {
		return nil, newErr(kindExpired, "token for %q expired at %d", tok.Capability, tok.ExpiresAt)
	}
	return tok, nil
}
