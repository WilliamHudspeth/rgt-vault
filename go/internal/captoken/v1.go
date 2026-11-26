package captoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// DefaultMaxTTLSeconds is TwoFactorHook's default max_ttl_seconds.
const DefaultMaxTTLSeconds = 3600

// CapabilityToken is the legacy v1 token of python/hook.py: namespace-scoped
// with a list of operations. Wire format:
//
//	base64url(json{"a","c"(sorted),"i","n","t","x"}) + "." + base64url(hmac)
//
// (no padding; sorted keys; compact separators; ensure_ascii).
//
// Python quirk, reproduced and flagged: CapabilityToken.to_compact() signs
// with an EMPTY key (`_sign(payload, b"")`, "placeholder; replaced when
// serialized") while TwoFactorHook._consult_v1 verifies against the shared
// secret, so no token produced by Python's to_compact() can ever verify.
// ToCompact(nil) reproduces that exact Python output; pass the shared secret
// to get a token TwoFactorHook accepts.
type CapabilityToken struct {
	Agent        string
	Namespace    string
	Capabilities []string // e.g. ["read", "write"]; "*" covers everything
	IssuedAt     int64    // unix seconds
	ExpiresAt    int64    // unix seconds
	TokenID      string
}

// NewTokenID returns uuid4().hex (32 lowercase hex characters).
func NewTokenID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("captoken: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:])
}

// IssueCapabilityToken mirrors TwoFactorHook.issue: it builds an (unsigned)
// token valid from now for ttlSeconds, which must be in [1, maxTTLSeconds]
// (pass DefaultMaxTTLSeconds for the Python default).
func IssueCapabilityToken(agent, namespace string, capabilities []string, ttlSeconds, maxTTLSeconds int, now time.Time) (*CapabilityToken, error) {
	if ttlSeconds <= 0 || ttlSeconds > maxTTLSeconds {
		return nil, newErr(kindValidation, "ttl_seconds must be between 1 and %d", maxTTLSeconds)
	}
	n := now.Unix()
	return &CapabilityToken{
		Agent:        agent,
		Namespace:    namespace,
		Capabilities: append([]string(nil), capabilities...),
		IssuedAt:     n,
		ExpiresAt:    n + int64(ttlSeconds),
		TokenID:      NewTokenID(),
	}, nil
}

func (t *CapabilityToken) payload() ([]byte, error) {
	caps := append([]string{}, t.Capabilities...)
	sort.Strings(caps)
	return canonicalJSON(map[string]any{
		"a": t.Agent,
		"n": t.Namespace,
		"c": caps,
		"i": t.IssuedAt,
		"x": t.ExpiresAt,
		"t": t.TokenID,
	})
}

// ToCompact serializes and signs the token with HMAC-SHA256(secret). A nil
// or empty secret reproduces Python's to_compact() (empty-key HMAC), which
// is not verifiable by TwoFactorHook; see the type comment.
func (t *CapabilityToken) ToCompact(secret []byte) (string, error) {
	payload, err := t.payload()
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	return envelope(payload, h.Sum(nil)), nil
}

// Covers reports whether the token covers operation on namespace at now:
// namespace equal or "*", IssuedAt <= now <= ExpiresAt, and the operation (or
// "*") listed in Capabilities.
func (t *CapabilityToken) Covers(operation, namespace string, now time.Time) bool {
	if t.Namespace != namespace && t.Namespace != "*" {
		return false
	}
	n := now.Unix()
	if !(t.IssuedAt <= n && n <= t.ExpiresAt) {
		return false
	}
	for _, c := range t.Capabilities {
		if c == operation || c == "*" {
			return true
		}
	}
	return false
}

// TokenFormat peeks at the envelope the way TwoFactorHook.consult does to
// dispatch v1 vs v2. It returns 2 when the (unverified!) payload decodes to a
// JSON object with "v" == 2, otherwise 1. A token without exactly the
// "payload.signature" shape (split on the first ".") is ErrMalformed. The
// result only selects a verifier; it is never a trust decision.
func TokenFormat(token string) (int, error) {
	body, _, ok := strings.Cut(token, ".")
	if !ok {
		return 0, newErr(kindMalformed, "malformed capability_token")
	}
	raw, err := decodeB64(body)
	if err != nil {
		return 1, nil
	}
	m, err := decodeObject(raw)
	if err != nil {
		return 1, nil
	}
	if v, ok := intField(m, "v", true); ok && v == TokenFormatVersion {
		return 2, nil
	}
	return 1, nil
}

// ParseV1 verifies a v1 token against secret and returns its claims,
// reproducing TwoFactorHook._consult_v1 up to (not including) the
// agent/coverage/replay checks. The envelope is split on the first ".".
// Errors: ErrMalformed (shape, base64, payload fields) and ErrSignature.
// Expiry is not checked here (Covers does it, as in Python); the caller
// compares Agent, calls Covers and applies its replay cache.
func ParseV1(token string, secret []byte) (*CapabilityToken, error) {
	body, sigPart, ok := strings.Cut(token, ".")
	if !ok {
		return nil, newErr(kindMalformed, "malformed capability_token")
	}
	payload, err1 := decodeB64(body)
	sig, err2 := decodeB64(sigPart)
	if err1 != nil || err2 != nil {
		return nil, newErr(kindMalformed, "capability_token base64 decode failed")
	}
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	if !hmac.Equal(h.Sum(nil), sig) {
		return nil, newErr(kindSignature, "capability_token signature invalid")
	}
	data, err := decodeObject(payload)
	if err != nil {
		return nil, newErr(kindMalformed, "capability_token payload invalid: not a JSON object")
	}
	agent, ok1 := data["a"].(string)
	ns, ok2 := data["n"].(string)
	tid, ok3 := data["t"].(string)
	issued, ok4 := intField(data, "i", false)
	exp, ok5 := intField(data, "x", false)
	rawCaps, ok6 := data["c"].([]any)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return nil, newErr(kindMalformed, "capability_token payload invalid: missing or mistyped field")
	}
	caps := make([]string, 0, len(rawCaps))
	for _, c := range rawCaps {
		s, ok := c.(string)
		if !ok {
			return nil, newErr(kindMalformed, "capability_token payload invalid: capabilities must be strings")
		}
		caps = append(caps, s)
	}
	return &CapabilityToken{Agent: agent, Namespace: ns, Capabilities: caps, IssuedAt: issued, ExpiresAt: exp, TokenID: tid}, nil
}
