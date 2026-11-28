package captoken

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

// TokenVerifier signs and verifies v2 capability tokens (Python
// TokenVerifier). The vault holds one verifier; callers never see key
// material.
type TokenVerifier interface {
	// Sign mints a token authorizing one capability for ttlSeconds.
	Sign(agentID, capability string, capabilityVersion int, contextBindings map[string]any, ttlSeconds int) (string, error)
	// Verify checks the token and returns its claims. Failures are *Error
	// values: ErrExpired, ErrSignature, ErrMalformed or ErrVersion.
	Verify(token string) (*CapabilityV2Token, error)
}

// Option configures an HMACTokenVerifier.
type Option func(*HMACTokenVerifier)

// WithClock overrides the time source (tests, deterministic vectors).
func WithClock(now func() time.Time) Option {
	return func(v *HMACTokenVerifier) { v.now = now }
}

// HMACTokenVerifier is the HMAC-SHA256 verifier (Python HMACTokenVerifier).
// Whoever holds the shared secret can mint tokens for any agent and
// capability; the minimum length is 32 bytes.
type HMACTokenVerifier struct {
	secret []byte
	now    func() time.Time
}

var _ TokenVerifier = (*HMACTokenVerifier)(nil)

// NewHMACTokenVerifier returns a verifier for the shared secret (>= 32
// bytes; the slice is copied).
func NewHMACTokenVerifier(sharedSecret []byte, opts ...Option) (*HMACTokenVerifier, error) {
	if len(sharedSecret) < MinSecretLen {
		return nil, newErr(kindValidation, "shared_secret must be at least %d bytes of random material", MinSecretLen)
	}
	// Algorithm-confusion guard (RGT-35): an HMAC secret is random bytes,
	// never a PEM-encoded (public) key. Keying HMAC with a public key would
	// let anyone who has that public key forge tokens.
	if bytes.Contains(sharedSecret, []byte("-----BEGIN")) {
		return nil, newErr(kindValidation, "shared_secret looks like a PEM-encoded key; an HMAC key must be random secret bytes, never a public key")
	}
	v := &HMACTokenVerifier{secret: append([]byte(nil), sharedSecret...), now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

func (v *HMACTokenVerifier) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, v.secret)
	h.Write(payload)
	return h.Sum(nil)
}

// Sign implements TokenVerifier. capabilityVersion < 1, empty agentID or
// capability, or ttlSeconds <= 0 return ErrValidation.
func (v *HMACTokenVerifier) Sign(agentID, capability string, capabilityVersion int, contextBindings map[string]any, ttlSeconds int) (string, error) {
	if ttlSeconds <= 0 {
		return "", newErr(kindValidation, "ttl_seconds must be > 0")
	}
	if agentID == "" {
		return "", newErr(kindValidation, "agent_id is required")
	}
	if capability == "" {
		return "", newErr(kindValidation, "capability is required")
	}
	if capabilityVersion < 1 {
		return "", newErr(kindValidation, "capability_version must be a positive int")
	}
	exp := v.now().Unix() + int64(ttlSeconds)
	payload, err := canonicalPayload(agentID, capability, capabilityVersion, contextBindings, exp)
	if err != nil {
		return "", err
	}
	return envelope(payload, v.mac(payload)), nil
}

// Verify implements TokenVerifier. The order of checks matches Python:
// envelope, constant-time signature, JSON/version/fields, expiry.
func (v *HMACTokenVerifier) Verify(token string) (*CapabilityV2Token, error) {
	payload, sig, err := openEnvelope(token)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(v.mac(payload), sig) {
		return nil, newErr(kindSignature, "token signature did not verify")
	}
	tok, err := parseV2Payload(payload)
	if err != nil {
		return nil, err
	}
	if tok.IsExpired(v.now()) {
		return nil, newErr(kindExpired, "token for %q expired at %d", tok.Capability, tok.ExpiresAt)
	}
	return tok, nil
}
