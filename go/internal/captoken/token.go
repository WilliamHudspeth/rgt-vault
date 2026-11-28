// Package captoken ports python/token.py (v2 capability tokens) and the v1
// namespace-scoped CapabilityToken of python/hook.py (TwoFactorHook).
//
// Wire format v2 (byte-compatible with Python):
//
//	base64url(payload_json) + "." + base64url(hmac_sha256(secret, payload_json))
//
// with NO base64 padding. payload_json is
// json.dumps({v, agent_id, capability, capability_version, context_bindings,
// exp}, sort_keys=True, separators=(",", ":")) with Python's default
// ensure_ascii=True, so the signed bytes match Python's exactly (see
// canonical.go). token_id = hex(sha256(payload_json))[:16].
//
// The package is stdlib-only.
package captoken

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TokenFormatVersion is the v2 payload "v" value. Verifiers dispatch on it.
const TokenFormatVersion = 2

// MinSecretLen is the minimum shared-secret length in bytes (256 bits).
const MinSecretLen = 32

// CapabilityV2Token is a v2 capability token after signature verification.
// TokenID is sha256(payload)[:16] in hex, deterministic and safe to log.
type CapabilityV2Token struct {
	AgentID           string
	Capability        string
	CapabilityVersion int
	ContextBindings   map[string]any
	ExpiresAt         int64 // unix seconds; <= 0 means "never expires" (as in Python)
	TokenID           string
	// KeyID is the Ed25519 key id of a v3 token ("" for v2 HMAC tokens).
	KeyID string
}

// IsExpired reports whether now is past ExpiresAt. As in Python, a token
// with ExpiresAt <= 0 never expires (the signer always sets exp > 0, so this
// is only reachable with a token minted by a key holder with a custom
// payload).
func (t *CapabilityV2Token) IsExpired(now time.Time) bool {
	if t.ExpiresAt <= 0 {
		return false
	}
	return now.Unix() > t.ExpiresAt
}

// CheckContext returns an ErrBinding error if requestContext violates any
// binding on the token. Bindings are equality constraints: every key/value
// of ContextBindings must be present in requestContext with an equal value
// (JSON-wise: numbers compare by value, so 1 == 1.0; unlike Python, a bool
// never equals a number). Extra request keys are allowed. A token with no
// bindings accepts any context.
func (t *CapabilityV2Token) CheckContext(requestContext map[string]any) error {
	if len(t.ContextBindings) == 0 {
		return nil
	}
	keys := make([]string, 0, len(t.ContextBindings))
	for k := range t.ContextBindings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		expected := t.ContextBindings[key]
		got, ok := requestContext[key]
		if !ok {
			return newErr(kindBinding, "capability %q requires context key %q in the request", t.Capability, key)
		}
		ne, err1 := normalize(expected)
		ng, err2 := normalize(got)
		if err1 != nil || err2 != nil || !valuesEqual(ne, ng) {
			return newErr(kindBinding, "capability %q context binding failed for %q: expected %v, got %v",
				t.Capability, key, expected, got)
		}
	}
	return nil
}

// CheckAudience verifies that the token is for exactly this agent,
// capability and capability version (the comparisons TwoFactorHook._consult_v2
// performs after verify). It returns an ErrAudience error otherwise.
func (t *CapabilityV2Token) CheckAudience(agentID, capability string, capabilityVersion int) error {
	if t.AgentID != agentID {
		return newErr(kindAudience, "token bound to agent %q, caller claimed %q", t.AgentID, agentID)
	}
	if t.Capability != capability {
		return newErr(kindAudience, "token authorizes %q, request asked for %q", t.Capability, capability)
	}
	if t.CapabilityVersion != capabilityVersion {
		return newErr(kindAudience, "token capability_version=%d, request asked for %d", t.CapabilityVersion, capabilityVersion)
	}
	return nil
}

// Authorize runs CheckAudience then CheckContext. It is the full
// post-signature check of the v2 hook path.
func (t *CapabilityV2Token) Authorize(agentID, capability string, capabilityVersion int, requestContext map[string]any) error {
	if err := t.CheckAudience(agentID, capability, capabilityVersion); err != nil {
		return err
	}
	return t.CheckContext(requestContext)
}

// canonicalPayload builds the exact bytes that get signed.
func canonicalPayload(agentID, capability string, capabilityVersion int, bindings map[string]any, expiresAt int64) ([]byte, error) {
	if bindings == nil {
		bindings = map[string]any{}
	}
	return canonicalJSON(map[string]any{
		"v":                  TokenFormatVersion,
		"agent_id":           agentID,
		"capability":         capability,
		"capability_version": capabilityVersion,
		"context_bindings":   bindings,
		"exp":                expiresAt,
	})
}

var b64 = base64.RawURLEncoding.Strict()

// decodeB64 is Strict base64url without padding. encoding/base64 silently
// skips \r and \n; reject them so a token has exactly one spelling.
func decodeB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, base64.CorruptInputError(0)
	}
	return b64.DecodeString(s)
}

func envelope(payload, sig []byte) string {
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig)
}

// openEnvelope reverses envelope. Unlike Python's lenient
// urlsafe_b64decode it rejects padding, whitespace and standard-alphabet
// characters; every token a signer emits is accepted.
func openEnvelope(token string) (payload, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, nil, newErr(kindMalformed, "token must be 'payload.signature'")
	}
	payload, err = decodeB64(parts[0])
	if err != nil {
		return nil, nil, newErr(kindMalformed, "token base64 decode failed")
	}
	sig, err = decodeB64(parts[1])
	if err != nil {
		return nil, nil, newErr(kindMalformed, "token base64 decode failed")
	}
	if len(payload) == 0 || len(sig) == 0 {
		return nil, nil, newErr(kindMalformed, "token payload or signature empty")
	}
	return payload, sig, nil
}

// parseV2Payload turns verified payload bytes into claims. Mirrors the
// post-signature half of HMACTokenVerifier.verify (without the expiry
// check, which the caller does with its clock).
func parseV2Payload(payload []byte) (*CapabilityV2Token, error) {
	return parsePayloadVersion(payload, TokenFormatVersion)
}

// parsePayloadVersion is parseV2Payload for a given format version (v2
// HMAC, v3 Ed25519): the claim set and its checks are the same.
func parsePayloadVersion(payload []byte, want int64) (*CapabilityV2Token, error) {
	data, err := decodeObject(payload)
	if err != nil {
		return nil, newErr(kindMalformed, "token payload not valid JSON object")
	}
	version, ok := intField(data, "v", true) // Python: int(data.get("v", 0))
	if !ok {
		return nil, newErr(kindMalformed, "token payload field v is not an integer")
	}
	if version != want {
		return nil, newErr(kindVersion, "token format version %d not supported; this verifier only handles v%d", version, want)
	}
	agent, ok1 := data["agent_id"].(string)
	capability, ok2 := data["capability"].(string)
	if _, present := data["agent_id"]; !present {
		return nil, newErr(kindMalformed, "token payload missing field: 'agent_id'")
	}
	if _, present := data["capability"]; !present {
		return nil, newErr(kindMalformed, "token payload missing field: 'capability'")
	}
	if !ok1 || !ok2 {
		return nil, newErr(kindMalformed, "token payload agent_id/capability must be strings")
	}
	cv, ok := intField(data, "capability_version", false)
	if !ok {
		return nil, newErr(kindMalformed, "token payload missing or invalid field: 'capability_version'")
	}
	exp, ok := intField(data, "exp", false)
	if !ok {
		return nil, newErr(kindMalformed, "token payload missing or invalid field: 'exp'")
	}
	bindings := map[string]any{}
	if raw, present := data["context_bindings"]; present && !pyFalsy(raw) {
		m, isMap := raw.(map[string]any)
		if !isMap {
			return nil, newErr(kindMalformed, "context_bindings must be a JSON object")
		}
		bindings = m
	}
	sum := sha256.Sum256(payload)
	return &CapabilityV2Token{
		AgentID:           agent,
		Capability:        capability,
		CapabilityVersion: int(cv),
		ContextBindings:   bindings,
		ExpiresAt:         exp,
		TokenID:           hex.EncodeToString(sum[:])[:16],
	}, nil
}

// pyFalsy mirrors Python truthiness for decoded JSON values: Python's
// `data.get("context_bindings") or {}` replaces null/false/0/""/[]/{} with {}.
func pyFalsy(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == ""
	case int64:
		return x == 0
	case float64:
		return x == 0
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return err == nil && f == 0
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// decodeObject parses payload as exactly one JSON object, keeping numbers
// precise: integers become int64 (or json.Number when beyond int64), other
// numbers float64. Trailing data is an error (as in Python's json.loads).
func decodeObject(payload []byte) (map[string]any, error) {
	v, err := decodeJSON(payload)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not an object")
	}
	return m, nil
}

func decodeJSON(payload []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	return convertNumbers(v)
}

func convertNumbers(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return i, nil
			}
			return x, nil // big integer: keep exact text
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, err
		}
		return f, nil
	case []any:
		for i := range x {
			c, err := convertNumbers(x[i])
			if err != nil {
				return nil, err
			}
			x[i] = c
		}
		return x, nil
	case map[string]any:
		for k := range x {
			c, err := convertNumbers(x[k])
			if err != nil {
				return nil, err
			}
			x[k] = c
		}
		return x, nil
	}
	return v, nil
}

// intField reads an integer claim. JSON numbers with an integral value are
// accepted (Python's int() would also accept strings and truncate floats;
// that leniency is deliberately not ported). When allowMissing is true an
// absent key reads as 0.
func intField(m map[string]any, key string, allowMissing bool) (int64, bool) {
	v, present := m[key]
	if !present {
		return 0, allowMissing
	}
	switch x := v.(type) {
	case int64:
		return x, true
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x), true
		}
	}
	return 0, false
}

// ---- context-binding value comparison ----

// normalize maps an arbitrary Go value onto the decoded-JSON value space
// (nil, bool, string, int64/json.Number/float64, []any, map[string]any) via a
// JSON round trip, so request contexts built from Go ints, structs or
// []string compare equal to the decoded token bindings.
func normalize(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeJSON(raw)
}

func numRat(v any) (*big.Rat, bool) {
	switch x := v.(type) {
	case int64:
		return new(big.Rat).SetInt64(x), true
	case json.Number:
		r, ok := new(big.Rat).SetString(string(x))
		return r, ok
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		return new(big.Rat).SetFloat64(x), true
	}
	return nil, false
}

func valuesEqual(a, b any) bool {
	if ra, ok := numRat(a); ok {
		rb, ok := numRat(b)
		return ok && ra.Cmp(rb) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool, string:
		return a == b
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !valuesEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !valuesEqual(xv, yv) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}
