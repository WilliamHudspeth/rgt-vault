// Package totp ports python/totp.py: RFC 6238 time-based one-time passwords
// (HMAC-SHA1/SHA256/SHA512, 30 s period, 6 digits by default) with a
// +/-1-step verification window, a replay-guarded verifier, base32 secret
// generation and otpauth:// provisioning URIs. Stdlib only.
//
// Differences from the Python code, all in the fail-closed direction
// (documented in the PR):
//   - codes must be ASCII digits (Python's str.isdigit also admits Unicode
//     digits, after which compare_digest raises TypeError);
//   - an empty decoded secret is rejected (Python happily HMACs with an empty
//     key); invalid digits/period/algorithm are errors instead of ValueError /
//     ZeroDivisionError / KeyError at call time;
//   - negative time-step counters (timestamps before 1970-01-01T00:00:30Z)
//     never match (Python raises struct.error).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default algorithm; HMAC-SHA1 is not weakened by SHA-1 collisions
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults, identical to python/totp.py.
const (
	DefaultDigits    = 6
	DefaultPeriod    = 30
	DefaultAlgorithm = "SHA1"
	DefaultWindow    = 1
	DefaultIssuer    = "rgt-vault"
	// DefaultSecretLength is the RFC 4226 recommended key size for SHA-1.
	DefaultSecretLength = 20
)

const maxDigits = 10

// params holds the per-call TOTP parameters.
type params struct {
	digits    int
	period    int
	algorithm string
	window    int
	issuer    string
	stateFile string
}

func defaults() params {
	return params{digits: DefaultDigits, period: DefaultPeriod, algorithm: DefaultAlgorithm, window: DefaultWindow, issuer: DefaultIssuer}
}

// Option customises Generate, Verify, NewReplayGuardedVerifier or
// ProvisioningURI.
type Option func(*params)

// WithDigits sets the code length (1..10, default 6).
func WithDigits(n int) Option { return func(p *params) { p.digits = n } }

// WithPeriod sets the time step in seconds (> 0, default 30).
func WithPeriod(seconds int) Option { return func(p *params) { p.period = seconds } }

// WithAlgorithm sets "SHA1" (default), "SHA256" or "SHA512".
func WithAlgorithm(name string) Option { return func(p *params) { p.algorithm = name } }

// WithWindow sets the number of +/- steps of clock skew tolerated when
// verifying (default 1; 0 disables skew tolerance).
func WithWindow(steps int) Option { return func(p *params) { p.window = steps } }

// WithIssuer sets the issuer label used by ProvisioningURI (default "rgt-vault").
func WithIssuer(issuer string) Option { return func(p *params) { p.issuer = issuer } }

// WithStateFile makes a ReplayGuardedVerifier remember the last accepted time
// step across restarts: the step is written (atomically, 0600) before a code
// is accepted, and loaded at construction, so a restart cannot reopen the
// replay window of a code that was already used (RGT-510). The file also
// carries a fingerprint of the secret: state of a replaced secret is ignored.
// If the state cannot be written, codes are refused (fail closed).
func WithStateFile(path string) Option { return func(p *params) { p.stateFile = path } }

func resolve(opts []Option) (params, error) {
	p := defaults()
	for _, o := range opts {
		o(&p)
	}
	if p.digits < 1 || p.digits > maxDigits {
		return p, fmt.Errorf("totp: digits must be between 1 and %d, got %d", maxDigits, p.digits)
	}
	if p.period < 1 {
		return p, fmt.Errorf("totp: period must be > 0, got %d", p.period)
	}
	if p.window < 0 {
		return p, fmt.Errorf("totp: window must be >= 0, got %d", p.window)
	}
	if _, ok := hashFor(p.algorithm); !ok {
		return p, fmt.Errorf("totp: unsupported algorithm %q (want SHA1, SHA256 or SHA512)", p.algorithm)
	}
	return p, nil
}

func hashFor(algorithm string) (func() hash.Hash, bool) {
	switch algorithm {
	case "SHA1":
		return sha1.New, true
	case "SHA256":
		return sha256.New, true
	case "SHA512":
		return sha512.New, true
	}
	return nil, false
}

var b32 = base32.StdEncoding

// GenerateSecret returns a fresh base32 TOTP secret (no padding) from
// length random bytes (use DefaultSecretLength).
func GenerateSecret(length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("totp: secret length must be > 0")
	}
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("totp: random secret: %w", err)
	}
	return strings.TrimRight(b32.EncodeToString(raw), "="), nil
}

// DecodeSecret decodes a base32 secret the way authenticator apps present
// it: surrounding whitespace and inner spaces ignored, case-insensitive,
// padding optional. Embedded newlines, other non-alphabet characters and an
// empty result are errors.
func DecodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("totp: invalid base32 secret")
	}
	if pad := (-len(s)) % 8; pad != 0 {
		s += strings.Repeat("=", (8+pad)%8)
	}
	key, err := b32.DecodeString(s)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("totp: invalid base32 secret")
	}
	return key, nil
}

// HOTP computes the RFC 4226 code for key at counter, zero-padded to digits.
func HOTP(key []byte, counter uint64, digits int, algorithm string) (string, error) {
	newHash, ok := hashFor(algorithm)
	if !ok {
		return "", fmt.Errorf("totp: unsupported algorithm %q", algorithm)
	}
	if digits < 1 || digits > maxDigits {
		return "", fmt.Errorf("totp: digits must be between 1 and %d", maxDigits)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(newHash, key)
	mac.Write(msg[:])
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(code)%mod), nil
}

// stepAt is int(timestamp // period): floor division, so times before the
// epoch round down.
func stepAt(t time.Time, period int) int64 {
	sec := t.Unix()
	p := int64(period)
	q := sec / p
	if sec%p != 0 && sec < 0 {
		q--
	}
	return q
}

// Generate returns the TOTP code for secret at t.
func Generate(secret string, t time.Time, opts ...Option) (string, error) {
	p, err := resolve(opts)
	if err != nil {
		return "", err
	}
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	step := stepAt(t, p.period)
	if step < 0 {
		return "", fmt.Errorf("totp: time before the epoch has no counter")
	}
	return HOTP(key, uint64(step), p.digits, p.algorithm)
}

// normalizeCode trims surrounding whitespace and requires ASCII digits.
func normalizeCode(code string) (string, bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return "", false
		}
	}
	return code, true
}

// Verify reports whether code is valid for secret at t, allowing +/-window
// steps of skew (default 1). Any malformed input returns false. The code is
// compared in constant time against every candidate in the window.
func Verify(secret, code string, t time.Time, opts ...Option) bool {
	code, ok := normalizeCode(code)
	if !ok {
		return false
	}
	p, err := resolve(opts)
	if err != nil {
		return false
	}
	key, err := DecodeSecret(secret)
	if err != nil {
		return false
	}
	step := stepAt(t, p.period)
	match := 0
	for off := -p.window; off <= p.window; off++ {
		c := step + int64(off)
		if c < 0 {
			continue
		}
		cand, err := HOTP(key, uint64(c), p.digits, p.algorithm)
		if err != nil {
			return false
		}
		match |= subtle.ConstantTimeCompare([]byte(cand), []byte(code))
	}
	return match == 1
}

// Result is the outcome of a replay-guarded verification. Telling a
// replayed code from a wrong one lets the caller audit and notify a reuse
// (ASVS 2.8.4 / RGT-312) instead of treating it as an ordinary typo.
type Result int

const (
	// ResultInvalid: the code is malformed or matches no step in the window.
	ResultInvalid Result = iota
	// ResultOK: the code was valid and its step is now consumed.
	ResultOK
	// ResultReplay: the code matches a step in the window that was already
	// consumed (or is older than the last accepted step): a reuse.
	ResultReplay
)

// String returns "ok", "invalid" or "replay".
func (r Result) String() string {
	switch r {
	case ResultOK:
		return "ok"
	case ResultReplay:
		return "replay"
	}
	return "invalid"
}

// ReplayGuardedVerifier verifies TOTP codes and accepts each time step at
// most once: it remembers the counter of the last accepted code and rejects
// any code whose counter is <= that, so one observed code cannot approve
// several requests inside the ~90 s validity window. State is in memory
// only (a restart forgets it, as in Python). Safe for concurrent use.
type ReplayGuardedVerifier struct {
	key []byte
	p   params

	mu          sync.Mutex
	lastCounter int64
}

// NewReplayGuardedVerifier validates the secret and options up front.
func NewReplayGuardedVerifier(secret string, opts ...Option) (*ReplayGuardedVerifier, error) {
	p, err := resolve(opts)
	if err != nil {
		return nil, err
	}
	key, err := DecodeSecret(secret)
	if err != nil {
		return nil, err
	}
	v := &ReplayGuardedVerifier{key: key, p: p, lastCounter: -1}
	if p.stateFile != "" {
		if err := v.loadState(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// keyFingerprint ties the state file to this secret.
func (v *ReplayGuardedVerifier) keyFingerprint() string {
	sum := sha256.Sum256(v.key)
	return hex.EncodeToString(sum[:4])
}

// loadState reads the persisted step (if any) and proves the state file is
// writable by writing it back.
func (v *ReplayGuardedVerifier) loadState() error {
	b, err := os.ReadFile(v.p.stateFile)
	switch {
	case err == nil:
		f := strings.Fields(string(b))
		if len(f) != 3 || f[0] != "v1" {
			return fmt.Errorf("totp: state file %s is corrupt (delete it only if you know no code was used in the last minute)", v.p.stateFile)
		}
		n, perr := strconv.ParseInt(f[2], 10, 64)
		if perr != nil {
			return fmt.Errorf("totp: state file %s is corrupt", v.p.stateFile)
		}
		if f[1] == v.keyFingerprint() {
			v.lastCounter = n
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("totp: read state file: %w", err)
	}
	return v.persist(v.lastCounter)
}

// persist writes the step atomically with mode 0600 (a private temp file in
// the same directory, then a rename).
func (v *ReplayGuardedVerifier) persist(counter int64) error {
	if v.p.stateFile == "" {
		return nil
	}
	dir := filepath.Dir(v.p.stateFile)
	tmp, err := os.CreateTemp(dir, ".totp-state-*")
	if err != nil {
		return fmt.Errorf("totp: write state file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, werr := fmt.Fprintf(tmp, "v1 %s %d\n", v.keyFingerprint(), counter)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("totp: write state file: %w", werr)
	}
	if err := os.Rename(name, v.p.stateFile); err != nil {
		return fmt.Errorf("totp: write state file: %w", err)
	}
	return nil
}

// Verify checks code against the current time. It has the signature the
// approval broker expects (func(code string) bool) as a method value.
func (v *ReplayGuardedVerifier) Verify(code string) bool { return v.VerifyAt(code, time.Now()) }

// VerifyAt checks code against time t and, on success, consumes its step.
func (v *ReplayGuardedVerifier) VerifyAt(code string, t time.Time) bool {
	return v.VerifyResultAt(code, t) == ResultOK
}

// VerifyResult is Verify returning the distinguishing Result.
func (v *ReplayGuardedVerifier) VerifyResult(code string) Result {
	return v.VerifyResultAt(code, time.Now())
}

// VerifyResultAt checks code against time t. On ResultOK the step is
// consumed; ResultReplay means the code is genuine for a step that was
// already used (or is older than the last accepted step) and is refused.
func (v *ReplayGuardedVerifier) VerifyResultAt(code string, t time.Time) Result {
	code, ok := normalizeCode(code)
	if !ok {
		return ResultInvalid
	}
	base := stepAt(t, v.p.period)
	v.mu.Lock()
	defer v.mu.Unlock()
	matched := int64(-1)
	replayed := false
	for off := -v.p.window; off <= v.p.window; off++ {
		c := base + int64(off)
		if c < 0 {
			continue
		}
		cand, err := HOTP(v.key, uint64(c), v.p.digits, v.p.algorithm)
		if err != nil {
			return ResultInvalid
		}
		// Every candidate is compared, in constant time, whether or not its
		// step was already consumed: no early exit on a secret-dependent
		// branch.
		if subtle.ConstantTimeCompare([]byte(cand), []byte(code)) != 1 {
			continue
		}
		if c <= v.lastCounter {
			replayed = true
		} else if matched < 0 {
			matched = c
		}
	}
	if matched < 0 {
		if replayed {
			return ResultReplay
		}
		return ResultInvalid
	}
	// Persist BEFORE accepting: if the step cannot be recorded, the code is
	// refused rather than risk a replay after a restart.
	if err := v.persist(matched); err != nil {
		log.Printf("ERROR: %v: refusing the TOTP code (fail closed)", err)
		return ResultInvalid
	}
	v.lastCounter = matched
	return ResultOK
}

// pyQuote mirrors urllib.parse.quote(s) with its default safe="/":
// letters, digits and "_.-~/" stay literal, every other UTF-8 byte becomes
// %XX with upper-case hex.
func pyQuote(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '-', c == '~', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// ProvisioningURI builds the otpauth:// URI for QR enrolment, byte-identical
// to python/totp.py:
//
//	otpauth://totp/<issuer>:<account>?secret=<secret>&issuer=<issuer>&algorithm=<alg>&digits=<n>&period=<s>
//
// issuer and account are percent-encoded like Python's urllib.parse.quote
// (the label colon stays literal); secret is inserted as given.
func ProvisioningURI(secret, accountName string, opts ...Option) (string, error) {
	p, err := resolve(opts)
	if err != nil {
		return "", err
	}
	iss := pyQuote(p.issuer)
	return "otpauth://totp/" + iss + ":" + pyQuote(accountName) +
		"?secret=" + secret + "&issuer=" + iss + "&algorithm=" + p.algorithm +
		"&digits=" + strconv.Itoa(p.digits) + "&period=" + strconv.Itoa(p.period), nil
}
