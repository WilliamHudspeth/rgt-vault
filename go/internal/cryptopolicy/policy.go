// Package cryptopolicy implements strengthen-only cryptographic policy floors
// for rgt-vault (RGT-220).
//
// A policy file (YAML or JSON) can raise minimum KDF costs (Argon2id memory,
// iterations, parallelism, salt length) and tighten DEK rotation ceilings
// (maximum encryptions or bytes per DEK), but can NEVER weaken the built-in
// defaults and can NEVER change on-disk cryptographic primitives or formats
// (AES-256-GCM, 32-byte key, 12-byte nonce, 16-byte tag, Argon2id; RGT-489).
package cryptopolicy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/keychain"
)

// Built-in cryptographic defaults and immutable format constants.
// These match go/internal/kdf, go/internal/crypto, go/internal/keychain,
// and go/internal/vault exactly.
const (
	RequiredCipher      = "AES-256-GCM"
	RequiredKDF         = keychain.KDFName // "argon2id"
	RequiredAESKeyBytes = keychain.DEKSize // 32 (256-bit)
	RequiredNonceBytes  = 12               // 96-bit per NIST SP 800-38D
	RequiredTagBytes    = 16               // 128-bit GCM authentication tag
	RequiredWrappedLen  = RequiredAESKeyBytes + RequiredTagBytes

	DefaultMinArgon2MemoryKiB   uint32 = kdf.DefaultMemoryCost  // 262144 KiB (256 MiB)
	DefaultMinArgon2TimeCost    uint32 = kdf.DefaultTimeCost    // 4
	DefaultMinArgon2Parallelism uint8  = kdf.DefaultParallelism // 4
	DefaultMinArgon2SaltBytes   int    = keychain.SaltSize      // 32

	// DefaultMaxEncryptionsPerDEK and DefaultMaxBytesPerDEK match
	// vault.DEKMaxEncryptions and vault.DEKMaxBytes (RGT-219 / NIST SP 800-38D).
	DefaultMaxEncryptionsPerDEK int64 = 100_000_000
	DefaultMaxBytesPerDEK       int64 = 512 * 1024 * 1024 * 1024 // 512 GiB

	maxPolicyFileBytes = 64 << 10 // 64 KiB
	maxKeychainBytes   = 1 << 20  // 1 MiB (matches keychain.maxFileSize)
)

// Sentinel errors returned by this package.
var (
	// ErrInvalidPolicy indicates malformed syntax, unknown fields, negative
	// values, or conflicting settings in a policy document.
	ErrInvalidPolicy = errors.New("cryptopolicy: invalid policy")

	// ErrPolicyWeakening indicates a policy attempted to lower a minimum floor
	// below the built-in default or raise a rotation ceiling above the default.
	ErrPolicyWeakening = errors.New("cryptopolicy: policy cannot weaken built-in defaults")

	// ErrFormatImmutable indicates a policy attempted to select a different
	// cipher, KDF, key size, nonce size, or tag size than the frozen format.
	ErrFormatImmutable = errors.New("cryptopolicy: on-disk cryptographic format cannot be changed")

	// ErrPolicyViolation indicates runtime parameters, DEK usage, or an
	// on-disk keychain.json file fail to satisfy the policy floors.
	ErrPolicyViolation = errors.New("cryptopolicy: policy violation")
)

// Policy defines strengthen-only cryptographic floors and rotation ceilings.
// Zero values are normalized to the built-in defaults by Parse / LoadFile.
type Policy struct {
	Cipher      string `yaml:"cipher,omitempty" json:"cipher,omitempty"`
	KDF         string `yaml:"kdf,omitempty" json:"kdf,omitempty"`
	AESKeyBytes int    `yaml:"aes_key_bytes,omitempty" json:"aes_key_bytes,omitempty"`
	NonceBytes  int    `yaml:"nonce_bytes,omitempty" json:"nonce_bytes,omitempty"`
	TagBytes    int    `yaml:"tag_bytes,omitempty" json:"tag_bytes,omitempty"`

	MinArgon2MemoryKiB   uint32 `yaml:"min_argon2_memory_kib" json:"min_argon2_memory_kib"`
	MinArgon2TimeCost    uint32 `yaml:"min_argon2_time_cost" json:"min_argon2_time_cost"`
	MinArgon2Parallelism uint8  `yaml:"min_argon2_parallelism" json:"min_argon2_parallelism"`
	MinArgon2SaltBytes   int    `yaml:"min_argon2_salt_bytes" json:"min_argon2_salt_bytes"`

	MaxEncryptionsPerDEK int64 `yaml:"max_encryptions_per_dek" json:"max_encryptions_per_dek"`
	MaxBytesPerDEK       int64 `yaml:"max_bytes_per_dek" json:"max_bytes_per_dek"`
}

// rawPolicy is the YAML/JSON decode shape. Signed integers catch negative
// numbers cleanly instead of failing with opaque unsigned overflow messages.
type rawPolicy struct {
	Cipher      string `yaml:"cipher"`
	KDF         string `yaml:"kdf"`
	AESKeyBytes *int   `yaml:"aes_key_bytes"`
	NonceBytes  *int   `yaml:"nonce_bytes"`
	TagBytes    *int   `yaml:"tag_bytes"`

	MinArgon2MemoryKiB   *int64 `yaml:"min_argon2_memory_kib"`
	MinArgon2MemoryMB    *int64 `yaml:"min_argon2_memory_mb"`
	MinArgon2TimeCost    *int64 `yaml:"min_argon2_time_cost"`
	MinArgon2Parallelism *int64 `yaml:"min_argon2_parallelism"`
	MinArgon2SaltBytes   *int   `yaml:"min_argon2_salt_bytes"`

	MaxEncryptionsPerDEK *int64 `yaml:"max_encryptions_per_dek"`
	MaxBytesPerDEK       *int64 `yaml:"max_bytes_per_dek"`
}

// Default returns the built-in strengthen-only baseline Policy.
func Default() Policy {
	return Policy{
		Cipher:               RequiredCipher,
		KDF:                  RequiredKDF,
		AESKeyBytes:          RequiredAESKeyBytes,
		NonceBytes:           RequiredNonceBytes,
		TagBytes:             RequiredTagBytes,
		MinArgon2MemoryKiB:   DefaultMinArgon2MemoryKiB,
		MinArgon2TimeCost:    DefaultMinArgon2TimeCost,
		MinArgon2Parallelism: DefaultMinArgon2Parallelism,
		MinArgon2SaltBytes:   DefaultMinArgon2SaltBytes,
		MaxEncryptionsPerDEK: DefaultMaxEncryptionsPerDEK,
		MaxBytesPerDEK:       DefaultMaxBytesPerDEK,
	}
}

// LoadFile reads and validates a YAML or JSON policy file (capped at 64 KiB).
func LoadFile(path string) (Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf("cryptopolicy: open %s: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxPolicyFileBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("cryptopolicy: read %s: %w", path, err)
	}
	if len(data) > maxPolicyFileBytes {
		return Policy{}, fmt.Errorf("%w: file exceeds %d bytes", ErrInvalidPolicy, maxPolicyFileBytes)
	}
	return Parse(data)
}

// Parse decodes a YAML or JSON policy document and enforces strengthen-only
// floors and immutable format invariants. An empty/whitespace-only document
// returns Default().
func Parse(data []byte) (Policy, error) {
	p := Default()
	if len(bytes.TrimSpace(data)) == 0 {
		return p, nil
	}

	var raw rawPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return p, nil
		}
		return Policy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Policy{}, fmt.Errorf("%w: multiple YAML documents are not allowed", ErrInvalidPolicy)
	}

	if raw.Cipher != "" {
		p.Cipher = raw.Cipher
	}
	if raw.KDF != "" {
		p.KDF = raw.KDF
	}
	if raw.AESKeyBytes != nil {
		p.AESKeyBytes = *raw.AESKeyBytes
	}
	if raw.NonceBytes != nil {
		p.NonceBytes = *raw.NonceBytes
	}
	if raw.TagBytes != nil {
		p.TagBytes = *raw.TagBytes
	}

	if raw.MinArgon2MemoryKiB != nil && raw.MinArgon2MemoryMB != nil {
		return Policy{}, fmt.Errorf("%w: specify either min_argon2_memory_kib or min_argon2_memory_mb, not both", ErrInvalidPolicy)
	}
	if raw.MinArgon2MemoryKiB != nil {
		v := *raw.MinArgon2MemoryKiB
		if v <= 0 || v > int64(^uint32(0)) {
			return Policy{}, fmt.Errorf("%w: min_argon2_memory_kib out of uint32 range", ErrInvalidPolicy)
		}
		p.MinArgon2MemoryKiB = uint32(v)
	}
	if raw.MinArgon2MemoryMB != nil {
		mb := *raw.MinArgon2MemoryMB
		if mb <= 0 || mb > int64(^uint32(0))/1024 {
			return Policy{}, fmt.Errorf("%w: min_argon2_memory_mb out of range", ErrInvalidPolicy)
		}
		p.MinArgon2MemoryKiB = uint32(mb * 1024)
	}
	if raw.MinArgon2TimeCost != nil {
		v := *raw.MinArgon2TimeCost
		if v <= 0 || v > int64(^uint32(0)) {
			return Policy{}, fmt.Errorf("%w: min_argon2_time_cost out of uint32 range", ErrInvalidPolicy)
		}
		p.MinArgon2TimeCost = uint32(v)
	}
	if raw.MinArgon2Parallelism != nil {
		v := *raw.MinArgon2Parallelism
		if v <= 0 || v > int64(^uint8(0)) {
			return Policy{}, fmt.Errorf("%w: min_argon2_parallelism out of uint8 range", ErrInvalidPolicy)
		}
		p.MinArgon2Parallelism = uint8(v)
	}
	if raw.MinArgon2SaltBytes != nil {
		if *raw.MinArgon2SaltBytes <= 0 {
			return Policy{}, fmt.Errorf("%w: min_argon2_salt_bytes must be positive", ErrInvalidPolicy)
		}
		p.MinArgon2SaltBytes = *raw.MinArgon2SaltBytes
	}
	if raw.MaxEncryptionsPerDEK != nil {
		if *raw.MaxEncryptionsPerDEK <= 0 {
			return Policy{}, fmt.Errorf("%w: max_encryptions_per_dek must be positive", ErrInvalidPolicy)
		}
		p.MaxEncryptionsPerDEK = *raw.MaxEncryptionsPerDEK
	}
	if raw.MaxBytesPerDEK != nil {
		if *raw.MaxBytesPerDEK <= 0 {
			return Policy{}, fmt.Errorf("%w: max_bytes_per_dek must be positive", ErrInvalidPolicy)
		}
		p.MaxBytesPerDEK = *raw.MaxBytesPerDEK
	}

	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate verifies that p does not alter immutable on-disk formats and does
// not weaken any built-in default floor or rotation ceiling.
func (p Policy) Validate() error {
	if p.Cipher != RequiredCipher {
		return fmt.Errorf("%w: cipher must be %q, got %q", ErrFormatImmutable, RequiredCipher, p.Cipher)
	}
	if p.KDF != RequiredKDF {
		return fmt.Errorf("%w: kdf must be %q, got %q", ErrFormatImmutable, RequiredKDF, p.KDF)
	}
	if p.AESKeyBytes != RequiredAESKeyBytes {
		return fmt.Errorf("%w: aes_key_bytes must be %d, got %d", ErrFormatImmutable, RequiredAESKeyBytes, p.AESKeyBytes)
	}
	if p.NonceBytes != RequiredNonceBytes {
		return fmt.Errorf("%w: nonce_bytes must be %d, got %d", ErrFormatImmutable, RequiredNonceBytes, p.NonceBytes)
	}
	if p.TagBytes != RequiredTagBytes {
		return fmt.Errorf("%w: tag_bytes must be %d, got %d", ErrFormatImmutable, RequiredTagBytes, p.TagBytes)
	}

	if p.MinArgon2MemoryKiB < DefaultMinArgon2MemoryKiB {
		return fmt.Errorf("%w: min_argon2_memory_kib %d < default %d", ErrPolicyWeakening, p.MinArgon2MemoryKiB, DefaultMinArgon2MemoryKiB)
	}
	if p.MinArgon2TimeCost < DefaultMinArgon2TimeCost {
		return fmt.Errorf("%w: min_argon2_time_cost %d < default %d", ErrPolicyWeakening, p.MinArgon2TimeCost, DefaultMinArgon2TimeCost)
	}
	if p.MinArgon2Parallelism < DefaultMinArgon2Parallelism {
		return fmt.Errorf("%w: min_argon2_parallelism %d < default %d", ErrPolicyWeakening, p.MinArgon2Parallelism, DefaultMinArgon2Parallelism)
	}
	if uint64(p.MinArgon2MemoryKiB) < 8*uint64(p.MinArgon2Parallelism) {
		return fmt.Errorf("%w: min_argon2_memory_kib (%d) must be >= 8*min_argon2_parallelism (%d)",
			ErrInvalidPolicy, p.MinArgon2MemoryKiB, 8*uint64(p.MinArgon2Parallelism))
	}
	if p.MinArgon2SaltBytes < DefaultMinArgon2SaltBytes {
		return fmt.Errorf("%w: min_argon2_salt_bytes %d < default %d", ErrPolicyWeakening, p.MinArgon2SaltBytes, DefaultMinArgon2SaltBytes)
	}
	if p.MaxEncryptionsPerDEK <= 0 {
		return fmt.Errorf("%w: max_encryptions_per_dek must be positive", ErrInvalidPolicy)
	}
	if p.MaxEncryptionsPerDEK > DefaultMaxEncryptionsPerDEK {
		return fmt.Errorf("%w: max_encryptions_per_dek %d > default %d", ErrPolicyWeakening, p.MaxEncryptionsPerDEK, DefaultMaxEncryptionsPerDEK)
	}
	if p.MaxBytesPerDEK <= 0 {
		return fmt.Errorf("%w: max_bytes_per_dek must be positive", ErrInvalidPolicy)
	}
	if p.MaxBytesPerDEK > DefaultMaxBytesPerDEK {
		return fmt.Errorf("%w: max_bytes_per_dek %d > default %d", ErrPolicyWeakening, p.MaxBytesPerDEK, DefaultMaxBytesPerDEK)
	}
	return nil
}

// CheckKDFParams returns ErrPolicyViolation if params fall below any floor
// required by p or violate Argon2id's memory >= 8*parallelism constraint.
func (p Policy) CheckKDFParams(params kdf.Params) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if params.MemoryCost < p.MinArgon2MemoryKiB {
		return fmt.Errorf("%w: argon2 memory_cost %d KiB < policy floor %d KiB", ErrPolicyViolation, params.MemoryCost, p.MinArgon2MemoryKiB)
	}
	if params.TimeCost < p.MinArgon2TimeCost {
		return fmt.Errorf("%w: argon2 time_cost %d < policy floor %d", ErrPolicyViolation, params.TimeCost, p.MinArgon2TimeCost)
	}
	if params.Parallelism < p.MinArgon2Parallelism {
		return fmt.Errorf("%w: argon2 parallelism %d < policy floor %d", ErrPolicyViolation, params.Parallelism, p.MinArgon2Parallelism)
	}
	if uint64(params.MemoryCost) < 8*uint64(params.Parallelism) {
		return fmt.Errorf("%w: argon2 memory_cost %d KiB < 8*parallelism (%d)", ErrPolicyViolation, params.MemoryCost, 8*uint64(params.Parallelism))
	}
	return nil
}

// EffectiveKDFParams returns params raised to at least the floors in p (and
// at least the built-in defaults). It can only strengthen parameters, never
// weaken them.
func (p Policy) EffectiveKDFParams(params kdf.Params) kdf.Params {
	out := params
	minMem := max(p.MinArgon2MemoryKiB, DefaultMinArgon2MemoryKiB)
	minTime := max(p.MinArgon2TimeCost, DefaultMinArgon2TimeCost)
	minPar := max(p.MinArgon2Parallelism, DefaultMinArgon2Parallelism)

	if out.MemoryCost < minMem {
		out.MemoryCost = minMem
	}
	if out.TimeCost < minTime {
		out.TimeCost = minTime
	}
	if out.Parallelism < minPar {
		out.Parallelism = minPar
	}
	if uint64(out.MemoryCost) < 8*uint64(out.Parallelism) {
		out.MemoryCost = 8 * uint32(out.Parallelism)
	}
	return out
}

// CheckDEKUsage verifies that current DEK usage is strictly below policy
// ceilings; reaching or exceeding either ceiling means rotation is required.
func (p Policy) CheckDEKUsage(encryptions, bytesEncrypted int64) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if encryptions < 0 || bytesEncrypted < 0 {
		return fmt.Errorf("%w: negative DEK usage counter", ErrPolicyViolation)
	}
	if encryptions >= p.MaxEncryptionsPerDEK {
		return fmt.Errorf("%w: DEK encryption count %d >= policy limit %d", ErrPolicyViolation, encryptions, p.MaxEncryptionsPerDEK)
	}
	if bytesEncrypted >= p.MaxBytesPerDEK {
		return fmt.Errorf("%w: DEK encrypted bytes %d >= policy limit %d", ErrPolicyViolation, bytesEncrypted, p.MaxBytesPerDEK)
	}
	return nil
}

// KeychainAudit summarizes an on-disk keychain.json file checked against a
// Policy without unwrapping or needing the master secret.
type KeychainAudit struct {
	Path            string     `json:"path"`
	SchemaVersion   int        `json:"schema_version"`
	KDF             string     `json:"kdf"`
	Params          kdf.Params `json:"argon2_params"`
	SaltBytes       int        `json:"salt_bytes"`
	WrappedDEKBytes int        `json:"wrapped_dek_bytes"`
	KeyEpoch        int64      `json:"key_epoch"`
	Compliant       bool       `json:"compliant"`
	Violations      []string   `json:"violations,omitempty"`
}

type keychainInspection struct {
	Version           int    `json:"version"`
	KDF               string `json:"kdf"`
	Argon2Salt        string `json:"argon2_salt"`
	Argon2MemoryCost  uint32 `json:"argon2_memory_cost"`
	Argon2TimeCost    uint32 `json:"argon2_time_cost"`
	Argon2Parallelism uint8  `json:"argon2_parallelism"`
	WrappedDEK        string `json:"wrapped_dek"`
	KeyEpoch          int64  `json:"key_epoch"`
}

// CheckKeychainFile inspects a keychain.json file's metadata and evaluates it
// against p. It never reads or requires the master secret.
func (p Policy) CheckKeychainFile(path string) (*KeychainAudit, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cryptopolicy: open keychain %s: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeychainBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cryptopolicy: read keychain %s: %w", path, err)
	}
	if len(raw) > maxKeychainBytes {
		return nil, fmt.Errorf("%w: keychain file exceeds %d bytes", ErrPolicyViolation, maxKeychainBytes)
	}

	var kf keychainInspection
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("%w: parse keychain JSON: %v", ErrPolicyViolation, err)
	}

	audit := &KeychainAudit{
		Path:          path,
		SchemaVersion: kf.Version,
		KDF:           kf.KDF,
		Params: kdf.Params{
			MemoryCost:  kf.Argon2MemoryCost,
			TimeCost:    kf.Argon2TimeCost,
			Parallelism: kf.Argon2Parallelism,
		},
		KeyEpoch: kf.KeyEpoch,
	}

	if kf.Version != keychain.SchemaVersion {
		audit.Violations = append(audit.Violations, fmt.Sprintf("schema version %d != expected %d", kf.Version, keychain.SchemaVersion))
	}
	if kf.KDF != RequiredKDF {
		audit.Violations = append(audit.Violations, fmt.Sprintf("kdf %q != required %q", kf.KDF, RequiredKDF))
	}

	salt, err := base64.StdEncoding.DecodeString(kf.Argon2Salt)
	if err != nil {
		audit.Violations = append(audit.Violations, "argon2_salt is not valid base64")
	} else {
		audit.SaltBytes = len(salt)
		if len(salt) < p.MinArgon2SaltBytes {
			audit.Violations = append(audit.Violations, fmt.Sprintf("argon2_salt length %d bytes < policy floor %d bytes", len(salt), p.MinArgon2SaltBytes))
		}
	}

	wrapped, err := base64.StdEncoding.DecodeString(kf.WrappedDEK)
	if err != nil {
		audit.Violations = append(audit.Violations, "wrapped_dek is not valid base64")
	} else {
		audit.WrappedDEKBytes = len(wrapped)
		if len(wrapped) != RequiredWrappedLen {
			audit.Violations = append(audit.Violations, fmt.Sprintf("wrapped_dek length %d bytes != expected %d bytes (32B DEK + 16B GCM tag)", len(wrapped), RequiredWrappedLen))
		}
	}

	if err := p.CheckKDFParams(audit.Params); err != nil {
		audit.Violations = append(audit.Violations, err.Error())
	}
	if kf.KeyEpoch < 1 {
		audit.Violations = append(audit.Violations, fmt.Sprintf("key_epoch %d must be >= 1", kf.KeyEpoch))
	}

	audit.Compliant = len(audit.Violations) == 0
	return audit, nil
}
