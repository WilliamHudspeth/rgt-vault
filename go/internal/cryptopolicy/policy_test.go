package cryptopolicy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/keychain"
)

func TestDefaultPolicyValidatesAndMatchesDefaults(t *testing.T) {
	p := Default()
	if err := p.Validate(); err != nil {
		t.Fatalf("Default().Validate(): %v", err)
	}
	if err := p.CheckKDFParams(kdf.DefaultParams()); err != nil {
		t.Fatalf("Default().CheckKDFParams(kdf.DefaultParams()): %v", err)
	}
	if p.MinArgon2MemoryKiB != kdf.DefaultMemoryCost ||
		p.MinArgon2TimeCost != kdf.DefaultTimeCost ||
		p.MinArgon2Parallelism != kdf.DefaultParallelism ||
		p.MinArgon2SaltBytes != keychain.SaltSize {
		t.Fatalf("Default() does not match kdf/keychain defaults: %+v", p)
	}
}

func TestParseEmptyAndStrengthenOnly(t *testing.T) {
	// Empty document returns defaults.
	p, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse(nil): %v", err)
	}
	if p != Default() {
		t.Fatalf("Parse(nil) = %+v, want Default()", p)
	}

	// Comment-only YAML returns defaults.
	p, err = Parse([]byte("# just a comment\n"))
	if err != nil {
		t.Fatalf("Parse(comment): %v", err)
	}
	if p != Default() {
		t.Fatalf("Parse(comment) = %+v, want Default()", p)
	}

	// Strengthening via YAML succeeds.
	yml := `
cipher: AES-256-GCM
kdf: argon2id
aes_key_bytes: 32
nonce_bytes: 12
tag_bytes: 16
min_argon2_memory_mb: 512
min_argon2_time_cost: 6
min_argon2_parallelism: 8
min_argon2_salt_bytes: 64
max_encryptions_per_dek: 10000000
max_bytes_per_dek: 1073741824
`
	p, err = Parse([]byte(yml))
	if err != nil {
		t.Fatalf("Parse(strengthened YAML): %v", err)
	}
	if p.MinArgon2MemoryKiB != 512*1024 || p.MinArgon2TimeCost != 6 || p.MinArgon2Parallelism != 8 ||
		p.MinArgon2SaltBytes != 64 || p.MaxEncryptionsPerDEK != 10_000_000 || p.MaxBytesPerDEK != 1<<30 {
		t.Fatalf("unexpected strengthened policy: %+v", p)
	}

	// Strengthening via JSON (valid YAML subset) with KiB succeeds.
	js := `{"min_argon2_memory_kib": 393216, "min_argon2_time_cost": 5}`
	p2, err := Parse([]byte(js))
	if err != nil {
		t.Fatalf("Parse(JSON): %v", err)
	}
	if p2.MinArgon2MemoryKiB != 393216 || p2.MinArgon2TimeCost != 5 || p2.MinArgon2Parallelism != DefaultMinArgon2Parallelism {
		t.Fatalf("unexpected JSON policy: %+v", p2)
	}
}

func TestParseRejectsWeakeningAndFormatChanges(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"lower memory KiB", "min_argon2_memory_kib: 65536\n", ErrPolicyWeakening},
		{"lower memory MB", "min_argon2_memory_mb: 128\n", ErrPolicyWeakening},
		{"lower time cost", "min_argon2_time_cost: 2\n", ErrPolicyWeakening},
		{"lower parallelism", "min_argon2_parallelism: 2\n", ErrPolicyWeakening},
		{"lower salt bytes", "min_argon2_salt_bytes: 16\n", ErrPolicyWeakening},
		{"higher max encryptions", "max_encryptions_per_dek: 200000000\n", ErrPolicyWeakening},
		{"higher max bytes", "max_bytes_per_dek: 1099511627776\n", ErrPolicyWeakening},
		{"change cipher", "cipher: AES-128-CBC\n", ErrFormatImmutable},
		{"change kdf", "kdf: pbkdf2\n", ErrFormatImmutable},
		{"change aes key size", "aes_key_bytes: 16\n", ErrFormatImmutable},
		{"change nonce size", "nonce_bytes: 16\n", ErrFormatImmutable},
		{"change tag size", "tag_bytes: 12\n", ErrFormatImmutable},
		{"both KiB and MB", "min_argon2_memory_kib: 262144\nmin_argon2_memory_mb: 256\n", ErrInvalidPolicy},
		{"unknown field", "allow_ecb: true\n", ErrInvalidPolicy},
		{"negative memory", "min_argon2_memory_kib: -1\n", ErrInvalidPolicy},
		{"zero memory MB", "min_argon2_memory_mb: 0\n", ErrInvalidPolicy},
		{"overflow memory MB", "min_argon2_memory_mb: 999999999\n", ErrInvalidPolicy},
		{"zero time cost", "min_argon2_time_cost: 0\n", ErrInvalidPolicy},
		{"overflow parallelism", "min_argon2_parallelism: 300\n", ErrInvalidPolicy},
		{"zero salt", "min_argon2_salt_bytes: 0\n", ErrInvalidPolicy},
		{"zero max encryptions", "max_encryptions_per_dek: 0\n", ErrInvalidPolicy},
		{"zero max bytes", "max_bytes_per_dek: 0\n", ErrInvalidPolicy},
		{"malformed yaml", ":\n\tbad: [", ErrInvalidPolicy},
		{"multi-doc yaml", "min_argon2_time_cost: 4\n---\nmin_argon2_time_cost: 5\n", ErrInvalidPolicy},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.input))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Parse(%q) err = %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateDirectStructEdges(t *testing.T) {
	p := Default()
	p.MaxEncryptionsPerDEK = 0
	if !errors.Is(p.Validate(), ErrInvalidPolicy) {
		t.Errorf("zero MaxEncryptionsPerDEK: got %v, want ErrInvalidPolicy", p.Validate())
	}
	p = Default()
	p.MaxBytesPerDEK = -5
	if !errors.Is(p.Validate(), ErrInvalidPolicy) {
		t.Errorf("negative MaxBytesPerDEK: got %v, want ErrInvalidPolicy", p.Validate())
	}
	// Memory < 8*parallelism cannot happen when memory >= 262144 and parallelism is uint8 (max 255 -> 8*255=2040),
	// so verify CheckKDFParams catches weak params directly.
	if err := Default().CheckKDFParams(kdf.Params{MemoryCost: 1024, TimeCost: 4, Parallelism: 4}); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("low memory CheckKDFParams: %v", err)
	}
	if err := Default().CheckKDFParams(kdf.Params{MemoryCost: 262144, TimeCost: 1, Parallelism: 4}); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("low time CheckKDFParams: %v", err)
	}
	if err := Default().CheckKDFParams(kdf.Params{MemoryCost: 262144, TimeCost: 4, Parallelism: 1}); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("low parallelism CheckKDFParams: %v", err)
	}
	// Invalid policy passed to CheckKDFParams/CheckDEKUsage/CheckKeychainFile fails closed.
	bad := Policy{}
	if err := bad.CheckKDFParams(kdf.DefaultParams()); !errors.Is(err, ErrFormatImmutable) {
		t.Errorf("bad policy CheckKDFParams: %v", err)
	}
	if err := bad.CheckDEKUsage(0, 0); !errors.Is(err, ErrFormatImmutable) {
		t.Errorf("bad policy CheckDEKUsage: %v", err)
	}
	if _, err := bad.CheckKeychainFile("nonexistent"); !errors.Is(err, ErrFormatImmutable) {
		t.Errorf("bad policy CheckKeychainFile: %v", err)
	}
}

func TestEffectiveKDFParamsStrengthensNeverWeakens(t *testing.T) {
	p, err := Parse([]byte("min_argon2_memory_kib: 524288\nmin_argon2_time_cost: 6\nmin_argon2_parallelism: 8\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Weak caller params are raised to policy floors.
	eff := p.EffectiveKDFParams(kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1})
	if eff.MemoryCost != 524288 || eff.TimeCost != 6 || eff.Parallelism != 8 {
		t.Fatalf("EffectiveKDFParams(weak) = %+v", eff)
	}

	// Stronger caller params are preserved.
	strong := kdf.Params{MemoryCost: 1048576, TimeCost: 8, Parallelism: 16}
	if got := p.EffectiveKDFParams(strong); got != strong {
		t.Fatalf("EffectiveKDFParams(strong) = %+v, want %+v", got, strong)
	}

	// Even a zero-value Policy clamps up to built-in defaults (never weakens).
	var zero Policy
	effZero := zero.EffectiveKDFParams(kdf.Params{MemoryCost: 1, TimeCost: 1, Parallelism: 1})
	if effZero != kdf.DefaultParams() {
		t.Fatalf("zero.EffectiveKDFParams = %+v, want %+v", effZero, kdf.DefaultParams())
	}
}

func TestCheckDEKUsage(t *testing.T) {
	p, err := Parse([]byte("max_encryptions_per_dek: 1000\nmax_bytes_per_dek: 4096\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckDEKUsage(999, 4095); err != nil {
		t.Fatalf("under limit: %v", err)
	}
	if err := p.CheckDEKUsage(1000, 0); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("at encryption limit: %v", err)
	}
	if err := p.CheckDEKUsage(0, 4096); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("at byte limit: %v", err)
	}
	if err := p.CheckDEKUsage(-1, 0); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("negative counter: %v", err)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crypto-policy.yaml")
	if err := os.WriteFile(path, []byte("min_argon2_time_cost: 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.MinArgon2TimeCost != 5 {
		t.Fatalf("MinArgon2TimeCost = %d, want 5", p.MinArgon2TimeCost)
	}

	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}

	bigPath := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(bigPath, bytes.Repeat([]byte("#"), maxPolicyFileBytes+10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(bigPath); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("oversized file: got %v, want ErrInvalidPolicy", err)
	}
}

func TestCheckKeychainFile(t *testing.T) {
	dir := t.TempDir()
	master := bytes.Repeat([]byte{0x42}, 32)

	// Compliant keychain using default params? Too slow in unit tests (256 MiB x 4),
	// so test both a real small-param keychain (non-compliant against default floors)
	// and a synthetic compliant keychain JSON matching schema v1.
	kcSmall := filepath.Join(dir, "small-keychain.json")
	mgr := keychain.New(kcSmall)
	defer mgr.Close()
	if _, err := mgr.Initialize(master, "11111111-2222-4333-8444-555555555555", 1, kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	audit, err := Default().CheckKeychainFile(kcSmall)
	if err != nil {
		t.Fatalf("CheckKeychainFile(small): %v", err)
	}
	if audit.Compliant {
		t.Fatalf("small-param keychain unexpectedly compliant: %+v", audit)
	}
	if audit.SaltBytes != 32 || audit.WrappedDEKBytes != 48 || audit.KeyEpoch != 1 {
		t.Fatalf("unexpected small keychain metadata: %+v", audit)
	}

	// Compliant v1 keychain matching default floors.
	kcOK := filepath.Join(dir, "ok-keychain.json")
	okJSON := `{
  "version": 1,
  "kdf": "argon2id",
  "argon2_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "argon2_memory_cost": 262144,
  "argon2_time_cost": 4,
  "argon2_parallelism": 4,
  "wrapped_dek": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "created_at": "2026-11-26T00:00:00+00:00",
  "key_epoch": 2
}`
	if err := os.WriteFile(kcOK, []byte(okJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	auditOK, err := Default().CheckKeychainFile(kcOK)
	if err != nil {
		t.Fatalf("CheckKeychainFile(ok): %v", err)
	}
	if !auditOK.Compliant || len(auditOK.Violations) != 0 {
		t.Fatalf("expected compliant keychain, got violations: %v", auditOK.Violations)
	}

	// Non-compliant keychain with bad version, bad kdf, short salt, bad wrapped_dek, epoch 0.
	kcBad := filepath.Join(dir, "bad-keychain.json")
	badJSON := `{
  "version": 99,
  "kdf": "pbkdf2",
  "argon2_salt": "AAAA",
  "argon2_memory_cost": 262144,
  "argon2_time_cost": 4,
  "argon2_parallelism": 4,
  "wrapped_dek": "not-base64!!!",
  "key_epoch": 0
}`
	if err := os.WriteFile(kcBad, []byte(badJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	auditBad, err := Default().CheckKeychainFile(kcBad)
	if err != nil {
		t.Fatalf("CheckKeychainFile(bad): %v", err)
	}
	if auditBad.Compliant || len(auditBad.Violations) < 4 {
		t.Fatalf("expected >=4 violations, got %+v", auditBad)
	}

	// Bad base64 salt & short wrapped_dek.
	kcBad2 := filepath.Join(dir, "bad2-keychain.json")
	if err := os.WriteFile(kcBad2, []byte(`{"version":1,"kdf":"argon2id","argon2_salt":"!!!","argon2_memory_cost":262144,"argon2_time_cost":4,"argon2_parallelism":4,"wrapped_dek":"AAAA","key_epoch":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	auditBad2, err := Default().CheckKeychainFile(kcBad2)
	if err != nil || auditBad2.Compliant || !strings.Contains(strings.Join(auditBad2.Violations, ";"), "argon2_salt") {
		t.Fatalf("expected bad salt/wrapped_dek violations: %+v, err=%v", auditBad2, err)
	}

	// Invalid JSON & missing file & oversized file.
	kcNotJSON := filepath.Join(dir, "not.json")
	_ = os.WriteFile(kcNotJSON, []byte("{bad"), 0o600)
	if _, err := Default().CheckKeychainFile(kcNotJSON); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("invalid JSON: %v", err)
	}
	if _, err := Default().CheckKeychainFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected missing file error")
	}
	kcHuge := filepath.Join(dir, "huge.json")
	_ = os.WriteFile(kcHuge, bytes.Repeat([]byte(" "), maxKeychainBytes+10), 0o600)
	if _, err := Default().CheckKeychainFile(kcHuge); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("oversized keychain: %v", err)
	}
}
