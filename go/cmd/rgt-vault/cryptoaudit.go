package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/cryptopolicy"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/keychain"
	"rgt-vault-server/internal/providers"
	"rgt-vault-server/internal/totp"
	"rgt-vault-server/internal/vault"
)

// Test seams for crypto-audit failure-path coverage.
var (
	cryptoAuditSelfTest = keychain.SelfTest
	cryptoAuditRandRead = rand.Read
)

// cryptoAuditReport is the structured output of `rgt-vault crypto-audit`.
type cryptoAuditReport struct {
	OK           bool                        `json:"ok"`
	Cipher       cipherAuditInfo             `json:"cipher"`
	KDF          kdfAuditInfo                `json:"kdf"`
	KeySizes     keySizesAuditInfo           `json:"key_sizes_bytes"`
	DEKRotation  dekRotationAuditInfo        `json:"dek_rotation_limits"`
	CSPRNG       csprngAuditInfo             `json:"csprng"`
	SelfTest     selfTestAuditInfo           `json:"selftest"`
	PolicySource string                      `json:"policy_source"`
	Keychain     *cryptopolicy.KeychainAudit `json:"keychain,omitempty"`
}

type cipherAuditInfo struct {
	Algorithm  string `json:"algorithm"`
	KeyBytes   int    `json:"key_bytes"`
	KeyBits    int    `json:"key_bits"`
	NonceBytes int    `json:"nonce_bytes"`
	NonceBits  int    `json:"nonce_bits"`
	TagBytes   int    `json:"tag_bytes"`
	TagBits    int    `json:"tag_bits"`
	SecretAAD  string `json:"secret_aad_format"`
	WrapAAD    string `json:"wrap_aad_format"`
}

type kdfAuditInfo struct {
	Pipeline            string     `json:"pipeline"`
	DefaultParams       kdf.Params `json:"default_params"`
	PolicyMinMemoryKiB  uint32     `json:"policy_min_memory_kib"`
	PolicyMinTimeCost   uint32     `json:"policy_min_time_cost"`
	PolicyMinParallel   uint8      `json:"policy_min_parallelism"`
	PolicyMinSaltBytes  int        `json:"policy_min_salt_bytes"`
	DefaultSaltBytes    int        `json:"default_salt_bytes"`
	HKDFStage2Algorithm string     `json:"hkdf_stage2"`
	HKDFStage3Algorithm string     `json:"hkdf_stage3"`
}

type keySizesAuditInfo struct {
	MasterSecretBytes int `json:"master_secret"`
	DEKBytes          int `json:"dek"`
	KEKBytes          int `json:"kek"`
	BearerTokenBytes  int `json:"bearer_token"`
	CapTokenMinBytes  int `json:"capability_token_hmac_min"`
	TOTPSecretDefault int `json:"totp_secret_default"`
}

type dekRotationAuditInfo struct {
	DefaultMaxEncryptions int64 `json:"default_max_encryptions"`
	DefaultMaxBytes       int64 `json:"default_max_bytes"`
	PolicyMaxEncryptions  int64 `json:"policy_max_encryptions"`
	PolicyMaxBytes        int64 `json:"policy_max_bytes"`
}

type csprngAuditInfo struct {
	Source string `json:"source"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

type selfTestAuditInfo struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func newCryptoAuditCmd(stdout io.Writer) *cobra.Command {
	var (
		jsonOut      bool
		policyPath   string
		keychainPath string
	)
	cmd := &cobra.Command{
		Use:   "crypto-audit",
		Short: "Verify active cryptographic parameters and run the crypto self-test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCryptoAudit(policyPath, keychainPath, jsonOut, stdout)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit audit report as JSON")
	cmd.Flags().StringVar(&policyPath, "policy", "", "optional strengthen-only crypto policy YAML/JSON file")
	cmd.Flags().StringVar(&keychainPath, "keychain", "", "optional keychain.json file to verify against policy floors")
	return cmd
}

func runCryptoAudit(policyPath, keychainPath string, jsonOut bool, out io.Writer) error {
	pol := cryptopolicy.Default()
	policySource := "built-in defaults"
	if policyPath != "" {
		loaded, err := cryptopolicy.LoadFile(policyPath)
		if err != nil {
			return fmt.Errorf("crypto-audit: load policy: %w", err)
		}
		pol = loaded
		policySource = policyPath
	}

	// Probe OS CSPRNG via crypto/rand.
	csprng := csprngAuditInfo{Source: "crypto/rand (OS CSPRNG)", OK: true}
	probe := make([]byte, 32)
	defer keychain.Wipe(probe)
	if n, err := cryptoAuditRandRead(probe); err != nil || n != len(probe) {
		csprng.OK = false
		if err != nil {
			csprng.Error = err.Error()
		} else {
			csprng.Error = fmt.Sprintf("short read: %d/%d bytes", n, len(probe))
		}
	} else {
		allZero := true
		for _, b := range probe {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			csprng.OK = false
			csprng.Error = "CSPRNG probe returned 32 zero bytes"
		}
	}

	// Run keychain cryptographic self-test (Argon2id + HKDF + AES-256-GCM + AAD + Python KAT).
	st := selfTestAuditInfo{OK: true}
	if err := cryptoAuditSelfTest(); err != nil {
		st.OK = false
		st.Error = err.Error()
	}

	var kcAudit *cryptopolicy.KeychainAudit
	if keychainPath != "" {
		ka, err := pol.CheckKeychainFile(keychainPath)
		if err != nil {
			return fmt.Errorf("crypto-audit: inspect keychain: %w", err)
		}
		kcAudit = ka
	}

	report := cryptoAuditReport{
		OK: csprng.OK && st.OK && (kcAudit == nil || kcAudit.Compliant),
		Cipher: cipherAuditInfo{
			Algorithm:  cryptopolicy.RequiredCipher,
			KeyBytes:   cryptopolicy.RequiredAESKeyBytes,
			KeyBits:    cryptopolicy.RequiredAESKeyBytes * 8,
			NonceBytes: cryptopolicy.RequiredNonceBytes,
			NonceBits:  cryptopolicy.RequiredNonceBytes * 8,
			TagBytes:   cryptopolicy.RequiredTagBytes,
			TagBits:    cryptopolicy.RequiredTagBytes * 8,
			SecretAAD:  "vault_id:namespace:name",
			WrapAAD:    "vault_id:epoch",
		},
		KDF: kdfAuditInfo{
			Pipeline:            "Argon2id -> HKDF-SHA512 -> HKDF-SHA256 (nonce expansion)",
			DefaultParams:       kdf.DefaultParams(),
			PolicyMinMemoryKiB:  pol.MinArgon2MemoryKiB,
			PolicyMinTimeCost:   pol.MinArgon2TimeCost,
			PolicyMinParallel:   pol.MinArgon2Parallelism,
			PolicyMinSaltBytes:  pol.MinArgon2SaltBytes,
			DefaultSaltBytes:    keychain.SaltSize,
			HKDFStage2Algorithm: "HKDF-SHA512",
			HKDFStage3Algorithm: "HKDF-SHA256",
		},
		KeySizes: keySizesAuditInfo{
			MasterSecretBytes: providers.MasterSecretSize,
			DEKBytes:          keychain.DEKSize,
			KEKBytes:          cryptopolicy.RequiredAESKeyBytes,
			BearerTokenBytes:  32,
			CapTokenMinBytes:  captoken.MinSecretLen,
			TOTPSecretDefault: totp.DefaultSecretLength,
		},
		DEKRotation: dekRotationAuditInfo{
			DefaultMaxEncryptions: vault.DEKMaxEncryptions,
			DefaultMaxBytes:       vault.DEKMaxBytes,
			PolicyMaxEncryptions:  pol.MaxEncryptionsPerDEK,
			PolicyMaxBytes:        pol.MaxBytesPerDEK,
		},
		CSPRNG:       csprng,
		SelfTest:     st,
		PolicySource: policySource,
		Keychain:     kcAudit,
	}

	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printCryptoAuditText(out, report)
	}

	if !report.OK {
		return fmt.Errorf("crypto-audit failed")
	}
	return nil
}

func printCryptoAuditText(out io.Writer, r cryptoAuditReport) {
	status := func(ok bool) string {
		if ok {
			return "PASS"
		}
		return "FAIL"
	}

	fmt.Fprintln(out, "rgt-vault Cryptographic Audit (Go)")
	fmt.Fprintf(out, "  Cipher:           %s (%d-bit key, %d-bit nonce, %d-bit tag)\n",
		r.Cipher.Algorithm, r.Cipher.KeyBits, r.Cipher.NonceBits, r.Cipher.TagBits)
	fmt.Fprintf(out, "  AAD Bindings:     secret=%s | wrap=%s\n", r.Cipher.SecretAAD, r.Cipher.WrapAAD)
	fmt.Fprintf(out, "  KDF Pipeline:     %s\n", r.KDF.Pipeline)
	fmt.Fprintf(out, "  Argon2id Default: memory=%d KiB (%d MiB), time=%d, parallelism=%d, salt=%d bytes\n",
		r.KDF.DefaultParams.MemoryCost, r.KDF.DefaultParams.MemoryCost/1024,
		r.KDF.DefaultParams.TimeCost, r.KDF.DefaultParams.Parallelism, r.KDF.DefaultSaltBytes)
	fmt.Fprintf(out, "  Policy Source:    %s\n", r.PolicySource)
	fmt.Fprintf(out, "  Policy Floors:    memory>=%d KiB, time>=%d, parallelism>=%d, salt>=%d bytes\n",
		r.KDF.PolicyMinMemoryKiB, r.KDF.PolicyMinTimeCost, r.KDF.PolicyMinParallel, r.KDF.PolicyMinSaltBytes)
	fmt.Fprintf(out, "  Key Sizes:        master=%d B, DEK=%d B, KEK=%d B, bearer=%d B, captoken>=%d B, TOTP=%d B\n",
		r.KeySizes.MasterSecretBytes, r.KeySizes.DEKBytes, r.KeySizes.KEKBytes,
		r.KeySizes.BearerTokenBytes, r.KeySizes.CapTokenMinBytes, r.KeySizes.TOTPSecretDefault)
	fmt.Fprintf(out, "  DEK Rotation:     max_encryptions=%d, max_bytes=%d (%s)\n",
		r.DEKRotation.PolicyMaxEncryptions, r.DEKRotation.PolicyMaxBytes, formatByteSize(r.DEKRotation.PolicyMaxBytes))
	if r.CSPRNG.OK {
		fmt.Fprintf(out, "  CSPRNG:           %s — PASS\n", r.CSPRNG.Source)
	} else {
		fmt.Fprintf(out, "  CSPRNG:           %s — FAIL (%s)\n", r.CSPRNG.Source, r.CSPRNG.Error)
	}
	if r.SelfTest.OK {
		fmt.Fprintf(out, "  SelfTest (KAT):   PASS\n")
	} else {
		fmt.Fprintf(out, "  SelfTest (KAT):   FAIL (%s)\n", r.SelfTest.Error)
	}
	if r.Keychain != nil {
		fmt.Fprintf(out, "  Keychain File:    %s (epoch=%d, memory=%d KiB, time=%d, parallelism=%d, salt=%d B) — %s\n",
			r.Keychain.Path, r.Keychain.KeyEpoch, r.Keychain.Params.MemoryCost, r.Keychain.Params.TimeCost,
			r.Keychain.Params.Parallelism, r.Keychain.SaltBytes, status(r.Keychain.Compliant))
		for _, v := range r.Keychain.Violations {
			fmt.Fprintf(out, "    violation: %s\n", v)
		}
	}
	fmt.Fprintf(out, "  Overall:          %s\n", status(r.OK))
}

func formatByteSize(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n/(1<<30))
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n/(1<<20))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
