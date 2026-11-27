package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/store"
)

// testParams are cheap Argon2 parameters for keychains created in tests.
var testParams = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

const allowAllPolicy = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: deny
    agent: intruder
    action: read
`

const pyvaultDir = "../../testdata/pyvault"

type manifestSecret struct {
	ID                     int64   `json:"id"`
	Namespace              string  `json:"namespace"`
	Name                   string  `json:"name"`
	Version                int64   `json:"version"`
	Status                 string  `json:"status"`
	DEKVersion             int64   `json:"dek_version"`
	Note                   string  `json:"note"`
	Require2FA             bool    `json:"require_2fa"`
	Honeytoken             bool    `json:"honeytoken"`
	Checksum               string  `json:"checksum"`
	Fingerprint            string  `json:"fingerprint"`
	AAD                    string  `json:"aad"`
	DecryptsWithCurrentDEK bool    `json:"decrypts_with_current_dek"`
	ReadLatest             *string `json:"read_latest"`
	ReadByVersion          string  `json:"read_by_version"`
	PlaintextSHA256        string  `json:"plaintext_sha256"`
}

type manifest struct {
	VaultID    string            `json:"vault_id"`
	KeyEpoch   int64             `json:"key_epoch"`
	PolicyHash string            `json:"policy_hash"`
	Metadata   map[string]string `json:"metadata"`
	RowCounts  map[string]int64  `json:"row_counts"`
	Secrets    []manifestSecret  `json:"secrets"`
	Audit      struct {
		Verify    bool           `json:"verify_audit_chain"`
		FirstHash string         `json:"first_entry_hash"`
		LastHash  string         `json:"last_entry_hash"`
		Actions   map[string]int `json:"actions"`
	} `json:"audit"`
	Export struct {
		SHA256 string `json:"sha256"`
	} `json:"export"`
}

func loadManifest(t *testing.T, fixture string) manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pyvaultDir, fixture, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// copyFixture copies a G0 vault directory into a temp dir (opening a vault
// writes audit rows and WAL files) and returns the db path and a file
// provider reading the fixture's master.bin copy.
func copyFixture(t *testing.T, fixture string) (dbPath string, prov providerstest.File) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), fixture)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"vault.db", "keychain.json", "master.bin", "policy.yaml", "export.b64"} {
		copyFile(t, filepath.Join(pyvaultDir, fixture, f), filepath.Join(dir, f))
	}
	return filepath.Join(dir, "vault.db"), providerstest.File{Path: filepath.Join(dir, "master.bin")}
}

func fixturePolicy(t *testing.T, fixture string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pyvaultDir, fixture, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func openT(t *testing.T, cfg Config) *Vault {
	t.Helper()
	if cfg.KDFParams == (kdf.Params{}) {
		cfg.KDFParams = testParams
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 1_000_000
	}
	v, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// newVault opens a fresh vault in a temp dir with an in-memory provider.
func newVault(t *testing.T, policyYAML string) (*Vault, *providerstest.Memory) {
	t.Helper()
	prov := providerstest.NewMemory()
	v := openT(t, Config{
		DBPath:     filepath.Join(t.TempDir(), "v", "vault.db"),
		Provider:   prov,
		PolicyYAML: policyYAML,
	})
	return v, prov
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// readVersion leases one version and returns sha256(plaintext) or an error
// label in Python's exception names.
func readVersion(t *testing.T, v *Vault, ns, name string, version int64) string {
	t.Helper()
	var got string
	err := v.Lease(context.Background(), LeaseRequest{
		Name: name, Namespace: ns, Agent: "ci-bot", Purpose: "compat-test", Version: version,
	}, func(b []byte) error {
		got = sha(b)
		return nil
	})
	return errLabel(err, got)
}

func errLabel(err error, ok string) string {
	switch {
	case err == nil:
		return ok
	case errors.Is(err, ErrHoneytoken):
		return "PermissionError"
	case errors.Is(err, ErrNotFound):
		return "SecretNotFoundError"
	case errors.Is(err, ErrPolicyDenied):
		return "PolicyDeniedError"
	case strings.Contains(err.Error(), "decryption failed"):
		return "DecryptionError"
	default:
		return "error: " + err.Error()
	}
}

func auditRows(t *testing.T, v *Vault) []store.AuditRow {
	t.Helper()
	rows, err := v.store.IterAuditLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func lastAudit(t *testing.T, v *Vault, n int) []store.AuditRow {
	t.Helper()
	rows := auditRows(t, v)
	if len(rows) < n {
		t.Fatalf("want >= %d audit rows, have %d", n, len(rows))
	}
	return rows[len(rows)-n:]
}

func mustVerify(t *testing.T, v *Vault) {
	t.Helper()
	ok, err := v.VerifyAuditChain(context.Background())
	if err != nil || !ok {
		t.Fatalf("VerifyAuditChain = %v, %v", ok, err)
	}
}

func set(t *testing.T, v *Vault, ns, name, value string) {
	t.Helper()
	if err := v.SetSecret(context.Background(), SetSecretRequest{
		Name: name, Namespace: ns, Agent: SystemAgent, Value: []byte(value),
	}); err != nil {
		t.Fatalf("SetSecret %s/%s: %v", ns, name, err)
	}
}

func get(t *testing.T, v *Vault, ns, name string, version int64) (string, error) {
	t.Helper()
	var got string
	err := v.Lease(context.Background(), LeaseRequest{
		Name: name, Namespace: ns, Agent: "ci-bot", Purpose: "test", Version: version,
	}, func(b []byte) error {
		got = string(b)
		return nil
	})
	return got, err
}

func fileProv(path string) providerstest.File { return providerstest.File{Path: path} }

func memProv() *providerstest.Memory { return providerstest.NewMemory() }
