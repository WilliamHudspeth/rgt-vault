package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/vault"
)

// export -> wipe -> import round trip on a Go vault.
func TestExportImportRoundTrip(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "a", "alpha")
	e.seed("prod", "b", "beta-ünï🔐")
	out := filepath.Join(e.dir, "backup.b64")

	stdout := e.mustCLI("", "export", "--out", out)
	if stdout != "" {
		t.Errorf("export printed %q", stdout)
	}
	assertMode0600(t, out)
	// An existing file is not overwritten without --force.
	if code, _, stderr := e.cli("", "export", "--out", out); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Errorf("overwrite: exit %d err %q", code, stderr)
	}
	e.mustCLI("", "export", "--out", out, "--force")
	// stdout form
	exp := e.mustCLI("", "export")
	if !bytes.Equal(bytes.TrimSpace([]byte(exp)), bytes.TrimSpace(mustRead(t, out))) {
		t.Error("stdout export differs from the --out file")
	}

	// Lose a secret, then import brings it back (and the audit log with it).
	stack := e.open()
	if err := stack.Vault.RevokeSecret(context.Background(), "prod", "a", "system"); err != nil {
		t.Fatal(err)
	}
	_ = stack.Close()
	if code, _, _ := e.cli("", "get", "a", "--namespace", "prod", "--purpose", "t", "--offline"); code != 1 {
		t.Fatal("revoked secret still readable")
	}
	if code, _, stderr := e.cli("", "import", "--in", out); code != 1 || !strings.Contains(stderr, "--yes") {
		t.Errorf("import without --yes: exit %d err %q", code, stderr)
	}
	if got := e.mustCLI("", "import", "--in", out, "--yes"); got != "Import complete.\n" {
		t.Errorf("import output %q", got)
	}
	if got := e.mustCLI("", "get", "a", "--namespace", "prod", "--purpose", "t", "--offline"); got != "alpha\n" {
		t.Errorf("restored a = %q", got)
	}
	if got := e.mustCLI("", "get", "b", "--namespace", "prod", "--purpose", "t", "--offline"); got != "beta-ünï🔐\n" {
		t.Errorf("restored b = %q", got)
	}
	if got := e.mustCLI("", "verify-audit", "--offline"); got != "OK\n" {
		t.Errorf("chain after import: %q", got)
	}
	// stdin form
	if got := e.mustCLI(exp, "import", "--yes"); got != "Import complete.\n" {
		t.Errorf("stdin import %q", got)
	}
}

func TestImportRefusals(t *testing.T) {
	other := newVaultEnv(t) // its export, taken before the provider seam moves on
	other.seed("prod", "x", "other")
	otherExport := other.mustCLI("", "export")
	e := newVaultEnv(t)
	e.seed("prod", "a", "alpha")
	bad := filepath.Join(e.dir, "bad.b64")
	_ = os.WriteFile(bad, []byte("%%% not base64 json %%%"), 0o600)
	if code, _, stderr := e.cli("", "import", "--yes", "--in", bad); code != 1 || !strings.Contains(stderr, "Invalid import payload") {
		t.Errorf("garbage: exit %d err %q", code, stderr)
	}
	if code, _, _ := e.cli("", "import", "--yes", "--in", filepath.Join(e.dir, "missing")); code != 1 {
		t.Errorf("missing file: exit %d", code)
	}
	// Another vault's export is refused (vault_id check).
	if code, _, stderr := e.cli(otherExport, "import", "--yes"); code != 1 || !strings.Contains(stderr, "belongs to vault") {
		t.Errorf("other vault: exit %d err %q", code, stderr)
	}
	// Oversized payloads are rejected without being buffered whole.
	big := strings.NewReader(strings.Repeat("A", vault.MaxImportBytes+10))
	if _, err := readLimited(big); err == nil || !strings.Contains(err.Error(), "maximum allowed size") {
		t.Errorf("oversized: %v", err)
	}
	// Exporting or importing a vault that does not exist does not create one.
	if code, _, stderr := runCLI(t, "", "--db", filepath.Join(t.TempDir(), "n", "v.db"), "export"); code != 1 || !strings.Contains(stderr, "no vault at") {
		t.Errorf("export without vault: exit %d err %q", code, stderr)
	}
}

// The Python-generated fixtures: Go's export of an untouched fixture vault
// is byte-identical to Python's export_vault, and Python's export imports.
func TestExportImportPythonFixtures(t *testing.T) {
	isolateEnv(t)
	for _, fx := range []string{"small", "default", "epoch1"} {
		t.Run(fx, func(t *testing.T) {
			dir := copyTree(t, filepath.Join(pyvaultDir, fx))
			master := mustRead(t, filepath.Join(dir, "master.bin"))
			useProvider(t, providerstest.NewMemoryFixed(master))
			db, policy := filepath.Join(dir, "vault.db"), filepath.Join(dir, "policy.yaml")
			args := func(a ...string) []string { return append([]string{"--db", db, "--policy", policy}, a...) }

			code, out, stderr := runCLI(t, "", args("export")...)
			if code != 0 {
				t.Fatalf("export: exit %d %s", code, stderr)
			}
			var m struct {
				Export struct {
					SHA256 string `json:"sha256"`
				} `json:"export"`
			}
			_ = json.Unmarshal(mustRead(t, filepath.Join(dir, "manifest.json")), &m)
			sum := sha256.Sum256([]byte(strings.TrimSuffix(out, "\n")))
			if hex.EncodeToString(sum[:]) != m.Export.SHA256 {
				t.Errorf("Go export of the untouched %s vault differs from Python's export_vault", fx)
			}

			// Python's own export imports (same vault id).
			pyExport := filepath.Join(dir, "export.b64")
			if code, _, stderr := runCLI(t, "", args("import", "--yes", "--in", pyExport)...); code != 0 {
				t.Fatalf("import python export: exit %d %s", code, stderr)
			}
			if code, out, _ := runCLI(t, "", args("verify-audit", "--offline")...); code != 0 {
				t.Errorf("chain after import: exit %d %s", code, out)
			}
		})
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Opt-in: the REAL Python VaultManager imports what `rgt-vault export` wrote
// and its own export imports back (both v1 directions):
//
//	python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
//	RGT_VAULT_PYTHON=$PWD/.venv/bin/python go test ./cmd/rgt-vault -run Python
func TestExportImportWithRealPython(t *testing.T) {
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault installed to run the Python round-trip")
	}
	script, err := filepath.Abs("../../internal/vault/testdata/pyroundtrip.py")
	if err != nil {
		t.Fatal(err)
	}
	isolateEnv(t)
	dir := t.TempDir()
	masterFile := filepath.Join(dir, "master.bin")
	prov := providerstest.NewMemory()
	secret, _ := prov.GetMasterSecret()
	if err := os.WriteFile(masterFile, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	useProvider(t, prov)
	db, policy := filepath.Join(dir, "vault.db"), filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(policy, []byte(allowAllPolicy), 0o600)
	stack, err := server.OpenStack(context.Background(), server.StackOptions{DBPath: db, PolicyFile: policy, MasterProvider: prov, KDFParams: kdfParams})
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range []string{"one", "two-ünï"} {
		if err := stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
			Name: "n" + string(rune('a'+i)), Namespace: "go", Agent: "system", Purpose: "t", Value: []byte(v)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = stack.Close()

	goExport, pyExport := filepath.Join(dir, "go.b64"), filepath.Join(dir, "py.b64")
	if code, _, stderr := runCLI(t, "", "--db", db, "--policy", policy, "export", "--out", goExport); code != 0 {
		t.Fatalf("export: %s", stderr)
	}
	expect := filepath.Join(dir, "expect.json")
	_ = os.WriteFile(expect, []byte(`[{"namespace":"go","name":"na","version":1,"want":""},{"namespace":"go","name":"nb","version":1,"want":""}]`), 0o600)
	cmd := exec.Command(py, script, dir, masterFile, expect, goExport, pyExport)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python: %v", err)
	}
	var r struct {
		ChainBefore bool `json:"chain_before"`
		Imported    bool `json:"imported"`
		ChainFinal  bool `json:"chain_final"`
	}
	if err := json.Unmarshal(out, &r); err != nil || !r.ChainBefore || !r.Imported || !r.ChainFinal {
		t.Fatalf("python report %s: %+v %v", out, r, err)
	}
	// Back in Go: Python's export (made after Python wrote a secret) imports.
	if code, _, stderr := runCLI(t, "", "--db", db, "--policy", policy, "import", "--yes", "--in", pyExport); code != 0 {
		t.Fatalf("import python export: %s", stderr)
	}
	if code, out, _ := runCLI(t, "", "--db", db, "verify-audit"); code != 0 {
		t.Errorf("chain: %s", out)
	}
}
