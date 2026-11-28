package vault

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
)

type pyExpect struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   int64  `json:"version"`
	Want      string `json:"want"`
}

// TestPythonRoundTrip has the REAL Python VaultManager open vaults that Go
// modified, rotated (DEK and master) and exported: Python must read every
// secret version Go reads, verify the audit chain, import Go's export, and
// write; Go then reads Python's write and imports Python's export.
//
// It needs a Python with rgt_vault installed:
//
//	python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
//	RGT_VAULT_PYTHON=$PWD/.venv/bin/python go test ./internal/vault -run Python
func TestPythonRoundTrip(t *testing.T) {
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault installed to run the Python round-trip")
	}
	script, err := filepath.Abs("testdata/pyroundtrip.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, fx := range append([]string{"go-fresh"}, vaultFixtures...) {
		t.Run(fx, func(t *testing.T) {
			ctx := context.Background()
			var (
				db     string
				master string
				m      manifest
			)
			if fx == "go-fresh" {
				dir, prov, v := newFileVault(t)
				_ = v.Close()
				db, master = filepath.Join(dir, "vault.db"), prov.Path
			} else {
				var prov providerstest.File
				db, prov = copyFixture(t, fx)
				master, m = prov.Path, loadManifest(t, fx)
			}
			cfg := Config{DBPath: db, Provider: fileProv(master), PolicyYAML: allowAllPolicy}
			v := openT(t, cfg)

			// Go writes, revokes and rotates both keys.
			set(t, v, "go", "written-by-go", "go-v1")
			set(t, v, "go", "written-by-go", "go-v2-ünï🔐")
			set(t, v, "go", "revoked", "rv")
			if err := v.RevokeSecret(ctx, "go", "revoked", SystemAgent); err != nil {
				t.Fatal(err)
			}
			if err := v.RotateDEK(ctx); err != nil {
				t.Fatal(err)
			}
			if err := v.RotateMaster(ctx); err != nil {
				t.Fatal(err)
			}
			set(t, v, "go", "after-rotation", "post")

			// What Go reads is what Python must read.
			var expect []pyExpect
			for _, s := range m.Secrets {
				expect = append(expect, pyExpect{s.Namespace, s.Name, s.Version, ""})
			}
			expect = append(expect,
				pyExpect{"go", "written-by-go", 1, ""}, pyExpect{"go", "written-by-go", 2, ""},
				pyExpect{"go", "written-by-go", 0, ""}, pyExpect{"go", "revoked", 1, ""},
				pyExpect{"go", "revoked", 0, ""}, pyExpect{"go", "after-rotation", 0, ""})
			want := make([]string, len(expect))
			for i, e := range expect {
				want[i] = readVersion(t, v, e.Namespace, e.Name, e.Version)
				if want[i] == "DecryptionError" && fx == "go-fresh" {
					t.Fatalf("Go cannot read its own %s/%s v%d", e.Namespace, e.Name, e.Version)
				}
			}
			goExport, err := v.Export(ctx)
			if err != nil {
				t.Fatal(err)
			}
			epoch := v.KeyEpoch()
			_ = v.Close()

			tmp := t.TempDir()
			expPath, goExpPath, pyExpPath := filepath.Join(tmp, "expect.json"), filepath.Join(tmp, "go.b64"), filepath.Join(tmp, "py.b64")
			b, _ := json.Marshal(expect)
			if err := os.WriteFile(expPath, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(goExpPath, goExport, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(py, script, filepath.Dir(db), master, expPath, goExpPath, pyExpPath)
			cmd.Stderr = os.Stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("python: %v", err)
			}
			var r struct {
				VaultID          string   `json:"vault_id"`
				KeyEpoch         int64    `json:"key_epoch"`
				ChainBefore      bool     `json:"chain_before"`
				Reads            []string `json:"reads"`
				Imported         bool     `json:"imported"`
				ChainAfterImport bool     `json:"chain_after_import"`
				ReadsAfterImport []string `json:"reads_after_import"`
				ChainFinal       bool     `json:"chain_final"`
			}
			if err := json.Unmarshal(out, &r); err != nil {
				t.Fatalf("python output: %v\n%s", err, out)
			}
			if r.KeyEpoch != epoch || !r.ChainBefore || !r.Imported || !r.ChainAfterImport || !r.ChainFinal {
				t.Fatalf("python report: %+v", r)
			}
			if !reflect.DeepEqual(r.Reads, want) || !reflect.DeepEqual(r.ReadsAfterImport, want) {
				for i := range want {
					if i < len(r.Reads) && r.Reads[i] != want[i] {
						t.Errorf("%+v: python %s, go %s", expect[i], r.Reads[i], want[i])
					}
				}
				t.Fatal("python reads differ from Go reads")
			}
			t.Logf("python read %d versions of the Go-rotated vault (epoch %d) and verified the chain", len(want), epoch)

			// Back in Go: Python's write, Python's chain, Python's export.
			v = openT(t, cfg)
			if got, err := get(t, v, "python", "written", 0); err != nil || got != "from-python" {
				t.Fatalf("python write: %q %v", got, err)
			}
			mustVerify(t, v)
			pyExport, err := os.ReadFile(pyExpPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Import(ctx, pyExport); err != nil {
				t.Fatal(err)
			}
			mustVerify(t, v)
			for i, e := range expect {
				if got := readVersion(t, v, e.Namespace, e.Name, e.Version); got != want[i] {
					t.Errorf("after importing python's export, %+v: %s want %s", e, got, want[i])
				}
			}
		})
	}
}
