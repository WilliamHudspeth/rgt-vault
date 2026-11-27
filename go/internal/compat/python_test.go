package compat

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type pyExpect struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   int64  `json:"version"`
}

// goLists is what the Go HTTP API lists for each namespace as agent ci-bot.
func goLists(t *testing.T, e *env, expect []pyExpect) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, x := range expect {
		if _, done := out[x.Namespace]; done {
			continue
		}
		m := e.mustOK("GET", "/v1/secrets?agent=ci-bot&purpose=compat&namespace="+url.QueryEscape(x.Namespace), nil)
		names := []string{}
		for _, it := range m["secrets"].([]any) {
			switch v := it.(type) {
			case map[string]any:
				names = append(names, fmt.Sprint(v["name"]))
			case string:
				names = append(names, v)
			}
		}
		sort.Strings(names)
		out[x.Namespace] = names
	}
	return out
}

// TestPythonOpensGoModifiedVault is the migration proof in the direction that
// matters for rollback: the REAL Python implementation opens vaults that Go
// created, modified and rotated (DEK and master), reads every version Go reads,
// verifies the audit chain, serves the vault through its own FastAPI app,
// imports Go's export, writes, and exports; Go then reads Python's write and
// imports Python's export. Needs RGT_VAULT_PYTHON.
func TestPythonOpensGoModifiedVault(t *testing.T) {
	py := python(t)
	for _, fx := range append([]string{"go-fresh"}, fixtures...) {
		t.Run(fx, func(t *testing.T) {
			var (
				d      vaultDir
				expect []pyExpect
			)
			if fx == "go-fresh" {
				d = emptyDir(t)
			} else {
				d = copyFixture(t, fx)
				for _, s := range loadManifest(t, fx).Secrets {
					expect = append(expect, pyExpect{s.Namespace, s.Name, s.Version})
				}
			}
			e := open(t, d)

			// Go writes, revokes and rotates both keys, then writes again.
			e.set("go", "written-by-go", "go-v1")
			e.set("go", "written-by-go", "go-v2-ünï🔐")
			e.set("go", "revoked", "rv")
			e.mustOK("POST", "/v1/secrets/go/revoked/revoke?agent=system", nil)
			e.rotate("dek")
			e.rotate("master")
			e.set("go", "after-rotation", "post")
			expect = append(expect,
				pyExpect{"go", "written-by-go", 1}, pyExpect{"go", "written-by-go", 2},
				pyExpect{"go", "written-by-go", 0}, pyExpect{"go", "revoked", 1},
				pyExpect{"go", "revoked", 0}, pyExpect{"go", "after-rotation", 0})

			// What Go reads is what Python must read.
			want := make([]string, len(expect))
			for i, x := range expect {
				want[i] = e.read(x.Namespace, x.Name, x.Version)
				if fx == "go-fresh" && (want[i] == "DecryptionError" || want[i][:5] == "error") {
					t.Fatalf("Go cannot read its own %+v: %s", x, want[i])
				}
			}
			lists := goLists(t, e, expect)
			goExport, err := e.V().Export(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			epoch := e.V().KeyEpoch()
			e.Close()

			tmp := t.TempDir()
			expPath, goExpPath, pyExpPath := filepath.Join(tmp, "expect.json"), filepath.Join(tmp, "go.b64"), filepath.Join(tmp, "py.b64")
			b, _ := json.Marshal(expect)
			for p, c := range map[string][]byte{expPath: b, goExpPath: goExport} {
				if err := os.WriteFile(p, c, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r := runPython(t, py, nil, "roundtrip", d.Dir, d.Master, d.Policy, expPath, goExpPath, pyExpPath)

			if r["key_epoch"] != float64(epoch) {
				t.Errorf("Python sees key_epoch %v, Go has %d", r["key_epoch"], epoch)
			}
			for _, k := range []string{"chain_before", "imported", "chain_after_import", "chain_final"} {
				if r[k] != true {
					t.Errorf("python %s = %v", k, r[k])
				}
			}
			for _, k := range []string{"reads", "reads_after_import"} {
				if got := strs(r[k]); !reflect.DeepEqual(got, want) {
					for i := range want {
						if i < len(got) && got[i] != want[i] {
							t.Errorf("%s %+v: Python %s, Go %s", k, expect[i], got[i], want[i])
						}
					}
					t.Fatalf("Python %s differ from Go's", k)
				}
			}
			// Python's own server over the Go-written files agrees with Go's list.
			srv, _ := r["server"].(map[string]any)
			pyLists := map[string][]string{}
			for ns, v := range srv["lists"].(map[string]any) {
				pyLists[ns] = strs(v)
				if pyLists[ns] == nil {
					pyLists[ns] = []string{}
				}
			}
			if !reflect.DeepEqual(pyLists, lists) {
				t.Errorf("Python server lists %v, Go %v", pyLists, lists)
			}
			if v, _ := srv["verify"].(map[string]any); v["ok"] != true {
				t.Errorf("Python POST /v1/audit/verify = %v", srv["verify"])
			}
			t.Logf("Python read %d versions of the Go-rotated vault (epoch %d) and verified the chain", len(want), epoch)

			// Back in Go: Python's write, Python's chain, Python's export.
			e = open(t, d)
			if lab, got := e.lease("python", "written", 0); lab != sha([]byte("from-python")) {
				t.Fatalf("Python's write reads back as %q (%s)", got, lab)
			}
			if !e.chainOK() {
				t.Fatal("Go: chain broken after Python's writes")
			}
			pyExport, err := os.ReadFile(pyExpPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.V().Import(t.Context(), pyExport); err != nil {
				t.Fatalf("Go cannot import Python's export: %v", err)
			}
			if !e.chainOK() {
				t.Fatal("Go: chain broken after importing Python's export")
			}
			for i, x := range expect {
				if got := e.read(x.Namespace, x.Name, x.Version); got != want[i] {
					t.Errorf("after importing Python's export, %+v: %s, want %s", x, got, want[i])
				}
			}
			if lab, _ := e.lease("python", "written", 0); lab != sha([]byte("from-python")) {
				t.Error("Python's write lost by the import of Python's own export")
			}
		})
	}
}
