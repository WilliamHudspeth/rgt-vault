package compat

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"testing"
)

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// checkAllReads leases every stored row by version, and the latest version of
// every name, and compares each result with what Python's manifest recorded
// (plaintext sha256, or the Python exception class).
func checkAllReads(t *testing.T, e *env, m manifest) {
	t.Helper()
	bad := 0
	for _, s := range m.Secrets {
		if got := e.read(s.Namespace, s.Name, s.Version); got != s.want() {
			t.Errorf("%s/%s v%d (%s): got %s, want %s", s.Namespace, s.Name, s.Version, s.Status, got, s.want())
			bad++
		}
		if want, ok := s.wantLatest(); ok {
			if got := e.read(s.Namespace, s.Name, 0); got != want {
				t.Errorf("%s/%s latest: got %s, want %s", s.Namespace, s.Name, got, want)
				bad++
			}
		}
		if bad > 20 {
			t.Fatal("too many differences")
		}
	}
}

// activeNames returns the ACTIVE, non-honeytoken names per namespace.
func activeNames(m manifest) map[string][]string {
	out := map[string][]string{}
	for _, s := range m.Secrets {
		if s.Status == "ACTIVE" {
			out[s.Namespace] = append(out[s.Namespace], s.Name)
		}
	}
	for ns := range out {
		sort.Strings(out[ns])
	}
	return out
}

// TestFixturesFullStackRead is the "Go opens a Python vault" proof. For each
// Python-created vault (small = rotated twice with a 1 MiB secret, default =
// production Argon2 cost, epoch1 = never rotated) the whole stack opens the
// ORIGINAL files, and:
//
//   - reading does not rewrite keychain.json and does not change the audit log;
//   - the chain verdict, first/last hash and export bytes equal Python's;
//   - every secret version decrypts to exactly what Python's manifest says
//     (including the versions Python itself could no longer decrypt);
//   - the same facts hold when asked over HTTP (list, fingerprint, verify).
func TestFixturesFullStackRead(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			d := copyFixture(t, fx)
			kcBefore := fileSHA(t, d.Keychain)
			e := open(t, d)
			v := e.V()

			if v.VaultID() != m.VaultID || v.KeyEpoch() != m.KeyEpoch || v.PolicyHash() != m.PolicyHash {
				t.Fatalf("vault_id/epoch/policy = %s/%d/%s, want %s/%d/%s",
					v.VaultID(), v.KeyEpoch(), v.PolicyHash(), m.VaultID, m.KeyEpoch, m.PolicyHash)
			}
			if got := fileSHA(t, d.Keychain); got != kcBefore {
				t.Fatal("opening the vault rewrote keychain.json")
			}

			// Chain verdict and the audit log as Python left it. (Done before
			// any HTTP call or read: every request and every read is audited.)
			if ok, err := v.VerifyAuditChain(t.Context()); err != nil || ok != m.Audit.Verify {
				t.Fatalf("VerifyAuditChain = %v, %v; Python said %v", ok, err, m.Audit.Verify)
			}
			rows, err := v.Store().IterAuditLog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 || rows[0].EntryHash != m.Audit.FirstHash || rows[len(rows)-1].EntryHash != m.Audit.LastHash {
				t.Fatalf("audit first/last hash differ from Python's manifest (%d rows)", len(rows))
			}
			if int64(len(rows)) != m.RowCounts["audit_logs"] {
				t.Fatalf("audit rows %d, want %d", len(rows), m.RowCounts["audit_logs"])
			}
			exp, err := v.Export(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got := sha(exp); got != m.Export.SHA256 {
				t.Fatalf("Go export sha256 %s != Python export_vault %s", got, m.Export.SHA256)
			}

			checkAllReads(t, e, m)

			// Same facts over HTTP: the verdict, the agent-visible list, and fingerprints.
			if got := e.chainOK(); got != m.Audit.Verify {
				t.Fatalf("POST /v1/audit/verify = %v, Python said %v", got, m.Audit.Verify)
			}
			for ns, names := range activeNames(m) {
				code, body := e.call("GET", "/v1/secrets?agent=ci-bot&purpose=compat&namespace="+url.QueryEscape(ns), nil)
				if code != http.StatusOK {
					t.Fatalf("GET /v1/secrets ns=%s: %d %v", ns, code, body)
				}
				var got []string
				for _, it := range body["secrets"].([]any) {
					switch x := it.(type) {
					case map[string]any:
						got = append(got, fmt.Sprint(x["name"]))
					case string:
						got = append(got, x)
					}
				}
				sort.Strings(got)
				// A honeytoken is listed like any other active name.
				if !reflect.DeepEqual(got, names) {
					t.Errorf("list %s: got %v, want %v", ns, got, names)
				}
			}
			for _, s := range m.Secrets {
				if s.Status != "ACTIVE" || s.Honeytoken {
					continue
				}
				code, body := e.call("GET", fmt.Sprintf("/v1/secrets/%s/%s?version=%d", url.PathEscape(s.Namespace), url.PathEscape(s.Name), s.Version), nil)
				if code != http.StatusOK || body["fingerprint"] != s.Fingerprint {
					t.Errorf("fingerprint %s/%s v%d: %d %v, want %s", s.Namespace, s.Name, s.Version, code, body, s.Fingerprint)
				}
			}
		})
	}
}

// keychainShape checks keychain.json still has the exact key set and types
// Python's HardenedDEKManager writes (so the Python line can still read it).
func keychainShape(t *testing.T, path string, wantEpoch int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kc map[string]any
	if err := json.Unmarshal(b, &kc); err != nil {
		t.Fatalf("keychain.json: %v", err)
	}
	keys := make([]string, 0, len(kc))
	for k := range kc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"argon2_memory_cost", "argon2_parallelism", "argon2_salt", "argon2_time_cost", "created_at", "key_epoch", "kdf", "version", "wrapped_dek"}
	sort.Strings(want)
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keychain.json keys %v, want Python's %v", keys, want)
	}
	if kc["version"] != float64(1) || kc["kdf"] != "argon2id" || kc["key_epoch"] != float64(wantEpoch) {
		t.Fatalf("keychain.json header %v (want version 1, argon2id, epoch %d)", kc, wantEpoch)
	}
	for _, k := range []string{"argon2_salt", "wrapped_dek", "created_at"} {
		if s, _ := kc[k].(string); s == "" {
			t.Fatalf("keychain.json %s is not a non-empty string", k)
		}
	}
}

// TestFixturesWriteRotateReverify is the "Go modifies a Python vault" proof,
// through the HTTP API: write (new versions, a revoke, unicode), rotate the
// DEK, rotate the master key, and re-verify after every step and again after
// re-opening the files from disk.
func TestFixturesWriteRotateReverify(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			d := copyFixture(t, fx)
			e := open(t, d)

			e.set("go", "written-by-go", "go-v1")
			e.set("go", "written-by-go", "go-v2-ünï🔐")
			e.set("go", "to-revoke", "revoked-value")
			e.mustOK("POST", "/v1/secrets/go/to-revoke/revoke?agent=system", nil)
			if !e.chainOK() {
				t.Fatal("chain broken by Go writes")
			}

			epoch := e.V().KeyEpoch()
			if got := e.rotate("dek"); got != epoch+1 {
				t.Fatalf("rotate dek: epoch %d, want %d", got, epoch+1)
			}
			if got := e.rotate("master"); got != epoch+2 {
				t.Fatalf("rotate master: epoch %d, want %d", got, epoch+2)
			}

			check := func(e *env, stage string) {
				t.Helper()
				checkAllReads(t, e, m) // Python's rows read exactly as before the rotations
				if lab, got := e.lease("go", "written-by-go", 1); lab != sha([]byte("go-v1")) {
					t.Errorf("%s: go v1 = %q", stage, got)
				}
				if lab, got := e.lease("go", "written-by-go", 2); lab != sha([]byte("go-v2-ünï🔐")) {
					t.Errorf("%s: go v2 = %q", stage, got)
				}
				if lab, got := e.lease("go", "written-by-go", 0); lab != sha([]byte("go-v2-ünï🔐")) {
					t.Errorf("%s: go latest = %q", stage, got)
				}
				// A revoked name is gone for latest reads but its version still decrypts.
				if got, _ := e.lease("go", "to-revoke", 0); got != "SecretNotFoundError" {
					t.Errorf("%s: revoked latest = %s", stage, got)
				}
				if lab, got := e.lease("go", "to-revoke", 1); lab != sha([]byte("revoked-value")) {
					t.Errorf("%s: revoked v1 = %q", stage, got)
				}
				if !e.chainOK() {
					t.Fatalf("%s: audit chain broken", stage)
				}
			}
			check(e, "after rotations")
			keychainShape(t, d.Keychain, epoch+2)
			e.Close()

			// A new process: re-open from disk with the rotated master secret.
			// (providerstest.File rewrites master.bin on RotateMasterSecret.)
			e2 := open(t, d)
			if e2.V().KeyEpoch() != epoch+2 {
				t.Fatalf("reopened epoch %d, want %d", e2.V().KeyEpoch(), epoch+2)
			}
			check(e2, "after reopen")
		})
	}
}

// TestFixturesExportImport: Go's export is Python's export byte for byte,
// and Python's export (export.b64, written by export_vault) imports into Go
// and replaces whatever Go had written since (the restore path).
func TestFixturesExportImport(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			d := copyFixture(t, fx)
			pyExport, err := os.ReadFile(d.Export)
			if err != nil {
				t.Fatal(err)
			}
			pyExport = bytes.TrimSpace(pyExport)
			e := open(t, d)

			exp, err := e.V().Export(t.Context())
			if err != nil || !bytes.Equal(exp, pyExport) {
				t.Fatalf("Go export != Python export_vault (err %v, %d vs %d bytes)", err, len(exp), len(pyExport))
			}

			// Diverge, then restore from Python's export.
			e.set("go", "post-export", "will be rolled back")
			if got, _ := e.lease("go", "post-export", 0); got == "SecretNotFoundError" {
				t.Fatal("setup: write did not land")
			}
			if err := e.V().Import(t.Context(), pyExport); err != nil {
				t.Fatalf("import of Python's export: %v", err)
			}
			// Re-export before any read (reads are audited): the secrets and
			// honeytokens are Python's again. Import itself may append an
			// IMPORT audit row, so compare the decoded secrets, not the bytes.
			again, err := e.V().Export(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !sameSecrets(t, again, pyExport) {
				t.Error("secrets after import differ from Python's export")
			}
			if got, _ := e.lease("go", "post-export", 0); got != "SecretNotFoundError" {
				t.Errorf("import did not replace the Go write (got %s)", got)
			}
			checkAllReads(t, e, m)
			if !e.chainOK() {
				t.Fatal("chain broken after import")
			}
		})
	}
}

// sameSecrets compares the secrets and honeytokens arrays of two exports
// (base64(JSON), Python's v1 envelope).
func sameSecrets(t *testing.T, a, b []byte) bool {
	t.Helper()
	dec := func(x []byte) map[string]any {
		raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(x)))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	ma, mb := dec(a), dec(b)
	return reflect.DeepEqual(ma["secrets"], mb["secrets"]) &&
		reflect.DeepEqual(ma["honeytokens"], mb["honeytokens"]) &&
		ma["vault_id"] == mb["vault_id"]
}
