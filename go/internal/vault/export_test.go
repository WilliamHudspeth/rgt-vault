package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rgt-vault-server/internal/store"
)

func TestPyJSON(t *testing.T) {
	obj := pyObject{
		{"s", "a\"b\\c\n\r\t\b\f\x01\x7f é 日 🔐 ~"}, {"n", nil}, {"t", true}, {"f", false}, {"i", -5},
		{"l", []any{1, []any{}, pyObject{}}}, {"e", map[string]any{}},
	}
	want := `{"s": "a\"b\\c\n\r\t\b\f\u0001\u007f \u00e9 \u65e5 \ud83d\udd10 ~", "n": null, "t": true, "f": false, "i": -5, "l": [1, [], {}], "e": {}}`
	if got := pyDumps(obj); got != want {
		t.Fatalf("pyDumps\n got %s\nwant %s", got, want)
	}
	floats := map[float64]string{1.0: "1.0", 0.1: "0.1", 1e16: "1e+16", 1.5e-5: "1.5e-05", 123456789012345.6: "123456789012345.6",
		-2.5: "-2.5", 1e-4: "0.0001", 1e22: "1e+22", math.Copysign(0, -1): "-0.0", 3.0e15: "3000000000000000.0", 0: "0.0",
		math.NaN(): "NaN", math.Inf(1): "Infinity", math.Inf(-1): "-Infinity"}
	for f, w := range floats {
		if got := pyDumps(f); got != w {
			t.Errorf("float %v: %s, want %s", f, got, w)
		}
	}
	nested := pyObject{{"a", []any{1, pyObject{{"b", []any{}}}}}, {"c", pyObject{}}}
	if got := pyDumpsIndent(nested, 2); got != "{\n  \"a\": [\n    1,\n    {\n      \"b\": []\n    }\n  ],\n  \"c\": {}\n}" {
		t.Fatalf("indent: %q", got)
	}
	if got := pyDumpsIndent([]any{}, 2); got != "[]" {
		t.Fatal(got)
	}
	other := []any{int64(1), int32(2), uint32(3), uint64(4), json.Number("5"), []byte("b"), []string{"x"},
		time.Duration(0), struct{ A int }{1}}
	if got := pyDumps(other); got != `[1, 2, 3, 4, 5, "b", ["x"], "0s", "{1}"]` {
		t.Fatalf("misc: %s", got)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	set(t, v, "n", "a", "alpha")
	set(t, v, "n", "a", "alpha-2")
	if err := v.SetSecret(ctx, SetSecretRequest{Name: "u", Namespace: "n", Agent: SystemAgent,
		Value: []byte("pässwörd-🔐"), Note: "Ünïcöde nöte ✓"}); err != nil {
		t.Fatal(err)
	}
	if err := v.store.AddHoneytoken(ctx, "n", "decoy"); err != nil {
		t.Fatal(err)
	}
	exp, err := v.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(string(exp))
	if !bytes.HasPrefix(raw, []byte("{\n  \"secrets\": [\n    {\n      \"id\": 1,")) ||
		!bytes.HasSuffix(raw, []byte("\"vault_id\": \""+v.VaultID()+"\"\n}")) || !isASCII(raw) {
		t.Fatalf("export layout:\n%s", raw[:200])
	}

	set(t, v, "n", "after-export", "lost on import")
	if err := v.Import(ctx, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, v, "n", "after-export", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("import did not replace the secrets: %v", err)
	}
	if got, err := get(t, v, "n", "a", 1); err != nil || got != "alpha" {
		t.Fatalf("after import %q %v", got, err)
	}
	if hit, _ := v.store.IsHoneytoken(ctx, "n", "decoy"); !hit {
		t.Fatal("honeytoken lost")
	}
	rows := auditRows(t, v)
	var imp *store.AuditRow
	for i := range rows {
		if rows[i].Action == "IMPORT" {
			imp = &rows[i]
		}
	}
	if imp == nil || imp.SecretName.String != "VAULT" || imp.Details.String != "Vault imported from external data" {
		t.Fatalf("import row %+v", imp)
	}
	mustVerify(t, v)

	// Lenient base64 like Python's b64decode: whitespace/newlines dropped.
	wrapped := []byte(strings.Join(chunk(string(exp), 76), "\n") + "\n")
	if err := v.Import(ctx, wrapped); err != nil {
		t.Fatalf("wrapped base64: %v", err)
	}
}

func chunk(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c > 0x7e || (c < 0x20 && c != '\n') {
			return false
		}
	}
	return true
}

func TestImportRejects(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	set(t, v, "n", "keep", "kept")
	enc := func(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
	cases := map[string][]byte{
		"Import payload exceeds the maximum allowed size of 10MB.":  bytes.Repeat([]byte("A"), MaxImportBytes+1),
		"Invalid import payload format: illegal base64":             []byte("abc"),
		"Invalid import payload format: payload is not valid UTF-8": enc("\xff\xfe"),
		"Invalid import payload format: invalid character":          enc("{nope"),
		"Invalid import payload format: top level must be":          enc("[1, 2]"),
		"Import refused: payload belongs to vault 'other-vault'":    enc(`{"vault_id": "other-vault", "secrets": []}`),
		"Import refused: payload belongs to vault '5'":              enc(`{"vault_id": 5}`),
	}
	for want, payload := range cases {
		err := v.Import(ctx, payload)
		if !errors.Is(err, ErrValidation) || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	// Store-level validation errors (Python ValueError) are returned too.
	if err := v.Import(ctx, enc(`{"secrets": 5}`)); err == nil {
		t.Fatal("non-list secrets accepted")
	}
	// Nothing changed.
	if got, err := get(t, v, "n", "keep", 0); err != nil || got != "kept" {
		t.Fatalf("a rejected import changed the vault: %q %v", got, err)
	}
	// A payload without vault_id (older exports) is accepted, as in Python.
	if err := v.Import(ctx, enc(`{"secrets": [], "audit_logs": [], "honeytokens": []}`)); err != nil {
		t.Fatalf("no vault_id: %v", err)
	}
}

// TestImportPythonExport imports Python's export_vault output into the
// same (Go-modified) vault: the Python state comes back exactly.
func TestImportPythonExport(t *testing.T) {
	ctx := context.Background()
	for _, fx := range vaultFixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			db, prov := copyFixture(t, fx)
			v := openT(t, Config{DBPath: db, Provider: prov, PolicyYAML: fixturePolicy(t, fx)})
			set(t, v, "go", "extra", "x")
			pyExp, err := os.ReadFile(filepath.Join(filepath.Dir(db), "export.b64"))
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Import(ctx, pyExp); err != nil {
				t.Fatal(err)
			}
			if _, err := get(t, v, "go", "extra", 0); !errors.Is(err, ErrNotFound) {
				t.Fatalf("go row survived the import: %v", err)
			}
			checkFixtureReads(t, v, m)
			mustVerify(t, v)
		})
	}
}
