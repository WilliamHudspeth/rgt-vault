// Package asvs_test contains end-to-end verification and source-guard tests
// for OWASP ASVS v4.0.3 Chapter V5 (Validation, Sanitization, Encoding,
// Deserialization, and Injection) and related V1/V4 input-handling tickets on
// the Go line (batch H7).
//
// Issues covered:
//
//	RGT-238, 239, 240, 241, 242, 258, 264, 349, 351, 354, 356, 358, 359,
//	360, 362, 363, 365, 366, 367, 368, 370, 371, 372, 373, 374, 375, 378,
//	379, 380, 433, 434, 435.
package asvs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/audit"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/cryptopolicy"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/netguard"
	"rgt-vault-server/internal/policy"
	"rgt-vault-server/internal/providers"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/tui"
	"rgt-vault-server/internal/validation"
	"rgt-vault-server/internal/vault"
)

// goRoot walks upward from os.Getwd() to locate the go/ module root
// (containing go.mod), so it works under -trimpath across Linux, macOS, and Windows.
func goRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking upward from working directory")
		}
		dir = parent
	}
}

// walkGoFiles parses every .go file under go/ and calls fn with the slash-normalized
// path relative to go/ (e.g. "internal/providers/exec.go"), the file set, and the AST.
func walkGoFiles(t *testing.T, fn func(rel string, fset *token.FileSet, f *ast.File)) {
	t.Helper()
	root := goRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		parsed, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		fn(rel, fset, parsed)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// fixedMasterProvider is an in-memory vault.MasterProvider for fast vault tests.
type fixedMasterProvider struct {
	secret []byte
}

func newFixedMasterProvider(t *testing.T) *fixedMasterProvider {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return &fixedMasterProvider{secret: b}
}

func (p *fixedMasterProvider) GetMasterSecret() ([]byte, error) {
	out := make([]byte, len(p.secret))
	copy(out, p.secret)
	return out, nil
}

// fastKDFParams uses small Argon2id parameters so tests run quickly across OSes.
var fastKDFParams = kdf.Params{
	TimeCost:    1,
	MemoryCost:  8192,
	Parallelism: 1,
}

// ---------------------------------------------------------------------------
// 1. SQL Injection Probes on store.Store and vault.Vault (RGT-367, RGT-368, RGT-238, RGT-241)
// ---------------------------------------------------------------------------

func TestASVS_V5_SQLInjectionProbesOnStore(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Seed a benign canary secret that must survive every hostile probe untouched.
	canaryCT := []byte("canary-ciphertext-bytes-0123456789")
	if _, err := st.SetSecret(ctx, store.SetSecretParams{
		Namespace:  "prod",
		Name:       "canary_key",
		Ciphertext: canaryCT,
		DEKVersion: 1,
		PolicyHash: "0123456789abcdef",
		Note:       "benign canary",
		Require2FA: true,
	}); err != nil {
		t.Fatalf("seed canary: %v", err)
	}

	// Hostile SQLi payloads: quotes, stacked queries, DROP TABLE, UNION, comments,
	// embedded NUL bytes, multi-script Unicode, and very long strings.
	probes := []string{
		`' OR '1'='1`,
		`' OR 1=1 --`,
		`"; DROP TABLE secrets; --`,
		`'; DROP TABLE audit_logs; --`,
		`'; DELETE FROM secrets WHERE '1'='1`,
		`' UNION SELECT secret_id, name, 1, '', '', 'ACTIVE', hex(ciphertext), 0 FROM secrets --`,
		"null_byte\x00'; DROP TABLE secrets; --",
		"unicode_probe_\u00e9_\u6771\u4eac_\U0001f512'; --",
		strings.Repeat("A';--", 1024), // 5120 chars
	}

	for i, payload := range probes {
		ct := []byte("probe-ct-" + strconv.Itoa(i))
		ver, err := st.SetSecret(ctx, store.SetSecretParams{
			Namespace:  payload,
			Name:       payload,
			Ciphertext: ct,
			DEKVersion: 1,
			PolicyHash: payload,
			Note:       payload,
			Require2FA: i%2 == 0,
		})
		if err != nil {
			t.Fatalf("probe %d SetSecret failed on parameterized store: %v", i, err)
		}
		if ver != 1 {
			t.Fatalf("probe %d version = %d, want 1", i, ver)
		}

		// Retrieve the secret by its exact hostile namespace and name: proves it
		// was stored verbatim and can be queried safely.
		gotCT, dekVer, err := st.GetSecret(ctx, payload, payload, payload)
		if err != nil {
			t.Fatalf("probe %d GetSecret failed: %v", i, err)
		}
		if !bytes.Equal(gotCT, ct) || dekVer != 1 {
			t.Fatalf("probe %d ciphertext/dekVer mismatch", i)
		}

		// ListSecrets with hostile namespace must only return the 1 secret in that
		// literal namespace, never the 'prod' canary (proving ' OR '1'='1 does not
		// tautologize WHERE namespace = ?).
		list, err := st.ListSecrets(ctx, payload, "0123456789abcdef", 100, 0)
		if err != nil {
			t.Fatalf("probe %d ListSecrets: %v", i, err)
		}
		if len(list) != 1 || list[0].Name != payload || list[0].Note != payload {
			t.Fatalf("probe %d ListSecrets returned %+v, want 1 verbatim row", i, list)
		}

		// Honeytoken and Requires2FA probes with the same hostile payload.
		if err := st.AddHoneytoken(ctx, payload, payload); err != nil {
			t.Fatalf("probe %d AddHoneytoken: %v", i, err)
		}
		isHT, err := st.IsHoneytoken(ctx, payload, payload)
		if err != nil || !isHT {
			t.Fatalf("probe %d IsHoneytoken = %v, %v", i, isHT, err)
		}
		if isProdHT, err := st.IsHoneytoken(ctx, "prod", "canary_key"); err != nil || isProdHT {
			t.Fatalf("probe %d polluted prod honeytoken status: %v, %v", i, isProdHT, err)
		}
	}

	// Verify the canary secret and its namespace are completely intact.
	gotCanary, dekVer, err := st.GetSecret(ctx, "prod", "canary_key", "0123456789abcdef")
	if err != nil {
		t.Fatalf("canary GetSecret after probes: %v", err)
	}
	if !bytes.Equal(gotCanary, canaryCT) || dekVer != 1 {
		t.Fatalf("canary corrupted after probes")
	}
	prodList, err := st.ListSecrets(ctx, "prod", "0123456789abcdef", 100, 0)
	if err != nil || len(prodList) != 1 || prodList[0].Name != "canary_key" {
		t.Fatalf("prod ListSecrets after probes = %+v, err=%v", prodList, err)
	}

	// Verify the hash-chained audit log is intact across all hostile audit rows.
	ok, err := st.VerifyAuditChain(ctx)
	if err != nil || !ok {
		t.Fatalf("VerifyAuditChain after SQLi probes: ok=%v err=%v", ok, err)
	}

	// Verify store.Open rejects SQLite URI/DSN parameter injection (RGT-367, RGT-372).
	// Using _pragma=foreign_keys(1) ensures the probe would otherwise succeed if the
	// '?' guard in store.Open (store.go:102-105) were removed.
	for _, badPath := range []string{
		filepath.Join(t.TempDir(), "vault.db?_pragma=foreign_keys(1)"),
		"file:" + filepath.Join(t.TempDir(), "vault.db"),
	} {
		if badStore, err := store.Open(ctx, badPath); err == nil {
			_ = badStore.Close()
			t.Errorf("store.Open(%q) succeeded; expected DSN/URI rejection", badPath)
		}
	}
}

func TestASVS_V5_VaultValidationAndABACRejectHostileInputs(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	policyYAML := `
rules:
  - agent: "agent-alpha"
    namespace: "app-*"
    purpose: "*"
    action: "write"
    effect: "allow"
  - agent: "agent-alpha"
    namespace: "app-*"
    purpose: "*"
    action: "read"
    effect: "allow"
  - agent: "agent-alpha"
    namespace: "app-restricted"
    purpose: "*"
    action: "*"
    effect: "deny"
`
	v, err := vault.Open(ctx, vault.Config{
		DBPath:     dbPath,
		Provider:   newFixedMasterProvider(t),
		PolicyYAML: policyYAML,
		KDFParams:  fastKDFParams,
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	// 1. SQLi payloads in free-text fields (Purpose, Note) that use only allowed
	// printable characters must be safely parameterized and round-trip without
	// affecting SQLite tables or audit verification (RGT-241, RGT-367).
	sqlFreeText := "audit 'SELECT * FROM secrets' WHERE name = 'x'; DROP TABLE secrets; --"
	wantSecret := []byte("super-secret-value-123")
	if err := v.SetSecret(ctx, vault.SetSecretRequest{
		Name:      "db_password",
		Namespace: "app-prod",
		Agent:     "agent-alpha",
		Purpose:   sqlFreeText,
		Note:      sqlFreeText,
		Value:     wantSecret,
	}); err != nil {
		t.Fatalf("SetSecret with valid-charset SQLi free text: %v", err)
	}

	var leased []byte
	if err := v.Lease(ctx, vault.LeaseRequest{
		Name:      "db_password",
		Namespace: "app-prod",
		Agent:     "agent-alpha",
		Purpose:   sqlFreeText,
	}, func(secret []byte) error {
		leased = append([]byte(nil), secret...)
		return nil
	}); err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if !bytes.Equal(leased, wantSecret) {
		t.Fatalf("leased secret = %q, want %q", leased, wantSecret)
	}

	// 2. Hostile identifier inputs (SQLi, NUL bytes, trailing newline, path traversal,
	// over-length) must be rejected at the trusted service layer with ErrValidation
	// (RGT-241, RGT-367, RGT-372).
	badIdentifiers := []string{
		`' OR '1'='1`,
		`'; DROP TABLE secrets; --`,
		"name_with_null\x00",
		"trailing_newline\n",
		"trailing_crlf\r\n",
		"../etc/passwd",
		`..\windows\win.ini`,
		strings.Repeat("a", validation.MaxNameLen+1),
	}
	for _, bad := range badIdentifiers {
		err := v.SetSecret(ctx, vault.SetSecretRequest{
			Name:      bad,
			Namespace: "app-prod",
			Agent:     "agent-alpha",
			Purpose:   "test",
			Value:     []byte("v"),
		})
		if !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Name=%q) err = %v, want vault.ErrValidation", bad, err)
		}
		err = v.SetSecret(ctx, vault.SetSecretRequest{
			Name:      "valid_name",
			Namespace: bad,
			Agent:     "agent-alpha",
			Purpose:   "test",
			Value:     []byte("v"),
		})
		if !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Namespace=%q) err = %v, want vault.ErrValidation", bad, err)
		}
		err = v.SetSecret(ctx, vault.SetSecretRequest{
			Name:      "valid_name",
			Namespace: "app-prod",
			Agent:     bad,
			Purpose:   "test",
			Value:     []byte("v"),
		})
		if !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Agent=%q) err = %v, want vault.ErrValidation", bad, err)
		}
	}

	// 3. Free-text fields with control characters (NUL, LF, CR, ESC) or bidi override
	// characters must be rejected at the service layer (RGT-241, RGT-365).
	for _, badText := range []string{"line1\nline2", "null\x00byte", "ansi\x1b[31m", "bidi\u202eoverride"} {
		err := v.SetSecret(ctx, vault.SetSecretRequest{
			Name:      "valid_name",
			Namespace: "app-prod",
			Agent:     "agent-alpha",
			Purpose:   badText,
			Value:     []byte("v"),
		})
		if !errors.Is(err, vault.ErrValidation) {
			t.Errorf("SetSecret(Purpose=%q) err = %v, want vault.ErrValidation", badText, err)
		}
	}

	// 4. ABAC explicit-deny and default-deny enforcement on SetSecret (RGT-238;
	// Lease/List/Revoke ABAC denials are covered by vault.TestPolicyDenials and
	// server.TestAuthzIDORBetweenAgents).
	if err := v.SetSecret(ctx, vault.SetSecretRequest{
		Name:      "k",
		Namespace: "app-restricted", // matches allow app-* AND explicit deny app-restricted -> deny wins
		Agent:     "agent-alpha",
		Purpose:   "test",
		Value:     []byte("v"),
	}); !errors.Is(err, vault.ErrPolicyDenied) {
		t.Errorf("explicit-deny namespace err = %v, want vault.ErrPolicyDenied", err)
	}
	if err := v.SetSecret(ctx, vault.SetSecretRequest{
		Name:      "k",
		Namespace: "other-ns", // no matching allow -> default deny
		Agent:     "agent-alpha",
		Purpose:   "test",
		Value:     []byte("v"),
	}); !errors.Is(err, vault.ErrPolicyDenied) {
		t.Errorf("default-deny namespace err = %v, want vault.ErrPolicyDenied", err)
	}

	// Audit chain must still verify cleanly.
	ok, err := v.VerifyAuditChain(ctx)
	if err != nil || !ok {
		t.Fatalf("VerifyAuditChain: ok=%v err=%v", ok, err)
	}
}

// ---------------------------------------------------------------------------
// 2. Source & AST Guards: os/exec, unsafe/cgo, format strings, N/A packages
//    (RGT-240, 258, 349, 356, 358, 359, 360, 362, 363, 367, 368, 370, 371,
//     373, 374, 375, 378, 379, 380, 433, 434, 435)
// ---------------------------------------------------------------------------

func TestASVS_V5_SourceScanNoShellExecAndAllowlistedImports(t *testing.T) {
	// Production files permitted to import "os/exec" (G6 master-secret providers).
	allowedProdExec := map[string]bool{
		"internal/providers/exec.go": true,
		"internal/providers/tpm.go":  true,
	}
	// The single first-party file in go/ permitted to import "unsafe" (G6 Windows DPAPI).
	allowedUnsafe := map[string]bool{
		"internal/providers/dpapi_windows.go": true,
	}
	// Production files permitted to import "reflect" (canonical JSON, claim/context comparison,
	// and known-field struct tag inspection for 422 JSON type errors).
	allowedProdReflect := map[string]bool{
		"internal/captoken/canonical.go":       true,
		"internal/captoken/token.go":           true,
		"internal/vault/capability.go":         true,
		"internal/server/handlers/handlers.go": true,
	}
	// Forbidden imports across all first-party go/ files. Strings are split so a
	// plain grep over go/ does not match this test file itself.
	forbiddenImports := map[string]string{
		"C":                       "cgo is forbidden in first-party go/ (RGT-374)",
		"encoding/" + "gob":       "gob deserialization is forbidden (RGT-240/RGT-379)",
		"encoding/" + "xml":       "XML parsing is not used (RGT-373/RGT-378)",
		"html/" + "template":      "HTML templates are not used (RGT-356/RGT-360/RGT-434/RGT-435)",
		"text/" + "template":      "text templates are not used in first-party go/ (RGT-360/RGT-363/RGT-434/RGT-435)",
		"net/" + "smtp":           "SMTP mail is not used (RGT-358)",
		"net/" + "mail":           "mail parsing is not used (RGT-358)",
		"mime/" + "multipart":     "multipart file uploads are not used (RGT-258)",
		"plug" + "in":             "dynamic Go plugin loading is forbidden (RGT-359)",
	}
	shellNames := map[string]bool{
		"sh": true, "/bin/sh": true, "bash": true, "/bin/bash": true, "zsh": true,
		"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true,
	}
	shellFlags := map[string]bool{
		"-c": true, "/c": true, "/C": true, "-Command": true, "-command": true,
	}

	seenUnsafe := false
	seenExec := false

	walkGoFiles(t, func(rel string, fset *token.FileSet, f *ast.File) {
		isTest := strings.HasSuffix(rel, "_test.go")

		for _, imp := range f.Imports {
			pkgPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if reason, bad := forbiddenImports[pkgPath]; bad {
				t.Errorf("%s imports %q: %s", rel, pkgPath, reason)
			}
			if strings.Contains(strings.ToLower(pkgPath), "ld"+"ap") {
				t.Errorf("%s imports LDAP package %q (RGT-370)", rel, pkgPath)
			}
			if pkgPath == "unsafe" {
				seenUnsafe = true
				if !allowedUnsafe[rel] {
					t.Errorf("%s imports \"unsafe\" outside allowlist %v (RGT-374)", rel, allowedUnsafe)
				}
			}
			if pkgPath == "os/exec" {
				seenExec = true
				if !isTest && !allowedProdExec[rel] {
					t.Errorf("production file %s imports \"os/exec\" outside allowlist %v (RGT-371)", rel, allowedProdExec)
				}
			}
			if pkgPath == "reflect" && !isTest && !allowedProdReflect[rel] {
				t.Errorf("production file %s imports \"reflect\" outside allowlist %v (RGT-379)", rel, allowedProdReflect)
			}
		}

		// Inspect AST calls across all files (including _test.go) for shell execution,
		// static file serving, cookies, non-constant format strings, and dynamic SQL formatting.
		for _, decl := range f.Decls {
			fnDecl, _ := decl.(*ast.FuncDecl)
			inFormatWrapper := hasFormatParam(fnDecl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				inClosureWrapper := enclosingFuncLitHasFormatParam(decl, call)

				// Check selector calls: recv.Method(...)
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					fnName := sel.Sel.Name
					pkgIdent, _ := sel.X.(*ast.Ident)
					pkgName := ""
					if pkgIdent != nil {
						pkgName = pkgIdent.Name
					}

					// 1. No shell invocation in exec.Command / exec.CommandContext (RGT-359, RGT-371).
					if pkgName == "exec" && (fnName == "Command" || fnName == "CommandContext") {
						argIdx := 0
						if fnName == "CommandContext" {
							argIdx = 1
						}
						for _, arg := range call.Args[argIdx:] {
							if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
								val, _ := strconv.Unquote(lit.Value)
								if shellNames[val] || shellFlags[val] {
									pos := fset.Position(call.Pos())
									t.Errorf("%s:%d invokes shell binary/flag %q in exec.%s (RGT-371)", rel, pos.Line, val, fnName)
								}
							}
						}
					}

					// 2. No static file servers or cookies in production code (RGT-258, RGT-349).
					if !isTest && pkgName == "http" {
						switch fnName {
						case "FileServer", "FileServerFS", "Dir", "ServeFile", "ServeFileFS", "SetCookie":
							pos := fset.Position(call.Pos())
							t.Errorf("%s:%d uses http.%s in production code", rel, pos.Line, fnName)
						}
					}

					// 3. Format strings across all files (production and tests) must be constant (RGT-375).
					if fmtIdx, ok := formatArgIndex(fnName); ok && fmtIdx < len(call.Args) {
						if !isConstantFormatArg(call.Args[fmtIdx], inFormatWrapper || inClosureWrapper) {
							pos := fset.Position(call.Pos())
							t.Errorf("%s:%d non-constant format string in .%s (RGT-375)", rel, pos.Line, fnName)
						}
					}

					// 4. SQL query methods in production code must never format queries with fmt.Sprintf (RGT-367, RGT-368).
					if !isTest {
						if qIdx, ok := sqlQueryArgIndex(fnName); ok && qIdx < len(call.Args) {
							if isSprintfCall(call.Args[qIdx]) {
								pos := fset.Position(call.Pos())
								t.Errorf("%s:%d passes fmt.Sprintf to SQL method %s (RGT-367/RGT-368)", rel, pos.Line, fnName)
							}
						}
					}
				}

				// Check package-internal variadic format helper functions:
				// fail, newValueError, validationErr, deniedErr, execErr, payloadErr, newErr, newError.
				if ident, ok := call.Fun.(*ast.Ident); ok {
					switch ident.Name {
					case "fail", "newValueError", "validationErr", "deniedErr", "execErr", "payloadErr":
						// Single-arg helpers in internal/hooks (validationErr(msg)) and
						// internal/mcp/sdk_e2e_test.go (fail(msg)) take a plain message, not a format string.
						if len(call.Args) <= 1 && (strings.HasPrefix(rel, "internal/hooks/") || isTest) {
							break
						}
						if len(call.Args) > 0 && !isConstantFormatArg(call.Args[0], inFormatWrapper || inClosureWrapper) {
							pos := fset.Position(call.Pos())
							t.Errorf("%s:%d non-constant format string in %s(...) (RGT-375)", rel, pos.Line, ident.Name)
						}
					case "newErr":
						// captoken.newErr(kind, format, ...) has format at index 1;
						// vault.newErr(kinds, cause, format, ...) has format at index 2.
						fmtIdx := 1
						if strings.HasPrefix(rel, "internal/vault/") {
							fmtIdx = 2
						}
						if fmtIdx < len(call.Args) && !isConstantFormatArg(call.Args[fmtIdx], inFormatWrapper || inClosureWrapper) {
							pos := fset.Position(call.Pos())
							t.Errorf("%s:%d non-constant format string in newErr(...) (RGT-375)", rel, pos.Line)
						}
					case "newError":
						// capabilities.newError(pyClass, cause, kinds, format, a...) has format at index 3.
						if strings.HasPrefix(rel, "internal/capabilities/") && len(call.Args) > 3 {
							if !isConstantFormatArg(call.Args[3], inFormatWrapper || inClosureWrapper) {
								pos := fset.Position(call.Pos())
								t.Errorf("%s:%d non-constant format string in newError(...) (RGT-375)", rel, pos.Line)
							}
						}
					}
				}
				return true
			})
		}
	})

	if !seenUnsafe {
		t.Error("expected to scan internal/providers/dpapi_windows.go importing unsafe")
	}
	if !seenExec {
		t.Error("expected to scan internal/providers/exec.go importing os/exec")
	}
}

func hasFormatParam(fnDecl *ast.FuncDecl) bool {
	if fnDecl == nil || fnDecl.Type.Params == nil {
		return false
	}
	return paramListHasFormat(fnDecl.Type.Params)
}

func paramListHasFormat(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	hasVariadic := false
	for _, field := range params.List {
		if _, ok := field.Type.(*ast.Ellipsis); ok {
			hasVariadic = true
		}
	}
	for _, field := range params.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "string" {
			for _, name := range field.Names {
				if name.Name == "format" || name.Name == "fmtStr" || (hasVariadic && name.Name == "f") {
					return true
				}
			}
		}
	}
	return false
}

func enclosingFuncLitHasFormatParam(root ast.Node, target *ast.CallExpr) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok || !paramListHasFormat(lit.Type.Params) {
			return true
		}
		if target.Pos() >= lit.Pos() && target.End() <= lit.End() {
			found = true
			return false
		}
		return true
	})
	return found
}

// formatArgIndex returns the index of the format string argument for any method
// or package function that takes a printf/scanf format specifier (including
// fmt.*, log.*, testing.TB.*, cobra.Command.Printf, mcp.Server.logf, etc.).
func formatArgIndex(fn string) (int, bool) {
	switch fn {
	case "Printf", "Sprintf", "Errorf", "Fatalf", "Panicf", "Logf", "Skipf", "Scanf", "logf":
		return 0, true
	case "Fprintf", "Fscanf", "Appendf", "Sscanf":
		return 1, true
	}
	return 0, false
}

func sqlQueryArgIndex(fn string) (int, bool) {
	switch fn {
	case "Exec", "Query", "QueryRow":
		return 0, true
	case "ExecContext", "QueryContext", "QueryRowContext":
		return 1, true
	}
	return 0, false
}

// isConstantFormatArg reports whether expr is a constant string literal (or
// binary '+' concatenation thereof), or the forwarded 'format'/'fmtStr' parameter
// inside a format wrapper function or test closure.
func isConstantFormatArg(expr ast.Expr, inFormatWrapper bool) bool {
	if inFormatWrapper {
		if ident, ok := expr.(*ast.Ident); ok && (ident.Name == "format" || ident.Name == "fmtStr" || ident.Name == "f") {
			return true
		}
	}
	return isConstantStringExpr(expr)
}

// isConstantStringExpr reports whether expr is a string literal or a binary `+`
// concatenation of string literals / constant identifiers.
func isConstantStringExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.BinaryExpr:
		return e.Op == token.ADD && isConstantStringExpr(e.X) && isConstantStringExpr(e.Y)
	case *ast.ParenExpr:
		return isConstantStringExpr(e.X)
	}
	return false
}

func isSprintfCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "fmt" && sel.Sel.Name == "Sprintf"
}

// ---------------------------------------------------------------------------
// 3. Command Injection & Output-Free Error Verification on Providers (RGT-371, RGT-242)
// ---------------------------------------------------------------------------

func TestASVS_V5_ProvidersCommandInjectionAndOutputFreeErrors(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "master_secret.priv")
	pub := filepath.Join(dir, "master_secret.pub")
	if err := os.WriteFile(priv, []byte("priv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, []byte("pub"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Hostile PCR bank names must be rejected before any command runs.
	for _, badBank := range []string{"", "sha256; id", "sha256\n", "sha256 && whoami", "../sha256", "SHA256"} {
		if _, err := providers.NewTPMProvider(priv, pub, providers.WithPCRBank(badBank)); err == nil {
			t.Errorf("NewTPMProvider accepted invalid PCR bank %q", badBank)
		}
	}

	// 2. When a tpm2-tools command fails and prints sensitive data, the returned
	// error must carry ONLY the tool name and exit code, never stdout/stderr (RGT-371).
	const leakedMarker = "SENSITIVE_TPM_STDOUT_STDERR_LEAK_MARKER_999"
	runner := func(_ context.Context, name string, args []string, _ []byte) ([]byte, error) {
		for _, a := range args {
			if strings.ContainsAny(a, ";|&`$()") {
				t.Errorf("unexpected shell metacharacter in argv for %s: %v", name, args)
			}
		}
		return []byte(leakedMarker), &providers.ExitError{Code: 1}
	}
	tpmProv, err := providers.NewTPMProvider(priv, pub, providers.WithRunner(runner))
	if err != nil {
		t.Fatalf("NewTPMProvider: %v", err)
	}
	_, err = tpmProv.GetMasterSecret()
	if err == nil {
		t.Fatal("expected TPMProvider.GetMasterSecret error")
	}
	if strings.Contains(err.Error(), leakedMarker) {
		t.Fatalf("TPM error leaked tool output: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("TPM error %q missing exit status", err.Error())
	}

	// 3. macOS security -i stdin serializer must reject control characters,
	// quotes, and backslashes in service, account, and secret (RGT-242, RGT-371).
	noopRunner := func(_ context.Context, _ string, _ []string, _ []byte) ([]byte, error) {
		return nil, nil
	}
	for _, hostile := range []string{
		"svc\nadd-generic-password",
		"svc\r",
		`svc"quoted`,
		`svc'quoted`,
		"svc`cmd`",
		`svc\backslash`,
		"svc\x00null",
	} {
		if err := providers.SealMacOSKeychainWith(noopRunner, []byte("ValidBase64Secret=="), hostile, "acct", true); err == nil {
			t.Errorf("SealMacOSKeychainWith accepted hostile service %q", hostile)
		}
		if err := providers.SealMacOSKeychainWith(noopRunner, []byte("ValidBase64Secret=="), "svc", hostile, true); err == nil {
			t.Errorf("SealMacOSKeychainWith accepted hostile account %q", hostile)
		}
		if err := providers.SealMacOSKeychainWith(noopRunner, []byte(hostile), "svc", "acct", true); err == nil {
			t.Errorf("SealMacOSKeychainWith accepted hostile secret %q", hostile)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Deserialization & Policy YAML Guards (RGT-240, RGT-354, RGT-379)
// ---------------------------------------------------------------------------

func TestASVS_V5_SafeDeserializationGuards(t *testing.T) {
	// 1. Policy YAML size cap (1 MiB MaxPolicyChars).
	oversized := "rules:\n" + strings.Repeat("  - agent: a\n", (policy.MaxPolicyChars/12)+10)
	if _, err := policy.Parse(oversized); !errors.Is(err, policy.ErrTooLarge) {
		t.Errorf("oversized YAML err = %v, want policy.ErrTooLarge", err)
	}

	// 2. Policy YAML rejects arbitrary constructor tags (e.g. PyYAML object injection tags).
	for _, badYAML := range []string{
		"rules:\n  - !!python/object/apply:os.system [\"id\"]\n",
		"rules:\n  - agent: !custom_tag \"agent-a\"\n",
		"rules: \"not-a-list\"\n",
		"rules:\n  - [\"not-a-mapping\"]\n",
		"rules:\n  - agent: 12345\n",
	} {
		if _, err := policy.Parse(badYAML); !errors.Is(err, policy.ErrInvalid) {
			t.Errorf("policy.Parse(%q) err = %v, want policy.ErrInvalid", badYAML, err)
		}
	}

	// 3. Policy YAML rejects alias bombs (>100,000 expanded nodes).
	var bomb strings.Builder
	bomb.WriteString("a0: &a0 [\"x\", \"x\", \"x\", \"x\", \"x\", \"x\", \"x\", \"x\", \"x\", \"x\"]\n")
	for i := 1; i <= 6; i++ {
		bomb.WriteString("a" + strconv.Itoa(i) + ": &a" + strconv.Itoa(i) + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				bomb.WriteString(", ")
			}
			bomb.WriteString("*a" + strconv.Itoa(i-1))
		}
		bomb.WriteString("]\n")
	}
	bomb.WriteString("rules: []\n")
	if _, err := policy.Parse(bomb.String()); !errors.Is(err, policy.ErrInvalid) {
		t.Errorf("YAML alias bomb err = %v, want policy.ErrInvalid", err)
	}

	// 3b. CryptoPolicy YAML parser enforces KnownFields(true) and single-document decoding.
	if _, err := cryptopolicy.Parse([]byte("unknown_field: 123\n")); !errors.Is(err, cryptopolicy.ErrInvalidPolicy) {
		t.Errorf("cryptopolicy.Parse unknown field err = %v, want ErrInvalidPolicy", err)
	}
	if _, err := cryptopolicy.Parse([]byte("cipher: AES-256-GCM\n---\ncipher: AES-256-GCM\n")); !errors.Is(err, cryptopolicy.ErrInvalidPolicy) {
		t.Errorf("cryptopolicy.Parse multi-doc err = %v, want ErrInvalidPolicy", err)
	}

	// 4. Capability token verifier verifies HMAC before parsing JSON and rejects
	// tampered or malformed payloads (RGT-240, RGT-354, RGT-379).
	key := bytes.Repeat([]byte("k"), captoken.MinSecretLen)
	verifier, err := captoken.NewHMACTokenVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify("not-a-token"); !errors.Is(err, captoken.ErrMalformed) {
		t.Errorf("malformed token err = %v, want ErrMalformed", err)
	}
	// Unsigned/forged JSON payload with arbitrary signature is rejected with ErrSignature
	// before payload claims are trusted.
	if _, err := verifier.Verify("eyJ2IjoyLCJhZ2VudF9pZCI6ImFkbWluIn0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, captoken.ErrSignature) {
		t.Errorf("forged token err = %v, want ErrSignature", err)
	}

	// 5. Capability payload schema validators (ParamList, JSONSchema, StructSchema)
	// reject unknown fields and wrong types (RGT-354).
	if err := (capabilities.ParamList{"url", "timeout"}).Validate("http.get", map[string]any{"url": "https://example.com", "evil": 1}); !errors.Is(err, vault.ErrValidation) {
		t.Errorf("ParamList unknown param err = %v, want vault.ErrValidation", err)
	}
	jSchema := capabilities.JSONSchema{
		"required":             []string{"query"},
		"additionalProperties": false,
		"properties": map[string]any{
			"query": map[string]any{"type": "string"},
			"count": map[string]any{"type": "integer"},
		},
	}
	if err := jSchema.Validate("cap", map[string]any{"count": 1}); !errors.Is(err, vault.ErrValidation) {
		t.Errorf("JSONSchema missing required field err = %v, want vault.ErrValidation", err)
	}
	if err := jSchema.Validate("cap", map[string]any{"query": 123}); !errors.Is(err, vault.ErrValidation) {
		t.Errorf("JSONSchema wrong type err = %v, want vault.ErrValidation", err)
	}
	if err := jSchema.Validate("cap", map[string]any{"query": "ok", "extra": true}); !errors.Is(err, vault.ErrValidation) {
		t.Errorf("JSONSchema additionalProperties=false err = %v, want vault.ErrValidation", err)
	}
	type sampleCapPayload struct {
		Target string `json:"target"`
	}
	if err := capabilities.Struct[sampleCapPayload]().Validate("cap", map[string]any{"target": "ok", "unknown": 1}); !errors.Is(err, vault.ErrValidation) {
		t.Errorf("StructSchema unknown field err = %v, want vault.ErrValidation", err)
	}
}

// ---------------------------------------------------------------------------
// 5. HTTP Layer (on real Vault + Per-Agent Token Store): Strict JSON, Duplicate
//    Query Params, Headers, XML Policy, LFI, and Service-Layer Validation
//    (RGT-238, RGT-240, RGT-241, RGT-242, RGT-264, RGT-349, RGT-351, RGT-354, RGT-365, RGT-366, RGT-372, RGT-433)
// ---------------------------------------------------------------------------

func newTestRouter(t *testing.T, maxBody int64) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	policyYAML := `
rules:
  - agent: "agent-alpha"
    namespace: "*"
    purpose: "*"
    action: "*"
    effect: "allow"
`
	v, err := vault.Open(context.Background(), vault.Config{
		DBPath:     filepath.Join(dir, "vault.db"),
		Provider:   newFixedMasterProvider(t),
		PolicyYAML: policyYAML,
		KDFParams:  fastKDFParams,
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	tokStore := auth.OpenStore(filepath.Join(dir, "tokens.json"))
	tok, _, err := tokStore.Mint(auth.MintOptions{
		Agent:  "agent-alpha",
		Scopes: []auth.Scope{auth.ScopeAgent, auth.ScopeAudit, auth.ScopeOperator},
	})
	if err != nil {
		t.Fatalf("tokStore.Mint: %v", err)
	}
	h, err := server.New(server.Config{
		Vault:        v,
		Tokens:       tokStore,
		MaxBodyBytes: maxBody,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return h, tok
}

func doReq(r http.Handler, method, target, tok, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestASVS_V5_HTTPStrictJSONAndBodyLimits(t *testing.T) {
	router, tok := newTestRouter(t, 512)

	// 1. Unknown fields and trailing JSON are rejected with 400 (DisallowUnknownFields);
	// wrong field types are rejected with 422 (RGT-354); hostile identifier characters
	// are rejected by service-layer validation with 400 (RGT-241).
	for _, tc := range []struct {
		path     string
		body     string
		wantCode int
	}{
		{"/v1/secrets", `{"name":"k","value":"v","unexpected_field":"boom"}`, http.StatusBadRequest},
		{"/v1/secrets", `{"name":"k","value":"v"}{"trailing":"json"}`, http.StatusBadRequest},
		{"/v1/secrets", `{"name":123,"value":"v"}`, http.StatusUnprocessableEntity},
		{"/v1/secrets", `{"name":"bad;name","value":"v"}`, http.StatusBadRequest},
		{"/v1/rotate", `{"target":"dek","admin":true}`, http.StatusBadRequest},
		{"/v1/policy/simulate", `{"agent":"agent-alpha","namespace":"default","extra":1}`, http.StatusBadRequest},
	} {
		rec := doReq(router, http.MethodPost, tc.path, tok, tc.body)
		if rec.Code != tc.wantCode {
			t.Errorf("POST %s body=%s: status = %d, want %d (%s)", tc.path, tc.body, rec.Code, tc.wantCode, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "unexpected_field") || strings.Contains(rec.Body.String(), "boom") {
			t.Errorf("POST %s echoed untrusted field name/value: %s", tc.path, rec.Body.String())
		}
	}

	// 2. Oversized body (> 512 bytes) is rejected with 413 RequestTooLarge, both
	// when Content-Length is declared and when streaming with ContentLength = -1.
	oversized := `{"name":"k","value":"` + strings.Repeat("A", 1024) + `"}`
	rec := doReq(router, http.MethodPost, "/v1/secrets", tok, oversized)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversized body status = %d, want 413", rec.Code)
	}

	streamReq := httptest.NewRequest(http.MethodPost, "/v1/secrets", io.NopCloser(strings.NewReader(oversized)))
	streamReq.ContentLength = -1
	streamReq.Header.Set("Authorization", "Bearer "+tok)
	streamRec := httptest.NewRecorder()
	router.ServeHTTP(streamRec, streamReq)
	if streamRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streamed oversized body status = %d, want 413", streamRec.Code)
	}
}

func TestASVS_V5_HTTPDuplicateQueryParameterPrecedence(t *testing.T) {
	// RGT-351: Go's net/url Values.Get and handlers.queryDefault return the FIRST
	// value for a repeated query parameter. Pin this behaviour across the server's
	// query-taking routes (GET /v1/secrets?namespace=... and GET /v1/audit?limit=...).
	router, tok := newTestRouter(t, 0)

	for _, tc := range []struct {
		ns, name, val string
	}{
		{"ns-first", "alpha", "val-first"},
		{"ns-second", "beta", "val-second"},
	} {
		body := `{"name":"` + tc.name + `","value":"` + tc.val + `","namespace":"` + tc.ns + `"}`
		if rec := doReq(router, http.MethodPost, "/v1/secrets", tok, body); rec.Code != http.StatusOK {
			t.Fatalf("seed %s/%s: %d %s", tc.ns, tc.name, rec.Code, rec.Body.String())
		}
	}

	// Duplicate namespace parameter: first ("ns-first") wins.
	rec := doReq(router, http.MethodGet, "/v1/secrets?namespace=ns-first&namespace=ns-second", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/secrets dup namespace: %d", rec.Code)
	}
	var listResp struct {
		Namespace string `json:"namespace"`
		Secrets   []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Namespace != "ns-first" || len(listResp.Secrets) != 1 || listResp.Secrets[0].Name != "alpha" {
		t.Fatalf("duplicate namespace parameter: got %+v, want ns-first/[alpha]", listResp)
	}

	// Duplicate limit parameter on /v1/audit: first ("limit=1") wins over second ("limit=50").
	rec = doReq(router, http.MethodGet, "/v1/audit?limit=1&limit=50", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit dup limit: %d", rec.Code)
	}
	var auditResp struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatal(err)
	}
	if len(auditResp.Entries) != 1 {
		t.Fatalf("duplicate limit parameter: got %d entries, want 1 (first parameter wins)", len(auditResp.Entries))
	}
}

func TestASVS_V5_HTTPSecurityHeadersXMLPolicyAndOutputEscaping(t *testing.T) {
	router, tok := newTestRouter(t, 0)

	// 1. Security headers present on 200, 400, 401, 404, and 405 responses
	// (RGT-365, RGT-366, RGT-433).
	for _, tc := range []struct {
		method, path, token, body string
		wantCode                  int
	}{
		{http.MethodGet, "/healthz", "", "", http.StatusOK},
		{http.MethodGet, "/v1/secrets", "", "", http.StatusUnauthorized},
		{http.MethodPost, "/v1/secrets", tok, `{"bad":1}`, http.StatusBadRequest},
		{http.MethodGet, "/.git/config", tok, "", http.StatusNotFound},
		{http.MethodGet, "/.svn/entries", tok, "", http.StatusNotFound},
		{http.MethodGet, "/.DS_Store", tok, "", http.StatusNotFound},
		{http.MethodTrace, "/v1/secrets", tok, "", http.StatusMethodNotAllowed},
	} {
		rec := doReq(router, tc.method, tc.path, tc.token, tc.body)
		if rec.Code != tc.wantCode {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, rec.Code, tc.wantCode)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s %s: X-Content-Type-Options = %q", tc.method, tc.path, got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s %s: X-Frame-Options = %q", tc.method, tc.path, got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s %s: Referrer-Policy = %q", tc.method, tc.path, got)
		}
		wantCSP := "default-src 'none'; frame-ancestors 'none'; sandbox"
		if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
			t.Errorf("%s %s: CSP = %q, want %q", tc.method, tc.path, got, wantCSP)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s %s: Content-Type = %q, want application/json", tc.method, tc.path, ct)
		}
	}

	// 2. Deprecated client-side technology XML policies blocked with 404 and no-store (RGT-264).
	for _, xmlPath := range []string{"/crossdomain.xml", "/clientaccesspolicy.xml"} {
		rec := doReq(router, http.MethodGet, xmlPath, "", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", xmlPath, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `permitted-cross-domain-policies="none"`) {
			t.Errorf("%s: body missing permitted-cross-domain-policies=\"none\": %s", xmlPath, rec.Body.String())
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store, no-cache, must-revalidate, max-age=0" {
			t.Errorf("%s: Cache-Control = %q", xmlPath, cc)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", xmlPath, got)
		}
	}

	// 3. JSON output escaping of HTML metacharacters (<, >, &) close to the HTTP
	// response writer (RGT-242, RGT-366).
	rec := httptest.NewRecorder()
	server.WriteJSONError(rec, http.StatusBadRequest, "ValidationError", "<script>alert(1)&\"</script>")
	rawBody := rec.Body.String()
	if strings.Contains(rawBody, "<script>") || strings.Contains(rawBody, "</script>") {
		t.Errorf("WriteJSONError did not HTML-escape angle brackets in JSON output: %s", rawBody)
	}
	if !strings.Contains(rawBody, `\u003cscript\u003e`) {
		t.Errorf("expected \\u003cscript\\u003e in JSON response, got: %s", rawBody)
	}
}

// ---------------------------------------------------------------------------
// 6. Validation: Trailing Newline, NFC Normalization, Int Bounds,
//    Audit Sanitizer, TUI Markup, and Netguard Scheme/IP Guard
//    (RGT-239, RGT-241, RGT-242, RGT-365, RGT-372)
// ---------------------------------------------------------------------------

func TestASVS_V5_ValidationTrailingNewlineNFCAndOutputEncoding(t *testing.T) {
	// 1. Trailing-newline rejection in identifiers (Go closes Python's `$` regex quirk).
	for _, s := range []string{"secret\n", "secret\r\n", "\nsecret", "sec\nret", "", "   ", "\t\n"} {
		if _, err := validation.ValidateName(s); !errors.Is(err, validation.ErrValidation) {
			t.Errorf("ValidateName(%q) = %v, want ErrValidation", s, err)
		}
		if _, err := validation.ValidateNamespace(s); !errors.Is(err, validation.ErrValidation) {
			t.Errorf("ValidateNamespace(%q) = %v, want ErrValidation", s, err)
		}
		if _, err := validation.ValidateAgent(s); !errors.Is(err, validation.ErrValidation) {
			t.Errorf("ValidateAgent(%q) = %v, want ErrValidation", s, err)
		}
	}

	// 2. NFC normalization and Unicode category allowlist (RGT-365).
	// NFD "cafe\u0301" (5 code points) normalizes to NFC "caf\u00e9" (4 code points).
	gotNFC, err := validation.ValidateFreeText("cafe\u0301", 4)
	if err != nil {
		t.Fatalf("ValidateFreeText NFD->NFC within 4-rune cap failed: %v", err)
	}
	if gotNFC != "caf\u00e9" {
		t.Fatalf("ValidateFreeText NFD->NFC = %q, want %q", gotNFC, "caf\u00e9")
	}
	// Exceeding the rune limit after NFC normalization is rejected.
	if _, err := validation.ValidateFreeText("cafe\u0301!", 4); !errors.Is(err, validation.ErrValidation) {
		t.Errorf("ValidateFreeText 5-rune NFC with maxLen=4: err = %v, want ErrValidation", err)
	}
	// Non-composable combining marks (Mn), control chars (Cc), format chars (Cf),
	// line separators (Zl/Zp), and invalid UTF-8 are rejected.
	for _, bad := range []string{
		"a\u0301\u0302", // second accent stays Mn after NFC
		"null\x00char",
		"newline\nchar",
		"bidi\u202echar",
		"linesep\u2028char",
		"invalid\xffutf8",
	} {
		if _, err := validation.ValidateFreeText(bad, 128); !errors.Is(err, validation.ErrValidation) {
			t.Errorf("ValidateFreeText(%q) = %v, want ErrValidation", bad, err)
		}
	}

	// 3. Integer bounds reject booleans, floats, strings, and huge integers without
	// echoing >128-bit values into the error message (RGT-239).
	for _, nonInt := range []any{true, false, 3.14, "42", nil, []int{1}} {
		if _, err := validation.ValidateIntBound("limit", nonInt, validation.Limit(1), validation.Limit(1000)); !errors.Is(err, validation.ErrValidation) {
			t.Errorf("ValidateIntBound(%T) = %v, want ErrValidation", nonInt, err)
		}
	}
	hugeNum := json.Number(strings.Repeat("9", 500))
	_, err = validation.ValidateIntBound("limit", hugeNum, validation.Limit(1), validation.Limit(1000))
	if !errors.Is(err, validation.ErrValidation) {
		t.Fatalf("ValidateIntBound(huge) = %v, want ErrValidation", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("9", 100)) {
		t.Errorf("ValidateIntBound error amplified huge untrusted integer: %q", err.Error())
	}

	// 4. Audit log CRLF/tab encoding close to the audit chain interpreter (RGT-242).
	sanitized := audit.Sanitize("ACTION\r\nFAKE_ROW\tDETAILS")
	if strings.ContainsAny(sanitized, "\r\n\t") || sanitized != `ACTION\r\nFAKE_ROW\tDETAILS` {
		t.Errorf("audit.Sanitize = %q", sanitized)
	}

	// 5. TUI output renders Rich-style markup tags literally (Lip Gloss does not
	// interpret inline markup in secret names or audit details, RGT-242).
	view := runTUIViewWithSecret("[bold red]markup_name[/]")
	if !strings.Contains(view, "[bold red]markup_name[/]") {
		t.Errorf("TUI view altered literal bracket text in secret name: %q", view)
	}

	// 6. Netguard + actions outbound URL & header guards reject file://, http://,
	// CRLF header injection, and link-local metadata IPs (RGT-242, RGT-372).
	guard, err := netguard.NewGuard()
	if err != nil {
		t.Fatal(err)
	}
	for _, badURL := range []string{
		"file:///etc/passwd",
		"http://example.com/secret",
		"ftp://example.com/file",
		"https://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1/admin",
		"https://user:pass@example.com/",
	} {
		if _, err := guard.CheckURL(badURL); err == nil {
			t.Errorf("netguard.Guard.CheckURL(%q) succeeded; expected rejection", badURL)
		}
	}
	if _, err := actions.ValidateHeaders(map[string]any{"X-Test": "val\r\nInjected: 1"}, nil); err == nil {
		t.Error("actions.ValidateHeaders accepted CRLF in header value")
	}
	if _, err := actions.ValidateHeaders(map[string]any{"Authorization": "Bearer override"}, nil); err == nil {
		t.Error("actions.ValidateHeaders accepted forbidden Authorization header")
	}
}

type stubTUIClient struct {
	secrets []tui.SecretInfo
}

func (s *stubTUIClient) Health() bool                                 { return true }
func (s *stubTUIClient) VerifyAudit() bool                            { return true }
func (s *stubTUIClient) ListSecrets(string) ([]tui.SecretInfo, error) { return s.secrets, nil }
func (s *stubTUIClient) Rotate(string) error                          { return nil }
func (s *stubTUIClient) GetAuditLog(int) ([]tui.AuditEntry, error)    { return nil, nil }

func runTUIViewWithSecret(name string) string {
	c := &stubTUIClient{secrets: []tui.SecretInfo{{Name: name, Fingerprint: "01234567"}}}
	m := tui.New(c, "default")
	initMsg := m.Init()()
	// tea.Batch returns a slice of tea.Cmd (tea.BatchMsg); execute the first
	// command (loadCmd) and feed its loadedMsg into Update so View() renders
	// the loaded flat-list dashboard.
	val := reflect.ValueOf(initMsg)
	if val.Kind() == reflect.Slice && val.Len() > 0 {
		out := val.Index(0).Call(nil)
		if len(out) == 1 {
			updated, _ := m.Update(out[0].Interface())
			if um, ok := updated.(tui.Model); ok {
				return um.View()
			}
		}
	}
	return m.View()
}
