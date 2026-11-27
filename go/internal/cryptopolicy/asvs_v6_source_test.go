package cryptopolicy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/crypto"
	"rgt-vault-server/internal/store"
)

// goModuleRoot locates the go/ directory from go/internal/cryptopolicy.
func goModuleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve go module root: %v", err)
	}
	return root
}

// walkProdGoFiles visits every non-test, non-testdata .go file under go/.
func walkProdGoFiles(t *testing.T, fn func(relSlash string, f *ast.File, fset *token.FileSet)) {
	t.Helper()
	root := goModuleRoot(t)
	fset := token.NewFileSet()
	count := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		count++
		fn(filepath.ToSlash(rel), f, fset)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if count == 0 {
		t.Fatal("expected to scan production .go files under go/, found 0")
	}
}

func importPaths(f *ast.File) []string {
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

// TestASVSV6_NoMathRandInProductionGo verifies ASVS 6.3.1 (RGT-404):
// no non-test Go file may import math/rand or math/rand/v2, with the single
// documented allowlist entry for the temporary cutover gateway's canary
// percentage router (non-security traffic split; slated for removal in GZ).
func TestASVSV6_NoMathRandInProductionGo(t *testing.T) {
	allowlist := map[string]string{
		"internal/gateway/gateway.go": "non-cryptographic canary traffic percentage split (rand.IntN(100)); slated for deletion in GZ (D10)",
	}

	seen := map[string]bool{}
	walkProdGoFiles(t, func(rel string, f *ast.File, _ *token.FileSet) {
		for _, imp := range importPaths(f) {
			if imp != "math/rand" && imp != "math/rand/v2" {
				continue
			}
			seen[rel] = true
			if _, ok := allowlist[rel]; !ok {
				t.Errorf("ASVS 6.3.1 violation: %s imports %q (must use crypto/rand)", rel, imp)
			}
		}
	})

	// Ensure allowlist stays accurate: if gateway.go is removed or stops using
	// math/rand/v2, fail so the stale allowlist entry is cleaned up.
	for rel := range allowlist {
		if !seen[rel] {
			t.Errorf("stale math/rand allowlist entry %q — remove it from the allowlist", rel)
		}
	}
}

// TestASVSV6_NoObsoleteCryptoAlgorithms verifies ASVS 6.2.5 (RGT-400) & 6.2.2 (RGT-397):
// no non-test Go file under go/ imports MD5, SHA-1, DES, RC4, MD4, RIPEMD-160,
// Blowfish, CAST5, TEA/XTEA, or uses non-AEAD block modes (CBC/CFB/OFB/CTR/ECB).
// The ONLY allowlisted entry is internal/totp/totp.go importing crypto/sha1
// strictly for RFC 6238 TOTP HMAC-SHA1 interoperability.
func TestASVSV6_NoObsoleteCryptoAlgorithms(t *testing.T) {
	forbiddenImports := map[string]bool{
		"crypto/md5":                    true,
		"crypto/sha1":                   true,
		"crypto/des":                    true,
		"crypto/rc4":                    true,
		"golang.org/x/crypto/md4":       true,
		"golang.org/x/crypto/ripemd160": true,
		"golang.org/x/crypto/blowfish":  true,
		"golang.org/x/crypto/cast5":     true,
		"golang.org/x/crypto/tea":       true,
		"golang.org/x/crypto/xtea":      true,
	}
	allowSHA1 := map[string]string{
		"internal/totp/totp.go": "RFC 6238 TOTP default HMAC-SHA1 interoperability (HMAC-SHA1 is not vulnerable to SHA-1 collision attacks; SHA256/SHA512 also supported)",
	}
	forbiddenCipherModes := map[string]bool{
		"NewCBCEncrypter": true,
		"NewCBCDecrypter": true,
		"NewCFBEncrypter": true,
		"NewCFBDecrypter": true,
		"NewOFB":          true,
		"NewCTR":          true,
	}

	seenSHA1 := map[string]bool{}
	walkProdGoFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		cipherAliases := map[string]bool{}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if p == "crypto/cipher" {
				alias := "cipher"
				if imp.Name != nil && imp.Name.Name != "" {
					alias = imp.Name.Name
				}
				cipherAliases[alias] = true
			}
			if forbiddenImports[p] {
				if p == "crypto/sha1" {
					seenSHA1[rel] = true
					if _, ok := allowSHA1[rel]; ok {
						continue
					}
				}
				t.Errorf("ASVS 6.2.5 violation: %s imports obsolete algorithm package %q", rel, p)
			}
		}

		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && cipherAliases[id.Name] && forbiddenCipherModes[sel.Sel.Name] {
				pos := fset.Position(sel.Pos())
				t.Errorf("ASVS 6.2.5 violation: %s:%d uses non-AEAD cipher mode %s.%s", rel, pos.Line, id.Name, sel.Sel.Name)
			}
			return true
		})
	})

	for rel := range allowSHA1 {
		if !seenSHA1[rel] {
			t.Errorf("stale crypto/sha1 allowlist entry %q", rel)
		}
	}
}

// TestASVSV6_AESGCMOnly32ByteKeys verifies ASVS 6.2.3 (RGT-398) & 6.2.7 (RGT-402):
// (1) crypto/aes is only imported in internal/crypto/crypto.go,
// internal/keychain/keychain.go and the crypto-audit reference parser
// (cmd/rgt-vault/cryptoaudit_probe.go, which opens real repo ciphertext with
// an independent stdlib GCM); each wraps the block cipher in cipher.NewGCM
// (no ECB/CBC); (2) crypto.Encrypt and crypto.Decrypt reject
// every key size other than 32 bytes (AES-256).
func TestASVSV6_AESGCMOnly32ByteKeys(t *testing.T) {
	allowedAES := map[string]bool{
		"internal/crypto/crypto.go":          true,
		"internal/keychain/keychain.go":      true,
		"cmd/rgt-vault/cryptoaudit_probe.go": true,
	}
	seenAES := map[string]bool{}

	walkProdGoFiles(t, func(rel string, f *ast.File, _ *token.FileSet) {
		importsAES := false
		for _, imp := range importPaths(f) {
			if imp == "crypto/aes" {
				importsAES = true
			}
		}
		if !importsAES {
			return
		}
		seenAES[rel] = true
		if !allowedAES[rel] {
			t.Errorf("unexpected crypto/aes import in %s", rel)
		}
		// Verify cipher.NewGCM is called in every file importing crypto/aes
		// and raw block.Encrypt / block.Decrypt (ECB) is never called.
		hasGCM := false
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "NewGCM" {
				hasGCM = true
			}
			// crypto.Encrypt / crypto.Decrypt are the repo's AES-GCM wrappers,
			// not raw block operations.
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "crypto" {
				return true
			}
			if sel.Sel.Name == "Encrypt" || sel.Sel.Name == "Decrypt" {
				t.Errorf("raw AES block.%s (ECB) found in %s", sel.Sel.Name, rel)
			}
			return true
		})
		if !hasGCM {
			t.Errorf("%s imports crypto/aes without calling cipher.NewGCM", rel)
		}
	})
	for rel := range allowedAES {
		if !seenAES[rel] {
			t.Errorf("expected %s to import crypto/aes", rel)
		}
	}

	// Runtime enforcement: only 32-byte (AES-256) keys are accepted.
	key32 := make([]byte, 32)
	if _, err := rand.Read(key32); err != nil {
		t.Fatal(err)
	}
	validCT, err := crypto.Encrypt([]byte("probe"), key32, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt(32B): %v", err)
	}
	for _, badSize := range []int{0, 1, 16, 24, 31, 33, 64} {
		k := make([]byte, badSize)
		if _, err := crypto.Encrypt([]byte("probe"), k, []byte("aad")); !errors.Is(err, crypto.ErrInvalidDEKLength) {
			t.Errorf("Encrypt with %d-byte key: got %v, want ErrInvalidDEKLength", badSize, err)
		}
		if _, err := crypto.Decrypt(validCT, k, []byte("aad")); !errors.Is(err, crypto.ErrInvalidDEKLength) {
			t.Errorf("Decrypt with %d-byte key: got %v, want ErrInvalidDEKLength", badSize, err)
		}
	}
}

// TestASVSV6_CSPRNGConcurrentLoad verifies ASVS 6.3.3 (RGT-406) against repo
// code: under heavy concurrency the repo's own generators (crypto.Encrypt
// nonces, auth.GenerateToken bearer tokens, captoken.NewTokenID,
// approval.NewRequest IDs) never error, never produce an all-zero value and
// never repeat. It is a -race smoke test of repo consumers of crypto/rand,
// not a proof about the OS CSPRNG itself (Go >= 1.24 crypto/rand is
// non-blocking and aborts the process if the OS source fails).
func TestASVSV6_CSPRNGConcurrentLoad(t *testing.T) {
	const (
		goroutines = 32
		perWorker  = 100
	)
	dek := bytes.Repeat([]byte{0x42}, 32)
	aad := []byte("concurrent-load")

	type draw struct {
		nonce [12]byte
		token string
		tokID string
		reqID string
	}
	results := make([]draw, goroutines*perWorker)
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			base := worker * perWorker
			for i := 0; i < perWorker; i++ {
				ct, err := crypto.Encrypt([]byte("x"), dek, aad)
				if err != nil {
					errs <- err
					return
				}
				copy(results[base+i].nonce[:], ct[:12])
				tok, err := auth.GenerateToken()
				if err != nil {
					errs <- err
					return
				}
				results[base+i].token = tok
				results[base+i].tokID = captoken.NewTokenID()
				results[base+i].reqID = approval.NewRequest("agent", "default", "s", "p").RequestID
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent repo generator failed: %v", err)
	}

	nonces := make(map[[12]byte]struct{}, len(results))
	tokens := make(map[string]struct{}, len(results))
	tokIDs := make(map[string]struct{}, len(results))
	reqIDs := make(map[string]struct{}, len(results))
	var zero [12]byte
	for i, r := range results {
		if r.nonce == zero {
			t.Fatalf("draw %d: all-zero AES-GCM nonce", i)
		}
		if _, dup := nonces[r.nonce]; dup {
			t.Fatalf("draw %d: duplicate AES-GCM nonce", i)
		}
		nonces[r.nonce] = struct{}{}
		if r.token == "" {
			t.Fatalf("draw %d: empty bearer token", i)
		}
		for _, c := range []struct {
			name string
			set  map[string]struct{}
			v    string
		}{{"bearer token", tokens, r.token}, {"captoken id", tokIDs, r.tokID}, {"approval request id", reqIDs, r.reqID}} {
			if _, dup := c.set[c.v]; dup {
				t.Fatalf("draw %d: duplicate %s", i, c.name)
			}
			c.set[c.v] = struct{}{}
		}
	}
}

// TestASVSV6_UUIDv4CSPRNG verifies ASVS 6.3.2 (RGT-405):
// random GUIDs generated across store (vault_id, secret_id), approval
// (RequestID), and captoken (v1 TokenID) conform to RFC 4122 v4 and are unique.
func TestASVSV6_UUIDv4CSPRNG(t *testing.T) {
	uuid4Hyphen := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	uuid4Hex := regexp.MustCompile(`^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$`)

	// 1. approval.NewRequest RequestID (RFC 4122 v4 hyphenated)
	seenReq := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := approval.NewRequest("agent", "default", "s", "p").RequestID
		if !uuid4Hyphen.MatchString(id) {
			t.Fatalf("approval RequestID %q is not RFC 4122 UUIDv4", id)
		}
		if _, dup := seenReq[id]; dup {
			t.Fatalf("duplicate approval RequestID %q", id)
		}
		seenReq[id] = struct{}{}
	}

	// 2. captoken.NewTokenID (RFC 4122 v4 hex, matching Python uuid4().hex)
	seenTok := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := captoken.NewTokenID()
		if !uuid4Hex.MatchString(id) {
			t.Fatalf("captoken TokenID %q is not RFC 4122 UUIDv4 hex", id)
		}
		if _, dup := seenTok[id]; dup {
			t.Fatalf("duplicate captoken TokenID %q", id)
		}
		seenTok[id] = struct{}{}
	}

	// 3. store vault_id and secret_id (RFC 4122 v4 hyphenated)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	vid, err := st.VaultID(ctx)
	if err != nil {
		t.Fatalf("VaultID: %v", err)
	}
	if !uuid4Hyphen.MatchString(vid) {
		t.Fatalf("vault_id %q is not RFC 4122 UUIDv4", vid)
	}

	seenSec := make(map[string]struct{}, 20)
	for i := 0; i < 20; i++ {
		name := "sec_" + strconv.Itoa(i)
		if _, err := st.SetSecret(ctx, store.SetSecretParams{
			Namespace:  "default",
			Name:       name,
			Ciphertext: []byte("dummy-ct-for-uuid-test"),
			DEKVersion: 1,
		}); err != nil {
			t.Fatalf("SetSecret(%s): %v", name, err)
		}
	}
	infos, err := st.ListSecrets(ctx, "default", "", 100, 0)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(infos) != 20 {
		t.Fatalf("ListSecrets returned %d items, want 20", len(infos))
	}
	for _, info := range infos {
		if !uuid4Hyphen.MatchString(info.SecretID) {
			t.Fatalf("secret_id %q is not RFC 4122 UUIDv4", info.SecretID)
		}
		if _, dup := seenSec[info.SecretID]; dup {
			t.Fatalf("duplicate secret_id %q", info.SecretID)
		}
		seenSec[info.SecretID] = struct{}{}
	}
}
