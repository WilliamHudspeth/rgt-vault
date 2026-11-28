package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goRoot is the go/ module root (this file lives in go/internal/transport).
func goRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// productionGoFiles are the non-test Go sources of the module.
func productionGoFiles(t *testing.T) []string {
	t.Helper()
	root := goRoot(t)
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == "testdata" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 50 {
		t.Fatalf("found only %d Go files under %s: wrong root?", len(files), root)
	}
	return files
}

// A source scan (CodeQL go/insecure-tls, ASVS 9.1.x): no production code may
// disable certificate verification, pin a legacy protocol version, or build a
// tls.Config without a MinVersion of at least TLS 1.2.
func TestSourceScanNoInsecureTLS(t *testing.T) {
	fset := token.NewFileSet()
	var literals int
	for _, path := range productionGoFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(goRoot(t), path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "InsecureSkipVerify" || x.Name == "InsecureSkipTimeVerify" {
					t.Errorf("%s:%s: %s is forbidden: certificate verification must stay on",
						rel, fset.Position(x.Pos()), x.Name)
				}
			case *ast.SelectorExpr:
				if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "tls" {
					switch x.Sel.Name {
					case "VersionSSL30", "VersionTLS10", "VersionTLS11":
						t.Errorf("%s:%s: tls.%s is below the TLS 1.2 floor", rel, fset.Position(x.Pos()), x.Sel.Name)
					case "InsecureCipherSuites", "RenegotiateFreelyAsClient":
						t.Errorf("%s:%s: tls.%s is forbidden", rel, fset.Position(x.Pos()), x.Sel.Name)
					}
					if strings.HasPrefix(x.Sel.Name, "TLS_RSA_") || strings.Contains(x.Sel.Name, "_CBC_") ||
						strings.Contains(x.Sel.Name, "RC4") || strings.Contains(x.Sel.Name, "3DES") {
						t.Errorf("%s:%s: tls.%s is not an AEAD ECDHE suite", rel, fset.Position(x.Pos()), x.Sel.Name)
					}
				}
			case *ast.CompositeLit:
				sel, ok := x.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Config" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "tls" {
					return true
				}
				literals++
				var hasMin bool
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "MinVersion" {
							hasMin = true
						}
					}
				}
				if !hasMin {
					t.Errorf("%s:%s: tls.Config literal without MinVersion", rel, fset.Position(x.Pos()))
				}
			}
			return true
		})
	}
	if literals == 0 {
		t.Error("the scan found no tls.Config literal: it is not looking at the code")
	}
}

// The scan above would be worthless if it missed the patterns it targets.
func TestSourceScanDetectsViolations(t *testing.T) {
	src := `package x
import "crypto/tls"
var a = &tls.Config{InsecureSkipVerify: true}
var b = &tls.Config{MinVersion: tls.VersionTLS10}
var c = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var skip, old, rsa, nomin int
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "InsecureSkipVerify" {
				skip++
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "VersionTLS10" {
				old++
			}
			if strings.HasPrefix(x.Sel.Name, "TLS_RSA_") {
				rsa++
			}
		case *ast.CompositeLit:
			if sel, ok := x.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Config" {
				has := false
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok && kv.Key.(*ast.Ident).Name == "MinVersion" {
						has = true
					}
				}
				if !has {
					nomin++
				}
			}
		}
		return true
	})
	if skip != 1 || old != 1 || rsa != 1 || nomin != 1 {
		t.Errorf("detector found skip=%d old=%d rsa=%d nomin=%d, want 1 each", skip, old, rsa, nomin)
	}
}
