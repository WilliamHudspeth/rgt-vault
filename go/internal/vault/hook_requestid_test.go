package vault

import (
	"go/parser"
	"go/token"
	"regexp"
	"testing"
)

// TestNewRequestIDIsUUIDv4 pins the RFC 4122 version/variant bits and
// uniqueness of newRequestID (ASVS 6.3.2 / RGT-405). The ID is read from
// crypto/rand (see TestASVSV6_NoMathRandInProductionGo, which fails if
// math/rand is imported anywhere in production code).
func TestNewRequestIDIsUUIDv4(t *testing.T) {
	uuid4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		id := newRequestID()
		if !uuid4.MatchString(id) {
			t.Fatalf("newRequestID %q is not an RFC 4122 UUIDv4", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate newRequestID %q", id)
		}
		seen[id] = struct{}{}
	}
}

// TestHookUsesCryptoRand fails if hook.go stops importing crypto/rand or
// starts importing math/rand for request IDs.
func TestHookUsesCryptoRand(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "hook.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var crypto bool
	for _, imp := range f.Imports {
		switch imp.Path.Value {
		case `"crypto/rand"`:
			crypto = true
		case `"math/rand"`, `"math/rand/v2"`:
			t.Fatalf("hook.go imports %s", imp.Path.Value)
		}
	}
	if !crypto {
		t.Fatal("hook.go does not import crypto/rand")
	}
}
