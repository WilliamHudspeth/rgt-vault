//go:build windows

package secfile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func meSID(t *testing.T) string {
	t.Helper()
	me, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return me.String()
}

// setDACL replaces the DACL of path with the D: part of sddl (protected, so
// nothing is inherited). An empty sddl sets a NULL DACL.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	var dacl *windows.ACL
	if sddl != "" {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("SDDL %q: %v", sddl, err)
		}
		if dacl, _, err = sd.DACL(); err != nil {
			t.Fatal(err)
		}
	}
	err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
}

func newKey(t *testing.T) string {
	t.Helper()
	p := filepath.Join(keyDir(t), "k")
	if err := CreateSecret(p, []byte("k\n")); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCreatedDACL: CreateSecret sets a protected owner+SYSTEM DACL at
// creation time, and the result passes OpenSecret.
func TestCreatedDACL(t *testing.T) {
	p := newKey(t)
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.String()
	if !strings.Contains(s, "D:P") {
		t.Fatalf("DACL not protected: %s", s)
	}
	aces, err := daclACEs(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 2 {
		t.Fatalf("DACL %s: want exactly 2 ACEs (owner + SYSTEM)", s)
	}
	if _, err := OpenSecret(p, Options{}); err != nil {
		t.Fatalf("OpenSecret(created file): %v", err)
	}
}

// TestDACLRefusals is one row per ACL refusal on a real file.
func TestDACLRefusals(t *testing.T) {
	me := meSID(t)
	cases := []struct {
		name, sddl, want string
	}{
		{"everyone", "D:P(A;;FA;;;" + me + ")(A;;FR;;;WD)", "Everyone"},
		{"authenticated-users", "D:P(A;;FA;;;" + me + ")(A;;FR;;;AU)", "Authenticated Users"},
		{"builtin-users", "D:P(A;;FA;;;" + me + ")(A;;FR;;;BU)", "Users"},
		{"other-sid", "D:P(A;;FA;;;" + me + ")(A;;FR;;;S-1-5-21-1-2-3-1001)", "S-1-5-21-1-2-3-1001"},
		{"null-dacl", "", "NULL DACL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newKey(t)
			setDACL(t, p, c.sddl)
			_, err := OpenSecret(p, Options{})
			if !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want ErrInsecure containing %q", err, c.want)
			}
			// The diagnosis escape hatch accepts it, with a warning.
			var warned string
			if _, err := OpenSecret(p, Options{InsecureACL: true, Warn: func(s string) { warned = s }}); err != nil {
				t.Fatalf("InsecureACL: %v", err)
			}
			if !strings.Contains(warned, "RGT_VAULT_INSECURE_KEY_ACL") {
				t.Fatalf("no warning under InsecureACL: %q", warned)
			}
		})
	}
	// Control: a DACL naming only trusted SIDs (and a deny ACE) passes.
	p := newKey(t)
	setDACL(t, p, "D:P(D;;0x2;;;WD)(A;;FA;;;"+me+")(A;;FA;;;SY)(A;;FA;;;BA)")
	if _, err := OpenSecret(p, Options{}); err != nil {
		t.Fatalf("trusted DACL refused: %v", err)
	}
}

// TestSecurityDescriptorRefusals covers owners and DACL shapes a test
// cannot put on a real file without privileges.
func TestSecurityDescriptorRefusals(t *testing.T) {
	me := meSID(t)
	cases := []struct {
		name, sddl, want string
	}{
		{"foreign-owner", "O:BUD:P(A;;FA;;;SY)", "is owned by"},
		{"no-dacl", "O:SY", "no readable DACL"},
		{"null-dacl", "O:SYD:NO_ACCESS_CONTROL", "NULL DACL"},
		{"no-owner", "D:P(A;;FA;;;SY)", "owner"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(c.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = checkSecurity("x", sd)
			if !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want ErrInsecure containing %q", err, c.want)
			}
		})
	}
	for _, owner := range []string{me, "SY", "BA"} {
		sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + me + ")")
		if err != nil {
			t.Fatal(err)
		}
		if err := checkSecurity("x", sd); err != nil {
			t.Fatalf("owner %s refused: %v", owner, err)
		}
	}
}

func TestCheckACE(t *testing.T) {
	trusted, err := trustedSIDs()
	if err != nil {
		t.Fatal(err)
	}
	for ace, ok := range map[string]bool{
		"A;;FA;;;SY":       true,
		"A;;FA;;;BA":       true,
		"D;;FA;;;WD":       true,
		"A;OICIIO;FA;;;WD": true, // inherit-only: does not apply to the file
		"A;;FA;;;WD":       false,
		"A;;FA;;;BU":       false,
		"XA;;FA;;;SY;(x)":  false,
		"OA;;FA;;;SY":      false,
		"A;;FA":            false,
		"A;;FA;;;nope":     false,
	} {
		if got := checkACE(ace, trusted) == nil; got != ok {
			t.Errorf("checkACE(%q) ok = %v, want %v", ace, got, ok)
		}
	}
}

func TestDACLParse(t *testing.T) {
	aces, err := daclACEs("O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)S:AI(AU;SA;FA;;;WD)")
	if err != nil || len(aces) != 2 || aces[1] != "A;;FA;;;BA" {
		t.Fatalf("aces = %v, %v", aces, err)
	}
	for _, bad := range []string{"O:SY", "D:NO_ACCESS_CONTROL", "D:(A;;FA;;;SY", "D:A;;FA;;;SY)"} {
		if _, err := daclACEs(bad); err == nil {
			t.Errorf("daclACEs(%q) succeeded", bad)
		}
	}
}

func TestReparseAndLinks(t *testing.T) {
	p := newKey(t)
	link := filepath.Join(filepath.Dir(p), "link")
	if err := os.Symlink(p, link); err != nil {
		t.Logf("symlink not permitted here (%v); skipping the reparse-point row", err)
	} else if _, err := OpenSecret(link, Options{}); !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("symlink: err = %v", err)
	}
	hard := filepath.Join(filepath.Dir(p), "hard")
	if err := os.Link(p, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSecret(p, Options{}); !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard link: err = %v", err)
	}
	if _, err := OpenSecret(filepath.Dir(p), Options{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("directory: err = %v", err)
	}
	for _, c := range []struct {
		attrs, links uint32
		ok           bool
	}{
		{windows.FILE_ATTRIBUTE_NORMAL, 1, true},
		{windows.FILE_ATTRIBUTE_REPARSE_POINT, 1, false},
		{windows.FILE_ATTRIBUTE_DIRECTORY, 1, false},
		{windows.FILE_ATTRIBUTE_NORMAL, 2, false},
	} {
		if got := checkAttributes("x", c.attrs, c.links) == nil; got != c.ok {
			t.Errorf("checkAttributes(%#x, %d) ok = %v", c.attrs, c.links, got)
		}
	}
}

func TestSecurityAttributesSize(t *testing.T) {
	if got := reflect.TypeOf(windows.SecurityAttributes{}).Size(); uintptr(securityAttributesSize) != got {
		t.Fatalf("securityAttributesSize = %d, sizeof(SecurityAttributes) = %d", securityAttributesSize, got)
	}
}

func TestLockRefusesReparseAndDir(t *testing.T) {
	d := keyDir(t)
	dir := filepath.Join(d, "dir.lock")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); err == nil {
		t.Fatal("Lock(dir) succeeded")
	}
	target := filepath.Join(d, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Logf("symlink not permitted (%v); skipping the reparse row", err)
		return
	}
	if _, err := Lock(link); !errors.Is(err, ErrInsecure) {
		t.Fatalf("Lock(symlink) = %v", err)
	}
}

// Error paths when the current user's SID cannot be read.
func TestNoCurrentUserSID(t *testing.T) {
	d := keyDir(t)
	good := filepath.Join(d, "good")
	if err := CreateSecret(good, []byte("k")); err != nil {
		t.Fatal(err)
	}
	old := currentUserSID
	t.Cleanup(func() { currentUserSID = old })
	currentUserSID = func() (*windows.SID, error) { return nil, errors.New("no token") }
	if err := CreateSecret(filepath.Join(d, "new"), []byte("k")); err == nil {
		t.Fatal("CreateSecret without a user SID succeeded")
	}
	if _, err := Lock(filepath.Join(d, "x.lock")); err == nil {
		t.Fatal("Lock without a user SID succeeded")
	}
	if _, err := OpenSecret(good, Options{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("OpenSecret without a user SID: %v", err)
	}
}

func TestCheckDirChainWindows(t *testing.T) {
	d := keyDir(t)
	f := filepath.Join(d, "f")
	if err := CreateSecret(f, []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := checkDirChain(f); !errors.Is(err, ErrInsecure) {
		t.Fatalf("checkDirChain(file) = %v", err)
	}
	if err := checkDirChain(filepath.Join(d, "missing")); err == nil {
		t.Fatal("checkDirChain(missing) succeeded")
	}
	link := filepath.Join(d, "dirlink")
	if err := os.Symlink(d, link); err == nil {
		if err := checkDirChain(link); !errors.Is(err, ErrInsecure) {
			t.Fatalf("checkDirChain(symlink) = %v", err)
		}
	}
	if err := checkDirChain(d); err != nil {
		t.Fatalf("checkDirChain(dir) = %v", err)
	}
}
