package providers

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestMacOSGetSecret(t *testing.T) {
	r := &fakeRunner{handle: func(c call) ([]byte, error) { return []byte("  s3cret-value \n"), nil }}
	p := NewMacOSKeychainProvider("", "")
	p.run = r.Run
	got, err := p.GetMasterSecret()
	if err != nil || string(got) != "s3cret-value" {
		t.Fatalf("got %q %v", got, err)
	}
	want := []string{"find-generic-password", "-s", "com.agentvault.master", "-a", "master-key", "-w"}
	if len(r.calls) != 1 || r.calls[0].Name != "/usr/bin/security" || !reflect.DeepEqual(r.calls[0].Args, want) {
		t.Fatalf("argv: %v", r.calls)
	}
	if r.calls[0].Stdin != "" {
		t.Fatal("no stdin expected")
	}
}

func TestMacOSGetSecretErrors(t *testing.T) {
	cases := []struct {
		name string
		out  string
		err  error
		want string
	}{
		{"not found", "", &ExitError{Code: 44}, "item not found"},
		{"other exit", "SECRET-LEAK", &ExitError{Code: 36}, "exit status 36"},
		{"missing tool", "", exec.ErrNotFound, "executable not found"},
		{"empty", "  \n", nil, "password is empty"},
	}
	for _, tc := range cases {
		r := &fakeRunner{handle: func(call) ([]byte, error) { return []byte(tc.out), tc.err }}
		p := NewMacOSKeychainProvider("svc", "acct")
		p.run = r.Run
		_, err := p.GetMasterSecret()
		if !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if strings.Contains(err.Error(), "SECRET-LEAK") {
			t.Errorf("%s: error echoes tool output", tc.name)
		}
	}
}

func TestSealMacOS(t *testing.T) {
	r := &fakeRunner{}
	if err := sealMacOS(t.Context(), r.Run, []byte("c2VjcmV0/+=="), "svc", "acct", true, true); err != nil {
		t.Fatal(err)
	}
	c := r.calls[0]
	if c.Name != "/usr/bin/security" || !reflect.DeepEqual(c.Args, []string{"-i"}) {
		t.Fatalf("argv must be just -i (secret never in argv): %v", c)
	}
	want := "add-generic-password -U -s svc -a acct -w c2VjcmV0/+== -T /usr/bin/security\n"
	if c.Stdin != want {
		t.Fatalf("stdin:\n got %q\nwant %q", c.Stdin, want)
	}

	// Not updatable, awkward service name needing quotes.
	r2 := &fakeRunner{}
	if err := sealMacOS(t.Context(), r2.Run, []byte("a b c"), "my svc", "my acct", false, true); err != nil {
		t.Fatal(err)
	}
	want = "add-generic-password -s 'my svc' -a 'my acct' -w 'a b c' -T /usr/bin/security\n"
	if r2.calls[0].Stdin != want {
		t.Fatalf("quoting:\n got %q\nwant %q", r2.calls[0].Stdin, want)
	}
}

func TestSealMacOSValidation(t *testing.T) {
	r := &fakeRunner{}
	bad := map[string][]byte{
		"empty":    nil,
		"newline":  []byte("ab\ncd"),
		"nul":      []byte("a\x00b"),
		"nonascii": []byte("caf\xc3\xa9"),
		"lead":     []byte(" x"),
		"trail":    []byte("x "),
	}
	for name, s := range bad {
		if err := SealMacOSKeychainWith(r.Run, s, "s", "a", false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := sealMacOS(t.Context(), r.Run, []byte("ok"), "", "a", false, true); err == nil {
		t.Error("empty service accepted")
	}
	if err := sealMacOS(t.Context(), r.Run, []byte(strings.Repeat("x", 5000)), "s", "a", false, true); err == nil {
		t.Error("oversized command accepted")
	}
	if len(r.calls) != 0 {
		t.Fatalf("no command may run on invalid input: %v", r.calls)
	}
	// Runner failure is reported without tool output.
	r.handle = func(call) ([]byte, error) { return []byte("LEAK"), &ExitError{Code: 1} }
	err := SealMacOSKeychainWith(r.Run, []byte("ok"), "s", "a", false)
	if err == nil || strings.Contains(err.Error(), "LEAK") || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("seal failure: %v", err)
	}
}

func TestSealMacOSRejectsInjection(t *testing.T) {
	r := &fakeRunner{}
	for name, tc := range map[string][3]string{
		"newline in service": {"s\nlist-keychains", "a", "secret"},
		"cr in account":      {"s", "a\r", "secret"},
		"quote in service":   {"s'x", "a", "secret"},
		"backslash secret":   {"s", "a", `sec\ret`},
		"dquote account":     {"s", `a"b`, "secret"},
		"backtick":           {"s", "a", "se`cret"},
		"del":                {"s", "a", "se\x7fcret"},
	} {
		// validate=false is the keyring-darwin path: it must be checked too.
		if err := sealMacOS(t.Context(), r.Run, []byte(tc[2]), tc[0], tc[1], false, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("security must not run: %v", r.calls)
	}
}

func TestSealMacOSLengthLimit(t *testing.T) {
	r := &fakeRunner{}
	// Build a line of exactly 4096 bytes (incl. the newline): must be refused.
	base := len("add-generic-password -s s -a a -w  -T /usr/bin/security\n")
	if err := sealMacOS(t.Context(), r.Run, []byte(strings.Repeat("x", 4096-base)), "s", "a", false, true); err == nil {
		t.Fatal("4096-byte line accepted")
	}
	if err := sealMacOS(t.Context(), r.Run, []byte(strings.Repeat("x", 4095-base)), "s", "a", false, true); err != nil {
		t.Fatalf("4095-byte line rejected: %v", err)
	}
}

func TestSecurityFindNotFound(t *testing.T) {
	r := &fakeRunner{handle: func(call) ([]byte, error) { return nil, &ExitError{Code: 44} }}
	if _, err := securityFind(t.Context(), r.Run, "s", "a"); !errors.Is(err, errKeyNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":         "''",
		"abc/+=:.": "abc/+=:.",
		"a b":      "'a b'",
		"a$b":      "'a$b'",
		"it's":     `'it'"'"'s'`,
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
