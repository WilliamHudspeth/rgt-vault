package providers

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// argAfter returns the value following flag in c.Args.
func argAfter(t *testing.T, c call, flag string) string {
	t.Helper()
	for i, a := range c.Args {
		if a == flag && i+1 < len(c.Args) {
			return c.Args[i+1]
		}
	}
	t.Fatalf("%s: flag %s not found in %v", c.Name, flag, c.Args)
	return ""
}

// fakeTPM simulates the tpm2-tools: it creates the context files the real
// tools would, and writes the "unsealed" secret to the -o file. It records
// the permission bits of the unseal file at the time of tpm2_unseal.
type fakeTPM struct {
	*fakeRunner
	secret      []byte
	unsealMode  os.FileMode
	scratchMode os.FileMode
	failTool    string
	failErr     error
	failStdout  string
}

func newFakeTPM(secret []byte) *fakeTPM {
	f := &fakeTPM{fakeRunner: &fakeRunner{}, secret: secret}
	f.handle = func(c call) ([]byte, error) {
		if c.Name == f.failTool {
			return []byte(f.failStdout), f.failErr
		}
		switch c.Name {
		case "tpm2_createprimary", "tpm2_load", "tpm2_startauthsession":
			// The real tools save a context file; do the same.
			flag := map[string]string{"tpm2_createprimary": "-c", "tpm2_load": "-c", "tpm2_startauthsession": "-S"}[c.Name]
			_ = os.WriteFile(argAfter(&testing.T{}, c, flag), []byte("ctx"), 0o600)
		case "tpm2_unseal":
			out := argAfter(&testing.T{}, c, "-o")
			if fi, err := os.Stat(out); err == nil {
				f.unsealMode = fi.Mode().Perm()
			}
			if fi, err := os.Stat(filepath.Dir(out)); err == nil {
				f.scratchMode = fi.Mode().Perm()
			}
			_ = os.WriteFile(out, f.secret, 0o600)
		case "tpm2_create":
			_ = os.WriteFile(argAfter(&testing.T{}, c, "-u"), []byte("pub"), 0o600)
			_ = os.WriteFile(argAfter(&testing.T{}, c, "-r"), []byte("priv"), 0o600)
		case "tpm2_createpolicy":
			_ = os.WriteFile(argAfter(&testing.T{}, c, "-L"), []byte("digest"), 0o600)
		}
		return nil, nil
	}
	return f
}

func sealedFixture(t *testing.T) (dir, priv, pub string) {
	t.Helper()
	dir = t.TempDir()
	priv = filepath.Join(dir, "master_secret.priv")
	pub = filepath.Join(dir, "master_secret.pub")
	if err := os.WriteFile(priv, []byte("priv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, []byte("pub"), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestTPMUnsealSequence(t *testing.T) {
	dir, priv, pub := sealedFixture(t)
	secret := bytes.Repeat([]byte{0xAB}, 32)
	f := newFakeTPM(secret)
	p, err := NewTPMProvider(priv, pub, WithRunner(f.Run))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.GetMasterSecret()
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("got %x %v", got, err)
	}

	// Exact tool order of python/providers/linux_tpm.py get_secret.
	var main []string
	for _, c := range f.calls {
		if c.Name != "tpm2_flushcontext" {
			main = append(main, c.Name)
		}
	}
	wantOrder := []string{"tpm2_createprimary", "tpm2_load", "tpm2_startauthsession", "tpm2_policypcr", "tpm2_unseal"}
	if !reflect.DeepEqual(main, wantOrder) {
		t.Fatalf("order: %v", main)
	}
	byName := map[string]call{}
	for _, c := range f.calls {
		byName[c.Name] = c
	}
	prim := argAfter(t, byName["tpm2_createprimary"], "-c")
	child := argAfter(t, byName["tpm2_load"], "-c")
	sess := argAfter(t, byName["tpm2_startauthsession"], "-S")
	out := argAfter(t, byName["tpm2_unseal"], "-o")

	want := map[string][]string{
		"tpm2_createprimary":    {"-C", "o", "-G", "rsa", "-c", prim},
		"tpm2_load":             {"-C", prim, "-u", pub, "-r", priv, "-c", child},
		"tpm2_startauthsession": {"--policy-session", "-S", sess},
		"tpm2_policypcr":        {"-S", sess, "-l", "sha256:0+sha256:7"},
		"tpm2_unseal":           {"-c", child, "-o", out, "-p", "session:" + sess},
	}
	for name, args := range want {
		if !reflect.DeepEqual(byName[name].Args, args) {
			t.Errorf("%s argv:\n got %v\nwant %v", name, byName[name].Args, args)
		}
	}
	scratch := filepath.Dir(out)
	for _, p := range []string{prim, child, sess} {
		if filepath.Dir(p) != scratch {
			t.Errorf("%s must live in the private scratch dir %s", p, scratch)
		}
	}
	if filepath.Dir(scratch) != dir || !strings.HasPrefix(filepath.Base(scratch), ".rgt-tpm-") {
		t.Errorf("scratch dir %s must be created beside the sealed blobs", scratch)
	}
	if fi, err := os.Stat(scratch); err == nil || !os.IsNotExist(err) {
		_ = fi
		t.Errorf("scratch dir not removed: %v", err)
	}
	if f.scratchMode != 0o700 {
		t.Errorf("scratch dir mode %v, want 0700", f.scratchMode)
	}
	if f.unsealMode != 0o600 {
		t.Errorf("unseal file mode %v, want 0600", f.unsealMode)
	}
	// "-T" (explicit TCTI) must not be passed, as in Python.
	for _, c := range f.calls {
		for _, a := range c.Args {
			if a == "-T" {
				t.Errorf("%s passes -T", c.Name)
			}
		}
	}

	// All three contexts were flushed while their files still existed, and
	// nothing is left behind.
	flushed := 0
	for _, c := range f.calls {
		if c.Name == "tpm2_flushcontext" {
			flushed++
			// Positional saved-context argument (tpm2-tools >= 4).
			if len(c.Args) != 1 || !strings.HasSuffix(c.Args[0], ".ctx") {
				t.Errorf("flush argv %v", c.Args)
			}
		}
	}
	if flushed != 3 {
		t.Errorf("flushed %d contexts, want 3", flushed)
	}
	if left := dirNames(t, dir); !reflect.DeepEqual(left, []string{"master_secret.priv", "master_secret.pub"}) {
		t.Fatalf("leftover files: %v", left)
	}
}

func TestTPMUsesPCRFileAndBank(t *testing.T) {
	_, priv, pub := sealedFixture(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(priv), "master_secret.pcrs"), []byte("1 2  5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFakeTPM([]byte("secret"))
	p, err := NewTPMProvider(priv, pub, WithRunner(f.Run), WithPCRBank("sha1"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.PCRList, []int{1, 2, 5}) {
		t.Fatalf("PCRList %v", p.PCRList)
	}
	if _, err := p.GetMasterSecret(); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if c.Name == "tpm2_policypcr" && argAfter(t, c, "-l") != "sha1:1+sha1:2+sha1:5" {
			t.Fatalf("policy spec: %v", c.Args)
		}
	}
}

func TestTPMPCRFileFallbacks(t *testing.T) {
	for name, content := range map[string]string{
		"empty": "\n", "garbage": "a b", "negative": "-1 7", "huge": "99", "": ""} {
		_, priv, pub := sealedFixture(t)
		if name != "" {
			_ = os.WriteFile(filepath.Join(filepath.Dir(priv), "master_secret.pcrs"), []byte(content), 0o600)
		}
		p, err := NewTPMProvider(priv, pub)
		if err != nil || !reflect.DeepEqual(p.PCRList, []int{0, 7}) {
			t.Errorf("%q: %v %v", name, p.PCRList, err)
		}
	}
}

func TestNewTPMProviderErrors(t *testing.T) {
	dir, priv, pub := sealedFixture(t)
	if _, err := NewTPMProvider(filepath.Join(dir, "x.priv"), pub); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing priv: %v", err)
	}
	if _, err := NewTPMProvider(priv, filepath.Join(dir, "x.pub")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing pub: %v", err)
	}
	for _, bank := range []string{"", "SHA256", "sha256:0", "--x"} {
		if _, err := NewTPMProvider(priv, pub, WithPCRBank(bank)); err == nil {
			t.Errorf("bank %q accepted", bank)
		}
	}
}

func TestPCRsPath(t *testing.T) {
	for in, want := range map[string]string{
		"/a/master_secret.priv": "/a/master_secret.pcrs",
		"/a/blob":               "/a/blob.pcrs",
		"/a/.priv":              "/a/.priv.pcrs",
		"/a.d/blob":             "/a.d/blob.pcrs",
		"/a/x.tar.gz":           "/a/x.tar.pcrs",
	} {
		if got := pcrsPath(in); got != want {
			t.Errorf("pcrsPath(%q) = %q want %q", in, got, want)
		}
	}
}

func TestTPMErrorsDoNotEchoToolOutput(t *testing.T) {
	const leak = "SUPER-SECRET-STDOUT"
	for _, tool := range []string{"tpm2_createprimary", "tpm2_load", "tpm2_startauthsession", "tpm2_policypcr", "tpm2_unseal"} {
		_, priv, pub := sealedFixture(t)
		f := newFakeTPM([]byte("s"))
		f.failTool, f.failErr, f.failStdout = tool, &ExitError{Code: 1}, leak
		p, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
		_, err := p.GetMasterSecret()
		if !errors.Is(err, ErrTPM) {
			t.Fatalf("%s: %v", tool, err)
		}
		msg := err.Error()
		if strings.Contains(msg, leak) || !strings.Contains(msg, tool) || !strings.Contains(msg, "exit status 1") {
			t.Errorf("%s: message %q", tool, msg)
		}
		// No scratch leftovers even on failure.
		if left := dirNames(t, filepath.Dir(priv)); len(left) != 2 {
			t.Errorf("%s: leftovers %v", tool, left)
		}
	}
}

func TestTPMToolMissingAndPermission(t *testing.T) {
	_, priv, pub := sealedFixture(t)
	f := newFakeTPM(nil)
	f.failTool, f.failErr = "tpm2_createprimary", exec.ErrNotFound
	p, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrTPM) || !strings.Contains(err.Error(), "tpm2-tools not found") {
		t.Fatalf("not found: %v", err)
	}
	f.failErr = fs.ErrPermission
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrTPM) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("permission: %v", err)
	}
}

func TestTPMEmptyUnsealRejected(t *testing.T) {
	_, priv, pub := sealedFixture(t)
	f := newFakeTPM(nil) // unseal writes zero bytes
	p, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrTPM) || !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("empty: %v", err)
	}
}

func TestTPMUnsealCannotCreateScratch(t *testing.T) {
	_, priv, pub := sealedFixture(t)
	p, _ := NewTPMProvider(priv, pub, WithRunner(newFakeTPM([]byte("s")).Run))
	p.PrivatePath = filepath.Join(t.TempDir(), "missing-dir", "x.priv")
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrTPM) {
		t.Fatalf("got %v", err)
	}
}

func TestTPMUnsealReadFailure(t *testing.T) {
	_, priv, pub := sealedFixture(t)
	f := newFakeTPM([]byte("s"))
	inner := f.handle
	f.handle = func(c call) ([]byte, error) {
		if c.Name == "tpm2_unseal" {
			_ = os.Remove(argAfter(t, c, "-o")) // tool "succeeded" but produced no file
			return nil, nil
		}
		return inner(c)
	}
	p, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrTPM) {
		t.Fatalf("got %v", err)
	}
}

func TestSealTPM(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sealed", "nested")
	f := newFakeTPM(nil)
	var secretAtCreate []byte
	var modeAtCreate os.FileMode
	inner := f.handle
	f.handle = func(c call) ([]byte, error) {
		if c.Name == "tpm2_create" {
			in := argAfter(t, c, "-i")
			secretAtCreate, _ = os.ReadFile(in)
			fi, _ := os.Stat(in)
			modeAtCreate = fi.Mode().Perm()
		}
		return inner(c)
	}
	secret := bytes.Repeat([]byte{7}, 32)
	priv, pub, err := sealTPM(t.Context(), f.Run, secret, out, []int{0, 2, 7}, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if priv != filepath.Join(out, "master_secret.priv") || pub != filepath.Join(out, "master_secret.pub") {
		t.Fatalf("paths %s %s", priv, pub)
	}
	if !bytes.Equal(secretAtCreate, secret) || modeAtCreate != 0o600 {
		t.Fatalf("seal input file: %x mode %v", secretAtCreate, modeAtCreate)
	}
	if !reflect.DeepEqual(f.names(), []string{"tpm2_createpolicy", "tpm2_createprimary", "tpm2_create", "tpm2_flushcontext"}) {
		t.Fatalf("order %v", f.names())
	}
	byName := map[string]call{}
	for _, c := range f.calls {
		byName[c.Name] = c
	}
	secretFile := argAfter(t, byName["tpm2_create"], "-i")
	scratch := filepath.Dir(secretFile)
	digest := filepath.Join(scratch, "policy.digest")
	primary := filepath.Join(scratch, "primary.ctx")
	if filepath.Dir(scratch) != out {
		t.Errorf("seal scratch %s must be inside the output dir", scratch)
	}
	wantArgs := map[string][]string{
		"tpm2_createpolicy":  {"--policy-pcr", "-l", "sha256:0+sha256:2+sha256:7", "-L", digest},
		"tpm2_createprimary": {"-C", "o", "-G", "rsa", "-c", primary},
		"tpm2_create":        {"-C", primary, "-i", secretFile, "-u", pub, "-r", priv, "-L", digest, "-g", "sha256"},
		"tpm2_flushcontext":  {"-t"},
	}
	for n, a := range wantArgs {
		if !reflect.DeepEqual(byName[n].Args, a) {
			t.Errorf("%s argv:\n got %v\nwant %v", n, byName[n].Args, a)
		}
	}
	pcrs, _ := os.ReadFile(filepath.Join(out, "master_secret.pcrs"))
	if string(pcrs) != "0 2 7\n" {
		t.Fatalf("pcrs file %q", pcrs)
	}
	if left := dirNames(t, out); !reflect.DeepEqual(left, []string{"master_secret.pcrs", "master_secret.priv", "master_secret.pub"}) {
		t.Fatalf("leftover scratch: %v", left)
	}

	// The provider picks the persisted PCR list up again.
	p, err := NewTPMProvider(priv, pub, WithRunner(newFakeTPM(secret).Run))
	if err != nil || !reflect.DeepEqual(p.PCRList, []int{0, 2, 7}) {
		t.Fatalf("reload: %v %v", p.PCRList, err)
	}
}

func TestSealTPMDefaultsAndValidation(t *testing.T) {
	out := t.TempDir()
	f := newFakeTPM(nil)
	if _, _, err := sealTPM(t.Context(), f.Run, []byte("s"), out, nil, ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if c.Name == "tpm2_createpolicy" && argAfter(t, c, "-l") != "sha256:0+sha256:7" {
			t.Fatalf("defaults: %v", c.Args)
		}
	}
	for _, bad := range []int{-1, 32} {
		if _, _, err := sealTPM(t.Context(), f.Run, []byte("s"), out, []int{bad}, ""); err == nil {
			t.Errorf("pcr %d accepted", bad)
		}
	}
	if _, _, err := sealTPM(t.Context(), f.Run, []byte("s"), out, nil, "bad bank"); err == nil {
		t.Error("bad bank accepted")
	}
	file := filepath.Join(out, "afile")
	_ = os.WriteFile(file, nil, 0o600)
	if _, _, err := sealTPM(t.Context(), f.Run, []byte("s"), filepath.Join(file, "sub"), nil, ""); err == nil {
		t.Error("mkdir failure not reported")
	}
}

func TestSealTPMToolFailure(t *testing.T) {
	const leak = "LEAK-IN-STDOUT"
	for _, tool := range []string{"tpm2_createpolicy", "tpm2_createprimary", "tpm2_create"} {
		out := t.TempDir()
		f := newFakeTPM(nil)
		f.failTool, f.failErr, f.failStdout = tool, &ExitError{Code: 2}, leak
		_, _, err := sealTPM(t.Context(), f.Run, []byte("s"), out, nil, "")
		if !errors.Is(err, ErrTPM) || strings.Contains(err.Error(), leak) || !strings.Contains(err.Error(), tool) {
			t.Errorf("%s: %v", tool, err)
		}
		if left := dirNames(t, out); len(left) != 0 {
			t.Errorf("%s: scratch left behind: %v", tool, left)
		}
		if f.names()[len(f.names())-1] != "tpm2_flushcontext" {
			t.Errorf("%s: transient objects not flushed", tool)
		}
	}
}

func TestTPMRotate(t *testing.T) {
	dir, priv, pub := sealedFixture(t)
	f := newFakeTPM(nil)
	p, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
	p.PCRList = []int{0, 4}
	nw, err := p.RotateMasterSecret()
	if err != nil || len(nw) != 32 {
		t.Fatalf("rotate: %v", err)
	}
	if b, _ := os.ReadFile(priv); string(b) != "priv" {
		t.Fatalf("priv %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "master_secret.pcrs")); err != nil {
		t.Fatal("pcrs not installed")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "master_secret.pcrs")); string(b) != "0 4\n" {
		t.Fatalf("pcrs %q", b)
	}
	if left := dirNames(t, dir); len(left) != 3 {
		t.Fatalf("leftover: %v", left)
	}

	// Seal failure leaves the old blobs untouched and cleans the scratch dir.
	dir2, priv2, pub2 := sealedFixture(t)
	f2 := newFakeTPM(nil)
	f2.failTool, f2.failErr = "tpm2_create", &ExitError{Code: 1}
	p2, _ := NewTPMProvider(priv2, pub2, WithRunner(f2.Run))
	if _, err := p2.RotateMasterSecret(); !errors.Is(err, ErrTPM) {
		t.Fatalf("got %v", err)
	}
	if left := dirNames(t, dir2); len(left) != 2 {
		t.Fatalf("leftover after failed rotate: %v", left)
	}

	// Scratch dir cannot be created.
	p3, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
	p3.PrivatePath = filepath.Join(t.TempDir(), "nodir", "x.priv")
	if _, err := p3.RotateMasterSecret(); !errors.Is(err, ErrTPM) {
		t.Fatalf("got %v", err)
	}
}

func TestTPMRotateRollsBackOnInstallFailure(t *testing.T) {
	dir, priv, pub := sealedFixture(t)
	pcrs := filepath.Join(dir, "master_secret.pcrs")
	_ = os.WriteFile(pcrs, []byte("0 7\n"), 0o600)
	f := newFakeTPM(nil)
	p, _ := NewTPMProvider(priv, pub, WithRunner(f.Run))
	// The public blob lives in a directory that does not exist, so installing
	// it fails AFTER the private blob was already replaced.
	p.PublicPath = filepath.Join(dir, "gone", "master_secret.pub")
	if _, err := p.RotateMasterSecret(); !errors.Is(err, ErrTPM) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(priv); string(b) != "priv" {
		t.Fatalf("private blob not restored: %q", b)
	}
	if b, _ := os.ReadFile(pcrs); string(b) != "0 7\n" {
		t.Fatalf("pcrs changed: %q", b)
	}
	if left := dirNames(t, dir); !reflect.DeepEqual(left, []string{"master_secret.pcrs", "master_secret.priv", "master_secret.pub"}) {
		t.Fatalf("leftovers after rollback: %v", left)
	}
}

func TestInstallAllMissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	_ = os.WriteFile(dst, []byte("old"), 0o600)
	err := installAll([]installFile{{filepath.Join(dir, "nosrc"), dst, false}})
	if err == nil {
		t.Fatal("missing source accepted")
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Fatal("destination modified")
	}
}

func TestSealTPMRejectsEmptySecret(t *testing.T) {
	if _, _, err := sealTPM(t.Context(), newFakeTPM(nil).Run, nil, t.TempDir(), nil, ""); err == nil {
		t.Fatal("empty secret sealed")
	}
}

func TestZeroAndRemove(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	_ = os.WriteFile(p, []byte("plaintext"), 0o600)
	zeroAndRemove(p)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("not removed")
	}
	zeroAndRemove(p) // missing file is fine
}

func TestBackupFileUniqueAndRestorable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	if bak, err := backupFile(path); err != nil || bak != "" {
		t.Fatalf("missing file: %q %v", bak, err)
	}
	_ = os.WriteFile(path, []byte("v1"), 0o600)
	b1, err1 := backupFile(path)
	b2, err2 := backupFile(path)
	if err1 != nil || err2 != nil || b1 == b2 || b1 == "" {
		t.Fatalf("backups must be unique: %q %q %v %v", b1, b2, err1, err2)
	}
	// The live file stays in place (hard link), and the backup holds its content.
	if b, _ := os.ReadFile(path); string(b) != "v1" {
		t.Fatal("live file disturbed")
	}
	if b, _ := os.ReadFile(b1); string(b) != "v1" {
		t.Fatal("backup content")
	}
}

func TestBackupFileCopyFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	_ = os.WriteFile(path, []byte("v1"), 0o600)
	// A directory cannot be hard-linked or read: backup must fail cleanly.
	sub := filepath.Join(dir, "sub")
	_ = os.Mkdir(sub, 0o700)
	if _, err := backupFile(sub); err == nil {
		t.Fatal("backing up a directory must fail")
	}
}

func TestInstallAllKeepsOldFileInPlaceUntilReplaced(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	src := filepath.Join(dir, "src")
	_ = os.WriteFile(dst, []byte("old"), 0o600)
	_ = os.WriteFile(src, []byte("new"), 0o600)
	if err := installAll([]installFile{{src, dst, false}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Fatalf("dst %q", b)
	}
	if left := dirNames(t, dir); !reflect.DeepEqual(left, []string{"dst"}) {
		t.Fatalf("leftovers (backups must be removed): %v", left)
	}
}

func TestInstallAllFailedRenameDoesNotDeleteForeignFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	_ = os.WriteFile(src, []byte("new"), 0o600)
	// dst's parent does not exist: Lstat says "not exist", Rename fails.
	dst := filepath.Join(dir, "nodir", "dst")
	if err := installAll([]installFile{{src, dst, false}}); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("source must be untouched on failure")
	}
}
