//go:build unix

package secfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeKey(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// TestOpenRefusals is one row per refusal of a real file. Each row fails if
// its check in checkFileInfo / checkDirChain is removed.
func TestOpenRefusals(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the ownership rules under test")
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, d string) string // returns the path to open
		want  string
	}{
		{"group-readable", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o640)
			return p
		}, "chmod 600"},
		{"other-readable", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o604)
			return p
		}, "chmod 600"},
		{"group-writable-only", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o620)
			return p
		}, "chmod 600"},
		{"setuid", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o600|fs.ModeSetuid)
			return p
		}, "setuid"},
		{"hard-link", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o600)
			if err := os.Link(p, filepath.Join(d, "k2")); err != nil {
				t.Fatal(err)
			}
			return p
		}, "hard links"},
		{"directory", func(t *testing.T, d string) string {
			p := filepath.Join(d, "sub")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		}, "not a regular file"},
		{"fifo", func(t *testing.T, d string) string {
			p := filepath.Join(d, "fifo")
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			return p
		}, "not a regular file"},
		{"own-dir-group-writable", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o600)
			chmod(t, d, 0o770)
			return p
		}, "group-writable"},
		{"own-dir-world-writable-sticky", func(t *testing.T, d string) string {
			p := filepath.Join(d, "k")
			writeKey(t, p, 0o600)
			chmod(t, d, 0o777|fs.ModeSticky)
			return p
		}, "world-writable"},
		{"ancestor-world-writable", func(t *testing.T, d string) string {
			sub := filepath.Join(d, "inner")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(sub, "k")
			writeKey(t, p, 0o600)
			chmod(t, d, 0o777)
			return p
		}, "an ancestor of the key"},
		{"ancestor-sticky-but-not-root", func(t *testing.T, d string) string {
			sub := filepath.Join(d, "inner")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(sub, "k")
			writeKey(t, p, 0o600)
			chmod(t, d, 0o777|fs.ModeSticky)
			return p
		}, "an ancestor of the key"},
		{"symlink-into-insecure-dir", func(t *testing.T, d string) string {
			bad := filepath.Join(d, "bad")
			if err := os.Mkdir(bad, 0o700); err != nil {
				t.Fatal(err)
			}
			writeKey(t, filepath.Join(bad, "k"), 0o600)
			chmod(t, bad, 0o777)
			link := filepath.Join(d, "link")
			if err := os.Symlink(filepath.Join(bad, "k"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}, "world-writable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := keyDir(t)
			p := c.setup(t, d)
			done := make(chan error, 1)
			go func() { _, err := OpenSecret(p, Options{}); done <- err }()
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("OpenSecret hung")
			}
			if !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want ErrInsecure containing %q", err, c.want)
			}
		})
	}
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o700) })
}

// The ownership rules cannot be exercised with real foreign files without
// root, so these rows run the checks on real fstat results with a different
// euid (the geteuid seam).
func TestOwnerRefusals(t *testing.T) {
	d := keyDir(t)
	p := filepath.Join(d, "k")
	writeKey(t, p, 0o600)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	me := os.Geteuid()
	if me == 0 {
		t.Skip("files created by root are always accepted")
	}
	other := me + 4242

	old := geteuid
	t.Cleanup(func() { geteuid = old })
	geteuid = func() int { return other }

	if err := checkFileInfo(p, fi); !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("file owned by someone else: err = %v", err)
	}
	if err := checkDirInfo(d, di, other, true); !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("own dir owned by someone else: err = %v", err)
	}
	if err := checkDirInfo(d, di, other, false); !errors.Is(err, ErrInsecure) {
		t.Fatalf("ancestor owned by someone else: err = %v", err)
	}
	if _, err := OpenSecret(p, Options{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("OpenSecret with a foreign owner: err = %v", err)
	}
	// Controls: the same infos pass for the real euid.
	if err := checkFileInfo(p, fi); err == nil {
		t.Fatal("seam not in effect")
	}
	geteuid = old
	if err := checkFileInfo(p, fi); err != nil {
		t.Fatalf("own file refused: %v", err)
	}
	if err := checkDirInfo(d, di, me, true); err != nil {
		t.Fatalf("own dir refused: %v", err)
	}
}

// fakeInfo lets the root-owned cases run without root.
type fakeInfo struct {
	mode fs.FileMode
	st   *syscall.Stat_t
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any {
	if f.st == nil {
		return nil
	}
	return f.st
}

func TestRootOwnedStickyDirs(t *testing.T) {
	root := &syscall.Stat_t{Uid: 0}
	tmp := fakeInfo{mode: fs.ModeDir | fs.ModeSticky | 0o777, st: root}
	if err := checkDirInfo("/tmp", tmp, 1000, false); err != nil {
		t.Fatalf("root-owned sticky ancestor refused: %v", err)
	}
	if err := checkDirInfo("/tmp", tmp, 1000, true); !errors.Is(err, ErrInsecure) {
		t.Fatalf("root-owned sticky OWN directory accepted: %v", err)
	}
	nonSticky := fakeInfo{mode: fs.ModeDir | 0o777, st: root}
	if err := checkDirInfo("/x", nonSticky, 1000, false); !errors.Is(err, ErrInsecure) {
		t.Fatalf("root-owned world-writable non-sticky ancestor accepted: %v", err)
	}
	if err := checkDirInfo("/etc", fakeInfo{mode: fs.ModeDir | 0o755, st: root}, 1000, true); err != nil {
		t.Fatalf("root-owned 0755 dir refused: %v", err)
	}
	if err := checkDirInfo("/x", fakeInfo{mode: 0o600, st: root}, 1000, true); !errors.Is(err, ErrInsecure) {
		t.Fatalf("non-directory accepted: %v", err)
	}
	if err := checkDirInfo("/x", fakeInfo{mode: fs.ModeDir | 0o700}, 1000, true); !errors.Is(err, ErrInsecure) {
		t.Fatalf("dir without Stat_t accepted: %v", err)
	}
	// Root-owned file (systemd credentials may be root-owned 0400): accepted.
	f := fakeInfo{mode: 0o400, st: &syscall.Stat_t{Uid: 0, Nlink: 1}}
	if err := checkFileInfo("/run/credentials/x", f); err != nil {
		t.Fatalf("root-owned 0400 file refused: %v", err)
	}
	if err := checkFileInfo("/x", fakeInfo{mode: 0o400}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("file without Stat_t accepted: %v", err)
	}
}

func TestSymlinkToGoodFileWorks(t *testing.T) {
	d := keyDir(t)
	real := filepath.Join(d, "real.key")
	writeKey(t, real, 0o600)
	// A chain of links, like a Kubernetes secret mount (..data -> ts dir).
	l1 := filepath.Join(d, "l1")
	l2 := filepath.Join(d, "l2")
	if err := os.Symlink(real, l1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(l1, l2); err != nil {
		t.Fatal(err)
	}
	got, err := OpenSecret(l2, Options{})
	if err != nil || string(got) != "k\n" {
		t.Fatalf("OpenSecret(link chain) = %q, %v", got, err)
	}
}

func TestCreateSecretRefusals(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the ownership rules under test")
	}
	d := keyDir(t)
	// A dangling symlink at the target is not followed (O_EXCL|O_NOFOLLOW).
	victim := filepath.Join(d, "victim")
	link := filepath.Join(d, "k")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := CreateSecret(link, []byte("x")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("CreateSecret over a dangling symlink: %v", err)
	}
	if _, err := os.Lstat(victim); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the symlink was followed")
	}
	// An insecure parent is refused before anything is created.
	chmod(t, d, 0o777)
	p := filepath.Join(d, "new.key")
	if err := CreateSecret(p, []byte("x")); !errors.Is(err, ErrInsecure) {
		t.Fatalf("CreateSecret in a world-writable dir: %v", err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("file created in an insecure dir")
	}
	if err := EnsureDir(d); !errors.Is(err, ErrInsecure) {
		t.Fatalf("EnsureDir of a world-writable dir: %v", err)
	}
}

func TestCreatedMode(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	d := keyDir(t)
	p := filepath.Join(d, "k")
	if err := CreateSecret(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", fi.Mode().Perm())
	}
	e := filepath.Join(secureTemp(t), "new")
	if err := EnsureDir(e); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(e); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %04o, want 0700", fi.Mode().Perm())
	}
}

func TestErrorPaths(t *testing.T) {
	d := keyDir(t)
	f := filepath.Join(d, "file")
	writeKey(t, f, 0o600)
	// A path through a regular file: resolution fails, not ErrNotExist.
	if _, err := OpenSecret(filepath.Join(f, "child"), Options{}); err == nil {
		t.Fatalf("OpenSecret(file/child) = %v", err)
	}
	if err := CheckDir(f); !errors.Is(err, ErrInsecure) {
		t.Fatalf("CheckDir(regular file) = %v", err)
	}
	// Name too long: createExclusive fails and nothing is left behind.
	long := filepath.Join(d, strings.Repeat("n", 300))
	if err := CreateSecret(long, []byte("x")); err == nil {
		t.Fatal("CreateSecret with a 300-byte name succeeded")
	}
	// ReplaceSecret over a directory: the rename fails, the temp file goes.
	sub := filepath.Join(d, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceSecret(sub, []byte("x")); err == nil {
		t.Fatal("ReplaceSecret over a non-empty directory succeeded")
	}
	ents, _ := os.ReadDir(d)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	// ReplaceSecret into an insecure directory is refused.
	chmod(t, d, 0o777)
	if err := ReplaceSecret(f, []byte("x")); !errors.Is(err, ErrInsecure) {
		t.Fatalf("ReplaceSecret in a world-writable dir = %v", err)
	}
}

func TestUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	d := keyDir(t)
	p := filepath.Join(d, "k")
	writeKey(t, p, 0o000)
	if _, err := OpenSecret(p, Options{}); err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("OpenSecret(mode 000) = %v", err)
	}
}

// Review H3: the systemd-credential exception, one row per condition.
func TestCredentialRule(t *testing.T) {
	root := &syscall.Stat_t{Uid: 0}
	user := &syscall.Stat_t{Uid: 1000}
	cases := []struct {
		name      string
		perm      fs.FileMode
		file, dir *syscall.Stat_t
		mem, ro   bool
		fsErr     error
		ok        bool
	}{
		{"systemd 255: root 0440 on ro tmpfs", 0o440, root, root, true, true, nil, true},
		{"root 0400", 0o400, root, root, true, true, nil, true},
		{"file not root", 0o440, user, root, true, true, nil, false},
		{"group writable", 0o460, root, root, true, true, nil, false},
		{"other readable", 0o444, root, root, true, true, nil, false},
		{"dir not root", 0o440, root, user, true, true, nil, false},
		{"not in memory", 0o440, root, root, false, true, nil, false},
		{"not read-only", 0o440, root, root, true, false, nil, false},
		{"statfs failed", 0o440, root, root, true, true, errors.New("x"), false},
		{"no owner info", 0o440, nil, root, true, true, nil, false},
	}
	for _, c := range cases {
		if err := credentialRule(c.perm, c.file, c.dir, c.mem, c.ro, c.fsErr); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// The exception is used only with Options.Credential, only for the mode
// check, and a non-root file is still refused.
func TestCredentialOptionOnRealFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root owner")
	}
	d := keyDir(t)
	p := filepath.Join(d, "rgt-vault-master")
	writeKey(t, p, 0o440)
	old := fsInfo
	t.Cleanup(func() { fsInfo = old })
	fsInfo = func(*os.File) (bool, bool, error) { return true, true, nil }
	for _, o := range []Options{{}, {Credential: true}} {
		_, err := OpenSecret(p, o)
		if !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("Credential=%v: err = %v", o.Credential, err)
		}
	}
	if _, err := OpenSecret(p, Options{Credential: true}); !strings.Contains(err.Error(), "not owned by root") {
		t.Fatalf("reason not given: %v", err)
	}
	// With a file that satisfies the rule, only Options.Credential lifts the
	// mode refusal, and never any other refusal (here: a hard link).
	oldCheck := credentialCheck
	t.Cleanup(func() { credentialCheck = oldCheck })
	credentialCheck = func(string, fs.FileInfo, *os.File) error { return nil }
	if _, err := OpenSecret(p, Options{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("exception applied without Options.Credential: %v", err)
	}
	if _, err := OpenSecret(p, Options{Credential: true}); err != nil {
		t.Fatalf("credential-shaped file refused: %v", err)
	}
	if err := os.Link(p, p+".2"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSecret(p, Options{Credential: true}); !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard-linked credential accepted: %v", err)
	}
}

func TestOpenNoFollow(t *testing.T) {
	d := keyDir(t)
	real := filepath.Join(d, "k")
	writeKey(t, real, 0o600)
	link := filepath.Join(d, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// What a swap between EvalSymlinks and open would present.
	if _, err := openNoFollow(link); !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("openNoFollow(symlink) = %v", err)
	}
	f, err := openNoFollow(real)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func TestCheckCreatable(t *testing.T) {
	base := secureTemp(t)
	deep := filepath.Join(base, "a", "b", "c")
	if err := CheckCreatable(deep); err != nil {
		t.Fatalf("CheckCreatable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("CheckCreatable created a directory")
	}
	chmod(t, base, 0o777)
	if err := CheckCreatable(deep); !errors.Is(err, ErrInsecure) {
		t.Fatalf("under a world-writable dir: %v", err)
	}
	f := filepath.Join(keyDir(t), "file")
	writeKey(t, f, 0o600)
	if err := CheckCreatable(filepath.Join(f, "x")); err == nil {
		t.Fatal("CheckCreatable under a regular file succeeded")
	}
}
