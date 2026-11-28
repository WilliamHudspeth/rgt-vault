//go:build unix

package secfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// geteuid is a seam for tests.
var geteuid = os.Geteuid

// openChecked resolves path, checks its directories, opens it without
// following a symlink and checks the opened handle. It returns the open file
// and its size.
func openChecked(path string, _ Options) (*os.File, int64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
		}
		return nil, 0, fmt.Errorf("resolve %s: %w", path, err)
	}
	if err := checkDirChain(filepath.Dir(resolved)); err != nil {
		return nil, 0, err
	}
	// O_NONBLOCK: opening a FIFO must not hang; it is refused below.
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, 0, insecure("%s became a symlink while it was opened", resolved)
		}
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	fi, err := f.Stat() // fstat on the handle
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := checkFileInfo(resolved, fi); err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// checkFileInfo applies the file rules to an fstat result.
func checkFileInfo(path string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return insecure("%s is not a regular file (%s)", path, fi.Mode().Type())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return insecure("%s: cannot read the file owner", path)
	}
	if st.Nlink != 1 {
		return insecure("%s has %d hard links; a secret file must have exactly one (copy it to a new file)", path, st.Nlink)
	}
	if fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
		return insecure("%s has the setuid/setgid bit: run chmod 600 %s", path, path)
	}
	euid := geteuid()
	if int(st.Uid) != euid && st.Uid != 0 {
		return insecure("%s is owned by uid %d, not by you (uid %d) or root: run chown %d %s", path, st.Uid, euid, euid, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return insecure("%s is accessible by group/other (mode %04o): run chmod 600 %s", path, perm, path)
	}
	return nil
}

// checkDirChain checks dir (the key's own directory, already resolved) and
// every ancestor up to the root.
func checkDirChain(dir string) error {
	euid := geteuid()
	own := true
	for {
		fi, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("directory %s: %w", dir, err)
		}
		if err := checkDirInfo(dir, fi, euid, own); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir, own = parent, false
	}
}

// checkDirInfo applies the directory rules. own is true for the key's own
// directory, which may never be a writable sticky directory.
func checkDirInfo(dir string, fi fs.FileInfo, euid int, own bool) error {
	if !fi.IsDir() {
		return insecure("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return insecure("directory %s: cannot read its owner", dir)
	}
	if int(st.Uid) != euid && st.Uid != 0 {
		return insecure("directory %s is owned by uid %d, not by you (uid %d) or root; move the key elsewhere or run chown %d %s",
			dir, st.Uid, euid, euid, dir)
	}
	perm := fi.Mode().Perm()
	if perm&0o022 == 0 {
		return nil
	}
	if !own && st.Uid == 0 && fi.Mode()&fs.ModeSticky != 0 {
		return nil // e.g. /tmp: others cannot rename or replace entries they do not own
	}
	what := "group-writable"
	if perm&0o002 != 0 {
		what = "world-writable"
	}
	if own {
		return insecure("directory %s is %s (mode %04o): run chmod 700 %s", dir, what, perm, dir)
	}
	return insecure("directory %s (an ancestor of the key) is %s (mode %04o): run chmod go-w %s", dir, what, perm, dir)
}

// createExclusive creates path 0600 with O_EXCL|O_NOFOLLOW and writes data.
func createExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	// The umask can only remove bits; make the mode explicit anyway.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return writeAndSync(f, path, data)
}
