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
func openChecked(path string, opts Options) (*os.File, int64, error) {
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
	f, err := openNoFollow(resolved)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat() // fstat on the handle
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := checkFileInfo(resolved, fi); err != nil {
		// A systemd credential: root-owned, group-readable through an ACL
		// mask, on a read-only in-memory filesystem (review H3).
		if !opts.Credential || !errors.Is(err, errModeBits) {
			_ = f.Close()
			return nil, 0, err
		}
		if cerr := credentialCheck(resolved, fi, f); cerr != nil {
			_ = f.Close()
			return nil, 0, fmt.Errorf("%w (not accepted as a systemd credential either: %v)", err, cerr)
		}
	}
	return f, fi.Size(), nil
}

// openNoFollow opens an already resolved path read-only without following a
// symlink in its last component. O_NONBLOCK: opening a FIFO must not hang;
// it is refused by the fstat checks.
func openNoFollow(resolved string) (*os.File, error) {
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, insecure("%s became a symlink while it was opened", resolved)
		}
		return nil, fmt.Errorf("open %s: %w", resolved, err)
	}
	return f, nil
}

// credentialCheck is a seam for tests (a root-owned file cannot be made
// without root).
var credentialCheck = credentialException

// errModeBits marks the group/other permission refusal, the only one the
// systemd-credential exception may lift.
var errModeBits = errors.New("group/other permission bits")

// credentialException accepts a file the mode check refused when it looks
// exactly like a credential systemd delivered with an ACL for the service
// user: owned by root, at most 0440, in a root-owned directory (the
// directory chain was already checked), on a read-only tmpfs/ramfs.
func credentialException(path string, fi fs.FileInfo, f *os.File) error {
	st, _ := fi.Sys().(*syscall.Stat_t)
	di, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	dst, _ := di.Sys().(*syscall.Stat_t)
	inMem, ro, ferr := fsInfo(f)
	return credentialRule(fi.Mode().Perm(), st, dst, inMem, ro, ferr)
}

// credentialRule is the testable core of credentialException.
func credentialRule(perm fs.FileMode, file, dir *syscall.Stat_t, inMemory, readOnly bool, fsErr error) error {
	switch {
	case file == nil || dir == nil:
		return errors.New("cannot read owners")
	case file.Uid != 0:
		return errors.New("the file is not owned by root")
	case file.Gid != 0:
		return errors.New("the file's group is not root")
	case perm&^0o440 != 0:
		return fmt.Errorf("mode %04o allows more than owner/group read", perm)
	case dir.Uid != 0:
		return errors.New("its directory is not owned by root")
	case dir.Gid != 0:
		return errors.New("its directory's group is not root")
	case fsErr != nil:
		return fmt.Errorf("filesystem not checked: %v", fsErr)
	case !inMemory:
		return errors.New("it is not on a tmpfs/ramfs")
	case !readOnly:
		return errors.New("its filesystem is not mounted read-only")
	}
	return nil
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
		return fmt.Errorf("%w: %w: %s is accessible by group/other (mode %04o): run chmod 600 %s",
			ErrInsecure, errModeBits, path, perm, path)
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

// Lock takes an exclusive advisory lock (flock) on path, creating it 0600
// (no symlink followed) if it is missing, and returns the release function.
// It blocks while another open file description holds the lock, in this or
// another process. The lock file is never removed (removing a lock file is
// racy).
func Lock(path string) (func(), error) {
	return lockFile(path, false)
}

// tryLockOnce takes the lock without blocking; errWouldBlock if it is held.
func tryLockOnce(path string) (func(), error) { return lockFile(path, true) }

func lockFile(path string, nonBlocking bool) (func(), error) {
	// O_NONBLOCK: a FIFO planted at the path must not hang the open.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, insecure("lock file %s is a symlink", path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		return nil, insecure("lock file %s is not a regular file (%s)", path, fi.Mode().Type())
	}
	how := syscall.LOCK_EX
	if nonBlocking {
		how |= syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), how)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errWouldBlock
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
