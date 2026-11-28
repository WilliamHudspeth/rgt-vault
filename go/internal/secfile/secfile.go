// Package secfile opens, checks and creates small secret files (master keys,
// tokens, TOTP seeds) so that a file other local users could read or replace
// is refused instead of used (RGT-522; reused by RGT-541).
//
// Every check is made on the opened handle (fstat / GetSecurityInfo on the
// handle), never stat-then-open, so the file that is checked is the file that
// is read.
//
// Unix (Linux, macOS), in the style of OpenSSH StrictModes:
//   - the path is resolved once (filepath.EvalSymlinks), so the symlink chains
//     of Kubernetes/Docker secret mounts work;
//   - the key's own directory must be owned by the euid or root and must not
//     be group/world-writable;
//   - every ancestor directory up to / must be owned by the euid or root and
//     must not be group/world-writable, except that a root-owned sticky
//     directory (such as /tmp) is accepted as an ancestor;
//   - the file is opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC and must be
//     a regular file with one link, no setuid/setgid bit, owned by the euid
//     or root, with no group/other permission bits, and no larger than the
//     size limit.
//
// Windows:
//   - the file is opened with FILE_FLAG_OPEN_REPARSE_POINT and refused if it
//     is a reparse point (symlink, junction), a directory or has more than
//     one link;
//   - the owner (read from the handle) must be the current user, SYSTEM or
//     BUILTIN\Administrators; the DACL must be present and non-null, and
//     every allow ACE may name only those three SIDs (Everyone, Authenticated
//     Users, BUILTIN\Users and any other SID are refused);
//   - a DACL that cannot be read or parsed is refused, unless
//     [Options.InsecureACL] is set (diagnosis only; the caller must warn).
//
// Creation ([CreateSecret]) uses O_CREATE|O_EXCL|O_NOFOLLOW with mode 0600
// (Windows: CREATE_NEW with a protected owner+SYSTEM DACL set at creation
// time), writes, fsyncs the file and its directory, and never overwrites.
package secfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DefaultMaxSize is the size limit when [Options.MaxSize] is zero.
const DefaultMaxSize = 64 << 10

// ErrInsecure is wrapped by every refusal of a file or directory whose
// type, owner, permissions or ACL would let someone else read or replace it.
var ErrInsecure = errors.New("insecure secret file")

// ErrTooLarge is wrapped when the file is over the size limit.
var ErrTooLarge = errors.New("secret file too large")

// Options tune [OpenSecret].
type Options struct {
	// MaxSize is the largest accepted file in bytes (0 = DefaultMaxSize).
	MaxSize int64
	// InsecureACL (Windows only) turns an ACL refusal into a call to Warn.
	// It exists for diagnosis only; reparse points, links and directories
	// are still refused.
	InsecureACL bool
	// Warn receives the warning that replaces a refusal under InsecureACL.
	Warn func(msg string)
	// Credential (Linux) also accepts a systemd credential that is owned by
	// root and group-readable through a POSIX ACL mask (mode at most 0440),
	// in a root-owned directory, on a read-only tmpfs/ramfs. Every other
	// check still applies.
	Credential bool
}

func (o Options) maxSize() int64 {
	if o.MaxSize > 0 {
		return o.MaxSize
	}
	return DefaultMaxSize
}

func (o Options) warn(msg string) {
	if o.Warn != nil {
		o.Warn(msg)
	}
}

func insecure(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInsecure}, args...)...)
}

// OpenSecret checks path as described in the package documentation and
// returns its contents. A missing file wraps fs.ErrNotExist.
func OpenSecret(path string, opts Options) ([]byte, error) {
	f, size, err := openChecked(path, opts)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limit := opts.maxSize()
	if size > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes (at most %d)", ErrTooLarge, path, size, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(b)) > limit { // grew after the fstat
		clear(b)
		return nil, fmt.Errorf("%w: %s is over %d bytes", ErrTooLarge, path, limit)
	}
	return b, nil
}

// CheckDir checks dir, the directory a secret file lives in, and its
// ancestors (Unix; see the package documentation). On Windows it checks
// that dir is a real directory, not a reparse point.
func CheckDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("directory %s: %w", dir, err)
	}
	return checkDirChain(resolved)
}

// CheckCreatable checks, without creating anything, that dir could be made
// by [EnsureDir]: dir itself if it exists, otherwise its nearest existing
// ancestor, must pass [CheckDir].
func CheckCreatable(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for d := abs; ; {
		if _, err := os.Lstat(d); err == nil {
			return CheckDir(d)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("directory %s: %w", d, err)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return fmt.Errorf("directory %s: no existing ancestor", dir)
		}
		d = parent
	}
}

// EnsureDir creates dir (and its parents) with mode 0700 if it is missing,
// then checks it with [CheckDir].
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	return CheckDir(dir)
}

// CreateSecret creates path holding data, exclusively: an existing file (or
// symlink) at path is never overwritten and the error wraps fs.ErrExist.
// The parent directory must exist and pass [CheckDir]. The file is fsynced,
// and so is its directory.
func CreateSecret(path string, data []byte) error {
	dir, err := checkedParent(path)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, filepath.Base(path))
	if err := createExclusive(target, data); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// ReplaceSecret writes data to a new temp file beside path (created like
// [CreateSecret]) and renames it over path, so readers see either the old
// or the new file, never a partial one.
func ReplaceSecret(path string, data []byte) error {
	dir, err := checkedParent(path)
	if err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	base := filepath.Base(path)
	tmp := filepath.Join(dir, "."+base+".tmp-"+hex.EncodeToString(rnd[:]))
	if err := createExclusive(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, base)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	syncDir(dir)
	return nil
}

func checkedParent(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("directory %s does not exist: %w", parent, err)
		}
		return "", fmt.Errorf("directory %s: %w", parent, err)
	}
	if err := checkDirChain(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort; not supported on every OS
		_ = d.Close()
	}
}

// writeAndSync writes data to f, fsyncs and closes it. On failure the file
// at path is removed.
func writeAndSync(f *os.File, path string, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// errWouldBlock: the lock is held elsewhere.
var errWouldBlock = errors.New("lock is held")

// ErrLockTimeout is returned by [TryLock] when the lock stayed held.
var ErrLockTimeout = errors.New("timed out waiting for the lock")

// TryLock is [Lock] with a deadline: it polls until timeout and then
// returns ErrLockTimeout.
func TryLock(path string, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		unlock, err := tryLockOnce(path)
		if !errors.Is(err, errWouldBlock) {
			return unlock, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: %s", ErrLockTimeout, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
