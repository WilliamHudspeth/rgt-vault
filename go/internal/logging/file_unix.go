//go:build !windows

package logging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openLogFileOS(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logging: create log directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("logging: stat log directory: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("logging: log directory must not be a symlink")
	}
	if !dirInfo.IsDir() {
		return nil, errors.New("logging: log parent path is not a directory")
	}
	if dirInfo.Mode().Perm()&0o077 != 0 && ownedByCurrentUser(dirInfo) && dirInfo.Mode()&os.ModeSticky == 0 {
		// Tighten an existing group/other-accessible log directory, but only
		// when this process owns it and it is not a sticky shared directory
		// such as /tmp: never chmod a system directory, even when running as root.
		// A failure here is not fatal (the file itself is still created 0600).
		_ = os.Chmod(dir, 0o700)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("logging: open log file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("logging: stat log file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("logging: log path must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("logging: tighten log file mode to 0600: %w", err)
		}
	}
	return f, nil
}

// ownedByCurrentUser reports whether info's owner is the effective user.
func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}
