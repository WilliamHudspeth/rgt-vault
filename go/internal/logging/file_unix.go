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
	if dirInfo.Mode().Perm()&0o077 != 0 {
		// Tighten an existing directory when owned by the current process;
		// ignore EPERM on system-owned parent directories like /tmp.
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
