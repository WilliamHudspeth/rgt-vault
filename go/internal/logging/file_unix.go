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
	// Only a directory this call creates is forced to 0700. A pre-existing
	// directory (/var/log, a home directory, a shared /tmp) is never chmodded:
	// its mode is the operator's decision, and a root-run daemon must not be
	// able to lock a system directory down by pointing the log path into it.
	_, statErr := os.Lstat(dir)
	created := errors.Is(statErr, os.ErrNotExist)
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
	if created && dirInfo.Mode().Perm() != 0o700 {
		// umask cannot loosen 0700, but be explicit for the final directory.
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("logging: restrict new log directory to 0700: %w", err)
		}
	}

	// Refuse anything but a regular file BEFORE opening: opening a FIFO for
	// write blocks forever without a reader, and a device node is never a log.
	if li, err := os.Lstat(path); err == nil && !li.Mode().IsRegular() {
		return nil, errors.New("logging: log path must be a regular file")
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
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
