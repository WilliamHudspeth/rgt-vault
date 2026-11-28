//go:build windows

package logging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func openLogFileOS(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logging: create log directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("logging: log path must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("logging: log path must be a regular file")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("logging: stat log file: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("logging: open log file: %w", err)
	}
	return f, nil
}
