package transport

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// CheckKeyFile refuses a private-key file that other local users can reach
// (RGT-456). See ReadKeyFile for the rules.
func CheckKeyFile(path string) error {
	f, _, err := openKeyFile(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// ReadKeyFile opens the private key ONCE, checks the descriptor it opened
// (not the path, so the file cannot be swapped between check and read) and
// returns its contents.
//
// On Unix the file must be a regular file with no group or other permission
// bits (0600 or 0400) and be owned by the effective user or by root; the
// check follows symlinks, so a Let's Encrypt style live/ -> archive/ link is
// judged by its target.
//
// On Windows the Go os.FileMode permission bits are synthetic (they reflect
// only the read-only attribute) and say nothing about the ACL, so no check is
// possible there: the operator must restrict the key's ACL to the service
// account (see docs/guides/tls.md; the server logs a notice at startup). The
// file must still be a regular file.
func ReadKeyFile(path string) ([]byte, error) {
	f, _, err := openKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	return b, nil
}

// openKeyFile opens path and validates the open descriptor.
func openKeyFile(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("private key: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("private key: %w", err)
	}
	if err := checkKeyInfo(path, fi, runtime.GOOS); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// checkKeyInfo applies the rules to the Fstat of the opened key.
func checkKeyInfo(path string, fi os.FileInfo, goos string) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("private key %s is not a regular file", path)
	}
	if goos == "windows" {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("private key %s has mode %04o: it is accessible by group/other. "+
			"Restrict it first: chmod 600 %s", path, perm, path)
	}
	return checkKeyOwner(path, fi)
}

// KeyACLNotice is the startup warning for platforms where the key file's
// access rights cannot be checked ("" elsewhere).
func KeyACLNotice(goos string) string {
	if goos != "windows" {
		return ""
	}
	return "Windows: the private key file's ACL is NOT checked (Go cannot read it). Make sure only the " +
		"service account and Administrators can read it (icacls /inheritance:r); see docs/guides/tls.md"
}
