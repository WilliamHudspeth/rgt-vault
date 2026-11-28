package transport

import (
	"fmt"
	"os"
	"runtime"
)

// CheckKeyFile refuses a private-key file that other local users can reach
// (RGT-456). On Unix the file must be a regular file with no group or other
// permission bits (0600 or 0400): the check follows symlinks, so a
// Let's Encrypt style live/ -> archive/ link is judged by its target.
//
// On Windows the Go os.FileMode permission bits are synthetic (they reflect
// only the read-only attribute) and say nothing about the ACL, so no check is
// possible there: the operator must restrict the key's ACL to the service
// account (see docs/guides/tls.md). The file must still be a regular file.
func CheckKeyFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("private key %s is not a regular file", path)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("private key %s has mode %04o: it is accessible by group/other. "+
			"Restrict it first: chmod 600 %s", path, perm, path)
	}
	return nil
}
