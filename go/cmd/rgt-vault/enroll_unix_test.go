//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The TOTP secret file is created 0600 by the open call itself (a private
// temp file, then moved into place): it never exists with a looser mode, not
// even under a umask of 0.
func TestEnrollSecretCreatedPrivateUnderZeroUmask(t *testing.T) {
	e := newVaultEnv(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	out := filepath.Join(e.dir, "sec", "totp.secret")
	e.mustCLI("", "enroll-2fa", "--out", out)
	assertMode0600(t, out)
	if fi, err := os.Stat(filepath.Dir(out)); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secret directory %v %v", fi, err)
	}
	// And the forced replacement keeps it private.
	e.mustCLI("", "enroll-2fa", "--out", out, "--force")
	assertMode0600(t, out)
}
