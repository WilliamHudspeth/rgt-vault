//go:build !windows && (!unix || solaris || aix)

package auth

import (
	"errors"
	"os"
)

// errLockUnsupported: this platform (plan9, js/wasm, wasip1, solaris/illumos,
// aix: no syscall.Flock) has no OS file
// lock the token store can use; writes fail closed instead of racing.
var errLockUnsupported = errors.New("token store writes need an OS file lock (flock or LockFileEx), unsupported on this platform")

func tryLock(*os.File) error    { return errLockUnsupported }
func unlockFile(*os.File) error { return errLockUnsupported }
