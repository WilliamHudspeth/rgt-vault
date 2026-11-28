//go:build unix

package transport

import (
	"fmt"
	"os"
	"syscall"
)

// checkKeyOwner refuses a key owned by neither the effective user nor root:
// its owner can rewrite or read it at will.
func checkKeyOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if !ownerAllowed(st.Uid, uint32(os.Geteuid())) {
		return fmt.Errorf("private key %s is owned by uid %d, not by the user running the server (uid %d) or root: "+
			"chown it", path, st.Uid, os.Geteuid())
	}
	return nil
}

func ownerAllowed(fileUID, euid uint32) bool { return fileUID == euid || fileUID == 0 }
