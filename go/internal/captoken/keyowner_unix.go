//go:build unix

package captoken

import (
	"fmt"
	"os"
	"syscall"
)

// checkKeyOwner refuses a key file owned by anyone but the user running the
// process or root (as transport.checkKeyOwner does for TLS keys).
func checkKeyOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if !ownerAllowed(st.Uid, uint32(geteuid())) {
		return fmt.Errorf("owned by uid %d, not by the user running the process (uid %d) or root: chown it", st.Uid, geteuid())
	}
	return nil
}

// geteuid is a test seam.
var geteuid = os.Geteuid

func ownerAllowed(fileUID, euid uint32) bool { return fileUID == euid || fileUID == 0 }
