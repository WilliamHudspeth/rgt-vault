//go:build linux

package secfile

import (
	"os"

	"golang.org/x/sys/unix"
)

// stRDOnly is ST_RDONLY in statfs(2) f_flags.
const stRDOnly = 0x1

// fsInfo reports the filesystem of an open file: whether it is a tmpfs or
// ramfs (the in-memory filesystems systemd puts credentials on) and whether
// it is mounted read-only. It is a seam for tests.
var fsInfo = func(f *os.File) (inMemory, readOnly bool, err error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return false, false, err
	}
	t := int64(st.Type)
	return t == unix.TMPFS_MAGIC || t == int64(uint32(unix.RAMFS_MAGIC)), int64(st.Flags)&stRDOnly != 0, nil
}
