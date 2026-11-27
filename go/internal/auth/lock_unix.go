//go:build !windows

package auth

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive, non-blocking flock(2) on f. errWouldBlock
// means another holder has it (another goroutine's or process's handle:
// flock locks belong to the open file description).
func tryLock(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN):
			return errWouldBlock
		default:
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
