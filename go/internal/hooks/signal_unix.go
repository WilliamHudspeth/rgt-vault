//go:build unix

package hooks

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// InstallFreezeSignalHandler makes SIGUSR1 freeze and SIGUSR2 unfreeze h
// (python install_freeze_signal_handler; reasons "USR1 signal" / "USR2
// signal"). The returned stop function uninstalls the handler and waits for
// the goroutine; it is safe to call more than once. On platforms without
// POSIX signals it is a no-op.
func InstallFreezeSignalHandler(h Freezer) (stop func()) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGUSR1, syscall.SIGUSR2)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case s := <-ch:
				switch s {
				case syscall.SIGUSR1:
					h.Freeze("USR1 signal")
				case syscall.SIGUSR2:
					h.Unfreeze("USR2 signal")
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
			<-finished
		})
	}
}
