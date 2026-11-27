//go:build unix

package hooks

import (
	"syscall"
	"testing"
	"time"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFreezeSignals(t *testing.T) {
	h := NewOffHook()
	reasons := make(chan string, 4)
	h.OnFreezeChange(func(_ bool, r string) { reasons <- r })
	stop := InstallFreezeSignalHandler(h)
	defer stop()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, h.Frozen)
	if r := <-reasons; r != "USR1 signal" {
		t.Fatalf("reason %q", r)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !h.Frozen() })
	if r := <-reasons; r != "USR2 signal" {
		t.Fatalf("reason %q", r)
	}
	stop()
	stop() // idempotent
}
