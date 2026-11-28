//go:build !windows

package logging

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFileWriterDirectoryAndFileModes(t *testing.T) {
	// A PRE-EXISTING directory is never chmodded (it may be /var/log or a home
	// directory); a pre-existing 0640 file is still tightened to 0600.
	base := t.TempDir()
	dir := filepath.Join(base, "logs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	fw, err := OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = fw.Close()
	assertMode(t, dir, 0o755)
	assertMode(t, path, 0o600)

	// A directory created by the writer is 0700 (even when the process umask is 0).
	oldMask := syscall.Umask(0)
	fresh := filepath.Join(base, "fresh", "deeper")
	fw, err = OpenFileWriter(filepath.Join(fresh, "c.log"))
	syscall.Umask(oldMask)
	if err != nil {
		t.Fatal(err)
	}
	_ = fw.Close()
	assertMode(t, fresh, 0o700)

	// A FIFO at the log path is refused promptly instead of blocking forever.
	fifo := filepath.Join(dir, "pipe.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		w, err := OpenFileWriter(fifo)
		if err == nil {
			_ = w.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("OpenFileWriter accepted a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenFileWriter blocked on a FIFO")
	}

	// A symlinked log FILE is refused (O_NOFOLLOW).
	target := filepath.Join(base, "target.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if fw, err := OpenFileWriter(link); err == nil {
		_ = fw.Close()
		t.Error("OpenFileWriter followed a symlinked log file")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != want {
		t.Errorf("%s mode = %04o, want %04o", path, got, want)
	}
}
