package providers

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The tests re-execute the test binary as a stand-in for an external tool.
func TestMain(m *testing.M) {
	if os.Getenv("RGT_PROVIDERS_HELPER") == "1" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

func helperMain() {
	switch os.Getenv("RGT_HELPER_MODE") {
	case "echo":
		in := make([]byte, 64)
		n, _ := os.Stdin.Read(in)
		os.Stdout.WriteString("out:" + string(in[:n]))
		os.Stderr.WriteString("ERR-SECRET")
	case "fail":
		os.Stdout.WriteString("partial")
		os.Stderr.WriteString("ERR-SECRET")
		os.Exit(3)
	case "sleep":
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}

func runHelper(t *testing.T, mode string, stdin []byte) ([]byte, error) {
	t.Helper()
	t.Setenv("RGT_PROVIDERS_HELPER", "1")
	t.Setenv("RGT_HELPER_MODE", mode)
	return execRunner(context.Background(), os.Args[0], nil, stdin)
}

func TestExecRunnerStdoutStdinAndDiscardedStderr(t *testing.T) {
	out, err := runHelper(t, "echo", []byte("hello"))
	if err != nil || string(out) != "out:hello" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if strings.Contains(string(out), "ERR-SECRET") {
		t.Fatal("stderr must not be captured")
	}
}

func TestExecRunnerExitCode(t *testing.T) {
	out, err := runHelper(t, "fail", nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 {
		t.Fatalf("err = %v", err)
	}
	if string(out) != "partial" {
		t.Fatalf("out %q", out)
	}
	if got := describeRunError(err); got != "exit status 3" || strings.Contains(err.Error(), "ERR-SECRET") {
		t.Fatalf("describe: %q / %v", got, err)
	}
}

func TestExecRunnerNotFoundAndTimeout(t *testing.T) {
	_, err := execRunner(context.Background(), "rgt-definitely-not-installed-xyz", nil, nil)
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	old := commandTimeout
	commandTimeout = 50 * time.Millisecond
	defer func() { commandTimeout = old }()
	_, err = runHelper(t, "sleep", nil)
	if !errors.Is(err, context.DeadlineExceeded) || describeRunError(err) != "timed out" {
		t.Fatalf("err = %v / %q", err, describeRunError(err))
	}
}

func TestDescribeRunError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&ExitError{Code: 44}, "exit status 44"},
		{exec.ErrNotFound, "executable not found"},
		{os.ErrNotExist, "executable not found"},
		{os.ErrPermission, "permission denied"},
		{context.DeadlineExceeded, "timed out"},
		{errors.New("whatever"), "could not be started"},
	} {
		if got := describeRunError(tc.err); got != tc.want {
			t.Errorf("%v: %q", tc.err, got)
		}
	}
}
