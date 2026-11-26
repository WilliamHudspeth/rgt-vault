package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"time"
)

// commandTimeout bounds every external tool invocation so a wedged TPM or
// keychain prompt cannot hang the vault forever.
var commandTimeout = 60 * time.Second

// Runner is the seam for starting an external program. name and args are an
// argv; no shell is ever involved. stdin may be nil. Only stdout is returned:
// stderr is discarded so tool diagnostics cannot leak into errors (RGT-371).
//
// A non-zero exit status must be reported as *[ExitError]. A missing binary
// must wrap exec.ErrNotFound, and an access problem must wrap fs.ErrPermission.
type Runner func(ctx context.Context, name string, args []string, stdin []byte) (stdout []byte, err error)

// ExitError reports that an external program exited with a non-zero status.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// execRunner is the real [Runner]: os/exec with an argv, a timeout, and
// stderr discarded.
func execRunner(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- argv only, name is a fixed tool name
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	// cmd.Stderr stays nil: output goes to the null device.

	err := cmd.Run()
	if err == nil {
		return out.Bytes(), nil
	}
	if ctx.Err() != nil {
		return out.Bytes(), fmt.Errorf("%s: %w", name, ctx.Err())
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Bytes(), &ExitError{Code: ee.ExitCode()}
	}
	return out.Bytes(), err
}

// describeRunError turns a Runner error into a short, output-free reason.
func describeRunError(err error) string {
	var ee *ExitError
	switch {
	case errors.As(err, &ee):
		return ee.Error()
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return "executable not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	default:
		return "could not be started"
	}
}
