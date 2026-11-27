package actions

import (
	"errors"
	"fmt"
)

var (
	// ErrActionNotFound is the Go form of ActionNotFoundError (HTTP 404).
	ErrActionNotFound = errors.New("action not found")
	// ErrActionExecution is the Go form of ActionExecutionError (HTTP 400/502).
	ErrActionExecution = errors.New("action execution failed")
)

// Error is an action error whose text is safe to return to the caller: it is
// composed only from caller-supplied names and fixed strings, never from an
// upstream body, a header, or the secret.
type Error struct {
	kind error
	msg  string
}

func (e *Error) Error() string { return e.msg }

// Is matches the kind sentinel.
func (e *Error) Is(target error) bool { return target == e.kind }

func execErr(format string, args ...any) error {
	return &Error{kind: ErrActionExecution, msg: fmt.Sprintf(format, args...)}
}

func notFound(format string, args ...any) error {
	return &Error{kind: ErrActionNotFound, msg: fmt.Sprintf(format, args...)}
}
