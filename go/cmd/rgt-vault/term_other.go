//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package main

import (
	"errors"
	"os"
)

// disableEcho is unsupported here: the prompt refuses, and --totp-code
// remains available.
func disableEcho(*os.File) (func(), error) {
	return nil, errors.New("no-echo prompt is not supported on this platform; use --totp-code")
}
