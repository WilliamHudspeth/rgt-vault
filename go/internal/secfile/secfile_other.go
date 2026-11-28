//go:build !unix && !windows

package secfile

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("secfile: not supported on this platform")

func openChecked(string, Options) (*os.File, int64, error) { return nil, 0, errUnsupported }

func checkDirChain(string) error { return errUnsupported }

func createExclusive(string, []byte) error { return errUnsupported }
