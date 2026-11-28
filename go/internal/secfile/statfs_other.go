//go:build unix && !linux

package secfile

import (
	"errors"
	"os"
)

// fsInfo: systemd credentials exist only on Linux; elsewhere the credential
// exception never applies.
var fsInfo = func(*os.File) (inMemory, readOnly bool, err error) {
	return false, false, errors.New("filesystem type not checked on this OS")
}
