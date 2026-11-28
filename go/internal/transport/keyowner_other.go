//go:build !unix

package transport

import "os"

// checkKeyOwner: file ownership is not checked off Unix.
func checkKeyOwner(string, os.FileInfo) error { return nil }
