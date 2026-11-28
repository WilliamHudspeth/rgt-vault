//go:build !unix

package captoken

import "os"

// checkKeyOwner is a no-op where file ownership is not a uid (Windows).
func checkKeyOwner(os.FileInfo) error { return nil }
