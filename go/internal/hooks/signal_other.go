//go:build !unix

package hooks

// InstallFreezeSignalHandler is a no-op without POSIX signals (Windows), as
// in Python. Use the freeze file or FreezeWatcher there.
func InstallFreezeSignalHandler(Freezer) (stop func()) { return func() {} }
