//go:build !windows

package providers

func platformDPAPIProtect(_, _ []byte) ([]byte, error) { return nil, ErrUnsupportedPlatform }

func platformDPAPIUnprotect(_, _ []byte) ([]byte, error) { return nil, ErrUnsupportedPlatform }
