//go:build !windows

package providers

import "github.com/zalando/go-keyring"

func cleanupLiveKeyring(service, user string) { _ = keyring.Delete(service, user) }
