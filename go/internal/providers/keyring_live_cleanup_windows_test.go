//go:build windows

package providers

import "github.com/danieljoos/wincred"

func cleanupLiveKeyring(service, user string) {
	for _, target := range []string{service, user + "@" + service, service + ":" + user} {
		if c, err := wincred.GetGenericCredential(target); err == nil {
			_ = c.Delete()
		}
	}
}
