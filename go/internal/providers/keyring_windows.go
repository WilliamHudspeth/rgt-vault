//go:build windows

package providers

import (
	"errors"
	"syscall"

	"github.com/danieljoos/wincred"
)

// Windows: go-keyring would address the credential "service:user", but Python
// keyring's WinVault backend uses target "service" (UserName = user) and
// "user@service" on collision. To read vaults provisioned by Python, and to
// write entries Python can read back, we speak WinVault's convention through
// wincred (see winvault.go). Entries written by go-keyring itself
// ("service:user", UTF-8 blob) are still readable as a fallback.

type wincredStore struct{}

func (wincredStore) Read(target string) (*winCredential, error) {
	c, err := wincred.GetGenericCredential(target)
	if err != nil {
		if errors.Is(err, syscall.ERROR_NOT_FOUND) {
			return nil, nil
		}
		return nil, err
	}
	return &winCredential{UserName: c.UserName, Blob: c.CredentialBlob}, nil
}

func (wincredStore) Write(target, userName string, blob []byte) error {
	c := wincred.NewGenericCredential(target)
	c.UserName = userName
	c.CredentialBlob = blob
	c.Comment = "Stored using python-keyring"
	c.Persist = wincred.PersistEnterprise
	return c.Write()
}

func platformKeyringGet(service, user string) (string, error) {
	return winVaultGet(wincredStore{}, service, user)
}

func platformKeyringSet(service, user, value string) error {
	return winVaultSet(wincredStore{}, service, user, value)
}
