//go:build darwin

package providers

import (
	"context"
	"errors"

	"github.com/zalando/go-keyring"
)

// macOS: reads go through go-keyring (it understands raw values, which is
// what Python keyring writes). Writes do NOT use keyring.Set because
// go-keyring prefixes values with "go-keyring-base64:", which Python's
// keyring would then return verbatim and fail to decode. The value is plain
// urlsafe-base64 (ASCII), so it is stored raw through `security -i`, the same
// way [SealMacOSKeychain] does.

func platformKeyringGet(service, user string) (string, error) {
	v, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", errKeyNotFound
	}
	return v, err
}

func platformKeyringSet(service, user, value string) error {
	return sealMacOS(context.Background(), execRunner, []byte(value), service, user, true, false)
}
