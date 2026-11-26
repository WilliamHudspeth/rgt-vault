//go:build !windows && !darwin

package providers

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// Linux and other Unix: go-keyring's Secret Service backend stores items with
// attributes {service, username}, the same attributes and label that Python
// keyring's SecretService backend uses, so entries are interchangeable.

func platformKeyringGet(service, user string) (string, error) {
	v, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", errKeyNotFound
	}
	return v, err
}

func platformKeyringSet(service, user, value string) error {
	return keyring.Set(service, user, value)
}
