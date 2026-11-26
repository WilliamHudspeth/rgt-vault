//go:build darwin

package providers

import "context"

// macOS: both directions go through the same absolute-path `security`
// invocations as [MacOSKeychainProvider]/[SealMacOSKeychain], with the
// commandTimeout and output-free errors of [execRunner]. go-keyring is not
// used here because keyring.Set prefixes values with "go-keyring-base64:",
// which Python's keyring would return verbatim and fail to decode. The value
// is plain urlsafe-base64 (ASCII), stored raw, so Python and Go interoperate.

func platformKeyringGet(service, user string) (string, error) {
	return securityFind(context.Background(), execRunner, service, user)
}

func platformKeyringSet(service, user, value string) error {
	return sealMacOS(context.Background(), execRunner, []byte(value), service, user, true, false)
}
