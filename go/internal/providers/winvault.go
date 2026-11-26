package providers

import (
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// This file is the portable half of the Windows Credential Manager keyring
// backend. It reproduces keyring/backends/Windows.py (WinVaultKeyring,
// keyring 25.x) over an abstract credential store, so the convention is unit
// tested on every OS; keyring_windows.go supplies the real store.
//
// WinVault has no (service, user) addressing, so Python keyring:
//   - stores a password under TargetName = service, UserName = user, with the
//     blob encoded UTF-16LE;
//   - on collision (same service, different user) first re-saves the existing
//     credential under TargetName = "<existingUser>@<service>";
//   - reads TargetName = service and, if its UserName differs, falls back to
//     "<user>@<service>".
//
// go-keyring instead uses TargetName "service:user" with a UTF-8 blob. That
// form is only consulted as a last-resort read fallback.
//
// UNVERIFIED on a real Windows host: the plan could not run Windows CI for
// this batch. The logic mirrors the Python source; the windows-tagged test in
// keyring_windows_test.go exercises the real wincred store.

// winCredential is the subset of a generic credential that matters here.
type winCredential struct {
	UserName string
	Blob     []byte
}

// credStore abstracts CredRead/CredWrite. Read returns (nil, nil) for "not found".
type credStore interface {
	Read(target string) (*winCredential, error)
	Write(target, userName string, blob []byte) error
}

func winCompoundName(user, service string) string { return user + "@" + service }

func winVaultGet(s credStore, service, user string) (string, error) {
	res, err := s.Read(service)
	if err != nil {
		return "", err
	}
	if res == nil || (user != "" && res.UserName != user) {
		if res, err = s.Read(winCompoundName(user, service)); err != nil {
			return "", err
		}
	}
	if res != nil {
		v := decodeWinBlob(res.Blob)
		if v == "" && len(res.Blob) > 0 {
			// An entry exists but cannot be decoded: fail closed rather than
			// report "missing" (which would let InitializeIfMissing overwrite it).
			return "", fmt.Errorf("%w: credential blob is neither UTF-16 nor UTF-8", ErrMasterSecretUnavailable)
		}
		return v, nil
	}
	// go-keyring convention, for entries written by go-keyring itself.
	res, err = s.Read(service + ":" + user)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", errKeyNotFound
	}
	return string(res.Blob), nil
}

func winVaultSet(s credStore, service, user, value string) error {
	existing, err := s.Read(service)
	if err != nil {
		return err
	}
	// Python also re-saves an existing entry of the SAME user under the
	// compound target. We skip that: it would keep a rotated (possibly
	// compromised) master secret in the Credential Manager indefinitely, and
	// winVaultGet could resurrect it. Entries of OTHER users are preserved.
	if existing != nil && existing.UserName != user {
		if err := s.Write(winCompoundName(existing.UserName, service), existing.UserName, existing.Blob); err != nil {
			return fmt.Errorf("preserve existing credential: %w", err)
		}
	}
	if err := s.Write(service, user, encodeWinBlob(value)); err != nil {
		return err
	}
	// Refresh aliases of this entry that already exist (Python's "<user>@<service>"
	// and go-keyring's "<service>:<user>"), so a rotation leaves no stale copy
	// of the old secret that winVaultGet could later fall back to.
	if c, err := s.Read(winCompoundName(user, service)); err != nil {
		return err
	} else if c != nil && c.UserName == user {
		if err := s.Write(winCompoundName(user, service), user, encodeWinBlob(value)); err != nil {
			return err
		}
	}
	if c, err := s.Read(service + ":" + user); err != nil {
		return err
	} else if c != nil {
		if err := s.Write(service+":"+user, user, []byte(value)); err != nil {
			return err
		}
	}
	return nil
}

// encodeWinBlob is str.encode("utf-16-le"): Python keyring's blob format.
func encodeWinBlob(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(units))
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// decodeWinBlob mirrors DecodingCredential.value: UTF-16 first (what Python
// writes), UTF-8 when the blob is not valid UTF-16.
func decodeWinBlob(blob []byte) string {
	if len(blob)%2 == 0 {
		units := make([]uint16, len(blob)/2)
		for i := range units {
			units[i] = uint16(blob[2*i]) | uint16(blob[2*i+1])<<8
		}
		if validUTF16(units) {
			return string(utf16.Decode(units))
		}
	}
	if utf8.Valid(blob) {
		return string(blob)
	}
	return "" // undecodable; the caller treats an empty value as missing
}

// validUTF16 reports whether units has no unpaired surrogate.
func validUTF16(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		switch u := units[i]; {
		case u >= 0xD800 && u < 0xDC00:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] >= 0xE000 {
				return false
			}
			i++
		case u >= 0xDC00 && u < 0xE000:
			return false
		}
	}
	return true
}
