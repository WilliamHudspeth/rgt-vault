package providers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDPAPIBlobPath is the Windows default of python/providers/__init__.py.
const DefaultDPAPIBlobPath = `C:\ProgramData\vault\sealed.bin`

// DPAPI seams: dpapi_windows.go installs the real crypt32 calls; every other
// OS gets stubs returning ErrUnsupportedPlatform. Tests replace them.
var (
	dpapiProtect   = platformDPAPIProtect
	dpapiUnprotect = platformDPAPIUnprotect
)

// DPAPIProvider unseals the master secret from a file holding base64 of a
// DPAPI blob (CryptProtectData, machine scope). Entropy is optional.
type DPAPIProvider struct {
	BlobPath string
	Entropy  []byte
}

// NewDPAPIProvider returns a provider for the blob at blobPath. Like Python,
// the file must already exist.
func NewDPAPIProvider(blobPath string, entropy []byte) (*DPAPIProvider, error) {
	if err := statRegular(blobPath, "DPAPI blob"); err != nil {
		return nil, err
	}
	return &DPAPIProvider{BlobPath: blobPath, Entropy: entropy}, nil
}

// GetMasterSecret reads the blob file, base64-decodes it and calls
// CryptUnprotectData(flags=4).
func (p *DPAPIProvider) GetMasterSecret() ([]byte, error) {
	text, err := os.ReadFile(p.BlobPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read DPAPI blob: %w", ErrMasterSecretUnavailable, err)
	}
	blob, err := decodeStdBase64(string(text))
	if err != nil {
		return nil, fmt.Errorf("%w: DPAPI blob file is not valid base64", ErrMasterSecretUnavailable)
	}
	secret, err := dpapiUnprotect(blob, p.Entropy)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterSecretUnavailable, err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: DPAPI blob holds an empty secret", ErrMasterSecretUnavailable)
	}
	return secret, nil
}

// RotateMasterSecret seals a fresh 32-byte secret over the existing blob file
// (write to a temp file in the same directory, then rename).
func (p *DPAPIProvider) RotateMasterSecret() ([]byte, error) {
	secret, err := newMasterSecret()
	if err != nil {
		return nil, err
	}
	if err := SealDPAPI(secret, p.BlobPath, p.Entropy); err != nil {
		Wipe(secret)
		return nil, err
	}
	return secret, nil
}

// SealDPAPI protects masterSecret with CryptProtectData (flags=4, description
// "Vault Master Secret") and writes base64 of the blob to outputPath, creating
// parent directories. The file is replaced atomically.
func SealDPAPI(masterSecret []byte, outputPath string, entropy []byte) error {
	if len(masterSecret) == 0 {
		return errors.New("refusing to seal an empty master secret")
	}
	blob, err := dpapiProtect(masterSecret, entropy)
	if err != nil {
		return err
	}
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create DPAPI blob directory: %w", err)
	}
	return writeFileAtomic(outputPath, []byte(base64.StdEncoding.EncodeToString(blob)), 0o600)
}

// writeFileAtomic writes data to a temp file beside path and renames it over
// path, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(perm); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// decodeStdBase64 mimics base64.b64decode: it ignores whitespace.
func decodeStdBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(s)
}

// statRegular checks that path is a regular file. A missing file wraps
// fs.ErrNotExist; any other failure (for example a permission error on the
// parent directory) is reported as itself instead of as "not found".
func statRegular(path, what string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s not found: %s: %w", what, path, fs.ErrNotExist)
		}
		return fmt.Errorf("%s: %w", what, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s not found: %s is not a regular file: %w", what, path, fs.ErrNotExist)
	}
	return nil
}
