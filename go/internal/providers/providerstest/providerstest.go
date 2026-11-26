// Package providerstest holds master-secret providers for tests of OTHER
// packages (vault, keychain, CLI, compat). It is not for production use: the
// secrets live in memory or in a plain file.
package providerstest

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Memory is an in-memory provider holding a fixed or random 32-byte secret.
// It implements providers.MasterProvider, Rotator and Bootstrapper
// structurally. The zero value is NOT usable; use [NewMemory] or [NewMemoryFixed].
type Memory struct {
	mu          sync.Mutex
	secret      []byte
	Gets        int   // number of GetMasterSecret calls
	Rotations   int   // number of RotateMasterSecret calls
	Bootstraps  int   // number of BootstrapMasterSecret calls
	GetErr      error // returned by GetMasterSecret when non-nil
	RotateErr   error // returned by RotateMasterSecret when non-nil
	BootstrapOK bool  // true after BootstrapMasterSecret created the secret
}

// NewMemory returns a provider with a random 32-byte secret.
func NewMemory() *Memory {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return &Memory{secret: b}
}

// NewMemoryFixed returns a provider with the given secret (copied).
func NewMemoryFixed(secret []byte) *Memory {
	return &Memory{secret: bytes.Clone(secret)}
}

// GetMasterSecret returns a copy of the secret.
func (m *Memory) GetMasterSecret() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Gets++
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	return bytes.Clone(m.secret), nil
}

// RotateMasterSecret replaces the secret with a new random one.
func (m *Memory) RotateMasterSecret() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Rotations++
	if m.RotateErr != nil {
		return nil, m.RotateErr
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	m.secret = b
	return bytes.Clone(b), nil
}

// BootstrapMasterSecret records the call; the secret already exists.
func (m *Memory) BootstrapMasterSecret() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Bootstraps++
	m.BootstrapOK = true
	return nil
}

// Fixed is a provider that can only read: it has no rotate or bootstrap
// capability, like the macOS provider. Use it to test the "rotation not
// supported" pre-check.
type Fixed struct{ Secret []byte }

// GetMasterSecret returns a copy of Secret.
func (f Fixed) GetMasterSecret() ([]byte, error) { return bytes.Clone(f.Secret), nil }

// File is a provider backed by a plain file holding the raw secret bytes
// (like a Docker/Kubernetes secret mount, or the G0 fixtures' master.bin).
type File struct{ Path string }

// GetMasterSecret reads the file. An empty or missing file is an error.
func (f File) GetMasterSecret() ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read master secret file: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("master secret file is empty")
	}
	return b, nil
}

// RotateMasterSecret writes a new random 32-byte secret (mode 0600).
func (f File) RotateMasterSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(f.Path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}
