package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/vault"
)

// Store is a throwaway development vault: a REAL vault (encrypted SQLite,
// keychain, hash-chained audit log) in a fresh temporary directory, with a
// random master secret held only in memory and an allow-all policy.
//
// Deprecated: it exists only so callers of the removed in-memory stub
// (`rgt-vault serve` in go/cmd/rgt-vault and one MCP test) keep compiling
// until batch G10 wires `serve` to server.New with --db/--policy/--provider.
// Everything in it is lost when the process exits. Do not use it for new
// code; build a vault with vault.Open (or server.OpenStack) and call
// server.New.
//
// TODO(G10): delete with the last caller.
type Store struct {
	Vault   *vault.Vault
	Actions *actions.Registry
	dir     string
}

// ephemeralPolicy allows everything: the removed stub had no policy at all.
const ephemeralPolicy = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
`

// ephemeralKDF: the master never leaves memory and the files are thrown
// away, so Argon2 hardness buys nothing here.
var ephemeralKDF = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

type memoryMaster struct {
	mu     sync.Mutex
	secret []byte
}

func (m *memoryMaster) GetMasterSecret() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.secret...), nil
}

// NewStore opens a fresh ephemeral development vault (see Store). It panics
// if the vault cannot be created.
//
// Deprecated: see Store.
func NewStore() *Store {
	s, err := newEphemeralStore()
	if err != nil {
		panic("handlers.NewStore: " + err.Error())
	}
	return s
}

func newEphemeralStore() (*Store, error) {
	dir, err := os.MkdirTemp("", "rgt-vault-ephemeral-")
	if err != nil {
		return nil, err
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	acts, err := actions.NewBuiltinRegistry(actions.Config{})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	v, err := vault.Open(context.Background(), vault.Config{
		DBPath:       filepath.Join(dir, "vault.db"),
		Provider:     &memoryMaster{secret: master},
		PolicyYAML:   ephemeralPolicy,
		KDFParams:    ephemeralKDF,
		Capabilities: capabilities.NewDefault(ActionBridge{Registry: acts}),
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("open ephemeral vault: %w", err)
	}
	log.Printf("WARNING: serving an EPHEMERAL allow-all development vault in %s; "+
		"secrets are lost on exit (TODO(G10): wire --db/--policy/--provider)", dir)
	return &Store{Vault: v, Actions: acts, dir: dir}, nil
}

// Close closes the vault and deletes its temporary directory.
func (s *Store) Close() error {
	err := s.Vault.Close()
	if rerr := os.RemoveAll(s.dir); err == nil {
		err = rerr
	}
	return err
}

// NewHandlers wires handlers over an ephemeral development Store. The token
// store argument is unused (authentication is the middleware's job) and is
// kept for source compatibility.
//
// Deprecated: build Handlers (or call server.New) with a real vault.
func NewHandlers(s *Store, _ *auth.TokenStore) *Handlers {
	return &Handlers{Vault: s.Vault, Actions: s.Actions}
}
