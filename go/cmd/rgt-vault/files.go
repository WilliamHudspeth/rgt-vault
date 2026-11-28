package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/keychain"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/servecmd"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
)

// writeSecretFile writes data to path as a fresh 0600 file, atomically: the
// bytes go to a private temp file in the same directory (0600 from the
// moment it is opened, so there is no window with a looser mode) which is
// then moved into place.
//
// With overwrite false an existing file is never touched: the move is a
// no-clobber hard link, so two concurrent `init` runs cannot both win, and
// created is false. With overwrite true the file is replaced.
func writeSecretFile(path string, data []byte, overwrite bool) (created bool, err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("creating directory for %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, ".rgt-*")
	if err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return false, fmt.Errorf("restricting %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	if overwrite {
		if err := os.Rename(tmpName, path); err != nil {
			return false, fmt.Errorf("writing %s: %w", path, err)
		}
		return true, nil
	}
	err = os.Link(tmpName, path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrExist):
		return false, nil
	}
	// The file system has no hard links: fall back to check-then-rename.
	if _, serr := os.Lstat(path); serr == nil {
		return false, nil
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	return true, nil
}

// vaultFileExists reports whether a vault already lives at db: the database
// and keychain.json next to it.
func vaultFileExists(db string) bool {
	_, e1 := os.Stat(db)
	_, e2 := os.Stat(filepath.Join(filepath.Dir(db), keychain.FileName))
	return e1 == nil && e2 == nil
}

// errNoVault says that no vault exists at db and how to create one.
func errNoVault(db string) error {
	return fmt.Errorf("no vault at %s (database or keychain.json missing): run `rgt-vault init --db %s` first", db, db)
}

// openStackFor opens the vault selected by vf. With create false it refuses
// to create one (a mistyped --db must not silently bootstrap a new vault and
// master secret).
func openStackFor(ctx context.Context, vf *servecmd.VaultFlags, create, approval bool) (*server.Stack, servecmd.Resolved, error) {
	res, err := vf.Resolve(os.Getenv)
	if err != nil {
		return nil, res, err
	}
	if !create && !vaultFileExists(res.DB) {
		return nil, res, errNoVault(res.DB)
	}
	stack, err := openStackAt(ctx, res, server.StackOptions{RequireApproval: approval})
	return stack, res, err
}

// openStackAt opens the vault at res with extra options.
func openStackAt(ctx context.Context, res servecmd.Resolved, o server.StackOptions) (*server.Stack, error) {
	mk := newProvider
	if mk == nil {
		mk = server.NewProvider
	}
	prov, err := mk(res.Provider)
	if err != nil {
		return nil, err
	}
	o.DBPath, o.PolicyFile, o.MasterProvider, o.KDFParams = res.DB, res.Policy, prov, kdfParams
	if ctx == nil {
		ctx = context.Background()
	}
	stack, err := server.OpenStack(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("opening vault %s: %w", res.DB, err)
	}
	return stack, nil
}
