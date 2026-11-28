package vault

// MasterProvider is the source of the root-of-trust master secret
// (Python: MasterSecretProvider.get_secret). The returned slice is owned by
// the vault, which wipes it once the keys are derived.
//
// go/internal/providers implements it structurally (it does not import this
// package), as do the test providers in providers/providerstest.
type MasterProvider interface {
	GetMasterSecret() ([]byte, error)
}

// Rotator is the optional capability to generate and persist a new master
// secret (Python: rotate_secret). RotateMaster checks for it BEFORE touching
// the key epoch (Python P1-4).
type Rotator interface {
	RotateMasterSecret() ([]byte, error)
}

// Bootstrapper is the optional capability to create the master secret on
// first use (Python: bootstrap_master_secret). Open calls it only when no
// keychain.json exists yet.
type Bootstrapper interface {
	BootstrapMasterSecret() error
}

// VaultBinder is implemented by providers whose storage location depends on
// the vault (RGT-522: the file provider's per-vault key path; RGT-535: the
// per-vault keyring account). Open calls it once, after reading the vault id
// and before Bootstrap/GetMasterSecret.
type VaultBinder interface {
	BindVault(vaultID string) error
}

// MasterRecovery is implemented by providers that keep the previous master
// secret across a rotation until the vault has proven the new one (RGT-522:
// the file provider's <key>.prev). It closes the window in which a crash
// between the provider's switch and the re-wrapped keychain would leave no
// key that opens the vault.
type MasterRecovery interface {
	// PreviousMasterSecret returns the secret from before the last,
	// unconfirmed rotation; an error (wrapping fs.ErrNotExist) when none is
	// kept.
	PreviousMasterSecret() ([]byte, error)
	// ConfirmMasterSecret is called once master has unwrapped keychain.json
	// of vault vaultID: the provider may drop the previous secret (if it
	// still holds master) and record which vault the key belongs to. An
	// error fails the open.
	ConfirmMasterSecret(vaultID string, master []byte) error
	// RecoveryHint tells the operator how to restore the previous secret.
	RecoveryHint() string
}

// keyLocator is implemented by providers that can name where the master
// secret is kept (never the secret itself).
type keyLocator interface{ Location() string }
