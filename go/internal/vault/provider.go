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
