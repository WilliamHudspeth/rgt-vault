package providers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/secfile"
)

// The `file` provider (RGT-522, docs/design/file-provider.md) delivers the
// master secret from exactly one source, chosen in this order:
//
//  1. an explicit path (--master-key-file / RGT_VAULT_MASTER_KEY_FILE);
//  2. a systemd credential: $CREDENTIALS_DIRECTORY/rgt-vault-master (name
//     overridable with RGT_VAULT_MASTER_CREDENTIAL), as delivered by
//     LoadCredential= or LoadCredentialEncrypted= (read-only);
//  3. the per-vault default path ~/.config/rgt-vault/keys/<vault-id>.key,
//     bound once the vault id is known ([FileProvider.BindVault]).
//
// On disk the key is the same text as the keyring entry: urlsafe-base64 of
// 32 random bytes plus "\n". On read that form (padded or not, either
// alphabet) or exactly 32 raw bytes is accepted; anything else, or anything
// over 128 bytes, is refused. Every read goes through package secfile.

// Environment variables of the file provider.
const (
	EnvMasterKeyFile        = "RGT_VAULT_MASTER_KEY_FILE"
	EnvCredentialsDirectory = "CREDENTIALS_DIRECTORY"
	EnvMasterCredential     = "RGT_VAULT_MASTER_CREDENTIAL"
	// EnvInsecureKeyACL=1 turns Windows ACL refusals of the key file into
	// warnings. Diagnosis only.
	EnvInsecureKeyACL = "RGT_VAULT_INSECURE_KEY_ACL"
)

// DefaultMasterCredential is the systemd credential name the file provider
// looks for in $CREDENTIALS_DIRECTORY.
const DefaultMasterCredential = "rgt-vault-master"

// MaxKeyFileSize is the largest key file the file provider reads.
const MaxKeyFileSize = 128

// CredentialRecipe is how to (re-)seal the master key as an encrypted
// systemd credential.
const CredentialRecipe = "systemd-creds encrypt --with-key=tpm2 --name=rgt-vault-master key.txt " +
	"/etc/credstore.encrypted/rgt-vault-master, then add " +
	"LoadCredentialEncrypted=rgt-vault-master:/etc/credstore.encrypted/rgt-vault-master to the unit and restart it"

// FileOptions configure [NewFileProvider].
type FileOptions struct {
	// Path is the explicit key file (source 1). Empty falls back to the
	// systemd credential, then to the default path.
	Path string
	// KeysDir overrides ~/.config/rgt-vault/keys (tests).
	KeysDir string
	// Getenv reads the environment (default os.Getenv).
	Getenv func(string) string
	// Warn receives warnings (default: standard error).
	Warn func(string)
}

// FileProvider reads the master secret from a key file: an explicit path or
// the per-vault default path. It implements [Rotator], [Bootstrapper],
// VaultBinder, MasterRecovery and Probe.
//
// Beside the key file <key> it keeps:
//   - <key>.vault-id: the id of the vault the key belongs to, written once the
//     key has unwrapped that vault's keychain. A key bound to another vault is
//     refused, so two vaults never share (and one never rotates away) a key.
//   - <key>.prev: the key from before a master rotation, until the vault has
//     opened with the new key. A crash in the middle of a rotation therefore
//     never leaves the vault without a key that opens it.
type FileProvider struct {
	path     string // the key file; empty until BindVault for the default source
	keysDir  string // non-empty for the default (per-vault) source
	explicit bool
	vaultID  string
	created  []string // files this process created (init cleans them up on failure)
	opts     secfile.Options
}

// PrevPath is where the key from before an unconfirmed rotation is kept.
func PrevPath(keyPath string) string { return keyPath + ".prev" }

// VaultIDPath is the sidecar that binds a key file to one vault.
func VaultIDPath(keyPath string) string { return keyPath + ".vault-id" }

// CredentialProvider reads the master secret from a systemd credential. It
// is read-only: it does not implement [Rotator], so a master rotation is
// refused before anything changes (re-seal it with [CredentialRecipe]).
type CredentialProvider struct {
	path string
	opts secfile.Options
}

var credentialName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// NewFileProvider returns the provider for the first source that applies.
func NewFileProvider(o FileOptions) (MasterProvider, error) {
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	warn := o.Warn
	if warn == nil {
		warn = func(s string) { fmt.Fprintln(os.Stderr, s) }
	}
	opts := secfile.Options{MaxSize: MaxKeyFileSize, Warn: warn}
	if getenv(EnvInsecureKeyACL) == "1" {
		opts.InsecureACL = true
		if runtime.GOOS == "windows" {
			warn("WARNING: " + EnvInsecureKeyACL + "=1: the master key file's ACL is NOT enforced (diagnosis only); unset it")
		} else {
			warn("WARNING: " + EnvInsecureKeyACL + "=1 has no effect on this OS (the Unix permission checks always apply)")
		}
	}

	if o.Path != "" {
		abs, err := filepath.Abs(o.Path)
		if err != nil {
			return nil, err
		}
		return &FileProvider{path: abs, explicit: true, opts: opts}, nil
	}

	credDir := getenv(EnvCredentialsDirectory)
	name := getenv(EnvMasterCredential)
	named := name != ""
	if !named {
		name = DefaultMasterCredential
	}
	if !credentialName.MatchString(name) || name == "." || name == ".." {
		return nil, fmt.Errorf("file provider: %s=%q is not a valid credential name", EnvMasterCredential, name)
	}
	switch {
	case credDir != "":
		p := filepath.Join(credDir, name)
		if _, err := os.Lstat(p); err == nil {
			copts := opts
			copts.Credential = true
			return &CredentialProvider{path: p, opts: copts}, nil
		}
		// Running under systemd without the credential: never fall back to a
		// plaintext default key file silently (review M2).
		return nil, fmt.Errorf("%w: systemd credential %q not found in $%s (%s): add "+
			"LoadCredentialEncrypted=%s:/etc/credstore.encrypted/%s (or LoadCredential=) to the unit, "+
			"or pass --master-key-file PATH to use a key file explicitly",
			ErrMasterSecretUnavailable, name, EnvCredentialsDirectory, credDir, name, name)
	case named:
		return nil, fmt.Errorf("%w: %s is set but $%s is not: the credential exists only inside a systemd unit "+
			"with LoadCredentialEncrypted=%s:/etc/credstore.encrypted/%s",
			ErrMasterSecretUnavailable, EnvMasterCredential, EnvCredentialsDirectory, name, name)
	}

	dir := o.KeysDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return nil, fmt.Errorf("file provider: no home directory for the default key path; pass --master-key-file")
		}
		dir = filepath.Join(home, ".config", "rgt-vault", "keys")
	}
	return &FileProvider{keysDir: dir, opts: opts}, nil
}

// DefaultKeyPath is the per-vault default key file under keysDir.
func DefaultKeyPath(keysDir, vaultID string) string {
	return filepath.Join(keysDir, vaultID+".key")
}

var vaultIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// BindVault sets the per-vault default path and refuses a key file that is
// bound to another vault (<key>.vault-id). The vault calls it once, after
// reading the vault id and before Bootstrap/GetMasterSecret.
func (p *FileProvider) BindVault(vaultID string) error {
	if !vaultIDPattern.MatchString(vaultID) || len(vaultID) > 128 {
		return fmt.Errorf("file provider: vault id %q cannot name a key file", vaultID)
	}
	if p.vaultID != "" && p.vaultID != vaultID {
		return fmt.Errorf("file provider: already bound to vault %s", p.vaultID)
	}
	if !p.explicit {
		p.path = DefaultKeyPath(p.keysDir, vaultID)
	}
	p.vaultID = vaultID
	owner, err := p.boundVault()
	if err != nil {
		return err
	}
	if owner != "" && owner != vaultID {
		return fmt.Errorf("%w: master key file %s belongs to vault %s, not to this vault (%s): two vaults must not "+
			"share a key file (rotating one would lock the other out). Give this vault its own key file",
			ErrMasterSecretUnavailable, p.path, owner, vaultID)
	}
	return nil
}

// boundVault returns the vault id recorded in <key>.vault-id, or "".
func (p *FileProvider) boundVault() (string, error) {
	b, err := secfile.OpenSecret(VaultIDPath(p.path), secfile.Options{MaxSize: 256, InsecureACL: p.opts.InsecureACL, Warn: p.opts.Warn})
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("vault binding of the master key file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// Location describes where the key is (for messages; never the key).
func (p *FileProvider) Location() string {
	if p.path != "" {
		return p.path
	}
	return filepath.Join(p.keysDir, "<vault-id>.key")
}

// Probe checks, without creating anything, that the provider can work
// before a vault is created: an existing explicit key file must pass every
// check; otherwise its directory (or the nearest existing ancestor) must be
// safe.
func (p *FileProvider) Probe() error {
	if p.path != "" {
		if _, err := os.Lstat(p.path); err == nil {
			secret, err := p.GetMasterSecret()
			Wipe(secret)
			return err
		}
		return secfile.CheckCreatable(filepath.Dir(p.path))
	}
	return secfile.CheckCreatable(p.keysDir)
}

// CreatedFiles are the files this provider created in this process (for
// init's cleanup after a failure).
func (p *FileProvider) CreatedFiles() []string { return append([]string(nil), p.created...) }

func (p *FileProvider) bound() error {
	if p.path == "" {
		return errors.New("file provider: the vault id is not known yet (BindVault was not called)")
	}
	return nil
}

// GetMasterSecret reads and checks the key file. A missing file fails
// closed: a new key would make an existing vault unreadable.
func (p *FileProvider) GetMasterSecret() ([]byte, error) {
	if err := p.bound(); err != nil {
		return nil, err
	}
	return readKeyFile(p.path, p.opts, func() error {
		return fmt.Errorf("%w: no master key file at %s. Refusing to create one for an existing vault "+
			"(that would make it unreadable): restore the file from your backup, or point --master-key-file at it",
			ErrMasterSecretUnavailable, p.path)
	})
}

// BootstrapMasterSecret creates the key file for a fresh vault if, and only
// if, it is missing. An existing file is used as it is (pre-provisioned).
func (p *FileProvider) BootstrapMasterSecret() error {
	if err := p.bound(); err != nil {
		return err
	}
	if _, err := os.Lstat(p.path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("master key file %s: %w", p.path, err)
	}
	if err := secfile.EnsureDir(filepath.Dir(p.path)); err != nil {
		return fmt.Errorf("master key directory: %w", err)
	}
	created, err := writeNewKey(p.path)
	if created {
		p.created = append(p.created, p.path)
	}
	return err
}

// RotateMasterSecret keeps the current key as <key>.prev, then writes a new
// key to a temp file beside the old one and renames it over it. <key>.prev
// is removed only once the vault has installed (or opened with) the new key
// (ConfirmMasterSecret), so a crash before the re-wrapped keychain is on
// disk leaves the old key available.
//
// The vault calls it only after the current key has unwrapped the keychain
// (vault.RotateMaster loads it first), so the key saved as .prev is good.
func (p *FileProvider) RotateMasterSecret() ([]byte, error) {
	if err := p.bound(); err != nil {
		return nil, err
	}
	if owner, err := p.boundVault(); err != nil {
		return nil, err
	} else if owner != "" && owner != p.vaultID {
		return nil, fmt.Errorf("file provider: refusing to rotate %s: it belongs to vault %s", p.path, owner)
	}
	prev := PrevPath(p.path)
	if _, err := os.Lstat(prev); err == nil {
		return nil, fmt.Errorf("file provider: refusing to rotate: %s exists from an earlier rotation that was not "+
			"confirmed. Re-open the vault once (that removes it when the current key works), or check it and remove it", prev)
	}
	old, err := secfile.OpenSecret(p.path, p.opts)
	if err != nil {
		return nil, fmt.Errorf("read the current master key file: %w", err)
	}
	err = secfile.CreateSecret(prev, old)
	Wipe(old)
	if err != nil {
		return nil, fmt.Errorf("keep the previous master key: %w", err)
	}
	raw, err := newMasterSecret()
	if err != nil {
		return nil, err
	}
	text := EncodeKeyFile(raw)
	defer Wipe(text)
	if err := secfile.ReplaceSecret(p.path, text); err != nil {
		Wipe(raw)
		_ = os.Remove(prev) // the old key is still in place
		return nil, fmt.Errorf("write master key file: %w", err)
	}
	return raw, nil
}

// PreviousMasterSecret returns the key kept in <key>.prev.
func (p *FileProvider) PreviousMasterSecret() ([]byte, error) {
	if err := p.bound(); err != nil {
		return nil, err
	}
	return readKeyFile(PrevPath(p.path), p.opts, func() error {
		return fmt.Errorf("no previous master key: %w", fs.ErrNotExist)
	})
}

// ConfirmMasterSecret is called once the current key has unwrapped the
// keychain of vaultID: it removes <key>.prev and records the binding in
// <key>.vault-id (once).
func (p *FileProvider) ConfirmMasterSecret(vaultID string) error {
	if err := p.bound(); err != nil {
		return err
	}
	if err := os.Remove(PrevPath(p.path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		if p.opts.Warn != nil {
			p.opts.Warn("WARNING: could not remove the previous master key " + PrevPath(p.path) + ": " + err.Error())
		}
	}
	owner, err := p.boundVault()
	if err != nil {
		return err
	}
	if owner == "" {
		err := secfile.CreateSecret(VaultIDPath(p.path), []byte(vaultID+"\n"))
		if err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("record the vault of the master key file: %w", err)
		}
		if owner, err = p.boundVault(); err != nil { // another process wrote it first
			return err
		}
	}
	if owner == vaultID {
		return nil
	}
	return fmt.Errorf("%w: master key file %s is bound to vault %s, not %s", ErrMasterSecretUnavailable, p.path, owner, vaultID)
}

// RecoveryHint says how to roll back to the previous key.
func (p *FileProvider) RecoveryHint() string {
	prev := PrevPath(p.Location())
	return fmt.Sprintf("the previous master key is kept in %s; to go back to it, replace the key file with it "+
		"(mv %s %s) and open the vault again", prev, prev, p.Location())
}

// writeNewKey creates path, exclusively, with a fresh key. created is false
// when another process created it first (that file is used).
func writeNewKey(path string) (created bool, err error) {
	raw, err := newMasterSecret()
	if err != nil {
		return false, err
	}
	defer Wipe(raw)
	text := EncodeKeyFile(raw)
	defer Wipe(text)
	if err := secfile.CreateSecret(path, text); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil // lost a race with another init: use that file
		}
		return false, fmt.Errorf("create master key file: %w", err)
	}
	return true, nil
}

// Location is the credential file.
func (p *CredentialProvider) Location() string { return p.path }

// Probe reads the credential once.
func (p *CredentialProvider) Probe() error {
	secret, err := p.GetMasterSecret()
	Wipe(secret)
	return err
}

// GetMasterSecret reads and checks the credential.
func (p *CredentialProvider) GetMasterSecret() ([]byte, error) {
	return readKeyFile(p.path, p.opts, func() error {
		return fmt.Errorf("%w: systemd credential %s is missing: check LoadCredentialEncrypted= in the unit",
			ErrMasterSecretUnavailable, p.path)
	})
}

// readKeyFile reads path with the secfile checks and decodes it.
func readKeyFile(path string, opts secfile.Options, missing func() error) ([]byte, error) {
	b, err := secfile.OpenSecret(path, opts)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, missing()
		}
		return nil, fmt.Errorf("%w: master key file refused: %w", ErrMasterSecretUnavailable, err)
	}
	defer Wipe(b)
	raw, err := DecodeKeyFile(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrMasterSecretUnavailable, path, err)
	}
	return raw, nil
}

// EncodeKeyFile returns the on-disk form of a 32-byte key: urlsafe-base64
// (padded) plus "\n", the same text as the keyring entry.
func EncodeKeyFile(raw []byte) []byte {
	out := make([]byte, base64.URLEncoding.EncodedLen(len(raw))+1)
	base64.URLEncoding.Encode(out, raw)
	out[len(out)-1] = '\n'
	return out
}

// errKeyFormat never includes the file's content.
var errKeyFormat = errors.New("not a master key: expected urlsafe-base64 of 32 bytes (44 characters) or exactly 32 raw bytes")

var errPrintableKey = errors.New("not a master key: 32 printable characters look like a passphrase, not 32 random bytes; " +
	"generate a key with `rgt-vault provider seal file --generate`")

func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// DecodeKeyFile accepts the base64 text form (padded or not, either
// alphabet, surrounding whitespace ignored) or exactly 32 raw bytes.
func DecodeKeyFile(b []byte) ([]byte, error) {
	if len(b) > MaxKeyFileSize {
		return nil, errKeyFormat
	}
	if len(b) == MasterSecretSize {
		if printableASCII(b) {
			// 32 random bytes are all printable with probability ~1e-14:
			// this is a passphrase or a truncated text key, not a key.
			return nil, errPrintableKey
		}
		return append([]byte(nil), b...), nil
	}
	raw, err := decodeKeyringSecret(string(b))
	if err != nil {
		return nil, errKeyFormat
	}
	if len(raw) != MasterSecretSize {
		Wipe(raw)
		return nil, errKeyFormat
	}
	return raw, nil
}
