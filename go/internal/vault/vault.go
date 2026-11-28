package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/crypto"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/keychain"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/policy"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/store"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/validation"
)

// RGT-219: rotate the DEK well before the AES-GCM safety bounds (NIST SP
// 800-38D: rekey before 2^32 encryptions with random 96-bit nonces, and
// before 2^39-256 bytes under one key). Same values as python/vault.py.
const (
	DEKMaxEncryptions int64 = 100_000_000
	DEKMaxBytes       int64 = 512 * 1024 * 1024 * 1024 // 512 GiB
)

// Defaults and limits from python/vault.py.
const (
	DefaultRateLimit  = 100
	DefaultRateWindow = time.Hour
	// AuthFailureLimit / AuthFailureWindow cap failed credential
	// verifications per agent (RGT-277); used by the capability path.
	AuthFailureLimit  = 100
	AuthFailureWindow = time.Hour

	// DefaultNamespace and SystemAgent are Python's argument defaults. The
	// Go API never substitutes them implicitly; callers pass them.
	DefaultNamespace = "default"
	SystemAgent      = "system"

	MaxValueBytes   = 1024 * 1024
	MaxNoteChars    = 512
	MaxPurposeChars = 256
	MaxImportBytes  = 10 * 1024 * 1024
	DefaultListSize = 100
)

// Config configures Open. Only Provider is required.
type Config struct {
	// DBPath is the vault database; keychain.json lives next to it.
	// Empty means ~/.secure-vault/vault.db.
	DBPath string
	// Provider supplies the master secret.
	Provider MasterProvider
	// PolicyYAML is the ABAC policy text. Empty means default deny for
	// everything (as in Python); its hash is recorded in audit rows.
	PolicyYAML string
	// RateLimit / RateWindow configure the per-agent lease limiter.
	// Zero means DefaultRateLimit / DefaultRateWindow.
	RateLimit  int
	RateWindow time.Duration
	// Hook is consulted before every sensitive operation. Nil means OffHook.
	Hook Hook
	// Approval is consulted before a secret is unsealed. Nil means
	// approval.AutoAllowGate.
	Approval approval.Gate
	// TokenVerifier verifies v2 capability tokens for ExecuteCapability.
	// Nil means capability execution fails closed (Python: token_verifier).
	TokenVerifier captoken.TokenVerifier
	// Capabilities is the capability registry for ExecuteCapability (see
	// internal/capabilities). Nil means no capability is registered.
	Capabilities CapabilityRegistry
	// HoneyCapabilities are decoy capability names (internal/honeycap).
	// Any ExecuteCapability call naming one is audited as
	// HONEY_CAPABILITY_TRIGGERED and alerted, and still answered like any
	// other unregistered capability. Nil disables the traps. Open fails if
	// a honey name is a registered capability.
	HoneyCapabilities HoneyDetector
	// KDFParams are the Argon2 parameters used when a keychain is created or
	// re-wrapped. Zero means kdf.DefaultParams() (what Python always writes).
	// Loading always uses the parameters stored in keychain.json.
	KDFParams kdf.Params
}

// Vault is an open vault (Python: VaultManager). It is safe for concurrent
// use.
type Vault struct {
	store              *store.Store
	engine             *policy.Engine
	policyHash         string
	rateLimiter        *RateLimiter
	authFailureLimiter *RateLimiter
	hook               Hook
	approval           approval.Gate
	tokenVerifier      captoken.TokenVerifier
	capabilities       CapabilityRegistry
	honey              HoneyDetector
	honeyLimit         *honeyLimiter
	provider           MasterProvider
	kdfParams          kdf.Params
	vaultID            string
	keychainPath       string

	// aux is the vault's own connection to vault.db, for the rotation
	// transaction and the few reads the store has no method for.
	aux *sql.DB

	// rotMu serialises rotations (held across their hook consultation).
	rotMu sync.Mutex
	// mu guards the key material and lifecycle state below. Store and
	// crypto work holds it shared; the key swap of a rotation, import and
	// Close hold it exclusively, so no row is written under a DEK that is
	// being replaced and no store write waits on SQLite's busy timeout
	// behind a rotation. Hooks and the approval gate are consulted WITHOUT
	// it, so a slow approval never stalls the vault and a hook may call back
	// into the vault.
	mu       sync.RWMutex
	km       *keychain.Manager
	dek      []byte
	keyEpoch int64
	closed   bool
	broken   error

	// Auto-rotation thresholds (DEKMax*); tests lower them.
	dekMaxEncryptions int64
	dekMaxBytes       int64

	// Test seams for the rotation atomicity tests. nil in production.
	testRewriteRow      func(n int) error // called before each row is rewritten
	testBeforeSwap      func() error      // called after commit, before the rename
	testAfterCommit     func()
	testMasterPreCommit func() error // RotateMaster: after the re-wrap, before the commit
}

// Open runs the cryptographic self-test, opens (creating if needed) the
// database, and loads the DEK, creating a new keychain only when
// keychain.json does not exist (Python P0-2).
func Open(ctx context.Context, cfg Config) (*Vault, error) {
	// 1. Cryptographic self-test, fail closed.
	if err := keychain.SelfTest(); err != nil {
		return nil, err
	}
	if cfg.Provider == nil {
		return nil, errors.New("vault: no master-secret provider configured")
	}

	engine, err := policy.Parse(cfg.PolicyYAML)
	if err != nil {
		return nil, err
	}
	if err := checkHoneyRegistry(cfg.HoneyCapabilities, cfg.Capabilities); err != nil {
		return nil, err
	}

	dbPath := cfg.DBPath
	if dbPath == "" {
		if dbPath, err = store.DefaultDBPath(); err != nil {
			return nil, err
		}
	}
	if cfg.RateLimit < 0 || cfg.RateWindow < 0 {
		return nil, errors.New("vault: RateLimit and RateWindow must not be negative")
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	aux, err := openAux(st.Path())
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	v := &Vault{
		store:              st,
		aux:                aux,
		engine:             engine,
		policyHash:         policy.HashPolicy(cfg.PolicyYAML),
		authFailureLimiter: NewRateLimiter(AuthFailureLimit, AuthFailureWindow),
		hook:               cfg.Hook,
		approval:           cfg.Approval,
		tokenVerifier:      cfg.TokenVerifier,
		capabilities:       cfg.Capabilities,
		honey:              cfg.HoneyCapabilities,
		honeyLimit:         newHoneyLimiter(),
		provider:           cfg.Provider,
		kdfParams:          cfg.KDFParams,
		keychainPath:       filepath.Join(filepath.Dir(dbPath), keychain.FileName),
		dekMaxEncryptions:  DEKMaxEncryptions,
		dekMaxBytes:        DEKMaxBytes,
	}
	limit, window := cfg.RateLimit, cfg.RateWindow
	if limit == 0 {
		limit = DefaultRateLimit
	}
	if window == 0 {
		window = DefaultRateWindow
	}
	v.rateLimiter = NewRateLimiter(limit, window)
	if v.hook == nil {
		v.hook = OffHook{}
	}
	if v.approval == nil {
		v.approval = approval.AutoAllowGate{}
	}
	if v.kdfParams == (kdf.Params{}) {
		v.kdfParams = kdf.DefaultParams()
	}

	if err := v.load(ctx); err != nil {
		_ = aux.Close()
		_ = st.Close()
		return nil, err
	}
	return v, nil
}

func (v *Vault) load(ctx context.Context) error {
	var err error
	if v.vaultID, err = v.store.VaultID(ctx); err != nil {
		return err
	}
	if v.keyEpoch, err = v.store.KeyEpoch(ctx); err != nil {
		return err
	}

	// Decision D3: refuse legacy Fernet rows before touching the keychain.
	legacy, err := v.store.HasLegacySecrets(ctx)
	if err != nil {
		return err
	}
	if legacy {
		return newErr([]error{ErrLegacyVault}, nil,
			"vault %s contains legacy Fernet-encrypted secrets (dek_version=0), which the Go line does not "+
				"migrate: open it once with the last Python release of rgt-vault (it upgrades them to AES-256-GCM "+
				"automatically), then open it with Go again", v.store.Path())
	}

	_, statErr := os.Stat(v.keychainPath)
	fresh := false
	switch {
	case statErr == nil:
	case errors.Is(statErr, fs.ErrNotExist):
		if _, err := os.Stat(v.keychainPath + ".new"); err == nil {
			break // a rotation died mid-rename: recover below
		}
		var n int64
		if err := v.aux.QueryRowContext(ctx, "SELECT COUNT(*) FROM secrets").Scan(&n); err != nil {
			return fmt.Errorf("vault: count secrets: %w", err)
		}
		if n > 0 {
			return newErr([]error{ErrKeychainMissing}, nil,
				"%s is missing but the vault holds %d secret versions; restore keychain.json from a backup "+
					"(creating a new key would make them permanently unreadable)", v.keychainPath, n)
		}
		fresh = true
	default:
		return fmt.Errorf("vault: stat keychain: %w", statErr)
	}

	if b, ok := v.provider.(VaultBinder); ok {
		if err := b.BindVault(v.vaultID); err != nil {
			return err
		}
	}
	if fresh {
		if b, ok := v.provider.(Bootstrapper); ok {
			if err := b.BootstrapMasterSecret(); err != nil {
				return err
			}
		}
	}
	master, err := v.provider.GetMasterSecret()
	if err != nil {
		return err
	}
	defer keychain.Wipe(master)

	km := keychain.New(v.keychainPath)
	var dek []byte
	if fresh {
		dek, err = km.Initialize(master, v.vaultID, v.keyEpoch, v.kdfParams)
	} else {
		dek, err = km.Load(master, v.vaultID, v.keyEpoch)
		if err != nil && (errors.Is(err, keychain.ErrRollback) || errors.Is(err, keychain.ErrUnwrapFailed) ||
			errors.Is(err, fs.ErrNotExist)) {
			km, dek, err = v.recoverRotation(ctx, master, err)
		}
	}
	if err != nil {
		if errors.Is(err, keychain.ErrUnwrapFailed) {
			return v.explainUnwrap(err)
		}
		return err
	}
	if r, ok := v.provider.(MasterRecovery); ok {
		if err := r.ConfirmMasterSecret(v.vaultID); err != nil {
			_ = km.Close()
			keychain.Wipe(dek)
			return err
		}
	}
	v.km, v.dek = km, dek
	return nil
}

// explainUnwrap turns "unable to unwrap DEK" into a message that names the
// key source and the vault, and says whether the previous master secret
// kept by an interrupted rotation (MasterRecovery) would open it. It never
// switches keys on its own.
func (v *Vault) explainUnwrap(orig error) error {
	src := "the master secret"
	if l, ok := v.provider.(keyLocator); ok {
		src += " from " + l.Location()
	}
	if r, ok := v.provider.(MasterRecovery); ok {
		if prev, err := r.PreviousMasterSecret(); err == nil {
			km := keychain.New(v.keychainPath)
			dek, lerr := km.Load(prev, v.vaultID, v.keyEpoch)
			keychain.Wipe(dek)
			keychain.Wipe(prev)
			_ = km.Close()
			if lerr == nil {
				return fmt.Errorf("vault %s: %s does not unwrap keychain.json, but the PREVIOUS master secret, kept by an "+
					"interrupted master-key rotation, does. Nothing was changed; %s: %w", v.vaultID, src, r.RecoveryHint(), orig)
			}
		}
	}
	return fmt.Errorf("vault %s: %s does not match this vault (keychain.json cannot be unwrapped with it; is it the "+
		"right key for this vault?): %w", v.vaultID, src, orig)
}

// recoverRotation completes a rotation that was interrupted around the
// replacement of keychain.json by keychain.json.new:
//
//   - RotateDEK or RotateMaster committed the epoch bump but died before the
//     rename: the database epoch equals the .new file's -> rename it.
//   - RotateMaster died after the provider switched to the new master but
//     before the epoch commit: keychain.json no longer unwraps and .new is
//     at the next epoch under the current master -> commit the epoch, rename.
//
// Anything else returns the original error. A .new file is trusted only if
// it unwraps under the provider's current master for this vault id, which
// only the holder of that master can produce.
func (v *Vault) recoverRotation(ctx context.Context, master []byte, orig error) (*keychain.Manager, []byte, error) {
	newPath := v.keychainPath + ".new"
	if _, err := os.Stat(newPath); err != nil {
		return nil, nil, orig
	}
	pending := keychain.New(newPath)
	defer func() { _ = pending.Close() }()
	epoch := v.keyEpoch
	bump := false
	dek, err := pending.Load(master, v.vaultID, epoch)
	if err != nil && errors.Is(orig, keychain.ErrUnwrapFailed) {
		dek, err = pending.Load(master, v.vaultID, epoch+1)
		bump = true
	}
	if err != nil {
		return nil, nil, orig
	}
	// The .new key must actually decrypt the stored rows: a stale .new from
	// a RotateDEK that never committed holds a DEK that encrypts nothing.
	ok, verr := v.dekDecryptsRows(ctx, dek)
	keychain.Wipe(dek)
	if verr != nil {
		return nil, nil, verr
	}
	if !ok {
		return nil, nil, orig
	}
	if bump {
		if err := v.casEpoch(ctx, epoch, epoch+1); err != nil {
			return nil, nil, err
		}
		epoch++
	}
	v.keyEpoch = epoch
	km, dek, err := v.installPending(master, epoch)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: complete interrupted rotation: %w", err)
	}
	return km, dek, nil
}

// dekDecryptsRows reports whether dek decrypts the newest ACTIVE row, or,
// with no ACTIVE row, any of the newest 50 rows. An empty vault matches.
func (v *Vault) dekDecryptsRows(ctx context.Context, dek []byte) (bool, error) {
	rows, err := v.aux.QueryContext(ctx,
		"SELECT namespace, name, ciphertext, status FROM secrets WHERE dek_version = 1 "+
			"ORDER BY (status = 'ACTIVE') DESC, id DESC LIMIT 50")
	if err != nil {
		return false, fmt.Errorf("vault: read secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	seen := false
	for rows.Next() {
		var ns, name, status string
		var ct []byte
		if err := rows.Scan(&ns, &name, &ct, &status); err != nil {
			return false, fmt.Errorf("vault: read secrets: %w", err)
		}
		seen = true
		pt, err := crypto.Decrypt(ct, dek, v.aad(ns, name))
		keychain.Wipe(pt)
		if err == nil {
			return true, nil
		}
		if status == store.StatusActive {
			return false, nil // the current DEK always decrypts ACTIVE rows
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("vault: read secrets: %w", err)
	}
	return !seen, nil
}

// casEpoch moves key_epoch from old to new in one durable transaction; an
// epoch already at new (another process recovered first) is accepted.
func (v *Vault) casEpoch(ctx context.Context, old, new int64) error {
	tx, err := v.aux.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("vault: recover epoch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	cur, err := readEpoch(ctx, tx)
	if err != nil {
		return err
	}
	switch cur {
	case new:
		return nil
	case old:
		if _, err := tx.ExecContext(ctx, "UPDATE metadata SET value = ? WHERE key = 'key_epoch'",
			strconv.FormatInt(new, 10)); err != nil {
			return fmt.Errorf("vault: recover epoch: %w", err)
		}
		return tx.Commit()
	default:
		return fmt.Errorf("vault: key_epoch is %d during recovery (expected %d)", cur, old)
	}
}

// Close wipes the key material and closes the database.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	keychain.Wipe(v.dek)
	v.dek = nil
	if v.km != nil {
		_ = v.km.Close()
	}
	_ = v.aux.Close()
	return v.store.Close()
}

// usable reports ErrClosed / ErrInconsistent; the caller holds mu.
func (v *Vault) usable() error {
	if v.closed {
		return ErrClosed
	}
	if v.broken != nil {
		return newErr([]error{ErrInconsistent}, v.broken, "%s: %v", ErrInconsistent.Error(), v.broken)
	}
	return nil
}

// rlock takes the shared lock and checks the vault is usable.
func (v *Vault) rlock() error {
	v.mu.RLock()
	if err := v.usable(); err != nil {
		v.mu.RUnlock()
		return err
	}
	return nil
}

// withR runs fn holding the shared lock on a usable vault.
func (v *Vault) withR(fn func() error) error {
	if err := v.rlock(); err != nil {
		return err
	}
	defer v.mu.RUnlock()
	return fn()
}

// VaultID returns the vault's UUID.
func (v *Vault) VaultID() string { return v.vaultID }

// KeyEpoch returns the current master-key epoch.
func (v *Vault) KeyEpoch() int64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keyEpoch
}

// PolicyHash returns the policy hash recorded in audit rows ("" for an
// empty policy).
func (v *Vault) PolicyHash() string { return v.policyHash }

// Policy returns the ABAC engine.
func (v *Vault) Policy() *policy.Engine { return v.engine }

// HookID returns the configured hook's id.
func (v *Vault) HookID() string { return v.hook.ID() }

// RateLimiter returns the per-agent lease limiter.
func (v *Vault) RateLimiter() *RateLimiter { return v.rateLimiter }

// AuthFailureLimiter returns the failed-credential limiter (RGT-277).
func (v *Vault) AuthFailureLimiter() *RateLimiter { return v.authFailureLimiter }

// Store returns the underlying store, for read-only status queries (CLI
// status). Writing through it bypasses policy, hooks and audit semantics.
func (v *Vault) Store() *store.Store { return v.store }

// KeychainPath returns the keychain.json path.
func (v *Vault) KeychainPath() string { return v.keychainPath }

func (v *Vault) aad(namespace, name string) []byte {
	return []byte(v.vaultID + ":" + namespace + ":" + name)
}

// logAudit appends one audit row (VaultManager._log_audit). Audit rows are
// written even if ctx was cancelled mid-operation.
func (v *Vault) logAudit(ctx context.Context, action string, secretName sql.NullString, details string) error {
	return v.store.LogAudit(context.WithoutCancel(ctx), store.AuditEvent{
		Action:     action,
		SecretName: secretName,
		Details:    details,
		PolicyHash: v.policyHash,
	})
}

// Audit appends an audit row on behalf of a caller (VaultManager.audit).
func (v *Vault) Audit(ctx context.Context, event string, secretName sql.NullString, details string, agentID sql.NullString) error {
	if err := v.rlock(); err != nil {
		return err
	}
	defer v.mu.RUnlock()
	return v.store.LogAudit(context.WithoutCancel(ctx), store.AuditEvent{
		Action:     event,
		SecretName: secretName,
		Details:    details,
		PolicyHash: v.policyHash,
		AgentID:    agentID,
	})
}

func isPySpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680,
		0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// Parameter kinds for validateParam.
const (
	paramName      = "name"
	paramNamespace = "namespace"
	paramAgent     = "agent"
	paramNote      = "note"
	paramPurpose   = "purpose"
)

// validateParam is VaultManager._validate_string_param: blank check, length
// in characters, then the input_validation allowlist for the parameter.
func validateParam(param, value string, maxLen int, allowEmpty bool) error {
	if !utf8.ValidString(value) {
		return validationErr("'%s' must be valid UTF-8.", param)
	}
	if !allowEmpty && strings.TrimFunc(value, isPySpace) == "" {
		return validationErr("'%s' cannot be empty or just whitespace.", param)
	}
	if utf8.RuneCountInString(value) > maxLen {
		return validationErr("'%s' exceeds the maximum allowed length of %d characters.", param, maxLen)
	}
	var err error
	switch param {
	case paramName:
		_, err = validation.ValidateName(value)
	case paramNamespace:
		_, err = validation.ValidateNamespace(value)
	case paramAgent:
		_, err = validation.ValidateAgent(value)
	case paramNote, paramPurpose:
		// Python validates but stores/evaluates the ORIGINAL text.
		_, err = validation.ValidateFreeText(value, maxLen)
	}
	return err
}

type param struct {
	kind, value string
	max         int
	allowEmpty  bool
	optional    bool // validate only when non-empty
}

func validateParams(ps ...param) error {
	for _, p := range ps {
		if p.optional && p.value == "" {
			continue
		}
		if err := validateParam(p.kind, p.value, p.max, p.allowEmpty); err != nil {
			return err
		}
	}
	return nil
}

func pName(v string) param { return param{kind: paramName, value: v, max: validation.MaxNameLen} }
func pNamespace(v string) param {
	return param{kind: paramNamespace, value: v, max: validation.MaxNamespaceLen}
}
func pAgent(v string) param { return param{kind: paramAgent, value: v, max: validation.MaxAgentLen} }
func pPurpose(v string, optional bool) param {
	return param{kind: paramPurpose, value: v, max: MaxPurposeChars, optional: optional}
}
