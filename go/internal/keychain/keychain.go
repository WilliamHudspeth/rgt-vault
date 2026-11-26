// Package keychain manages the vault's data encryption key (DEK) and its
// wrapped form on disk, keychain.json.
//
// It is a byte-compatible port of python/keychain.py HardenedDEKManager and
// run_crypto_selftest. A keychain.json written by either line can be loaded
// by the other; see testdata/ for Python-generated fixtures and
// testdata/verify_with_python.py for the reverse direction.
//
// # Wrap format (must not change; RGT-489)
//
//	salt        = 32 random bytes, fresh on every wrap
//	(kek,nonce) = kdf.Derive(master, salt, "rgt-vault:"+vaultID, params)
//	aad         = vaultID + ":" + decimal(epoch)
//	wrapped_dek = AES-256-GCM(kek).Seal(nonce, dek, aad)   // ct||tag, NO nonce prefix
//
// The nonce is derived from the KDF, not random, and is not stored. This is
// safe only because every wrap uses a fresh salt (and therefore a fresh
// kek); do not reuse a salt. Note that this is deliberately NOT the
// internal/crypto envelope (nonce||ct||tag), which is used for secrets.
//
// # keychain.json (schema version 1)
//
//	{
//	  "version": 1,
//	  "kdf": "argon2id",
//	  "argon2_salt": "<std base64>",
//	  "argon2_memory_cost": 262144,
//	  "argon2_time_cost": 4,
//	  "argon2_parallelism": 4,
//	  "wrapped_dek": "<std base64>",
//	  "created_at": "<Python datetime.isoformat(), UTC>",
//	  "key_epoch": 1
//	}
//
// Written exactly as Python's json.dump(data, f, indent=2) would write it
// (same key order, two-space indent, no trailing newline). Load reads the
// Argon2 parameters from the file; Initialize and Rewrap take them as
// arguments (Python defaults: kdf.DefaultParams()).
//
// # Differences from Python (hardening that cannot affect valid files)
//
//   - Writes are atomic (temp file in the same directory, fsync, rename) and
//     the file is created 0600 rather than chmod-ed after the fact.
//   - Load rejects an unwrapped DEK that is not 32 bytes, Argon2 parameters
//     that Python's cryptography library would also reject (memory_cost <
//     8*parallelism, which golang.org/x/crypto/argon2 would otherwise
//     silently round up), and keychain files over 1 MiB.
//   - Load does not inspect "version" or "kdf", exactly like Python.
//   - Key material held by a Manager is zeroed on Close and when replaced.
//     Go cannot wipe the AES key schedule inside crypto/cipher or the
//     Argon2 intermediate inside internal/kdf; zeroization is best effort.
package keychain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"rgt-vault-server/internal/kdf"
)

const (
	// SchemaVersion is the "version" written to keychain.json.
	SchemaVersion = 1
	// KDFName is the "kdf" written to keychain.json.
	KDFName = "argon2id"
	// SaltSize is the per-wrap Argon2 salt length (keychain.py: os.urandom(32)).
	SaltSize = 32
	// DEKSize is the length of the data encryption key (AES-256).
	DEKSize = 32
	// FileName is the conventional name of the keychain file, stored next
	// to vault.db (vault.py: os.path.join(dirname(db), "keychain.json")).
	FileName = "keychain.json"

	maxFileSize = 1 << 20
	fileMode    = 0o600
	dirMode     = 0o700
)

var (
	// ErrRollback is returned (wrapped, with Python's message) by Load when
	// the keychain epoch does not equal the epoch recorded in the database.
	ErrRollback = errors.New("keychain: Rollback attack detected") // Python wording, kept for log parity
	// ErrUnwrapFailed is returned by Load when AES-GCM authentication of the
	// wrapped DEK fails: wrong master secret, wrong vault id, or a tampered
	// file. It deliberately carries no further detail.
	ErrUnwrapFailed = errors.New("keychain: unable to unwrap DEK")
	// ErrInvalidKeychain is returned when keychain.json is malformed.
	ErrInvalidKeychain = errors.New("keychain: invalid keychain file")
	// ErrDEKNotLoaded is returned by Rewrap and ActiveDEK before Initialize
	// or Load succeeded (Python: "DEK must be loaded to rewrap it.").
	ErrDEKNotLoaded = errors.New("keychain: DEK is not loaded")
	// ErrInvalidParams is returned for Argon2 parameters out of range.
	ErrInvalidParams = errors.New("keychain: invalid Argon2 parameters")
	// ErrSelfTest is returned (wrapped) by SelfTest.
	ErrSelfTest = errors.New("keychain: cryptographic self-test failed")
)

// randReader is the entropy source for DEKs and salts; tests may swap it.
var randReader io.Reader = rand.Reader

// nowFunc is the clock for created_at; tests may swap it.
var nowFunc = time.Now

// fileV1 is keychain.json. Field order is the on-disk key order and must
// match the dict literal in keychain.py.
type fileV1 struct {
	Version           int    `json:"version"`
	KDF               string `json:"kdf"`
	Argon2Salt        string `json:"argon2_salt"`
	Argon2MemoryCost  uint32 `json:"argon2_memory_cost"`
	Argon2TimeCost    uint32 `json:"argon2_time_cost"`
	Argon2Parallelism uint8  `json:"argon2_parallelism"`
	WrappedDEK        string `json:"wrapped_dek"`
	CreatedAt         string `json:"created_at"`
	KeyEpoch          int64  `json:"key_epoch"`
}

// fileIn is the permissive decode shape used by Load. Numbers are kept raw
// so that range and type errors can be reported without panics, and so
// that a missing key_epoch can be told apart from 0.
type fileIn struct {
	Argon2Salt        *string          `json:"argon2_salt"`
	Argon2MemoryCost  *json.Number     `json:"argon2_memory_cost"`
	Argon2TimeCost    *json.Number     `json:"argon2_time_cost"`
	Argon2Parallelism *json.Number     `json:"argon2_parallelism"`
	WrappedDEK        *string          `json:"wrapped_dek"`
	KeyEpoch          *json.RawMessage `json:"key_epoch"`
}

// Manager is the Go counterpart of HardenedDEKManager. It owns one
// keychain.json path and, once Initialize or Load succeeded, the plaintext
// DEK. A Manager is safe for concurrent use: Initialize, Load, Rewrap and
// Close are serialized (including their file I/O and Argon2 work), so the
// file on disk and the DEK in memory always agree. Call Close to wipe the
// DEK.
//
// The master secret is passed as plain bytes so that any master-secret
// provider can feed it; the Manager never retains it.
type Manager struct {
	path string

	mu  sync.Mutex
	dek []byte
}

// New returns a Manager for the keychain file at path. It does not touch
// the filesystem.
func New(path string) *Manager {
	return &Manager{path: path}
}

// Path returns the keychain file path.
func (m *Manager) Path() string { return m.path }

// Initialize generates a fresh random DEK, wraps it under master for
// (vaultID, epoch) with the given Argon2 parameters, writes keychain.json
// (creating the parent directory 0700 if needed) and keeps the DEK loaded.
// An existing file at the path is replaced, as in Python.
//
// It returns a copy of the DEK; the caller owns the copy and should Wipe it.
func (m *Manager) Initialize(master []byte, vaultID string, epoch int64, params kdf.Params) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(randReader, dek); err != nil {
		return nil, fmt.Errorf("keychain: read random: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(m.path), dirMode); err != nil {
		Wipe(dek)
		return nil, fmt.Errorf("keychain: create directory: %w", err)
	}
	if err := writeWrapped(m.path, dek, master, vaultID, epoch, params); err != nil {
		Wipe(dek)
		return nil, err
	}
	out := clone(dek)
	m.setDEKLocked(dek)
	return out, nil
}

// Load reads keychain.json, checks that its key_epoch equals
// expectedEpoch (the epoch stored in the vault database), unwraps the DEK
// under master using the Argon2 parameters recorded in the file, and keeps
// it loaded.
//
// A missing file yields an error satisfying errors.Is(err, fs.ErrNotExist).
// An epoch mismatch yields ErrRollback. A wrong master secret or vault id
// yields ErrUnwrapFailed.
//
// It returns a copy of the DEK; the caller owns the copy and should Wipe it.
func (m *Manager) Load(master []byte, vaultID string, expectedEpoch int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := readFile(m.path)
	if err != nil {
		return nil, err
	}
	var in fileIn
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeychain, err)
	}
	if _, err := dec.Token(); err != io.EOF { // json.load rejects trailing data too
		return nil, fmt.Errorf("%w: trailing data after JSON object", ErrInvalidKeychain)
	}

	// Epoch check first, exactly as Python does, before any KDF work.
	if err := checkEpoch(in.KeyEpoch, expectedEpoch); err != nil {
		return nil, err
	}

	if in.Argon2Salt == nil || in.WrappedDEK == nil {
		return nil, fmt.Errorf("%w: missing argon2_salt or wrapped_dek", ErrInvalidKeychain)
	}
	salt, err := base64.StdEncoding.DecodeString(*in.Argon2Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: argon2_salt is not base64", ErrInvalidKeychain)
	}
	wrapped, err := base64.StdEncoding.DecodeString(*in.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("%w: wrapped_dek is not base64", ErrInvalidKeychain)
	}
	params, err := paramsFromFile(in)
	if err != nil {
		return nil, err
	}

	dek, err := unwrap(wrapped, master, salt, vaultID, expectedEpoch, params)
	if err != nil {
		return nil, err
	}
	out := clone(dek)
	m.setDEKLocked(dek)
	return out, nil
}

// Rewrap wraps the currently loaded DEK under master for (vaultID, epoch)
// with a fresh salt and the given Argon2 parameters, and atomically
// replaces keychain.json. The DEK itself does not change. This is the
// rotate_master_key path.
func (m *Manager) Rewrap(master []byte, vaultID string, epoch int64, params kdf.Params) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.dek) == 0 {
		return ErrDEKNotLoaded
	}
	return writeWrapped(m.path, m.dek, master, vaultID, epoch, params)
}

// ActiveDEK returns a copy of the loaded DEK. The caller should Wipe it.
func (m *Manager) ActiveDEK() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.dek) == 0 {
		return nil, ErrDEKNotLoaded
	}
	return clone(m.dek), nil
}

// Close wipes the loaded DEK. The Manager may be reused by calling Load.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setDEKLocked(nil)
	return nil
}

// setDEKLocked wipes the previous DEK and installs dek. m.mu must be held.
func (m *Manager) setDEKLocked(dek []byte) {
	Wipe(m.dek)
	m.dek = dek
}

// Wipe overwrites b with zeros. It is best effort: the compiler is kept
// from eliding the stores by runtime.KeepAlive, but copies made elsewhere
// (by the GC, by crypto/cipher) are out of reach.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// BindingContext returns the KDF binding context for vaultID.
func BindingContext(vaultID string) []byte { return []byte("rgt-vault:" + vaultID) }

// WrapAAD returns the AES-GCM associated data for (vaultID, epoch).
func WrapAAD(vaultID string, epoch int64) []byte {
	return []byte(vaultID + ":" + strconv.FormatInt(epoch, 10))
}

func validateParams(p kdf.Params) error {
	if p.MemoryCost == 0 || p.TimeCost == 0 || p.Parallelism == 0 {
		return fmt.Errorf("%w: all of memory_cost, time_cost, parallelism must be positive", ErrInvalidParams)
	}
	// cryptography's Argon2id raises for memory_cost < 8*lanes; x/crypto
	// would silently raise memory to 8*lanes and derive a different key.
	if uint64(p.MemoryCost) < 8*uint64(p.Parallelism) {
		return fmt.Errorf("%w: memory_cost must be at least 8*parallelism", ErrInvalidParams)
	}
	return nil
}

func deriveAEAD(master, salt, context []byte, params kdf.Params) (cipher.AEAD, [12]byte, error) {
	if err := validateParams(params); err != nil {
		return nil, [12]byte{}, err
	}
	km, err := kdf.Derive(master, salt, context, params)
	if err != nil {
		return nil, [12]byte{}, fmt.Errorf("keychain: derive wrapping key: %w", err)
	}
	defer Wipe(km.Key[:])
	block, err := aes.NewCipher(km.Key[:])
	if err != nil {
		return nil, [12]byte{}, fmt.Errorf("keychain: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, [12]byte{}, fmt.Errorf("keychain: gcm: %w", err)
	}
	return aead, km.Nonce, nil
}

func wrap(dek, master, salt []byte, vaultID string, epoch int64, params kdf.Params) ([]byte, error) {
	aead, nonce, err := deriveAEAD(master, salt, BindingContext(vaultID), params)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], dek, WrapAAD(vaultID, epoch)), nil
}

func unwrap(wrapped, master, salt []byte, vaultID string, epoch int64, params kdf.Params) ([]byte, error) {
	aead, nonce, err := deriveAEAD(master, salt, BindingContext(vaultID), params)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, nonce[:], wrapped, WrapAAD(vaultID, epoch))
	if err != nil {
		return nil, ErrUnwrapFailed
	}
	if len(dek) != DEKSize {
		Wipe(dek)
		return nil, fmt.Errorf("%w: unwrapped DEK has wrong length", ErrInvalidKeychain)
	}
	return dek, nil
}

func writeWrapped(path string, dek, master []byte, vaultID string, epoch int64, params kdf.Params) error {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return fmt.Errorf("keychain: read random: %w", err)
	}
	wrapped, err := wrap(dek, master, salt, vaultID, epoch, params)
	if err != nil {
		return err
	}
	data, err := marshalFile(fileV1{
		Version:           SchemaVersion,
		KDF:               KDFName,
		Argon2Salt:        base64.StdEncoding.EncodeToString(salt),
		Argon2MemoryCost:  params.MemoryCost,
		Argon2TimeCost:    params.TimeCost,
		Argon2Parallelism: params.Parallelism,
		WrappedDEK:        base64.StdEncoding.EncodeToString(wrapped),
		CreatedAt:         pyISOTime(nowFunc()),
		KeyEpoch:          epoch,
	})
	if err != nil {
		return err
	}
	return atomicWrite(path, data)
}

// marshalFile reproduces json.dump(data, f, indent=2): two-space indent,
// ", "/": " separators collapse to ","+newline and ": ", no trailing
// newline. All values are ASCII (base64, digits, ISO time) so Python's
// ensure_ascii and Go's HTML escaping both leave them alone.
func marshalFile(f fileV1) ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

// pyISOTime renders t like Python's datetime.now(timezone.utc).isoformat():
// microsecond precision, the fraction omitted when it is zero, "+00:00".
func pyISOTime(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}

func checkEpoch(raw *json.RawMessage, expected int64) error {
	shown := "None" // Python renders a missing key or JSON null as None.
	if raw != nil {
		shown = string(*raw)
		if n, err := strconv.ParseInt(shown, 10, 64); err == nil && n == expected {
			return nil
		}
		if len(shown) > 32 { // do not echo an arbitrarily large value
			shown = shown[:32] + "..."
		}
	}
	return fmt.Errorf("%w! DB epoch %d does not match keychain epoch %s", ErrRollback, expected, shown)
}

func paramsFromFile(in fileIn) (kdf.Params, error) {
	mem, err := uint32Field(in.Argon2MemoryCost, "argon2_memory_cost")
	if err != nil {
		return kdf.Params{}, err
	}
	tc, err := uint32Field(in.Argon2TimeCost, "argon2_time_cost")
	if err != nil {
		return kdf.Params{}, err
	}
	par, err := uint8Field(in.Argon2Parallelism, "argon2_parallelism")
	if err != nil {
		return kdf.Params{}, err
	}
	p := kdf.Params{MemoryCost: mem, TimeCost: tc, Parallelism: par}
	if err := validateParams(p); err != nil {
		return kdf.Params{}, err
	}
	return p, nil
}

// uint32Field and uint8Field parse a non-negative JSON integer with the
// target bit size, so strconv rejects (ErrRange) anything that would not
// fit and the conversion below cannot truncate. The bit size is a literal
// at each ParseUint call so static analysis can see the bound.
func uint32Field(n *json.Number, name string) (uint32, error) {
	if n == nil {
		return 0, fmt.Errorf("%w: missing %s", ErrInvalidKeychain, name)
	}
	v, err := strconv.ParseUint(n.String(), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %s out of range", ErrInvalidParams, name)
	}
	return uint32(v), nil
}

func uint8Field(n *json.Number, name string) (uint8, error) {
	if n == nil {
		return 0, fmt.Errorf("%w: missing %s", ErrInvalidKeychain, name)
	}
	v, err := strconv.ParseUint(n.String(), 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%w: %s out of range", ErrInvalidParams, name)
	}
	return uint8(v), nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keychain: open: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("keychain: read: %w", err)
	}
	if len(raw) > maxFileSize {
		return nil, fmt.Errorf("%w: file too large", ErrInvalidKeychain)
	}
	return raw, nil
}

// atomicWrite writes data to a 0600 temp file in path's directory, fsyncs
// it, and renames it over path, so a crash leaves either the old or the new
// keychain, never a torn one.
func atomicWrite(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("keychain: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if runtime.GOOS != "windows" { // CreateTemp is already 0600; be explicit.
		if err = tmp.Chmod(fileMode); err != nil {
			return fmt.Errorf("keychain: chmod temp file: %w", err)
		}
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("keychain: write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("keychain: sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("keychain: close temp file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keychain: replace keychain file: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir fsyncs a directory so the rename is durable. Best effort: not
// supported on Windows, and failure does not undo the rename.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
