package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"rgt-vault-server/internal/validation"
)

// Scope is a permission carried by a token in the per-agent token store.
type Scope string

// Token scopes (batch H1, design B1).
const (
	// ScopeAgent: act as the token's own agent on the secrets routes
	// (set, list, use, revoke, fingerprint, simulate, capabilities), always
	// under the ABAC policy.
	ScopeAgent Scope = "agent"
	// ScopeOperator: approve/deny (/v1/requests*), rotate keys, and read
	// the audit log. Operator implies audit.
	ScopeOperator Scope = "operator"
	// ScopeAudit: read and verify the audit log only.
	ScopeAudit Scope = "audit"
	// ScopeLease: receive a secret's plaintext over HTTP
	// (POST /v1/secrets/{ns}/{name}/lease), still as the token's own agent
	// and under ABAC "read". Opt-in, so a plain agent token can use secrets
	// server-side (actions, capabilities) without ever seeing them.
	ScopeLease Scope = "lease"
)

// AllScopes lists every known scope in display order.
var AllScopes = []Scope{ScopeAgent, ScopeOperator, ScopeAudit, ScopeLease}

// ParseScopes parses a comma-separated scope list ("agent,lease"). Blank
// entries are ignored, duplicates collapsed; an unknown scope is an error.
// The result is sorted in AllScopes order and never empty.
func ParseScopes(csv string) ([]Scope, error) {
	seen := map[Scope]bool{}
	for _, part := range strings.Split(csv, ",") {
		p := Scope(strings.ToLower(strings.TrimSpace(part)))
		if p == "" {
			continue
		}
		if !knownScope(p) {
			return nil, fmt.Errorf("unknown scope %q (valid: agent, operator, audit, lease)", string(p))
		}
		seen[p] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	out := make([]Scope, 0, len(seen))
	for _, s := range AllScopes {
		if seen[s] {
			out = append(out, s)
		}
	}
	return out, nil
}

func knownScope(s Scope) bool {
	for _, k := range AllScopes {
		if s == k {
			return true
		}
	}
	return false
}

// Store errors. None of their texts contains a token.
var (
	ErrExpiredToken   = errors.New("expired bearer token")
	ErrUnknownTokenID = errors.New("no token with that id")
	ErrDuplicateToken = errors.New("that token is already in the store")
	ErrStoreLocked    = errors.New("token store is locked by another process")
	ErrStoreCorrupt   = errors.New("token store file is invalid")
)

// Principal is the authenticated caller of one request.
type Principal struct {
	// TokenID is safe to log: the store record id, or for a legacy shared
	// token the sha256 prefix (TokenID).
	TokenID string
	// Agent is the ABAC subject. Empty for a legacy shared token, whose
	// agent is still the self-asserted request field.
	Agent string
	// Scopes the token carries.
	Scopes []Scope
	// Legacy marks a request authenticated with the deprecated shared
	// token file (--legacy-shared-token).
	Legacy bool
}

// Has reports whether p carries scope s. Operator implies audit.
func (p Principal) Has(s Scope) bool {
	for _, have := range p.Scopes {
		if have == s || (s == ScopeAudit && have == ScopeOperator) {
			return true
		}
	}
	return false
}

// TokenInfo is the public view of a stored token: never its hash and never
// the token itself.
type TokenInfo struct {
	ID        string     `json:"id"`
	Agent     string     `json:"agent_id"`
	Scopes    []Scope    `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Expired reports whether the token is past its expiry at now.
func (t TokenInfo) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

// record is one on-disk entry.
type record struct {
	ID        string     `json:"id"`
	Hash      string     `json:"sha256"`
	Agent     string     `json:"agent_id"`
	Scopes    []Scope    `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (r record) info() TokenInfo {
	return TokenInfo{ID: r.ID, Agent: r.Agent, Scopes: append([]Scope(nil), r.Scopes...), CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
}

// fileFormat is the token store file (JSON, mode 0600).
type fileFormat struct {
	Version int      `json:"version"`
	Tokens  []record `json:"tokens"`
}

const storeVersion = 1

// MaxStoreBytes caps the token store file (a sanity bound, ~10k tokens).
const MaxStoreBytes = 4 << 20

// lockTimeout bounds waiting for another writer; staleLock is the age after
// which a leftover lock file (a crashed writer) is broken.
var (
	lockTimeout = 10 * time.Second
	staleLock   = 60 * time.Second
)

// Store is the file-backed per-agent token store: sha256(token) ->
// {id, agent_id, scopes, created_at, expires_at}. Only hashes are stored;
// the plaintext token exists only in the return value of Mint/Rotate.
//
// A Store is safe for concurrent use. Reads re-load the file when it
// changed on disk (size or mtime), so `rgt-vault token revoke` takes effect
// on a running server at its next request. Writes take an exclusive lock
// file next to the store and replace the file atomically (temp + rename).
type Store struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	byHash  map[[sha256.Size]byte]record
	loaded  bool
	fileFI  os.FileInfo // the file last loaded (nil: absent)
	loadErr error
}

// OpenStore returns the store at path. The file need not exist yet: an
// absent file is an empty store (every token is rejected).
func OpenStore(path string) *Store {
	return &Store{path: path, now: time.Now}
}

// Path returns the store file path.
func (s *Store) Path() string { return s.path }

// SetClock replaces the store's clock (tests).
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// Exists reports whether the store file exists.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

func hashToken(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }

func newRecordID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token id: %w", err)
	}
	return "tok_" + hex.EncodeToString(b), nil
}

// readFile parses the store file. A missing file is an empty store.
func readFile(path string) (fileFormat, os.FileInfo, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileFormat{Version: storeVersion}, nil, nil
	}
	if err != nil {
		return fileFormat{}, nil, fmt.Errorf("opening token store: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fileFormat{}, nil, fmt.Errorf("reading token store: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxStoreBytes+1))
	if err != nil {
		return fileFormat{}, nil, fmt.Errorf("reading token store: %w", err)
	}
	if len(data) > MaxStoreBytes {
		return fileFormat{}, nil, fmt.Errorf("%w: larger than %d bytes", ErrStoreCorrupt, MaxStoreBytes)
	}
	var ff fileFormat
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ff); err != nil {
		// json errors may quote file content; the file holds only hashes,
		// but keep the message generic anyway.
		return fileFormat{}, nil, fmt.Errorf("%w: not valid JSON", ErrStoreCorrupt)
	}
	if ff.Version != storeVersion {
		return fileFormat{}, nil, fmt.Errorf("%w: unsupported version %d", ErrStoreCorrupt, ff.Version)
	}
	if err := validateRecords(ff.Tokens); err != nil {
		return fileFormat{}, nil, err
	}
	return ff, fi, nil
}

func validateRecords(recs []record) error {
	ids := map[string]bool{}
	hashes := map[string]bool{}
	for i, r := range recs {
		bad := func(what string) error { return fmt.Errorf("%w: entry %d: %s", ErrStoreCorrupt, i, what) }
		if !strings.HasPrefix(r.ID, "tok_") || len(r.ID) != 20 {
			return bad("bad id")
		}
		if h, err := hex.DecodeString(r.Hash); err != nil || len(h) != sha256.Size || r.Hash != strings.ToLower(r.Hash) {
			return bad("bad sha256")
		}
		if _, err := validation.ValidateAgent(r.Agent); err != nil {
			return bad("bad agent_id")
		}
		if len(r.Scopes) == 0 {
			return bad("no scopes")
		}
		for _, sc := range r.Scopes {
			if !knownScope(sc) {
				return bad("unknown scope")
			}
		}
		if ids[r.ID] || hashes[r.Hash] {
			return bad("duplicate id or hash")
		}
		ids[r.ID], hashes[r.Hash] = true, true
	}
	return nil
}

// refresh re-loads the file if it changed since the last load. Caller holds mu.
func (s *Store) refresh() error {
	fi, statErr := os.Stat(s.path)
	switch {
	case statErr == nil:
		// Every write replaces the file by rename, so a different file
		// identity (inode / file index) means new contents even when size
		// and a coarse mtime are unchanged.
		if s.loaded && s.loadErr == nil && s.fileFI != nil && os.SameFile(fi, s.fileFI) &&
			fi.ModTime().Equal(s.fileFI.ModTime()) && fi.Size() == s.fileFI.Size() {
			return nil
		}
	case errors.Is(statErr, fs.ErrNotExist):
		// Absent: an empty store (fail closed: no token is valid).
		s.byHash, s.loaded, s.loadErr, s.fileFI = map[[sha256.Size]byte]record{}, false, nil, nil
		return nil
	default:
		s.loadErr = fmt.Errorf("token store unavailable: %w", statErr)
		return s.loadErr
	}
	var ff fileFormat
	var rfi os.FileInfo
	err := retryTransient(func() error {
		var rerr error
		ff, rfi, rerr = readFile(s.path)
		return rerr
	})
	if err != nil {
		s.loadErr = err
		return err
	}
	m := make(map[[sha256.Size]byte]record, len(ff.Tokens))
	for _, r := range ff.Tokens {
		var k [sha256.Size]byte
		h, _ := hex.DecodeString(r.Hash) // validated
		copy(k[:], h)
		m[k] = r
	}
	s.byHash, s.loadErr, s.fileFI = m, nil, rfi
	s.loaded = rfi != nil
	return nil
}

// presentedToken extracts the token from an Authorization header value
// ("Bearer <token>" or the raw token).
func presentedToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingAuth
	}
	presented := strings.TrimSpace(authHeader)
	if strings.HasPrefix(strings.ToLower(presented), "bearer ") {
		presented = strings.TrimSpace(presented[7:])
	}
	if presented == "" || strings.EqualFold(presented, "bearer") {
		return "", ErrEmptyToken
	}
	return presented, nil
}

// PresentedID returns the short, log-safe id (sha256 prefix) of the token in
// an Authorization header, or "" when there is none. It is what an audit row
// for a FAILED authentication records: never the token.
func PresentedID(authHeader string) string {
	t, err := presentedToken(authHeader)
	if err != nil {
		return ""
	}
	return TokenID(t)
}

// Authenticate checks an Authorization header against the store.
//
// The lookup hashes the presented token first and indexes by the digest, so
// its timing depends only on the (unpredictable) hash, never on how much of
// a stored token the caller guessed; the digest is then compared again in
// constant time. Missing, unknown, revoked and expired tokens are distinct
// errors for the audit log, but callers answer all of them with the same
// generic 401.
func (s *Store) Authenticate(authHeader string) (Principal, error) {
	presented, err := presentedToken(authHeader)
	if err != nil {
		return Principal{}, err
	}
	digest := hashToken(presented)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return Principal{}, err
	}
	rec, ok := s.byHash[digest]
	var stored [sha256.Size]byte
	if ok {
		h, _ := hex.DecodeString(rec.Hash)
		copy(stored[:], h)
	}
	if subtle.ConstantTimeCompare(stored[:], digest[:]) != 1 || !ok {
		return Principal{}, ErrInvalidToken
	}
	if rec.info().Expired(s.now()) {
		return Principal{TokenID: rec.ID, Agent: rec.Agent}, ErrExpiredToken
	}
	return Principal{TokenID: rec.ID, Agent: rec.Agent, Scopes: append([]Scope(nil), rec.Scopes...)}, nil
}

// List returns every stored token's public metadata, oldest first. It never
// returns hashes or tokens.
func (s *Store) List() ([]TokenInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, err
	}
	out := make([]TokenInfo, 0, len(s.byHash))
	for _, r := range s.byHash {
		out = append(out, r.info())
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// MintOptions describe a new token.
type MintOptions struct {
	Agent  string
	Scopes []Scope
	// TTL > 0 sets expires_at = now + TTL; 0 means no expiry.
	TTL time.Duration
}

func (s *Store) newRecord(token string, o MintOptions) (record, error) {
	agent, err := validation.ValidateAgent(o.Agent)
	if err != nil {
		return record{}, fmt.Errorf("invalid agent id: %w", err)
	}
	if len(o.Scopes) == 0 {
		return record{}, errors.New("at least one scope is required")
	}
	for _, sc := range o.Scopes {
		if !knownScope(sc) {
			return record{}, fmt.Errorf("unknown scope %q", string(sc))
		}
	}
	if o.TTL < 0 {
		return record{}, errors.New("expiry must be positive")
	}
	id, err := newRecordID()
	if err != nil {
		return record{}, err
	}
	s.mu.Lock()
	now := s.now().UTC().Truncate(time.Second)
	s.mu.Unlock()
	d := hashToken(token)
	r := record{ID: id, Hash: hex.EncodeToString(d[:]), Agent: agent, Scopes: append([]Scope(nil), o.Scopes...), CreatedAt: now}
	if o.TTL > 0 {
		exp := now.Add(o.TTL)
		r.ExpiresAt = &exp
	}
	return r, nil
}

// Mint creates a token. The plaintext is returned exactly once and is not
// stored anywhere.
func (s *Store) Mint(o MintOptions) (string, TokenInfo, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", TokenInfo{}, err
	}
	info, err := s.add(token, o)
	if err != nil {
		return "", TokenInfo{}, err
	}
	return token, info, nil
}

// Import adds an existing token (for example a legacy token file) under the
// given agent and scopes, storing only its hash.
func (s *Store) Import(token string, o MintOptions) (TokenInfo, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return TokenInfo{}, ErrEmptyToken
	}
	return s.add(token, o)
}

// Contains reports whether token is in the store (expired or not).
func (s *Store) Contains(token string) (TokenInfo, bool, error) {
	d := hashToken(strings.TrimSpace(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return TokenInfo{}, false, err
	}
	r, ok := s.byHash[d]
	return r.info(), ok, nil
}

func (s *Store) add(token string, o MintOptions) (TokenInfo, error) {
	r, err := s.newRecord(token, o)
	if err != nil {
		return TokenInfo{}, err
	}
	err = s.update(func(ff *fileFormat) error {
		for _, have := range ff.Tokens {
			if have.Hash == r.Hash {
				return ErrDuplicateToken
			}
		}
		ff.Tokens = append(ff.Tokens, r)
		return nil
	})
	if err != nil {
		return TokenInfo{}, err
	}
	return r.info(), nil
}

// Revoke deletes the token with the given id. It takes effect at the next
// request a server authenticates.
func (s *Store) Revoke(id string) (TokenInfo, error) {
	var gone record
	err := s.update(func(ff *fileFormat) error {
		for i, r := range ff.Tokens {
			if r.ID == id {
				gone = r
				ff.Tokens = append(ff.Tokens[:i], ff.Tokens[i+1:]...)
				return nil
			}
		}
		return ErrUnknownTokenID
	})
	if err != nil {
		return TokenInfo{}, err
	}
	return gone.info(), nil
}

// Rotate replaces the token with the given id by a new one for the same
// agent and scopes, in one atomic write: the old token stops working the
// moment the new one exists. ttl > 0 sets a new expiry; ttl == 0 keeps the
// old token's lifetime (expires_at - created_at), or none.
func (s *Store) Rotate(id string, ttl time.Duration) (string, TokenInfo, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", TokenInfo{}, err
	}
	var fresh record
	err = s.update(func(ff *fileFormat) error {
		for i, r := range ff.Tokens {
			if r.ID != id {
				continue
			}
			life := ttl
			if life == 0 && r.ExpiresAt != nil {
				life = r.ExpiresAt.Sub(r.CreatedAt)
			}
			nr, err := s.newRecord(token, MintOptions{Agent: r.Agent, Scopes: r.Scopes, TTL: life})
			if err != nil {
				return err
			}
			fresh = nr
			ff.Tokens[i] = nr
			return nil
		}
		return ErrUnknownTokenID
	})
	if err != nil {
		return "", TokenInfo{}, err
	}
	return token, fresh.info(), nil
}

// update runs fn on the current file contents under the cross-process lock
// and writes the result atomically.
func (s *Store) update(fn func(*fileFormat) error) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating token store directory: %w", err)
	}
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	ff, _, err := readFile(s.path)
	if err != nil {
		return err
	}
	if err := fn(&ff); err != nil {
		return err
	}
	ff.Version = storeVersion
	if ff.Tokens == nil {
		ff.Tokens = []record{}
	}
	data, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(s.path, append(data, '\n')); err != nil {
		return err
	}
	s.mu.Lock()
	s.loaded = false // force a re-load on the next read
	s.mu.Unlock()
	return nil
}

// lockFile takes an exclusive lock by creating path with O_EXCL; it breaks a
// lock older than staleLock (a writer that crashed).
func lockFile(path string) (func(), error) {
	deadline := time.Now().Add(lockTimeout)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("locking token store: %w", err)
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > staleLock {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, ErrStoreLocked
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writeAtomic writes data to path through a 0600 temp file in the same
// directory, fsynced, then renamed over path.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tokens-*")
	if err != nil {
		return fmt.Errorf("writing token store: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after the rename
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return fmt.Errorf("writing token store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing token store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing token store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing token store: %w", err)
	}
	if err := retryTransient(func() error { return os.Rename(name, path) }); err != nil {
		return fmt.Errorf("writing token store: %w", err)
	}
	return nil
}

// retryTransient retries fn a few times on an error that is not a
// "does not exist" or corrupt-store error. On Windows a rename over a file
// another reader has open, or an open during that rename, fails with
// "access denied" for a moment; elsewhere the first attempt decides.
func retryTransient(fn func() error) error {
	var err error
	for i := 0; i < 50; i++ {
		if err = fn(); err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrStoreCorrupt) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}
