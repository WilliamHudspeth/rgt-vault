package compat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

func TestMain(m *testing.M) {
	// Error paths log incident ids; keep test output readable.
	log.SetOutput(io.Discard)
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// pyvaultDir is go/testdata/pyvault (frozen Python-written fixtures, G0).
const pyvaultDir = "../../testdata/pyvault"

// testKDF are cheap Argon2 parameters for keychains the Go side creates.
var testKDF = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

// fixtures are the three Python-created vault directories.
var fixtures = []string{"small", "default", "epoch1"}

// ---------------------------------------------------------------- manifest

type manifestSecret struct {
	Namespace       string  `json:"namespace"`
	Name            string  `json:"name"`
	Version         int64   `json:"version"`
	Status          string  `json:"status"`
	Honeytoken      bool    `json:"honeytoken"`
	Fingerprint     string  `json:"fingerprint"`
	ReadLatest      *string `json:"read_latest"`
	ReadByVersion   string  `json:"read_by_version"`
	PlaintextSHA256 string  `json:"plaintext_sha256"`
	Plaintext       *string `json:"plaintext"`
}

type manifest struct {
	VaultID    string           `json:"vault_id"`
	KeyEpoch   int64            `json:"key_epoch"`
	PolicyHash string           `json:"policy_hash"`
	Keychain   map[string]any   `json:"keychain"`
	RowCounts  map[string]int64 `json:"row_counts"`
	Migrations []int            `json:"migrations_applied"`
	Secrets    []manifestSecret `json:"secrets"`
	Audit      struct {
		Verify    bool   `json:"verify_audit_chain"`
		FirstHash string `json:"first_entry_hash"`
		LastHash  string `json:"last_entry_hash"`
	} `json:"audit"`
	Export struct {
		SHA256 string `json:"sha256"`
	} `json:"export"`
}

func loadManifest(t *testing.T, fixture string) manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pyvaultDir, fixture, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// want is the sha256 (or Python exception name) a by-version read must give.
func (s manifestSecret) want() string {
	if s.ReadByVersion == "ok" {
		return s.PlaintextSHA256
	}
	return s.ReadByVersion
}

// wantLatest is the same for a read of the latest version of the name.
func (s manifestSecret) wantLatest() (string, bool) {
	if s.ReadLatest == nil {
		return "", false
	}
	if *s.ReadLatest == "ok" {
		return s.PlaintextSHA256, true
	}
	return *s.ReadLatest, true
}

// -------------------------------------------------------- vault directories

// vaultDir is a private copy of a vault directory (opening a vault appends
// audit rows and creates WAL files, so tests never touch the committed copy).
type vaultDir struct {
	Dir      string
	DB       string
	Master   string // raw 32-byte master secret file (fixed-master provider)
	Policy   string // policy.yaml path, "" = none
	Keychain string
	Export   string // export.b64 as Python wrote it (fixtures only)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// copyFixture copies one of small/default/epoch1 to a temp dir.
func copyFixture(t *testing.T, name string) vaultDir {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"vault.db", "keychain.json", "master.bin", "policy.yaml", "export.b64"} {
		copyFile(t, filepath.Join(pyvaultDir, name, f), filepath.Join(dir, f))
	}
	return vaultDir{
		Dir: dir, DB: filepath.Join(dir, "vault.db"), Master: filepath.Join(dir, "master.bin"),
		Policy: filepath.Join(dir, "policy.yaml"), Keychain: filepath.Join(dir, "keychain.json"),
		Export: filepath.Join(dir, "export.b64"),
	}
}

// emptyDir returns a vault directory with a fresh random master secret and
// an allow-everything policy, for vaults Go creates itself.
func emptyDir(t *testing.T) vaultDir {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fresh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mem := providerstest.NewMemory()
	secret, _ := mem.GetMasterSecret()
	v := vaultDir{
		Dir: dir, DB: filepath.Join(dir, "vault.db"), Master: filepath.Join(dir, "master.bin"),
		Policy: filepath.Join(dir, "policy.yaml"), Keychain: filepath.Join(dir, "keychain.json"),
	}
	if err := os.WriteFile(v.Master, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v.Policy, []byte(allowAllPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	return v
}

const allowAllPolicy = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: deny
    agent: intruder
    action: read
`

// ------------------------------------------------------------ the full stack

// env is an open vault behind the real HTTP handler (middleware, auth, audit
// of every request), exactly what `rgt-vault serve` mounts.
type env struct {
	t     *testing.T
	Dir   vaultDir
	Stack *server.Stack
	h     http.Handler
	token string
}

// open opens dir through server.OpenStack (providers -> keychain -> store ->
// vault -> actions/capabilities) and mounts the HTTP handler on it.
func open(t *testing.T, d vaultDir) *env {
	t.Helper()
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath:         d.DB,
		PolicyFile:     d.Policy,
		MasterProvider: providerstest.File{Path: d.Master},
		RateLimit:      1_000_000,
		KDFParams:      testKDF,
	})
	if err != nil {
		t.Fatalf("OpenStack(%s): %v", d.DB, err)
	}
	e := &env{t: t, Dir: d, Stack: stack}
	t.Cleanup(e.Close)

	store := auth.NewTokenStore(filepath.Join(d.Dir, "agent.token"))
	tok, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(tok); err != nil {
		t.Fatal(err)
	}
	e.token = tok
	e.h, err = server.New(server.Config{
		// Python parity = the pre-H1 shared-token model, including the
		// privileged routes (audit/verify, rotate, lease) Python serves.
		Vault: stack.Vault, AgentTokens: store, LegacyPrivilegedRoutes: true, Broker: stack.Broker,
		Actions: stack.Actions, Capabilities: stack.Capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Close closes the vault (idempotent).
func (e *env) Close() {
	if e.Stack != nil {
		_ = e.Stack.Close()
		e.Stack = nil
	}
}

// V is the vault.
func (e *env) V() *vault.Vault { return e.Stack.Vault }

// call performs one HTTP request and decodes the JSON object response.
func (e *env) call(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("Authorization", "Bearer "+e.token)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func (e *env) mustOK(method, path string, body any) map[string]any {
	e.t.Helper()
	code, m := e.call(method, path, body)
	if code != http.StatusOK {
		e.t.Fatalf("%s %s: HTTP %d %v", method, path, code, m)
	}
	return m
}

// set writes a secret through POST /v1/secrets.
func (e *env) set(ns, name, value string) {
	e.t.Helper()
	e.mustOK("POST", "/v1/secrets", map[string]any{
		"name": name, "namespace": ns, "value": value, "agent": "system", "purpose": "compat",
	})
}

// rotate calls POST /v1/rotate (target "dek" or "master").
func (e *env) rotate(target string) int64 {
	e.t.Helper()
	m := e.mustOK("POST", "/v1/rotate", map[string]any{"target": target})
	n, _ := m["key_epoch"].(float64)
	return int64(n)
}

// chainOK is POST /v1/audit/verify.
func (e *env) chainOK() bool {
	e.t.Helper()
	m := e.mustOK("POST", "/v1/audit/verify", nil)
	ok, _ := m["ok"].(bool)
	return ok
}

// read leases one version (0 = latest) as agent ci-bot and returns
// sha256(plaintext) or the Python exception name of the failure.
func (e *env) read(ns, name string, version int64) string {
	e.t.Helper()
	got, _ := e.lease(ns, name, version)
	return got
}

// lease is read plus the plaintext (empty on error).
func (e *env) lease(ns, name string, version int64) (label, plaintext string) {
	e.t.Helper()
	var buf []byte
	err := e.V().Lease(context.Background(), vault.LeaseRequest{
		Name: name, Namespace: ns, Agent: "ci-bot", Purpose: "compat-test", Version: version,
	}, func(b []byte) error {
		buf = bytes.Clone(b)
		return nil
	})
	return errLabel(err, sha(buf)), string(buf)
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// errLabel maps a Go error to the Python exception class name the manifest uses.
func errLabel(err error, ok string) string {
	switch {
	case err == nil:
		return ok
	case errors.Is(err, vault.ErrHoneytoken):
		return "PermissionError"
	case errors.Is(err, vault.ErrNotFound):
		return "SecretNotFoundError"
	case errors.Is(err, vault.ErrPolicyDenied):
		return "PolicyDeniedError"
	case strings.Contains(err.Error(), "decryption failed"):
		return "DecryptionError"
	default:
		return "error: " + err.Error()
	}
}

// ------------------------------------------------------------- the binary

var (
	binOnce sync.Once
	binDir  string
	binPath string
	binErr  error
)

// binary builds the real cmd/rgt-vault once and returns its path. CGO is off
// (as in the release build), so the binary is the shipped artifact.
func binary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("RGT_COMPAT_BIN"); p != "" {
		return p
	}
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "rgt-compat-bin-")
		if binErr != nil {
			return
		}
		name := "rgt-vault"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		binPath = filepath.Join(binDir, name)
		cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/rgt-vault")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = errors.New("go build ./cmd/rgt-vault: " + err.Error() + "\n" + string(out))
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

// runBin runs the binary with a scrubbed environment (no inherited
// RGT_VAULT_* settings, HOME in a temp dir) and returns stdout, stderr and
// the exit code.
func runBin(t *testing.T, extraEnv []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	home := t.TempDir()
	cmd.Env = append(cleanEnv(), "HOME="+home, "USERPROFILE="+home)
	cmd.Env = append(cmd.Env, extraEnv...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("running %v: %v", args, err)
	}
	return so.String(), se.String(), code
}

// cleanEnv is os.Environ without RGT_VAULT_* / VAULT_* variables.
func cleanEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RGT_VAULT_") || strings.HasPrefix(kv, "VAULT_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// ------------------------------------------------------------------ python

// python returns the interpreter with rgt_vault installed, or skips.
func python(t *testing.T) string {
	t.Helper()
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault installed (pip install -e '.[server,dev]') to run the Python round trip")
	}
	return py
}

// runPython runs testdata/pycompat.py <cmd> and decodes its JSON report.
func runPython(t *testing.T, py string, extraEnv []string, args ...string) map[string]any {
	t.Helper()
	script, err := filepath.Abs("testdata/pycompat.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var se bytes.Buffer
	cmd.Stderr = &se
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python %v: %v\n%s", args[0], err, se.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("python %v output: %v\n%s", args[0], err, out)
	}
	return m
}

func strs(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, len(raw))
	for i, x := range raw {
		out[i], _ = x.(string)
	}
	return out
}
