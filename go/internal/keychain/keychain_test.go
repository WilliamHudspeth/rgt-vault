package keychain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/crypto"
	"rgt-vault-server/internal/kdf"
)

var small = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

type manifest struct {
	MasterHex           string `json:"master_hex"`
	VaultID             string `json:"vault_id"`
	Epoch               int64  `json:"epoch"`
	DEKHex              string `json:"dek_hex"`
	SecretAAD           string `json:"secret_aad"`
	SecretCiphertextHex string `json:"secret_ciphertext_hex"`
	SecretPlaintext     string `json:"secret_plaintext"`
}

func readManifest(t *testing.T, dir string) manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureDirs lists testdata/<side>/*; the default-params case is slow
// (256 MiB, 4 passes) and skipped under -short.
func fixtureDirs(t *testing.T, side string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join("testdata", side, "*"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range dirs {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		if testing.Short() && filepath.Base(d) == "default" {
			continue
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		t.Fatalf("no fixtures under testdata/%s", side)
	}
	return out
}

// copyKeychain copies a fixture keychain.json into a temp dir so tests
// never write to testdata.
func copyKeychain(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// (a) Go Load of a Python-written keychain.json yields the same DEK, and
// that DEK decrypts a secret Python encrypted with it.
func TestLoadPythonFixtures(t *testing.T) {
	for _, dir := range fixtureDirs(t, "py") {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			m := readManifest(t, dir)
			mgr := New(copyKeychain(t, dir))
			defer mgr.Close()
			dek, err := mgr.Load(mustHex(t, m.MasterHex), m.VaultID, m.Epoch)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !bytes.Equal(dek, mustHex(t, m.DEKHex)) {
				t.Fatalf("DEK mismatch: got %x want %s", dek, m.DEKHex)
			}
			pt, err := crypto.Decrypt(mustHex(t, m.SecretCiphertextHex), dek, []byte(m.SecretAAD))
			if err != nil || string(pt) != m.SecretPlaintext {
				t.Fatalf("secret decrypt: %q, %v", pt, err)
			}
			active, err := mgr.ActiveDEK()
			if err != nil || !bytes.Equal(active, dek) {
				t.Fatalf("ActiveDEK: %x, %v", active, err)
			}
		})
	}
}

// The Go encoder reproduces the exact bytes Python's json.dump(indent=2)
// wrote, so a Go-written file is indistinguishable from a Python one.
func TestMarshalMatchesPythonBytes(t *testing.T) {
	for _, dir := range fixtureDirs(t, "py") {
		raw, err := os.ReadFile(filepath.Join(dir, FileName))
		if err != nil {
			t.Fatal(err)
		}
		var f fileV1
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		got, err := marshalFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("%s: re-encoded bytes differ\n got: %s\nwant: %s", dir, got, raw)
		}
	}
}

// (b) The checked-in Go-written fixtures (testdata/go) still load in Go.
// Python loads them via testdata/verify_with_python.py; see
// TestPythonLoadsGoFixtures.
func TestLoadGoFixtures(t *testing.T) {
	for _, dir := range fixtureDirs(t, "go") {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			m := readManifest(t, dir)
			dek, err := New(copyKeychain(t, dir)).Load(mustHex(t, m.MasterHex), m.VaultID, m.Epoch)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !bytes.Equal(dek, mustHex(t, m.DEKHex)) {
				t.Fatal("DEK mismatch")
			}
		})
	}
}

// TestWriteGoFixtures regenerates testdata/go. It only runs when
// KEYCHAIN_WRITE_GO_FIXTURES=1, so the checked-in files stay static.
func TestWriteGoFixtures(t *testing.T) {
	if os.Getenv("KEYCHAIN_WRITE_GO_FIXTURES") != "1" {
		t.Skip("set KEYCHAIN_WRITE_GO_FIXTURES=1 to regenerate testdata/go")
	}
	cases := []struct {
		name    string
		master  []byte
		vaultID string
		epoch   int64
		params  kdf.Params
		rewrap  int64
	}{
		{"small", bytes.Repeat([]byte{0x42}, 32), "go-written-vault", 1, small, 0},
		{"small_rewrapped", []byte("go master, not 32 bytes"), "go-rewrap-vault", 1, small, 5},
		{"default", bytes.Repeat([]byte{0x17}, 32), "c0ffee00-1111-2222-3333-444455556666", 1, kdf.DefaultParams(), 0},
	}
	for _, c := range cases {
		dir := filepath.Join("testdata", "go", c.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		mgr := New(filepath.Join(dir, FileName))
		dek, err := mgr.Initialize(c.master, c.vaultID, c.epoch, c.params)
		if err != nil {
			t.Fatal(err)
		}
		epoch := c.epoch
		if c.rewrap != 0 {
			if err := mgr.Rewrap(c.master, c.vaultID, c.rewrap, c.params); err != nil {
				t.Fatal(err)
			}
			epoch = c.rewrap
		}
		aad := c.vaultID + ":default:api_key"
		ct, err := crypto.Encrypt([]byte("go-plaintext"), dek, []byte(aad))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.MarshalIndent(manifest{
			MasterHex: hex.EncodeToString(c.master), VaultID: c.vaultID, Epoch: epoch,
			DEKHex: hex.EncodeToString(dek), SecretAAD: aad,
			SecretCiphertextHex: hex.EncodeToString(ct), SecretPlaintext: "go-plaintext",
		}, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPythonLoadsGoFixtures runs testdata/verify_with_python.py with the
// repo's venv when it exists (python/ is end-of-life, so CI may not have
// it). It checks Python's HardenedDEKManager.load_dek on every Go-written
// fixture and on a keychain this test writes fresh.
func TestPythonLoadsGoFixtures(t *testing.T) {
	py := os.Getenv("RGT_PYTHON")
	if py == "" {
		py = filepath.Join("..", "..", "..", ".venv", "bin", "python")
	}
	if _, err := os.Stat(py); err != nil {
		t.Skipf("no Python venv at %s (set RGT_PYTHON)", py)
	}
	// Fresh Go-written case in a temp dir, alongside the checked-in ones.
	fresh := filepath.Join(t.TempDir(), "fresh")
	master := []byte("fresh-master-secret")
	mgr := New(filepath.Join(fresh, FileName))
	dek, err := mgr.Initialize(master, "fresh-vault", 7, small)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(manifest{MasterHex: hex.EncodeToString(master), VaultID: "fresh-vault", Epoch: 7, DEKHex: hex.EncodeToString(dek)})
	if err := os.WriteFile(filepath.Join(fresh, "manifest.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-I", filepath.Join("testdata", "verify_with_python.py"), fresh}, fixtureDirs(t, "go")...)
	cmd := exec.Command(py, args...)
	res, err := cmd.CombinedOutput()
	t.Logf("python output:\n%s", res)
	if err != nil {
		t.Fatalf("verify_with_python.py failed: %v", err)
	}
}

// (c) Rollback detection: the keychain epoch must equal the DB epoch.
func TestRollbackDetected(t *testing.T) {
	dir := filepath.Join("testdata", "py", "small")
	m := readManifest(t, dir)
	mgr := New(copyKeychain(t, dir))
	_, err := mgr.Load(mustHex(t, m.MasterHex), m.VaultID, m.Epoch+1)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("want ErrRollback, got %v", err)
	}
	want := "Rollback attack detected! DB epoch 2 does not match keychain epoch 1"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("message %q does not contain %q", err, want)
	}
	if _, err := mgr.ActiveDEK(); !errors.Is(err, ErrDEKNotLoaded) {
		t.Fatal("DEK must not be loaded after a rollback error")
	}
}

func TestRollbackEpochEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		epochJSON string // "" means the key is absent
		shown     string
	}{
		{"", "None"},
		{"1.0", "1.0"},
		{`"1"`, `"1"`},
		{"null", "None"}, // JSON null is None in Python too
		{"0", "0"},
		{`"` + strings.Repeat("A", 100) + `"`, `"` + strings.Repeat("A", 31) + "..."},
	} {
		p := filepath.Join(t.TempDir(), FileName)
		writeRaw(t, p, func(f map[string]any) {
			if tc.epochJSON == "" {
				delete(f, "key_epoch")
			} else {
				f["key_epoch"] = json.RawMessage(tc.epochJSON)
			}
		})
		_, err := New(p).Load([]byte("x"), "v", 1)
		if !errors.Is(err, ErrRollback) || !strings.HasSuffix(err.Error(), "keychain epoch "+tc.shown) {
			t.Errorf("epoch %q: got %v", tc.epochJSON, err)
		}
	}
}

// (d) A wrong master secret (or vault id) fails with a fixed error that
// carries no key material or crypto detail.
func TestWrongMasterFailsOpaquely(t *testing.T) {
	dir := filepath.Join("testdata", "py", "small")
	m := readManifest(t, dir)
	master := mustHex(t, m.MasterHex)
	wrong := bytes.Clone(master)
	wrong[0] ^= 1
	for name, try := range map[string]func(*Manager) error{
		"master": func(mgr *Manager) error { _, err := mgr.Load(wrong, m.VaultID, m.Epoch); return err },
		"vault":  func(mgr *Manager) error { _, err := mgr.Load(master, m.VaultID+"x", m.Epoch); return err },
	} {
		mgr := New(copyKeychain(t, dir))
		err := try(mgr)
		if err != ErrUnwrapFailed { //nolint:errorlint // must be the bare sentinel, no wrapping detail
			t.Fatalf("%s: want bare ErrUnwrapFailed, got %v", name, err)
		}
		for _, leak := range []string{m.MasterHex, hex.EncodeToString(wrong), m.DEKHex, "cipher", "authentication"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("%s: error leaks %q", name, leak)
			}
		}
		if _, err := mgr.ActiveDEK(); !errors.Is(err, ErrDEKNotLoaded) {
			t.Fatalf("%s: DEK loaded after failure", name)
		}
	}
}

// (e) Rewrap changes the salt and wrapped bytes but keeps the DEK.
func TestRewrapChangesSaltKeepsDEK(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	master := []byte("master-one")
	mgr := New(p)
	dek, err := mgr.Initialize(master, "vid", 1, small)
	if err != nil {
		t.Fatal(err)
	}
	before := readJSON(t, p)

	newMaster := []byte("master-two")
	if err := mgr.Rewrap(newMaster, "vid", 2, small); err != nil {
		t.Fatal(err)
	}
	after := readJSON(t, p)
	if before["argon2_salt"] == after["argon2_salt"] {
		t.Fatal("salt did not change on rewrap")
	}
	if before["wrapped_dek"] == after["wrapped_dek"] {
		t.Fatal("wrapped_dek did not change on rewrap")
	}
	if after["key_epoch"] != float64(2) {
		t.Fatalf("key_epoch = %v", after["key_epoch"])
	}
	salt, _ := base64.StdEncoding.DecodeString(after["argon2_salt"].(string))
	if len(salt) != SaltSize {
		t.Fatalf("salt length %d", len(salt))
	}

	got, err := New(p).Load(newMaster, "vid", 2)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Load after rewrap: %v", err)
	}
	if _, err := New(p).Load(master, "vid", 2); !errors.Is(err, ErrUnwrapFailed) {
		t.Fatalf("old master must fail after rewrap: %v", err)
	}
	if _, err := New(p).Load(newMaster, "vid", 1); !errors.Is(err, ErrRollback) {
		t.Fatalf("old epoch must be a rollback: %v", err)
	}
}

func TestRewrapRewritesParams(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	mgr := New(p)
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	p2 := kdf.Params{MemoryCost: 2048, TimeCost: 2, Parallelism: 2}
	if err := mgr.Rewrap([]byte("m"), "v", 1, p2); err != nil {
		t.Fatal(err)
	}
	f := readJSON(t, p)
	if f["argon2_memory_cost"] != float64(2048) || f["argon2_time_cost"] != float64(2) || f["argon2_parallelism"] != float64(2) {
		t.Fatalf("params not rewritten: %v", f)
	}
	if _, err := New(p).Load([]byte("m"), "v", 1); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeWritesV1Schema(t *testing.T) {
	old := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 123456789, time.FixedZone("x", 3600)) }
	defer func() { nowFunc = old }()

	dir := filepath.Join(t.TempDir(), "nested", "vault")
	p := filepath.Join(dir, FileName)
	dek, err := New(p).Initialize([]byte("m"), "v", 3, small)
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != DEKSize {
		t.Fatalf("dek length %d", len(dek))
	}
	raw, _ := os.ReadFile(p)
	var keys []string
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.Token()
	for dec.More() {
		k, _ := dec.Token()
		keys = append(keys, k.(string))
		var v json.RawMessage
		dec.Decode(&v)
	}
	want := "version,kdf,argon2_salt,argon2_memory_cost,argon2_time_cost,argon2_parallelism,wrapped_dek,created_at,key_epoch"
	if strings.Join(keys, ",") != want {
		t.Fatalf("key order %v", keys)
	}
	f := readJSON(t, p)
	if f["version"] != float64(1) || f["kdf"] != "argon2id" || f["created_at"] != "2026-11-26T11:00:00.123456+00:00" {
		t.Fatalf("unexpected fields: %v", f)
	}
	if bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("Python json.dump writes no trailing newline")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %v", st.Mode().Perm())
		}
		dst, _ := os.Stat(dir)
		if dst.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", dst.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestPyISOTime(t *testing.T) {
	if got := pyISOTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); got != "2026-01-02T03:04:05+00:00" {
		t.Fatal(got)
	}
	if got := pyISOTime(time.Date(2026, 1, 2, 3, 4, 5, 999, time.UTC)); got != "2026-01-02T03:04:05+00:00" {
		t.Fatalf("sub-microsecond must truncate: %s", got)
	}
	if got := pyISOTime(time.Date(2026, 1, 2, 3, 4, 5, 1000, time.UTC)); got != "2026-01-02T03:04:05.000001+00:00" {
		t.Fatal(got)
	}
}

func TestInitializeReplacesExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	a, _ := New(p).Initialize([]byte("m"), "v", 1, small)
	b, err := New(p).Initialize([]byte("m"), "v", 1, small)
	if err != nil || bytes.Equal(a, b) {
		t.Fatalf("second Initialize should replace with a new DEK: %v", err)
	}
	got, _ := New(p).Load([]byte("m"), "v", 1)
	if !bytes.Equal(got, b) {
		t.Fatal("file does not hold the newest DEK")
	}
}

func TestNotLoaded(t *testing.T) {
	mgr := New(filepath.Join(t.TempDir(), FileName))
	if err := mgr.Rewrap([]byte("m"), "v", 1, small); !errors.Is(err, ErrDEKNotLoaded) {
		t.Fatal(err)
	}
	if _, err := mgr.ActiveDEK(); !errors.Is(err, ErrDEKNotLoaded) {
		t.Fatal(err)
	}
	if _, err := mgr.Load([]byte("m"), "v", 1); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if mgr.Path() == "" {
		t.Fatal("Path")
	}
}

func TestCloseWipes(t *testing.T) {
	mgr := New(filepath.Join(t.TempDir(), FileName))
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	inner := mgr.dek
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inner, make([]byte, DEKSize)) {
		t.Fatal("DEK not zeroed on Close")
	}
	if _, err := mgr.ActiveDEK(); !errors.Is(err, ErrDEKNotLoaded) {
		t.Fatal("DEK still loaded after Close")
	}
}

func TestReturnedDEKIsACopy(t *testing.T) {
	mgr := New(filepath.Join(t.TempDir(), FileName))
	dek, _ := mgr.Initialize([]byte("m"), "v", 1, small)
	Wipe(dek)
	active, _ := mgr.ActiveDEK()
	if bytes.Equal(active, make([]byte, DEKSize)) {
		t.Fatal("wiping the returned DEK wiped the manager's copy")
	}
}

func TestInvalidParams(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	for _, bad := range []kdf.Params{
		{MemoryCost: 0, TimeCost: 1, Parallelism: 1},
		{MemoryCost: 1024, TimeCost: 0, Parallelism: 1},
		{MemoryCost: 1024, TimeCost: 1, Parallelism: 0},
		{MemoryCost: 31, TimeCost: 1, Parallelism: 4}, // < 8*lanes
	} {
		if _, err := New(p).Initialize([]byte("m"), "v", 1, bad); !errors.Is(err, ErrInvalidParams) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed Initialize must not write a file")
	}
}

func TestLoadRejectsMalformedFiles(t *testing.T) {
	valid := filepath.Join(t.TempDir(), FileName)
	if _, err := New(valid).Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		edit func(map[string]any)
		want error
	}{
		"missing salt":     {func(f map[string]any) { delete(f, "argon2_salt") }, ErrInvalidKeychain},
		"missing wrapped":  {func(f map[string]any) { delete(f, "wrapped_dek") }, ErrInvalidKeychain},
		"bad salt b64":     {func(f map[string]any) { f["argon2_salt"] = "!!" }, ErrInvalidKeychain},
		"bad wrapped b64":  {func(f map[string]any) { f["wrapped_dek"] = "!!" }, ErrInvalidKeychain},
		"missing mem":      {func(f map[string]any) { delete(f, "argon2_memory_cost") }, ErrInvalidKeychain},
		"missing time":     {func(f map[string]any) { delete(f, "argon2_time_cost") }, ErrInvalidKeychain},
		"missing par":      {func(f map[string]any) { delete(f, "argon2_parallelism") }, ErrInvalidKeychain},
		"negative mem":     {func(f map[string]any) { f["argon2_memory_cost"] = -1 }, ErrInvalidParams},
		"float time":       {func(f map[string]any) { f["argon2_time_cost"] = 1.5 }, ErrInvalidParams},
		"par too big":      {func(f map[string]any) { f["argon2_parallelism"] = 256 }, ErrInvalidParams},
		"mem below 8xpar":  {func(f map[string]any) { f["argon2_parallelism"] = 200 }, ErrInvalidParams},
		"short salt":       {func(f map[string]any) { f["argon2_salt"] = "AAAA" }, kdf.ErrInvalidSalt},
		"tampered wrapped": {func(f map[string]any) { f["wrapped_dek"] = flipB64(f["wrapped_dek"].(string)) }, ErrUnwrapFailed},
		"tampered salt":    {func(f map[string]any) { f["argon2_salt"] = flipB64(f["argon2_salt"].(string)) }, ErrUnwrapFailed},
		"truncated":        {func(f map[string]any) { f["wrapped_dek"] = "AAAA" }, ErrUnwrapFailed},
	}
	for name, tc := range cases {
		p := filepath.Join(t.TempDir(), FileName)
		raw, _ := os.ReadFile(valid)
		os.WriteFile(p, raw, 0o600)
		writeRaw(t, p, tc.edit)
		if _, err := New(p).Load([]byte("m"), "v", 1); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}

	p := filepath.Join(t.TempDir(), FileName)
	raw, _ := os.ReadFile(valid)
	os.WriteFile(p, append(raw, []byte(" {}")...), 0o600)
	if _, err := New(p).Load([]byte("m"), "v", 1); !errors.Is(err, ErrInvalidKeychain) {
		t.Errorf("trailing data: %v", err)
	}
	os.WriteFile(p, append(raw, []byte("\n\t ")...), 0o600)
	if _, err := New(p).Load([]byte("m"), "v", 1); err != nil {
		t.Errorf("trailing whitespace must be accepted like json.load: %v", err)
	}
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := New(p).Load([]byte("m"), "v", 1); !errors.Is(err, ErrInvalidKeychain) {
		t.Errorf("bad json: %v", err)
	}
	os.WriteFile(p, bytes.Repeat([]byte(" "), maxFileSize+1), 0o600)
	if _, err := New(p).Load([]byte("m"), "v", 1); !errors.Is(err, ErrInvalidKeychain) {
		t.Errorf("oversize: %v", err)
	}
	if _, err := New(t.TempDir()).Load([]byte("m"), "v", 1); err == nil {
		t.Error("loading a directory must fail")
	}
}

// A wrapped value that authenticates but is not a 32-byte DEK is refused
// (Python would accept it and silently use AES-128/192).
func TestLoadRejectsShortDEK(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	if _, err := New(p).Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	f := readJSON(t, p)
	salt, _ := base64.StdEncoding.DecodeString(f["argon2_salt"].(string))
	short, err := wrap(make([]byte, 16), []byte("m"), salt, "v", 1, small)
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, p, func(f map[string]any) { f["wrapped_dek"] = base64.StdEncoding.EncodeToString(short) })
	if _, err := New(p).Load([]byte("m"), "v", 1); !errors.Is(err, ErrInvalidKeychain) {
		t.Fatalf("got %v", err)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestRandomFailure(t *testing.T) {
	old := randReader
	defer func() { randReader = old }()
	p := filepath.Join(t.TempDir(), FileName)
	mgr := New(p)
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	randReader = failReader{}
	if _, err := New(p).Initialize([]byte("m"), "v", 1, small); err == nil {
		t.Fatal("Initialize must fail without entropy")
	}
	if err := mgr.Rewrap([]byte("m"), "v", 2, small); err == nil {
		t.Fatal("Rewrap must fail without entropy")
	}
	if _, err := New(p).Load([]byte("m"), "v", 1); err != nil {
		t.Fatalf("failed rewrap must leave the old file intact: %v", err)
	}
}

func TestWriteFailures(t *testing.T) {
	// Parent path is a regular file: MkdirAll fails.
	base := t.TempDir()
	blocker := filepath.Join(base, "file")
	os.WriteFile(blocker, nil, 0o600)
	if _, err := New(filepath.Join(blocker, "sub", FileName)).Initialize([]byte("m"), "v", 1, small); err == nil {
		t.Fatal("Initialize under a file must fail")
	}
	// Rewrap after the directory vanished: CreateTemp fails.
	dir := filepath.Join(base, "gone")
	mgr := New(filepath.Join(dir, FileName))
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(dir)
	if err := mgr.Rewrap([]byte("m"), "v", 2, small); err == nil {
		t.Fatal("Rewrap into a missing directory must fail")
	}
	// Target is a non-empty directory: rename fails and the temp file is removed.
	dir2 := filepath.Join(base, "d2")
	target := filepath.Join(dir2, FileName)
	os.MkdirAll(filepath.Join(target, "x"), 0o700)
	if err := atomicWrite(target, []byte("{}")); err == nil {
		t.Fatal("rename over a directory must fail")
	}
	entries, _ := os.ReadDir(dir2)
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestSelfTest(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatal(err)
	}
	// The constant matches the Python-generated vector file.
	raw, err := os.ReadFile(filepath.Join("testdata", "py", "selftest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		CiphertextHex string `json:"ciphertext_hex"`
	}
	json.Unmarshal(raw, &v)
	if v.CiphertextHex != selfTestKAT {
		t.Fatalf("selfTestKAT %s != Python %s", selfTestKAT, v.CiphertextHex)
	}
	err = selfTest([]byte("wrong"))
	if !errors.Is(err, ErrSelfTest) || !strings.Contains(err.Error(), "known-answer") {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	mgr := New(p)
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				if _, err := mgr.ActiveDEK(); err != nil {
					t.Error(err)
				}
			} else if err := mgr.Rewrap([]byte("m"), "v", 1, small); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if _, err := New(p).Load([]byte("m"), "v", 1); err != nil {
		t.Fatal(err)
	}
}

// Initialize, Load and Close racing must never hand out a zeroed DEK or
// leave the in-memory DEK out of step with the file. Run with -race.
func TestConcurrentInitLoadClose(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	mgr := New(p)
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, DEKSize)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var dek []byte
			var err error
			switch i % 3 {
			case 0:
				dek, err = mgr.Initialize([]byte("m"), "v", 1, small)
			case 1:
				dek, err = mgr.Load([]byte("m"), "v", 1)
			default:
				err = mgr.Close()
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			if bytes.Equal(dek, zero) {
				t.Error("returned DEK was wiped by a concurrent call")
			}
		}(i)
	}
	wg.Wait()
	onDisk, err := New(p).Load([]byte("m"), "v", 1)
	if err != nil {
		t.Fatal(err)
	}
	if mem, err := mgr.ActiveDEK(); err == nil && !bytes.Equal(mem, onDisk) {
		t.Fatal("in-memory DEK differs from keychain.json")
	}
}

func TestReplacingDEKWipesOld(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	mgr := New(p)
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	old := mgr.dek
	if _, err := mgr.Load([]byte("m"), "v", 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, make([]byte, DEKSize)) {
		t.Fatal("previous DEK not zeroed when replaced by Load")
	}
	old = mgr.dek
	if _, err := mgr.Initialize([]byte("m"), "v", 1, small); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, make([]byte, DEKSize)) {
		t.Fatal("previous DEK not zeroed when replaced by Initialize")
	}
}

func TestHelpers(t *testing.T) {
	if string(BindingContext("abc")) != "rgt-vault:abc" {
		t.Fatal("binding")
	}
	if string(WrapAAD("abc", -3)) != "abc:-3" || string(WrapAAD("abc", 12)) != "abc:12" {
		t.Fatal("aad")
	}
}

func readJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// writeRaw rewrites the keychain at p (or a minimal valid-looking one if p
// does not exist) after applying edit.
func writeRaw(t *testing.T, p string, edit func(map[string]any)) {
	t.Helper()
	f := map[string]any{
		"version": 1, "kdf": "argon2id",
		"argon2_salt":        base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"argon2_memory_cost": 1024, "argon2_time_cost": 1, "argon2_parallelism": 1,
		"wrapped_dek": base64.StdEncoding.EncodeToString(make([]byte, 48)),
		"created_at":  "2026-01-01T00:00:00+00:00", "key_epoch": 1,
	}
	if raw, err := os.ReadFile(p); err == nil {
		f = nil
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
	}
	edit(f)
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func flipB64(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	b[len(b)-1] ^= 0x01
	return base64.StdEncoding.EncodeToString(b)
}
