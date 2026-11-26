package providers

import (
	"bytes"
	"errors"
	"testing"
)

// fakeKeyring installs in-memory keyring seams for one test.
type fakeKeyring struct {
	store   map[string]string
	getErr  error
	setErr  error
	sets    int
	lastSvc string
}

func useFakeKeyring(t *testing.T) *fakeKeyring {
	t.Helper()
	f := &fakeKeyring{store: map[string]string{}}
	oldGet, oldSet := keyringGet, keyringSet
	keyringGet = func(svc, user string) (string, error) {
		if f.getErr != nil {
			return "", f.getErr
		}
		v, ok := f.store[svc+"\x00"+user]
		if !ok {
			return "", errKeyNotFound
		}
		return v, nil
	}
	keyringSet = func(svc, user, val string) error {
		f.sets++
		f.lastSvc = svc
		if f.setErr != nil {
			return f.setErr
		}
		f.store[svc+"\x00"+user] = val
		return nil
	}
	t.Cleanup(func() { keyringGet, keyringSet = oldGet, oldSet })
	return f
}

// Vectors produced by Python:
//
//	base64.urlsafe_b64encode(bytes(range(32))).decode()
const pyVector = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func seq32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestKeyringDefaults(t *testing.T) {
	p := NewKeyringProvider("", "")
	if p.Service != "rgt_vault" || p.User != "master_key" {
		t.Fatalf("defaults: %+v", p)
	}
	q := NewKeyringProvider("s", "u")
	if q.Service != "s" || q.User != "u" {
		t.Fatalf("explicit: %+v", q)
	}
}

func TestKeyringGetPythonVector(t *testing.T) {
	f := useFakeKeyring(t)
	f.store["rgt_vault\x00master_key"] = pyVector
	got, err := NewKeyringProvider("", "").GetMasterSecret()
	if err != nil || !bytes.Equal(got, seq32()) {
		t.Fatalf("got %x, %v", got, err)
	}
}

func TestDecodeKeyringSecretVariants(t *testing.T) {
	want := seq32()
	unpadded := pyVector[:len(pyVector)-1] // legacy entries lacking '='
	std := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	for name, in := range map[string]string{
		"padded": pyVector, "unpadded": unpadded, "std-alphabet": std, "newline": pyVector + "\n",
	} {
		got, err := decodeKeyringSecret(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %x %v", name, got, err)
		}
	}
	// '+' and '/' (standard alphabet) are accepted like Python's translate.
	got, err := decodeKeyringSecret("++//")
	if err != nil || !bytes.Equal(got, []byte{0xfb, 0xef, 0xff}) {
		t.Errorf("std chars: %x %v", got, err)
	}
	if _, err := decodeKeyringSecret("!!!!"); !errors.Is(err, ErrMasterSecretUnavailable) {
		t.Errorf("invalid: %v", err)
	}
	if _, err := decodeKeyringSecret("A"); err == nil {
		t.Error("length 1 mod 4 must fail")
	}
}

func TestKeyringGetMissingFailsClosed(t *testing.T) {
	f := useFakeKeyring(t)
	p := NewKeyringProvider("", "")
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) {
		t.Fatalf("missing: %v", err)
	}
	if f.sets != 0 {
		t.Fatal("GetMasterSecret must never create a secret")
	}
	f.store["rgt_vault\x00master_key"] = ""
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) {
		t.Fatalf("empty: %v", err)
	}
	f.getErr = errors.New("dbus down")
	_, err := p.GetMasterSecret()
	if err == nil || errors.Is(err, ErrMasterSecretUnavailable) {
		t.Fatalf("backend failure should be surfaced distinctly: %v", err)
	}
}

func TestKeyringRotateStoresURLSafePadded(t *testing.T) {
	f := useFakeKeyring(t)
	p := NewKeyringProvider("", "")
	raw, err := p.RotateMasterSecret()
	if err != nil || len(raw) != 32 {
		t.Fatalf("rotate: %x %v", raw, err)
	}
	stored := f.store["rgt_vault\x00master_key"]
	if len(stored) != 44 || stored[43] != '=' {
		t.Fatalf("stored form %q must be 44-char padded urlsafe base64", stored)
	}
	back, err := p.GetMasterSecret()
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatalf("roundtrip: %x %v", back, err)
	}
	f.setErr = errors.New("locked")
	if _, err := p.RotateMasterSecret(); err == nil {
		t.Fatal("set failure must propagate")
	}
}

func TestKeyringInitializeIfMissing(t *testing.T) {
	f := useFakeKeyring(t)
	p := NewKeyringProvider("", "")

	if err := p.BootstrapMasterSecret(); err != nil || f.sets != 1 {
		t.Fatalf("first bootstrap: %v sets=%d", err, f.sets)
	}
	first, _ := p.GetMasterSecret()

	// Second call must keep the existing secret.
	second, err := p.InitializeIfMissing()
	if err != nil || !bytes.Equal(first, second) || f.sets != 1 {
		t.Fatalf("idempotent init: %v sets=%d", err, f.sets)
	}

	// A keyring failure other than not-found must NOT create a secret.
	g := useFakeKeyring(t)
	g.getErr = errors.New("keyring locked")
	if _, err := p.InitializeIfMissing(); err == nil || g.sets != 0 {
		t.Fatalf("must fail closed: %v sets=%d", err, g.sets)
	}
	if err := p.BootstrapMasterSecret(); err == nil {
		t.Fatal("bootstrap must surface the failure")
	}

	// Empty stored value counts as missing.
	h := useFakeKeyring(t)
	h.store["rgt_vault\x00master_key"] = ""
	if _, err := p.InitializeIfMissing(); err != nil || h.sets != 1 {
		t.Fatalf("empty entry: %v sets=%d", err, h.sets)
	}

	// Corrupt existing value is an error, never overwritten.
	k := useFakeKeyring(t)
	k.store["rgt_vault\x00master_key"] = "!!!!"
	if _, err := p.InitializeIfMissing(); err == nil || k.sets != 0 {
		t.Fatalf("corrupt entry must not be replaced: %v sets=%d", err, k.sets)
	}
}
