package providers

import (
	"errors"
	"testing"
)

type fakeCred struct {
	user string
	blob []byte
}

type fakeCredStore struct {
	m        map[string]fakeCred
	readErr  error
	writeErr error
	writes   []string
}

func newFakeCredStore() *fakeCredStore { return &fakeCredStore{m: map[string]fakeCred{}} }

func (f *fakeCredStore) Read(target string) (*winCredential, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	c, ok := f.m[target]
	if !ok {
		return nil, nil
	}
	return &winCredential{UserName: c.user, Blob: c.blob}, nil
}

func (f *fakeCredStore) Write(target, user string, blob []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, target)
	f.m[target] = fakeCred{user, blob}
	return nil
}

func TestWinBlobCodec(t *testing.T) {
	// Python: 'A'.encode('utf-16-le') == 4100, 'k€' == 6b00ac20.
	if got := encodeWinBlob("A"); string(got) != "A\x00" {
		t.Fatalf("A: %x", got)
	}
	if got := encodeWinBlob("k€"); string(got) != "\x6b\x00\xac\x20" {
		t.Fatalf("k€: %x", got)
	}
	if got := decodeWinBlob([]byte("\x6b\x00\xac\x20")); got != "k€" {
		t.Fatalf("decode utf16: %q", got)
	}
	// Surrogate pair (U+1F600) round-trips.
	if got := decodeWinBlob(encodeWinBlob("😀")); got != "😀" {
		t.Fatalf("surrogates: %q", got)
	}
	// Odd length: not UTF-16, valid UTF-8 → UTF-8 fallback (DecodingCredential).
	if got := decodeWinBlob([]byte("abc")); got != "abc" {
		t.Fatalf("utf8 fallback: %q", got)
	}
	// Lone surrogate, even length, valid UTF-8 bytes? 0x00 0xD8 is not UTF-8-safe,
	// but "\x00\xd8" is invalid UTF-8 → empty.
	if got := decodeWinBlob([]byte{0x00, 0xD8}); got != "" {
		t.Fatalf("undecodable: %q", got)
	}
	// Unpaired low surrogate, high surrogate followed by non-low.
	for _, units := range [][]uint16{{0xDC00}, {0xD800}, {0xD800, 0x0041}} {
		if validUTF16(units) {
			t.Errorf("%x should be invalid", units)
		}
	}
}

func TestWinVaultSetThenGet(t *testing.T) {
	s := newFakeCredStore()
	if err := winVaultSet(s, "rgt_vault", "master_key", "SECRET"); err != nil {
		t.Fatal(err)
	}
	c := s.m["rgt_vault"]
	if c.user != "master_key" || string(c.blob) != string(encodeWinBlob("SECRET")) {
		t.Fatalf("stored under service name with UTF-16 blob: %+v", c)
	}
	got, err := winVaultGet(s, "rgt_vault", "master_key")
	if err != nil || got != "SECRET" {
		t.Fatalf("get: %q %v", got, err)
	}
}

func TestWinVaultCollisionUsesCompoundTarget(t *testing.T) {
	s := newFakeCredStore()
	_ = winVaultSet(s, "svc", "alice", "pw-alice")
	_ = winVaultSet(s, "svc", "bob", "pw-bob")

	// alice's entry was moved to alice@svc, bob now owns "svc".
	if c := s.m["alice@svc"]; c.user != "alice" {
		t.Fatalf("alice should have moved to compound target: %+v", s.m)
	}
	if got, _ := winVaultGet(s, "svc", "bob"); got != "pw-bob" {
		t.Fatalf("bob: %q", got)
	}
	if got, _ := winVaultGet(s, "svc", "alice"); got != "pw-alice" {
		t.Fatalf("alice: %q", got)
	}
	// Re-setting the same user also re-saves the previous entry compound-style.
	_ = winVaultSet(s, "svc", "bob", "pw-bob2")
	if got, _ := winVaultGet(s, "svc", "bob"); got != "pw-bob2" {
		t.Fatalf("bob2: %q", got)
	}
	// A rotation by the same user must not keep the old secret around.
	if _, ok := s.m["bob@svc"]; ok {
		t.Fatal("same-user rotation must not preserve the old secret under bob@svc")
	}
}

func TestWinVaultGetFallbackAndMissing(t *testing.T) {
	s := newFakeCredStore()
	if _, err := winVaultGet(s, "svc", "u"); !errors.Is(err, errKeyNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// An entry written by go-keyring itself: target "svc:u", UTF-8 blob.
	s.m["svc:u"] = fakeCred{"u", []byte("from-go-keyring")}
	if got, err := winVaultGet(s, "svc", "u"); err != nil || got != "from-go-keyring" {
		t.Fatalf("go-keyring fallback: %q %v", got, err)
	}
	// Another user's credential under the service name does not match.
	s2 := newFakeCredStore()
	s2.m["svc"] = fakeCred{"other", encodeWinBlob("x")}
	if _, err := winVaultGet(s2, "svc", "u"); !errors.Is(err, errKeyNotFound) {
		t.Fatalf("other user: %v", err)
	}
	// Empty username matches whatever is under the service name.
	if got, err := winVaultGet(s2, "svc", ""); err != nil || got != "x" {
		t.Fatalf("empty username: %q %v", got, err)
	}
}

func TestWinVaultRotationRefreshesAliases(t *testing.T) {
	s := newFakeCredStore()
	s.m["svc"] = fakeCred{"u", encodeWinBlob("old")}
	s.m["u@svc"] = fakeCred{"u", encodeWinBlob("old")}       // written by Python keyring
	s.m["svc:u"] = fakeCred{"u", []byte("old")}              // written by go-keyring
	s.m["u2@svc"] = fakeCred{"someone-else", []byte("keep")} // different user: untouched
	if err := winVaultSet(s, "svc", "u", "new"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"svc", "u@svc"} {
		if got := decodeWinBlob(s.m[target].blob); got != "new" {
			t.Errorf("%s still holds %q", target, got)
		}
	}
	if string(s.m["svc:u"].blob) != "new" {
		t.Errorf("go-keyring alias still holds %q", s.m["svc:u"].blob)
	}
	if string(s.m["u2@svc"].blob) != "keep" {
		t.Error("unrelated entry modified")
	}
	// Alias read / write failures surface.
	boom := errors.New("boom")
	f3 := &failNth{fakeCredStore: newFakeCredStore(), at: 2, err: boom}
	if err := winVaultSet(f3, "svc", "u", "x"); !errors.Is(err, boom) {
		t.Fatalf("compound read: %v", err)
	}
	f4 := &failNth{fakeCredStore: newFakeCredStore(), at: 3, err: boom}
	if err := winVaultSet(f4, "svc", "u", "x"); !errors.Is(err, boom) {
		t.Fatalf("go-keyring alias read: %v", err)
	}
	w := &failWriteN{fakeCredStore: newFakeCredStore(), at: 2, err: boom}
	w.m["u@svc"] = fakeCred{"u", encodeWinBlob("old")}
	if err := winVaultSet(w, "svc", "u", "x"); !errors.Is(err, boom) {
		t.Fatalf("compound refresh write: %v", err)
	}
	w2 := &failWriteN{fakeCredStore: newFakeCredStore(), at: 2, err: boom}
	w2.m["svc:u"] = fakeCred{"u", []byte("old")}
	if err := winVaultSet(w2, "svc", "u", "x"); !errors.Is(err, boom) {
		t.Fatalf("alias refresh write: %v", err)
	}
}

type failWriteN struct {
	*fakeCredStore
	at, calls int
	err       error
}

func (f *failWriteN) Write(target, user string, blob []byte) error {
	f.calls++
	if f.calls == f.at {
		return f.err
	}
	return f.fakeCredStore.Write(target, user, blob)
}

func TestWinVaultUndecodableFailsClosed(t *testing.T) {
	s := newFakeCredStore()
	s.m["svc"] = fakeCred{"u", []byte{0x00, 0xD8}} // lone surrogate, invalid UTF-8
	if _, err := winVaultGet(s, "svc", "u"); err == nil || errors.Is(err, errKeyNotFound) {
		t.Fatalf("must be an error, not 'missing': %v", err)
	}
}

func TestWinVaultErrors(t *testing.T) {
	boom := errors.New("boom")
	s := newFakeCredStore()
	s.readErr = boom
	if _, err := winVaultGet(s, "a", "b"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := winVaultSet(s, "a", "b", "c"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	// Read error on the compound lookup and on the go-keyring fallback.
	n := 0
	s2 := &failNth{fakeCredStore: newFakeCredStore(), at: 2, err: boom}
	s2.m["a"] = fakeCred{"other", encodeWinBlob("x")}
	if _, err := winVaultGet(s2, "a", "b"); !errors.Is(err, boom) {
		t.Fatalf("compound read: %v", err)
	}
	_ = n
	s3 := &failNth{fakeCredStore: newFakeCredStore(), at: 3, err: boom}
	if _, err := winVaultGet(s3, "a", "b"); !errors.Is(err, boom) {
		t.Fatalf("fallback read: %v", err)
	}
	w := newFakeCredStore()
	w.m["a"] = fakeCred{"x", encodeWinBlob("old")}
	w.writeErr = boom
	if err := winVaultSet(w, "a", "b", "c"); !errors.Is(err, boom) {
		t.Fatalf("preserve write: %v", err)
	}
	w2 := newFakeCredStore()
	w2.writeErr = boom
	if err := winVaultSet(w2, "a", "b", "c"); !errors.Is(err, boom) {
		t.Fatalf("write: %v", err)
	}
}

// failNth fails the nth Read call.
type failNth struct {
	*fakeCredStore
	at, calls int
	err       error
}

func (f *failNth) Read(target string) (*winCredential, error) {
	f.calls++
	if f.calls == f.at {
		return nil, f.err
	}
	return f.fakeCredStore.Read(target)
}
