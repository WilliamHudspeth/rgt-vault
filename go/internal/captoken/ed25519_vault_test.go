package captoken_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/vault"
)

// TestEd25519ThroughVault: the vault runs a capability on a v3 token from a
// verifier that holds only the public key, refuses a v2 HMAC token there,
// and records the refusal class as Python's token error class.
func TestEd25519ThroughVault(t *testing.T) {
	seed := sha256.Sum256([]byte("vault e2e"))
	signer, err := captoken.NewEd25519Signer(ed25519.NewKeyFromSeed(seed[:]), "")
	if err != nil {
		t.Fatal(err)
	}
	ver, err := captoken.NewEd25519Verifier(map[string]ed25519.PublicKey{signer.KeyID(): signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(context.Background(), vault.Config{
		DBPath:        filepath.Join(t.TempDir(), "vault.db"),
		Provider:      providerstest.NewMemory(),
		PolicyYAML:    "rules:\n  - {effect: allow, agent: '*', namespace: '*', purpose: '*', action: '*'}\n",
		Capabilities:  capabilities.NewDefault(nil),
		TokenVerifier: captoken.NewReplayGuard(ver),
		KDFParams:     kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	tok, err := signer.Sign("agent-1", "secrets.echo", 1, nil, 60)
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.ExecuteCapability(context.Background(), vault.CapabilityRequest{
		Capability: "secrets.echo", Agent: "agent-1", Token: tok, Payload: map[string]any{"message": "hi"},
	})
	if err != nil || res == nil {
		t.Fatalf("v3 execute: %v %v", res, err)
	}
	h, _ := captoken.NewHMACTokenVerifier([]byte("0123456789abcdef0123456789abcdef"))
	v2, _ := h.Sign("agent-1", "secrets.echo", 1, nil, 60)
	_, err = v.ExecuteCapability(context.Background(), vault.CapabilityRequest{Capability: "secrets.echo", Agent: "agent-1", Token: v2})
	if !errors.Is(err, vault.ErrPolicyDenied) {
		t.Fatalf("v2 to Ed25519 vault: %v", err)
	}
	rows, _ := v.AuditLog(context.Background(), 100)
	found := false
	for _, r := range rows {
		if r.Action == "CAPABILITY_DENIED" && r.Details.Valid && strings.Contains(r.Details.String, `"reason": "token: TokenVersionError"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("no CAPABILITY_DENIED token: TokenVersionError row")
	}
}
