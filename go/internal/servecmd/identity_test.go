package servecmd

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"rgt-vault-server/internal/auth"
)

// `serve` defaults to the per-agent token store (batch H1).
func TestServeOnTokenStore(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "tokens.json")
	e := map[string]string{"RGT_VAULT_DB": filepath.Join(dir, "vault", "vault.db"), "RGT_VAULT_TOKEN_STORE": store}

	// No store / empty store: refuse to start, pointing at init and mint.
	err := execute(context.Background(), []string{"--port", "0"}, Env{Getenv: env(e)})
	if err == nil || !strings.Contains(err.Error(), "no tokens") || !strings.Contains(err.Error(), "token mint") {
		t.Fatalf("empty store: %v", err)
	}
	st := auth.OpenStore(store)
	tok, _, err := st.Mint(auth.MintOptions{Agent: "bot", Scopes: []auth.Scope{auth.ScopeAgent}})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(store, 0o644)
	}
	addr, _, out, logs, stop := startServer(t, []string{"--port", "0", "--require-approval"}, e)
	defer stop()
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(store); fi.Mode().Perm() != 0o600 {
			t.Errorf("store not tightened: %o", fi.Mode().Perm())
		}
	}
	if !strings.Contains(out.String(), "per-agent tokens from "+store) || strings.Contains(out.String(), "LEGACY") {
		t.Errorf("banner:\n%s", out.String())
	}
	if !strings.Contains(logs.String(), "no live operator-scoped token") || strings.Contains(logs.String(), "DEPRECATED") {
		t.Errorf("logs:\n%s", logs.String())
	}
	if strings.Contains(out.String()+logs.String(), tok) {
		t.Fatal("a token was printed")
	}
	get := func(path, token string) int {
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get("/v1/actions", tok) != 200 || get("/v1/audit", tok) != 403 || get("/v1/actions", "nope") != 401 {
		t.Error("store-mode auth")
	}
	// Minted while running: usable at once.
	late, _, err := auth.OpenStore(store).Mint(auth.MintOptions{Agent: "aud", Scopes: []auth.Scope{auth.ScopeAudit}})
	if err != nil {
		t.Fatal(err)
	}
	if get("/v1/audit", late) != 200 {
		t.Error("a token minted while serving is not accepted")
	}
}

func TestServeCorruptStoreRefused(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "tokens.json")
	_ = os.WriteFile(store, []byte("{"), 0o600)
	e := map[string]string{"RGT_VAULT_DB": filepath.Join(dir, "v.db"), "RGT_VAULT_TOKEN_STORE": store}
	if err := execute(context.Background(), []string{"--port", "0"}, Env{Getenv: env(e)}); err == nil || !strings.Contains(err.Error(), "token store") {
		t.Errorf("corrupt store: %v", err)
	}
}

// --legacy-shared-token keeps the pre-H1 behaviour and warns at startup.
func TestServeLegacyWarns(t *testing.T) {
	addr, tokenPath, out, logs, stop := startServer(t, []string{"--port", "0"}, map[string]string{})
	defer stop()
	if !strings.Contains(logs.String(), LegacyWarning) || !strings.Contains(out.String(), "LEGACY shared bearer token") {
		t.Errorf("no legacy warning:\nlogs %s\nout %s", logs.String(), out.String())
	}
	raw, _ := os.ReadFile(tokenPath)
	req, _ := http.NewRequest("GET", "http://"+addr+"/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 { // legacy: the shared token reaches everything but /v1/requests
		t.Errorf("legacy audit: %d", resp.StatusCode)
	}
}
