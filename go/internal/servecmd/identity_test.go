package servecmd

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
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

// --legacy-shared-token keeps the pre-H1 identity model and warns at
// startup, but refuses the lease route, rotation and the audit log unless
// --legacy-allow-privileged-routes is also given (review MEDIUM-3).
func TestServeLegacyWarns(t *testing.T) {
	for _, privileged := range []bool{false, true} {
		args := []string{"--port", "0"}
		if privileged {
			args = append(args, "--legacy-allow-privileged-routes")
		}
		addr, tokenPath, out, logs, stop := startServer(t, args, map[string]string{})
		if !strings.Contains(logs.String(), LegacyWarning) || !strings.Contains(out.String(), "LEGACY shared bearer token") {
			t.Errorf("no legacy warning:\nlogs %s\nout %s", logs.String(), out.String())
		}
		if privileged != strings.Contains(logs.String(), LegacyPrivilegedWarning) {
			t.Errorf("privileged=%v: logs %s", privileged, logs.String())
		}
		raw, _ := os.ReadFile(tokenPath)
		tok := strings.TrimSpace(string(raw))
		do := func(method, path, body string) (int, string) {
			req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		for _, c := range []struct{ method, path, body string }{
			{"GET", "/v1/audit", ""}, {"POST", "/v1/audit/verify", ""},
			{"POST", "/v1/rotate", `{"target":"dek"}`}, {"POST", "/v1/secrets/default/k/lease", `{"agent":"a"}`},
		} {
			code, body := do(c.method, c.path, c.body)
			refused := code == 403 && strings.Contains(body, "legacy shared-token mode")
			if refused != !privileged {
				t.Errorf("legacy privileged=%v %s %s: %d %s", privileged, c.method, c.path, code, body)
			}
		}
		if code, _ := do("GET", "/v1/actions", ""); code != 200 {
			t.Errorf("legacy agent route: %d", code)
		}
		stop()
	}
	if _, err := parse(flagsOf(func(f *Flags) { f.LegacyPrivileged = true }), env(nil)); err == nil {
		t.Error("--legacy-allow-privileged-routes without --legacy-shared-token accepted")
	}
}
