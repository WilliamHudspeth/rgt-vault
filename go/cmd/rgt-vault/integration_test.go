package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegration_SetGetListRevoke drives the CLI against the real
// internal/server router (the handler `serve` uses).
func TestIntegration_SetGetListRevoke(t *testing.T) {
	isolateEnv(t)
	tokenPath := filepath.Join(t.TempDir(), "server.token")
	h, _, err := newServeHandler(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	raw, _ := os.ReadFile(tokenPath)
	token := strings.TrimSpace(string(raw))
	cli := func(stdin string, args ...string) (int, string, string) {
		return runCLI(t, stdin, append([]string{"--host", srv.URL, "--token", token}, args...)...)
	}

	// set
	if code, out, stderr := cli("s3cr3t-value\n", "set", "api-key", "--namespace", "prod", "--agent", "bot", "--purpose", "ci"); code != 0 || out != "Secret stored.\n" {
		t.Fatalf("set: exit %d out %q err %q", code, out, stderr)
	}

	// get: the single-secret route. B3 (RGT-232) keeps it returning `value`;
	// the pre-B3 stub returns metadata only, in which case get must fail
	// loudly rather than print something wrong.
	t.Run("get", func(t *testing.T) {
		code, out, stderr := cli("", "get", "api-key", "--namespace", "prod")
		if serverReturnsValue(t, srv.URL, token, "prod", "api-key") {
			if code != 0 || out != "s3cr3t-value\n" {
				t.Fatalf("get: exit %d out %q err %q", code, out, stderr)
			}
			return
		}
		if code != 1 || !strings.Contains(stderr, "did not return a secret value") {
			t.Fatalf("get on metadata-only server: exit %d err %q", code, stderr)
		}
		t.Log("server GET one is metadata-only (pre-B3); asserted the explicit error path")
	})

	// list: names only
	code, out, stderr := cli("", "list", "--namespace", "prod")
	if code != 0 || !strings.HasPrefix(out, "api-key\t") || strings.Contains(out, "s3cr3t-value") {
		t.Fatalf("list: exit %d out %q err %q", code, out, stderr)
	}

	// revoke, then the secret is gone
	if code, out, stderr := cli("", "revoke", "api-key", "--namespace", "prod"); code != 0 || out != "Secret revoked.\n" {
		t.Fatalf("revoke: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, _ := cli("", "list", "--namespace", "prod"); code != 0 || strings.Contains(out, "api-key") {
		t.Fatalf("list after revoke: exit %d out %q", code, out)
	}
	if code, _, stderr := cli("", "get", "api-key", "--namespace", "prod"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Fatalf("get after revoke: exit %d err %q", code, stderr)
	}

	// audit chain over the real router verifies
	if code, out, stderr := cli("", "verify-audit"); code != 0 || out != "OK\n" {
		t.Fatalf("verify-audit: exit %d out %q err %q", code, out, stderr)
	}
}

func serverReturnsValue(t *testing.T, base, token, ns, name string) bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/secrets/"+ns+"/"+name, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	_, ok := m["value"]
	return ok
}
