package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression from the security review of PR #53 (HIGH-1): an MCP or agent
// process with no explicit token must not silently get the operator token.
func TestReviewTokenFallbackIsOperator(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("RGT_VAULT_TOKEN", "")
	t.Setenv("RGT_VAULT_TOKEN_FILE", "")
	dir := filepath.Join(home, ".config", "rgt-vault")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "operator.token"), []byte("OPERATOR-TOKEN\n"), 0o600)
	for name, src := range map[string]tokenSources{"mcp": explicitOnly, "agent command": agentCmd} {
		if got := resolveToken("", src); got == "OPERATOR-TOKEN" {
			t.Errorf("%s: resolveToken(\"\") falls back to the full-scope operator token: %q", name, got)
		}
	}
}
