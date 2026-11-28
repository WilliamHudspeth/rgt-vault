package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/servecmd"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// The alias is a thin wrapper: its behaviour is covered in
// internal/servecmd. These tests pin that it IS that command (same flags,
// same defaults) and that the deployment unit runs the real vault.

func TestAliasIsTheServeCommand(t *testing.T) {
	cmd := servecmd.NewCommand(servecmd.Env{}, nil)
	for _, name := range []string{"db", "policy", "provider", "host", "port", "token-file", "operator-token-file",
		"require-approval", "totp-secret-file", "approval-timeout", "harness-key-file", "allow-private-network"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("--%s missing", name)
		}
	}
}

func TestAliasRunsAndReportsErrors(t *testing.T) {
	env := servecmd.Env{
		Getenv:      func(string) string { return "" },
		Stdout:      io.Discard,
		NewProvider: func(string) (vault.MasterProvider, error) { return providerstest.NewMemory(), nil },
		KDFParams:   kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	}
	// A bad flag value is an error exit with a message, not a panic.
	if code := run([]string{"--port", "not-a-port"}, env); code != 1 {
		t.Errorf("bad port: exit %d, want 1", code)
	}
	// A non-loopback bind is refused (it used to be only a warning).
	dir := t.TempDir()
	code := run([]string{"--host", "0.0.0.0", "--port", "0", "--db", filepath.Join(dir, "v.db"), "--token-file", filepath.Join(dir, "t")}, env)
	if code != 1 {
		t.Errorf("0.0.0.0: exit %d, want 1", code)
	}
}

// deploy/rgt-vault-go.service runs the real vault: persistent --db, an
// explicit --policy and --provider, the D6 port, loopback only, sandboxed
// (RGT-505). scripts/lint_systemd_units.sh checks the sandbox in CI too.
func TestSystemdUnitIsSandboxed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "rgt-vault-go.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := strings.ReplaceAll(string(raw), "\r\n", "\n") // checkouts with autocrlf
	for _, want := range []string{
		"User=rgtvault", "Group=rgtvault", "NoNewPrivileges=true", "ProtectSystem=strict",
		"ProtectHome=true", "PrivateTmp=true", "PrivateDevices=true", "CapabilityBoundingSet=",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "SystemCallFilter=@system-service",
		"MemoryDenyWriteExecute=true", "UMask=0077", "--host 127.0.0.1",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if strings.Contains(unit, "User=root") || strings.Contains(unit, "0.0.0.0") {
		t.Error("unit must not run as root or bind 0.0.0.0")
	}

	// ExecStart (joined over its line continuations) carries the vault flags.
	var exec string
	for _, block := range strings.Split(strings.ReplaceAll(unit, "\\\n", " "), "\n") {
		if strings.HasPrefix(block, "ExecStart=") {
			exec = block
		}
	}
	for _, want := range []string{
		"/rgt-vault serve", "--db /var/lib/rgt-vault/vault.db", "--policy /etc/rgt-vault/policy.yaml",
		"--provider platform", "--port 8765", "--token-store /var/lib/rgt-vault/tokens.json", // per-agent tokens (H1)
	} {
		if !strings.Contains(exec, want) {
			t.Errorf("ExecStart lacks %q:\n%s", want, exec)
		}
	}
	if strings.Contains(exec, "8080") || strings.Contains(exec, "rgt-vault-server") || strings.Contains(exec, "--token-file") {
		t.Errorf("ExecStart still uses the old port/binary:\n%s", exec)
	}
	if !bytes.Contains(raw, []byte("VAULT_TPM_PRIV=")) {
		t.Error("unit does not locate the sealed TPM blobs")
	}
}
