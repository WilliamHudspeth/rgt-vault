package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCLIEndToEnd builds the real Go CLI (go/cmd/rgt-vault) and drives it
// against server.New on a real vault: set, get (D5 route), list, fingerprint
// (RGT-502: it now works and never fetches plaintext), simulate, rotate,
// audit, verify-audit and revoke.
func TestCLIEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	bin := filepath.Join(t.TempDir(), "rgt-vault")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command(goBin, "build", "-o", bin, "../../cmd/rgt-vault")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	e := newEnv(t, envOpts{})
	srv := httptest.NewServer(e.h)
	defer srv.Close()

	home := t.TempDir()
	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command(bin, append([]string{"--host", srv.URL, "--token", e.agentTok}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		// Isolate from the developer's real config and token.
		cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "RGT_VAULT_TOKEN=")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return out.String(), errb.String(), code
	}
	mustRun := func(stdin string, args ...string) string {
		t.Helper()
		out, errOut, code := run(stdin, args...)
		if code != 0 {
			t.Fatalf("rgt-vault %v: exit %d\nstdout %q\nstderr %q", args, code, out, errOut)
		}
		return out
	}

	const value = "cli-e2e-SENTINEL"
	if out := mustRun(value+"\n", "set", "demo_key", "--namespace", "w1", "--agent", "bot", "--purpose", "ci"); out != "Secret stored.\n" {
		t.Fatalf("set: %q", out)
	}
	if out := mustRun("", "get", "demo_key", "--namespace", "w1"); out != value+"\n" {
		t.Fatalf("get: %q", out)
	}
	if out := mustRun("", "list", "--namespace", "w1"); !strings.HasPrefix(out, "demo_key\t") || strings.Contains(out, value) {
		t.Fatalf("list: %q", out)
	}

	// RGT-502: fingerprint works and matches the vault's own fingerprint.
	want, err := e.stack.Vault.Fingerprint(context.Background(), "w1", "demo_key", 0)
	if err != nil {
		t.Fatal(err)
	}
	readsBefore := countAction(e.auditRows(""), "SECRET_READ")
	if out := mustRun("", "fingerprint", "demo_key", "--namespace", "w1"); out != want+"\n" {
		t.Fatalf("fingerprint: %q, want %q", out, want)
	}
	if countAction(e.auditRows(""), "SECRET_READ") != readsBefore {
		t.Error("fingerprint fetched the plaintext (SECRET_READ written)")
	}
	if _, errOut, code := run("", "fingerprint", "nope", "--namespace", "w1"); code == 0 || !strings.Contains(errOut, "404") {
		t.Errorf("fingerprint of a missing secret: exit %d %q", code, errOut)
	}

	if out := mustRun("", "simulate", "--agent", "intruder", "--namespace", "w1"); !strings.Contains(out, `"allowed":false`) {
		t.Errorf("simulate: %q", out)
	}
	mustRun("", "rotate", "--target", "dek")
	if out := mustRun("", "fingerprint", "demo_key", "--namespace", "w1"); out == want+"\n" {
		t.Error("fingerprint unchanged after DEK rotation")
	}
	if out := mustRun("", "get", "demo_key", "--namespace", "w1"); out != value+"\n" {
		t.Fatalf("get after rotation: %q", out)
	}
	if out := mustRun("", "audit", "--limit", "5"); !strings.Contains(out, `"entries"`) || strings.Contains(out, e.agentTok) {
		t.Errorf("audit: %q", out)
	}
	if out := mustRun("", "verify-audit"); out != "OK\n" {
		t.Errorf("verify-audit: %q", out)
	}
	if out := mustRun("", "revoke", "demo_key", "--namespace", "w1"); out != "Secret revoked.\n" {
		t.Errorf("revoke: %q", out)
	}
	if _, errOut, code := run("", "get", "demo_key", "--namespace", "w1"); code != 1 || !strings.Contains(errOut, "not found") {
		t.Errorf("get after revoke: exit %d %q", code, errOut)
	}
}

func countAction(rows []map[string]any, action string) int {
	n := 0
	for _, r := range rows {
		if r["action"] == action {
			n++
		}
	}
	return n
}
