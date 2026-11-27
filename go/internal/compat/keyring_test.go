package compat

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestKeyringInPlaceMigration is the whole migration story with nothing
// faked: a REAL vault created by the Python line, whose master secret lives
// in the OS keyring (Secret Service on Linux), is taken over IN PLACE by the
// released Go binary (same vault.db, keychain.json and keyring entry), and
// handed back to Python:
//
//  1. Python (real keyring + VaultManager) creates the vault, writes secrets
//     (versions, unicode, a revoke) and rotates the DEK;
//  2. rgt-vault migrate check says READY; `get --offline` returns Python's
//     latest unicode value;
//  3. rgt-vault serve + the HTTP CLI write a secret and rotate the DEK AND
//     the master key (the new master secret is written to the keyring by Go);
//  4. rgt-vault export and verify-audit work on the same files;
//  5. Python re-opens the vault with the keyring entry Go wrote, reads every
//     version, verifies the chain and writes; Go reads Python's write.
//
// It writes to the REAL keyring entry rgt_vault/master_key, so it only runs
// with RGT_COMPAT_KEYRING=1 (the compat CI job on a throw-away runner) and
// refuses if that entry already exists.
func TestKeyringInPlaceMigration(t *testing.T) {
	if os.Getenv("RGT_COMPAT_KEYRING") != "1" {
		t.Skip("set RGT_COMPAT_KEYRING=1 (and RGT_VAULT_PYTHON) to run against the REAL OS keyring; it uses the rgt_vault/master_key entry")
	}
	py := python(t)
	probe := runPython(t, py, nil, "keyring-probe")
	t.Logf("python keyring backend: %v", probe)
	if probe["error"] != nil {
		t.Fatalf("no usable Python keyring backend: %v", probe)
	}
	if probe["present"] == true {
		t.Fatal("refusing to run: rgt_vault/master_key already exists in the OS keyring (this test would rotate it)")
	}
	t.Cleanup(func() { runPython(t, py, nil, "keyring-cleanup") })

	dir := t.TempDir()
	vdir := filepath.Join(dir, "vault")
	if err := os.MkdirAll(vdir, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte(allowAllPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(vdir, "vault.db")

	// 1. Python creates the vault.
	created := runPython(t, py, nil, "create-keyring", vdir, policy)
	if created["chain"] != true {
		t.Fatalf("python create: %v", created)
	}
	var expect []map[string]any
	for _, x := range created["expect"].([]any) {
		expect = append(expect, x.(map[string]any))
	}

	// 2. Read-only check, then an offline read through the keyring.
	out, errOut, code := runBin(t, nil, "migrate", "check", "--db", db)
	if code != 0 || !strings.Contains(out, "verdict:      READY") || !strings.Contains(out, "vault_id:     "+created["vault_id"].(string)) {
		t.Fatalf("migrate check: exit %d\n%s%s", code, out, errOut)
	}
	get := func(ns, name string) string {
		t.Helper()
		out, errOut, code := runBin(t, nil, "--db", db, "--policy", policy, "get", name, "--namespace", ns,
			"--agent", "ci-bot", "--purpose", "compat", "--offline")
		if code != 0 {
			t.Fatalf("get %s/%s: exit %d: %s", ns, name, code, errOut)
		}
		return strings.TrimSuffix(out, "\n")
	}
	if got := get("prod", "api"); got != "api-v2-ünï🔐" {
		t.Fatalf("Go reads Python's latest api as %q", got)
	}

	// 3. serve + HTTP CLI: write, rotate DEK, rotate master.
	port := freePort(t)
	srv := startServe(t, dir, db, policy, port)
	host := "http://127.0.0.1:" + strconv.Itoa(port)
	tok, err := os.ReadFile(filepath.Join(dir, "agent.token"))
	if err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) (string, string, int) {
		return runBin(t, []string{"RGT_VAULT_TOKEN=" + strings.TrimSpace(string(tok))}, append([]string{"--host", host}, args...)...)
	}
	valFile := filepath.Join(dir, "value.txt")
	if err := os.WriteFile(valFile, []byte("from-go-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := cli("set", "go-written", "--namespace", "default", "--value-file", valFile); code != 0 {
		t.Fatalf("set: exit %d %s", code, errOut)
	}
	for _, target := range []string{"dek", "master"} {
		if _, errOut, code := cli("rotate", "--target", target); code != 0 {
			t.Fatalf("rotate %s: exit %d %s", target, code, errOut)
		}
	}
	if out, errOut, code := cli("verify-audit"); code != 0 || strings.TrimSpace(out) != "OK" {
		t.Fatalf("verify-audit over HTTP: exit %d %q %s", code, out, errOut)
	}
	srv.stop(t)

	// 4. Offline export and verify on the same files.
	exp := filepath.Join(dir, "export.b64")
	if _, errOut, code := runBin(t, nil, "--db", db, "--policy", policy, "export", "--out", exp); code != 0 {
		t.Fatalf("export: exit %d %s", code, errOut)
	}
	if st, err := os.Stat(exp); err != nil || st.Size() == 0 {
		t.Fatalf("export file: %v", err)
	}
	if out, _, code := runBin(t, nil, "verify-audit", "--db", db); code != 0 || strings.TrimSpace(out) != "OK" {
		t.Fatalf("offline verify-audit: exit %d %q", code, out)
	}
	if got := get("default", "go-written"); got != "from-go-binary" {
		t.Fatalf("go-written reads %q", got)
	}
	status, _, _ := runBin(t, nil, "status", "--db", db)
	m := regexp.MustCompile(`key_epoch:\s+(\d+)`).FindStringSubmatch(status)
	if m == nil {
		t.Fatalf("no key_epoch in status:\n%s", status)
	}
	goEpoch, _ := strconv.ParseFloat(m[1], 64)
	if goEpoch != created["key_epoch"].(float64)+2 {
		t.Fatalf("epoch after two Go rotations = %v, Python created at %v", goEpoch, created["key_epoch"])
	}

	// 5. Python takes the vault back, with the master key Go wrote to the keyring.
	expect = append(expect, map[string]any{"namespace": "default", "name": "go-written", "version": float64(0), "want": sha([]byte("from-go-binary"))})
	b, _ := json.Marshal(expect)
	expPath := filepath.Join(dir, "expect.json")
	if err := os.WriteFile(expPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	r := runPython(t, py, nil, "open-keyring", vdir, policy, expPath)
	var want []string
	for _, e := range expect {
		want = append(want, e["want"].(string))
	}
	if !reflect.DeepEqual(strs(r["reads"]), want) {
		t.Fatalf("Python reads after the Go migration:\n got %v\nwant %v", strs(r["reads"]), want)
	}
	if r["chain_before"] != true || r["chain_final"] != true || r["key_epoch"] != goEpoch {
		t.Fatalf("Python report: %v", r)
	}
	if got := get("default", "python-again"); got != "py2" {
		t.Fatalf("Go reads Python's post-migration write as %q", got)
	}
	if out, _, code := runBin(t, nil, "verify-audit", "--db", db); code != 0 || strings.TrimSpace(out) != "OK" {
		t.Fatalf("final offline verify-audit: exit %d %q", code, out)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type serveProc struct {
	cmd  *exec.Cmd
	done chan error
}

// startServe runs `rgt-vault serve` (keyring provider) and waits for /healthz.
func startServe(t *testing.T, dir, db, policy string, port int) *serveProc {
	t.Helper()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary(t), "--db", db, "--policy", policy, "serve",
		"--port", strconv.Itoa(port), "--token-file", filepath.Join(dir, "agent.token"))
	cmd.Env = append(cleanEnv(), "HOME="+home, "USERPROFILE="+home)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &serveProc{cmd: cmd, done: make(chan error, 1)}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() { // drain so the server never blocks on stdout
			t.Log("serve: " + sc.Text())
		}
		p.done <- cmd.Wait()
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			t.Fatalf("serve exited early: %v", err)
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/healthz", port), nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return p
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("serve did not become healthy")
	return nil
}

// stop shuts the server down (SIGTERM; kill where unsupported) and waits.
func (p *serveProc) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
