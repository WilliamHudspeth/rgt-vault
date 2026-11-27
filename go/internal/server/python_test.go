package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"rgt-vault-server/internal/providers/providerstest"
)

// TestPythonServerParity: a vault created by the REAL Python VaultManager
// is served by Go; Go's answers for list / use / simulate / capabilities
// (and the fingerprint) equal what Python's FastAPI app answered on the same
// files. Then Go-served writes (set, use, revoke-free reads, a DEK rotation)
// leave a chain that Python verifies, and Python reads the Go-written secret.
//
//	python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
//	RGT_VAULT_PYTHON=$PWD/.venv/bin/python go test ./internal/server -run Python
func TestPythonServerParity(t *testing.T) {
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault[server] installed to run the Python parity check")
	}
	script, err := filepath.Abs("testdata/pyserver.py")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, "vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	masterPath := writeFile(t, filepath.Join(dir, "master.bin"), string(master))
	policyPath := writeFile(t, filepath.Join(dir, "policy.yaml"), testPolicy)
	tokenPath := filepath.Join(dir, "agent.token")
	agentStore, _ := newToken(t, tokenPath)

	runPy := func(args ...string) map[string]any {
		t.Helper()
		cmd := exec.Command(py, append([]string{script}, args...)...)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("python %v: %v", args[0], err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("python output: %v\n%s", err, out)
		}
		return m
	}
	pyOut := runPy("create", vaultDir, masterPath, tokenPath, policyPath)
	if pyOut["chain"] != true {
		t.Fatalf("python chain: %v", pyOut)
	}

	stack, err := OpenStack(context.Background(), StackOptions{
		DBPath: filepath.Join(vaultDir, "vault.db"), PolicyFile: policyPath,
		MasterProvider: providerstest.File{Path: masterPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{Vault: stack.Vault, AgentTokens: agentStore, Actions: stack.Actions, Capabilities: stack.Capabilities})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := agentStore.Read()
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, stack: stack, h: h, agentTok: tok}

	same := func(what string, goV, pyV any) {
		t.Helper()
		// Round-trip Go's value through JSON so both sides have the same types.
		raw, _ := json.Marshal(goV)
		var norm any
		_ = json.Unmarshal(raw, &norm)
		if !reflect.DeepEqual(norm, pyV) {
			t.Errorf("%s differs:\n go: %v\n py: %v", what, norm, pyV)
		}
	}
	same("list", e.mustOK("GET", "/v1/secrets?namespace=parity&agent=bot", nil), pyOut["list"])
	code, _ := e.agent("GET", "/v1/secrets?namespace=parity&agent=intruder", nil)
	same("list denied status", code, pyOut["list_denied"])
	same("use", e.mustOK("POST", "/v1/secrets/parity/alpha/use", map[string]any{"action": "echo", "agent": "bot", "purpose": "parity"}), pyOut["use"])
	code, _ = e.agent("POST", "/v1/secrets/parity/missing/use", map[string]any{"action": "echo", "agent": "bot", "purpose": "parity"})
	same("use missing status", code, pyOut["use_missing"])
	same("simulate", e.mustOK("POST", "/v1/policy/simulate", map[string]any{"agent": "intruder", "namespace": "parity"}), pyOut["simulate"])
	same("capabilities", e.mustOK("GET", "/v1/capabilities", nil), pyOut["capabilities"])
	same("fingerprint", e.mustOK("GET", "/v1/secrets/parity/beta", nil)["fingerprint"], pyOut["fingerprint_beta"])

	// Go-served writes on Python's vault.
	const goValue = "written-through-go-server"
	e.set("parity", "go-written", goValue, nil)
	e.mustOK("POST", "/v1/secrets/parity/go-written/use", map[string]any{"action": "echo", "agent": "bot", "purpose": "go"})
	e.mustOK("POST", "/v1/rotate", map[string]any{"target": "dek"})
	if m := e.mustOK("POST", "/v1/audit/verify", nil); m["ok"] != true {
		t.Fatal("Go does not verify the mixed chain")
	}
	epoch := stack.Vault.KeyEpoch()
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}

	v := runPy("verify", vaultDir, masterPath, policyPath)
	sum := sha256.Sum256([]byte(goValue))
	if v["chain"] != true || v["chain_after_reads"] != true {
		t.Errorf("python does not verify the chain after Go-served writes: %v", v)
	}
	if v["go_written_sha256"] != hex.EncodeToString(sum[:]) || v["beta"] != "beta-v2-ünï" {
		t.Errorf("python reads: %v", v)
	}
	if fmt.Sprint(v["names"]) != "[alpha beta go-written]" || int64(v["key_epoch"].(float64)) != epoch {
		t.Errorf("python view: %v (go epoch %d)", v, epoch)
	}
}
