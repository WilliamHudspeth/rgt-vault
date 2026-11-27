package capabilities

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/hooks"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/vault"
)

const pyvaultDir = "../../testdata/pyvault"

type parityToken struct {
	Kind       string         `json:"kind"` // ok | badsig | raw
	Agent      string         `json:"agent,omitempty"`
	Capability string         `json:"capability,omitempty"`
	Version    int            `json:"version,omitempty"`
	Bindings   map[string]any `json:"bindings,omitempty"`
	Raw        string         `json:"raw,omitempty"`
}

type parityCase struct {
	Name       string          `json:"name"`
	Capability string          `json:"capability"`
	Agent      string          `json:"agent"`
	Version    int             `json:"version"`
	Payload    json.RawMessage `json:"payload"`
	Token      parityToken     `json:"token"`
	NoVerifier bool            `json:"no_verifier,omitempty"`
	Frozen     bool            `json:"frozen,omitempty"`
}

type parityResult struct {
	Error string      `json:"error"`
	Rows  [][2]string `json:"rows"`
}

func ok1(agent, capability string, bindings map[string]any) parityToken {
	return parityToken{Kind: "ok", Agent: agent, Capability: capability, Version: 1, Bindings: bindings}
}

var parityCases = []parityCase{
	{Name: "echo", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{"message": "h\u00e9llo <b>&amp;</b> \ud83d\ude00"}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "echo nested", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{"message": {"b": [1, 2.5, null, true], "a": "x"}}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "echo bound", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{"message": "pinned"}`), Token: ok1("agent-1", EchoCapability, map[string]any{"message": "pinned"})},
	{Name: "no verifier", Capability: EchoCapability, Agent: "agent-1", Version: 1, NoVerifier: true,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "frozen", Capability: EchoCapability, Agent: "agent-1", Version: 1, Frozen: true,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "bad signature", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{}`), Token: parityToken{Kind: "badsig", Agent: "agent-1", Capability: EchoCapability, Version: 1}},
	{Name: "malformed", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{}`), Token: parityToken{Kind: "raw", Raw: "abc"}},
	{Name: "agent mismatch", Capability: EchoCapability, Agent: "agent-2", Version: 1,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "capability mismatch", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", UseCapability, nil)},
	{Name: "version mismatch", Capability: EchoCapability, Agent: "agent-1", Version: 2,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "binding mismatch", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{"message": "evil'<script>"}`), Token: ok1("agent-1", EchoCapability, map[string]any{"message": "a"})},
	{Name: "binding missing", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", EchoCapability, map[string]any{"message": "a"})},
	{Name: "unknown capability", Capability: "nope.x", Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{}`), Token: ok1("agent-1", "nope.x", nil)},
	{Name: "version unsupported", Capability: EchoCapability, Agent: "agent-1", Version: 2,
		Payload: json.RawMessage(`{}`), Token: parityToken{Kind: "ok", Agent: "agent-1", Capability: EchoCapability, Version: 2}},
	{Name: "unknown param", Capability: EchoCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{"message": "x", "evil": "<script>", "z'": 1}`), Token: ok1("agent-1", EchoCapability, nil)},
	{Name: "use without secret_name", Capability: UseCapability, Agent: "agent-1", Version: 1,
		Payload: json.RawMessage(`{"action": "x"}`), Token: ok1("agent-1", UseCapability, nil)},
}

// pyErrClass names the Python exception class Go's error corresponds to.
func pyErrClass(err error) string {
	var pc interface{ PyClass() string }
	switch {
	case err == nil:
		return ""
	case errors.Is(err, captoken.ErrBinding):
		return "TokenBindingError"
	case errors.Is(err, vault.ErrCapabilityFailed) && errors.As(err, &pc):
		return pc.PyClass()
	case errors.Is(err, vault.ErrCapabilityNotFound):
		return "CapabilityNotFoundError"
	case errors.Is(err, vault.ErrCapabilityVersion):
		return "CapabilityVersionError"
	case errors.Is(err, vault.ErrValidation):
		return "ValidationError"
	case errors.Is(err, vault.ErrPolicyDenied):
		return "PolicyDeniedError"
	case errors.Is(err, vault.ErrPermission):
		return "PermissionError"
	}
	return "error: " + err.Error()
}

func copyFixture(t *testing.T, fixture string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), fixture)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"vault.db", "keychain.json", "master.bin", "policy.yaml"} {
		b, err := os.ReadFile(filepath.Join(pyvaultDir, fixture, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runGoParity runs the cases on a Go vault over dir.
func runGoParity(t *testing.T, dir string, key []byte) []parityResult {
	t.Helper()
	ctx := context.Background()
	policy, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ver, err := captoken.NewHMACTokenVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	rev := slices.Clone(key)
	slices.Reverse(rev)
	other, _ := captoken.NewHMACTokenVerifier(rev)
	hook := hooks.NewOffHook()
	reg := NewDefault(nil)
	var out []parityResult
	for _, c := range parityCases {
		cfg := vault.Config{
			DBPath: filepath.Join(dir, "vault.db"), Provider: providerstest.File{Path: filepath.Join(dir, "master.bin")},
			PolicyYAML: string(policy), Hook: hook, Capabilities: reg, TokenVerifier: ver,
		}
		if c.NoVerifier {
			cfg.TokenVerifier = nil
		}
		v, err := vault.Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var tok string
		switch c.Token.Kind {
		case "ok":
			tok, err = ver.Sign(c.Token.Agent, c.Token.Capability, c.Token.Version, c.Token.Bindings, 60)
		case "badsig":
			tok, err = other.Sign(c.Token.Agent, c.Token.Capability, c.Token.Version, c.Token.Bindings, 60)
		default:
			tok = c.Token.Raw
		}
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(c.Payload))
		dec.UseNumber()
		var payload map[string]any
		if err := dec.Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if c.Frozen {
			hook.Freeze("test")
		}
		before := auditCount(t, v)
		_, xerr := v.ExecuteCapability(ctx, vault.CapabilityRequest{
			Capability: c.Capability, Version: c.Version, Agent: c.Agent, Token: tok, Payload: payload,
		})
		hook.Unfreeze("test")
		rows, err := v.Store().IterAuditLog(ctx)
		if err != nil {
			t.Fatal(err)
		}
		res := parityResult{Error: pyErrClass(xerr), Rows: [][2]string{}}
		for _, r := range rows[before:] {
			res.Rows = append(res.Rows, [2]string{r.Action, r.Details.String})
		}
		out = append(out, res)
		ok, err := v.VerifyAuditChain(ctx)
		if !ok || err != nil {
			t.Fatalf("%s: audit chain broken: %v", c.Name, err)
		}
		_ = v.Close()
	}
	return out
}

func auditCount(t *testing.T, v *vault.Vault) int {
	t.Helper()
	rows, err := v.Store().IterAuditLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// TestPythonExecuteCapabilityParity runs the same execute_capability cases
// through the REAL Python VaultManager and through Go, each on its own copy
// of the G0 "small" fixture vault, and requires identical exception classes
// and identical audit rows (action and details strings).
//
//	RGT_VAULT_PYTHON=$PWD/.venv/bin/python go test ./internal/capabilities -run Python
func TestPythonExecuteCapabilityParity(t *testing.T) {
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault installed to run the Python parity check")
	}
	key, _ := hex.DecodeString("8caf46fc16783d0da2e20c6114e68218496cbe91b2460c87c5fb1f3c455e3efa")
	script, err := filepath.Abs("testdata/pyexec.py")
	if err != nil {
		t.Fatal(err)
	}
	pyDir := copyFixture(t, "small")
	casesPath := filepath.Join(t.TempDir(), "cases.json")
	b, _ := json.Marshal(parityCases)
	if err := os.WriteFile(casesPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, script, pyDir, filepath.Join(pyDir, "master.bin"), hex.EncodeToString(key), casesPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	outJSON, err := cmd.Output()
	if err != nil {
		t.Fatalf("python: %v\n%s", err, stderr.String())
	}
	var pyRes []parityResult
	if err := json.Unmarshal(outJSON, &pyRes); err != nil {
		t.Fatalf("python output: %v\n%s", err, outJSON)
	}
	goRes := runGoParity(t, copyFixture(t, "small"), key)
	if len(pyRes) != len(goRes) {
		t.Fatalf("python ran %d cases, go %d", len(pyRes), len(goRes))
	}
	for i, c := range parityCases {
		if !reflect.DeepEqual(pyRes[i], goRes[i]) {
			t.Errorf("%s:\n python %q\n     go %q", c.Name, pyRes[i], goRes[i])
		} else {
			t.Logf("%s: %s %d row(s) identical", c.Name, pyRes[i].Error, len(pyRes[i].Rows))
		}
	}
}
