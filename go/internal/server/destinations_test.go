package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/actions"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/tlstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// RGT-523 end-to-end tests through OpenStack: they fail if the wiring in
// stack.go (destination policy, audit, notifier) or in the handlers (secret
// identity, 403 mapping) is dropped, e.g. by a rebase.

type destEvents struct {
	mu sync.Mutex
	ev []approval.Event
}

func (d *destEvents) Notify(_ context.Context, e approval.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ev = append(d.ev, e)
}

func (d *destEvents) count(kind approval.EventKind) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, e := range d.ev {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

type destStackEnv struct {
	*testEnv
	aPort, bPort   string
	aConns, bConns atomic.Int64
	bAuth          atomic.Int64
	events         *destEvents
	masterPath     string
	policyPath     string
}

const destPolicy = `rules:
  - {effect: allow, agent: "*", namespace: "*", purpose: "*", action: "*", allowed_hosts: ["a.test:PORTA", "b.test:PORTB"]}
  - {effect: deny, agent: intruder, action: "*"}
destinations:
  github/GITHUB_TOKEN: ["a.test:PORTA"]
`

func newDestStackEnv(t *testing.T, mode actions.DestinationMode) *destStackEnv {
	t.Helper()
	ca := tlstest.NewCA(t)
	files := ca.Issue(t, "", tlstest.Leaf{Name: "dest", DNSNames: []string{"a.test", "b.test"}})
	cert, err := tls.LoadX509KeyPair(files.Cert, files.Key)
	if err != nil {
		t.Fatal(err)
	}
	d := &destStackEnv{events: &destEvents{}}
	start := func(h http.Handler, conns *atomic.Int64) string {
		s := httptest.NewUnstartedServer(h)
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				conns.Add(1)
			}
		}
		s.StartTLS()
		t.Cleanup(s.Close)
		_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
		return port
	}
	d.bPort = start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			d.bAuth.Add(1)
		}
		_, _ = w.Write([]byte("collected"))
	}), &d.bConns)
	d.aPort = start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r-off" {
			http.Redirect(w, r, "https://b.test:"+d.bPort+"/ok", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("fine"))
	}), &d.aConns)

	dir := t.TempDir()
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	d.masterPath = writeFile(t, filepath.Join(dir, "master.bin"), string(master))
	d.policyPath = writeFile(t, filepath.Join(dir, "policy.yaml"),
		strings.NewReplacer("PORTA", d.aPort, "PORTB", d.bPort).Replace(destPolicy))
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	hexKey := hex.EncodeToString(key)
	so := StackOptions{
		DBPath:              filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:          d.policyPath,
		MasterProvider:      providerstest.File{Path: d.masterPath},
		HarnessKeyFile:      writeFile(t, filepath.Join(dir, "harness.key"), hexKey+"\n"),
		Notifier:            d.events,
		AllowPrivateNetwork: true,
		Destinations:        mode,
		KDFParams:           testKDF,
		actionsOverride: func(c *actions.Config) {
			c.RootCAs = ca.Pool()
			c.Resolver = staticResolver{}
		},
	}
	stack, err := OpenStack(context.Background(), so)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	agentStore, agentTok := newToken(t, filepath.Join(dir, "agent.token"))
	h, err := New(Config{Vault: stack.Vault, AgentTokens: agentStore, LegacyPrivilegedRoutes: true,
		Notifier: d.events, Actions: stack.Actions, Capabilities: stack.Capabilities})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := captoken.NewHMACTokenVerifier([]byte(hexKey))
	if err != nil {
		t.Fatal(err)
	}
	d.testEnv = &testEnv{t: t, dir: dir, stack: stack, h: h, agentTok: agentTok, opTok: agentTok, signer: signer}
	raw := make([]byte, 20)
	_, _ = rand.Read(raw)
	d.set("github", "GITHUB_TOKEN", "tok_"+hex.EncodeToString(raw), nil)
	d.set("misc", "OTHER", "tok_"+hex.EncodeToString(raw[:10]), nil)
	return d
}

type staticResolver struct{}

func (staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "a.test", "b.test":
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	return nil, errors.New("no such host")
}

func (d *destStackEnv) use(agent, ns, name, rawURL string) (int, map[string]any) {
	d.t.Helper()
	return d.agent("POST", "/v1/secrets/"+ns+"/"+name+"/use", map[string]any{
		"action": "http_get_with_auth", "agent": agent, "purpose": "ci", "params": map[string]any{"url": rawURL},
	})
}

func (d *destStackEnv) aURL(p string) string { return "https://a.test:" + d.aPort + p }
func (d *destStackEnv) bURL(p string) string { return "https://b.test:" + d.bPort + p }

func (d *destStackEnv) assertBUntouched() {
	d.t.Helper()
	if d.bConns.Load() != 0 || d.bAuth.Load() != 0 {
		d.t.Fatalf("server B: %d connection(s), %d credential(s)", d.bConns.Load(), d.bAuth.Load())
	}
}

// recentActions returns the n newest vault audit actions (HTTP_API request
// rows skipped), oldest first.
func (d *destStackEnv) recentActions(n int) []string {
	var out []string
	for _, r := range d.auditRows("") {
		if a := r["action"].(string); a != "HTTP_API" && len(out) < n {
			out = append([]string{a}, out...)
		}
	}
	return out
}

// lastRow returns the newest row with action.
func (d *destStackEnv) lastRow(action string) map[string]any {
	for _, r := range d.auditRows("") {
		if r["action"] == action {
			return r
		}
	}
	d.t.Fatalf("no %s row", action)
	return nil
}

// Required tests 1 and 8 (use endpoint), 11 (ABAC deny), 7 (no redirects).
func TestStackDestinationsUseEndpoint(t *testing.T) {
	d := newDestStackEnv(t, actions.DestinationsEnforce)
	if code, m := d.use("coder", "github", "GITHUB_TOKEN", d.aURL("/ok")); code != 200 {
		t.Fatalf("listed host: %d %v", code, m)
	}
	code, m := d.use("coder", "github", "GITHUB_TOKEN", d.bURL("/collect?token=x"))
	want := "destination b.test:" + d.bPort + " is not allowed for secret github/GITHUB_TOKEN (HOST_NOT_LISTED)"
	if code != http.StatusForbidden || m["error"] != "DestinationRefusedError" || m["detail"] != want {
		t.Fatalf("refusal: %d %v", code, m)
	}
	d.assertBUntouched()
	if got := strings.Join(d.recentActions(3), ","); got != "LEASE_GRANTED,DESTINATION_REFUSED,LEASE_RETURNED" {
		t.Fatalf("audit order = %s", got)
	}
	row := d.lastRow(vault.DestinationRefusedEvent)
	details, _ := row["details"].(string)
	if row["secret_name"] != "GITHUB_TOKEN" || row["agent_id"] != "coder" ||
		details != "namespace=github action=http_get_with_auth destination=b.test:"+d.bPort+" reason=HOST_NOT_LISTED mode=enforce outcome=refused" {
		t.Fatalf("row = %v", row)
	}
	if n := d.events.count(vault.DestinationRefusedEvent); n != 1 {
		t.Fatalf("security events = %d", n)
	}
	// A secret with no entry: the exact NO_LIST message.
	code, m = d.use("coder", "misc", "OTHER", d.aURL("/ok"))
	if code != http.StatusForbidden || m["detail"] != `no destination is allowed for secret misc/OTHER: add it under "destinations:" in the policy file` {
		t.Fatalf("NO_LIST: %d %v", code, m)
	}
	// ABAC deny comes first: ordinary denial, no DESTINATION_REFUSED row.
	before := countRows(d.auditRows(""), vault.DestinationRefusedEvent)
	code, _ = d.use("intruder", "github", "GITHUB_TOKEN", d.bURL("/"))
	if code != http.StatusForbidden || !hasAction(d.auditRows(""), "POLICY_DENIED") ||
		countRows(d.auditRows(""), vault.DestinationRefusedEvent) != before {
		t.Fatalf("ABAC deny: %d", code)
	}
	// The server follows no redirects: a 302 from A is an error, B untouched.
	if code, _ := d.use("coder", "github", "GITHUB_TOKEN", d.aURL("/r-off")); code == 200 {
		t.Fatal("redirect followed")
	}
	d.assertBUntouched()
	if m := d.mustOK("POST", "/v1/audit/verify", nil); m["ok"] != true {
		t.Fatal("audit chain does not verify")
	}
	if d.stack.DestinationMode != actions.DestinationsEnforce {
		t.Fatal("mode")
	}
}

func countRows(rows []map[string]any, action string) int {
	n := 0
	for _, r := range rows {
		if r["action"] == action {
			n++
		}
	}
	return n
}

// Required test 8 (capability path): secrets.use to B is refused with the
// refusal's own 403, not the generic "capability failed".
func TestStackDestinationsCapabilityPath(t *testing.T) {
	d := newDestStackEnv(t, actions.DestinationsEnforce)
	exec := func(u string) (int, map[string]any) {
		return d.agent("POST", "/v1/capabilities/execute", map[string]any{
			"capability": "secrets.use", "capability_token": d.sign("coder", "secrets.use", 1), "agent_id": "coder",
			"payload": map[string]any{"secret_name": "GITHUB_TOKEN", "namespace": "github", "action": "http_get_with_auth",
				"params": map[string]any{"url": u}},
		})
	}
	if code, m := exec(d.aURL("/ok")); code != 200 {
		t.Fatalf("listed host via capability: %d %v", code, m)
	}
	code, m := exec(d.bURL("/collect"))
	if code != http.StatusForbidden || m["error"] != "DestinationRefusedError" || !strings.Contains(m["detail"].(string), "HOST_NOT_LISTED") {
		t.Fatalf("capability refusal: %d %v", code, m)
	}
	d.assertBUntouched()
	rows := d.auditRows("")
	if countRows(rows, vault.DestinationRefusedEvent) != 1 {
		t.Fatal("no DESTINATION_REFUSED row on the capability path")
	}
}

// Required test 10: a honeytoken still raises its alarm.
func TestStackDestinationsHoneytoken(t *testing.T) {
	d := newDestStackEnv(t, actions.DestinationsEnforce)
	if err := d.stack.Vault.Store().AddHoneytoken(context.Background(), "github", "GITHUB_TOKEN"); err != nil {
		t.Fatal(err)
	}
	code, _ := d.use("coder", "github", "GITHUB_TOKEN", d.bURL("/"))
	if code == 200 || !hasAction(d.auditRows(""), "HONEYTOKEN_TRIGGERED") {
		t.Fatalf("honeytoken alarm missing (status %d)", code)
	}
	d.assertBUntouched()
}

// Required tests 15/16 through the stack: warn mode relaxes NO_LIST only,
// and the start-up lines say so.
func TestStackDestinationsWarnMode(t *testing.T) {
	d := newDestStackEnv(t, actions.DestinationsWarn)
	if code, m := d.use("coder", "misc", "OTHER", d.aURL("/ok")); code != 200 {
		t.Fatalf("warn mode, no entry: %d %v", code, m)
	}
	rows := d.auditRows("")
	if countRows(rows, vault.DestinationRefusedEvent) != 1 {
		t.Fatal("warn-mode send not audited")
	}
	if code, _ := d.use("coder", "github", "GITHUB_TOKEN", d.bURL("/")); code != http.StatusForbidden {
		t.Fatalf("warn mode relaxed a secret with an entry: %d", code)
	}
	d.assertBUntouched()
	w := strings.Join(d.stack.DestinationWarnings, "\n")
	if !strings.Contains(w, "WARN mode") || d.stack.DestinationMode != actions.DestinationsWarn {
		t.Fatalf("warnings: %s", w)
	}
}

// Start-up warnings through the stack name namespaces, not secrets, and
// a policy without a destinations section still installs an empty policy.
func TestStackDestinationsStartup(t *testing.T) {
	d := newDestStackEnv(t, actions.DestinationsEnforce)
	if err := d.stack.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen the same vault: the secrets now exist at start-up.
	for _, c := range []struct{ policy, want string }{
		{"", `namespace "misc" has 1 secret(s)`},
		{testPolicy, `no "destinations:" section`},
	} {
		so := StackOptions{DBPath: d.stack.DBPath, MasterProvider: providerstest.File{Path: d.masterPath}, KDFParams: testKDF}
		if c.policy != "" {
			so.PolicyFile = writeFile(t, filepath.Join(d.dir, "p2.yaml"), c.policy)
		} else {
			so.PolicyFile = d.policyPath
		}
		s, err := OpenStack(context.Background(), so)
		if err != nil {
			t.Fatal(err)
		}
		w := strings.Join(s.DestinationWarnings, "\n")
		_ = s.Close()
		if !strings.Contains(w, c.want) || strings.Contains(w, "OTHER") {
			t.Fatalf("warnings:\n%s", w)
		}
	}
	// A malformed destinations section fails start-up.
	so := StackOptions{DBPath: d.stack.DBPath, MasterProvider: providerstest.File{Path: d.masterPath}, KDFParams: testKDF,
		PolicyFile: writeFile(t, filepath.Join(d.dir, "bad.yaml"), testPolicy+"destinations:\n  github/*: [\"*.com\"]\n")}
	if _, err := OpenStack(context.Background(), so); err == nil || !strings.Contains(err.Error(), "public suffix") {
		t.Fatalf("bad destinations accepted: %v", err)
	}
}

// Required test 18 (compat): the Python line verifies a chain that holds
// DESTINATION_REFUSED rows and parses the policy with both new keys.
//
//	RGT_VAULT_PYTHON=$PWD/.venv/bin/python go test ./internal/server -run PythonDestinations
func TestPythonDestinationsCompat(t *testing.T) {
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault installed to run the Python cross-check")
	}
	d := newDestStackEnv(t, actions.DestinationsEnforce)
	d.use("coder", "github", "GITHUB_TOKEN", d.bURL("/"))
	if err := d.stack.Close(); err != nil {
		t.Fatal(err)
	}
	script, _ := filepath.Abs("testdata/pydest.py")
	cmd := exec.Command(py, script, filepath.Dir(d.stack.DBPath), d.masterPath, d.policyPath)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("python output %q: %v", out, err)
	}
	if m["chain"] != true || m["allowed"] != true || m["rules"] != float64(2) || m["destination_rows"] != float64(1) {
		t.Fatalf("python: %v", m)
	}
}
