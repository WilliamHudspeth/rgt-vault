package main

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
)

// fakeTerminal replaces the no-echo prompt for a test.
type fakeTerminal struct {
	mu      sync.Mutex
	isTerm  bool
	codes   []string // returned by successive prompts
	prompts []string
	readErr error
}

func (f *fakeTerminal) install(t *testing.T) {
	t.Helper()
	old := term
	term = terminalIO{
		isTerminal: func(io.Reader) bool { return f.isTerm },
		readSecret: func(_ io.Reader, out io.Writer, prompt string) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.prompts = append(f.prompts, prompt)
			_, _ = io.WriteString(out, prompt)
			if f.readErr != nil {
				return "", f.readErr
			}
			if len(f.codes) == 0 {
				t.Error("prompted more often than expected")
				return "", errors.New("no more codes")
			}
			c := f.codes[0]
			f.codes = f.codes[1:]
			return c, nil
		},
	}
	t.Cleanup(func() { term = old })
}

// startUse runs `use` in the background (it blocks until the request is
// decided) and returns a function that waits for its result.
func startUse(t *testing.T, s *realStack, ns, name string) func() (int, string, string) {
	t.Helper()
	type res struct {
		code     int
		out, err string
	}
	ch := make(chan res, 1)
	go func() {
		c, o, e := s.agent(t, "", "use", name, "--namespace", ns, "--action", "echo", "--purpose", "approval-test")
		ch <- res{c, o, e}
	}()
	return func() (int, string, string) {
		select {
		case r := <-ch:
			return r.code, r.out, r.err
		case <-time.After(30 * time.Second):
			t.Fatal("use did not return")
			return 0, "", ""
		}
	}
}

// pendingID polls `requests list` until a request is pending and returns the
// first line's fields.
func pendingID(t *testing.T, s *realStack) []string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if code, out, _ := s.operator(t, "", "requests", "list"); code == 0 && strings.TrimSpace(out) != "" {
			return strings.Split(strings.SplitN(out, "\n", 2)[0], "\t")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no pending request appeared")
	return nil
}

// The 2FA flow, end to end on the real stack: set --require-2fa --note, an
// agent's `use` waits, `requests list` shows it, `requests approve` prompts
// (no echo, fake terminal), a wrong code prints the server's message, the
// right one releases the request.
func TestRequestsApprove2FAPrompt(t *testing.T) {
	s := startRealStack(t, stackOpts{approval: true})
	if code, _, e := s.agent(t, "guarded-value\n", "set", "vault-key", "--namespace", "prod", "--purpose", "setup",
		"--require-2fa", "--note", "prod signing key"); code != 0 {
		t.Fatalf("set: %d %s", code, e)
	}
	wait := startUse(t, s, "prod", "vault-key")
	f := pendingID(t, s)
	if len(f) != 7 || f[1] != "bot" || f[2] != "prod/vault-key" || f[3] != "read" || f[4] != "approval-test" || f[5] != "2fa" {
		t.Fatalf("list line fields = %q", f)
	}
	id := f[0]

	// A wrong code: the server's message, the request stays pending.
	ft := &fakeTerminal{isTerm: true, codes: []string{"000000"}}
	ft.install(t)
	code, out, stderr := s.operator(t, "", "requests", "approve", id)
	if code != 1 || out != "" || !strings.Contains(stderr, "approve failed: ") || !strings.Contains(stderr, "HTTP 400 ApprovalError") || !strings.Contains(stderr, ", incident ") {
		t.Fatalf("wrong code: exit %d out %q err %q", code, out, stderr)
	}
	if len(ft.prompts) != 1 || !strings.Contains(ft.prompts[0], "prod/vault-key") || !strings.Contains(stderr, "TOTP code to approve") {
		t.Errorf("prompt %q / stderr %q", ft.prompts, stderr)
	}
	if strings.Contains(stderr, "000000") {
		t.Errorf("the typed code was echoed: %q", stderr)
	}

	// The right code, typed at the prompt.
	good, err := totp.Generate(s.totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ft.codes = []string{good}
	code, out, stderr = s.operator(t, "", "requests", "approve", id)
	if code != 0 || out != "Request "+id+" approved.\n" {
		t.Fatalf("approve: exit %d out %q err %q", code, out, stderr)
	}
	if strings.Contains(out+stderr, good) {
		t.Errorf("the code appears in the output")
	}
	ucode, uout, uerr := wait()
	if ucode != 0 || !strings.Contains(uout, `"leaked_secret": false`) {
		t.Fatalf("use after approval: %d %q %q", ucode, uout, uerr)
	}
}

// Without a terminal and without --totp-code the command refuses and sends no
// approval; --totp-code is the script form.
func TestRequestsApproveNeedsTerminalOrFlag(t *testing.T) {
	s := startRealStack(t, stackOpts{approval: true})
	if code, _, e := s.agent(t, "v\n", "set", "k", "--namespace", "prod", "--purpose", "setup", "--require-2fa"); code != 0 {
		t.Fatalf("set: %d %s", code, e)
	}
	wait := startUse(t, s, "prod", "k")
	id := pendingID(t, s)[0]

	(&fakeTerminal{isTerm: false}).install(t) // stdin is a pipe/file
	code, _, stderr := s.operator(t, "", "requests", "approve", id)
	if code != 1 || !strings.Contains(stderr, "stdin is not a terminal") || !strings.Contains(stderr, "--totp-code") {
		t.Fatalf("no terminal: exit %d err %q", code, stderr)
	}
	// Still pending: nothing was approved.
	if _, out, _ := s.operator(t, "", "requests", "list"); !strings.Contains(out, id) {
		t.Fatalf("request left the queue: %q", out)
	}
	// A prompt that fails or returns nothing is an error too.
	(&fakeTerminal{isTerm: true, readErr: errors.New("boom")}).install(t)
	if code, _, stderr = s.operator(t, "", "requests", "approve", id); code != 1 || !strings.Contains(stderr, "reading the TOTP code: boom") {
		t.Errorf("read error: %d %q", code, stderr)
	}
	(&fakeTerminal{isTerm: true, codes: []string{"  "}}).install(t)
	if code, _, stderr = s.operator(t, "", "requests", "approve", id); code != 1 || !strings.Contains(stderr, "no TOTP code entered") {
		t.Errorf("empty code: %d %q", code, stderr)
	}

	good, _ := totp.Generate(s.totpSecret, time.Now())
	code, out, stderr := s.operator(t, "", "requests", "approve", id, "--totp-code", good)
	if code != 0 || !strings.Contains(out, "approved") {
		t.Fatalf("--totp-code: exit %d out %q err %q", code, out, stderr)
	}
	if ucode, _, uerr := wait(); ucode != 0 {
		t.Fatalf("use: %d %q", ucode, uerr)
	}
}

// A request that needs no second factor is approved without any prompt, and
// deny carries the reason back to the requester.
func TestRequestsApproveWithoutTOTPAndDeny(t *testing.T) {
	s := startRealStack(t, stackOpts{approval: true})
	if code, _, e := s.agent(t, "v\n", "set", "plain", "--namespace", "prod", "--purpose", "setup"); code != 0 {
		t.Fatalf("set: %d %s", code, e)
	}
	(&fakeTerminal{isTerm: true}).install(t) // any prompt would fail the test (no codes)

	wait := startUse(t, s, "prod", "plain")
	f := pendingID(t, s)
	if f[5] != "no" {
		t.Fatalf("2fa column = %q", f[5])
	}
	if code, out, e := s.operator(t, "", "requests", "approve", f[0]); code != 0 || out != "Request "+f[0]+" approved.\n" {
		t.Fatalf("approve: %d %q %q", code, out, e)
	}
	if code, _, e := wait(); code != 0 {
		t.Fatalf("use: %d %q", code, e)
	}

	wait = startUse(t, s, "prod", "plain")
	id := pendingID(t, s)[0]
	if code, out, e := s.operator(t, "", "requests", "deny", id, "--reason", "not during the freeze"); code != 0 || out != "Request "+id+" denied.\n" {
		t.Fatalf("deny: %d %q %q", code, out, e)
	}
	code, _, e := wait()
	if code != 1 || !strings.Contains(e, "not during the freeze") {
		t.Fatalf("use after deny: %d %q (the reason must reach the requester)", code, e)
	}

	// Unknown id: the server's message, with incident id.
	if code, _, e := s.operator(t, "", "requests", "deny", "nope"); code != 1 || !strings.Contains(e, "deny failed: ") || !strings.Contains(e, "incident") {
		t.Errorf("deny unknown: %d %q", code, e)
	}
	// An empty queue says so on stderr and prints nothing on stdout.
	if code, out, e := s.operator(t, "", "requests", "list"); code != 0 || out != "" || !strings.Contains(e, "No pending requests.") {
		t.Errorf("empty list: %d %q %q", code, out, e)
	}
}

// The agent token cannot work the queue, and the refusal is explained.
func TestRequestsNeedOperatorToken(t *testing.T) {
	s := startRealStack(t, stackOpts{approval: true})
	code, _, e := s.agent(t, "", "requests", "list")
	if code != 1 || !strings.Contains(e, "requests list failed: insufficient scope for this route (HTTP 403 AuthorizationError, incident ") {
		t.Errorf("exit %d err %q", code, e)
	}
}

// approve and deny send no "operator" name: the server takes the approver
// from the token and refuses a different name.
func TestRequestsSendNoOperatorName(t *testing.T) {
	isolateEnv(t)
	srv, seen := recordingServer(t, 200, `{"ok":true}`)
	run := func(args ...string) {
		t.Helper()
		if code, _, e := runCLI(t, "", append([]string{"--host", srv.URL, "--token", cliToken}, args...)...); code != 0 {
			t.Fatalf("%v: %d %s", args, code, e)
		}
	}
	run("requests", "approve", "r 1", "--totp-code", " 123456 ")
	run("requests", "deny", "r2", "--reason", "no")
	run("requests", "deny", "r3")
	if len(*seen) != 3 {
		t.Fatalf("%d requests", len(*seen))
	}
	for i, want := range []struct{ path, body string }{
		{"/v1/requests/r%201/approve", `{"totp_code":"123456"}`},
		{"/v1/requests/r2/deny", `{"reason":"no"}`},
		{"/v1/requests/r3/deny", `{}`},
	} {
		got := (*seen)[i]
		if got.Method != "POST" || got.Path != want.path || got.RawBody != want.body {
			t.Errorf("request %d: %s %s %s, want POST %s %s", i, got.Method, got.Path, got.RawBody, want.path, want.body)
		}
		if _, has := got.Body["operator"]; has {
			t.Errorf("request %d sent an operator name", i)
		}
	}
}

// Server text in the listing is neutralised (an agent chose the purpose).
func TestRequestsListNeutralisesServerText(t *testing.T) {
	isolateEnv(t)
	srv, _ := recordingServer(t, 200, `{"requests":[{"request_id":"r1","agent":"a\u001b[31m","namespace":"n","secret_name":"s","purpose":"p\nforged\tline","action":"use","require_2fa":true,"created_at":1700000000.5}]}`)
	code, out, e := runCLI(t, "", "--host", srv.URL, "--token", cliToken, "requests", "list")
	if code != 0 || out != "r1\ta?[31m\tn/s\tuse\tp?forged?line\t2fa\t2023-11-14T22:13:20Z\n" {
		t.Errorf("exit %d out %q err %q", code, out, e)
	}
}

func TestRequestsCommandErrors(t *testing.T) {
	isolateEnv(t)
	for _, args := range [][]string{{"requests", "approve"}, {"requests", "deny"}, {"requests", "approve", ""}, {"requests", "deny", ""}, {"requests", "list", "x"}} {
		if code, _, _ := runCLI(t, "", append([]string{"--host", "http://127.0.0.1:1", "--token", cliToken}, args...)...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	// The operator-token fallback (like audit): no token at all is explained.
	if code, _, e := runCLI(t, "", "--host", "http://127.0.0.1:1", "requests", "list"); code != 1 || !strings.Contains(e, "no bearer token") {
		t.Errorf("no token: %d %q", code, e)
	}
}

func TestReadSecretNoEchoRefusesNonFile(t *testing.T) {
	if _, err := readSecretNoEcho(strings.NewReader("x"), io.Discard, "p: "); err == nil {
		t.Error("a non-file stdin was accepted")
	}
	if stdinIsTerminal(strings.NewReader("")) {
		t.Error("a reader is not a terminal")
	}
}
