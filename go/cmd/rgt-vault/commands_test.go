package main

// Go-native acceptance tests for the rgt-vault CLI (RGT-157, revised
// acceptance): one table case per subcommand against an httptest.Server,
// asserting method, path, bearer auth, JSON body, exit code and stdout.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const cliToken = "cli-test-token"

// runCLI runs the CLI in-process and returns (exit code, stdout, stderr).
func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// isolateEnv keeps the real ~/.config token and RGT_VAULT_TOKEN out of tests.
func isolateEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("RGT_VAULT_TOKEN", "")
}

type seenRequest struct {
	Method, Path, Query, Auth, ContentType string
	Body                                   map[string]any
	RawBody                                string
}

func recordingServer(t *testing.T, status int, respBody string) (*httptest.Server, *[]seenRequest) {
	t.Helper()
	var seen []seenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sr := seenRequest{
			Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"),
			RawBody: string(raw),
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &sr.Body); err != nil {
				t.Errorf("request body is not JSON: %q", raw)
			}
		}
		seen = append(seen, sr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestSubcommands(t *testing.T) {
	valueFile := filepath.Join(t.TempDir(), "value.txt")
	if err := os.WriteFile(valueFile, []byte("from-file\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		args       []string
		stdin      string
		status     int
		resp       string
		wantMethod string
		wantPath   string
		wantQuery  string
		wantBody   map[string]any // nil = no body expected
		noAuth     bool           // status sends no token
		wantCode   int
		wantStdout string // exact; "{URL}" is replaced by the server URL
		wantErr    string // substring of stderr for failing cases
	}{
		{name: "set from stdin", args: []string{"set", "api-key", "--namespace", "prod", "--agent", "bot", "--purpose", "ci"},
			stdin: "s3cr3t\n", status: 201, resp: `{"ok":true}`,
			wantMethod: "POST", wantPath: "/v1/secrets",
			wantBody:   map[string]any{"name": "api-key", "namespace": "prod", "value": "s3cr3t", "agent": "bot", "purpose": "ci"},
			wantStdout: "Secret stored.\n"},
		{name: "set from value file", args: []string{"set", "k", "--value-file", valueFile}, status: 200, resp: `{}`,
			wantMethod: "POST", wantPath: "/v1/secrets",
			wantBody:   map[string]any{"name": "k", "namespace": "default", "value": "from-file", "agent": "system", "purpose": ""},
			wantStdout: "Secret stored.\n"},
		{name: "set server error", args: []string{"set", "k"}, stdin: "v", status: 500, resp: `{"error":"x"}`,
			wantMethod: "POST", wantPath: "/v1/secrets",
			wantBody: map[string]any{"name": "k", "namespace": "default", "value": "v", "agent": "system", "purpose": ""},
			wantCode: 1, wantErr: "set failed: HTTP 500"},
		{name: "get", args: []string{"get", "api-key", "--namespace", "prod"}, status: 200,
			resp:       `{"namespace":"prod","secrets":[{"name":"api-key","namespace":"prod","value":"s3cr3t"}]}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=prod&name=api-key", wantStdout: "s3cr3t\n"},
		{name: "get escapes query values", args: []string{"get", "a b&c", "--namespace", "n?s"}, status: 200,
			resp:       `{"secrets":[{"name":"a b&c","value":"v"}]}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=n%3Fs&name=a+b%26c", wantStdout: "v\n"},
		{name: "get not found (empty list)", args: []string{"get", "nope"}, status: 200, resp: `{"namespace":"default","secrets":[]}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=default&name=nope", wantCode: 1, wantErr: "secret \"nope\" not found in namespace \"default\""},
		{name: "get ignores non-exact names", args: []string{"get", "k"}, status: 200, resp: `{"secrets":[{"name":"k2","value":"x"}]}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=default&name=k", wantCode: 1, wantErr: "secret \"k\" not found"},
		{name: "get without value", args: []string{"get", "k"}, status: 200, resp: `{"secrets":[{"name":"k"}]}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=default&name=k", wantCode: 1, wantErr: "server did not return a secret value"},
		{name: "get server error", args: []string{"get", "k"}, status: 401, resp: `{}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=default&name=k", wantCode: 1, wantErr: "get failed: HTTP 401"},
		{name: "list prints names, never values", args: []string{"list", "--namespace", "prod"}, status: 200,
			resp:       `{"namespace":"prod","secrets":[{"name":"a","value":"PLAINTEXT","created_at":"t1"},{"name":"b","created_at":"t2"}]}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=prod", wantStdout: "a\tt1\nb\tt2\n"},
		{name: "list error", args: []string{"list"}, status: 401, resp: `{}`,
			wantMethod: "GET", wantPath: "/v1/secrets", wantQuery: "namespace=default", wantCode: 1, wantErr: "list failed: HTTP 401"},
		{name: "revoke", args: []string{"revoke", "api-key", "--namespace", "prod"}, status: 200, resp: `{"ok":true}`,
			wantMethod: "POST", wantPath: "/v1/secrets/prod/api-key/revoke", wantBody: map[string]any{},
			wantStdout: "Secret revoked.\n"},
		{name: "simulate", args: []string{"simulate", "--agent", "bot", "--namespace", "prod", "--purpose", "deploy", "--action", "write"},
			status: 200, resp: `{"decision":"allow"}` + "\n",
			wantMethod: "POST", wantPath: "/v1/policy/simulate",
			wantBody:   map[string]any{"agent": "bot", "namespace": "prod", "purpose": "deploy", "action": "write"},
			wantStdout: `{"decision":"allow"}` + "\n"},
		{name: "fingerprint", args: []string{"fingerprint", "api-key", "--namespace", "prod"}, status: 200, resp: `{"fingerprint":"ab12cd"}`,
			wantMethod: "GET", wantPath: "/v1/secrets/prod/api-key", wantStdout: "ab12cd\n"},
		{name: "fingerprint missing", args: []string{"fingerprint", "k"}, status: 200, resp: `{"name":"k"}`,
			wantMethod: "GET", wantPath: "/v1/secrets/default/k", wantCode: 1, wantErr: "server did not return a fingerprint"},
		{name: "rotate", args: []string{"rotate", "--target", "dek"}, status: 200, resp: `{"ok":true}`,
			wantMethod: "POST", wantPath: "/v1/rotate", wantBody: map[string]any{"target": "dek"},
			wantStdout: "Rotation complete.\n"},
		{name: "verify-audit ok", args: []string{"verify-audit"}, status: 200, resp: `{"ok":true}`,
			wantMethod: "POST", wantPath: "/v1/audit/verify", wantBody: map[string]any{}, wantStdout: "OK\n"},
		{name: "verify-audit tampered exits 2", args: []string{"verify-audit"}, status: 200, resp: `{"ok":false}`,
			wantMethod: "POST", wantPath: "/v1/audit/verify", wantBody: map[string]any{}, wantCode: 2, wantStdout: "TAMPERED\n", wantErr: "audit chain verification failed"},
		{name: "verify-audit legacy valid field", args: []string{"verify-audit"}, status: 200, resp: `{"valid":true}`,
			wantMethod: "POST", wantPath: "/v1/audit/verify", wantBody: map[string]any{}, wantStdout: "OK\n"},
		{name: "verify-audit no verdict", args: []string{"verify-audit"}, status: 200, resp: `{}`,
			wantMethod: "POST", wantPath: "/v1/audit/verify", wantBody: map[string]any{}, wantCode: 1, wantErr: "server response has no verdict"},
		{name: "audit", args: []string{"audit", "--limit", "5"}, status: 200, resp: `{"entries":[]}`,
			wantMethod: "GET", wantPath: "/v1/audit", wantQuery: "limit=5", wantStdout: `{"entries":[]}` + "\n"},
		{name: "status ok", args: []string{"status"}, status: 200, resp: `{"status":"ok"}`, noAuth: true,
			wantMethod: "GET", wantPath: "/healthz", wantStdout: "Server OK: {URL}\n"},
		{name: "status unhealthy", args: []string{"status"}, status: 503, resp: `{}`, noAuth: true,
			wantMethod: "GET", wantPath: "/healthz", wantCode: 1, wantStdout: "Server unreachable: {URL} (HTTP 503)\n", wantErr: "unexpected status: 503"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			srv, seen := recordingServer(t, tc.status, tc.resp)
			args := append([]string{"--host", srv.URL + "/", "--token", cliToken}, tc.args...)
			code, stdout, stderr := runCLI(t, tc.stdin, args...)

			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr=%q)", code, tc.wantCode, stderr)
			}
			if want := strings.ReplaceAll(tc.wantStdout, "{URL}", srv.URL); stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
			if tc.wantCode == 0 && stderr != "" {
				t.Errorf("unexpected stderr %q", stderr)
			}
			if tc.wantCode != 0 {
				if tc.wantErr == "" {
					t.Fatal("failing case must set wantErr")
				}
				if !strings.HasPrefix(stderr, "Error: ") || !strings.Contains(stderr, tc.wantErr) {
					t.Errorf("stderr = %q, want Error: ...%s", stderr, tc.wantErr)
				}
			}
			if strings.Contains(stdout, "PLAINTEXT") {
				t.Errorf("list leaked a value: %q", stdout)
			}
			if len(*seen) != 1 {
				t.Fatalf("server saw %d requests, want 1", len(*seen))
			}
			r := (*seen)[0]
			if r.Method != tc.wantMethod || r.Path != tc.wantPath || r.Query != tc.wantQuery {
				t.Errorf("request = %s %s?%s, want %s %s?%s", r.Method, r.Path, r.Query, tc.wantMethod, tc.wantPath, tc.wantQuery)
			}
			wantAuth := "Bearer " + cliToken
			if tc.noAuth {
				wantAuth = ""
			}
			if r.Auth != wantAuth {
				t.Errorf("Authorization = %q, want %q", r.Auth, wantAuth)
			}
			if tc.wantBody == nil {
				if r.RawBody != "" {
					t.Errorf("unexpected body %q", r.RawBody)
				}
			} else {
				if r.ContentType != "application/json" {
					t.Errorf("Content-Type = %q", r.ContentType)
				}
				got, _ := json.Marshal(r.Body)
				want, _ := json.Marshal(tc.wantBody)
				if !bytes.Equal(got, want) {
					t.Errorf("body = %s, want %s", got, want)
				}
			}
		})
	}
}

// Every one of the 12 subcommands from RGT-157 is covered by a test here.
func TestAllTwelveSubcommandsRegistered(t *testing.T) {
	root := newRootCmd(strings.NewReader(""), io.Discard)
	have := map[string]bool{}
	for _, c := range root.Commands() {
		have[c.Name()] = true
	}
	for _, name := range []string{"set", "get", "list", "revoke", "simulate", "fingerprint",
		"rotate", "verify-audit", "audit", "init", "serve", "status"} {
		if !have[name] {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func TestTokenResolution(t *testing.T) {
	isolateEnv(t)
	srv, seen := recordingServer(t, 200, `{"ok":true}`)

	// env var
	t.Setenv("RGT_VAULT_TOKEN", "from-env")
	if code, _, _ := runCLI(t, "", "--host", srv.URL, "rotate"); code != 0 {
		t.Fatal("rotate failed")
	}
	// token file under $HOME when neither flag nor env is set
	t.Setenv("RGT_VAULT_TOKEN", "")
	home, _ := os.UserHomeDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "rgt-vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "rgt-vault", "server.token"), []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "", "--host", srv.URL, "rotate"); code != 0 {
		t.Fatal("rotate failed")
	}
	if got := []string{(*seen)[0].Auth, (*seen)[1].Auth}; got[0] != "Bearer from-env" || got[1] != "Bearer from-file" {
		t.Errorf("auth headers = %v", got)
	}
}

func TestGetRejectsEmptyName(t *testing.T) {
	isolateEnv(t)
	srv, seen := recordingServer(t, 200, `{"secrets":[]}`)
	code, _, stderr := runCLI(t, "", "--host", srv.URL, "get", "")
	if code != 1 || !strings.Contains(stderr, "secret name must not be empty") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(*seen) != 0 {
		t.Error("empty name reached the server (would be an unfiltered list)")
	}
}

func TestSetRejectsEmptyValueAndMissingFile(t *testing.T) {
	isolateEnv(t)
	srv, seen := recordingServer(t, 200, `{}`)
	if code, _, _ := runCLI(t, "\n", "--host", srv.URL, "set", "k"); code != 1 {
		t.Errorf("empty value: exit %d, want 1", code)
	}
	if code, _, _ := runCLI(t, "", "--host", srv.URL, "set", "k", "--value-file", filepath.Join(t.TempDir(), "none")); code != 1 {
		t.Errorf("missing file: exit %d, want 1", code)
	}
	if len(*seen) != 0 {
		t.Errorf("server was called %d times", len(*seen))
	}
}

func TestUnreachableServerAndBadArgs(t *testing.T) {
	isolateEnv(t)
	dead := "http://127.0.0.1:1"
	for _, args := range [][]string{
		{"get", "k"}, {"list"}, {"revoke", "k"}, {"simulate"}, {"fingerprint", "k"},
		{"rotate"}, {"verify-audit"}, {"audit"}, {"status"}, {"set", "k"},
	} {
		code, _, stderr := runCLI(t, "v", append([]string{"--host", dead, "--token", "x"}, args...)...)
		if code != 1 || !strings.HasPrefix(stderr, "Error: ") {
			t.Errorf("%v: exit %d stderr %q", args, code, stderr)
		}
	}
	// Wrong arity is a usage error (exit 1), and nothing is sent.
	if code, _, _ := runCLI(t, "", "get"); code != 1 {
		t.Errorf("get without name: exit %d", code)
	}
	// Bare invocation prints help and succeeds.
	if code, out, _ := runCLI(t, ""); code != 0 || !strings.Contains(out, "Available Commands") {
		t.Errorf("bare run: exit %d out %q", code, out)
	}
}

func TestBadJSONResponses(t *testing.T) {
	isolateEnv(t)
	srv, _ := recordingServer(t, 200, `not json`)
	for _, args := range [][]string{{"get", "k"}, {"list"}, {"fingerprint", "k"}, {"verify-audit"}} {
		if code, _, _ := runCLI(t, "", append([]string{"--host", srv.URL, "--token", "x"}, args...)...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	srv2, _ := recordingServer(t, 500, `{}`)
	for _, args := range [][]string{{"revoke", "k"}, {"simulate"}, {"fingerprint", "k"}, {"rotate"}, {"verify-audit"}, {"audit"}} {
		if code, _, _ := runCLI(t, "", append([]string{"--host", srv2.URL, "--token", "x"}, args...)...); code != 1 {
			t.Errorf("%v on 500: exit %d, want 1", args, code)
		}
	}
}

// ---- init ----------------------------------------------------------------

func TestInitWrites0600TokenFile(t *testing.T) {
	isolateEnv(t)
	path := filepath.Join(t.TempDir(), "nested", "server.token")
	code, stdout, stderr := runCLI(t, "", "init", "--token-file", path)
	if code != 0 {
		t.Fatalf("init exit %d: %s", code, stderr)
	}
	if stdout != "Vault initialised. Token written to: "+path+"\n" {
		t.Errorf("stdout = %q", stdout)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 43 || strings.ContainsAny(string(data), "+/=\n") {
		t.Errorf("token %q is not 32 bytes raw-url-base64", data)
	}
	if strings.Contains(stdout, string(data)) {
		t.Error("init printed the token")
	}
	assertMode0600(t, path)

	// Re-running replaces the token and tightens a loose pre-existing mode.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "", "init", "--token-file", path); code != 0 {
		t.Fatal("second init failed")
	}
	data2, _ := os.ReadFile(path)
	if bytes.Equal(data, data2) {
		t.Error("second init reused the token")
	}
	assertMode0600(t, path)
}

func TestInitDefaultPathUnderHome(t *testing.T) {
	isolateEnv(t)
	if code, _, stderr := runCLI(t, "", "init"); code != 0 {
		t.Fatalf("init: %s", stderr)
	}
	home, _ := os.UserHomeDir()
	assertMode0600(t, filepath.Join(home, ".config", "rgt-vault", "server.token"))
}

func TestInitFailsOnUnwritablePath(t *testing.T) {
	isolateEnv(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "", "init", "--token-file", filepath.Join(blocker, "server.token")); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if err := runInit("", io.Discard); err == nil {
		t.Error("empty token path accepted")
	}
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // POSIX modes are not meaningful on Windows
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %o, want 600", path, fi.Mode().Perm())
	}
}

// ---- serve ---------------------------------------------------------------

func TestServeHandlerUsesRealRouterAndAuth(t *testing.T) {
	isolateEnv(t)
	tokenPath := filepath.Join(t.TempDir(), "server.token")
	h, path, err := newServeHandler(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if path != tokenPath {
		t.Errorf("path = %q", path)
	}
	assertMode0600(t, tokenPath)
	raw, _ := os.ReadFile(tokenPath)
	token := strings.TrimSpace(string(raw))

	srv := httptest.NewServer(h)
	defer srv.Close()

	// status against the served /healthz (no token needed)
	if code, out, _ := runCLI(t, "", "--host", srv.URL, "status"); code != 0 || out != "Server OK: "+srv.URL+"\n" {
		t.Errorf("status: exit %d out %q", code, out)
	}
	// authenticated route rejects a wrong token, accepts the file's token
	if code, _, _ := runCLI(t, "", "--host", srv.URL, "--token", "wrong", "list"); code != 1 {
		t.Errorf("wrong token: exit %d, want 1", code)
	}
	if code, _, stderr := runCLI(t, "", "--host", srv.URL, "--token", token, "list"); code != 0 {
		t.Errorf("right token: exit %d %s", code, stderr)
	}
	// existing token file is reused, not regenerated
	if _, _, err := newServeHandler(tokenPath); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(tokenPath)
	if !bytes.Equal(raw, raw2) {
		t.Error("serve regenerated an existing token")
	}
}

func TestServeCommandErrors(t *testing.T) {
	isolateEnv(t)
	// An unusable listen address makes serve exit 1 instead of blocking.
	if code, _, stderr := runCLI(t, "", "serve", "--addr", "127.0.0.1:-1", "--token-file", filepath.Join(t.TempDir(), "t")); code != 1 {
		t.Errorf("serve bad addr: exit %d (%s)", code, stderr)
	}
	if _, _, err := newServeHandler(""); err == nil {
		t.Error("empty token path accepted")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	if code, _, _ := runCLI(t, "", "serve", "--token-file", filepath.Join(blocker, "t")); code != 1 {
		t.Errorf("serve bad token path: exit %d", code)
	}
}

func TestServeRefusesNonLoopback(t *testing.T) {
	isolateEnv(t)
	tok := filepath.Join(t.TempDir(), "t")
	code, _, stderr := runCLI(t, "", "serve", "--addr", ":0", "--token-file", tok)
	if code != 1 || !strings.Contains(stderr, "not a loopback address") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if _, err := os.Stat(tok); err == nil {
		t.Error("token file created before the bind check")
	}
	for addr, want := range map[string]bool{"127.0.0.1:1": true, "localhost:1": true, "[::1%lo]:1": true, ":1": false, "0.0.0.0:1": false, "bad": false} {
		if isLoopbackAddr(addr) != want {
			t.Errorf("isLoopbackAddr(%q) != %v", addr, want)
		}
	}
}

func TestServeTightensExistingTokenFile(t *testing.T) {
	isolateEnv(t)
	p := filepath.Join(t.TempDir(), "server.token")
	if err := os.WriteFile(p, []byte("existing-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newServeHandler(p); err != nil {
		t.Fatal(err)
	}
	assertMode0600(t, p)
}

func TestMCPSubcommandUsesInjectedStreams(t *testing.T) {
	isolateEnv(t)
	var out bytes.Buffer
	code := run([]string{"--host", "http://127.0.0.1:1/", "mcp"},
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, io.Discard)
	if code != 0 || !strings.Contains(out.String(), `"id":1`) {
		t.Fatalf("exit %d out %q", code, out.String())
	}

	// Backend error details go to the injected stderr, never to stdout.
	srv, _ := recordingServer(t, 500, `{"detail":"INTERNAL-DETAIL /srv/state.db"}`)
	var out2, errOut bytes.Buffer
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_secrets","arguments":{"namespace":"prod"}}}` + "\n"
	code = run([]string{"--host", srv.URL, "--token", "x", "mcp"}, strings.NewReader(call), &out2, &errOut)
	if code != 0 || !strings.Contains(out2.String(), "backend error: 500") || strings.Contains(out2.String(), "INTERNAL-DETAIL") {
		t.Fatalf("exit %d stdout %q", code, out2.String())
	}
	if !strings.Contains(errOut.String(), "INTERNAL-DETAIL") || !strings.Contains(errOut.String(), "rgt-vault mcp: ") {
		t.Errorf("backend detail not logged to injected stderr: %q", errOut.String())
	}
}

func TestMCPAgentFlagAndEnv(t *testing.T) {
	isolateEnv(t)
	if got := mcpAgentLabel(""); got != "mcp-client" {
		t.Errorf("default agent = %q", got)
	}
	t.Setenv("RGT_VAULT_MCP_AGENT", "env-bot")
	if got := mcpAgentLabel(""); got != "env-bot" {
		t.Errorf("env agent = %q", got)
	}
	if got := mcpAgentLabel("flag-bot"); got != "flag-bot" {
		t.Errorf("flag agent = %q", got)
	}

	// The flag reaches execute_secret's request body.
	srv, seen := recordingServer(t, 200, `{"ok":true}`)
	call := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_secret","arguments":{"namespace":"ns","name":"n","action":"a"}}}` + "\n"
	var out bytes.Buffer
	if code := run([]string{"--host", srv.URL, "--token", "x", "mcp", "--agent", "flag-bot"}, strings.NewReader(call), &out, io.Discard); code != 0 {
		t.Fatalf("exit %d out %q", code, out.String())
	}
	if len(*seen) != 1 || (*seen)[0].Body["agent"] != "flag-bot" {
		t.Fatalf("backend saw %+v", *seen)
	}

	// An invalid label is refused before serving.
	var errOut bytes.Buffer
	if code := run([]string{"--host", srv.URL, "mcp", "--agent", "bad agent"}, strings.NewReader(""), io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "--agent") {
		t.Errorf("bad agent: exit %d stderr %q", code, errOut.String())
	}
}

func TestServeDefaultsToLoopback(t *testing.T) {
	root := newRootCmd(strings.NewReader(""), io.Discard)
	serve, _, err := root.Find([]string{"serve"})
	if err != nil {
		t.Fatal(err)
	}
	if got := serve.Flags().Lookup("addr").DefValue; got != "127.0.0.1:8080" {
		t.Errorf("serve --addr default = %q, want loopback", got)
	}
}
