package main

import (
	"fmt"
	"strings"
	"testing"
)

// clientCommands is every command that talks to the server: argument list and
// whether the command is an approval one (needs the operator token).
var clientCommands = []struct {
	name string
	args []string
}{
	{"set", []string{"set", "k"}},
	{"get", []string{"get", "k"}},
	{"list", []string{"list"}},
	{"revoke", []string{"revoke", "k"}},
	{"simulate", []string{"simulate", "--purpose", "p"}},
	{"fingerprint", []string{"fingerprint", "k"}},
	{"rotate", []string{"rotate", "--target", "dek"}},
	{"verify-audit", []string{"verify-audit"}},
	{"audit", []string{"audit"}},
	{"use", []string{"use", "k", "--action", "echo"}},
	{"actions", []string{"actions"}},
	{"requests list", []string{"requests", "list"}},
	{"approve", []string{"requests", "approve", "r1", "--totp-code", "123456"}},
	{"deny", []string{"requests", "deny", "r1"}},
}

// Every client command prints the server's reason, class, status and incident
// id (RGT-526), and the status alone when the body is not the standard shape.
func TestAPIErrorEveryClientCommand(t *testing.T) {
	const std = `{"error":"PolicyDeniedError","detail":"Agent 'rogue' denied read access to 'GITHUB_TOKEN' (github/ci-build)","incident_id":"77cb31cd4a6983ea"}`
	bodies := []struct {
		name, body string
		want       []string
		notWant    []string
	}{
		{"standard", std, []string{
			"Agent 'rogue' denied read access to 'GITHUB_TOKEN' (github/ci-build) (HTTP 403 PolicyDeniedError, incident 77cb31cd4a6983ea)"}, nil},
		{"class only", `{"error":"x"}`, []string{"HTTP 403"}, []string{"incident", "PolicyDeniedError"}},
		{"html page", `<html>Forbidden by proxy</html>`, []string{"HTTP 403"}, []string{"proxy", "incident"}},
		{"detail is not a string", `{"error":"X","detail":["a","b"],"incident_id":"i1"}`, []string{"HTTP 403"}, []string{"incident"}},
		{"empty body", ``, []string{"HTTP 403"}, nil},
	}
	for _, cmd := range clientCommands {
		for _, b := range bodies {
			t.Run(cmd.name+"/"+b.name, func(t *testing.T) {
				isolateEnv(t)
				srv, _ := recordingServer(t, 403, b.body)
				args := append([]string{"--host", srv.URL, "--token", cliToken}, cmd.args...)
				code, _, stderr := runCLI(t, "v", args...)
				if code != 1 {
					t.Fatalf("exit %d, want 1 (stderr %q)", code, stderr)
				}
				if !strings.Contains(stderr, cmd.name+" failed: ") {
					t.Errorf("stderr %q lacks %q", stderr, cmd.name+" failed: ")
				}
				for _, w := range b.want {
					if !strings.Contains(stderr, w) {
						t.Errorf("stderr %q lacks %q", stderr, w)
					}
				}
				for _, w := range b.notWant {
					if strings.Contains(stderr, w) {
						t.Errorf("stderr %q must not contain %q", stderr, w)
					}
				}
			})
		}
	}
}

// Control characters, escape sequences, bidi overrides and newlines in
// server text never reach the terminal (this test fails without safeText).
func TestAPIErrorNeutralisesServerText(t *testing.T) {
	hostile := `{"error":"Pol\u001b[2Jicy","detail":"line1\nError: forged\u001b]0;pwned\u0007 ‮evil \u0085   end","incident_id":"ab\u0007cd\r"}`
	for _, cmd := range clientCommands {
		t.Run(cmd.name, func(t *testing.T) {
			isolateEnv(t)
			srv, _ := recordingServer(t, 403, hostile)
			args := append([]string{"--host", srv.URL, "--token", cliToken}, cmd.args...)
			_, _, stderr := runCLI(t, "v", args...)
			for _, bad := range []string{"\x1b", "\a", "‮", "\u0085", " ", "\r"} {
				if strings.Contains(stderr, bad) {
					t.Errorf("stderr %q contains control text %q", stderr, bad)
				}
			}
			if n := strings.Count(stderr, "\n"); n != 1 {
				t.Errorf("stderr has %d lines, want 1: %q", n, stderr)
			}
			if !strings.Contains(stderr, "line1?Error: forged") {
				t.Errorf("detail not shown (neutralised): %q", stderr)
			}
		})
	}
}

func TestAPIErrorCapsLongText(t *testing.T) {
	err := apiError("x", 500, []byte(`{"error":"E","detail":"`+strings.Repeat("a", 5000)+`","incident_id":"i"}`))
	if n := len([]rune(err.Error())); n > 700 {
		t.Errorf("error is %d runes long", n)
	}
	if !strings.Contains(err.Error(), "…") {
		t.Errorf("no ellipsis: %q", err)
	}
}

func TestSafeText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":         "plain",
		"a\x00b":        "a?b",
		"a\xffb":        "a?b",
		"tab\there":     "tab?here",
		"​zero":         "?zero",
		"héllo wörld ✓": "héllo wörld ✓",
		fmt.Sprint("é"): "é",
	} {
		if got := safeText(in, 100); got != want {
			t.Errorf("safeText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := safeText("abcdef", 3); got != "abc…" {
		t.Errorf("cap: %q", got)
	}
}

// get with a token that has no lease scope says how to fix it.
func TestGetWithoutLeaseScopeHint(t *testing.T) {
	isolateEnv(t)
	srv, _ := recordingServer(t, 403, `{"error":"AuthorizationError","detail":"insufficient scope for this route","incident_id":"c0ffee"}`)
	code, _, stderr := runCLI(t, "", "--host", srv.URL, "--token", cliToken, "get", "k")
	if code != 1 || !strings.Contains(stderr, "insufficient scope for this route (HTTP 403 AuthorizationError, incident c0ffee)") ||
		!strings.Contains(stderr, "agent,lease") || !strings.Contains(stderr, "--offline") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	// Another 403 (a policy denial) gets no scope hint.
	srv2, _ := recordingServer(t, 403, `{"error":"PolicyDeniedError","detail":"denied","incident_id":"c0ffee"}`)
	_, _, stderr = runCLI(t, "", "--host", srv2.URL, "--token", cliToken, "get", "k")
	if strings.Contains(stderr, "lease") {
		t.Errorf("policy denial got the scope hint: %q", stderr)
	}
}
