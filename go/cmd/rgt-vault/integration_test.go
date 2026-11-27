package main

import (
	"strings"
	"testing"
)

// The CLI against the real server.New stack on a persistent vault:
// set -> get -> list -> revoke over HTTP, then the same data through the
// offline commands.
func TestIntegration_RealStack(t *testing.T) {
	e := newVaultEnv(t)
	url, token := e.startServer()
	cli := func(stdin string, args ...string) (int, string, string) {
		return runCLI(t, stdin, append([]string{"--host", url, "--token", token}, args...)...)
	}

	if code, out, stderr := cli("s3cr3t-value\n", "set", "api-key", "--namespace", "prod", "--agent", "bot", "--purpose", "ci"); code != 0 || out != "Secret stored.\n" {
		t.Fatalf("set: exit %d out %q err %q", code, out, stderr)
	}
	// get over HTTP: the server leases it (D5 transitional route).
	if code, out, stderr := cli("", "get", "api-key", "--namespace", "prod"); code != 0 || out != "s3cr3t-value\n" {
		t.Fatalf("get: exit %d out %q err %q", code, out, stderr)
	}
	code, out, stderr := cli("", "list", "--namespace", "prod")
	if code != 0 || !strings.HasPrefix(out, "api-key\t") || strings.Contains(out, "s3cr3t-value") {
		t.Fatalf("list: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, _ := cli("", "fingerprint", "api-key", "--namespace", "prod"); code != 0 || len(strings.TrimSpace(out)) == 0 {
		t.Fatalf("fingerprint: exit %d out %q", code, out)
	}
	if code, out, stderr := cli("", "simulate", "--agent", "bot", "--namespace", "prod", "--purpose", "ci"); code != 0 || !strings.Contains(out, "allow") {
		t.Fatalf("simulate: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, stderr := cli("", "rotate", "--target", "dek"); code != 0 || out != "Rotation complete.\n" {
		t.Fatalf("rotate dek: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, stderr := cli("", "rotate", "--target", "master"); code != 0 || out != "Rotation complete.\n" {
		t.Fatalf("rotate master: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, stderr := cli("", "get", "api-key", "--namespace", "prod"); code != 0 || out != "s3cr3t-value\n" {
		t.Fatalf("get after rotation: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, _ := cli("", "audit", "--limit", "3"); code != 0 || !strings.Contains(out, "LEASE") {
		t.Fatalf("audit: exit %d out %q", code, out)
	}
	if code, out, stderr := cli("", "verify-audit"); code != 0 || out != "OK\n" {
		t.Fatalf("verify-audit: exit %d out %q err %q", code, out, stderr)
	}
	if code, out, stderr := cli("", "revoke", "api-key", "--namespace", "prod"); code != 0 || out != "Secret revoked.\n" {
		t.Fatalf("revoke: exit %d out %q err %q", code, out, stderr)
	}
	if code, _, stderr := cli("", "get", "api-key", "--namespace", "prod"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Fatalf("get after revoke: exit %d err %q", code, stderr)
	}

	// The same chain, verified offline from the database file.
	if code, out, stderr := e.cli("", "verify-audit", "--offline"); code != 0 || out != "OK\n" {
		t.Fatalf("offline verify-audit: exit %d out %q err %q", code, out, stderr)
	}
}

// get --offline opens the vault files locally: same ABAC policy, same audit
// rows, no server.
func TestGetOffline(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "api-key", "offline-value")

	out := e.mustCLI("", "get", "api-key", "--namespace", "prod", "--purpose", "deploy", "--agent", "op", "--offline")
	if out != "offline-value\n" {
		t.Fatalf("get --offline = %q", out)
	}
	// An explicit --db alone also selects the offline path.
	if code, out, stderr := runCLI(t, "", "--db", e.db, "--policy", e.policy, "get", "api-key", "--namespace", "prod", "--purpose", "deploy"); code != 0 || out != "offline-value\n" {
		t.Fatalf("get --db: exit %d out %q err %q", code, out, stderr)
	}
	// The lease is in the audit chain, with the agent that asked.
	stack := e.open()
	rows, err := stack.Vault.AuditLog(t.Context(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var granted bool
	for _, r := range rows {
		if r.Action == "LEASE_GRANTED" && strings.Contains(r.Details.String, "op") {
			granted = true
		}
	}
	if !granted {
		t.Errorf("no LEASE_GRANTED row for the offline get: %+v", rows)
	}
	_ = stack.Close()

	// Missing purpose, unknown secret, default-deny without a policy.
	if code, _, stderr := e.cli("", "get", "api-key", "--namespace", "prod", "--offline"); code != 1 || !strings.Contains(stderr, "--purpose is required") {
		t.Errorf("no purpose: exit %d err %q", code, stderr)
	}
	if code, _, stderr := e.cli("", "get", "nope", "--purpose", "x", "--offline"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("unknown secret: exit %d err %q", code, stderr)
	}
	if code, _, stderr := runCLI(t, "", "--db", e.db, "get", "api-key", "--namespace", "prod", "--purpose", "x", "--offline"); code != 1 || strings.Contains(stderr, "offline-value") {
		t.Errorf("default deny: exit %d err %q", code, stderr)
	}
	if code, _, _ := e.cli("", "get", "", "--purpose", "x", "--offline"); code != 1 {
		t.Errorf("empty name: exit %d", code)
	}
	// A vault that does not exist is not created by a read.
	if code, _, stderr := runCLI(t, "", "--db", e.dir+"/nope/vault.db", "get", "k", "--purpose", "x", "--offline"); code != 1 || !strings.Contains(stderr, "no vault at") {
		t.Errorf("missing vault: exit %d err %q", code, stderr)
	}
}
