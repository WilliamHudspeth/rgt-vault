// Command rgt-vault is the CLI for the rgt-vault secrets manager.
//
// Usage:
//
//	rgt-vault [--host URL] [--token TOKEN] <subcommand> [flags]
//
// Subcommands: set, get, list, revoke, simulate, fingerprint,
//
//	rotate, verify-audit, audit, init, serve, status
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// resolveToken returns the bearer token from flag > env > token file.
func resolveToken(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("RGT_VAULT_TOKEN"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".config", "rgt-vault", "server.token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Build metadata, injected at release time via -ldflags by GoReleaser
// (e.g. -X main.version=0.3.0 -X main.commit=abc123 -X main.date=...).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var host, token string

	rootCmd := &cobra.Command{
		Use:     "rgt-vault",
		Short:   "rgt-vault — encrypted secrets manager for AI agents",
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	rootCmd.PersistentFlags().StringVar(&host, "host", "http://localhost:8080", "server base URL")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "bearer token (overrides env RGT_VAULT_TOKEN and ~/.config/rgt-vault/server.token)")

	// Helper to get resolved token at command runtime.
	getToken := func() string { return resolveToken(token) }

	// -----------------------------------------------------------------------
	// set  — write a secret (value from stdin or --value-file)
	// -----------------------------------------------------------------------
	var setNamespace, setAgent, setPurpose, setValueFile string
	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Store a secret (pipe value via stdin or --value-file)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runSet(host, getToken(), args[0], setNamespace, setAgent, setPurpose, setValueFile) },
	}
	setCmd.Flags().StringVar(&setNamespace, "namespace", "default", "secret namespace")
	setCmd.Flags().StringVar(&setAgent, "agent", "system", "agent identity")
	setCmd.Flags().StringVar(&setPurpose, "purpose", "", "purpose label")
	setCmd.Flags().StringVar(&setValueFile, "value-file", "", "read secret from file instead of stdin")

	// -----------------------------------------------------------------------
	// get  — retrieve / lease a secret
	// -----------------------------------------------------------------------
	var getNamespace, getAgent, getPurpose string
	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Retrieve a secret value",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runGet(host, getToken(), args[0], getNamespace, getAgent, getPurpose) },
	}
	getCmd.Flags().StringVar(&getNamespace, "namespace", "default", "secret namespace")
	getCmd.Flags().StringVar(&getAgent, "agent", "system", "agent identity")
	getCmd.Flags().StringVar(&getPurpose, "purpose", "", "purpose label")

	// -----------------------------------------------------------------------
	// list  — list secrets in a namespace
	// -----------------------------------------------------------------------
	var listNamespace, listAgent string
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets in a namespace",
		RunE:  func(cmd *cobra.Command, args []string) error { return runList(host, getToken(), listNamespace, listAgent) },
	}
	listCmd.Flags().StringVar(&listNamespace, "namespace", "default", "secret namespace")
	listCmd.Flags().StringVar(&listAgent, "agent", "system", "agent identity")

	// -----------------------------------------------------------------------
	// revoke  — revoke a secret
	// -----------------------------------------------------------------------
	var revokeNamespace string
	revokeCmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke (soft-delete) a secret",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runRevoke(host, getToken(), args[0], revokeNamespace) },
	}
	revokeCmd.Flags().StringVar(&revokeNamespace, "namespace", "default", "secret namespace")

	// -----------------------------------------------------------------------
	// simulate  — simulate a policy decision
	// -----------------------------------------------------------------------
	var simNamespace, simAgent, simPurpose, simAction string
	simulateCmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate a policy decision without accessing secrets",
		RunE:  func(cmd *cobra.Command, args []string) error { return runSimulate(host, getToken(), simAgent, simNamespace, simPurpose, simAction) },
	}
	simulateCmd.Flags().StringVar(&simAgent, "agent", "system", "agent identity")
	simulateCmd.Flags().StringVar(&simNamespace, "namespace", "default", "secret namespace")
	simulateCmd.Flags().StringVar(&simPurpose, "purpose", "", "purpose label")
	simulateCmd.Flags().StringVar(&simAction, "action", "read", "action to simulate (read|write)")

	// -----------------------------------------------------------------------
	// fingerprint  — print ciphertext fingerprint
	// -----------------------------------------------------------------------
	var fpNamespace string
	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint <name>",
		Short: "Print the ciphertext fingerprint of a secret (no plaintext exposed)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runFingerprint(host, getToken(), args[0], fpNamespace) },
	}
	fingerprintCmd.Flags().StringVar(&fpNamespace, "namespace", "default", "secret namespace")

	// -----------------------------------------------------------------------
	// rotate  — rotate master key or DEK
	// -----------------------------------------------------------------------
	var rotateTarget string
	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the master key or DEK",
		RunE:  func(cmd *cobra.Command, args []string) error { return runRotate(host, getToken(), rotateTarget) },
	}
	rotateCmd.Flags().StringVar(&rotateTarget, "target", "master", "what to rotate: master | dek")

	// -----------------------------------------------------------------------
	// verify-audit  — verify audit chain integrity
	// -----------------------------------------------------------------------
	verifyAuditCmd := &cobra.Command{
		Use:   "verify-audit",
		Short: "Verify the audit log hash chain",
		RunE:  func(cmd *cobra.Command, args []string) error { return runVerifyAudit(host, getToken()) },
	}

	// -----------------------------------------------------------------------
	// audit  — print audit log entries
	// -----------------------------------------------------------------------
	var auditLimit int
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Print audit log entries",
		RunE:  func(cmd *cobra.Command, args []string) error { return runAudit(host, getToken(), auditLimit) },
	}
	auditCmd.Flags().IntVar(&auditLimit, "limit", 100, "maximum entries to return")

	// -----------------------------------------------------------------------
	// init  — initialise a new vault token
	// -----------------------------------------------------------------------
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialise vault credentials (creates server.token)",
		RunE:  func(cmd *cobra.Command, args []string) error { return runInit() },
	}

	// -----------------------------------------------------------------------
	// serve  — start the HTTP server
	// -----------------------------------------------------------------------
	var serveAddr string
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the rgt-vault HTTP server",
		RunE:  func(cmd *cobra.Command, args []string) error { return runServe(serveAddr) },
	}
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "listen address")

	// -----------------------------------------------------------------------
	// status  — check if the server is reachable
	// -----------------------------------------------------------------------
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check server health",
		RunE:  func(cmd *cobra.Command, args []string) error { return runStatus(host) },
	}

	// -----------------------------------------------------------------------
	// mcp  — stdio MCP server bridging to the vault backend
	// -----------------------------------------------------------------------
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run a stdio MCP server bridging to the vault backend",
		RunE:  func(cmd *cobra.Command, args []string) error { return runMCP(host, getToken()) },
	}

	// -----------------------------------------------------------------------
	// tui  — interactive Bubble Tea dashboard
	// -----------------------------------------------------------------------
	var tuiNamespace string
	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive dashboard (read-only by default)",
		RunE:  func(cmd *cobra.Command, args []string) error { return runTUI(host, getToken(), tuiNamespace) },
	}
	tuiCmd.Flags().StringVar(&tuiNamespace, "namespace", "default", "namespace to display")

	rootCmd.AddCommand(setCmd, getCmd, listCmd, revokeCmd, simulateCmd,
		fingerprintCmd, rotateCmd, verifyAuditCmd, auditCmd,
		initCmd, serveCmd, statusCmd, mcpCmd, tuiCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Fatal(err)
	}
}
