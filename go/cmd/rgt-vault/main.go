// Command rgt-vault is the CLI for the rgt-vault secrets manager.
//
// Usage:
//
//	rgt-vault [--host URL] [--token TOKEN] <subcommand> [flags]
//	rgt-vault [--db PATH] [--policy FILE] [--provider keyring|platform] <offline subcommand>
//
// Subcommands that talk to a running server (--host, default
// http://127.0.0.1:8765, the same port as Python): set, get, list, revoke,
// simulate, fingerprint, rotate, audit, verify-audit, status.
//
// Subcommands that open the vault files directly: serve, init, enroll-2fa,
// export, import, migrate check, provider seal, and the offline forms of
// get, verify-audit and status (--offline, or an explicit --db).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/mcp"
	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/vault"
)

// defaultHost is the server URL the client subcommands talk to (decision
// D6: Python's port, 8765).
const defaultHost = "http://127.0.0.1:8765"

// Test seams: tests replace the master-secret provider (no OS keyring in CI)
// and use cheap Argon2 parameters for new keychains. Production leaves them
// nil/zero: server.NewProvider and Python's parameters.
var (
	newProvider func(name string) (vault.MasterProvider, error)
	kdfParams   kdf.Params
	serveReady  func(addr string) // called when `serve` is listening
)

// serveEnv is the environment of the vault-opening subcommands.
func serveEnv(stdout io.Writer) servecmd.Env {
	return servecmd.Env{Stdout: stdout, NewProvider: newProvider, KDFParams: kdfParams, Ready: serveReady}
}

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

// mcpAgentLabel resolves the MCP agent label: flag > $RGT_VAULT_MCP_AGENT >
// mcp.DefaultAgent.
func mcpAgentLabel(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("RGT_VAULT_MCP_AGENT"); v != "" {
		return v
	}
	return mcp.DefaultAgent
}

// Build metadata, injected at release time via -ldflags by GoReleaser
// (e.g. -X main.version=0.3.0 -X main.commit=abc123 -X main.date=...).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run executes the CLI with the given arguments and streams and returns the
// process exit code (0 ok, 1 error, 2 audit chain tampered).
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdin, stdout, stderr)
}

// runContext is run with a context that stops `serve` when cancelled.
func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCmd(stdin, stdout)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "Error:", err)
	}
	return exitCode(err)
}

func newRootCmd(stdin io.Reader, stdout io.Writer) *cobra.Command {
	var host, token string

	rootCmd := &cobra.Command{
		Use:     "rgt-vault",
		Short:   "rgt-vault — encrypted secrets manager for AI agents",
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&host, "host", defaultHost, "server base URL (client subcommands)")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "bearer token (overrides env RGT_VAULT_TOKEN and ~/.config/rgt-vault/server.token)")

	// --db / --policy / --provider select the vault for every subcommand that
	// opens the vault files (Python's global options).
	var vf servecmd.VaultFlags
	vf.Register(rootCmd, true)

	// Helper to get resolved token at command runtime.
	getToken := func() string { return resolveToken(token) }
	// newCLI resolves the per-invocation HTTP environment at run time.
	newCLI := func() *cli {
		return &cli{host: strings.TrimSuffix(host, "/"), token: getToken(), stdin: stdin, stdout: stdout, client: newHTTPClient()}
	}

	// -----------------------------------------------------------------------
	// set  — write a secret (value from stdin or --value-file)
	// -----------------------------------------------------------------------
	var setNamespace, setAgent, setPurpose, setValueFile string
	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Store a secret (pipe value via stdin or --value-file)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return newCLI().runSet(args[0], setNamespace, setAgent, setPurpose, setValueFile)
		},
	}
	setCmd.Flags().StringVar(&setNamespace, "namespace", "default", "secret namespace")
	setCmd.Flags().StringVar(&setAgent, "agent", "system", "agent identity")
	setCmd.Flags().StringVar(&setPurpose, "purpose", "", "purpose label")
	setCmd.Flags().StringVar(&setValueFile, "value-file", "", "read secret from file instead of stdin")

	// -----------------------------------------------------------------------
	// get  — retrieve / lease a secret
	// -----------------------------------------------------------------------
	var getNamespace, getAgent, getPurpose string
	var getOffline bool
	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Retrieve a secret value",
		Long: "Print a secret's plaintext.\n\n" +
			"By default the value comes from the running server (GET /v1/secrets?name=, a lease\n" +
			"performed server-side; transitional, decision D5). With --offline (or an explicit --db) the\n" +
			"vault files are opened locally instead: operator-only, no server involved, same ABAC\n" +
			"policy (--policy) and the same audit rows. --purpose is required offline.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if getOffline || cmd.Flags().Changed("db") {
				return runGetOffline(cmd.Context(), &vf, args[0], getNamespace, getAgent, getPurpose, stdout)
			}
			return newCLI().runGet(args[0], getNamespace)
		},
	}
	getCmd.Flags().StringVar(&getNamespace, "namespace", "default", "secret namespace")
	getCmd.Flags().StringVar(&getAgent, "agent", "system", "agent identity")
	getCmd.Flags().StringVar(&getPurpose, "purpose", "", "purpose label (required with --offline)")
	getCmd.Flags().BoolVar(&getOffline, "offline", false, "open the vault files locally instead of asking a server (operator only)")

	// -----------------------------------------------------------------------
	// list  — list secrets in a namespace
	// -----------------------------------------------------------------------
	var listNamespace, listAgent string
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets in a namespace",
		RunE:  func(cmd *cobra.Command, args []string) error { return newCLI().runList(listNamespace) },
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
		RunE:  func(cmd *cobra.Command, args []string) error { return newCLI().runRevoke(args[0], revokeNamespace) },
	}
	revokeCmd.Flags().StringVar(&revokeNamespace, "namespace", "default", "secret namespace")

	// -----------------------------------------------------------------------
	// simulate  — simulate a policy decision
	// -----------------------------------------------------------------------
	var simNamespace, simAgent, simPurpose, simAction string
	simulateCmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate a policy decision without accessing secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return newCLI().runSimulate(simAgent, simNamespace, simPurpose, simAction)
		},
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
		RunE:  func(cmd *cobra.Command, args []string) error { return newCLI().runFingerprint(args[0], fpNamespace) },
	}
	fingerprintCmd.Flags().StringVar(&fpNamespace, "namespace", "default", "secret namespace")

	// -----------------------------------------------------------------------
	// rotate  — rotate master key or DEK
	// -----------------------------------------------------------------------
	var rotateTarget string
	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the master key or DEK",
		RunE:  func(cmd *cobra.Command, args []string) error { return newCLI().runRotate(rotateTarget) },
	}
	rotateCmd.Flags().StringVar(&rotateTarget, "target", "master", "what to rotate: master | dek")

	// -----------------------------------------------------------------------
	// verify-audit  — verify audit chain integrity
	// -----------------------------------------------------------------------
	var verifyOffline bool
	verifyAuditCmd := &cobra.Command{
		Use:   "verify-audit",
		Short: "Verify the audit log hash chain",
		Long: "Verify the audit log hash chain: prints OK, or TAMPERED and exits 2.\n\n" +
			"By default the running server verifies its own log. With --offline (or an explicit --db) the\n" +
			"database is opened read-only and checked locally; no server and no master secret are needed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if verifyOffline || cmd.Flags().Changed("db") {
				return runVerifyAuditOffline(cmd.Context(), &vf, stdout)
			}
			return newCLI().runVerifyAudit()
		},
	}
	verifyAuditCmd.Flags().BoolVar(&verifyOffline, "offline", false, "verify the database file directly (read-only)")

	// -----------------------------------------------------------------------
	// audit  — print audit log entries
	// -----------------------------------------------------------------------
	var auditLimit int
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Print audit log entries",
		RunE:  func(cmd *cobra.Command, args []string) error { return newCLI().runAudit(auditLimit) },
	}
	auditCmd.Flags().IntVar(&auditLimit, "limit", 100, "maximum entries to return")

	// -----------------------------------------------------------------------
	// init, serve, status, enroll-2fa, export, import, migrate, provider
	// -----------------------------------------------------------------------
	initCmd := newInitCmd(&vf, stdout)
	serveCmd := servecmd.NewCommand(serveEnv(stdout), &vf)
	var statusOffline bool
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check server health, or summarise the vault files with --offline",
		Long: "Without flags: ask the server's /healthz whether it is up.\n\n" +
			"With --offline (or an explicit --db): open the database read-only and print the vault id, key\n" +
			"epoch, active secrets per namespace, audit row count and the audit chain verdict (exit 2 when\n" +
			"TAMPERED). No server and no master secret are needed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if statusOffline || cmd.Flags().Changed("db") {
				return runStatusOffline(cmd.Context(), &vf, stdout)
			}
			return runStatus(strings.TrimSuffix(host, "/"), stdout)
		},
	}
	statusCmd.Flags().BoolVar(&statusOffline, "offline", false, "summarise the database file directly (read-only)")

	// -----------------------------------------------------------------------
	// mcp  — stdio MCP server bridging to the vault backend
	// -----------------------------------------------------------------------
	var mcpAgent string
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run a stdio MCP server bridging to the vault backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCP(strings.TrimSuffix(host, "/"), getToken(), mcpAgentLabel(mcpAgent), stdin, stdout, cmd.ErrOrStderr())
		},
	}

	mcpCmd.Flags().StringVar(&mcpAgent, "agent", "", "agent label sent with execute_secret (default $RGT_VAULT_MCP_AGENT, else \""+mcp.DefaultAgent+"\"); not an authenticated identity")

	// -----------------------------------------------------------------------
	// tui  — interactive Bubble Tea dashboard
	// -----------------------------------------------------------------------
	var tuiNamespace string
	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive dashboard (read-only by default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(strings.TrimSuffix(host, "/"), getToken(), tuiNamespace)
		},
	}
	tuiCmd.Flags().StringVar(&tuiNamespace, "namespace", "default", "namespace to display")

	rootCmd.AddCommand(setCmd, getCmd, listCmd, revokeCmd, simulateCmd,
		fingerprintCmd, rotateCmd, verifyAuditCmd, auditCmd,
		initCmd, serveCmd, statusCmd, mcpCmd, tuiCmd,
		newEnroll2FACmd(&vf, stdout), newExportCmd(&vf, stdout), newImportCmd(&vf, stdin, stdout),
		newMigrateCmd(&vf, stdout), newProviderCmd(stdin, stdout),
		newCryptoAuditCmd(stdout))
	return rootCmd
}
