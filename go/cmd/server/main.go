// Command server starts the rgt-vault HTTP server on the real vault
// (internal/vault): the same vault.db + keychain.json files as the Python
// line, the ABAC policy, the hash-chained audit log and, optionally, the
// live approval broker with TOTP.
//
// Usage:
//
//	go run ./cmd/server [--db PATH] [--policy FILE] [--provider keyring|platform]
//	                    [--host 127.0.0.1] [--port 8765] [--token-file PATH]
//	                    [--operator-token-file PATH] [--require-approval
//	                    [--totp-secret-file PATH] [--approval-timeout 120s]]
//	                    [--harness-key-file PATH] [--allow-private-network]
//
// By default the server binds to the loopback interface only (127.0.0.1:8765,
// Python's default, decision D6).
//
// Configuration (flag overrides environment, environment overrides default):
//
//	--db / RGT_VAULT_DB                   default ~/.secure-vault/vault.db
//	--policy / RGT_VAULT_POLICY           ABAC policy YAML; unset = deny everything
//	--provider / RGT_VAULT_PROVIDER       keyring (default) or platform
//	--host / RGT_VAULT_HOST               listen address, default 127.0.0.1
//	--port / RGT_VAULT_PORT               listen port, default 8765
//	--token-file / RGT_VAULT_TOKEN_FILE   default ~/.config/rgt-vault/server.token
//	--operator-token-file / RGT_VAULT_OPERATOR_TOKEN_FILE
//	                                      token for /v1/requests* (approve/deny)
//	--require-approval                    live approval of every unseal
//	--totp-secret-file / RGT_VAULT_TOTP_SECRET_FILE   base32 secret (2FA approvals)
//	--approval-timeout                    default 120s
//	--harness-key-file / RGT_VAULT_HARNESS_KEY_FILE   HMAC key for v2 capability
//	                                      tokens; unset = capability execution
//	                                      fails closed
//	--allow-private-network               built-in HTTP actions may reach private
//	                                      addresses (SSRF risk)
//	CORS_ALLOWED_ORIGINS                  comma-separated exact origins; unset = no CORS
//	RGT_VAULT_MAX_BODY_BYTES              request body limit, default 1 MiB
//
// The bearer tokens are NEVER printed or logged. Only the token file paths
// and short token ids (a hash prefix) appear in output.
//
// TODO(G10): `rgt-vault serve` (go/cmd/rgt-vault) gets the same flags via
// server.OpenStack + server.New and this command becomes its alias.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/vault"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = "8765"
)

// Test seams: tests swap in an in-memory master provider and cheap Argon2
// parameters. Production uses server.NewProvider and Python's defaults.
var (
	newProvider = server.NewProvider
	kdfParams   kdf.Params
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, log.Default(), nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// config is the resolved server configuration.
type config struct {
	host      string
	port      string
	tokenFile string
	origins   []string
	rejected  []string
	maxBody   int64

	db                  string
	policy              string
	provider            string
	operatorTokenFile   string
	requireApproval     bool
	totpSecretFile      string
	approvalTimeout     time.Duration
	harnessKeyFile      string
	allowPrivateNetwork bool
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseConfig resolves flags, then environment, then defaults.
func parseConfig(args []string, getenv func(string) string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "", "listen address (env RGT_VAULT_HOST, default "+defaultHost+")")
	port := fs.String("port", "", "listen port (env RGT_VAULT_PORT, default "+defaultPort+")")
	tokenFile := fs.String("token-file", "", "agent bearer token file (env RGT_VAULT_TOKEN_FILE)")
	db := fs.String("db", "", "vault database (env RGT_VAULT_DB, default "+server.DefaultDBPath+")")
	policy := fs.String("policy", "", "ABAC policy YAML (env RGT_VAULT_POLICY; default: deny everything)")
	provider := fs.String("provider", "", "master-secret provider: keyring or platform (env RGT_VAULT_PROVIDER, default keyring)")
	operatorTokenFile := fs.String("operator-token-file", "", "operator token for approve/deny (env RGT_VAULT_OPERATOR_TOKEN_FILE)")
	requireApproval := fs.Bool("require-approval", false, "require live operator approval for every unseal")
	totpSecretFile := fs.String("totp-secret-file", "", "base32 TOTP secret for 2FA approvals (env RGT_VAULT_TOTP_SECRET_FILE)")
	approvalTimeout := fs.Duration("approval-timeout", 120*time.Second, "how long an approval request waits before it is denied")
	harnessKeyFile := fs.String("harness-key-file", "", "HMAC key for v2 capability tokens (env RGT_VAULT_HARNESS_KEY_FILE)")
	allowPrivate := fs.Bool("allow-private-network", false, "let built-in HTTP actions reach loopback/private addresses (SSRF risk)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *approvalTimeout <= 0 {
		return config{}, fmt.Errorf("invalid --approval-timeout %s", *approvalTimeout)
	}

	cfg := config{
		host:      firstNonEmpty(*host, getenv("RGT_VAULT_HOST"), defaultHost),
		port:      firstNonEmpty(*port, getenv("RGT_VAULT_PORT"), defaultPort),
		tokenFile: firstNonEmpty(*tokenFile, getenv("RGT_VAULT_TOKEN_FILE")),
		maxBody:   server.DefaultMaxBodyBytes,

		db:                  firstNonEmpty(*db, getenv("RGT_VAULT_DB"), server.DefaultDBPath),
		policy:              firstNonEmpty(*policy, getenv("RGT_VAULT_POLICY")),
		provider:            firstNonEmpty(*provider, getenv("RGT_VAULT_PROVIDER"), server.ProviderKeyring),
		operatorTokenFile:   firstNonEmpty(*operatorTokenFile, getenv("RGT_VAULT_OPERATOR_TOKEN_FILE")),
		requireApproval:     *requireApproval,
		totpSecretFile:      firstNonEmpty(*totpSecretFile, getenv("RGT_VAULT_TOTP_SECRET_FILE")),
		approvalTimeout:     *approvalTimeout,
		harnessKeyFile:      firstNonEmpty(*harnessKeyFile, getenv("RGT_VAULT_HARNESS_KEY_FILE")),
		allowPrivateNetwork: *allowPrivate,
	}
	if cfg.provider != server.ProviderKeyring && cfg.provider != server.ProviderPlatform {
		return config{}, fmt.Errorf("unknown provider %q: use 'keyring' or 'platform'", cfg.provider)
	}
	if cfg.totpSecretFile != "" && !cfg.requireApproval {
		return config{}, errors.New("--totp-secret-file needs --require-approval")
	}
	if p, err := strconv.Atoi(cfg.port); err != nil || p < 0 || p > 65535 {
		return config{}, fmt.Errorf("invalid port %q", cfg.port)
	}
	if v := getenv("RGT_VAULT_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return config{}, fmt.Errorf("invalid RGT_VAULT_MAX_BODY_BYTES %q", v)
		}
		cfg.maxBody = n
	}
	cfg.origins, cfg.rejected = server.ParseAllowedOrigins(getenv("CORS_ALLOWED_ORIGINS"))

	if cfg.tokenFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return config{}, fmt.Errorf("failed to get home directory: %w", err)
		}
		cfg.tokenFile = filepath.Join(home, ".config", "rgt-vault", "server.token")
	}
	return cfg, nil
}

// writeTimeout bounds writing a response. A request waiting for operator
// approval holds its response until the broker decides (up to the approval
// timeout), so the limit must outlast it or an approved lease could not be
// answered.
func writeTimeout(cfg config) time.Duration {
	const base = 60 * time.Second
	if cfg.requireApproval {
		return cfg.approvalTimeout + base
	}
	return base
}

// isLoopback reports whether host is a loopback address or "localhost".
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// run builds and serves until ctx is cancelled. ready, if non-nil, is called
// with the bound address once the listener is up (used by tests).
func run(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, logger *log.Logger, ready func(addr string)) error {
	cfg, err := parseConfig(args, getenv, stdout)
	if err != nil {
		return err
	}

	// Load or create the bearer token. The token itself is never printed.
	path, token, err := auth.LoadOrCreateToken(cfg.tokenFile)
	if err != nil {
		return fmt.Errorf("failed to load/create token: %w", err)
	}
	tokenID := auth.TokenID(token)
	logger.Printf("Token file: %s", path)
	logger.Printf("Token ID: %s", tokenID)
	for _, bad := range cfg.rejected {
		logger.Printf("WARNING: ignoring CORS origin %q (wildcards and \"null\" are not accepted)", bad)
	}

	tokenStore := auth.NewTokenStore(path)

	var operatorStore *auth.TokenStore
	if cfg.operatorTokenFile != "" {
		opPath, opToken, err := auth.LoadOrCreateToken(cfg.operatorTokenFile)
		if err != nil {
			return fmt.Errorf("failed to load/create operator token: %w", err)
		}
		if opToken == token {
			return errors.New("the operator token must differ from the agent token")
		}
		operatorStore = auth.NewTokenStore(opPath)
		logger.Printf("Operator token file: %s (id %s)", opPath, auth.TokenID(opToken))
	} else if cfg.requireApproval {
		logger.Printf("WARNING: --require-approval is on but no --operator-token-file was given. " +
			"The approve/deny endpoints will accept the agent token, so an agent could " +
			"self-approve. Pass --operator-token-file to separate the operator scope.")
	}
	if cfg.allowPrivateNetwork {
		logger.Printf("WARNING: --allow-private-network enables the built-in HTTP actions to call " +
			"loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to " +
			"probe internal services (SSRF). Only enable on trusted networks.")
	}

	var prov vault.MasterProvider
	if prov, err = newProvider(cfg.provider); err != nil {
		return err
	}
	stack, err := server.OpenStack(ctx, server.StackOptions{
		DBPath:              cfg.db,
		PolicyFile:          cfg.policy,
		MasterProvider:      prov,
		RequireApproval:     cfg.requireApproval,
		TOTPSecretFile:      cfg.totpSecretFile,
		ApprovalTimeout:     cfg.approvalTimeout,
		HarnessKeyFile:      cfg.harnessKeyFile,
		AllowPrivateNetwork: cfg.allowPrivateNetwork,
		KDFParams:           kdfParams,
	})
	if err != nil {
		return fmt.Errorf("failed to open vault: %w", err)
	}
	defer func() {
		if cerr := stack.Close(); cerr != nil {
			logger.Printf("closing vault: %v", cerr)
		}
	}()
	if cfg.policy == "" {
		logger.Printf("WARNING: no --policy given: every secret request is denied (default deny)")
	}
	if cfg.harnessKeyFile == "" {
		logger.Printf("No --harness-key-file: /v1/capabilities/execute fails closed")
	}

	router, err := server.New(server.Config{
		Vault:          stack.Vault,
		AgentTokens:    tokenStore,
		OperatorTokens: operatorStore,
		Broker:         stack.Broker,
		Actions:        stack.Actions,
		Capabilities:   stack.Capabilities,
		AllowedOrigins: cfg.origins,
		MaxBodyBytes:   cfg.maxBody,
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.host, cfg.port))
	if err != nil {
		return err
	}
	addr := ln.Addr().String()

	if !isLoopback(cfg.host) {
		logger.Printf("WARNING: listening on non-loopback address %s over plain HTTP; "+
			"put a TLS reverse proxy in front and firewall the port", addr)
	}

	fmt.Fprintln(stdout, "==============================================")
	fmt.Fprintln(stdout, "  rgt-vault Go server v0.3.0")
	fmt.Fprintf(stdout, "  Listening on %s\n", addr)
	fmt.Fprintf(stdout, "  Vault: %s (id %s, epoch %d)\n", stack.DBPath, stack.Vault.VaultID(), stack.Vault.KeyEpoch())
	fmt.Fprintf(stdout, "  Health check: http://%s/healthz\n", addr)
	fmt.Fprintf(stdout, "  Auth: Bearer token from %s (id %s)\n", path, tokenID)
	fmt.Fprintln(stdout, "==============================================")

	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout(cfg),
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	logger.Printf("Starting HTTP server on %s", addr)
	if ready != nil {
		ready(addr)
	}

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Graceful drain timed out: force-close remaining connections.
			logger.Printf("graceful shutdown incomplete (%v); closing connections", err)
			_ = srv.Close()
		}
		return nil
	}
}
