// Command server starts the rgt-vault HTTP server.
//
// Usage:
//
//	go run ./cmd/server [--host 127.0.0.1] [--port 8080] [--token-file PATH]
//
// By default the server binds to the loopback interface only (127.0.0.1) and
// provides a REST API for managing secrets with bearer-token authentication.
//
// Configuration (flag overrides environment, environment overrides default):
//
//	--host / RGT_VAULT_HOST         listen address, default 127.0.0.1
//	--port / RGT_VAULT_PORT         listen port, default 8080
//	--token-file / RGT_VAULT_TOKEN_FILE   default ~/.config/rgt-vault/server.token
//	CORS_ALLOWED_ORIGINS            comma-separated exact origins; unset = no CORS
//	RGT_VAULT_MAX_BODY_BYTES        request body limit, default 1 MiB
//
// The bearer token is NEVER printed or logged. Only the token file path and a
// short token id (a hash prefix) appear in output.
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
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/server/handlers"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = "8080"
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
	tokenFile := fs.String("token-file", "", "bearer token file (env RGT_VAULT_TOKEN_FILE)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	cfg := config{
		host:      firstNonEmpty(*host, getenv("RGT_VAULT_HOST"), defaultHost),
		port:      firstNonEmpty(*port, getenv("RGT_VAULT_PORT"), defaultPort),
		tokenFile: firstNonEmpty(*tokenFile, getenv("RGT_VAULT_TOKEN_FILE")),
		maxBody:   server.DefaultMaxBodyBytes,
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
	store := handlers.NewStore()
	h := handlers.NewHandlers(store, tokenStore)

	mw := server.NewMiddleware(tokenStore)
	mw.AllowedOrigins = cfg.origins
	mw.MaxBodyBytes = cfg.maxBody
	router := server.NewRouter(h, mw)

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
	fmt.Fprintln(stdout, "  rgt-vault Go server v0.2.0")
	fmt.Fprintf(stdout, "  Listening on %s\n", addr)
	fmt.Fprintf(stdout, "  Health check: http://%s/healthz\n", addr)
	fmt.Fprintf(stdout, "  Auth: Bearer token from %s (id %s)\n", path, tokenID)
	fmt.Fprintln(stdout, "==============================================")

	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
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
