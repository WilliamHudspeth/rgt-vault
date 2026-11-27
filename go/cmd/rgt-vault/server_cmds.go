package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/mcp"
	"rgt-vault-server/internal/netguard"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/server/handlers"
	"rgt-vault-server/internal/tui"
)

// defaultTokenPath is ~/.config/rgt-vault/server.token ("" if no home dir).
func defaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "rgt-vault", "server.token")
}

func runInit(tokenPath string, out io.Writer) error {
	if tokenPath == "" {
		return fmt.Errorf("no token path: home directory unknown, pass --token-file")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generating token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	dir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	// Write a fresh 0600 temp file and rename it over the target, so the new
	// token is never readable through a pre-existing file's looser mode.
	tmp, err := os.CreateTemp(dir, ".server.token-*")
	if err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restricting token file: %w", err)
	}
	if _, err := tmp.WriteString(token); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}
	if err := os.Rename(tmpName, tokenPath); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}
	fmt.Fprintf(out, "Vault initialised. Token written to: %s\n", tokenPath)
	return nil
}

// newServeHandler builds the HTTP handler for `serve` (real router + bearer
// auth from the token file, created on first use).
func newServeHandler(tokenPath string) (http.Handler, string, error) {
	if tokenPath == "" {
		return nil, "", fmt.Errorf("no token path: home directory unknown, pass --token-file")
	}
	path, _, err := auth.LoadOrCreateToken(tokenPath)
	if err != nil {
		return nil, "", fmt.Errorf("loading token: %w", err)
	}
	// LoadOrCreateToken reuses an existing file as-is; tighten it.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, "", fmt.Errorf("restricting token file: %w", err)
	}
	tokenStore := auth.NewTokenStore(path)
	h := handlers.NewHandlers(handlers.NewStore(), tokenStore)
	return server.NewRouter(h, server.NewMiddleware(tokenStore)), path, nil
}

// isLoopbackAddr reports whether host:port binds only to loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func runServe(addr, tokenPath string, allowNonLoopback bool, out io.Writer) error {
	if !isLoopbackAddr(addr) && !allowNonLoopback {
		return fmt.Errorf("refusing to bind %s: not a loopback address (pass --allow-non-loopback to override)", addr)
	}
	handler, path, err := newServeHandler(tokenPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "rgt-vault server listening on %s (token file: %s)\n", addr, path)
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// runMCP serves MCP on in/out. out is the protocol channel; backend error
// details go to errOut (the command's stderr), never to out.
func runMCP(host, token string, in io.Reader, out, errOut io.Writer) error {
	s := mcp.NewServer(host, token)
	s.SetLogger(log.New(errOut, "rgt-vault mcp: ", log.LstdFlags))
	return s.Serve(in, out)
}

func runTUI(host, token, namespace string) error {
	client := tui.NewHTTPClient(host, token)
	m := tui.New(client, namespace)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func runStatus(host string, out io.Writer) error {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: netguard.NewDialer(true).DialContext},
	}
	resp, err := client.Get(host + "/healthz")
	if err != nil {
		fmt.Fprintf(out, "Server unreachable: %s\n", host)
		return fmt.Errorf("health check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Fprintf(out, "Server OK: %s\n", host)
		return nil
	}
	fmt.Fprintf(out, "Server unreachable: %s (HTTP %d)\n", host, resp.StatusCode)
	return fmt.Errorf("unexpected status: %d", resp.StatusCode)
}
