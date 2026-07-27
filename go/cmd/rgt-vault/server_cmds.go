package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/mcp"
	"rgt-vault-server/internal/netguard"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/server/handlers"
	"rgt-vault-server/internal/tui"
)

func runInit() error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generating token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	cfgDir := filepath.Join(home, ".config", "rgt-vault")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	tokenPath := filepath.Join(cfgDir, "server.token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}
	fmt.Printf("Vault initialised. Token written to: %s\n", tokenPath)
	return nil
}

func runServe(addr string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	tokenPath := filepath.Join(home, ".config", "rgt-vault", "server.token")

	// LoadOrCreateToken returns (path, token, error)
	path, _, err := auth.LoadOrCreateToken(tokenPath)
	if err != nil {
		return fmt.Errorf("loading token: %w", err)
	}

	tokenStore := auth.NewTokenStore(path)
	store := handlers.NewStore()
	h := handlers.NewHandlers(store, tokenStore)
	mw := server.NewMiddleware(tokenStore)
	router := server.NewRouter(h, mw)

	fmt.Printf("rgt-vault server listening on %s\n", addr)
	return http.ListenAndServe(addr, router)
}

func runMCP(host, token string) error {
	return mcp.NewServer(host, token).Serve(os.Stdin, os.Stdout)
}

func runTUI(host, token, namespace string) error {
	client := tui.NewHTTPClient(host, token)
	m := tui.New(client, namespace)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func runStatus(host string) error {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: netguard.NewDialer(true).DialContext},
	}
	resp, err := client.Get(host + "/healthz")
	if err != nil {
		fmt.Printf("Server unreachable: %s\n", host)
		return fmt.Errorf("health check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Server OK: %s\n", host)
		return nil
	}
	fmt.Printf("Server unreachable: %s (HTTP %d)\n", host, resp.StatusCode)
	return fmt.Errorf("unexpected status: %d", resp.StatusCode)
}
