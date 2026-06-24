// Command server starts the rgt-vault HTTP server on :8080.
//
// Usage:
//
//	go run ./cmd/server
//
// The server listens on 0.0.0.0:8080 and provides a REST API for managing
// secrets with bearer-token authentication.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/server/handlers"
)

func main() {
	// Determine token file path
	tokenPath := os.Getenv("RGT_VAULT_TOKEN_FILE")
	if tokenPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		tokenPath = filepath.Join(home, ".config", "rgt-vault", "server.token")
	}

	// Load or create the bearer token
	path, token, err := auth.LoadOrCreateToken(tokenPath)
	if err != nil {
		log.Fatalf("Failed to load/create token: %v", err)
	}
	log.Printf("Token file: %s", path)
	log.Printf("Bearer token: %s", token)
	log.Printf("Token ID: %s", auth.TokenID(token))

	// Create the token store
	tokenStore := auth.NewTokenStore(path)

	// Create the in-memory secret store
	store := handlers.NewStore()

	// Create the handlers
	h := handlers.NewHandlers(store, tokenStore)

	// Create the middleware
	mw := server.NewMiddleware(tokenStore)

	// Create the router
	router := server.NewRouter(h, mw)

	// Print startup banner
	fmt.Println("=" + "==============================================")
	fmt.Println("  rgt-vault Go server v0.2.0")
	fmt.Printf("  Listening on :8080\n")
	fmt.Printf("  Health check: http://localhost:8080/healthz\n")
	fmt.Printf("  Auth: Bearer %s\n", token)
	fmt.Println("=" + "==============================================")

	// Start the server
	addr := ":8080"
	log.Printf("Starting HTTP server on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
