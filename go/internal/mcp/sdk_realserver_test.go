package mcp_test

// The go-sdk client drives the MCP server against the REAL internal/server
// router, so a change in the server's plaintext route (D5) breaks this test
// instead of silently breaking lease_secret.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"rgt-vault-server/internal/auth"
	rgtmcp "rgt-vault-server/internal/mcp"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/server/handlers"
)

func TestSDKClient_RealRouter(t *testing.T) {
	ts := auth.NewTokenStore(filepath.Join(t.TempDir(), "server.token"))
	if err := ts.Write(testToken); err != nil {
		t.Fatal(err)
	}
	router := server.NewRouter(handlers.NewHandlers(handlers.NewStore(), ts), server.NewMiddleware(ts))
	backend := httptest.NewServer(router)
	defer backend.Close()

	// Seed a secret through the real API.
	body, _ := json.Marshal(map[string]string{"name": "api-key", "namespace": "prod", "value": "s3cr3t-value", "agent": "bot", "purpose": "ci"})
	req, _ := http.NewRequest(http.MethodPost, backend.URL+"/v1/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	seedClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := seedClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed: HTTP %d", resp.StatusCode)
	}

	s := rgtmcp.NewServer(backend.URL, testToken)
	s.SetLogger(log.New(io.Discard, "", 0))
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	done := make(chan struct{})
	defer func() { <-done }() // runs last: join the server goroutine
	defer c2sW.Close()
	defer s2cR.Close()
	go func() {
		defer close(done)
		_ = s.Serve(c2sR, s2cW)
		_ = s2cW.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "rgt-e2e", Version: "test"}, nil).
		Connect(ctx, &sdk.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer cs.Close()

	call := func(name string, args map[string]any) (string, bool) {
		t.Helper()
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return toolText(t, res), res.IsError
	}
	key := map[string]any{"namespace": "prod", "name": "api-key"}

	if txt, isErr := call("list_secrets", map[string]any{"namespace": "prod"}); isErr || !strings.Contains(txt, `"api-key"`) || strings.Contains(txt, "s3cr3t-value") {
		t.Fatalf("list_secrets: (%q, %v)", txt, isErr)
	}
	if txt, isErr := call("lease_secret", key); isErr || txt != "s3cr3t-value" {
		t.Fatalf("lease_secret against real router: (%q, %v)", txt, isErr)
	}
	if txt, isErr := call("execute_secret", map[string]any{"namespace": "prod", "name": "api-key", "action": "echo"}); isErr || strings.Contains(txt, "s3cr3t-value") {
		t.Fatalf("execute_secret: (%q, %v)", txt, isErr)
	}
	if txt, isErr := call("revoke_secret", key); isErr {
		t.Fatalf("revoke_secret: %q", txt)
	}
	if txt, isErr := call("lease_secret", key); !isErr || txt != "secret not found" {
		t.Fatalf("lease after revoke: (%q, %v)", txt, isErr)
	}
}
