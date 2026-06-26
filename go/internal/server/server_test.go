// Package server contains integration tests for the rgt-vault Go server.
//
// Tests cover:
//  1. Health check endpoint (no auth required)
//  2. Authentication middleware (rejects missing/invalid tokens)
//  3. Secret CRUD operations (set, get, list, delete)
//  4. Audit log endpoint
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server/handlers"
)

// setupTestServer creates a test server with a fresh token and store.
func setupTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "server.token")

	// Generate and write a token
	token, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	tokenStore := auth.NewTokenStore(tokenPath)
	if err := tokenStore.Write(token); err != nil {
		t.Fatalf("Failed to write token: %v", err)
	}

	// Create store and handlers
	store := handlers.NewStore()
	h := handlers.NewHandlers(store, tokenStore)

	// Create middleware and router
	mw := NewMiddleware(tokenStore)
	router := NewRouter(h, mw)

	ts := httptest.NewServer(router)
	return ts, token
}

// authHeader returns the Authorization header value for the given token.
func authHeader(token string) string {
	return "Bearer " + token
}

// doJSON performs an HTTP request and decodes the JSON response.
func doJSON(t *testing.T, method, url, token string, body interface{}) (*http.Response, map[string]interface{}) {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if token != "" {
		req.Header.Set("Authorization", authHeader(token))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	var result map[string]interface{}
	if resp.Body != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			// Empty body or non-JSON - not an error for some tests
			result = nil
		}
	}

	return resp, result
}

// ---------------------------------------------------------------------------
// Test 1: Health check returns real JSON status (no auth required)
// ---------------------------------------------------------------------------

func TestHealthCheck(t *testing.T) {
	ts, _ := setupTestServer(t)
	defer ts.Close()

	resp, result := doJSON(t, "GET", ts.URL+"/healthz", "", nil)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if result == nil {
		t.Fatal("Expected JSON response body")
	}

	if status, ok := result["status"].(string); !ok || status != "ok" {
		t.Errorf("Expected status 'ok', got %v", result["status"])
	}

	if vaultID, ok := result["vault_id"].(string); !ok || vaultID == "" {
		t.Errorf("Expected non-empty vault_id, got %v", result["vault_id"])
	}

	if _, ok := result["key_epoch"]; !ok {
		t.Error("Expected key_epoch in response")
	}

	t.Logf("Health check response: %+v", result)
}

// ---------------------------------------------------------------------------
// Test 2: Auth middleware rejects missing and invalid tokens
// ---------------------------------------------------------------------------

func TestAuthRejectsUnauthorized(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	// Test missing auth header
	resp, result := doJSON(t, "GET", ts.URL+"/v1/secrets?namespace=default", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing auth, got %d", resp.StatusCode)
	}
	if result != nil {
		t.Logf("Missing auth response: %+v", result)
	}

	// Test invalid token
	resp, result = doJSON(t, "GET", ts.URL+"/v1/secrets?namespace=default", "invalid-token", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid token, got %d", resp.StatusCode)
	}
	if result != nil {
		t.Logf("Invalid auth response: %+v", result)
	}

	// Test valid token works
	resp, result = doJSON(t, "GET", ts.URL+"/v1/secrets?namespace=default", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for valid token, got %d", resp.StatusCode)
	}
	if result != nil {
		t.Logf("Valid auth response: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Secret CRUD operations (set, get, list, delete)
// ---------------------------------------------------------------------------

func TestSecretCRUD(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	// SET a secret
	setBody := map[string]interface{}{
		"name":      "api-key",
		"value":     "sk-1234567890abcdef",
		"namespace": "default",
		"agent":     "test-agent",
		"purpose":   "integration-test",
	}
	resp, result := doJSON(t, "POST", baseURL+"/v1/secrets", token, setBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SetSecret failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("Expected ok=true, got %v", result["ok"])
	}
	t.Logf("SetSecret response: %+v", result)

	// GET the secret
	resp, result = doJSON(t, "GET", baseURL+"/v1/secrets/default/api-key", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetSecret failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if name, _ := result["name"].(string); name != "api-key" {
		t.Errorf("Expected name='api-key', got %q", name)
	}
	if ns, _ := result["namespace"].(string); ns != "default" {
		t.Errorf("Expected namespace='default', got %q", ns)
	}
	t.Logf("GetSecret response: %+v", result)

	// LIST secrets
	resp, result = doJSON(t, "GET", baseURL+"/v1/secrets?namespace=default", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListSecrets failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	secrets, ok := result["secrets"].([]interface{})
	if !ok {
		t.Fatalf("Expected secrets array, got %T", result["secrets"])
	}
	if len(secrets) != 1 {
		t.Errorf("Expected 1 secret, got %d", len(secrets))
	}
	t.Logf("ListSecrets response: %+v", result)

	// DELETE the secret
	resp, result = doJSON(t, "DELETE", baseURL+"/v1/secrets/default/api-key", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteSecret failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("Expected ok=true, got %v", result["ok"])
	}

	// Verify secret is gone
	resp, result = doJSON(t, "GET", baseURL+"/v1/secrets/default/api-key", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for deleted secret, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Audit log endpoint returns entries
// ---------------------------------------------------------------------------

func TestAuditLog(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	// First, create a few secrets to generate audit entries
	for i := 1; i <= 3; i++ {
		setBody := map[string]interface{}{
			"name":      fmt.Sprintf("secret-%d", i),
			"value":     fmt.Sprintf("value-%d", i),
			"namespace": "default",
			"agent":     "audit-test",
		}
		resp, _ := doJSON(t, "POST", baseURL+"/v1/secrets", token, setBody)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("SetSecret %d failed: status=%d", i, resp.StatusCode)
		}
	}

	// Now fetch the audit log
	resp, result := doJSON(t, "GET", baseURL+"/v1/audit?limit=10", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Audit failed: status=%d, body=%+v", resp.StatusCode, result)
	}

	entries, ok := result["entries"].([]interface{})
	if !ok {
		t.Fatalf("Expected entries array, got %T", result["entries"])
	}
	if len(entries) < 3 {
		t.Errorf("Expected at least 3 audit entries, got %d", len(entries))
	}

	// Check that entries have expected fields
	for i, entry := range entries {
		e, ok := entry.(map[string]interface{})
		if !ok {
			t.Errorf("Entry %d is not a map: %T", i, entry)
			continue
		}
		if _, ok := e["timestamp"]; !ok {
			t.Errorf("Entry %d missing 'timestamp'", i)
		}
		if _, ok := e["event"]; !ok {
			t.Errorf("Entry %d missing 'event'", i)
		}
		if _, ok := e["hash"]; !ok {
			t.Errorf("Entry %d missing 'hash'", i)
		}
	}

	t.Logf("Audit log has %d entries", len(entries))
	t.Logf("First entry: %+v", entries[0])
}

// ---------------------------------------------------------------------------
// Test 5: Rotate endpoint
// ---------------------------------------------------------------------------

func TestRotate(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	// Rotate master key
	rotateBody := map[string]interface{}{
		"target": "master",
	}
	resp, result := doJSON(t, "POST", baseURL+"/v1/rotate", token, rotateBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Rotate master failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("Expected ok=true, got %v", result["ok"])
	}
	if target, _ := result["target"].(string); target != "master" {
		t.Errorf("Expected target='master', got %q", target)
	}
	t.Logf("Rotate master response: %+v", result)

	// Rotate DEK
	rotateBody["target"] = "dek"
	resp, result = doJSON(t, "POST", baseURL+"/v1/rotate", token, rotateBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Rotate dek failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if target, _ := result["target"].(string); target != "dek" {
		t.Errorf("Expected target='dek', got %q", target)
	}

	// Invalid target
	rotateBody["target"] = "invalid"
	resp, result = doJSON(t, "POST", baseURL+"/v1/rotate", token, rotateBody)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid target, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Use secret endpoint
// ---------------------------------------------------------------------------

func TestUseSecret(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	// Create a secret first
	setBody := map[string]interface{}{
		"name":      "test-secret",
		"value":     "my-secret-value",
		"namespace": "default",
		"agent":     "use-test",
	}
	resp, _ := doJSON(t, "POST", baseURL+"/v1/secrets", token, setBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SetSecret failed: status=%d", resp.StatusCode)
	}

	// Use the secret
	useBody := map[string]interface{}{
		"action":  "echo",
		"agent":   "use-test",
		"purpose": "testing",
		"params":  map[string]interface{}{"message": "hello"},
	}
	resp, result := doJSON(t, "POST", baseURL+"/v1/secrets/default/test-secret/use", token, useBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UseSecret failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("Expected ok=true, got %v", result["ok"])
	}
	if action, _ := result["action"].(string); action != "echo" {
		t.Errorf("Expected action='echo', got %q", action)
	}
	t.Logf("UseSecret response: %+v", result)

	// Use non-existent secret
	resp, result = doJSON(t, "POST", baseURL+"/v1/secrets/default/nonexistent/use", token, useBody)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for nonexistent secret, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Policy simulate endpoint
// ---------------------------------------------------------------------------

func TestPolicySimulate(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	simBody := map[string]interface{}{
		"agent":     "test-agent",
		"namespace": "default",
		"purpose":   "testing",
		"action":    "read",
	}
	resp, result := doJSON(t, "POST", baseURL+"/v1/policy/simulate", token, simBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PolicySimulate failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if allowed, _ := result["allowed"].(bool); !allowed {
		t.Errorf("Expected allowed=true, got %v", result["allowed"])
	}
	t.Logf("PolicySimulate response: %+v", result)
}

// ---------------------------------------------------------------------------
// Test 8: Audit verify endpoint
// ---------------------------------------------------------------------------

func TestAuditVerify(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	resp, result := doJSON(t, "POST", baseURL+"/v1/audit/verify", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AuditVerify failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("Expected ok=true, got %v", result["ok"])
	}
	t.Logf("AuditVerify response: %+v", result)
}

// ---------------------------------------------------------------------------
// Test 9: Validation errors
// ---------------------------------------------------------------------------

func TestValidationErrors(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	// Test missing name
	body := map[string]interface{}{
		"value":     "some-value",
		"namespace": "default",
	}
	resp, result := doJSON(t, "POST", baseURL+"/v1/secrets", token, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing name, got %d", resp.StatusCode)
	}
	if result != nil {
		t.Logf("Validation error response: %+v", result)
	}

	// Test missing value
	body = map[string]interface{}{
		"name":      "some-name",
		"namespace": "default",
	}
	resp, result = doJSON(t, "POST", baseURL+"/v1/secrets", token, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing value, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 10: List actions endpoint
// ---------------------------------------------------------------------------

func TestListActions(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	resp, result := doJSON(t, "GET", baseURL+"/v1/actions", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListActions failed: status=%d, body=%+v", resp.StatusCode, result)
	}

	actions, ok := result["actions"].([]interface{})
	if !ok {
		t.Fatalf("Expected actions array, got %T", result["actions"])
	}
	if len(actions) < 1 {
		t.Error("Expected at least 1 action")
	}
	t.Logf("ListActions response: %+v", result)
}

// ---------------------------------------------------------------------------
// Test 11: Revoke secret
// ---------------------------------------------------------------------------

func TestRevokeSecret(t *testing.T) {
	ts, token := setupTestServer(t)
	defer ts.Close()

	baseURL := ts.URL

	// Create a secret first
	setBody := map[string]interface{}{
		"name":      "revoke-test",
		"value":     "to-be-revoked",
		"namespace": "default",
		"agent":     "revoke-test",
	}
	resp, _ := doJSON(t, "POST", baseURL+"/v1/secrets", token, setBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SetSecret failed: status=%d", resp.StatusCode)
	}

	// Revoke it
	resp, result := doJSON(t, "POST", baseURL+"/v1/secrets/default/revoke-test/revoke", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("RevokeSecret failed: status=%d, body=%+v", resp.StatusCode, result)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("Expected ok=true, got %v", result["ok"])
	}

	// Verify secret is gone
	resp, _ = doJSON(t, "GET", baseURL+"/v1/secrets/default/revoke-test", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for revoked secret, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Health check
// ---------------------------------------------------------------------------

func BenchmarkHealthCheck(b *testing.B) {
	// Create minimal setup without httptest.Server overhead per iteration
	tmpDir := b.TempDir()
	tokenPath := filepath.Join(tmpDir, "server.token")
	token, _ := auth.GenerateToken()
	tokenStore := auth.NewTokenStore(tokenPath)
	tokenStore.Write(token)

	store := handlers.NewStore()
	h := handlers.NewHandlers(store, tokenStore)
	mw := NewMiddleware(tokenStore)
	router := NewRouter(h, mw)

	ts := httptest.NewServer(router)
	defer ts.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Milestone 2 tests: Server header stripping and XML policy caching
// ---------------------------------------------------------------------------

func TestServerHeaderAndDebugStripped(t *testing.T) {
	ts, _ := setupTestServer(t)
	defer ts.Close()

	resp, _ := doJSON(t, "GET", ts.URL+"/healthz", "", nil)

	// Verify server metadata headers are stripped (RGT-452)
	if serverHeader := resp.Header.Get("Server"); serverHeader != "" {
		t.Errorf("Expected Server header to be empty, got %q", serverHeader)
	}
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		t.Errorf("Expected X-Powered-By header to be empty, got %q", poweredBy)
	}
}

func TestXMLPoliciesCacheDisabled(t *testing.T) {
	ts, _ := setupTestServer(t)
	defer ts.Close()

	paths := []string{"/crossdomain.xml", "/clientaccesspolicy.xml"}
	for _, path := range paths {
		resp, _ := doJSON(t, "GET", ts.URL+path, "", nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for %s, got %d", path, resp.StatusCode)
		}

		// Verify Cache-Control directives (RGT-437)
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store, no-cache, must-revalidate, max-age=0" {
			t.Errorf("Expected strict Cache-Control for %s, got %q", path, cc)
		}
		if pragma := resp.Header.Get("Pragma"); pragma != "no-cache" {
			t.Errorf("Expected Pragma: no-cache, got %q", pragma)
		}
		if expires := resp.Header.Get("Expires"); expires != "0" {
			t.Errorf("Expected Expires: 0, got %q", expires)
		}
	}
}
