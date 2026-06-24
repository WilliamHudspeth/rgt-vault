package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Shared HTTP helper
// ---------------------------------------------------------------------------

func makeRequest(method, url, token string, body any) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = strings.NewReader(string(b))
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

func runSet(host, token, name, namespace, agent, purpose, valueFile string) error {
	var value string
	if valueFile != "" {
		data, err := os.ReadFile(valueFile)
		if err != nil {
			return fmt.Errorf("reading value file: %w", err)
		}
		value = strings.TrimRight(string(data), "\r\n")
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		value = strings.TrimRight(string(data), "\r\n")
	}

	reqBody := struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Value     string `json:"value"`
		Agent     string `json:"agent"`
		Purpose   string `json:"purpose"`
	}{Name: name, Namespace: namespace, Value: value, Agent: agent, Purpose: purpose}

	_, status, err := makeRequest("POST", host+"/v1/secrets", token, reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("set failed: HTTP %d", status)
	}
	fmt.Println("Secret stored.")
	return nil
}

// listResponse matches {"namespace":"...","secrets":[...]} from GET /v1/secrets
type listResponse struct {
	Namespace string `json:"namespace"`
	Secrets   []struct {
		Name      string `json:"name"`
		Value     string `json:"value"`
		CreatedAt string `json:"created_at"`
	} `json:"secrets"`
}

func runGet(host, token, name, namespace, agent, purpose string) error {
	url := fmt.Sprintf("%s/v1/secrets?namespace=%s&name=%s", host, namespace, name)
	body, status, err := makeRequest("GET", url, token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("get failed: HTTP %d", status)
	}
	var resp listResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	for _, s := range resp.Secrets {
		if s.Name == name {
			fmt.Println(s.Value)
			return nil
		}
	}
	return fmt.Errorf("secret %q not found in namespace %q", name, namespace)
}

func runList(host, token, namespace, agent string) error {
	url := fmt.Sprintf("%s/v1/secrets?namespace=%s", host, namespace)
	body, status, err := makeRequest("GET", url, token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("list failed: HTTP %d", status)
	}
	var resp listResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	for _, s := range resp.Secrets {
		fmt.Printf("%s\t%s\n", s.Name, s.CreatedAt)
	}
	return nil
}

func runRevoke(host, token, name, namespace string) error {
	url := fmt.Sprintf("%s/v1/secrets/%s/%s/revoke", host, namespace, name)
	_, status, err := makeRequest("POST", url, token, struct{}{})
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("revoke failed: HTTP %d", status)
	}
	fmt.Println("Secret revoked.")
	return nil
}

func runSimulate(host, token, agent, namespace, purpose, action string) error {
	reqBody := struct {
		Agent     string `json:"agent"`
		Namespace string `json:"namespace"`
		Purpose   string `json:"purpose"`
		Action    string `json:"action"`
	}{Agent: agent, Namespace: namespace, Purpose: purpose, Action: action}

	body, status, err := makeRequest("POST", host+"/v1/policy/simulate", token, reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("simulate failed: HTTP %d", status)
	}
	fmt.Println(string(body))
	return nil
}

func runFingerprint(host, token, name, namespace string) error {
	url := fmt.Sprintf("%s/v1/secrets/%s/%s", host, namespace, name)
	body, status, err := makeRequest("GET", url, token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("fingerprint failed: HTTP %d", status)
	}
	var resp struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	fmt.Println(resp.Fingerprint)
	return nil
}

func runRotate(host, token, target string) error {
	reqBody := struct {
		Target string `json:"target"`
	}{Target: target}

	_, status, err := makeRequest("POST", host+"/v1/rotate", token, reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("rotate failed: HTTP %d", status)
	}
	fmt.Println("Rotation complete.")
	return nil
}

func runVerifyAudit(host, token string) error {
	body, status, err := makeRequest("POST", host+"/v1/audit/verify", token, struct{}{})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("verify-audit failed: HTTP %d", status)
	}
	var resp struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	if resp.Valid {
		fmt.Println("Chain OK")
	} else {
		fmt.Println("Chain INVALID")
	}
	return nil
}

func runAudit(host, token string, limit int) error {
	url := fmt.Sprintf("%s/v1/audit?limit=%s", host, strconv.Itoa(limit))
	body, status, err := makeRequest("GET", url, token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("audit failed: HTTP %d", status)
	}
	fmt.Println(string(body))
	return nil
}
