package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"rgt-vault-server/internal/transport"
)

// exitError carries a specific process exit code (default for errors is 1).
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// exitCode maps a command error to the process exit code.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// cli is the per-invocation environment shared by the HTTP subcommands.
type cli struct {
	// err, when set, is returned by every request (no usable token).
	err    error
	host   string
	token  string
	stdin  io.Reader
	stdout io.Writer
	client *http.Client
}

// newHTTPClient is the client of the HTTP subcommands; rt is the TLS-policy
// transport from clientTLSFlags.prepare.
func newHTTPClient(rt http.RoundTripper) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: rt, CheckRedirect: transport.NoRedirect}
}

// secretURL builds /v1/secrets/{ns}/{name}[/suffix] with path escaping.
func (c *cli) secretURL(namespace, name, suffix string) string {
	u := c.host + "/v1/secrets/" + url.PathEscape(namespace) + "/" + url.PathEscape(name)
	if suffix != "" {
		u += "/" + suffix
	}
	return u
}

// ---------------------------------------------------------------------------
// Shared HTTP helper
// ---------------------------------------------------------------------------

func (c *cli) do(method, reqURL string, body any) ([]byte, int, error) {
	if c.err != nil {
		return nil, 0, c.err
	}
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = strings.NewReader(string(b))
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

func (c *cli) runSet(name, namespace, agent, purpose, valueFile string) error {
	var data []byte
	var err error
	if valueFile != "" {
		data, err = os.ReadFile(valueFile)
		if err != nil {
			return fmt.Errorf("reading value file: %w", err)
		}
	} else {
		data, err = io.ReadAll(c.stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" {
		return errors.New("refusing to store an empty secret value")
	}

	reqBody := struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Value     string `json:"value"`
		Agent     string `json:"agent,omitempty"`
		Purpose   string `json:"purpose"`
	}{Name: name, Namespace: namespace, Value: value, Agent: agent, Purpose: purpose}

	_, status, err := c.do(http.MethodPost, c.host+"/v1/secrets", reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("set failed: HTTP %d", status)
	}
	fmt.Fprintln(c.stdout, "Secret stored.")
	return nil
}

// runGet fetches the plaintext through POST /v1/secrets/{ns}/{name}/lease
// (RGT-504): a server-side lease as the token's agent, which needs a token
// with the agent and lease scopes. agent and purpose are sent only when set.
func (c *cli) runGet(name, namespace, agent, purpose string) error {
	if name == "" {
		return errors.New("secret name must not be empty")
	}
	reqBody := struct {
		Agent   string `json:"agent,omitempty"`
		Purpose string `json:"purpose,omitempty"`
	}{Agent: agent, Purpose: purpose}
	body, status, err := c.do(http.MethodPost, c.secretURL(namespace, name, "lease"), reqBody)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return fmt.Errorf("secret %q not found in namespace %q", name, namespace)
	}
	if status != http.StatusOK {
		return fmt.Errorf("get failed: HTTP %d", status)
	}
	var resp struct {
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	if resp.Value == nil {
		return errors.New("server did not return a secret value")
	}
	fmt.Fprintln(c.stdout, *resp.Value)
	return nil
}

// listResponse matches {"namespace":"...","secrets":[...]} from GET /v1/secrets.
type listResponse struct {
	Namespace string `json:"namespace"`
	Secrets   []struct {
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	} `json:"secrets"`
}

func (c *cli) runList(namespace string) error {
	body, status, err := c.do(http.MethodGet, c.host+"/v1/secrets?namespace="+url.QueryEscape(namespace), nil)
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
		fmt.Fprintf(c.stdout, "%s\t%s\n", s.Name, s.CreatedAt)
	}
	return nil
}

func (c *cli) runRevoke(name, namespace string) error {
	_, status, err := c.do(http.MethodPost, c.secretURL(namespace, name, "revoke"), struct{}{})
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("revoke failed: HTTP %d", status)
	}
	fmt.Fprintln(c.stdout, "Secret revoked.")
	return nil
}

func (c *cli) runSimulate(agent, namespace, purpose, action string) error {
	reqBody := struct {
		Agent     string `json:"agent,omitempty"`
		Namespace string `json:"namespace"`
		Purpose   string `json:"purpose"`
		Action    string `json:"action"`
	}{Agent: agent, Namespace: namespace, Purpose: purpose, Action: action}

	body, status, err := c.do(http.MethodPost, c.host+"/v1/policy/simulate", reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("simulate failed: HTTP %d", status)
	}
	fmt.Fprintln(c.stdout, strings.TrimSpace(string(body)))
	return nil
}

func (c *cli) runFingerprint(name, namespace string) error {
	body, status, err := c.do(http.MethodGet, c.secretURL(namespace, name, ""), nil)
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
	if resp.Fingerprint == "" {
		return errors.New("server did not return a fingerprint")
	}
	fmt.Fprintln(c.stdout, resp.Fingerprint)
	return nil
}

func (c *cli) runRotate(target string) error {
	reqBody := struct {
		Target string `json:"target"`
	}{Target: target}

	_, status, err := c.do(http.MethodPost, c.host+"/v1/rotate", reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("rotate failed: HTTP %d", status)
	}
	fmt.Fprintln(c.stdout, "Rotation complete.")
	return nil
}

// runVerifyAudit prints OK / TAMPERED and exits 2 on a broken chain, like the
// Python CLI. The server reports {"ok": bool}; "valid" is accepted as well.
func (c *cli) runVerifyAudit() error {
	body, status, err := c.do(http.MethodPost, c.host+"/v1/audit/verify", struct{}{})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("verify-audit failed: HTTP %d", status)
	}
	var resp struct {
		OK    *bool `json:"ok"`
		Valid *bool `json:"valid"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	verdict := resp.OK
	if verdict == nil {
		verdict = resp.Valid
	}
	if verdict == nil {
		return errors.New("server response has no verdict")
	}
	if *verdict {
		fmt.Fprintln(c.stdout, "OK")
		return nil
	}
	fmt.Fprintln(c.stdout, "TAMPERED")
	return &exitError{code: 2, msg: "audit chain verification failed"}
}

func (c *cli) runAudit(limit int) error {
	body, status, err := c.do(http.MethodGet, c.host+"/v1/audit?limit="+strconv.Itoa(limit), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("audit failed: HTTP %d", status)
	}
	fmt.Fprintln(c.stdout, strings.TrimSpace(string(body)))
	return nil
}
