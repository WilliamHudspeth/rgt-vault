package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"rgt-vault-server/internal/netguard"
	"rgt-vault-server/internal/transport"
	"rgt-vault-server/internal/validation"
)

// DefaultBaseURL is the server the TUI talks to when none is given: the vault
// server's default listen address (cmd/server: 127.0.0.1:8765).
const DefaultBaseURL = "http://127.0.0.1:8765"

// DefaultAgent was the agent label the TUI sent on list calls before H1
// (python tui_client: agent="operator"). It is no longer sent by default:
// the server takes the agent from the bearer token (batch H1). SetAgent sets
// a label for a legacy shared-token server.
const DefaultAgent = "operator"

// maxResponseBytes bounds how much of any server response is read.
const maxResponseBytes = 4 << 20

// maxFingerprintWorkers bounds the concurrent fingerprint lookups of one list.
const maxFingerprintWorkers = 8

// ErrRejected means the server refused an approve/deny decision with HTTP 400:
// a bad or missing 2FA code, a replayed code, or a request that is already
// decided or gone (python tui_client returns False for this case).
var ErrRejected = errors.New("rejected by the server")

// StatusError is a non-success HTTP answer. It deliberately carries no body:
// server error text is never shown to the operator.
type StatusError struct {
	Op   string
	Code int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: HTTP %d %s", e.Op, e.Code, http.StatusText(e.Code))
}

// HTTPClient talks to a running rgt-vault server. It never asks for, receives
// or stores a secret value: lists carry metadata and fingerprints only.
type HTTPClient struct {
	baseURL       string
	token         string // agent token: secrets, audit, rotate
	operatorToken string // operator token: /v1/requests*; defaults to token
	agent         string
	hc            *http.Client
}

// NewHTTPClient builds a client for baseURL (empty means DefaultBaseURL) that
// authenticates with token. Approval calls use the same token until
// SetOperatorToken is called.
func NewHTTPClient(baseURL, token string) *HTTPClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	return &HTTPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{DialContext: netguard.NewDialer(true).DialContext},
			CheckRedirect: transport.NoRedirect, // never replay the bearer token to a redirect target
		},
	}
}

// SetTransport replaces the HTTP transport (the TLS policy of
// internal/transport: TLS 1.2+, AEAD suites, --cacert). A nil transport keeps
// the default.
func (c *HTTPClient) SetTransport(rt http.RoundTripper) {
	if rt != nil {
		c.hc.Transport = rt
	}
}

// SetOperatorToken sets the token used for the approval endpoints. A server
// started with a separate operator token file accepts only that token there
// (and refuses it everywhere else).
func (c *HTTPClient) SetOperatorToken(token string) { c.operatorToken = token }

// SetAgent sets the agent label sent on list calls and as the operator name
// on approve/deny (legacy shared-token servers; with per-agent tokens it must
// equal the token's agent). "" clears it.
func (c *HTTPClient) SetAgent(agent string) error {
	if agent == "" {
		c.agent = ""
		return nil
	}
	a, err := validation.ValidateAgent(agent)
	if err != nil {
		return err
	}
	c.agent = a
	return nil
}

func (c *HTTPClient) approvalToken() string {
	if c.operatorToken != "" {
		return c.operatorToken
	}
	return c.token
}

// request performs one call and, for a 200 answer, decodes the JSON body into
// out (when non-nil). Any other status is a *StatusError (the body is
// discarded unread beyond the cap).
func (c *HTTPClient) request(op, method, path string, query url.Values, token string, body any, out any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Op: op, Code: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: invalid response", op)
	}
	return nil
}

// Health reports whether GET /healthz answers 200.
func (c *HTTPClient) Health() bool {
	return c.request("health", http.MethodGet, "/healthz", nil, c.token, nil, nil) == nil
}

// VerifyAudit asks the server to verify the audit hash chain.
func (c *HTTPClient) VerifyAudit() bool {
	var res struct {
		OK    *bool `json:"ok"`
		Valid *bool `json:"valid"` // pre-G9 spelling
	}
	if err := c.request("verify audit", http.MethodPost, "/v1/audit/verify", nil, c.token, struct{}{}, &res); err != nil {
		return false
	}
	switch {
	case res.OK != nil:
		return *res.OK
	case res.Valid != nil:
		return *res.Valid
	}
	return false
}

type secretListItem struct {
	Name        string `json:"name"`
	Note        string `json:"note"`
	Require2FA  bool   `json:"require_2fa"`
	Fingerprint string `json:"fingerprint"` // optional: used when the list carries it
	Type        string `json:"type"`        // optional: used when the server carries it
	// There is deliberately no field for a secret value: whatever a server
	// sends beyond the metadata is dropped by the decoder.
}

// ListSecrets lists the active secrets of namespace with their metadata and
// ciphertext fingerprints. The list route carries no fingerprint, so each one
// is fetched from GET /v1/secrets/{namespace}/{name} (bounded concurrency);
// a secret whose fingerprint cannot be fetched shows an empty fingerprint.
func (c *HTTPClient) ListSecrets(namespace string) ([]SecretInfo, error) {
	var lr struct {
		Secrets []secretListItem `json:"secrets"`
	}
	q := url.Values{"namespace": {namespace}}
	if c.agent != "" {
		q.Set("agent", c.agent)
	}
	if err := c.request("list secrets", http.MethodGet, "/v1/secrets", q, c.token, nil, &lr); err != nil {
		return nil, err
	}
	infos := make([]SecretInfo, len(lr.Secrets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxFingerprintWorkers)
	for i, s := range lr.Secrets {
		infos[i] = SecretInfo{Name: s.Name, Note: s.Note, Require2FA: s.Require2FA, Type: s.Type, Fingerprint: s.Fingerprint}
		if s.Fingerprint != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			infos[i].Fingerprint = c.fingerprint(namespace, name)
		}(i, s.Name)
	}
	wg.Wait()
	return infos, nil
}

// fingerprint fetches sha256(ciphertext)[:8] of one secret; "" on any failure.
func (c *HTTPClient) fingerprint(namespace, name string) string {
	var res struct {
		Fingerprint string `json:"fingerprint"`
	}
	path := "/v1/secrets/" + url.PathEscape(namespace) + "/" + url.PathEscape(name)
	if err := c.request("fingerprint", http.MethodGet, path, nil, c.token, nil, &res); err != nil {
		return ""
	}
	return res.Fingerprint
}

// AuditEntry is one audit row as the TUI shows it.
type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Principal string `json:"principal"`
	Detail    string `json:"detail"`
	Hash      string `json:"hash"`
}

// GetAuditLog returns up to limit audit rows, oldest first (the server answers
// newest first; the stream view shows the tail).
func (c *HTTPClient) GetAuditLog(limit int) ([]AuditEntry, error) {
	var res struct {
		Entries []struct {
			Action    string  `json:"action"`
			Timestamp string  `json:"timestamp"`
			Details   *string `json:"details"`
			EntryHash string  `json:"entry_hash"`
			AgentID   *string `json:"agent_id"`
		} `json:"entries"`
	}
	q := url.Values{"limit": {fmt.Sprint(limit)}}
	if err := c.request("get audit", http.MethodGet, "/v1/audit", q, c.token, nil, &res); err != nil {
		return nil, err
	}
	out := make([]AuditEntry, 0, len(res.Entries))
	for i := len(res.Entries) - 1; i >= 0; i-- {
		e := res.Entries[i]
		entry := AuditEntry{Timestamp: e.Timestamp, Event: e.Action, Hash: e.EntryHash}
		if e.AgentID != nil {
			entry.Principal = *e.AgentID
		}
		if e.Details != nil {
			entry.Detail = *e.Details
		}
		out = append(out, entry)
	}
	return out, nil
}

// Rotate rotates the "master" key or the "dek".
func (c *HTTPClient) Rotate(target string) error {
	return c.request("rotate", http.MethodPost, "/v1/rotate", nil, c.token, map[string]string{"target": target}, nil)
}

// PendingRequest is an agent request waiting for an operator decision
// (python tui_client.PendingRequest). It carries no secret value.
type PendingRequest struct {
	RequestID  string  `json:"request_id"`
	Agent      string  `json:"agent"`
	Namespace  string  `json:"namespace"`
	SecretName string  `json:"secret_name"`
	Purpose    string  `json:"purpose"`
	Action     string  `json:"action"`
	Require2FA bool    `json:"require_2fa"`
	CreatedAt  float64 `json:"created_at"`
}

// ListRequests returns the pending approval requests, oldest first, using the
// operator token.
func (c *HTTPClient) ListRequests() ([]PendingRequest, error) {
	var res struct {
		Requests []PendingRequest `json:"requests"`
	}
	if err := c.request("list requests", http.MethodGet, "/v1/requests", nil, c.approvalToken(), nil, &res); err != nil {
		return nil, err
	}
	return res.Requests, nil
}

// Approve approves a request. totpCode is required (and verified by the
// server, single use) when the request needs a second factor. A refusal of
// the decision (HTTP 400) is ErrRejected.
func (c *HTTPClient) Approve(requestID, totpCode string) error {
	var code *string
	if totpCode != "" {
		code = &totpCode
	}
	body := map[string]any{"totp_code": code}
	if c.agent != "" {
		body["operator"] = c.agent
	}
	return c.decide("approve", requestID, body)
}

// Deny denies a request.
func (c *HTTPClient) Deny(requestID, reason string) error {
	if reason == "" {
		reason = "denied by operator"
	}
	body := map[string]any{"reason": reason}
	if c.agent != "" {
		body["operator"] = c.agent
	}
	return c.decide("deny", requestID, body)
}

func (c *HTTPClient) decide(verb, requestID string, body map[string]any) error {
	path := "/v1/requests/" + url.PathEscape(requestID) + "/" + verb
	err := c.request(verb, http.MethodPost, path, nil, c.approvalToken(), body, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusBadRequest {
		return ErrRejected
	}
	return err
}

var (
	_ Client         = (*HTTPClient)(nil)
	_ ApprovalClient = (*HTTPClient)(nil)
)
