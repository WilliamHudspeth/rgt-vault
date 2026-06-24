package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPClient struct {
	baseURL string
	token   string
	hc      *http.Client
}

func NewHTTPClient(baseURL, token string) *HTTPClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &HTTPClient{
		baseURL: baseURL,
		token:   token,
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *HTTPClient) Health() bool {
	req, err := c.newReq(http.MethodGet, c.baseURL+"/healthz", "")
	if err != nil {
		return false
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (c *HTTPClient) VerifyAudit() bool {
	req, err := c.newReq(http.MethodPost, c.baseURL+"/v1/audit/verify", "{}")
	if err != nil {
		return false
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.Valid
}

type listSecretsResponse struct {
	Namespace string       `json:"namespace"`
	Secrets   []secretItem `json:"secrets"`
}

type secretItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (c *HTTPClient) ListSecrets(namespace string) ([]SecretInfo, error) {
	u := c.baseURL + "/v1/secrets"
	params := url.Values{}
	params.Set("namespace", namespace)
	u = u + "?" + params.Encode()
	req, err := c.newReq(http.MethodGet, u, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list secrets: unexpected status %d", resp.StatusCode)
	}
	var lr listSecretsResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, err
	}
	infos := make([]SecretInfo, len(lr.Secrets))
	for i, s := range lr.Secrets {
		h := sha256.Sum256([]byte(s.Value))
		fingerprint := hex.EncodeToString(h[:])[:8]
		infos[i] = SecretInfo{Name: s.Name, Fingerprint: fingerprint}
	}
	return infos, nil
}

func (c *HTTPClient) Rotate(target string) error {
	body, err := json.Marshal(map[string]string{"target": target})
	if err != nil {
		return err
	}
	req, err := c.newReq(http.MethodPost, c.baseURL+"/v1/rotate", string(body))
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return fmt.Errorf("rotate: unexpected status %d", resp.StatusCode)
}

func (c *HTTPClient) newReq(method, url, bodyJSON string) (*http.Request, error) {
	var req *http.Request
	var err error
	if bodyJSON != "" {
		req, err = http.NewRequest(method, url, strings.NewReader(bodyJSON))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

var _ Client = (*HTTPClient)(nil)
