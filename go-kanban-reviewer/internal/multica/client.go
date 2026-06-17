// Multica REST API client. Uses only net/http and encoding/json.
package multica

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// maxErrorBodyBytes caps how much of a non-2xx response body we
	// retain in an error. Multica error responses are small but defend
	// against a misconfigured proxy returning a huge page.
	maxErrorBodyBytes = 4096
	// defaultTimeout is the per-request timeout used by NewClient.
	defaultTimeout = 30 * time.Second
)

// Client is a Multica API client.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewClient returns a Client with sensible defaults (30s per-request timeout).
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		HTTPClient: &http.Client{Timeout: defaultTimeout},
	}
}

// do sends an HTTP request and returns the response body on 2xx.
// On non-2xx, returns an error with status + body (capped).
func (c *Client) do(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("multica: marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("multica: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("multica: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, fmt.Errorf("multica: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

// ListIssues returns up to `limit` issues in the workspace.
func (c *Client) ListIssues(ctx context.Context, workspaceID string, limit int) ([]Issue, error) {
	path := fmt.Sprintf("/api/issues?workspace_id=%s&limit=%d", workspaceID, limit)
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	// Multica sometimes returns a bare array, sometimes an envelope.
	var envelope issuesResponse
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Issues != nil {
		return envelope.Issues, nil
	}
	var bare []Issue
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, fmt.Errorf("multica: parse issues: %w (body: %s)", err, string(raw[:min(200, len(raw))]))
	}
	return bare, nil
}

// GetIssue fetches a single issue by UUID.
func (c *Client) GetIssue(ctx context.Context, workspaceID, issueID string) (*Issue, error) {
	path := fmt.Sprintf("/api/issues/%s?workspace_id=%s", issueID, workspaceID)
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var issue Issue
	if err := json.Unmarshal(raw, &issue); err != nil {
		return nil, fmt.Errorf("multica: parse issue: %w", err)
	}
	return &issue, nil
}

// PostComment posts a comment to the given issue. Returns the new comment.
func (c *Client) PostComment(ctx context.Context, workspaceID, issueID, content string) (*Comment, error) {
	path := fmt.Sprintf("/api/issues/%s/comments?workspace_id=%s", issueID, workspaceID)
	raw, err := c.do(ctx, http.MethodPost, path, CommentRequest{Content: content})
	if err != nil {
		return nil, err
	}
	var cmt Comment
	if err := json.Unmarshal(raw, &cmt); err != nil {
		return nil, fmt.Errorf("multica: parse comment: %w", err)
	}
	return &cmt, nil
}

// ListComments returns all comments on the given issue.
func (c *Client) ListComments(ctx context.Context, workspaceID, issueID string) ([]Comment, error) {
	path := fmt.Sprintf("/api/issues/%s/comments?workspace_id=%s", issueID, workspaceID)
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	// Try envelope first, then bare array (matches ListIssues behavior).
	var envelope commentsResponse
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Comments != nil {
		return envelope.Comments, nil
	}
	var bare []Comment
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, fmt.Errorf("multica: parse comments: %w", err)
	}
	return bare, nil
}

// ListProjects returns all milestone projects in the workspace.
func (c *Client) ListProjects(ctx context.Context, workspaceID string) ([]Project, error) {
	path := fmt.Sprintf("/api/projects?workspace_id=%s", workspaceID)
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var envelope projectsResponse
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Projects != nil {
		return envelope.Projects, nil
	}
	var bare []Project
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, fmt.Errorf("multica: parse projects: %w", err)
	}
	return bare, nil
}

// min is a tiny helper to avoid pulling in the "min" builtin for
// older Go versions; can be removed once Go 1.21+ is guaranteed.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
