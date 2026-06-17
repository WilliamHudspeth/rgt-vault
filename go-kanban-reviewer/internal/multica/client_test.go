// Tests for the Multica API client. Uses net/http/httptest to stub
// the Multica server.
package multica

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testWorkspace = "ws-abc"
	testToken     = "test-token-123"
)

// newTestClient wires a Client to an httptest.Server and returns both
// so the test can control server responses.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, testToken)
	return c, srv
}

// authCapture returns a handler that records the Authorization header
// it saw and forwards to inner.
func authCapture(inner http.HandlerFunc, seen *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Get("Authorization")
		inner(w, r)
	}
}

func TestListIssues_Success(t *testing.T) {
	fixture := `{"issues":[
		{"id":"i1","workspace_id":"ws-abc","number":1,"identifier":"HUD-1","title":"first","description":"d","status":"todo","priority":"high","labels":[{"id":"l1","name":"bug"}]},
		{"id":"i2","workspace_id":"ws-abc","number":2,"identifier":"HUD-2","title":"second","description":"","status":"in_progress","priority":"medium"}
	]}`

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/api/issues") {
			t.Errorf("path = %s, want /api/issues", r.URL.Path)
		}
		if got := r.URL.Query().Get("workspace_id"); got != testWorkspace {
			t.Errorf("workspace_id = %q, want %q", got, testWorkspace)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Errorf("limit = %q, want %q", got, "5")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fixture)
	})

	got, err := c.ListIssues(context.Background(), testWorkspace, 5)
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d issues, want 2", len(got))
	}
	if got[0].ID != "i1" || got[0].Identifier != "HUD-1" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[0].Labels[0].Name != "bug" {
		t.Errorf("got[0].Labels[0].Name = %q, want %q", got[0].Labels[0].Name, "bug")
	}
}

func TestListIssues_BareArray(t *testing.T) {
	// Some Multica endpoints return a bare array. Make sure we accept it.
	fixture := `[{"id":"i1","workspace_id":"ws-abc","number":1,"identifier":"HUD-1","title":"x","description":"","status":"todo","priority":"low"}]`

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fixture)
	})

	got, err := c.ListIssues(context.Background(), testWorkspace, 10)
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(got) != 1 || got[0].ID != "i1" {
		t.Errorf("got = %+v", got)
	}
}

func TestGetIssue_Success(t *testing.T) {
	fixture := `{"id":"i9","workspace_id":"ws-abc","number":9,"identifier":"HUD-9","title":"solo","description":"desc","status":"done","priority":"urgent"}`

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		want := "/api/issues/i9"
		if !strings.HasPrefix(r.URL.Path, want) {
			t.Errorf("path = %s, want prefix %s", r.URL.Path, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fixture)
	})

	got, err := c.GetIssue(context.Background(), testWorkspace, "i9")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if got == nil {
		t.Fatal("GetIssue returned nil")
	}
	if got.ID != "i9" || got.Identifier != "HUD-9" || got.Status != "done" {
		t.Errorf("got = %+v", got)
	}
}

func TestPostComment_Success(t *testing.T) {
	var seenAuth, seenCT, seenMethod string
	var seenBody CommentRequest

	handler := func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenCT = r.Header.Get("Content-Type")
		seenMethod = r.Method
		if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":"c1","issue_id":"i1","content":"hello","created_at":"2026-06-17T00:00:00Z","author_id":"u1"}`)
	}

	c, _ := newTestClient(t, handler)

	got, err := c.PostComment(context.Background(), testWorkspace, "i1", "hello")
	if err != nil {
		t.Fatalf("PostComment: %v", err)
	}
	if seenMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", seenMethod)
	}
	if seenCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", seenCT)
	}
	if seenAuth != "Bearer "+testToken {
		t.Errorf("Authorization = %q, want Bearer %q", seenAuth, testToken)
	}
	if seenBody.Content != "hello" {
		t.Errorf("sent body.Content = %q, want %q", seenBody.Content, "hello")
	}
	if got.ID != "c1" || got.IssueID != "i1" || got.Content != "hello" {
		t.Errorf("got = %+v", got)
	}
}

func TestPostComment_4xx(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid token"}`)
	})

	_, err := c.PostComment(context.Background(), testWorkspace, "i1", "hi")
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not mention 401", err)
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("error %q does not include server body", err)
	}
}

func TestAuthHeader_Sent(t *testing.T) {
	var seenAuth string
	c, _ := newTestClient(t, authCapture(func(w http.ResponseWriter, r *http.Request) {
		// Return a minimal valid envelope for ListIssues.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"issues":[]}`)
	}, &seenAuth))

	if _, err := c.ListIssues(context.Background(), testWorkspace, 1); err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	want := "Bearer " + testToken
	if seenAuth != want {
		t.Errorf("Authorization = %q, want %q", seenAuth, want)
	}
}

func TestListComments_Success(t *testing.T) {
	fixture := `{"comments":[
		{"id":"c1","issue_id":"i1","content":"first","created_at":"2026-06-17T00:00:00Z","author_id":"u1"},
		{"id":"c2","issue_id":"i1","content":"second","created_at":"2026-06-17T01:00:00Z","author_id":"u2"}
	]}`

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/comments") {
			t.Errorf("path = %s, want suffix /comments", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fixture)
	})

	got, err := c.ListComments(context.Background(), testWorkspace, "i1")
	if err != nil {
		t.Fatalf("ListComments: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d comments, want 2", len(got))
	}
	if got[0].ID != "c1" || got[1].AuthorID != "u2" {
		t.Errorf("got = %+v", got)
	}
}

func TestListProjects_Success(t *testing.T) {
	fixture := `{"projects":[
		{"id":"p1","title":"Alpha"},
		{"id":"p2","title":"Bravo"}
	]}`

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/projects" {
			t.Errorf("path = %s, want /api/projects", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fixture)
	})

	got, err := c.ListProjects(context.Background(), testWorkspace)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(got) != 2 || got[0].Title != "Alpha" || got[1].Title != "Bravo" {
		t.Errorf("got = %+v", got)
	}
}

func TestURLEncoding_IssueIDAndWorkspaceEscaped(t *testing.T) {
	// Use a workspace and issue ID containing characters that must be
	// percent-encoded. If they aren't, http.NewRequest will reject the
	// URL or the test server will see a different (truncated) path.
	weirdWS := "ws with space"
	weirdID := "id/with?slash&and"

	var sawEscapedPath string
	var sawRawQuery string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// r.URL.EscapedPath() preserves the percent-encoding; r.URL.Path is decoded.
		sawEscapedPath = r.URL.EscapedPath()
		sawRawQuery = r.URL.RawQuery
		if got := r.URL.Query().Get("workspace_id"); got != weirdWS {
			t.Errorf("workspace_id = %q, want %q (raw query: %s)", got, weirdWS, r.URL.RawQuery)
		}
		// The dangerous characters in a path segment are '?' and '#'
		// (which would terminate the path) and '/' (which would create
		// extra segments). All three must be percent-encoded.
		if !strings.Contains(sawEscapedPath, "id%2Fwith%3F") {
			t.Errorf("EscapedPath %q does not encode id/ and ?", sawEscapedPath)
		}
		if strings.Contains(sawEscapedPath, "?slash") {
			t.Errorf("EscapedPath %q contains unescaped '?slash'", sawEscapedPath)
		}
		// Raw query must be present (so the workspace_id made it through).
		if !strings.Contains(sawRawQuery, "workspace_id=") {
			t.Errorf("RawQuery %q missing workspace_id", sawRawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"id":"x","workspace_id":"ws","number":1,"identifier":"X-1","title":"","description":"","status":"todo","priority":"low"}`)
	})

	if _, err := c.GetIssue(context.Background(), weirdWS, weirdID); err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
}

func TestGetIssue_EnvelopeFallback(t *testing.T) {
	// Some Multica endpoints return {"issue":{...}}. Make sure we accept it.
	envelope := `{"issue":{"id":"i1","workspace_id":"ws","number":1,"identifier":"HUD-1","title":"x","description":"","status":"todo","priority":"low"}}`

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, envelope)
	})

	got, err := c.GetIssue(context.Background(), "ws", "i1")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if got.ID != "i1" || got.Identifier != "HUD-1" {
		t.Errorf("got = %+v", got)
	}
}

func TestGetIssue_NullBody(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "null")
	})

	_, err := c.GetIssue(context.Background(), "ws", "i1")
	if err == nil {
		t.Fatal("expected error on null body, got nil")
	}
	if !strings.Contains(err.Error(), "null") {
		t.Errorf("error %q does not mention null", err)
	}
}
