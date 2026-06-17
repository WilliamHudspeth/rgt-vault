// Package multica implements the Multica API client for the rgt-vault
// kanban reviewer. Only uses the Go standard library (net/http, encoding/json).
package multica

import "encoding/json"

// Issue represents a Multica ticket.
type Issue struct {
	ID            string  `json:"id"`
	WorkspaceID   string  `json:"workspace_id"`
	Number        int     `json:"number"`
	Identifier    string  `json:"identifier"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	Status        string  `json:"status"`
	Priority      string  `json:"priority"`
	AssigneeType  string  `json:"assignee_type,omitempty"`
	AssigneeID    string  `json:"assignee_id,omitempty"`
	CreatorType   string  `json:"creator_type,omitempty"`
	CreatorID     string  `json:"creator_id,omitempty"`
	ParentIssueID string  `json:"parent_issue_id,omitempty"`
	ProjectID     string  `json:"project_id,omitempty"`
	Position      float64 `json:"position,omitempty"`
	Labels        []Label `json:"labels,omitempty"`
	CreatedAt     string  `json:"created_at,omitempty"`
	UpdatedAt     string  `json:"updated_at,omitempty"`
}

// Label is a Multica label attached to an issue.
type Label struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CommentRequest is the body for posting a comment.
type CommentRequest struct {
	Content string `json:"content"`
}

// Comment is a Multica comment on an issue.
type Comment struct {
	ID        string `json:"id"`
	IssueID   string `json:"issue_id"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at,omitempty"`
	AuthorID  string `json:"author_id,omitempty"`
}

// Project is a Multica milestone project.
type Project struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// issuesResponse is the envelope returned by ListIssues.
type issuesResponse struct {
	Issues []Issue `json:"issues"`
}

// projectsResponse is the envelope returned by ListProjects.
type projectsResponse struct {
	Projects []Project `json:"projects"`
}

// commentsResponse is the envelope returned by ListComments.
type commentsResponse struct {
	Comments []Comment `json:"comments"`
}

// MarshalIndent is a helper for tests/debugging.
func (i *Issue) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(i, "", "  ")
}
