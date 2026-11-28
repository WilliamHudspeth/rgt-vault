package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Display caps for text the server (or something between us and it) supplied.
const (
	maxErrDetailRunes = 500
	maxErrClassRunes  = 64
	maxErrIDRunes     = 64
)

// apiErrorBody is the standard error envelope of the server
// (handlers.ErrorBody): {"error": class, "detail": reason, "incident_id": id}.
type apiErrorBody struct {
	Error      string `json:"error"`
	Detail     string `json:"detail"`
	IncidentID string `json:"incident_id"`
}

// apiError turns a non-success answer into the error a client command
// returns (RGT-526):
//
//	<command> failed: <detail> (HTTP <code> <error>, incident <id>)
//
// so the operator sees the server's reason and the incident id that finds
// the matching server log line. When the body is not the standard envelope
// (no JSON, no "detail", a non-string field, a proxy's HTML page) the answer
// is the status alone: "<command> failed: HTTP <code>". Every piece of
// server-provided text is neutralised first (safeText): a hostile or
// compromised server, or a secret/agent name echoed in a policy message,
// cannot move the cursor, recolour the terminal or forge a second line.
// The exit code stays 1 (a plain error).
func apiError(command string, status int, body []byte) error {
	var b apiErrorBody
	if json.Unmarshal(body, &b) != nil || strings.TrimSpace(b.Detail) == "" {
		return fmt.Errorf("%s failed: HTTP %d", command, status)
	}
	var meta []string
	code := fmt.Sprintf("HTTP %d", status)
	if class := safeText(strings.TrimSpace(b.Error), maxErrClassRunes); class != "" {
		code += " " + class
	}
	meta = append(meta, code)
	if id := safeText(strings.TrimSpace(b.IncidentID), maxErrIDRunes); id != "" {
		meta = append(meta, "incident "+id)
	}
	return fmt.Errorf("%s failed: %s (%s)", command, safeText(strings.TrimSpace(b.Detail), maxErrDetailRunes), strings.Join(meta, ", "))
}

// errorClass returns the "error" field of a standard error body, "" when the
// body is not one.
func errorClass(body []byte) string {
	var b apiErrorBody
	if json.Unmarshal(body, &b) != nil {
		return ""
	}
	return b.Error
}

// isScopeRefusal reports the server's answer to a token that lacks a scope.
func isScopeRefusal(status int, body []byte) bool {
	return status == http.StatusForbidden && errorClass(body) == "AuthorizationError"
}

// safeText makes server-supplied text safe to print on a terminal: control
// characters (ESC, so no escape sequence; the C1 range; newlines), line and
// paragraph separators, bidirectional overrides and other invisible format
// characters become "?", invalid UTF-8 becomes "?", and the result is cut to
// max runes (with an ellipsis). It is the same rule as the TUI's (unexported)
// internal/tui safeText.
func safeText(s string, max int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if n >= max {
			b.WriteString("…")
			break
		}
		switch {
		case r == utf8.RuneError && size <= 1:
			r = '?'
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
