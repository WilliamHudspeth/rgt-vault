package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/apierr"
)

// Display caps for text the server (or something between us and it) supplied.
const (
	maxErrDetailRunes = 500
	maxErrClassRunes  = 64
	maxErrIDRunes     = 64

	maxRetryAfterRunes = 32
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
	return apiErrorRA(command, status, body, "")
}

// apiErrorRA is apiError with the answer's Retry-After header (a 429 says
// how long to wait); "" when there was none.
func apiErrorRA(command string, status int, body []byte, retryAfter string) error {
	ra := safeText(strings.TrimSpace(retryAfter), maxRetryAfterRunes)
	var b apiErrorBody
	if json.Unmarshal(body, &b) != nil || strings.TrimSpace(b.Detail) == "" {
		if ra != "" {
			return fmt.Errorf("%s failed: HTTP %d (retry after %s)", command, status, ra)
		}
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
	if ra != "" {
		meta = append(meta, "retry after "+ra)
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

// isScopeRefusal reports the server's answer to a token that lacks a scope:
// 403 AuthorizationError "insufficient scope for this route". The same class
// is also used for "agent does not match the authenticated token", which
// is not a scope problem and gets no scope hint.
func isScopeRefusal(status int, body []byte) bool {
	if status != http.StatusForbidden {
		return false
	}
	var b apiErrorBody
	return json.Unmarshal(body, &b) == nil && b.Error == "AuthorizationError" &&
		strings.Contains(b.Detail, "insufficient scope")
}

// escapeJSONText makes JSON text from the server safe to print: every
// control character (DEL, C1 such as U+009B = CSI, ESC), bidirectional
// override, line/paragraph separator and other invisible format character
// becomes a \uXXXX escape (valid JSON inside a string, so the output still
// parses and means the same), and invalid UTF-8 becomes \ufffd. Only the
// newlines and spaces json.Indent adds are kept.
func escapeJSONText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			b.WriteString(`\ufffd`)
		case r == '\n' || r == ' ':
			b.WriteRune(r)
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			if r1, r2 := utf16.EncodeRune(r); r1 != unicode.ReplacementChar {
				fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// safeText makes server-supplied text safe to print on a terminal; the rule
// lives in internal/apierr so the MCP bridge applies the same one.
func safeText(s string, max int) string { return apierr.SafeText(s, max) }
