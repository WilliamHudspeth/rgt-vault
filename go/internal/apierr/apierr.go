// Package apierr holds the pieces of server-error handling that the CLI
// (cmd/rgt-vault) and the MCP bridge (internal/mcp) share: the standard error
// envelope of the server and the rule that makes server-supplied text safe to
// show to a terminal or to a language model.
package apierr

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Display caps for text the server (or something between us and it) supplied.
const (
	MaxDetailRunes = 500
	MaxClassRunes  = 64
	MaxIDRunes     = 64
)

// Body is the standard error envelope of the server (handlers.ErrorBody):
// {"error": class, "detail": reason, "incident_id": id}.
type Body struct {
	Error      string `json:"error"`
	Detail     string `json:"detail"`
	IncidentID string `json:"incident_id"`
}

// Parse decodes body as the standard envelope. ok is false when the body is
// not JSON of that shape or carries no detail text (a proxy's HTML page, a
// non-string field, an empty reason).
func Parse(body []byte) (b Body, ok bool) {
	if json.Unmarshal(body, &b) != nil || strings.TrimSpace(b.Detail) == "" {
		return Body{}, false
	}
	return b, true
}

// SafeText makes server-supplied text safe to print or hand to a model:
// control characters (ESC, so no escape sequence; the C1 range; newlines),
// line and paragraph separators, bidirectional overrides and other invisible
// format characters become "?", invalid UTF-8 becomes "?", and the result is
// cut to max runes (with an ellipsis).
func SafeText(s string, max int) string {
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
