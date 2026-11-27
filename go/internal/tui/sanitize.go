package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// safeText makes server- or agent-supplied text safe to draw in a terminal:
// control characters (including ESC, so no escape-sequence injection, and the
// C1 range), line/paragraph separators, bidirectional overrides and other
// invisible format characters become "?", invalid UTF-8 becomes "?", and the
// result is cut to max runes (with an ellipsis). A secret name, note, agent
// or purpose chosen by an attacker can therefore not move the cursor, recolour
// the screen or spoof another row.
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

// Display caps for server-supplied fields.
const (
	maxNameRunes   = 64
	maxNoteRunes   = 60
	maxFieldRunes  = 40
	maxErrorRunes  = 120
	maxDetailRunes = 40
)

// errText renders an error for the status line.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return safeText(err.Error(), maxErrorRunes)
}
