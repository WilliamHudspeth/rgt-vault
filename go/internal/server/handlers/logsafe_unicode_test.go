package handlers

import (
	"strings"
	"testing"
)

// LogSafe must encode the same invisible/reordering code points as
// logging.SanitizeText (PR #58 review): a request path containing U+2028 or a
// BiDi override must not reach the log raw.
func TestLogSafeEncodesLineSeparatorsBiDiAndInvisibles(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"a\u2028b", "a\\u2028b"},
		{"a\u2029b", "a\\u2029b"},
		{"a\u202eb", "a\\u202eb"},
		{"a\u200eb", "a\\u200eb"},
		{"a\u00adb", "a\\u00adb"},
		{"a\u2060b", "a\\u2060b"},
		{"a\ue000b", "a\\ue000b"},
		{"a\U000e0041" + "1b", "a\\U000e00411b"},
		{"a\u034fb", "a\\u034fb"},
		{"caf\u00e9 \u4e16\u754c", "caf\u00e9 \u4e16\u754c"}, // ordinary non-ASCII is untouched
	} {
		if got := LogSafe(tc.in); got != tc.want {
			t.Errorf("LogSafe(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := LogSafe("x\u2028FORGED"); strings.ContainsRune(got, '\u2028') {
		t.Errorf("raw U+2028 survived: %q", got)
	}
}
