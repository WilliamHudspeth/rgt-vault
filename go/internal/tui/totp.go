// totp.go provides TOTP countdown helpers for RGT-160.
package tui

import (
	"strings"
	"time"
)

// TOTPPeriod is the default TOTP step in seconds.
const TOTPPeriod = 30

// TOTPRemaining returns the seconds remaining in the current TOTP window.
// period <= 0 is treated as TOTPPeriod. Result is in [1, period].
func TOTPRemaining(now time.Time, period int) int {
	if period <= 0 {
		period = TOTPPeriod
	}
	elapsed := int(now.Unix() % int64(period))
	rem := period - elapsed
	return rem
}

// totpNoteTags are the note tokens that mark a secret as a TOTP seed.
var totpNoteTags = []string{"type=totp", "type:totp"}

// IsTOTP reports whether a secret is a TOTP secret, from its metadata and
// never from its name (a secret that merely has "otp" in its name is not one,
// and a TOTP secret may have any name). The server's metadata for a secret is
// its free-text note and, when the server provides one, a "type": a secret
// is TOTP when its type is "totp" or its note carries the token "type=totp"
// (or "type:totp"), case-insensitively, separated by spaces, commas or
// semicolons.
func IsTOTP(s SecretInfo) bool {
	if strings.EqualFold(strings.TrimSpace(s.Type), "totp") {
		return true
	}
	tokens := strings.FieldsFunc(strings.ToLower(s.Note), func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\t' || r == '\n'
	})
	for _, tok := range tokens {
		for _, tag := range totpNoteTags {
			if tok == tag {
				return true
			}
		}
	}
	return false
}
