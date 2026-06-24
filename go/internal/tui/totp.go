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

// IsTOTP reports whether a secret should be treated as a TOTP secret.
// Heuristic until the backend carries a real type: name contains "totp" or "otp"
// (case-insensitive).
func IsTOTP(s SecretInfo) bool {
	lower := strings.ToLower(s.Name)
	return strings.Contains(lower, "totp") || strings.Contains(lower, "otp")
}
