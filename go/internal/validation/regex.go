package validation

import (
	"regexp"
	"time"
)

// DefaultRegexTimeout is safe_regex_match's default timeout.
const DefaultRegexTimeout = time.Second

// SafeRegexMatch applies re to text anchored at the start of the string
// (python: pattern.match, not fullmatch) and returns the submatches (index 0
// is the whole match), or nil if there is no match.
//
// Go's regexp is RE2: it runs in time linear in len(text) and has no
// catastrophic backtracking, so the ReDoS the Python helper guards against
// cannot occur. The timeout is kept as a belt-and-braces bound and for
// behavioural parity: when it expires a ValidationError with Python's
// message is returned. A non-positive timeout means DefaultRegexTimeout.
func SafeRegexMatch(re *regexp.Regexp, text string, timeout time.Duration) ([]string, error) {
	return safeRegexMatch(func() []int { return re.FindStringSubmatchIndex(text) }, text, timeout)
}

// safeRegexMatch runs find (a submatch-index search over text) under the
// timeout; tests inject a slow find.
func safeRegexMatch(find func() []int, text string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = DefaultRegexTimeout
	}
	ch := make(chan []string, 1)
	go func() {
		// The search is leftmost: a match starting at 0, if any, is the one
		// returned. Reject matches that start later.
		loc := find()
		if loc == nil || loc[0] != 0 {
			ch <- nil
			return
		}
		groups := make([]string, len(loc)/2)
		for i := range groups {
			if loc[2*i] >= 0 {
				groups[i] = text[loc[2*i]:loc[2*i+1]]
			}
		}
		ch <- groups
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case m := <-ch:
		return m, nil
	case <-timer.C:
		return nil, fail("Regex match aborted: exceeded %ds timeout. "+
			"The input may be causing catastrophic backtracking.", max(1, int(timeout.Round(time.Second)/time.Second)))
	}
}
