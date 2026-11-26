package policy

import (
	"errors"
	"fmt"
)

// This file is a port of Python's fnmatch.fnmatchcase (CPython 3.12
// fnmatch.translate): `*` matches any run of characters INCLUDING '/' and
// newlines, `?` matches exactly one character, `[seq]` / `[!seq]` match
// one character from / not from seq, and matching is case-sensitive.
// Go's path.Match is NOT a substitute: its `*` never crosses '/', and
// `purpose` values are free text that may contain '/'.
//
// Python builds a regular expression; here the same parsing steps
// (including its quirky character-class chunk logic) produce a token list
// that a linear two-pointer glob matcher executes. Because every token
// except `*` consumes exactly one character, the result is identical to the
// anchored regular expression Python builds.

// ErrBadPattern reports a pattern that Python's fnmatch machinery cannot
// turn into a valid regular expression (it raises IndexError or re.error).
var ErrBadPattern = errors.New("policy: bad fnmatch pattern")

type tokKind uint8

const (
	tokLit   tokKind = iota // one specific rune
	tokAny                  // `?`
	tokStar                 // `*` (runs of stars are collapsed)
	tokSet                  // `[...]`
	tokNever                // `[]` and friends: an empty set never matches
)

type runeRange struct{ lo, hi rune }

type token struct {
	kind   tokKind
	lit    rune
	negate bool
	single []rune
	ranges []runeRange
}

func (t *token) matches(r rune) bool {
	switch t.kind {
	case tokLit:
		return r == t.lit
	case tokAny:
		return true
	case tokSet:
		in := false
		for _, s := range t.single {
			if s == r {
				in = true
				break
			}
		}
		if !in {
			for _, rg := range t.ranges {
				if r >= rg.lo && r <= rg.hi {
					in = true
					break
				}
			}
		}
		return in != t.negate
	}
	return false
}

// Pattern is a compiled fnmatchcase pattern. It is immutable and safe for
// concurrent use.
type Pattern struct {
	toks []token
}

// CompilePattern compiles an fnmatch pattern. It returns ErrBadPattern for
// the rare patterns where Python itself raises while translating.
func CompilePattern(pattern string) (*Pattern, error) {
	pat := []rune(pattern)
	var toks []token
	i, n := 0, len(pat)
	for i < n {
		c := pat[i]
		i++
		switch c {
		case '*':
			if len(toks) == 0 || toks[len(toks)-1].kind != tokStar {
				toks = append(toks, token{kind: tokStar})
			}
		case '?':
			toks = append(toks, token{kind: tokAny})
		case '[':
			j := i
			if j < n && pat[j] == '!' {
				j++
			}
			if j < n && pat[j] == ']' {
				j++
			}
			for j < n && pat[j] != ']' {
				j++
			}
			if j >= n {
				toks = append(toks, token{kind: tokLit, lit: '['})
				continue
			}
			stuff, err := buildStuff(pat, i, j)
			if err != nil {
				return nil, err
			}
			i = j + 1
			switch {
			case len(stuff) == 0:
				toks = append(toks, token{kind: tokNever})
			case len(stuff) == 1 && stuff[0] == '!':
				toks = append(toks, token{kind: tokAny})
			default:
				if stuff[0] == '!' {
					stuff[0] = '^'
				} else if stuff[0] == '^' || stuff[0] == '[' {
					stuff = append([]rune{'\\'}, stuff...)
				}
				tk, err := parseClass(stuff)
				if err != nil {
					return nil, err
				}
				toks = append(toks, tk)
			}
		default:
			toks = append(toks, token{kind: tokLit, lit: c})
		}
	}
	return &Pattern{toks: toks}, nil
}

// buildStuff reproduces the character-class body Python hands to re
// (pat[i:j] after chunking, range repair and escaping).
func buildStuff(pat []rune, i, j int) ([]rune, error) {
	raw := pat[i:j]
	hasDash := false
	for _, r := range raw {
		if r == '-' {
			hasDash = true
			break
		}
	}
	var stuff []rune
	if !hasDash {
		stuff = escapeBackslash(raw, false)
	} else {
		var chunks [][]rune
		k := i + 1
		if pat[i] == '!' {
			k = i + 2
		}
		start := i
		for {
			k = findRune(pat, '-', k, j)
			if k < 0 {
				break
			}
			chunks = append(chunks, append([]rune(nil), pat[start:k]...))
			start = k + 1
			k += 3
		}
		chunk := pat[start:j]
		if len(chunk) > 0 {
			chunks = append(chunks, append([]rune(nil), chunk...))
		} else {
			last := len(chunks) - 1
			chunks[last] = append(chunks[last], '-')
		}
		// Remove empty ranges (invalid in a regular expression).
		for k := len(chunks) - 1; k > 0; k-- {
			a, b := chunks[k-1], chunks[k]
			if len(a) == 0 || len(b) == 0 {
				return nil, fmt.Errorf("%w: %q (IndexError in Python)", ErrBadPattern, string(pat))
			}
			if a[len(a)-1] > b[0] {
				merged := append(append([]rune(nil), a[:len(a)-1]...), b[1:]...)
				chunks[k-1] = merged
				chunks = append(chunks[:k], chunks[k+1:]...)
			}
		}
		for idx, ch := range chunks {
			if idx > 0 {
				stuff = append(stuff, '-')
			}
			stuff = append(stuff, escapeBackslash(ch, true)...)
		}
	}
	// Escape set operations (&&, ~~ and ||).
	var out []rune
	for _, r := range stuff {
		if r == '&' || r == '~' || r == '|' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return out, nil
}

func escapeBackslash(in []rune, alsoDash bool) []rune {
	out := make([]rune, 0, len(in)+2)
	for _, r := range in {
		switch {
		case r == '\\':
			out = append(out, '\\', '\\')
		case alsoDash && r == '-':
			out = append(out, '\\', '-')
		default:
			out = append(out, r)
		}
	}
	return out
}

func findRune(s []rune, r rune, from, to int) int {
	if from < 0 {
		from = 0
	}
	for k := from; k < to && k < len(s); k++ {
		if s[k] == r {
			return k
		}
	}
	return -1
}

// parseClass interprets "[" + stuff + "]" the way Python's sre_parse does
// for the subset of syntax that fnmatch.translate can produce.
func parseClass(stuff []rune) (token, error) {
	tk := token{kind: tokSet}
	p := 0
	if p < len(stuff) && stuff[p] == '^' {
		tk.negate = true
		p++
	}
	next := func() (rune, bool) {
		if p >= len(stuff) {
			return 0, false
		}
		r := stuff[p]
		p++
		if r == '\\' && p < len(stuff) {
			r = stuff[p]
			p++
		}
		return r, true
	}
	for p < len(stuff) {
		lo, _ := next()
		if p < len(stuff) && stuff[p] == '-' && p+1 < len(stuff) {
			p++ // the '-'
			hi, _ := next()
			if lo > hi {
				return tk, fmt.Errorf("%w: bad character range %c-%c (re.error in Python)", ErrBadPattern, lo, hi)
			}
			tk.ranges = append(tk.ranges, runeRange{lo, hi})
			continue
		}
		tk.single = append(tk.single, lo)
	}
	return tk, nil
}

// Match reports whether value matches the fnmatch pattern, with Python's
// fnmatch.fnmatchcase semantics. It returns ErrBadPattern where Python would
// raise.
func (p *Pattern) Match(value string) bool {
	s := []rune(value)
	t := p.toks
	si, ti := 0, 0
	starTi, starSi := -1, 0
	for si < len(s) {
		switch {
		case ti < len(t) && t[ti].kind == tokStar:
			starTi, starSi = ti, si
			ti++
		case ti < len(t) && t[ti].matches(s[si]):
			si++
			ti++
		case starTi >= 0:
			starSi++
			si = starSi
			ti = starTi + 1
		default:
			return false
		}
	}
	for ti < len(t) && t[ti].kind == tokStar {
		ti++
	}
	return ti == len(t)
}

// Match is fnmatch.fnmatchcase(value, pattern).
func Match(value, pattern string) (bool, error) {
	p, err := CompilePattern(pattern)
	if err != nil {
		return false, err
	}
	return p.Match(value), nil
}
