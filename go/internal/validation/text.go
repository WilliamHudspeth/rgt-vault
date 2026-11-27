package validation

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// safeCategories are the Unicode general categories allowed in free-form
// text (python: _SAFE_UNICODE_CATEGORIES). Control (Cc), format (Cf),
// surrogate (Cs), private-use (Co), unassigned (Cn), combining marks
// (Mn, Mc, Me) and line/paragraph separators (Zl, Zp) are excluded.
var safeCategories = []*unicode.RangeTable{
	unicode.Lu, unicode.Ll, unicode.Lt, unicode.Lm, unicode.Lo,
	unicode.Nd, unicode.Nl, unicode.No,
	unicode.Pc, unicode.Pd, unicode.Ps, unicode.Pe, unicode.Pi, unicode.Pf, unicode.Po,
	unicode.Sm, unicode.Sc, unicode.Sk, unicode.So,
	unicode.Zs,
}

// allCategories lists the two-letter general categories that have tables
// (unicode.Categories also holds one-letter groups and "LC").
var allCategories = []string{
	"Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me", "Nd", "Nl", "No",
	"Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So",
	"Zs", "Zl", "Zp", "Cc", "Cf", "Cs", "Co",
}

// categoryOf returns the two-letter general category of r ("Cn" if
// unassigned), as unicodedata.category does.
func categoryOf(r rune) string {
	for _, name := range allCategories {
		if unicode.Is(unicode.Categories[name], r) {
			return name
		}
	}
	return "Cn"
}

// Form is a Unicode normalization form.
type Form string

// Supported forms for NormalizeUnicodeForm.
const (
	NFC  Form = "NFC"
	NFD  Form = "NFD"
	NFKC Form = "NFKC"
	NFKD Form = "NFKD"
)

func (f Form) norm() (norm.Form, bool) {
	switch f {
	case NFC:
		return norm.NFC, true
	case NFD:
		return norm.NFD, true
	case NFKC:
		return norm.NFKC, true
	case NFKD:
		return norm.NFKD, true
	}
	return 0, false
}

// NormalizeUnicode returns text after NFC normalization and rejects any
// character outside the safe category set (python: normalize_unicode).
func NormalizeUnicode(text string) (string, error) {
	return NormalizeUnicodeForm(text, NFC)
}

// NormalizeUnicodeForm is NormalizeUnicode with an explicit form. An unknown
// form is a validation error (Python raises ValueError).
func NormalizeUnicodeForm(text string, form Form) (string, error) {
	nf, ok := form.norm()
	if !ok {
		return "", fail("unsupported normalization form %q", string(form))
	}
	if !utf8.ValidString(text) {
		return "", fail("Input is not valid UTF-8.")
	}
	normalized := nf.String(text)
	i := 0
	for _, r := range normalized {
		if !unicode.In(r, safeCategories...) {
			return "", fail("Character at position %d (U+%04X, category '%s') is not permitted in this field.",
				i, r, categoryOf(r))
		}
		i++
	}
	return normalized, nil
}

// ValidateFreeText validates and normalizes a free-text field (note,
// purpose, description): NFC, category allowlist, and a length cap of
// maxLen characters measured after normalization (python: validate_free_text;
// use DefaultFreeTextMax for Python's default).
func ValidateFreeText(value string, maxLen int) (string, error) {
	normalized, err := NormalizeUnicode(value)
	if err != nil {
		return "", err
	}
	if utf8.RuneCountInString(normalized) > maxLen {
		return "", fail("Field exceeds maximum length of %d characters after normalization.", maxLen)
	}
	return normalized, nil
}
