// Package artifactname validates user-facing deliverable file names.
package artifactname

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const MaximumBytes = 255

// Valid reports whether value is a safe, normalized, single-component file
// name. It intentionally accepts Unicode, mixed case, and spaces.
func Valid(value string) bool {
	if value == "" || len(value) > MaximumBytes || !utf8.ValidString(value) ||
		!norm.NFC.IsNormalString(value) || strings.TrimSpace(value) != value ||
		value == "." || value == ".." || strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") || strings.ContainsAny(value, `/\\<>:"|?*`) {
		return false
	}
	return strings.IndexFunc(value, unsafeRune) < 0
}

func unsafeRune(value rune) bool {
	if unicode.IsControl(value) {
		return true
	}
	// Reject bidirectional controls that can make a displayed extension differ
	// from the actual file name while preserving ordinary Unicode and emoji.
	return value == '\u061c' || value == '\u200e' || value == '\u200f' ||
		(value >= '\u202a' && value <= '\u202e') ||
		(value >= '\u2066' && value <= '\u2069')
}
