package coreruntime

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

// boundedSummary truncates a user-visible Agent result summary at a UTF-8 rune
// boundary. It performs no I/O and always returns at most MaxSummaryBytes.
func boundedSummary(s string) string {
	if len([]byte(s)) <= coretask.MaxSummaryBytes {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		n := len(string(r))
		if b.Len()+n > coretask.MaxSummaryBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
