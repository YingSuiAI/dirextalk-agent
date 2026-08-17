package cloudworker

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func TestBoundedSummaryPreservesUTF8AndByteLimit(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "chinese", input: strings.Repeat("重任务结果", 1200)},
		{name: "emoji", input: strings.Repeat("🧪", 1500)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := boundedSummary(test.input)
			if !utf8.ValidString(got) || len([]byte(got)) > coretask.MaxSummaryBytes {
				t.Fatalf("invalid bounded summary: valid=%t bytes=%d", utf8.ValidString(got), len([]byte(got)))
			}
			if got == "" || !strings.HasPrefix(test.input, got) {
				t.Fatalf("bounded summary is not a non-empty rune prefix")
			}
			if remainder := test.input[len([]byte(got)):]; remainder != "" {
				current, _ := utf8.DecodeRuneInString(remainder)
				if len([]byte(got))+len(string(current)) <= coretask.MaxSummaryBytes {
					t.Fatalf("summary left room for the next rune: bytes=%d next=%q", len([]byte(got)), current)
				}
			}
		})
	}
}
