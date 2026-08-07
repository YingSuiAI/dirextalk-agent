package cloudworker

import (
	"strings"
	"testing"
	"unicode/utf8"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
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
			for _, current := range test.input[len([]byte(got)):] {
				if len([]byte(got))+len(string(current)) <= coretask.MaxSummaryBytes {
					t.Fatalf("summary left room for the next rune: bytes=%d next=%q", len([]byte(got)), current)
				}
				break
			}
		})
	}
}

func TestCentrallyQualifiedSummaryIsUTF8SafeAndBounded(t *testing.T) {
	final := cloudruntime.PiFinalV1{
		Status:       "completed",
		Summary:      strings.Repeat("中文结果", coretask.MaxSummaryBytes),
		Deliverables: []string{strings.Repeat("交付物", coretask.MaxSummaryBytes)},
		Tests:        []string{strings.Repeat("检查", coretask.MaxSummaryBytes)},
	}

	got := centrallyQualifiedSummary(final)
	if got == "" || len([]byte(got)) > coretask.MaxSummaryBytes || !utf8.ValidString(got) ||
		!strings.HasPrefix(got, "Cloud Worker result") {
		t.Fatalf("bounded summary: valid=%t bytes=%d value=%q", utf8.ValidString(got), len([]byte(got)), got)
	}
}
