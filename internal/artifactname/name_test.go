package artifactname

import (
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestValidAcceptsUserFacingFileNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"Dirextalk_Business_Plan.pptx",
		"Dirextalk 商业计划书 2026.pptx",
		"经营分析报告.md",
		"结果 01.json",
	} {
		if !Valid(name) {
			t.Fatalf("Valid(%q) = false", name)
		}
	}
}

func TestValidRejectsUnsafeOrAmbiguousFileNames(t *testing.T) {
	t.Parallel()
	decomposed := norm.NFD.String("Café.md")
	for _, name := range []string{
		"", ".", "..", ".hidden", "trailing.", " report.md",
		"report.md ", "../report.md", `folder\\report.md`, "bad\nname.md",
		"report?.md", "invoice\u202egpj.exe", decomposed,
		strings.Repeat("中", 86) + ".md",
	} {
		if Valid(name) {
			t.Fatalf("Valid(%q) = true", name)
		}
	}
}
