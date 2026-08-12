package source

import (
	"context"
	"reflect"
	"strings"
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

func TestBuiltinSkillsExposePinnedNetworkFreeCatalog(t *testing.T) {
	adapter, err := NewBuiltinSkills()
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindSkill, Source: core.SourceBuiltin, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"dirextalk-research-and-verify", "dirextalk-review-code", "dirextalk-verify-delivery", "dirextalk-write-technical-docs"}
	if len(page.Candidates) != len(wantIDs) {
		t.Fatalf("candidates = %d, want %d", len(page.Candidates), len(wantIDs))
	}
	for index, candidate := range page.Candidates {
		if candidate.ID != wantIDs[index] || candidate.Source != core.SourceBuiltin || candidate.Kind != core.KindSkill || candidate.Pin.RegistryVersion != builtinSkillVersion || len(candidate.Pin.RegistrySHA256) != 64 {
			t.Fatalf("candidate[%d] = %#v", index, candidate)
		}
		if candidate.Name != candidate.ID || !strings.HasPrefix(candidate.ID, "dirextalk-") || strings.Contains(strings.ToLower(candidate.ID+" "+candidate.Name), "adam") {
			t.Fatalf("candidate[%d] exposes non-Dirextalk identity: %#v", index, candidate)
		}
		inspection, inspectErr := adapter.Inspect(context.Background(), core.InspectRequest{Kind: core.KindSkill, Source: core.SourceBuiltin, ID: candidate.ID, Pin: candidate.Pin})
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		artifact, fetchErr := adapter.Fetch(context.Background(), candidate)
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		if artifact.Validate() != nil || !reflect.DeepEqual(artifact.Inspection, inspection) || inspection.Execution.Skill == nil || inspection.Execution.Skill.RelativePath != "SKILL.md" || len(inspection.NetworkGrants) != 0 || len(inspection.SecretGrants) != 0 {
			t.Fatalf("invalid builtin artifact for %s", candidate.ID)
		}
		definition := builtinSkillDefinitions[index]
		files, readErr := readBuiltinSkillFiles(definition.Directory)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var skillBody string
		for _, file := range files {
			if file.Path == "SKILL.md" {
				skillBody = file.Content
				break
			}
		}
		if !strings.HasPrefix(skillBody, "---\nname: "+candidate.ID+"\n") || strings.Contains(strings.ToLower(skillBody), "adam") {
			t.Fatalf("SKILL.md identity for %s is not canonical", candidate.ID)
		}
	}
}

func TestBuiltinSkillsRejectDriftAndUnsupportedSource(t *testing.T) {
	adapter, err := NewBuiltinSkills()
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindSkill, Source: core.SourceBuiltin, Text: "code"})
	if err != nil || len(page.Candidates) != 1 || page.Candidates[0].ID != "dirextalk-review-code" {
		t.Fatalf("filtered page = %#v, err = %v", page, err)
	}
	candidate := page.Candidates[0]
	drift := candidate
	drift.Description = "changed"
	if _, err := adapter.Fetch(context.Background(), drift); err == nil {
		t.Fatal("expected drift rejection")
	}
	if _, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceBuiltin}); err == nil {
		t.Fatal("expected MCP rejection")
	}
}
