package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

func TestBuiltinMCPsExposeTwoPinnedReadOnlyServers(t *testing.T) {
	executable := []byte{'E', 'L', 'F', 0xff, 0xfe, 0x00, 0x80}
	adapter, err := NewBuiltinMCPs(executable)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceBuiltin})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"dirextalk-server-load", "dirextalk-server-time"}
	if len(page.Candidates) != len(wantIDs) {
		t.Fatalf("candidates=%d, want %d", len(page.Candidates), len(wantIDs))
	}
	for index, candidate := range page.Candidates {
		if candidate.ID != wantIDs[index] || candidate.Kind != core.KindMCP || candidate.Source != core.SourceBuiltin || candidate.Transport != core.TransportStdioStatic || candidate.Pin.RegistryVersion != builtinMCPVersion {
			t.Fatalf("candidate[%d]=%#v", index, candidate)
		}
		artifact, err := adapter.Fetch(context.Background(), candidate)
		if err != nil || artifact.Validate() != nil || artifact.Inspection.Execution.Stdio == nil || len(artifact.Inspection.NetworkGrants) != 0 || len(artifact.Inspection.SecretGrants) != 0 {
			t.Fatalf("artifact[%d]=%#v err=%v", index, artifact, err)
		}
		wantTool := strings.ReplaceAll(strings.TrimPrefix(candidate.ID, "dirextalk-"), "-", "_")
		if !reflect.DeepEqual(artifact.Inspection.Execution.Stdio.Argv, []string{"entry", wantTool}) {
			t.Fatalf("argv[%d]=%v", index, artifact.Inspection.Execution.Stdio.Argv)
		}
		var files []canonicalContentFile
		err = json.Unmarshal(artifact.Content, &files)
		if err != nil || len(files) != 2 {
			t.Fatalf("decode artifact[%d]: files=%#v err=%v", index, files, err)
		}
		decoded, err := base64.RawStdEncoding.DecodeString(files[0].Content)
		if err != nil || !reflect.DeepEqual(decoded, executable) {
			t.Fatalf("binary artifact[%d] drifted: %x err=%v", index, decoded, err)
		}
	}
}

func TestBuiltinCatalogRoutesBothKinds(t *testing.T) {
	skills, err := NewBuiltinSkills()
	if err != nil {
		t.Fatal(err)
	}
	mcps, err := NewBuiltinMCPs([]byte("ELF fixture"))
	if err != nil {
		t.Fatal(err)
	}
	catalog := &BuiltinCatalog{Skills: skills, MCPs: mcps}
	for _, kind := range []core.Kind{core.KindSkill, core.KindMCP} {
		page, err := catalog.Search(context.Background(), core.SearchQuery{Kind: kind, Source: core.SourceBuiltin})
		if err != nil || len(page.Candidates) == 0 {
			t.Fatalf("kind=%s page=%#v err=%v", kind, page, err)
		}
	}
}
