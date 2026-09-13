package main

import (
	"context"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

type recordingExtensionResolver struct {
	selections []coreconversation.ExtensionSelection
	resolved   []coreconversation.ResolvedExtension
	calls      int
}

func (r *recordingExtensionResolver) ResolveExtensions(_ context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	r.calls++
	r.selections = append([]coreconversation.ExtensionSelection(nil), selections...)
	return r.resolved, nil
}

// TestGroupToolChainIsTheOwnerChainPlusRoomReads guards the architecture this
// refactor exists for: the group does not keep a second catalog that has to be
// extended for every new tool. Whatever the owner's chain resolves is what a
// group turn resolves; the only group-specific additions are the room-scoped
// read tools, which by definition cannot exist in a private conversation.
func TestGroupToolChainIsTheOwnerChainPlusRoomReads(t *testing.T) {
	ownerTool := coreconversation.ResolvedExtension{Snapshot: coreconversation.ExtensionExecutionSnapshot{Source: "github-mcp"}}
	roomTool := coreconversation.ResolvedExtension{Snapshot: coreconversation.ExtensionExecutionSnapshot{Source: "group-message"}}
	base := &recordingExtensionResolver{resolved: []coreconversation.ResolvedExtension{ownerTool}}
	group := &recordingExtensionResolver{resolved: []coreconversation.ResolvedExtension{roomTool}}
	selections := []coreconversation.ExtensionSelection{{ID: "owner-selection"}}

	resolved, err := groupToolChain{base: base, group: group}.ResolveExtensions(context.Background(), selections)
	if err != nil {
		t.Fatal(err)
	}
	if base.calls != 1 || group.calls != 1 {
		t.Fatalf("chain calls base=%d group=%d", base.calls, group.calls)
	}
	if len(resolved) != 2 || resolved[0].Snapshot.Source != "github-mcp" || resolved[1].Snapshot.Source != "group-message" {
		t.Fatalf("group chain dropped an owner tool or reordered it: %+v", resolved)
	}
	if len(base.selections) != 1 || base.selections[0].ID != "owner-selection" {
		t.Fatalf("owner chain did not receive the turn's selections: %+v", base.selections)
	}
	// A group with no room-scoped resolver still serves the owner's tools.
	resolved, err = groupToolChain{base: base, group: nil}.ResolveExtensions(context.Background(), nil)
	if err != nil || len(resolved) != 1 || resolved[0].Snapshot.Source != "github-mcp" {
		t.Fatalf("group chain without room tools=%+v err=%v", resolved, err)
	}
}

// TestMarkGroupBoundMCPSharesOnlyBoundReadOnlyInstallations pins the group
// plugin marking: only the installations the owner bound to this room are
// marked, and only when the resolved tool is a read-only MCP tool that needs no
// confirmation and carries no skill instructions.
func TestMarkGroupBoundMCPSharesOnlyBoundReadOnlyInstallations(t *testing.T) {
	boundID := "11111111-1111-4111-8111-111111111111"
	otherID := "22222222-2222-4222-8222-222222222222"
	extension := func(installationID string, readOnly bool) coreconversation.ResolvedExtension {
		selection := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: installationID,
			Version: "1.0.0", Digest: strings.Repeat("a", 64), AllowedTools: []string{"read"}}
		return coreconversation.ResolvedExtension{Selection: selection, Snapshot: coreconversation.ExtensionExecutionSnapshot{
			Selection: selection, InstallationID: installationID, VersionID: "1.0.0", Source: "third-party",
			ContentDigest: selection.Digest, ArtifactDigest: selection.Digest, ToolNames: []string{"read"}, ReadOnly: readOnly}}
	}
	resolved := []coreconversation.ResolvedExtension{
		extension(boundID, true),
		extension(otherID, true),
		extension(boundID, false),
	}
	marked := markGroupBoundMCP(resolved, []string{boundID})
	if marked[0].Snapshot.Source != coreconversation.GroupBoundMCPSource {
		t.Fatalf("bound read-only installation was not marked: %+v", marked[0].Snapshot)
	}
	if marked[1].Snapshot.Source != "third-party" {
		t.Fatalf("unbound installation was marked: %+v", marked[1].Snapshot)
	}
	if marked[2].Snapshot.Source != "third-party" {
		t.Fatalf("mutating installation was marked: %+v", marked[2].Snapshot)
	}
	// No bindings (or an unreadable list) shares nothing.
	for _, none := range [][]string{nil, {}} {
		if got := markGroupBoundMCP(resolved, none); got[0].Snapshot.Source != "third-party" {
			t.Fatalf("empty bindings marked an installation: %+v", got[0].Snapshot)
		}
	}
}
