package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type conversationSkillReader struct {
	content []byte
	digest  string
	path    string
}

func (r *conversationSkillReader) ReadSkill(_ context.Context, digest, path string) ([]byte, error) {
	r.digest, r.path = digest, path
	return append([]byte(nil), r.content...), nil
}

func conversationResolverInstallation() coreextension.Installation {
	installID := "00000000-0000-4000-8000-000000000001"
	versionID := "00000000-0000-4000-8000-000000000002"
	digest := strings.Repeat("a", 64)
	echoSchema := json.RawMessage(`{"additionalProperties":false,"properties":{"text":{"type":"string"}},"required":["text"],"type":"object"}`)
	hiddenSchema := json.RawMessage(`{"additionalProperties":false,"properties":{},"type":"object"}`)
	return coreextension.Installation{
		ID: installID, Kind: coreextension.KindMCP, Source: coreextension.SourceOfficialRegistry,
		State: coreextension.StateInstalled, Enabled: true, Revision: 7, ActiveVersionID: versionID,
		Versions: []coreextension.VersionRecord{{
			VersionID: versionID, Pin: coreextension.SourcePin{RegistryVersion: "1.2.3"},
			ContentDigest: digest, ArtifactDigest: strings.Repeat("b", 64),
			NetworkSchemaDigest: strings.Repeat("c", 64), SecretSchemaDigest: strings.Repeat("d", 64),
			Tools: []coreextension.Tool{
				{Name: "echo", Description: "Run a bounded local echo task.", InputSchemaDigest: schemaDigest(echoSchema), InputSchema: echoSchema},
				{Name: "hidden", Description: "Not selected.", InputSchemaDigest: schemaDigest(hiddenSchema), InputSchema: hiddenSchema},
			},
		}},
	}
}

func conversationResolverSelection(installation coreextension.Installation) coreconversation.ExtensionSelection {
	return coreconversation.ExtensionSelection{
		Kind: coreconversation.ExtensionMCP, ID: installation.ID, Version: "1.2.3",
		Digest: installation.Versions[0].ContentDigest, AllowedTools: []string{"echo"},
	}
}

func TestConversationExtensionResolverPublishesOnlyExactAllowedToolSchemas(t *testing.T) {
	installation := conversationResolverInstallation()
	selection := conversationResolverSelection(installation)
	resolved, err := (conversationExtensionResolver{store: compositionExtensionStore{installation: installation}}).ResolveExtensions(context.Background(), []coreconversation.ExtensionSelection{selection})
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	extension := resolved[0]
	if extension.Selection.ID != selection.ID || len(extension.Selection.AllowedTools) != 1 || extension.Selection.AllowedTools[0] != "echo" ||
		len(extension.Snapshot.ToolNames) != 1 || extension.Snapshot.ToolNames[0] != "echo" || !extension.Snapshot.RequiresConfirmation ||
		len(extension.Tools) != 1 || extension.Tools[0].Name != "echo" || extension.Tools[0].Description != installation.Versions[0].Tools[0].Description {
		t.Fatalf("resolved extension=%+v", extension)
	}
	properties, ok := extension.Tools[0].InputSchema["properties"].(map[string]any)
	if !ok || properties["text"] == nil || extension.Snapshot.ToolSchemaDigest != toolSchemaDigest(installation.Versions[0].Tools[:1]) {
		t.Fatalf("exact schema was not preserved: tool=%+v snapshot=%+v", extension.Tools[0], extension.Snapshot)
	}
}

func TestConversationExtensionResolverInjectsPinnedSkillInstructionsWithoutTools(t *testing.T) {
	content := []byte("# Deploy service\n\nFollow the deployment workflow.")
	skillDigest := sha256.Sum256(content)
	installation := conversationResolverInstallation()
	installation.Kind = coreextension.KindSkill
	installation.Versions[0].Tools = nil
	installation.Versions[0].Execution = coreextension.ExecutionDescriptor{Skill: &coreextension.SkillEntry{
		RelativePath: "SKILL.md", Digest: hex.EncodeToString(skillDigest[:]),
	}}
	selection := conversationResolverSelection(installation)
	selection.Kind = coreconversation.ExtensionSkill
	selection.AllowedTools = nil
	reader := &conversationSkillReader{content: content}

	resolved, err := (conversationExtensionResolver{store: compositionExtensionStore{installation: installation}, skillReader: reader}).ResolveExtensions(context.Background(), []coreconversation.ExtensionSelection{selection})
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	extension := resolved[0]
	if len(extension.Tools) != 0 || extension.Snapshot.SkillInstructions != string(content) || !extension.Snapshot.ReadOnly || extension.Snapshot.RequiresConfirmation {
		t.Fatalf("resolved skill=%+v", extension)
	}
	if reader.digest != installation.Versions[0].ArtifactDigest || reader.path != "SKILL.md" {
		t.Fatalf("reader digest=%q path=%q", reader.digest, reader.path)
	}
}

func TestConversationExtensionResolverAutomaticallyAddsOwnedLocalSandbox(t *testing.T) {
	installation := conversationResolverInstallation()
	installation.Source = coreextension.SourceBuiltin
	installation.CandidateID = coreextension.BuiltinLocalSandboxCandidateID
	installation.Versions[0].Tools = installation.Versions[0].Tools[:1]
	installation.Versions[0].Tools[0].Name = coreextension.BuiltinLocalSandboxToolName
	installation.Versions[0].Tools[0].InputSchemaDigest = schemaDigest(installation.Versions[0].Tools[0].InputSchema)
	selection := conversationResolverSelection(installation)
	selection.AllowedTools = []string{coreextension.BuiltinLocalSandboxToolName}
	resolver := conversationExtensionResolver{store: compositionExtensionStore{installation: installation}, automatic: &selection}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000010", RootOperationId: "00000000-0000-4000-8000-000000000011"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
	merged, err := resolver.MergeAutomaticExtensions(ctx, nil)
	if err != nil || len(merged) != 1 || !sameExtensionSelection(merged[0], selection) {
		t.Fatalf("merged=%+v err=%v", merged, err)
	}
	resolved, err := resolver.ResolveExtensions(ctx, nil)
	if err != nil || len(resolved) != 1 || resolved[0].Snapshot.RequiresConfirmation || resolved[0].Tools[0].Name != coreextension.BuiltinLocalSandboxToolName {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if unauthenticated, err := resolver.MergeAutomaticExtensions(context.Background(), nil); err != nil || len(unauthenticated) != 0 {
		t.Fatalf("unauthenticated merge=%+v err=%v", unauthenticated, err)
	}
}

func TestConversationExtensionResolverSelectsActiveRecordWhenHistoricalVersionHasSamePin(t *testing.T) {
	installation := conversationResolverInstallation()
	active := installation.Versions[0]
	historical := active
	historical.VersionID = "00000000-0000-4000-8000-000000000003"
	historical.ContentDigest = strings.Repeat("e", 64)
	historical.ArtifactDigest = strings.Repeat("f", 64)
	installation.Versions = []coreextension.VersionRecord{historical, active}
	selection := conversationResolverSelection(installation)
	selection.Digest = active.ContentDigest

	resolved, err := (conversationExtensionResolver{store: compositionExtensionStore{installation: installation}}).ResolveExtensions(context.Background(), []coreconversation.ExtensionSelection{selection})
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if snapshot := resolved[0].Snapshot; snapshot.VersionID != active.VersionID || snapshot.ContentDigest != active.ContentDigest || snapshot.ArtifactDigest != active.ArtifactDigest {
		t.Fatalf("resolver selected historical version: %+v", snapshot)
	}
}

func TestConversationExtensionResolverRejectsMutableOrInexactSelections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*coreextension.Installation, *coreconversation.ExtensionSelection)
	}{
		{name: "disabled", mutate: func(i *coreextension.Installation, _ *coreconversation.ExtensionSelection) { i.Enabled = false }},
		{name: "kind mismatch", mutate: func(_ *coreextension.Installation, s *coreconversation.ExtensionSelection) {
			s.Kind = coreconversation.ExtensionSkill
		}},
		{name: "version id is not a pin", mutate: func(i *coreextension.Installation, s *coreconversation.ExtensionSelection) {
			s.Version = i.Versions[0].VersionID
		}},
		{name: "digest drift", mutate: func(_ *coreextension.Installation, s *coreconversation.ExtensionSelection) {
			s.Digest = strings.Repeat("e", 64)
		}},
		{name: "unknown tool", mutate: func(_ *coreextension.Installation, s *coreconversation.ExtensionSelection) {
			s.AllowedTools = []string{"missing"}
		}},
		{name: "duplicate tool", mutate: func(_ *coreextension.Installation, s *coreconversation.ExtensionSelection) {
			s.AllowedTools = []string{"echo", "echo"}
		}},
		{name: "empty allowlist", mutate: func(_ *coreextension.Installation, s *coreconversation.ExtensionSelection) { s.AllowedTools = nil }},
		{name: "schema digest drift", mutate: func(i *coreextension.Installation, _ *coreconversation.ExtensionSelection) {
			i.Versions[0].Tools[0].InputSchemaDigest = strings.Repeat("f", 64)
		}},
		{name: "non object schema", mutate: func(i *coreextension.Installation, _ *coreconversation.ExtensionSelection) {
			i.Versions[0].Tools[0].InputSchema = json.RawMessage(`[]`)
			i.Versions[0].Tools[0].InputSchemaDigest = schemaDigest(i.Versions[0].Tools[0].InputSchema)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installation := conversationResolverInstallation()
			selection := conversationResolverSelection(installation)
			test.mutate(&installation, &selection)
			resolved, err := (conversationExtensionResolver{store: compositionExtensionStore{installation: installation}}).ResolveExtensions(context.Background(), []coreconversation.ExtensionSelection{selection})
			if err == nil || len(resolved) != 0 {
				t.Fatalf("resolved=%+v err=%v", resolved, err)
			}
		})
	}
}
