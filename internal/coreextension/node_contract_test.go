package coreextension

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func nodeContractFixture() (Candidate, Inspection, NodeArtifactReceipt) {
	digest := strings.Repeat("a", 64)
	candidate := Candidate{
		ID:        "@dirextalk/example-mcp",
		Kind:      KindMCP,
		Source:    SourceNPM,
		Name:      "Example MCP",
		Pin:       SourcePin{RegistryVersion: "1.2.3", RegistrySHA256: digest},
		Transport: TransportStdioNode,
	}
	execution := ExecutionDescriptor{Stdio: &StaticEntry{RelativePath: "node_modules/@dirextalk/example-mcp/dist/index.js", Digest: digest, Runtime: "node"}}
	inspection := Inspection{Candidate: candidate, ContentDigest: digest, ManifestDigest: digest, ExecutionDigest: digest, NetworkSchemaDigest: digest, SecretSchemaDigest: digest, Execution: execution}
	receipt := NodeArtifactReceipt{
		InputDigest:              digest,
		ArtifactDigest:           digest,
		ArtifactBytes:            1024,
		FileCount:                12,
		EntryPath:                execution.Stdio.RelativePath,
		EntrySHA256:              digest,
		PackageName:              candidate.ID,
		PackageVersion:           candidate.Pin.RegistryVersion,
		LockSHA256:               digest,
		NodeVersion:              ManagedNodeVersion,
		NPMVersion:               ManagedNPMVersion,
		LifecycleScriptsDisabled: true,
		NativeAddonsAbsent:       true,
	}
	return candidate, inspection, receipt
}

func TestManagedNodeMCPContractAcceptsOnlyImmutableNPMOrGitHubInputs(t *testing.T) {
	candidate, inspection, receipt := nodeContractFixture()
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid exact npm candidate: %v", err)
	}
	if err := inspection.Validate(); err != nil {
		t.Fatalf("valid Node inspection: %v", err)
	}
	mutation := Mutation{Candidate: candidate, Inspection: inspection, ArtifactDigest: receipt.ArtifactDigest, ArtifactCleanupToken: uuid.NewString(), NodeArtifact: &receipt}
	if err := mutation.ValidateArtifactReceipt(); err != nil {
		t.Fatalf("valid offline build receipt: %v", err)
	}

	for _, version := range []string{"latest", "1", "1.2", "^1.2.3", "~1.2.3", ">=1.2.3", "1.2.x", "1.2.3 || 2.0.0", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01"} {
		invalid := candidate
		invalid.Pin.RegistryVersion = version
		if invalid.Validate() == nil {
			t.Fatalf("accepted non-exact npm version %q", version)
		}
	}
	for _, name := range []string{"Example", "@Dirextalk/example", "@dirextalk/Example", "../example", "@dirextalk", "@dirextalk/example/extra"} {
		invalid := candidate
		invalid.ID = name
		if invalid.Validate() == nil {
			t.Fatalf("accepted invalid npm package name %q", name)
		}
	}

	github := candidate
	github.ID = "dirextalk/example-mcp"
	github.Source = SourceGitHub
	github.Pin = SourcePin{GitCommit: strings.Repeat("b", 40), GitSHA256: strings.Repeat("c", 64)}
	if err := github.Validate(); err != nil {
		t.Fatalf("valid exact GitHub commit: %v", err)
	}
	github.Pin.GitCommit = "main"
	if github.Validate() == nil {
		t.Fatal("accepted mutable GitHub ref")
	}
}

func TestManagedNodeMCPContractRejectsUnsafeRuntimeAndBuildReceipts(t *testing.T) {
	candidate, inspection, receipt := nodeContractFixture()

	unsafeInspection := inspection
	unsafeInspection.Execution = ExecutionDescriptor{Stdio: &StaticEntry{RelativePath: inspection.Execution.Stdio.RelativePath, Digest: inspection.Execution.Stdio.Digest}}
	if unsafeInspection.Validate() == nil {
		t.Fatal("accepted Node execution without the managed runtime")
	}
	unsafeInspection = inspection
	unsafeInspection.NetworkGrants = []NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/", Digest: strings.Repeat("d", 64)}}
	if unsafeInspection.Validate() == nil {
		t.Fatal("accepted runtime network grant for managed Node")
	}

	cases := []struct {
		name   string
		mutate func(*NodeArtifactReceipt)
	}{
		{"oversize", func(r *NodeArtifactReceipt) { r.ArtifactBytes = MaxNodeArtifactBytes + 1 }},
		{"too_many_files", func(r *NodeArtifactReceipt) { r.FileCount = MaxNodeArtifactFiles + 1 }},
		{"scripts_not_disabled", func(r *NodeArtifactReceipt) { r.LifecycleScriptsDisabled = false }},
		{"native_addon", func(r *NodeArtifactReceipt) { r.NativeAddonsAbsent = false }},
		{"wrong_node", func(r *NodeArtifactReceipt) { r.NodeVersion = "v22.0.0" }},
		{"wrong_npm", func(r *NodeArtifactReceipt) { r.NPMVersion = "10.0.0" }},
		{"wrong_package", func(r *NodeArtifactReceipt) { r.PackageName = "other" }},
		{"wrong_entry", func(r *NodeArtifactReceipt) { r.EntryPath = "dist/other.js" }},
		{"wrong_input", func(r *NodeArtifactReceipt) { r.InputDigest = strings.Repeat("e", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invalid := receipt
			tc.mutate(&invalid)
			mutation := Mutation{Candidate: candidate, Inspection: inspection, ArtifactDigest: receipt.ArtifactDigest, ArtifactCleanupToken: uuid.NewString(), NodeArtifact: &invalid}
			if !errors.Is(mutation.ValidateArtifactReceipt(), ErrInvalid) {
				t.Fatal("accepted unsafe managed Node build receipt")
			}
		})
	}

	nonNode := candidate
	nonNode.Source = SourceOfficialRegistry
	nonNode.Transport = TransportStdioStatic
	nonNode.Pin = SourcePin{RegistryVersion: "1", RegistrySHA256: strings.Repeat("a", 64)}
	nonNodeInspection := inspection
	nonNodeInspection.Candidate = nonNode
	nonNodeInspection.Execution.Stdio.Runtime = ""
	if err := (Mutation{Candidate: nonNode, Inspection: nonNodeInspection, ArtifactDigest: receipt.ArtifactDigest, ArtifactCleanupToken: uuid.NewString(), NodeArtifact: &receipt}).ValidateArtifactReceipt(); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted a Node build receipt for native stdio")
	}
}

func TestManagedNodePublicProjectionNeverExposesPreparedAuthority(t *testing.T) {
	_, _, receipt := nodeContractFixture()
	prepared := VersionRecord{
		ArtifactPath:         "prepared/private",
		ArtifactDigest:       receipt.ArtifactDigest,
		ArtifactCleanupToken: uuid.NewString(),
		NodeArtifact:         &receipt,
		Execution: ExecutionDescriptor{Stdio: &StaticEntry{
			RelativePath: "dist/index.js",
			Digest:       strings.Repeat("a", 64),
			Runtime:      "node",
		}},
	}
	public := (Installation{Versions: []VersionRecord{prepared}}).Public().Versions[0]
	if public.NodeArtifact != nil {
		t.Fatalf("prepared authority leaked through public projection: %#v", public)
	}
	prepared.PublishedAt = time.Now().UTC()
	public = (Installation{Versions: []VersionRecord{prepared}}).Public().Versions[0]
	if public.NodeArtifact == nil || public.NodeArtifact.PackageName != receipt.PackageName {
		t.Fatalf("published projection missing safe receipt or exposed authority: %#v", public)
	}
	raw, err := json.Marshal((Installation{Versions: []VersionRecord{prepared}}).Public())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		t.Fatal("public installation JSON is invalid")
	}
	versions := object["versions"].([]any)
	version := versions[0].(map[string]any)
	for _, forbidden := range []string{"artifact_path", "artifact_digest", "artifact_cleanup_token", "published_at", "tools"} {
		if _, exists := version[forbidden]; exists {
			t.Fatalf("public version exposed %q: %s", forbidden, raw)
		}
	}
	for _, field := range []string{"network_grants", "secret_grants"} {
		value, ok := version[field].([]any)
		if !ok || len(value) != 0 {
			t.Fatalf("public version %s is not an explicit empty array: %s", field, raw)
		}
	}
	if value, ok := object["network_grants"].([]any); !ok || len(value) != 0 {
		t.Fatalf("public installation network_grants is not an explicit empty array: %s", raw)
	}
	if value, ok := object["secret_grants"].([]any); !ok || len(value) != 0 {
		t.Fatalf("public installation secret_grants is not an explicit empty array: %s", raw)
	}
	execution := version["execution"].(map[string]any)
	stdio := execution["stdio"].(map[string]any)
	if argv, ok := stdio["argv"].([]any); !ok || len(argv) != 0 {
		t.Fatalf("public Node stdio argv is not an explicit empty array: %s", raw)
	}
	node := version["node_artifact"].(map[string]any)
	if len(node) != 8 {
		t.Fatalf("public Node receipt fields=%v, want exactly 8", node)
	}
	if disabled, ok := node["lifecycle_scripts_disabled"].(bool); !ok || !disabled {
		t.Fatalf("public Node receipt missing trusted scripts-disabled fact: %s", raw)
	}
	for _, forbidden := range []string{"input_digest", "artifact_digest", "entry_path", "entry_sha256", "lock_sha256", "cleanup_token", "lifecycle_scripts_absent"} {
		if _, exists := node[forbidden]; exists {
			t.Fatalf("public Node receipt exposed %q: %s", forbidden, raw)
		}
	}
}

func TestManagedNodeInternalReceiptRejectsSupersededLifecycleKey(t *testing.T) {
	candidate, inspection, valid := nodeContractFixture()
	raw, _ := json.Marshal(valid)
	raw = []byte(strings.Replace(string(raw), `"lifecycle_scripts_disabled":true`, `"lifecycle_scripts_absent":true`, 1))
	var decoded NodeArtifactReceipt
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(candidate, inspection.Execution, valid.ArtifactDigest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("superseded receipt key accepted: %v", err)
	}
}
