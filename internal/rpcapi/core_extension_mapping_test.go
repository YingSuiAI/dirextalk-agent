package rpcapi

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestExecutableSkillMappingPreservesDescriptor(t *testing.T) {
	proto := &agentv1.CoreExecution{Descriptor_: &agentv1.CoreExecution_Skill{Skill: &agentv1.CoreSkillEntry{
		RelativePath: "entry", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Executable: true, Argv: []string{"--serve"},
	}}}
	domain := executionFrom(proto)
	if domain.Skill == nil || !domain.Skill.Executable || domain.Skill.RelativePath != "entry" || len(domain.Skill.Argv) != 1 || domain.Skill.Argv[0] != "--serve" {
		t.Fatalf("domain skill=%#v", domain.Skill)
	}
	roundTrip := executionTo(domain)
	got := roundTrip.GetSkill()
	if got == nil || !got.Executable || got.RelativePath != "entry" || len(got.Argv) != 1 || got.Argv[0] != "--serve" {
		t.Fatalf("round-trip skill=%#v", got)
	}
	if err := domain.Validate(coreextension.KindSkill, coreextension.TransportSkillStatic); err != nil {
		t.Fatalf("descriptor validation: %v", err)
	}
}

func TestExtensionAdmissionRPCUsesFixedSafeSummaries(t *testing.T) {
	tests := []struct {
		err      error
		wantCode codes.Code
		message  string
		reason   string
	}{
		{coreextension.ErrInstallBusy, codes.FailedPrecondition, "Another extension installation is in progress", "extension_install_busy"},
		{coreextension.ErrInstallationLimit, codes.ResourceExhausted, "Extension installation capacity is exhausted", "extension_installation_limit"},
		{coreextension.ErrNodeStorageQuota, codes.ResourceExhausted, "Managed Node extension storage quota is exhausted", "extension_node_storage_quota"},
	}
	for _, test := range tests {
		got := extErr(test.err)
		if status.Code(got) != test.wantCode || status.Convert(got).Message() != test.message || strings.Contains(got.Error(), test.err.Error()) {
			t.Fatalf("error=%v rpc=%v", test.err, got)
		}
		details := status.Convert(got).Details()
		if len(details) != 1 {
			t.Fatalf("error=%v details=%v", test.err, details)
		}
		info, ok := details[0].(*errdetails.ErrorInfo)
		if !ok || info.Reason != test.reason || info.Domain != "dirextalk.agent.extension" {
			t.Fatalf("error=%v ErrorInfo=%#v", test.err, details[0])
		}
	}
}

func TestManagedNodeMappingPreservesRuntimeAndPublishesOnlyFinalReceipt(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	domainExecution := coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "node_modules/example/dist/index.js", Digest: digest, Runtime: "node"}}
	roundTrip := executionFrom(executionTo(domainExecution))
	if roundTrip.Stdio == nil || roundTrip.Stdio.Runtime != "node" || roundTrip.Stdio.RelativePath != domainExecution.Stdio.RelativePath {
		t.Fatalf("Node execution round trip=%#v", roundTrip.Stdio)
	}
	if sourceProto(agentv1.CoreExtensionSource_CORE_EXTENSION_SOURCE_NPM) != coreextension.SourceNPM || transportProto(agentv1.CoreExtensionTransport_CORE_EXTENSION_TRANSPORT_STDIO_NODE) != coreextension.TransportStdioNode {
		t.Fatal("managed Node source/transport enum mapping drifted")
	}
	receipt := &coreextension.NodeArtifactReceipt{PackageName: "example", PackageVersion: "1.0.0", ArtifactBytes: 1234, FileCount: 12, NodeVersion: coreextension.ManagedNodeVersion, NPMVersion: coreextension.ManagedNPMVersion, LifecycleScriptsDisabled: true, NativeAddonsAbsent: true}
	networkGrant := coreextension.NetworkGrant{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: digest}
	secretGrant := coreextension.SecretGrantDescriptor{ReferenceID: "00000000-0000-4000-8000-000000000001", Purpose: coreextension.SecretPurposeMCPCredential, BindingDigest: digest, Configured: true}
	installation := coreextension.Installation{NetworkGrants: []coreextension.NetworkGrant{networkGrant}, SecretGrants: []coreextension.SecretGrantDescriptor{secretGrant}, Versions: []coreextension.VersionRecord{{NodeArtifact: receipt, NetworkGrants: []coreextension.NetworkGrant{networkGrant}, SecretGrants: []coreextension.SecretGrantDescriptor{secretGrant}}}}
	mapped := installTo(installation)
	networkMatches := func(g *agentv1.CoreNetworkGrant) bool {
		return g != nil && g.Scheme == networkGrant.Scheme && g.Host == networkGrant.Host && g.Port == networkGrant.Port && g.PathPrefix == networkGrant.PathPrefix && g.Digest == networkGrant.Digest
	}
	secretMatches := func(g *agentv1.CoreExtensionSecretGrantDescriptor) bool {
		return g != nil && g.ReferenceId == secretGrant.ReferenceID && g.Purpose == purposeProto(secretGrant.Purpose) && g.BindingDigest == secretGrant.BindingDigest && g.Configured == secretGrant.Configured
	}
	if len(mapped.NetworkGrants) != 1 || !networkMatches(mapped.NetworkGrants[0]) || len(mapped.SecretGrants) != 1 || !secretMatches(mapped.SecretGrants[0]) || len(mapped.Versions[0].NetworkGrants) != 1 || !networkMatches(mapped.Versions[0].NetworkGrants[0]) || len(mapped.Versions[0].SecretGrants) != 1 || !secretMatches(mapped.Versions[0].SecretGrants[0]) {
		t.Fatalf("installation/version grant mapping drifted: %#v", mapped)
	}
	if got := installTo(installation).Versions[0].NodeArtifact; got != nil {
		t.Fatalf("prepared receipt leaked through public contract: %#v", got)
	}
	installation.Versions[0].PublishedAt = time.Now().UTC()
	got := installTo(installation).Versions[0].NodeArtifact
	if got == nil || got.PackageName != receipt.PackageName || got.PackageVersion != receipt.PackageVersion || got.ArtifactBytes != receipt.ArtifactBytes || got.FileCount != receipt.FileCount || got.NodeVersion != receipt.NodeVersion || got.NpmVersion != receipt.NPMVersion || !got.LifecycleScriptsDisabled || !got.NativeAddonsAbsent {
		t.Fatalf("published Node receipt mapping=%#v", got)
	}
}
