package workeramictl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
)

func TestPersistBuilderReachabilityEvidenceUpgradesPartialStateAtomically(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "publication.json.builder-reachability")
	partial := workerami.BuilderReachabilityEvidenceV2{
		SchemaVersion: workerami.BuilderReachabilitySchemaV2, AgentInstanceID: "11111111-1111-4111-8111-111111111111",
		AccountID: "123456789012", Region: "us-west-2", BuildDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		VPCID: "vpc-0123456789abcdef0", RouteTableID: "rtb-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0",
		S3PrefixListID: "pl-0123456789abcdef0", ArtifactBucket: "dtx-worker-artifacts", ArtifactKey: "worker-ami/releases/rootfs.tar",
		VPCEndpointID: "vpce-0123456789abcdef0",
	}
	if err := persistBuilderReachabilityEvidence(path, partial); err != nil {
		t.Fatalf("persist partial evidence: %v", err)
	}
	full := partial
	full.SecurityGroupRuleID = "sgr-0123456789abcdef0"
	if err := persistBuilderReachabilityEvidence(path, full); err != nil {
		t.Fatalf("upgrade to complete evidence: %v", err)
	}
	persisted, err := readBuilderReachabilityEvidence(path)
	if err != nil || persisted != full || persisted.Validate() != nil {
		t.Fatalf("persisted evidence = %#v, %v", persisted, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode = %v, %v", info, err)
	}
	if err := persistBuilderReachabilityEvidence(path, partial); err != nil {
		t.Fatalf("endpoint-first replay after complete evidence: %v", err)
	}
	conflict := full
	conflict.VPCEndpointID = "vpce-11111111111111111"
	if err := persistBuilderReachabilityEvidence(path, conflict); err == nil {
		t.Fatal("conflicting endpoint evidence was accepted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("temporary recovery files leaked: %#v, %v", entries, err)
	}
}
