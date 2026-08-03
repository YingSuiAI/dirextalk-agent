package githubsource

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGitHubSourceFactBindsInputArtifactAndAWSConnection(t *testing.T) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	bindingDigest, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := SnapshotV1{
		SchemaVersion:      SnapshotSchemaV1,
		InputID:            binding.InputID,
		InputDigest:        binding.InputDigest,
		InputBindingDigest: bindingDigest,
		SourceDigest:       binding.SourceDigest,
		Repository:         binding.Repository,
		WorkspaceDigest:    "sha256:" + strings.Repeat("a", 64),
		SizeBytes:          4096,
		FileCount:          3,
	}
	connectionID := uuid.NewString()
	artifact, err := NewArtifactV1(
		snapshot,
		connectionID,
		"dirextalk-artifacts-123456789012-ap-northeast-3",
		"opaque-version-id",
	)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := NewFactV1(snapshot, artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fact.Digest()
	if err != nil {
		t.Fatal(err)
	}
	stored := StoredFact{
		Fact:       fact,
		FactDigest: digest,
		CreatedAt:  time.Now().UTC(),
	}
	if stored.Validate() != nil ||
		artifact.Key != "source-snapshots/github/"+
			binding.InputID+"/"+
			strings.Repeat("a", 64)+".tar" {
		t.Fatalf("invalid source fact: %#v", stored)
	}
}

func TestGitHubSourceFactRejectsSubstitution(t *testing.T) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	bindingDigest, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := SnapshotV1{
		SchemaVersion:      SnapshotSchemaV1,
		InputID:            binding.InputID,
		InputDigest:        binding.InputDigest,
		InputBindingDigest: bindingDigest,
		SourceDigest:       binding.SourceDigest,
		Repository:         binding.Repository,
		WorkspaceDigest:    "sha256:" + strings.Repeat("b", 64),
		SizeBytes:          2048,
		FileCount:          1,
	}
	artifact, err := NewArtifactV1(
		snapshot,
		uuid.NewString(),
		"dirextalk-artifacts-123456789012-ap-northeast-3",
		"version-one",
	)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := NewFactV1(snapshot, artifact)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*FactV1)
	}{
		{
			name: "connection",
			mutate: func(value *FactV1) {
				value.ConnectionID = uuid.NewString()
			},
		},
		{
			name: "source",
			mutate: func(value *FactV1) {
				value.Snapshot.SourceDigest =
					"sha256:" + strings.Repeat("c", 64)
			},
		},
		{
			name: "workspace artifact",
			mutate: func(value *FactV1) {
				value.Artifact.WorkspaceDigest =
					"sha256:" + strings.Repeat("d", 64)
			},
		},
		{
			name: "object key",
			mutate: func(value *FactV1) {
				value.Artifact.Key = "source-snapshots/github/other.tar"
			},
		},
		{
			name: "version",
			mutate: func(value *FactV1) {
				value.Artifact.VersionID = "bad\nversion"
			},
		},
	}
	for _, testCase := range tests {
		changed := fact
		testCase.mutate(&changed)
		if changed.Validate() == nil {
			t.Fatalf("%s substitution was accepted", testCase.name)
		}
	}
}
