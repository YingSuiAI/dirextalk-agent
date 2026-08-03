package awsartifact

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/google/uuid"
)

func TestBundlePublisherPublishesAndCopiesVersionBoundGitHubSource(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	compiled, workspaceBytes := teamArtifactFixture(t, deploymentID)
	defer compiled.Destroy()
	snapshot := githubSourceSnapshotFixture(t, workspaceBytes)
	content := &memoryTeamWorkspace{content: workspaceBytes}

	artifact, err := publisher.PublishGitHubSourceSnapshot(
		context.Background(),
		connection,
		snapshot,
		content,
	)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Validate() != nil ||
		artifact.ConnectionID != connection.ConnectionID ||
		artifact.VersionID != "version-1" ||
		artifact.Key != githubsource.ArtifactKey(snapshot) {
		t.Fatalf("invalid source artifact: %#v", artifact)
	}
	spec, err := publisher.foundationSpec(connection)
	if err != nil {
		t.Fatal(err)
	}
	sourceName := artifact.Bucket + "/" + artifact.Key
	source, ok := factory.client.objects[sourceName]
	if !ok ||
		!bytes.Equal(source.payload, workspaceBytes) ||
		source.contentType != githubsource.SourceArtifactMediaType ||
		source.metadata["kind"] != githubSourceArtifactKind ||
		source.metadata["input-id"] != snapshot.InputID ||
		source.metadata["input-digest"] !=
			strings.TrimPrefix(snapshot.InputDigest, "sha256:") ||
		source.metadata["input-binding-digest"] !=
			strings.TrimPrefix(
				snapshot.InputBindingDigest,
				"sha256:",
			) ||
		source.metadata["source-digest"] !=
			strings.TrimPrefix(snapshot.SourceDigest, "sha256:") ||
		source.kmsKey != "alias/"+spec.StackName ||
		!source.bucketKey {
		t.Fatalf("unsafe source snapshot object: %#v", source)
	}
	sourceTags, err := url.ParseQuery(source.tagging)
	if err != nil ||
		sourceTags.Get("dirextalk:input_id") != snapshot.InputID ||
		sourceTags.Get("dirextalk:component") !=
			githubSourceArtifactKind {
		t.Fatalf("unsafe source tags: %q", source.tagging)
	}

	puts := factory.client.putCalls
	replayed, err := publisher.PublishGitHubSourceSnapshot(
		context.Background(),
		connection,
		snapshot,
		content,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != artifact ||
		factory.client.putCalls != puts ||
		content.opens != 2 {
		t.Fatalf(
			"source replay artifact=%#v puts=%d want=%d opens=%d",
			replayed,
			factory.client.putCalls,
			puts,
			content.opens,
		)
	}

	workspace, err := NewGitHubSourceWorkspace(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishTeamInputs(
		context.Background(),
		connection,
		deploymentID,
		compiled,
		workspace,
	); err != nil {
		t.Fatal(err)
	}
	targetName := artifact.Bucket + "/deployments/" +
		deploymentID + "/artifacts/" +
		compiled.WorkspaceObject.ObjectName
	target, ok := factory.client.objects[targetName]
	if !ok ||
		!bytes.Equal(target.payload, workspaceBytes) ||
		target.metadata["kind"] != "worker-input" ||
		target.metadata["deployment-id"] != deploymentID ||
		target.metadata["sha256"] != strings.TrimPrefix(
			snapshot.WorkspaceDigest,
			"sha256:",
		) {
		t.Fatalf("unsafe copied Worker input: %#v", target)
	}
	targetTags, err := url.ParseQuery(target.tagging)
	if err != nil ||
		targetTags.Get("dirextalk:deployment_id") != deploymentID ||
		targetTags.Get("dirextalk:component") != "worker-input" {
		t.Fatalf("unsafe copied Worker tags: %q", target.tagging)
	}
	puts = factory.client.putCalls
	copies := factory.client.copyCalls
	if err := publisher.PublishTeamInputs(
		context.Background(),
		connection,
		deploymentID,
		compiled,
		workspace,
	); err != nil {
		t.Fatal(err)
	}
	if factory.client.putCalls != puts ||
		factory.client.copyCalls != copies ||
		copies != 1 {
		t.Fatalf(
			"Team input replay puts=%d want=%d copies=%d want=%d",
			factory.client.putCalls,
			puts,
			factory.client.copyCalls,
			copies,
		)
	}
}

func TestBundlePublisherRejectsGitHubSourceSubstitutions(t *testing.T) {
	t.Run("local content", func(t *testing.T) {
		publisher, factory, connection, _ := publisherFixture(t)
		snapshot := githubSourceSnapshotFixture(
			t,
			[]byte("approved-workspace"),
		)
		_, err := publisher.PublishGitHubSourceSnapshot(
			context.Background(),
			connection,
			snapshot,
			&memoryTeamWorkspace{content: []byte("substituted")},
		)
		if !errors.Is(err, ErrSourceIntegrity) ||
			factory.calls != 0 ||
			factory.client.putCalls != 0 {
			t.Fatalf(
				"content substitution err=%v factory=%d puts=%d",
				err,
				factory.calls,
				factory.client.putCalls,
			)
		}
	})

	t.Run("source version", func(t *testing.T) {
		publisher, factory, connection, deploymentID := publisherFixture(t)
		compiled, workspaceBytes := teamArtifactFixture(t, deploymentID)
		defer compiled.Destroy()
		snapshot := githubSourceSnapshotFixture(t, workspaceBytes)
		artifact, err := publisher.PublishGitHubSourceSnapshot(
			context.Background(),
			connection,
			snapshot,
			&memoryTeamWorkspace{content: workspaceBytes},
		)
		if err != nil {
			t.Fatal(err)
		}
		artifact.VersionID = "substituted-version"
		workspace, err := NewGitHubSourceWorkspace(artifact)
		if err != nil {
			t.Fatal(err)
		}
		err = publisher.PublishTeamInputs(
			context.Background(),
			connection,
			deploymentID,
			compiled,
			workspace,
		)
		if !errors.Is(err, ErrSourceIntegrity) ||
			factory.client.copyCalls != 0 {
			t.Fatalf(
				"version substitution err=%v copies=%d",
				err,
				factory.client.copyCalls,
			)
		}
	})

	t.Run("AWS connection", func(t *testing.T) {
		publisher, factory, connection, deploymentID := publisherFixture(t)
		compiled, workspaceBytes := teamArtifactFixture(t, deploymentID)
		defer compiled.Destroy()
		snapshot := githubSourceSnapshotFixture(t, workspaceBytes)
		artifact, err := publisher.PublishGitHubSourceSnapshot(
			context.Background(),
			connection,
			snapshot,
			&memoryTeamWorkspace{content: workspaceBytes},
		)
		if err != nil {
			t.Fatal(err)
		}
		workspace, err := NewGitHubSourceWorkspace(artifact)
		if err != nil {
			t.Fatal(err)
		}
		connection.ConnectionID = uuid.NewString()
		calls := factory.calls
		err = publisher.PublishTeamInputs(
			context.Background(),
			connection,
			deploymentID,
			compiled,
			workspace,
		)
		if !errors.Is(err, ErrInvalidRequest) ||
			factory.calls != calls ||
			factory.client.copyCalls != 0 {
			t.Fatalf(
				"connection substitution err=%v factory=%d want=%d copies=%d",
				err,
				factory.calls,
				calls,
				factory.client.copyCalls,
			)
		}
	})
}

func githubSourceSnapshotFixture(
	t *testing.T,
	workspace []byte,
) githubsource.SnapshotV1 {
	t.Helper()
	input, err := taskinput.NewGitHubInput(
		"owner-a",
		uuid.NewString(),
		"sha256:"+strings.Repeat("1", 64),
		taskinput.GitRepositoryV1{
			Provider:      taskinput.GitProviderGitHub,
			Host:          taskinput.GitHubHost,
			ConnectionID:  uuid.NewString(),
			RepositoryID:  "42",
			Owner:         "YingSuiAI",
			Name:          "dirextalk-agent",
			BaseCommitSHA: strings.Repeat("a", 40),
			BaseRef:       "refs/heads/codex/native-agent-v2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := input.Binding()
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := githubsource.SnapshotV1{
		SchemaVersion:      githubsource.SnapshotSchemaV1,
		InputID:            binding.InputID,
		InputDigest:        binding.InputDigest,
		InputBindingDigest: bindingDigest,
		SourceDigest:       binding.SourceDigest,
		Repository:         binding.Repository,
		WorkspaceDigest:    artifactTestDigest(workspace),
		SizeBytes:          int64(len(workspace)),
		FileCount:          1,
	}
	if snapshot.Validate() != nil {
		t.Fatalf("invalid fixture snapshot: %#v", snapshot)
	}
	return snapshot
}
