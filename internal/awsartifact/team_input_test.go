package awsartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

type memoryTeamWorkspace struct {
	content []byte
	opens   int
}

func (workspace *memoryTeamWorkspace) Open(context.Context) (io.ReadSeekCloser, error) {
	workspace.opens++
	return &memoryReadSeekCloser{
		Reader: bytes.NewReader(workspace.content),
	}, nil
}

type memoryReadSeekCloser struct {
	*bytes.Reader
}

func (*memoryReadSeekCloser) Close() error {
	return nil
}

func TestBundlePublisherStreamsDigestBoundTeamInputsIdempotently(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	compiled, workspaceBytes := teamArtifactFixture(t, deploymentID)
	defer compiled.Destroy()
	workspace := &memoryTeamWorkspace{content: workspaceBytes}

	if err := publisher.PublishTeamInputs(
		context.Background(),
		connection,
		deploymentID,
		compiled,
		workspace,
	); err != nil {
		t.Fatal(err)
	}
	spec, err := publisher.foundationSpec(connection)
	if err != nil {
		t.Fatal(err)
	}
	prefix := spec.ArtifactBucketName + "/deployments/" +
		deploymentID + "/artifacts/"
	for _, expected := range []struct {
		object workerrunner.MaterializeObjectV1
		bytes  []byte
	}{
		{object: compiled.ContextObject, bytes: compiled.ContextBytes},
		{object: compiled.WorkspaceObject, bytes: workspaceBytes},
	} {
		stored, ok := factory.client.objects[prefix+expected.object.ObjectName]
		if !ok ||
			!bytes.Equal(stored.payload, expected.bytes) ||
			stored.contentType != expected.object.ContentType ||
			stored.metadata["kind"] != "worker-input" ||
			stored.metadata["deployment-id"] != deploymentID ||
			stored.metadata["sha256"] !=
				strings.TrimPrefix(expected.object.SHA256, "sha256:") ||
			stored.kmsKey != "alias/"+spec.StackName ||
			!stored.bucketKey ||
			stored.versionID == "" {
			t.Fatalf(
				"unsafe Team input object %q: %#v",
				expected.object.ObjectName,
				stored,
			)
		}
	}
	puts := factory.client.putCalls
	if err := publisher.PublishTeamInputs(
		context.Background(),
		connection,
		deploymentID,
		compiled,
		workspace,
	); err != nil {
		t.Fatal(err)
	}
	if factory.client.putCalls != puts || workspace.opens != 2 {
		t.Fatalf(
			"idempotent replay puts=%d want=%d opens=%d",
			factory.client.putCalls,
			puts,
			workspace.opens,
		)
	}
}

func TestBundlePublisherRejectsMismatchedTeamWorkspaceBeforeWrite(t *testing.T) {
	publisher, factory, connection, deploymentID := publisherFixture(t)
	compiled, _ := teamArtifactFixture(t, deploymentID)
	defer compiled.Destroy()
	workspace := &memoryTeamWorkspace{content: []byte("substituted")}

	if err := publisher.PublishTeamInputs(
		context.Background(),
		connection,
		deploymentID,
		compiled,
		workspace,
	); err != ErrSourceIntegrity {
		t.Fatalf("workspace substitution error=%v", err)
	}
	if factory.client.putCalls != 1 {
		t.Fatalf(
			"context publication count=%d want=1",
			factory.client.putCalls,
		)
	}
}

func teamArtifactFixture(
	t *testing.T,
	deploymentID string,
) (teaminput.CompiledInput, []byte) {
	t.Helper()
	contextBytes := []byte(`{"goal":"review the approved change"}`)
	workspaceBytes := []byte("canonical-workspace-tar")
	contextDigest := artifactTestDigest(contextBytes)
	workspaceDigest := artifactTestDigest(workspaceBytes)
	manifestBytes := []byte(
		`{"schema_version":"dirextalk.agent.team-worker-input/v1"}`,
	)
	manifestDigest := artifactTestDigest(manifestBytes)
	contextObject := workerrunner.MaterializeObjectV1{
		ObjectName: "team-context-" +
			strings.TrimPrefix(contextDigest, "sha256:") + ".json",
		SHA256:      contextDigest,
		SizeBytes:   int64(len(contextBytes)),
		ContentType: "application/json",
	}
	workspaceObject := workerrunner.MaterializeObjectV1{
		ObjectName: "team-workspace-" +
			strings.TrimPrefix(workspaceDigest, "sha256:") + ".tar",
		SHA256:      workspaceDigest,
		SizeBytes:   int64(len(workspaceBytes)),
		ContentType: "application/x-tar",
	}
	bundle := workerrunner.ExecutionBundleV1{
		SchemaVersion: 1,
		RecipeSHA256: strings.TrimPrefix(
			manifestDigest,
			"sha256:",
		),
		Actions: []workerrunner.ActionV1{
			{
				ID:             "materialize-input",
				Kind:           workerrunner.InputMaterializeActionKind,
				TimeoutSeconds: 300,
				Input: &workerrunner.InputMaterializeInputV1{
					Context:   contextObject,
					Workspace: &workspaceObject,
				},
			},
			{
				ID:             "execute-role",
				Kind:           workerrunner.RuntimeExecuteActionKind,
				TimeoutSeconds: 300,
				Runtime: &workerrunner.RuntimeExecuteInputV1{
					Task: workerruntime.TaskV1{
						ContextDigest:   contextDigest,
						WorkspaceMode:   workerruntime.WorkspaceReadOnly,
						WorkspaceDigest: workspaceDigest,
					},
				},
			},
		},
	}
	executionBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return teaminput.CompiledInput{
		Manifest: teaminput.ManifestV1{
			DeploymentID: deploymentID,
		},
		ManifestBytes:   manifestBytes,
		ManifestDigest:  manifestDigest,
		ContextBytes:    contextBytes,
		ExecutionBytes:  executionBytes,
		ContextObject:   contextObject,
		WorkspaceObject: workspaceObject,
	}, workspaceBytes
}

func artifactTestDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
