package workerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestCollectorVerifiesManifestAndFetchesOnlyFinalArtifacts(t *testing.T) {
	t.Parallel()
	deployment, objects := resultFixture(t)
	reader := &memoryReader{objects: objects}
	collector, err := NewCollector(reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := collector.Collect(context.Background(), deployment)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Destroy()
	if len(result.Finals) != 1 ||
		string(result.Finals[0].Content) !=
			`{"status":"completed","summary":"done"}` ||
		len(result.Manifest.RuntimeResults) != 1 ||
		reader.calls != 2 {
		t.Fatalf("collected result = %+v calls=%d", result, reader.calls)
	}
}

func TestCollectorRejectsTamperedFinalArtifact(t *testing.T) {
	t.Parallel()
	deployment, objects := resultFixture(t)
	for reference := range objects {
		if reference != deployment.ResultRef {
			objects[reference] = []byte(`{"status":"tampered"}`)
		}
	}
	collector, err := NewCollector(&memoryReader{objects: objects})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(
		context.Background(), deployment,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered artifact error = %v", err)
	}
}

func resultFixture(
	t *testing.T,
) (worker.Deployment, map[string][]byte) {
	t.Helper()
	deployment := worker.Deployment{
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		WorkerID:     "22222222-2222-4222-8222-222222222222",
		TaskID:       "33333333-3333-4333-8333-333333333333",
		StepID:       "44444444-4444-4444-8444-444444444444",
		State:        worker.StateFinished,
		Outcome:      worker.OutcomeSucceeded,
		RecipeBundle: worker.BundleRef{
			S3Ref:  "s3://worker-bucket/deployments/test/recipe.cbor",
			SHA256: sha256.Sum256([]byte("recipe")),
		},
		ExecutionBundle: worker.BundleRef{
			S3Ref:  "s3://worker-bucket/deployments/test/execution.json",
			SHA256: sha256.Sum256([]byte("execution")),
		},
		Access: worker.AccessScope{
			ArtifactPrefix:   "s3://worker-bucket/deployments/test/artifacts/",
			CheckpointPrefix: "s3://worker-bucket/deployments/test/checkpoints/",
			EvidencePrefix:   "s3://worker-bucket/deployments/test/evidence/",
			LogPrefix:        "cloudwatch://worker-log/deployments/test",
		},
		Lease: worker.Lease{
			Attempt: 1, Epoch: 9,
			LastHeartbeatAt: time.Now().UTC(),
		},
	}
	final := []byte(`{"status":"completed","summary":"done"}`)
	finalDigest := sha256.Sum256(final)
	nameDigest := sha256.Sum256([]byte("final.json"))
	finalRef := fmt.Sprintf(
		"s3://worker-bucket/deployments/test/artifacts/runtime-a1-e9-implement-%s-%s.json",
		hex.EncodeToString(nameDigest[:8]),
		hex.EncodeToString(finalDigest[:]),
	)
	manifest := workerrunner.ResultManifestV2{
		SchemaVersion: workerrunner.ResultManifestSchemaV2,
		DeploymentID:  deployment.DeploymentID,
		WorkerID:      deployment.WorkerID,
		TaskID:        deployment.TaskID,
		StepID:        deployment.StepID,
		Attempt:       1, LeaseEpoch: 9,
		RecipeSHA256: hex.EncodeToString(
			deployment.RecipeBundle.SHA256[:],
		),
		ExecutionSHA256: hex.EncodeToString(
			deployment.ExecutionBundle.SHA256[:],
		),
		Status: "succeeded", CompletedActions: []string{"implement"},
		RuntimeResults: []workerrunner.RuntimeActionResultV1{{
			ActionID: "implement", TaskID: deployment.TaskID,
			Adapter: workerruntime.AdapterCodexV1,
			Usage: workerruntime.Usage{
				InputTokens: 10, OutputTokens: 5,
			},
			Artifacts: []workerrunner.RuntimeArtifactClaimV1{{
				Attempt: 1, LeaseEpoch: 9, Name: "final.json",
				Ref:       finalRef,
				SHA256:    "sha256:" + hex.EncodeToString(finalDigest[:]),
				SizeBytes: int64(len(final)), MediaType: "application/json",
			}},
		}},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifestRaw)
	deployment.ResultRef = "s3://worker-bucket/deployments/test/artifacts/result.json"
	deployment.Evidence = []worker.EvidenceRef{{
		Kind: "artifact", Ref: deployment.ResultRef,
		ObjectSHA256: "sha256:" + hex.EncodeToString(manifestDigest[:]),
		SizeBytes:    int64(len(manifestRaw)), MediaType: "application/json",
		Trust: worker.TrustWorkerClaim, Attempt: 1, LeaseEpoch: 9,
		RecordedAt: time.Now().UTC(),
	}}
	return deployment, map[string][]byte{
		deployment.ResultRef: manifestRaw,
		finalRef:             bytes.Clone(final),
	}
}

type memoryReader struct {
	objects map[string][]byte
	calls   int
}

func (reader *memoryReader) Get(
	_ context.Context,
	reference string,
	maximum int64,
) ([]byte, error) {
	reader.calls++
	value, ok := reader.objects[reference]
	if !ok {
		return nil, ErrUnavailable
	}
	if maximum < 1 || int64(len(value)) > maximum {
		return nil, ErrInvalid
	}
	return bytes.Clone(value), nil
}
