package workerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestCollectorVerifiesManifestAndFetchesAllBoundedArtifacts(t *testing.T) {
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
			`{"schema_version":"dirextalk.agent.codex-final/v1","status":"completed","summary":"done","deliverables":[],"tests":[],"risks":[]}` ||
		len(result.Artifacts) != 2 ||
		result.Artifacts[1].Artifact.Name != "changes.patch" ||
		len(result.Manifest.RuntimeResults) != 1 ||
		reader.calls != 3 {
		t.Fatalf("collected result = %+v calls=%d", result, reader.calls)
	}
}

func TestValidateTeamRoleBuildsBoundedDurableEvidence(t *testing.T) {
	t.Parallel()
	deployment, objects := resultFixture(t)
	collector, err := NewCollector(&memoryReader{objects: objects})
	if err != nil {
		t.Fatal(err)
	}
	collected, err := collector.Collect(context.Background(), deployment)
	if err != nil {
		t.Fatal(err)
	}
	defer collected.Destroy()
	intent := teamResultIntent(deployment)
	evidence, err := ValidateTeamRole(intent, deployment, collected)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Validate() != nil ||
		evidence.OperationID != intent.OperationID ||
		evidence.WorkerID != intent.ExpectedWorkerID ||
		evidence.ResultRef != deployment.ResultRef ||
		len(evidence.Finals) != 1 ||
		evidence.Finals[0].Summary != "done" ||
		evidence.Finals[0].ArtifactSHA256 == "" {
		t.Fatalf("validated Team result = %#v", evidence)
	}
	artifacts, err := VerifiedTeamArtifacts(
		intent,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		deployment,
		evidence,
		collected,
		time.Date(2026, 8, 3, 1, 2, 3, 0, time.UTC),
		90*24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 ||
		artifacts[0].Name != "final.json" ||
		artifacts[1].Name != "changes.patch" ||
		artifacts[1].Kind != "patch" {
		t.Fatalf("registered artifacts = %#v", artifacts)
	}
}

func TestValidateTeamRoleAcceptsCanonicalPiResult(t *testing.T) {
	t.Parallel()
	final := []byte(
		`{"schema_version":"dirextalk.agent.pi-final/v1","status":"completed","summary":"Pi completed the role.","deliverables":["implementation"],"tests":["focused tests passed"],"risks":[]}`,
	)
	deployment, objects := resultFixtureForAdapter(
		t,
		workerruntime.AdapterPiV1,
		final,
	)
	collector, err := NewCollector(&memoryReader{objects: objects})
	if err != nil {
		t.Fatal(err)
	}
	collected, err := collector.Collect(context.Background(), deployment)
	if err != nil {
		t.Fatal(err)
	}
	defer collected.Destroy()
	evidence, err := ValidateTeamRole(
		teamResultIntent(deployment),
		deployment,
		collected,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Finals) != 1 ||
		evidence.Finals[0].Adapter != workerruntime.AdapterPiV1 ||
		evidence.Finals[0].Summary != "Pi completed the role." {
		t.Fatalf("validated Pi result = %#v", evidence)
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
	return resultFixtureForAdapter(
		t,
		workerruntime.AdapterCodexV1,
		[]byte(
			`{"schema_version":"dirextalk.agent.codex-final/v1","status":"completed","summary":"done","deliverables":[],"tests":[],"risks":[]}`,
		),
	)
}

func resultFixtureForAdapter(
	t *testing.T,
	adapter workerruntime.Adapter,
	final []byte,
) (worker.Deployment, map[string][]byte) {
	t.Helper()
	deployment := worker.Deployment{
		DeploymentID: "11111111-1111-4111-8111-111111111111",
		OwnerID:      "owner-team-result",
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
	finalDigest := sha256.Sum256(final)
	patch := []byte("diff --git a/main.go b/main.go\n")
	patchDigest := sha256.Sum256(patch)
	nameDigest := sha256.Sum256([]byte("final.json"))
	finalRef := fmt.Sprintf(
		"s3://worker-bucket/deployments/test/artifacts/runtime-a1-e9-implement-%s-%s.json",
		hex.EncodeToString(nameDigest[:8]),
		hex.EncodeToString(finalDigest[:]),
	)
	patchNameDigest := sha256.Sum256([]byte("changes.patch"))
	patchRef := fmt.Sprintf(
		"s3://worker-bucket/deployments/test/artifacts/runtime-a1-e9-implement-%s-%s.txt",
		hex.EncodeToString(patchNameDigest[:8]),
		hex.EncodeToString(patchDigest[:]),
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
			Adapter: adapter,
			Usage: workerruntime.Usage{
				InputTokens: 10, OutputTokens: 5,
			},
			Artifacts: []workerrunner.RuntimeArtifactClaimV1{
				{
					Attempt: 1, LeaseEpoch: 9, Name: "final.json",
					Ref:       finalRef,
					SHA256:    "sha256:" + hex.EncodeToString(finalDigest[:]),
					SizeBytes: int64(len(final)), MediaType: "application/json",
				},
				{
					Attempt: 1, LeaseEpoch: 9, Name: "changes.patch",
					Ref:       patchRef,
					SHA256:    "sha256:" + hex.EncodeToString(patchDigest[:]),
					SizeBytes: int64(len(patch)), MediaType: "text/plain; charset=utf-8",
				},
			},
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
		patchRef:             bytes.Clone(patch),
	}
}

func teamResultIntent(
	deployment worker.Deployment,
) teamdispatch.IntentV1 {
	return teamdispatch.IntentV1{
		SchemaVersion:         teamdispatch.SchemaV1,
		OperationID:           "55555555-5555-4555-8555-555555555555",
		AgentInstanceID:       "66666666-6666-4666-8666-666666666666",
		OwnerID:               deployment.OwnerID,
		ExecutionID:           "77777777-7777-4777-8777-777777777777",
		ExecutionDigest:       "sha256:" + strings.Repeat("1", 64),
		PlanID:                "88888888-8888-4888-8888-888888888888",
		PlanRevision:          1,
		PlanDigest:            "sha256:" + strings.Repeat("2", 64),
		ApprovalID:            "99999999-9999-4999-8999-999999999999",
		LaunchAuthorizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		LaunchAuthorizationDigest: "sha256:" +
			strings.Repeat("3", 64),
		RoleID:                    "implement",
		RoleDigest:                "sha256:" + strings.Repeat("4", 64),
		TaskID:                    deployment.TaskID,
		TaskStepID:                deployment.StepID,
		DeploymentID:              deployment.DeploymentID,
		ExpectedWorkerID:          deployment.WorkerID,
		ModelCredentialRef:        "secret_ref:model/codex",
		MaximumApprovedCostMicros: 1,
		LaunchNotAfter: time.Date(
			2026, 8, 1, 0, 0, 0, 0, time.UTC,
		),
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
