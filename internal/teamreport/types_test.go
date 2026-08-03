package teamreport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestBuildProjectsVerifiedResultsWithoutObjectCoordinates(t *testing.T) {
	t.Parallel()
	execution, operation := validReportInputs(t)
	report, err := Build(execution, []teamdispatch.Fact{operation})
	if err != nil {
		t.Fatal(err)
	}
	if report.Roles[0].Finals[0].Summary !=
		"Implementation completed and verified." ||
		report.TotalUsage.InputTokens != 100 ||
		report.TotalUsage.OutputTokens != 20 {
		t.Fatalf("report = %#v", report)
	}
	encoded := mustCanonicalReport(t, report)
	for _, forbidden := range []string{
		"s3://",
		"artifact_ref",
		"model_credential",
		"secret_ref:",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("report contains forbidden %q: %s", forbidden, encoded)
		}
	}
}

func TestBuildRejectsIncompleteOrMismatchedRole(t *testing.T) {
	t.Parallel()
	execution, operation := validReportInputs(t)
	operation.Phase = teamdispatch.PhaseDestroying
	if _, err := Build(
		execution,
		[]teamdispatch.Fact{operation},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete Build() error = %v", err)
	}

	_, operation = validReportInputs(t)
	operation.ResultEvidence.Finals[0].Adapter =
		workerruntime.AdapterHermesV1
	if _, err := Build(
		execution,
		[]teamdispatch.Fact{operation},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("adapter mismatch Build() error = %v", err)
	}
}

func validReportInputs(
	t *testing.T,
) (teamexecution.ExecutionV1, teamdispatch.Fact) {
	t.Helper()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	execution := teamexecution.ExecutionV1{
		SchemaVersion:       teamexecution.SchemaV1,
		ExecutionID:         "11111111-1111-4111-8111-111111111111",
		OwnerID:             "owner-report",
		TaskID:              "22222222-2222-4222-8222-222222222222",
		PlanID:              "33333333-3333-4333-8333-333333333333",
		PlanRevision:        1,
		PlanDigest:          "sha256:" + strings.Repeat("1", 64),
		ApprovalID:          "44444444-4444-4444-8444-444444444444",
		ApprovalSignerKeyID: "device-key-report",
		GoalDigest:          "sha256:" + strings.Repeat("2", 64),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       "55555555-5555-4555-8555-555555555555",
			ConnectionRevision: 1,
			AccountID:          "123456789012",
		},
		Region:                "us-east-1",
		CatalogRevision:       "sha256:" + strings.Repeat("3", 64),
		PolicyRevision:        "sha256:" + strings.Repeat("4", 64),
		PricingSnapshotID:     "66666666-6666-4666-8666-666666666666",
		PricingSnapshotDigest: "sha256:" + strings.Repeat("5", 64),
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Currency:              "USD",
		MinimumCostMicros:     1,
		ExpectedCostMicros:    2,
		MaximumCostMicros:     3,
		HardBudgetMicros:      4,
		Schedule: teamexecution.ScheduleEstimateV1{
			MinimumWallSeconds:  1,
			ExpectedWallSeconds: 2,
			MaximumWallSeconds:  3,
		},
		AuthorizedAt: now,
		Roles: []teamexecution.RoleV1{{
			RoleID:    "implement-api",
			Title:     "Implement API",
			Objective: "Implement the bounded API.",
			WorkClass: teamplan.WorkSoftwareImplementation,
			RequiredCapabilities: []teamplan.Capability{
				teamplan.CapabilityRepositoryRead,
				teamplan.CapabilityRepositoryWrite,
			},
			Workspace:          teamplan.WorkspaceIsolated,
			StepDeclarationID:  "77777777-7777-4777-8777-777777777777",
			DeploymentID:       "99999999-9999-4999-8999-999999999999",
			ExpectedWorkerID:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			RuntimeReleaseID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			RuntimeFamily:      teamplan.RuntimeCodex,
			RuntimeVersion:     "0.1.0",
			RuntimeImageDigest: "sha256:" + strings.Repeat("6", 64),
			RuntimeAdapter:     teamplan.AdapterCodexV1,
			ModelProfileID:     "openai-balanced",
			ModelProvider:      "openai",
			Model:              "gpt-test",
			ModelInterface:     teamplan.ModelOpenAIResponses,
			ModelCredentialSlot: "model-" +
				strings.Repeat("a", 16),
			ComputeOfferID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			InstanceType:   "t3.medium",
			Resources: teamplan.ResourceEnvelope{
				VCPU: 2, MemoryMiB: 4096, DiskGiB: 40,
				Arch: recipe.ArchitectureAMD64,
			},
			Duration: teamexecution.DurationEstimateV1{
				MinimumSeconds:  1,
				ExpectedSeconds: 2,
				MaximumSeconds:  3,
			},
			Tokens: teamplan.TokenEstimate{
				InputMinimum:   1,
				InputExpected:  2,
				InputMaximum:   3,
				OutputMinimum:  1,
				OutputExpected: 2,
				OutputMaximum:  3,
			},
			ColdStartSeconds: 1,
		}},
	}
	stepID, err := task.MaterializeStepID(
		execution.TaskID,
		execution.Roles[0].StepDeclarationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	execution.Roles[0].TaskStepID = stepID
	intent := teamdispatch.IntentV1{
		SchemaVersion:             teamdispatch.SchemaV1,
		OperationID:               "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		AgentInstanceID:           "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		OwnerID:                   execution.OwnerID,
		ExecutionID:               execution.ExecutionID,
		ExecutionDigest:           "sha256:" + strings.Repeat("7", 64),
		PlanID:                    execution.PlanID,
		PlanRevision:              execution.PlanRevision,
		PlanDigest:                execution.PlanDigest,
		ApprovalID:                execution.ApprovalID,
		LaunchAuthorizationID:     "ffffffff-ffff-4fff-8fff-ffffffffffff",
		LaunchAuthorizationDigest: "sha256:" + strings.Repeat("8", 64),
		RoleID:                    execution.Roles[0].RoleID,
		RoleDigest:                "sha256:" + strings.Repeat("9", 64),
		TaskID:                    execution.TaskID,
		TaskStepID:                execution.Roles[0].TaskStepID,
		DeploymentID:              execution.Roles[0].DeploymentID,
		ExpectedWorkerID:          execution.Roles[0].ExpectedWorkerID,
		ModelCredentialRef:        "secret_ref:model/codex",
		MaximumApprovedCostMicros: 4,
		LaunchNotAfter:            now.Add(time.Hour),
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	evidence := teamresult.EvidenceV1{
		SchemaVersion:    teamresult.SchemaV1,
		OperationID:      intent.OperationID,
		ExecutionID:      intent.ExecutionID,
		RoleID:           intent.RoleID,
		DeploymentID:     intent.DeploymentID,
		ExpectedWorkerID: intent.ExpectedWorkerID,
		TaskID:           intent.TaskID,
		TaskStepID:       intent.TaskStepID,
		WorkerID:         intent.ExpectedWorkerID,
		Attempt:          1,
		LeaseEpoch:       1,
		ResultRef: "s3://team-report/deployments/" +
			intent.DeploymentID + "/artifacts/result.json",
		ResultSHA256:    "sha256:" + strings.Repeat("a", 64),
		ResultSizeBytes: 512,
		ResultMediaType: "application/json",
		Finals: []teamresult.FinalV1{{
			ActionID: "execute",
			Adapter:  workerruntime.AdapterCodexV1,
			Usage: workerruntime.Usage{
				InputTokens: 100, OutputTokens: 20,
			},
			Status:       "completed",
			Summary:      "Implementation completed and verified.",
			Deliverables: []string{"Implementation"},
			Tests:        []string{"Focused tests passed."},
			Risks:        []string{},
			ArtifactRef: "s3://team-report/deployments/" +
				intent.DeploymentID + "/artifacts/final.json",
			ArtifactSHA256:    "sha256:" + strings.Repeat("b", 64),
			ArtifactSizeBytes: 256,
			ArtifactMediaType: "application/json",
		}},
	}
	evidenceDigest, err := evidence.Digest()
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := now.Add(time.Minute)
	operation := teamdispatch.Fact{
		Intent:               intent,
		IntentDigest:         intentDigest,
		Phase:                teamdispatch.PhaseCompleted,
		Outcome:              task.OutcomeSucceeded,
		ResultEvidence:       &evidence,
		ResultEvidenceDigest: evidenceDigest,
		ResultVerifiedAt:     &verifiedAt,
		RecordRevision:       4,
		CreatedAt:            now,
		UpdatedAt:            verifiedAt,
	}
	if err := execution.Validate(); err != nil {
		t.Fatalf("invalid execution fixture: %v", err)
	}
	if err := operation.Validate(); err != nil {
		t.Fatalf("invalid operation fixture: %v", err)
	}
	return execution, operation
}

func mustCanonicalReport(t *testing.T, report ReportV1) []byte {
	t.Helper()
	digest, err := report.Digest()
	if err != nil || digest == "" {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
