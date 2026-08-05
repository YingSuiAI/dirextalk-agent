package teamdispatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestReadyRoleIDsRespectsDependenciesAndSignedConcurrency(t *testing.T) {
	authorized, _ := dispatchFixture(t)
	progress := dispatchProgress(false)

	ready, err := ReadyRoleIDs(authorized, progress, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 1 || ready[0] != "implement" {
		t.Fatalf("unexpected initial ready roles: %#v", ready)
	}

	intent, err := NewIntent(
		authorized,
		"implement",
		fixtureLaunchTime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	reserved := dispatchFact(
		t,
		intent,
		PhaseDestroying,
		task.OutcomePending,
	)
	ready, err = ReadyRoleIDs(authorized, progress, []Fact{reserved})
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 0 {
		t.Fatalf("concurrency reservation was ignored: %#v", ready)
	}

	completed := dispatchFact(
		t,
		intent,
		PhaseCompleted,
		task.OutcomeSucceeded,
	)
	ready, err = ReadyRoleIDs(
		authorized,
		dispatchProgress(true),
		[]Fact{completed},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 1 || ready[0] != "review" {
		t.Fatalf("dependent role was not released: %#v", ready)
	}
}

func TestIntentBindsExactSignedFactsAndLaunchWindow(t *testing.T) {
	authorized, now := dispatchFixture(t)
	intent, err := NewIntent(
		authorized,
		"implement",
		now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if intent.ModelCredentialRef != "secret_ref:model/primary" ||
		intent.LaunchAuthorizationID != authorized.Approval.Approval.
			Authorization.AuthorizationID ||
		intent.DeploymentID != authorized.Execution.Execution.
			Roles[0].DeploymentID {
		t.Fatalf("intent lost signed bindings: %#v", intent)
	}

	tampered := intent
	tampered.ModelCredentialRef = "secret_ref:model/other"
	if !errors.Is(
		tampered.ValidateAgainst(authorized),
		ErrFactMismatch,
	) {
		t.Fatal("credential reference substitution was accepted")
	}
	if _, err := NewIntent(
		authorized,
		"implement",
		authorized.Approval.Approval.Authorization.LaunchNotAfter,
	); !errors.Is(err, ErrNotReady) {
		t.Fatalf("expired launch authorization was accepted: %v", err)
	}
}

func TestResultCollectionAuthorizationAcceptsVerifyingOnlyBeforeTerminal(t *testing.T) {
	authorized, now := dispatchFixture(t)
	intent, err := NewIntent(
		authorized,
		"implement",
		now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	authorized.Execution.Status = teamexecution.StatusVerifying
	if !errors.Is(authorized.Validate(), ErrNotReady) {
		t.Fatal("ordinary authorization accepted verifying execution")
	}
	if err := authorized.ValidateForResultCollection(); err != nil {
		t.Fatalf("result collection rejected verifying execution: %v", err)
	}
	if err := intent.ValidateAgainstForResultCollection(authorized); err != nil {
		t.Fatalf("result collection rejected bound intent: %v", err)
	}

	authorized.Execution.Status = teamexecution.StatusCompleted
	if !errors.Is(
		authorized.ValidateForResultCollection(),
		ErrNotReady,
	) {
		t.Fatal("result collection accepted terminal execution")
	}
	if !errors.Is(
		intent.ValidateAgainstForResultCollection(authorized),
		ErrFactMismatch,
	) {
		t.Fatal("result collection accepted terminal intent binding")
	}
}

func TestServiceSchedulesConvergentlyAndReleasesDependency(t *testing.T) {
	authorized, now := dispatchFixture(t)
	progress := &dispatchProgressReader{items: dispatchProgress(false)}
	repository := &dispatchRepository{now: now.Add(2 * time.Minute)}
	service, err := NewService(
		dispatchAuthorizationReader{authorized: authorized},
		progress,
		repository,
		func() time.Time { return now.Add(2 * time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "internal.team-dispatcher",
		CredentialID: uuid.NewString(),
	}
	first, err := service.Schedule(
		context.Background(),
		scope,
		authorized.Execution.Execution.OwnerID,
		authorized.Execution.Execution.ExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Intent.RoleID != "implement" {
		t.Fatalf("unexpected first schedule: %#v", first)
	}
	replayed, err := service.Schedule(
		context.Background(),
		scope,
		authorized.Execution.Execution.OwnerID,
		authorized.Execution.Execution.ExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 0 || repository.claims != 1 {
		t.Fatalf(
			"schedule replay created a duplicate: facts=%d claims=%d",
			len(replayed),
			repository.claims,
		)
	}

	repository.complete("implement")
	progress.items = dispatchProgress(true)
	second, err := service.Schedule(
		context.Background(),
		scope,
		authorized.Execution.Execution.OwnerID,
		authorized.Execution.Execution.ExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Intent.RoleID != "review" ||
		repository.claims != 2 {
		t.Fatalf(
			"dependent role was not claimed exactly once: %#v",
			second,
		)
	}
}

type dispatchAuthorizationReader struct {
	authorized AuthorizedExecution
}

func (reader dispatchAuthorizationReader) LoadAuthorizedExecution(
	_ context.Context,
	ownerID,
	executionID string,
) (AuthorizedExecution, error) {
	if reader.authorized.Execution.Execution.OwnerID != ownerID ||
		reader.authorized.Execution.Execution.ExecutionID != executionID {
		return AuthorizedExecution{}, ErrNotFound
	}
	return reader.authorized, nil
}

type dispatchProgressReader struct {
	items []RoleProgress
}

func (reader *dispatchProgressReader) LoadRoleProgress(
	_ context.Context,
	_,
	_ string,
) ([]RoleProgress, error) {
	return append([]RoleProgress(nil), reader.items...), nil
}

type dispatchRepository struct {
	mu         sync.Mutex
	now        time.Time
	operations []Fact
	claims     int
}

func (repository *dispatchRepository) ListExecutionOperations(
	_ context.Context,
	_,
	_ string,
) ([]Fact, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]Fact(nil), repository.operations...), nil
}

func (repository *dispatchRepository) ClaimRole(
	_ context.Context,
	_ task.MutationScope,
	command ClaimCommand,
) (Fact, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for _, operation := range repository.operations {
		if operation.Intent.OperationID == command.Intent.OperationID {
			return operation, true, nil
		}
	}
	var reserved uint32
	for _, operation := range repository.operations {
		if operation.Phase != PhaseCompleted {
			reserved++
		}
	}
	if reserved >= command.MaxConcurrentRoles {
		return Fact{}, false, ErrConcurrencyLimit
	}
	repository.claims++
	fact := dispatchFact(
		nil,
		command.Intent,
		PhaseIntent,
		task.OutcomePending,
	)
	fact.CreatedAt = repository.now
	fact.UpdatedAt = repository.now
	repository.operations = append(repository.operations, fact)
	return fact, false, nil
}

func (repository *dispatchRepository) GetRoleOperation(
	_ context.Context,
	ownerID,
	operationID string,
) (Fact, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for _, operation := range repository.operations {
		if operation.Intent.OwnerID == ownerID &&
			operation.Intent.OperationID == operationID {
			return operation, nil
		}
	}
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) AdvanceRole(
	context.Context,
	AdvanceCommand,
) (Fact, error) {
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) PublishRoleArtifacts(
	context.Context,
	PublishArtifactsCommand,
) (Fact, error) {
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) BeginProvisioning(
	context.Context,
	BeginProvisioningCommand,
) (Fact, error) {
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) RefreshProvisioningQuote(
	context.Context,
	RefreshProvisioningQuoteCommand,
) (Fact, error) {
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) RecordRoleResult(
	context.Context,
	RecordResultCommand,
) (Fact, error) {
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) ScheduleRoleRetry(
	context.Context,
	RetryCommand,
) (Fact, error) {
	return Fact{}, ErrNotFound
}

func (repository *dispatchRepository) ListRecoverableRoleDispatches(
	context.Context,
	*RecoverableCursor,
	uint32,
	time.Time,
) ([]Fact, error) {
	return nil, nil
}

func (repository *dispatchRepository) complete(roleID string) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for index := range repository.operations {
		if repository.operations[index].Intent.RoleID == roleID {
			repository.operations[index].Phase = PhaseCompleted
			repository.operations[index].Outcome = task.OutcomeSucceeded
			repository.operations[index].UpdatedAt = repository.now.Add(
				time.Second,
			)
			repository.operations[index].RecordRevision++
			attachSucceededResultEvidence(
				&repository.operations[index],
			)
		}
	}
}

func dispatchFact(
	t *testing.T,
	intent IntentV1,
	phase Phase,
	outcome task.OutcomeStatus,
) Fact {
	if t != nil {
		t.Helper()
	}
	digest, err := intent.Digest()
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	now := fixtureLaunchTime()
	fact := Fact{
		Intent:         intent,
		IntentDigest:   digest,
		Phase:          phase,
		Outcome:        outcome,
		RecordRevision: 1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if phase == PhaseCompleted &&
		outcome == task.OutcomeSucceeded {
		attachSucceededResultEvidence(&fact)
	}
	if fact.Validate() != nil {
		if t != nil {
			t.Fatalf("invalid dispatch fact fixture: %#v", fact)
		}
		panic("invalid dispatch fact fixture")
	}
	return fact
}

func attachSucceededResultEvidence(fact *Fact) {
	intent := fact.Intent
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
		ResultRef: "s3://team-result/" +
			intent.DeploymentID + "/result.json",
		ResultSHA256:    "sha256:" + strings.Repeat("a", 64),
		ResultSizeBytes: 128,
		ResultMediaType: "application/json",
		Finals: []teamresult.FinalV1{{
			ActionID:     "execute",
			Adapter:      workerruntime.AdapterCodexV1,
			Usage:        workerruntime.Usage{},
			Status:       "completed",
			Summary:      "Role completed.",
			Deliverables: []string{},
			Tests:        []string{},
			Risks:        []string{},
			ArtifactRef: "s3://team-result/" +
				intent.DeploymentID + "/final.json",
			ArtifactSHA256: "sha256:" +
				strings.Repeat("b", 64),
			ArtifactSizeBytes: 64,
			ArtifactMediaType: "application/json",
		}},
	}
	digest, err := evidence.Digest()
	if err != nil {
		panic(err)
	}
	fact.ResultEvidence = &evidence
	fact.ResultEvidenceDigest = digest
	verifiedAt := fact.UpdatedAt
	fact.ResultVerifiedAt = &verifiedAt
}

func dispatchProgress(implementationComplete bool) []RoleProgress {
	implementation := RoleProgress{
		RoleID:          "implement",
		ExecutionStatus: task.ExecutionQueued,
		OutcomeStatus:   task.OutcomePending,
	}
	if implementationComplete {
		implementation.ExecutionStatus = task.ExecutionFinished
		implementation.OutcomeStatus = task.OutcomeSucceeded
	}
	return []RoleProgress{
		implementation,
		{
			RoleID:          "review",
			ExecutionStatus: task.ExecutionQueued,
			OutcomeStatus:   task.OutcomePending,
		},
	}
}

func fixtureLaunchTime() time.Time {
	return time.Date(2026, 7, 30, 8, 2, 0, 0, time.UTC)
}

func dispatchFixture(
	t *testing.T,
) (AuthorizedExecution, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	planID := uuid.NewString()
	taskID := uuid.NewString()
	approvalID := uuid.NewString()
	assignments := []teamplan.WorkerAssignment{
		dispatchAssignment(planID, "implement", nil),
		dispatchAssignment(planID, "review", []string{"implement"}),
	}
	assignments[1].Title = "Review"
	assignments[1].Objective = "Review and test the implementation."
	assignments[1].WorkClass = teamplan.WorkSoftwareReview
	assignments[1].RequiredCapabilities = []teamplan.Capability{
		teamplan.CapabilityCodeReview,
	}
	plan := teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        planID,
		Revision:      1,
		OwnerID:       "owner-team-dispatch",
		GoalDigest:    "sha256:" + strings.Repeat("1", 64),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       uuid.NewString(),
			ConnectionRevision: 1,
			AccountID:          "123456789012",
		},
		Region:                "us-east-1",
		CatalogRevision:       "sha256:" + strings.Repeat("2", 64),
		PolicyRevision:        "sha256:" + strings.Repeat("3", 64),
		PricingSnapshotID:     uuid.NewString(),
		PricingSnapshotDigest: "sha256:" + strings.Repeat("4", 64),
		QuotedAt:              now,
		ValidUntil:            now.Add(10 * time.Minute),
		ProposalConfidence:    90,
		ProposalRationale:     "Implementation and independent review.",
		WorkerCount:           2,
		MaxConcurrentWorkers:  1,
		Assignments:           assignments,
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  2 * time.Minute,
			ExpectedWallTime: 4 * time.Minute,
			MaximumWallTime:  6 * time.Minute,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    20_000,
			ExpectedMicros:   40_000,
			MaximumMicros:    60_000,
			HardBudgetMicros: 72_000,
			Roles: []teamplan.RoleCostEstimate{
				dispatchRoleCost("implement"),
				dispatchRoleCost("review"),
			},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"unapproved_retries"},
		},
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("invalid Plan fixture: %v", err)
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := now.Add(time.Minute)
	launch, err := teamlaunch.NewAuthorizationV1(
		teamlaunch.BuildRequest{
			Plan:            plan,
			AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			ApprovalID:      approvalID,
			Network: teamlaunch.NetworkV1{
				ConnectivityMode: teamlaunch.
					ConnectivityDirectPublicTLSV1,
				VPCID:            "vpc-0123456789abcdef0",
				SubnetID:         "subnet-0123456789abcdef0",
				AvailabilityZone: "us-east-1a",
				SecurityGroupMode: teamlaunch.
					SecurityGroupDedicatedNoIngress,
				PublicIPv4:           true,
				PublicInbound:        false,
				ControlPlaneEndpoint: "grpcs://worker.demo.test:443",
				Egress: []teamlaunch.EgressRuleV1{
					{
						Protocol: "tcp",
						FromPort: 443,
						ToPort:   443,
						CIDRv4:   "0.0.0.0/0",
					},
					{
						Protocol: "udp",
						FromPort: 53,
						ToPort:   53,
						CIDRv4:   "169.254.169.253/32",
					},
				},
			},
			Retention: teamlaunch.RetentionV1{
				Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
				AutoDestroy:            true,
				MaximumLifetimeSeconds: 3600,
				DestroyGraceSeconds:    300,
			},
			LaunchNotBefore: now.Add(30 * time.Second),
			LaunchNotAfter:  now.Add(9 * time.Minute),
			RoleSelections: []teamlaunch.RoleSelection{
				dispatchRoleSelection(t, now, "implement"),
				dispatchRoleSelection(t, now, "review"),
			},
		},
	)
	if err != nil {
		t.Fatalf("build launch authorization: %v", err)
	}
	launchDigest, err := launch.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approved := teamorchestration.ApprovedPlanFact{
		Plan: teamorchestration.PlanFact{
			TaskID:         taskID,
			Plan:           plan,
			PlanDigest:     planDigest,
			Status:         teamorchestration.PlanApproved,
			RecordRevision: 2,
			CreatedAt:      now,
			UpdatedAt:      approvedAt,
		},
		Approval: teamorchestration.ApprovalFact{
			Signature: teamapproval.SignatureV1{
				SchemaVersion:             teamapproval.SignatureSchemaV2,
				ApprovalID:                approvalID,
				ChallengeID:               uuid.NewString(),
				PlanID:                    planID,
				PlanRevision:              1,
				PlanDigest:                planDigest,
				LaunchAuthorizationID:     launch.AuthorizationID,
				LaunchAuthorizationDigest: launchDigest,
				SignerKeyID:               "team-device-1",
				SignatureBase64URL:        strings.Repeat("A", 86),
			},
			Authorization: &launch,
			ApprovedAt:    approvedAt,
			CreatedAt:     approvedAt,
		},
	}
	execution, err := teamexecution.Materialize(approved)
	if err != nil {
		t.Fatalf("materialize execution: %v", err)
	}
	executionDigest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approved.Plan.Status = teamorchestration.PlanExecuting
	return AuthorizedExecution{
		Approval: approved,
		Execution: teamexecution.Fact{
			Execution:       execution,
			ExecutionDigest: executionDigest,
			Status:          teamexecution.StatusDispatching,
			RecordRevision:  2,
			CreatedAt:       approvedAt,
			UpdatedAt:       approvedAt,
		},
	}, now
}

func dispatchAssignment(
	planID,
	roleID string,
	dependencies []string,
) teamplan.WorkerAssignment {
	return teamplan.WorkerAssignment{
		RoleID:    roleID,
		Title:     "Implementation",
		Objective: "Implement the approved change.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		DependsOnRoleIDs:   dependencies,
		RuntimeReleaseID:   uuid.NewSHA1(uuid.MustParse(planID), []byte("runtime:"+roleID)).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "model-balanced",
		ModelProvider:      "openai",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:model/primary",
		ComputeOfferID:     uuid.NewSHA1(uuid.MustParse(planID), []byte("compute:"+roleID)).String(),
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 8192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  3 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
	}
}

func dispatchRoleCost(roleID string) teamplan.RoleCostEstimate {
	return teamplan.RoleCostEstimate{
		RoleID:                roleID,
		ComputeMinimumMicros:  8_000,
		ComputeExpectedMicros: 18_000,
		ComputeMaximumMicros:  28_000,
		ModelMinimumMicros:    1_000,
		ModelExpectedMicros:   1_000,
		ModelMaximumMicros:    1_000,
		TotalMinimumMicros:    10_000,
		TotalExpectedMicros:   20_000,
		TotalMaximumMicros:    30_000,
	}
}

func dispatchRoleSelection(
	t *testing.T,
	now time.Time,
	roleID string,
) teamlaunch.RoleSelection {
	t.Helper()
	return teamlaunch.RoleSelection{
		RoleID: roleID,
		RuntimeInstallationDigest: "sha256:" +
			strings.Repeat("b", 64),
		RuntimeExecutableDigest: "sha256:" +
			strings.Repeat("c", 64),
		WorkerRelease: dispatchWorkerRelease(t, now),
	}
}

func dispatchWorkerRelease(
	t *testing.T,
	now time.Time,
) workerrelease.ReleaseV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion:         workerami.ImageManifestSchemaV1,
		AgentInstanceID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ImageID:               "ami-0123456789abcdef0",
		ImageName:             "dtx-worker-ami-0123456789abcdef0123",
		RootSnapshotID:        "snap-0123456789abcdef0",
		AccountID:             "123456789012",
		Region:                "us-east-1",
		Architecture:          "amd64",
		BaseAMIID:             "ami-0abcdef0123456789",
		BaseAMIOwnerID:        "099720109477",
		RootDeviceName:        "/dev/sda1",
		ReleaseManifestDigest: "sha256:" + strings.Repeat("d", 64),
		WorkerRootFSDigest:    "sha256:" + strings.Repeat("e", 64),
		WorkerBinaryDigest:    "sha256:" + strings.Repeat("f", 64),
		CreatedAt: now.Add(-time.Hour).UTC().
			Truncate(time.Second).Format(time.RFC3339),
	}
	attestation := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion:         awsprovider.WorkerAMIAttestationSchemaV1,
		AgentInstanceID:       image.AgentInstanceID,
		AMIID:                 image.ImageID,
		RootSnapshotID:        image.RootSnapshotID,
		AccountID:             image.AccountID,
		Region:                image.Region,
		Architecture:          recipe.ArchitectureAMD64,
		ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest:    image.WorkerRootFSDigest,
		WorkerBinaryDigest:    image.WorkerBinaryDigest,
		ObservedAt: now.Add(-59 * time.Minute).UTC().
			Truncate(time.Second),
	}
	imageDigest, err := attestation.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workerrelease.PublicationV1{
		SchemaVersion: workerrelease.PublicationSchemaV1,
		ImageManifest: image,
		ImageDigest:   imageDigest,
		Attestation:   attestation,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := workerrelease.ParsePublicationJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return release
}
