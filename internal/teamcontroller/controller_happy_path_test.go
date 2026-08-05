package teamcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerresult"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestProcessRoleCompletesApprovedWorkerLifecycle(t *testing.T) {
	t.Parallel()
	fixture := newControllerHappyPathFixture(t)
	ctx := context.Background()

	wantPhases := []teamdispatch.Phase{
		teamdispatch.PhaseInputReady,
		teamdispatch.PhaseArtifactsReady,
		teamdispatch.PhaseWorkerRegistered,
		teamdispatch.PhaseBootstrapReady,
		teamdispatch.PhaseProvisioning,
		teamdispatch.PhaseActive,
	}
	for _, want := range wantPhases {
		if err := fixture.controller.ProcessRole(
			ctx,
			fixture.intent.OwnerID,
			fixture.intent.OperationID,
		); err != nil {
			t.Fatalf("advance to %s: %v", want, err)
		}
		if got := fixture.repository.current.Phase; got != want {
			t.Fatalf("phase = %s, want %s", got, want)
		}
	}

	fixture.workers.finishSucceeded(t, fixture.objects)
	for _, want := range []teamdispatch.Phase{
		teamdispatch.PhaseResultReady,
		teamdispatch.PhaseDestroying,
		teamdispatch.PhaseCompleted,
	} {
		if err := fixture.controller.ProcessRole(
			ctx,
			fixture.intent.OwnerID,
			fixture.intent.OperationID,
		); err != nil {
			t.Fatalf("advance to %s: %v", want, err)
		}
		if got := fixture.repository.current.Phase; got != want {
			t.Fatalf("phase = %s, want %s", got, want)
		}
	}
	if err := fixture.controller.ProcessRole(
		ctx,
		fixture.intent.OwnerID,
		fixture.intent.OperationID,
	); err != nil {
		t.Fatalf("terminal replay: %v", err)
	}

	completed := fixture.repository.current
	if completed.Validate() != nil ||
		completed.Outcome != task.OutcomeSucceeded ||
		completed.ResultEvidence == nil ||
		len(completed.ResultEvidence.Finals) != 1 ||
		completed.ResultEvidence.Finals[0].Summary != "done" {
		t.Fatalf("completed dispatch = %#v", completed)
	}
	if fixture.materializer.calls != 5 ||
		fixture.artifacts.inputCalls != 4 ||
		fixture.artifacts.bundleCalls != 4 ||
		fixture.workers.createCalls != 2 ||
		fixture.bootstrap.calls != 1 ||
		len(fixture.resources.specs) != 4 ||
		fixture.results.calls != 1 ||
		fixture.cleanup.calls != 1 {
		t.Fatalf(
			"calls materialize=%d inputs=%d bundles=%d worker=%d bootstrap=%d resources=%d results=%d cleanup=%d",
			fixture.materializer.calls,
			fixture.artifacts.inputCalls,
			fixture.artifacts.bundleCalls,
			fixture.workers.createCalls,
			fixture.bootstrap.calls,
			len(fixture.resources.specs),
			fixture.results.calls,
			fixture.cleanup.calls,
		)
	}
	if fixture.tasks.cancelCalls != 0 {
		t.Fatalf("successful task cancel calls = %d, want 0", fixture.tasks.cancelCalls)
	}
}

func TestProcessRoleCollectsResultWhileExecutionIsVerifying(t *testing.T) {
	t.Parallel()
	fixture := newControllerHappyPathFixture(t)
	ctx := context.Background()

	for range 6 {
		if err := fixture.controller.ProcessRole(
			ctx,
			fixture.intent.OwnerID,
			fixture.intent.OperationID,
		); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.repository.current.Phase != teamdispatch.PhaseActive {
		t.Fatalf("phase = %s, want active", fixture.repository.current.Phase)
	}
	fixture.workers.finishSucceeded(t, fixture.objects)
	reader := fixture.controller.authorizations.(happyPathAuthorizationReader)
	reader.authorized.Execution.Status = teamexecution.StatusVerifying
	fixture.controller.authorizations = reader

	if err := fixture.controller.ProcessRole(
		ctx,
		fixture.intent.OwnerID,
		fixture.intent.OperationID,
	); err != nil {
		t.Fatalf("collect verifying result: %v", err)
	}
	if fixture.repository.current.Phase != teamdispatch.PhaseResultReady {
		t.Fatalf(
			"phase = %s, want result_ready",
			fixture.repository.current.Phase,
		)
	}
}

type controllerHappyPathFixture struct {
	controller   *Controller
	intent       teamdispatch.IntentV1
	repository   *happyPathRepository
	materializer *happyPathMaterializer
	artifacts    *happyPathArtifactPublisher
	workers      *happyPathWorkerControl
	bootstrap    *happyPathBootstrapPublisher
	resources    *happyPathResourceProvisioner
	objects      *happyPathObjectReader
	results      *happyPathResultCollector
	cleanup      *happyPathCleanup
	tasks        *taskControlStub
}

func newControllerHappyPathFixture(t *testing.T) controllerHappyPathFixture {
	t.Helper()
	now := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	authorized, plan := happyPathAuthorizedExecution(t, now)
	intent, err := teamdispatch.NewIntent(
		authorized,
		"implementation",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	repository := &happyPathRepository{
		now: func() time.Time { return now },
		current: teamdispatch.Fact{
			Intent:         intent,
			IntentDigest:   intentDigest,
			Phase:          teamdispatch.PhaseIntent,
			Outcome:        task.OutcomePending,
			RecordRevision: 1,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	}
	if err := repository.current.Validate(); err != nil {
		t.Fatalf("initial dispatch: %v", err)
	}

	workspace := []byte("controller happy path workspace tar")
	materializer := &happyPathMaterializer{
		authorized: authorized,
		workspace:  workspace,
		now:        now,
	}
	credentialBuilder := happyPathCredentialBuilder(t, plan, now)
	artifacts := &happyPathArtifactPublisher{
		accountID: plan.ProviderScope.AccountID,
		region:    plan.Region,
		workspace: workspace,
	}
	connection := cloudapp.Connection{
		ConnectionID:   plan.ProviderScope.ConnectionID,
		OwnerID:        plan.OwnerID,
		AccountID:      plan.ProviderScope.AccountID,
		Region:         plan.Region,
		ControlRoleARN: "arn:aws:iam::123456789012:role/dtx-test-control",
		Status:         "active",
		Revision:       int64(plan.ProviderScope.ConnectionRevision),
	}
	workers := &happyPathWorkerControl{now: now, intent: intent}
	repository.enrollmentExpires = func() time.Time {
		return workers.current.Enrollment.ExpiresAt
	}
	bootstrap := &happyPathBootstrapPublisher{}
	offers := &happyPathOfferSource{plan: plan, now: now}
	resources := &happyPathResourceProvisioner{}
	objects := &happyPathObjectReader{objects: make(map[string][]byte)}
	collector, err := workerresult.NewCollector(objects)
	if err != nil {
		t.Fatal(err)
	}
	results := &happyPathResultCollector{collector: collector}
	cleanup := &happyPathCleanup{}
	tasks := &taskControlStub{current: task.Task{
		TaskID:          intent.TaskID,
		OwnerID:         intent.OwnerID,
		ExecutionStatus: task.ExecutionQueued,
		OutcomeStatus:   task.OutcomePending,
		Revision:        1,
	}}
	authorizations := happyPathAuthorizationReader{authorized: authorized}
	scheduler, err := teamdispatch.NewService(
		authorizations,
		happyPathProgressReader{},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := New(
		Config{
			AgentInstanceID: intent.AgentInstanceID,
			PollInterval:    100 * time.Millisecond,
			BatchSize:       8,
			Now:             func() time.Time { return now },
		},
		Dependencies{
			Scheduler:       scheduler,
			Executions:      &executionDispatcherStub{},
			ExecutionQueue:  executionQueueStub{},
			Dispatches:      repository,
			Authorizations:  authorizations,
			Inputs:          materializer,
			Workspaces:      happyPathWorkspaceSource{workspace: workspace},
			Credentials:     credentialBuilder,
			Artifacts:       artifacts,
			Connections:     happyPathConnectionReader{connection: connection},
			Workers:         workers,
			Bootstraps:      bootstrap,
			Offers:          offers,
			Resources:       resources,
			Results:         results,
			Cleanup:         cleanup,
			Finalizer:       executionFinalizerStub{},
			Tasks:           tasks,
			PlanExpirations: &planExpiryControlStub{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return controllerHappyPathFixture{
		controller: controller, intent: intent,
		repository: repository, materializer: materializer,
		artifacts: artifacts, workers: workers, bootstrap: bootstrap,
		resources: resources, objects: objects, results: results,
		cleanup: cleanup, tasks: tasks,
	}
}

func happyPathAuthorizedExecution(
	t *testing.T,
	now time.Time,
) (teamdispatch.AuthorizedExecution, teamplan.Plan) {
	t.Helper()
	plan := happyPathPlan(t, now.Add(-5*time.Minute))
	approvalID := uuid.NewString()
	authorization, err := teamlaunch.NewAuthorizationV1(
		teamlaunch.BuildRequest{
			Plan:            plan,
			AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			ApprovalID:      approvalID,
			Network: teamlaunch.NetworkV1{
				ConnectivityMode:  teamlaunch.ConnectivityDirectPublicTLSV1,
				VPCID:             "vpc-0123456789abcdef0",
				SubnetID:          "subnet-0123456789abcdef0",
				AvailabilityZone:  "ap-northeast-3a",
				SecurityGroupMode: teamlaunch.SecurityGroupDedicatedNoIngress,
				PublicIPv4:        true,
				PublicInbound:     false,
				ControlPlaneEndpoint: "grpcs://" +
					"worker-control.example.com:443",
				Egress: []teamlaunch.EgressRuleV1{
					{
						Protocol: "udp", FromPort: 53, ToPort: 53,
						CIDRv4: "169.254.169.253/32",
					},
					{
						Protocol: "tcp", FromPort: 443, ToPort: 443,
						CIDRv4: "0.0.0.0/0",
					},
				},
			},
			Retention: teamlaunch.RetentionV1{
				Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
				AutoDestroy:            true,
				MaximumLifetimeSeconds: 2 * 60 * 60,
				DestroyGraceSeconds:    5 * 60,
			},
			LaunchNotBefore: now.Add(-time.Minute),
			LaunchNotAfter:  now.Add(20 * time.Minute),
			RoleSelections: []teamlaunch.RoleSelection{{
				RoleID:                    "implementation",
				RuntimeInstallationDigest: happyPathDigest("8"),
				RuntimeExecutableDigest:   happyPathDigest("7"),
				WorkerRelease: happyPathWorkerRelease(
					t,
					"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
					plan.ProviderScope.AccountID,
					plan.Region,
					now,
				),
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	launchDigest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := now.Add(-30 * time.Second)
	approved := teamorchestration.ApprovedPlanFact{
		Plan: teamorchestration.PlanFact{
			TaskID:         uuid.NewString(),
			Plan:           plan,
			PlanDigest:     planDigest,
			Status:         teamorchestration.PlanApproved,
			RecordRevision: 2,
			CreatedAt:      plan.QuotedAt,
			UpdatedAt:      approvedAt,
		},
		Approval: teamorchestration.ApprovalFact{
			Signature: teamapproval.SignatureV1{
				SchemaVersion:             teamapproval.SignatureSchemaV2,
				ApprovalID:                approvalID,
				ChallengeID:               uuid.NewString(),
				PlanID:                    plan.PlanID,
				PlanRevision:              plan.Revision,
				PlanDigest:                planDigest,
				LaunchAuthorizationID:     authorization.AuthorizationID,
				LaunchAuthorizationDigest: launchDigest,
				SignerKeyID:               "team-device-happy-path",
				SignatureBase64URL:        strings.Repeat("A", 86),
			},
			Authorization: &authorization,
			ApprovedAt:    approvedAt,
			CreatedAt:     approvedAt,
		},
	}
	execution, err := teamexecution.Materialize(approved)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approved.Plan.Status = teamorchestration.PlanExecuting
	authorized := teamdispatch.AuthorizedExecution{
		Approval: approved,
		Execution: teamexecution.Fact{
			Execution:       execution,
			ExecutionDigest: executionDigest,
			Status:          teamexecution.StatusDispatching,
			RecordRevision:  2,
			CreatedAt:       approvedAt,
			UpdatedAt:       now,
		},
	}
	if err := authorized.ValidateForLaunch(now); err != nil {
		t.Fatalf("authorized execution: %v", err)
	}
	return authorized, plan
}

func happyPathPlan(t *testing.T, quotedAt time.Time) teamplan.Plan {
	t.Helper()
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "Implement and verify the approved change.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
			teamplan.CapabilityRepositoryWrite,
			teamplan.CapabilityStructuredResults,
			teamplan.CapabilityTest,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   uuid.NewString(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "0.1.0",
		RuntimeImageDigest: happyPathDigest("1"),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "openai-code-premium",
		ModelProvider:      "openai",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:models/openai-code",
		ComputeOfferID:     uuid.NewString(),
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU: 2, MemoryMiB: 8192, DiskGiB: 40,
			Arch: recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  10 * time.Minute,
			Expected: 20 * time.Minute,
			Maximum:  45 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum: 10_000, InputExpected: 30_000,
			InputMaximum: 80_000, OutputMinimum: 2_000,
			OutputExpected: 8_000, OutputMaximum: 20_000,
		},
		ColdStart: 90 * time.Second,
	}
	plan := teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        uuid.NewString(),
		Revision:      1,
		OwnerID:       "owner-controller-happy-path",
		GoalDigest:    happyPathDigest("2"),
		ProviderScope: teamplan.ProviderScope{
			Provider:     teamplan.CloudProviderAWS,
			ConnectionID: uuid.NewString(), ConnectionRevision: 11,
			AccountID: "123456789012",
		},
		Region:                "ap-northeast-3",
		CatalogRevision:       happyPathDigest("3"),
		PolicyRevision:        happyPathDigest("5"),
		PricingSnapshotID:     uuid.NewString(),
		PricingSnapshotDigest: happyPathDigest("4"),
		QuotedAt:              quotedAt,
		ValidUntil:            quotedAt.Add(teamplan.OfferSnapshotValidity),
		ProposalConfidence:    85,
		ProposalRationale:     "One isolated implementation Worker is sufficient.",
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  11*time.Minute + 30*time.Second,
			ExpectedWallTime: 21*time.Minute + 30*time.Second,
			MaximumWallTime:  46*time.Minute + 30*time.Second,
		},
		Cost: teamplan.CostEstimate{
			Currency: "USD", MinimumMicros: 120_000,
			ExpectedMicros: 280_000, MaximumMicros: 650_000,
			HardBudgetMicros: 780_000,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:               "implementation",
				ComputeMinimumMicros: 20_000, ComputeExpectedMicros: 50_000,
				ComputeMaximumMicros: 100_000, ModelMinimumMicros: 90_000,
				ModelExpectedMicros: 220_000, ModelMaximumMicros: 540_000,
				TotalMinimumMicros: 120_000, TotalExpectedMicros: 280_000,
				TotalMaximumMicros: 650_000,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func happyPathWorkerRelease(
	t *testing.T,
	agentInstanceID,
	accountID,
	region string,
	now time.Time,
) workerrelease.ReleaseV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion:         workerami.ImageManifestSchemaV1,
		AgentInstanceID:       agentInstanceID,
		ImageID:               "ami-0123456789abcdef0",
		ImageName:             "dtx-worker-ami-0123456789abcdef0123",
		RootSnapshotID:        "snap-0123456789abcdef0",
		AccountID:             accountID,
		Region:                region,
		Architecture:          "amd64",
		BaseAMIID:             "ami-0abcdef0123456789",
		BaseAMIOwnerID:        "099720109477",
		RootDeviceName:        "/dev/sda1",
		ReleaseManifestDigest: happyPathDigest("e"),
		WorkerRootFSDigest:    happyPathDigest("f"),
		WorkerBinaryDigest:    happyPathDigest("6"),
		CreatedAt: now.Add(-2 * time.Hour).UTC().
			Truncate(time.Second).Format(time.RFC3339),
	}
	evidence := awsprovider.WorkerAMIAttestationV1{
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
		ObservedAt:            now.Add(-90 * time.Minute),
	}
	imageDigest, err := evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workerrelease.PublicationV1{
		SchemaVersion: workerrelease.PublicationSchemaV1,
		ImageManifest: image,
		ImageDigest:   imageDigest,
		Attestation:   evidence,
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

type happyPathAuthorizationReader struct {
	authorized teamdispatch.AuthorizedExecution
}

func (reader happyPathAuthorizationReader) LoadAuthorizedExecution(
	_ context.Context,
	ownerID,
	executionID string,
) (teamdispatch.AuthorizedExecution, error) {
	if ownerID != reader.authorized.Execution.Execution.OwnerID ||
		executionID != reader.authorized.Execution.Execution.ExecutionID {
		return teamdispatch.AuthorizedExecution{}, teamdispatch.ErrNotFound
	}
	return reader.authorized, nil
}

type happyPathProgressReader struct{}

func (happyPathProgressReader) LoadRoleProgress(
	context.Context,
	string,
	string,
) ([]teamdispatch.RoleProgress, error) {
	return nil, nil
}

type happyPathMaterializer struct {
	authorized teamdispatch.AuthorizedExecution
	workspace  []byte
	now        time.Time
	calls      int
}

func (materializer *happyPathMaterializer) Materialize(
	_ context.Context,
	_ task.MutationScope,
	request teaminput.MaterializeRequest,
) (teaminput.PreparedInput, error) {
	materializer.calls++
	execution := materializer.authorized.Execution.Execution
	if request.OwnerID != execution.OwnerID ||
		request.ExecutionID != execution.ExecutionID ||
		request.RoleID != "implementation" {
		return teaminput.PreparedInput{}, teaminput.ErrFactMismatch
	}
	contextID, err := teaminput.ContextSnapshotID(
		execution.ExecutionID,
		request.RoleID,
	)
	if err != nil {
		return teaminput.PreparedInput{}, err
	}
	workspaceID, err := teaminput.WorkspaceSnapshotID(
		execution.ExecutionID,
		request.RoleID,
	)
	if err != nil {
		return teaminput.PreparedInput{}, err
	}
	workspaceDigest := happyPathContentDigest(materializer.workspace)
	compiled, err := teaminput.Compile(teaminput.CompileRequest{
		Execution:       execution,
		ExecutionDigest: materializer.authorized.Execution.ExecutionDigest,
		RoleID:          request.RoleID,
		Context: teaminput.ContextInput{
			SnapshotID:   contextID,
			GoalDigest:   execution.GoalDigest,
			GoalSummary:  "Complete the approved implementation and tests.",
			Constraints:  []string{"Do not modify the main branch."},
			Dependencies: []teaminput.DependencyResultV1{},
			Artifacts:    []teaminput.ArtifactRefV1{},
		},
		Workspace: teaminput.WorkspaceSnapshot{
			SnapshotID: workspaceID,
			Digest:     workspaceDigest,
			SizeBytes:  int64(len(materializer.workspace)),
		},
	})
	if err != nil {
		return teaminput.PreparedInput{}, err
	}
	role := execution.Roles[0]
	inputID, err := teaminput.InputID(execution.ExecutionID, role.RoleID)
	if err != nil {
		compiled.Destroy()
		return teaminput.PreparedInput{}, err
	}
	roleDigest, err := role.Digest()
	if err != nil {
		compiled.Destroy()
		return teaminput.PreparedInput{}, err
	}
	materialization := teaminput.MaterializationV1{
		SchemaVersion:         teaminput.MaterializationSchemaV1,
		InputID:               inputID,
		OwnerID:               execution.OwnerID,
		ExecutionID:           execution.ExecutionID,
		ExecutionDigest:       compiled.Manifest.ExecutionDigest,
		RoleID:                role.RoleID,
		RoleDigest:            roleDigest,
		TaskID:                execution.TaskID,
		TaskStepID:            role.TaskStepID,
		DeploymentID:          role.DeploymentID,
		ExpectedWorkerID:      role.ExpectedWorkerID,
		ContextSnapshotID:     compiled.Manifest.ContextSnapshotID,
		ContextDigest:         compiled.Manifest.ContextDigest,
		WorkspaceSnapshotID:   compiled.Manifest.WorkspaceSnapshotID,
		WorkspaceDigest:       compiled.Manifest.WorkspaceDigest,
		Manifest:              compiled.Manifest,
		ManifestDigest:        compiled.ManifestDigest,
		RuntimeTask:           compiled.RuntimeTask,
		RuntimeTaskDigest:     compiled.Manifest.RuntimeTaskDigest,
		ExecutionBundleDigest: compiled.ExecutionBundleDigest,
		CredentialGrant:       compiled.CredentialGrant,
		CredentialGrantDigest: compiled.CredentialGrantDigest,
		ContextTargetPath:     compiled.ContextTargetPath,
		WorkspaceTargetPath:   compiled.WorkspaceTargetPath,
		CredentialTargetPath:  compiled.CredentialTargetPath,
	}
	if err := materialization.Validate(); err != nil {
		compiled.Destroy()
		return teaminput.PreparedInput{}, err
	}
	return teaminput.PreparedInput{
		Fact: teaminput.Fact{
			Materialization: materialization,
			Status:          teaminput.StatusMaterialized,
			RecordRevision:  1,
			CreatedAt:       materializer.now,
			UpdatedAt:       materializer.now,
		},
		Compiled: compiled,
	}, nil
}

type happyPathWorkspaceSource struct{ workspace []byte }

func (source happyPathWorkspaceSource) LoadRoleWorkspaceContent(
	_ context.Context,
	_ teamdispatch.IntentV1,
	_ teaminput.MaterializationV1,
) (awsartifact.TeamWorkspaceContent, error) {
	return happyPathWorkspaceContent{content: bytes.Clone(source.workspace)}, nil
}

type happyPathWorkspaceContent struct{ content []byte }

func (content happyPathWorkspaceContent) Open(
	context.Context,
) (io.ReadSeekCloser, error) {
	return &happyPathReadSeekCloser{Reader: bytes.NewReader(content.content)}, nil
}

type happyPathReadSeekCloser struct{ *bytes.Reader }

func (*happyPathReadSeekCloser) Close() error { return nil }

type happyPathSecretResolver struct{ value []byte }

func (resolver happyPathSecretResolver) ResolveSecret(
	context.Context,
	string,
) ([]byte, error) {
	return bytes.Clone(resolver.value), nil
}

func happyPathCredentialBuilder(
	t *testing.T,
	plan teamplan.Plan,
	now time.Time,
) *teamcredential.Builder {
	t.Helper()
	assignment := plan.Assignments[0]
	profiles, err := modelapi.NewProfileCatalog([]modelapi.Profile{{
		ProfileID:       assignment.ModelProfileID,
		Provider:        modelapi.ProviderOpenAICompatible,
		Model:           assignment.Model,
		BaseURL:         "https://api.openai.example/v1",
		SecretRef:       "mounted:openai-code",
		ContextWindow:   256_000,
		MaxOutputTokens: 64_000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := teampricing.NewModelOfferCatalog(
		teampricing.ModelOfferCatalogDocument{
			SchemaVersion: teampricing.ModelOfferCatalogSchemaV1,
			Currency:      "USD",
			Sources: []teampricing.ModelPriceSource{{
				SourceID: "openai-pricing",
				Digest:   happyPathDigest("a"),
				CapturedAt: now.Add(-time.Hour).UTC().
					Truncate(time.Microsecond),
			}},
			Offers: []teampricing.ModelOfferEntry{{
				ProfileID:              assignment.ModelProfileID,
				WorkerProvider:         assignment.ModelProvider,
				Interface:              assignment.ModelInterface,
				Quality:                teamplan.QualityPremium,
				InputMicrosPerMillion:  2_000_000,
				OutputMicrosPerMillion: 8_000_000,
				WorkerCredentialRef:    assignment.ModelCredentialRef,
				Enabled:                true,
				SourceID:               "openai-pricing",
			}},
		},
		profiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := teampricing.NewCatalogCredentialReadiness(
		catalog,
		happyPathSecretResolver{value: []byte("provider-token-value")},
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Close)
	builder, err := teamcredential.NewBuilder(
		issuer,
		readiness,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

type happyPathArtifactPublisher struct {
	accountID   string
	region      string
	workspace   []byte
	inputCalls  int
	bundleCalls int
}

func (publisher *happyPathArtifactPublisher) PublishTeamInputs(
	ctx context.Context,
	_ cloudapp.Connection,
	_ string,
	compiled teaminput.CompiledInput,
	workspace awsartifact.TeamWorkspaceContent,
) error {
	publisher.inputCalls++
	reader, err := workspace.Open(ctx)
	if err != nil {
		return err
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(raw, publisher.workspace) ||
		compiled.WorkspaceObject.SHA256 != happyPathContentDigest(raw) {
		return teaminput.ErrFactMismatch
	}
	return nil
}

func (publisher *happyPathArtifactPublisher) PublishBundles(
	_ context.Context,
	_ cloudapp.Connection,
	deploymentID string,
	compiled cloudexecution.CompiledBundles,
	secretRefs []string,
) (cloudexecution.PublishedBundles, error) {
	publisher.bundleCalls++
	if compiled.InstallerRootTrust == nil ||
		len(compiled.InstallerArtifacts) != 0 ||
		len(compiled.InstallerSecrets) != 1 ||
		len(secretRefs) != 1 {
		return cloudexecution.PublishedBundles{}, errors.New("invalid installer staging")
	}
	recipeDigest := sha256.Sum256(compiled.RecipeBytes)
	executionDigest := sha256.Sum256(compiled.ExecutionBytes)
	launchDigest := sha256.Sum256([]byte("launch-config"))
	base := "s3://controller-happy-path/deployments/" + deploymentID + "/"
	staging := compiled.InstallerSecrets[0]
	bound := "secret://aws/deployments/" + deploymentID + "/" +
		staging.SlotID + "/" + staging.VersionID
	published := cloudexecution.PublishedBundles{
		Recipe: worker.BundleRef{
			S3Ref: base + "bundles/recipe.cbor", SHA256: recipeDigest,
		},
		Execution: worker.BundleRef{
			S3Ref: base + "bundles/execution.json", SHA256: executionDigest,
		},
		Launch: cloudexecution.BootstrapArtifact{
			Reference: base + "launch/config.json", SHA256: launchDigest,
		},
		Access: worker.AccessScope{
			ArtifactPrefix:   base + "artifacts/",
			CheckpointPrefix: base + "checkpoints/",
			EvidencePrefix:   base + "evidence/",
			LogPrefix:        "cloudwatch://controller-happy-path/" + deploymentID,
			SecretRefs:       []string{bound},
		},
		SecretBindings:     map[string]string{staging.SecretRef: bound},
		InstallerRootTrust: compiled.InstallerRootTrust,
		InstallerArtifacts: []installerbootstrap.ArtifactSourceV1{},
		InstallerSecrets: []installerbootstrap.SecretSourceV1{{
			SchemaVersion: installerbootstrap.SecretSourceSchemaV1,
			SlotID:        staging.SlotID, SecretRef: staging.SecretRef,
			SecretARN: "arn:aws:secretsmanager:" + publisher.region + ":" +
				publisher.accountID + ":secret:" + staging.SecretName + "-abcdef",
			SecretName: staging.SecretName, VersionID: staging.VersionID,
			KMSKeyARN: "arn:aws:kms:" + publisher.region + ":" +
				publisher.accountID + ":key/55555555-5555-4555-8555-555555555555",
			TargetPath: staging.TargetPath, FileMode: staging.FileMode,
			OwnerUID: staging.OwnerUID, OwnerGID: staging.OwnerGID,
			RecipeDigest: staging.RecipeDigest,
		}},
	}
	if published.Recipe.Validate() != nil ||
		published.Execution.Validate() != nil ||
		published.Access.Validate() != nil {
		return cloudexecution.PublishedBundles{}, errors.New("invalid publication")
	}
	return published, nil
}

type happyPathConnectionReader struct{ connection cloudapp.Connection }

func (reader happyPathConnectionReader) LoadConnection(
	_ context.Context,
	ownerID,
	connectionID string,
) (cloudapp.Connection, error) {
	if ownerID != reader.connection.OwnerID ||
		connectionID != reader.connection.ConnectionID {
		return cloudapp.Connection{}, cloudapp.ErrNotFound
	}
	return reader.connection, nil
}

type happyPathCredential struct{ value []byte }

func (credential *happyPathCredential) Reveal() []byte {
	return bytes.Clone(credential.value)
}

func (credential *happyPathCredential) Destroy() {
	clear(credential.value)
	credential.value = nil
}

type happyPathWorkerControl struct {
	now         time.Time
	intent      teamdispatch.IntentV1
	current     worker.Deployment
	createCalls int
}

func (control *happyPathWorkerControl) CreateDeployment(
	_ context.Context,
	_ cloudexecution.WorkerCreateMutation,
	request worker.CreateDeploymentRequest,
) (worker.Deployment, cloudexecution.SensitiveCredential, error) {
	control.createCalls++
	credential := []byte("0123456789abcdef0123456789abcdef")
	if control.current.DeploymentID == "" {
		if request.DeploymentID != control.intent.DeploymentID ||
			request.OwnerID != control.intent.OwnerID ||
			request.TaskID != control.intent.TaskID ||
			request.StepID != control.intent.TaskStepID ||
			worker.ValidateInstallerCapability(
				request.DeploymentID,
				request.TaskID,
				request.RecipeBundle,
				request.InstallerDelivery,
				request.InstallerCommandIDs,
			) != nil {
			return worker.Deployment{}, nil, worker.ErrInvalid
		}
		control.current = worker.Deployment{
			DeploymentID: request.DeploymentID,
			OwnerID:      request.OwnerID, TaskID: request.TaskID,
			StepID:               request.StepID,
			ControlPlaneEndpoint: request.ControlPlaneEndpoint,
			RecipeBundle:         request.RecipeBundle,
			ExecutionBundle:      request.ExecutionBundle,
			ExecutionTimeout:     request.ExecutionTimeout,
			InstallerDelivery:    request.InstallerDelivery,
			InstallerCommandIDs:  append([]string(nil), request.InstallerCommandIDs...),
			State:                worker.StatePendingEnrollment,
			Outcome:              worker.OutcomePending,
			Access:               request.Access,
			Enrollment: worker.Enrollment{
				CredentialDigest: sha256.Sum256(credential),
				ExpiresAt:        control.now.Add(request.EnrollmentTTL),
			},
			Revision: 1, CreatedAt: control.now, UpdatedAt: control.now,
		}
	}
	return control.current, &happyPathCredential{value: credential}, nil
}

func (control *happyPathWorkerControl) GetDeployment(
	context.Context,
	string,
) (worker.Deployment, error) {
	if control.current.DeploymentID == "" {
		return worker.Deployment{}, worker.ErrNotFound
	}
	return control.current, nil
}

func (control *happyPathWorkerControl) RequestCancel(
	context.Context,
	string,
	string,
) (worker.Deployment, error) {
	return worker.Deployment{}, errors.New("unexpected cancellation")
}

func (control *happyPathWorkerControl) finishSucceeded(
	t *testing.T,
	objects *happyPathObjectReader,
) {
	t.Helper()
	final := []byte(
		`{"schema_version":"dirextalk.agent.codex-final/v1","status":"completed","summary":"done","deliverables":[],"tests":[],"risks":[]}`,
	)
	finalDigest := sha256.Sum256(final)
	nameDigest := sha256.Sum256([]byte("final.json"))
	finalRef := control.current.Access.ArtifactPrefix +
		"runtime-a1-e1-execute-role-" +
		hex.EncodeToString(nameDigest[:8]) + "-" +
		hex.EncodeToString(finalDigest[:]) + ".json"
	control.current.WorkerID = control.intent.ExpectedWorkerID
	control.current.ProviderInstanceID = "i-0123456789abcdef0"
	control.current.State = worker.StateFinished
	control.current.Outcome = worker.OutcomeSucceeded
	control.current.Lease = worker.Lease{
		Attempt: 1, Epoch: 1,
		LastHeartbeatAt: control.now,
	}
	manifest := workerrunner.ResultManifestV2{
		SchemaVersion: workerrunner.ResultManifestSchemaV2,
		DeploymentID:  control.current.DeploymentID,
		WorkerID:      control.current.WorkerID,
		TaskID:        control.current.TaskID,
		StepID:        control.current.StepID,
		Attempt:       1, LeaseEpoch: 1,
		RecipeSHA256:     hex.EncodeToString(control.current.RecipeBundle.SHA256[:]),
		ExecutionSHA256:  hex.EncodeToString(control.current.ExecutionBundle.SHA256[:]),
		Status:           "succeeded",
		CompletedActions: []string{"execute-role"},
		RuntimeResults: []workerrunner.RuntimeActionResultV1{{
			ActionID: "execute-role", TaskID: control.current.TaskID,
			Adapter: workerruntime.AdapterCodexV1,
			Usage:   workerruntime.Usage{InputTokens: 10, OutputTokens: 5},
			Artifacts: []workerrunner.RuntimeArtifactClaimV1{{
				Attempt: 1, LeaseEpoch: 1, Name: "final.json",
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
	control.current.ResultRef = control.current.Access.ArtifactPrefix + "result.json"
	control.current.Evidence = []worker.EvidenceRef{{
		Kind: "artifact", Ref: control.current.ResultRef,
		ObjectSHA256: "sha256:" + hex.EncodeToString(manifestDigest[:]),
		SizeBytes:    int64(len(manifestRaw)), MediaType: "application/json",
		Trust: worker.TrustWorkerClaim, Attempt: 1, LeaseEpoch: 1,
		RecordedAt: control.now,
	}}
	control.current.Revision++
	control.current.UpdatedAt = control.now
	objects.objects[control.current.ResultRef] = manifestRaw
	objects.objects[finalRef] = bytes.Clone(final)
}

type happyPathBootstrapPublisher struct{ calls int }

func (publisher *happyPathBootstrapPublisher) PublishBootstrap(
	_ context.Context,
	_ cloudapp.Connection,
	request cloudexecution.BootstrapRequest,
) (cloudexecution.BootstrapArtifact, error) {
	publisher.calls++
	if len(request.EnrollmentCredential) != 32 ||
		request.EnrollmentRevision != 1 {
		return cloudexecution.BootstrapArtifact{}, cloudexecution.ErrInvalid
	}
	result := request.Launch
	result.EnrollmentMaterialRef = "identity://aws-sts/" + request.DeploymentID
	return result, nil
}

type happyPathOfferSource struct {
	plan teamplan.Plan
	now  time.Time
}

func (source *happyPathOfferSource) BuildForConnection(
	_ context.Context,
	ownerID,
	connectionID string,
) (*teamplan.OfferSnapshot, error) {
	if ownerID != source.plan.OwnerID ||
		connectionID != source.plan.ProviderScope.ConnectionID {
		return nil, teamplan.ErrInvalid
	}
	assignment := source.plan.Assignments[0]
	capturedAt := source.now
	return teamplan.NewOfferSnapshot(teamplan.OfferSnapshotDocument{
		SchemaVersion: teamplan.OfferSnapshotSchemaV1,
		SnapshotID: uuid.NewSHA1(
			uuid.MustParse(source.plan.PlanID),
			[]byte("happy-path-fresh-quote"),
		).String(),
		ProviderScope: source.plan.ProviderScope,
		Region:        source.plan.Region, Currency: source.plan.Cost.Currency,
		CapturedAt: capturedAt,
		ValidUntil: capturedAt.Add(teamplan.OfferSnapshotValidity),
		Sources: []teamplan.OfferSourceReceipt{
			{Kind: teamplan.OfferSourceModelPricing, SourceID: "test:model-pricing", Digest: happyPathDigest("1"), CapturedAt: capturedAt},
			{Kind: teamplan.OfferSourceComputePricing, SourceID: "test:compute-pricing", Digest: happyPathDigest("2"), CapturedAt: capturedAt},
			{Kind: teamplan.OfferSourceComputeCapacity, SourceID: "test:compute-capacity", Digest: happyPathDigest("3"), CapturedAt: capturedAt},
			{Kind: teamplan.OfferSourceComputeConfig, SourceID: "test:compute-config", Digest: happyPathDigest("4"), CapturedAt: capturedAt},
		},
		ModelOffers: []teamplan.ModelOffer{{
			ProfileID: assignment.ModelProfileID,
			Provider:  assignment.ModelProvider, Model: assignment.Model,
			Interface: assignment.ModelInterface,
			Quality:   teamplan.QualityPremium, ContextTokens: 256_000,
			InputMicrosPerMillion:  2_000_000,
			OutputMicrosPerMillion: 8_000_000,
			CredentialRef:          assignment.ModelCredentialRef,
			Enabled:                true, CredentialReady: true,
		}},
		ComputeOffers: []teamplan.ComputeOffer{{
			OfferID: assignment.ComputeOfferID, Region: source.plan.Region,
			InstanceType: assignment.InstanceType,
			Architecture: assignment.Resources.Arch,
			VCPU:         assignment.Resources.VCPU,
			MemoryMiB:    assignment.Resources.MemoryMiB,
			DiskGiB:      assignment.Resources.DiskGiB,
			HourlyMicros: 100_000, PurchaseOption: "on_demand",
			CapacityPool:   "aws:ec2-quota:L-1216C47A",
			CapacityUnits:  uint64(assignment.Resources.VCPU),
			AvailableUnits: 64, Available: true,
		}},
	})
}

type happyPathResourceProvisioner struct {
	specs []resource.ProvisionSpec
}

func (provisioner *happyPathResourceProvisioner) Provision(
	_ context.Context,
	_ cloudapp.Connection,
	spec resource.ProvisionSpec,
	_ resource.ProviderCreateAuthorization,
) (resource.ResourceV1, error) {
	provisioner.specs = append(provisioner.specs, spec)
	return resource.ResourceV1{
		ResourceID:   spec.ResourceID,
		DeploymentID: spec.DeploymentID,
		State:        resource.StateActive,
	}, nil
}

type happyPathObjectReader struct {
	objects map[string][]byte
}

func (reader *happyPathObjectReader) Get(
	_ context.Context,
	reference string,
	maximum int64,
) ([]byte, error) {
	value, ok := reader.objects[reference]
	if !ok || maximum < 1 || int64(len(value)) > maximum {
		return nil, workerresult.ErrUnavailable
	}
	return bytes.Clone(value), nil
}

type happyPathResultCollector struct {
	collector *workerresult.Collector
	calls     int
}

func (collector *happyPathResultCollector) Collect(
	ctx context.Context,
	_ cloudapp.Connection,
	deployment worker.Deployment,
) (workerresult.Collected, error) {
	collector.calls++
	return collector.collector.Collect(ctx, deployment)
}

type happyPathCleanup struct{ calls int }

func (cleanup *happyPathCleanup) DestroyRole(
	_ context.Context,
	_ cloudapp.Connection,
	dispatch teamdispatch.Fact,
) (bool, error) {
	cleanup.calls++
	if dispatch.Phase != teamdispatch.PhaseDestroying {
		return false, ErrFactMismatch
	}
	return true, nil
}

type happyPathRepository struct {
	now               func() time.Time
	current           teamdispatch.Fact
	enrollmentExpires func() time.Time
}

func (repository *happyPathRepository) ListExecutionOperations(
	context.Context,
	string,
	string,
) ([]teamdispatch.Fact, error) {
	return []teamdispatch.Fact{repository.current}, nil
}

func (repository *happyPathRepository) ClaimRole(
	context.Context,
	task.MutationScope,
	teamdispatch.ClaimCommand,
) (teamdispatch.Fact, bool, error) {
	return repository.current, false, nil
}

func (repository *happyPathRepository) GetRoleOperation(
	_ context.Context,
	ownerID,
	operationID string,
) (teamdispatch.Fact, error) {
	if ownerID != repository.current.Intent.OwnerID ||
		operationID != repository.current.Intent.OperationID {
		return teamdispatch.Fact{}, teamdispatch.ErrNotFound
	}
	return repository.current, nil
}

func (repository *happyPathRepository) AdvanceRole(
	_ context.Context,
	command teamdispatch.AdvanceCommand,
) (teamdispatch.Fact, error) {
	if command.Validate() != nil ||
		command.OwnerID != repository.current.Intent.OwnerID ||
		command.OperationID != repository.current.Intent.OperationID ||
		command.ExpectedRevision != repository.current.RecordRevision ||
		command.FromPhase != repository.current.Phase {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	repository.current.Phase = command.ToPhase
	repository.current.Outcome = command.Outcome
	repository.bump()
	return repository.validCurrent()
}

func (repository *happyPathRepository) PublishRoleArtifacts(
	_ context.Context,
	command teamdispatch.PublishArtifactsCommand,
) (teamdispatch.Fact, error) {
	if command.Validate() != nil ||
		repository.current.Phase != teamdispatch.PhaseInputReady ||
		command.ExpectedRevision != repository.current.RecordRevision {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	digest, err := command.Evidence.Digest()
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	now := repository.now().UTC().Truncate(time.Microsecond)
	repository.current.PublishedEvidence = &command.Evidence
	repository.current.PublishedEvidenceDigest = digest
	repository.current.PublishedAt = &now
	repository.current.Phase = teamdispatch.PhaseArtifactsReady
	repository.current.Outcome = task.OutcomePending
	repository.bump()
	return repository.validCurrent()
}

func (repository *happyPathRepository) BeginProvisioning(
	_ context.Context,
	command teamdispatch.BeginProvisioningCommand,
) (teamdispatch.Fact, error) {
	if command.Validate() != nil ||
		repository.current.Phase != teamdispatch.PhaseBootstrapReady ||
		command.ExpectedRevision != repository.current.RecordRevision ||
		repository.enrollmentExpires == nil {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	digest, err := command.Quote.Digest()
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	now := repository.now().UTC().Truncate(time.Microsecond)
	expires := repository.enrollmentExpires().UTC().Truncate(time.Microsecond)
	repository.current.ProvisioningQuote = &command.Quote
	repository.current.ProvisioningQuoteDigest = digest
	repository.current.ProvisioningStartedAt = &now
	repository.current.ProvisioningWorkerRevision = command.WorkerDeploymentRevision
	repository.current.ProvisioningEnrollmentExpires = &expires
	repository.current.Phase = teamdispatch.PhaseProvisioning
	repository.current.Outcome = task.OutcomePending
	repository.bump()
	return repository.validCurrent()
}

func (repository *happyPathRepository) RefreshProvisioningQuote(
	_ context.Context,
	command teamdispatch.RefreshProvisioningQuoteCommand,
) (teamdispatch.Fact, error) {
	if command.Validate() != nil ||
		repository.current.Phase != teamdispatch.PhaseProvisioning ||
		command.ExpectedRevision != repository.current.RecordRevision {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	digest, err := command.Quote.Digest()
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	repository.current.ProvisioningQuote = &command.Quote
	repository.current.ProvisioningQuoteDigest = digest
	repository.bump()
	return repository.validCurrent()
}

func (repository *happyPathRepository) RecordRoleResult(
	_ context.Context,
	command teamdispatch.RecordResultCommand,
) (teamdispatch.Fact, error) {
	if command.Validate() != nil ||
		repository.current.Phase != teamdispatch.PhaseActive ||
		command.ExpectedRevision != repository.current.RecordRevision {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	digest, err := command.Evidence.Digest()
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	now := repository.now().UTC().Truncate(time.Microsecond)
	repository.current.ResultEvidence = &command.Evidence
	repository.current.ResultEvidenceDigest = digest
	repository.current.ResultVerifiedAt = &now
	repository.current.Phase = teamdispatch.PhaseResultReady
	repository.current.Outcome = task.OutcomePending
	repository.bump()
	return repository.validCurrent()
}

func (repository *happyPathRepository) ScheduleRoleRetry(
	context.Context,
	teamdispatch.RetryCommand,
) (teamdispatch.Fact, error) {
	return teamdispatch.Fact{}, errors.New("unexpected retry")
}

func (repository *happyPathRepository) ListRecoverableRoleDispatches(
	context.Context,
	*teamdispatch.RecoverableCursor,
	uint32,
	time.Time,
) ([]teamdispatch.Fact, error) {
	return []teamdispatch.Fact{repository.current}, nil
}

func (repository *happyPathRepository) bump() {
	repository.current.RecordRevision++
	repository.current.RetryAfter = nil
	repository.current.FailureCode = ""
	repository.current.UpdatedAt = repository.now().UTC().Truncate(time.Microsecond)
}

func (repository *happyPathRepository) validCurrent() (
	teamdispatch.Fact,
	error,
) {
	if err := repository.current.Validate(); err != nil {
		return teamdispatch.Fact{}, errors.Join(teamdispatch.ErrFactMismatch, err)
	}
	return repository.current, nil
}

func happyPathDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}

func happyPathContentDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
