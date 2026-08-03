package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

func TestDurableTeamWorkspaceProviderPersistsAndReplaysGitHubSource(
	t *testing.T,
) {
	execution, executionDigest := githubTeamExecutionFixture(t)
	role := execution.Roles[0]
	connection := githubTeamAWSConnection(execution)
	snapshot := githubTeamSnapshotFixture(
		t,
		execution.TaskInput,
		[]byte("canonical-github-workspace"),
	)
	snapshots := &githubTeamSnapshotRepository{}
	snapshotter := &githubTeamSnapshotter{snapshot: snapshot}
	publisher := &githubTeamSnapshotPublisher{}
	executions := &githubTeamExecutionReader{
		fact: teamexecution.Fact{
			Execution:       execution,
			ExecutionDigest: executionDigest,
			Status:          teamexecution.StatusDispatching,
			RecordRevision:  2,
			CreatedAt:       execution.AuthorizedAt,
			UpdatedAt:       execution.AuthorizedAt.Add(time.Second),
		},
	}
	empty, err := newEmptyTeamWorkspaceProvider()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newDurableTeamWorkspaceProvider(
		empty,
		executions,
		&githubTeamConnectionReader{connection: connection},
		snapshots,
		snapshotter,
		publisher,
	)
	if err != nil {
		t.Fatal(err)
	}

	workspace, err := provider.LoadRoleWorkspace(
		context.Background(),
		execution,
		role,
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedSnapshotID, err := teaminput.WorkspaceSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.SnapshotID != expectedSnapshotID ||
		workspace.Digest != snapshot.WorkspaceDigest ||
		workspace.SizeBytes != snapshot.SizeBytes ||
		snapshotter.calls != 1 ||
		publisher.calls != 1 ||
		snapshots.persistCalls != 1 {
		t.Fatalf(
			"first workspace=%#v snapshot=%d publish=%d persist=%d",
			workspace,
			snapshotter.calls,
			publisher.calls,
			snapshots.persistCalls,
		)
	}
	replayed, err := provider.LoadRoleWorkspace(
		context.Background(),
		execution,
		role,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != workspace ||
		snapshotter.calls != 1 ||
		publisher.calls != 1 ||
		snapshots.persistCalls != 1 {
		t.Fatalf(
			"replayed workspace=%#v snapshot=%d publish=%d persist=%d",
			replayed,
			snapshotter.calls,
			publisher.calls,
			snapshots.persistCalls,
		)
	}

	intent := githubTeamIntentFixture(
		t,
		execution,
		executionDigest,
		role,
	)
	materialization := githubTeamMaterializationFixture(
		t,
		execution,
		executionDigest,
		role,
		workspace,
	)
	content, err := provider.LoadRoleWorkspaceContent(
		context.Background(),
		intent,
		materialization,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := content.(*awsartifact.GitHubSourceWorkspace); !ok {
		t.Fatalf("unexpected source content type %T", content)
	}
}

func TestDurableTeamWorkspaceProviderFailsClosedForGitHubSource(
	t *testing.T,
) {
	execution, _ := githubTeamExecutionFixture(t)
	role := execution.Roles[0]
	empty, err := newEmptyTeamWorkspaceProvider()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("broker disabled", func(t *testing.T) {
		provider, err := newDurableTeamWorkspaceProvider(
			empty,
			&githubTeamExecutionReader{},
			nil,
			nil,
			nil,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.LoadRoleWorkspace(
			context.Background(),
			execution,
			role,
		)
		if !errors.Is(err, teaminput.ErrNotReady) {
			t.Fatalf("disabled GitHub source error=%v", err)
		}
	})

	t.Run("AWS connection drift", func(t *testing.T) {
		connection := githubTeamAWSConnection(execution)
		connection.Revision++
		snapshotter := &githubTeamSnapshotter{}
		provider, err := newDurableTeamWorkspaceProvider(
			empty,
			&githubTeamExecutionReader{},
			&githubTeamConnectionReader{connection: connection},
			&githubTeamSnapshotRepository{},
			snapshotter,
			&githubTeamSnapshotPublisher{},
		)
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.LoadRoleWorkspace(
			context.Background(),
			execution,
			role,
		)
		if !errors.Is(err, teaminput.ErrFactMismatch) ||
			snapshotter.calls != 0 {
			t.Fatalf(
				"connection drift error=%v snapshot calls=%d",
				err,
				snapshotter.calls,
			)
		}
	})
}

type githubTeamSnapshotter struct {
	snapshot githubsource.SnapshotV1
	calls    int
}

func (snapshotter *githubTeamSnapshotter) Prepare(
	_ context.Context,
	binding taskinput.BindingV2,
) (githubsource.Prepared, error) {
	snapshotter.calls++
	if snapshotter.snapshot.Validate() != nil ||
		snapshotter.snapshot.InputID != binding.InputID {
		return githubsource.Prepared{}, githubsource.ErrInvalid
	}
	return githubsource.Prepared{Snapshot: snapshotter.snapshot}, nil
}

type githubTeamSnapshotPublisher struct {
	calls int
}

func (publisher *githubTeamSnapshotPublisher) PublishGitHubSourceSnapshot(
	_ context.Context,
	connection cloudapp.Connection,
	snapshot githubsource.SnapshotV1,
	_ awsartifact.TeamWorkspaceContent,
) (githubsource.ArtifactV1, error) {
	publisher.calls++
	return githubsource.NewArtifactV1(
		snapshot,
		connection.ConnectionID,
		"dirextalk-test-artifacts",
		"version-1",
	)
}

type githubTeamSnapshotRepository struct {
	stored       githubsource.StoredFact
	persistCalls int
}

func (repository *githubTeamSnapshotRepository) FindGitHubSourceSnapshot(
	_ context.Context,
	key githubsource.LookupKey,
) (githubsource.StoredFact, bool, error) {
	if repository.stored.Validate() != nil {
		return githubsource.StoredFact{}, false, nil
	}
	fact := repository.stored.Fact
	if fact.Snapshot.InputID != key.InputID ||
		fact.Snapshot.InputDigest != key.InputDigest ||
		fact.ConnectionID != key.ConnectionID {
		return githubsource.StoredFact{}, false, nil
	}
	return repository.stored, true, nil
}

func (repository *githubTeamSnapshotRepository) PersistGitHubSourceSnapshot(
	_ context.Context,
	fact githubsource.FactV1,
) (githubsource.StoredFact, error) {
	repository.persistCalls++
	if repository.stored.Validate() == nil {
		return repository.stored, nil
	}
	digest, err := fact.Digest()
	if err != nil {
		return githubsource.StoredFact{}, err
	}
	repository.stored = githubsource.StoredFact{
		Fact:       fact,
		FactDigest: digest,
		CreatedAt: time.Date(
			2026,
			time.July,
			30,
			12,
			0,
			0,
			0,
			time.UTC,
		),
	}
	return repository.stored, nil
}

type githubTeamConnectionReader struct {
	connection cloudapp.Connection
}

func (reader *githubTeamConnectionReader) LoadConnection(
	_ context.Context,
	_,
	_ string,
) (cloudapp.Connection, error) {
	return reader.connection, nil
}

type githubTeamExecutionReader struct {
	fact teamexecution.Fact
}

func (reader *githubTeamExecutionReader) GetTeamExecution(
	_ context.Context,
	_,
	_ string,
) (teamexecution.Fact, error) {
	return reader.fact, nil
}

func githubTeamExecutionFixture(
	t *testing.T,
) (teamexecution.ExecutionV1, string) {
	t.Helper()
	executionID := uuid.NewString()
	taskID := uuid.NewString()
	goalDigest := githubTeamDigest("1")
	input, err := taskinput.NewGitHubInput(
		"owner-a",
		taskID,
		goalDigest,
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
	role := githubTeamRoleFixture(t, executionID, taskID)
	execution := teamexecution.ExecutionV1{
		SchemaVersion:       teamexecution.SchemaV3,
		ExecutionID:         executionID,
		OwnerID:             input.OwnerID,
		TaskID:              taskID,
		PlanID:              uuid.NewString(),
		PlanRevision:        1,
		PlanDigest:          githubTeamDigest("2"),
		ApprovalID:          uuid.NewString(),
		ApprovalSignerKeyID: "device-a",
		GoalDigest:          goalDigest,
		TaskInput:           binding,
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       uuid.NewString(),
			ConnectionRevision: 3,
			AccountID:          "123456789012",
		},
		Region:                "us-east-2",
		CatalogRevision:       githubTeamDigest("3"),
		PolicyRevision:        githubTeamDigest("4"),
		PricingSnapshotID:     uuid.NewString(),
		PricingSnapshotDigest: githubTeamDigest("5"),
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Currency:              "USD",
		MinimumCostMicros:     10_000,
		ExpectedCostMicros:    20_000,
		MaximumCostMicros:     30_000,
		HardBudgetMicros:      36_000,
		Schedule: teamexecution.ScheduleEstimateV1{
			MinimumWallSeconds:  60,
			ExpectedWallSeconds: 120,
			MaximumWallSeconds:  300,
		},
		AuthorizedAt: time.Date(
			2026,
			time.July,
			30,
			10,
			0,
			0,
			0,
			time.UTC,
		),
		Roles: []teamexecution.RoleV1{role},
	}
	if err := execution.Validate(); err != nil {
		t.Fatalf("invalid GitHub Team execution: %v", err)
	}
	digest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return execution, digest
}

func githubTeamRoleFixture(
	t *testing.T,
	executionID,
	taskID string,
) teamexecution.RoleV1 {
	t.Helper()
	executionUUID := uuid.MustParse(executionID)
	roleID := "implementation"
	declarationID := uuid.NewSHA1(
		executionUUID,
		[]byte("step-declaration:"+roleID),
	).String()
	stepID, err := task.MaterializeStepID(taskID, declarationID)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.NewSHA1(
		executionUUID,
		[]byte("deployment:"+roleID),
	).String()
	workerID, err := workeridentity.DeriveWorkerID(deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	return teamexecution.RoleV1{
		RoleID:               roleID,
		Title:                "Implementation",
		Objective:            "Implement the approved repository change.",
		WorkClass:            teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{teamplan.CapabilityGit},
		Workspace:            teamplan.WorkspaceIsolated,
		StepDeclarationID:    declarationID,
		TaskStepID:           stepID,
		DeploymentID:         deploymentID,
		ExpectedWorkerID:     workerID,
		RuntimeReleaseID: uuid.NewSHA1(
			executionUUID,
			[]byte("runtime:"+roleID),
		).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: githubTeamDigest("6"),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "model-balanced",
		ModelProvider:      "openai",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialSlot: "model-" +
			strings.Repeat("a", 16),
		ComputeOfferID: uuid.NewSHA1(
			executionUUID,
			[]byte("compute:"+roleID),
		).String(),
		InstanceType: "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 8192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
		Duration: teamexecution.DurationEstimateV1{
			MinimumSeconds:  60,
			ExpectedSeconds: 120,
			MaximumSeconds:  180,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
		ColdStartSeconds: 30,
	}
}

func githubTeamSnapshotFixture(
	t *testing.T,
	binding taskinput.BindingV2,
	content []byte,
) githubsource.SnapshotV1 {
	t.Helper()
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
		WorkspaceDigest:    githubTeamBytesDigest(content),
		SizeBytes:          int64(len(content)),
		FileCount:          1,
	}
	if snapshot.Validate() != nil {
		t.Fatalf("invalid GitHub source fixture: %#v", snapshot)
	}
	return snapshot
}

func githubTeamAWSConnection(
	execution teamexecution.ExecutionV1,
) cloudapp.Connection {
	return cloudapp.Connection{
		ConnectionID: execution.ProviderScope.ConnectionID,
		OwnerID:      execution.OwnerID,
		AccountID:    execution.ProviderScope.AccountID,
		Region:       execution.Region,
		Status:       "active",
		Revision: int64(
			execution.ProviderScope.ConnectionRevision,
		),
	}
}

func githubTeamIntentFixture(
	t *testing.T,
	execution teamexecution.ExecutionV1,
	executionDigest string,
	role teamexecution.RoleV1,
) teamdispatch.IntentV1 {
	t.Helper()
	roleDigest, err := role.Digest()
	if err != nil {
		t.Fatal(err)
	}
	intent := teamdispatch.IntentV1{
		SchemaVersion:             teamdispatch.SchemaV1,
		OperationID:               uuid.NewString(),
		AgentInstanceID:           uuid.NewString(),
		OwnerID:                   execution.OwnerID,
		ExecutionID:               execution.ExecutionID,
		ExecutionDigest:           executionDigest,
		PlanID:                    execution.PlanID,
		PlanRevision:              execution.PlanRevision,
		PlanDigest:                execution.PlanDigest,
		ApprovalID:                execution.ApprovalID,
		LaunchAuthorizationID:     uuid.NewString(),
		LaunchAuthorizationDigest: githubTeamDigest("7"),
		RoleID:                    role.RoleID,
		RoleDigest:                roleDigest,
		TaskID:                    execution.TaskID,
		TaskStepID:                role.TaskStepID,
		DeploymentID:              role.DeploymentID,
		ExpectedWorkerID:          role.ExpectedWorkerID,
		ModelCredentialRef:        "secret_ref:models/openai-code",
		MaximumApprovedCostMicros: execution.MaximumCostMicros,
		LaunchNotAfter: execution.AuthorizedAt.
			Add(time.Hour).
			UTC(),
	}
	if intent.Validate() != nil {
		t.Fatalf("invalid Team intent fixture: %#v", intent)
	}
	return intent
}

func githubTeamMaterializationFixture(
	t *testing.T,
	execution teamexecution.ExecutionV1,
	executionDigest string,
	role teamexecution.RoleV1,
	workspace teaminput.WorkspaceSnapshot,
) teaminput.MaterializationV1 {
	t.Helper()
	contextSnapshotID, err := teaminput.ContextSnapshotID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := teaminput.Compile(teaminput.CompileRequest{
		Execution:       execution,
		ExecutionDigest: executionDigest,
		RoleID:          role.RoleID,
		Context: teaminput.ContextInput{
			SnapshotID:  contextSnapshotID,
			GoalDigest:  execution.GoalDigest,
			GoalSummary: "Implement the approved repository change.",
			Constraints: []string{"Use only approved source."},
		},
		Workspace: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Destroy()
	inputID, err := teaminput.InputID(
		execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	roleDigest, err := role.Digest()
	if err != nil {
		t.Fatal(err)
	}
	materialization := teaminput.MaterializationV1{
		SchemaVersion:         teaminput.MaterializationSchemaV1,
		InputID:               inputID,
		OwnerID:               execution.OwnerID,
		ExecutionID:           execution.ExecutionID,
		ExecutionDigest:       executionDigest,
		RoleID:                role.RoleID,
		RoleDigest:            roleDigest,
		TaskID:                execution.TaskID,
		TaskStepID:            role.TaskStepID,
		DeploymentID:          role.DeploymentID,
		ExpectedWorkerID:      role.ExpectedWorkerID,
		ContextSnapshotID:     compiled.Manifest.ContextSnapshotID,
		ContextDigest:         compiled.Manifest.ContextDigest,
		WorkspaceSnapshotID:   workspace.SnapshotID,
		WorkspaceDigest:       workspace.Digest,
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
	if materialization.Validate() != nil {
		t.Fatalf(
			"invalid Team materialization fixture: %#v",
			materialization,
		)
	}
	return materialization
}

func githubTeamDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func githubTeamBytesDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
