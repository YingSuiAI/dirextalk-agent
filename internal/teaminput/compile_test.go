package teaminput

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestCompileBuildsDeterministicSecretFreeRuntimeInput(t *testing.T) {
	t.Parallel()
	execution, executionDigest := teamInputExecutionFixture(t)
	request := teamInputCompileRequest(execution, executionDigest)
	first, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if !bytes.Equal(first.ContextBytes, second.ContextBytes) ||
		!bytes.Equal(first.ManifestBytes, second.ManifestBytes) ||
		!bytes.Equal(first.ExecutionBytes, second.ExecutionBytes) ||
		first.ManifestDigest != second.ManifestDigest ||
		first.ExecutionBundleDigest != second.ExecutionBundleDigest {
		t.Fatal("Team Worker input compilation was not deterministic")
	}
	role := execution.Roles[1]
	if first.Manifest.ExecutionID != execution.ExecutionID ||
		first.Manifest.RoleID != role.RoleID ||
		first.Manifest.DeploymentID != role.DeploymentID ||
		first.Manifest.ExpectedWorkerID != role.ExpectedWorkerID ||
		first.RuntimeTask.TaskID != execution.TaskID ||
		first.RuntimeTask.Adapter != workerruntime.AdapterCodexV1 ||
		first.RuntimeTask.WorkspaceMode != workerruntime.WorkspaceReadOnly ||
		first.RuntimeTask.IncludePatch ||
		first.RuntimeTask.ContextDigest != first.Manifest.ContextDigest ||
		first.RuntimeTask.MaxOutputTokens != role.Tokens.OutputMaximum ||
		first.CredentialGrant.CredentialSlot != role.ModelCredentialSlot ||
		first.CredentialGrant.MaximumInputTokens !=
			role.Tokens.InputMaximum ||
		first.CredentialGrant.MaximumOutputTokens !=
			role.Tokens.OutputMaximum {
		t.Fatalf("compiled Team Worker input = %#v", first)
	}
	var bundle workerrunner.ExecutionBundleV1
	if err := json.Unmarshal(first.ExecutionBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion != 1 ||
		bundle.RecipeSHA256 !=
			strings.TrimPrefix(first.ManifestDigest, "sha256:") ||
		len(bundle.Actions) != 2 ||
		bundle.Actions[0].Kind !=
			workerrunner.InputMaterializeActionKind ||
		bundle.Actions[0].Input == nil ||
		bundle.Actions[0].Input.Context != first.ContextObject ||
		bundle.Actions[0].Input.Workspace == nil ||
		*bundle.Actions[0].Input.Workspace != first.WorkspaceObject ||
		bundle.Actions[1].Kind !=
			workerrunner.RuntimeExecuteActionKind ||
		bundle.Actions[1].Runtime == nil ||
		bundle.Actions[1].Runtime.Task != first.RuntimeTask {
		t.Fatalf("execution bundle = %#v", bundle)
	}
	all := string(first.ContextBytes) +
		string(first.ManifestBytes) +
		string(first.ExecutionBytes)
	for _, forbidden := range []string{
		"secret_ref:",
		"api_key",
		"aws_secret_access_key",
		"model/primary",
	} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("compiled input leaked %q: %s", forbidden, all)
		}
	}
	if first.ContextTargetPath !=
		workerruntime.DefaultContextRoot+"/"+
			strings.TrimPrefix(first.Manifest.ContextDigest, "sha256:")+
			".json" ||
		first.WorkspaceTargetPath !=
			workerruntime.DefaultWorkspaceRoot+"/"+
				strings.TrimPrefix(
					request.Workspace.Digest,
					"sha256:",
				) ||
		first.CredentialTargetPath !=
			workerruntime.DefaultCredentialRoot+"/"+
				role.ModelCredentialSlot {
		t.Fatalf(
			"fixed Worker targets = %q %q %q",
			first.ContextTargetPath,
			first.WorkspaceTargetPath,
			first.CredentialTargetPath,
		)
	}
}

func TestCompileCarriesQualifiedPiAdapterIntoRuntimeTask(t *testing.T) {
	t.Parallel()
	execution, _ := teamInputExecutionFixture(t)
	role := &execution.Roles[1]
	role.RuntimeFamily = teamplan.RuntimePi
	role.RuntimeVersion = "0.83.0"
	role.RuntimeAdapter = teamplan.AdapterPiV1
	role.RuntimeReleaseID = uuid.NewString()
	executionDigest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(
		teamInputCompileRequest(execution, executionDigest),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Destroy()
	if compiled.RuntimeTask.Adapter != workerruntime.AdapterPiV1 ||
		compiled.RuntimeTask.RuntimeVersion != "0.83.0" ||
		compiled.RuntimeTask.RuntimeReleaseID != role.RuntimeReleaseID {
		t.Fatalf("Pi runtime task = %#v", compiled.RuntimeTask)
	}
}

func TestCompileCanonicalizesTrustedContextOrdering(t *testing.T) {
	t.Parallel()
	execution, executionDigest := teamInputExecutionFixture(t)
	firstRequest := teamInputCompileRequest(execution, executionDigest)
	secondRequest := teamInputCompileRequest(execution, executionDigest)
	firstRequest.Context.Constraints = []string{
		"Run focused tests.",
		"Do not modify the main branch.",
	}
	secondRequest.Context.Constraints = []string{
		"Do not modify the main branch.",
		"Run focused tests.",
	}
	firstRequest.Context.Artifacts[0],
		firstRequest.Context.Artifacts[1] =
		firstRequest.Context.Artifacts[1],
		firstRequest.Context.Artifacts[0]
	first, err := Compile(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := Compile(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if !bytes.Equal(first.ContextBytes, second.ContextBytes) ||
		!bytes.Equal(first.ManifestBytes, second.ManifestBytes) ||
		!bytes.Equal(first.ExecutionBytes, second.ExecutionBytes) {
		t.Fatal("semantically identical context ordering changed bundle bytes")
	}
}

func TestCompileRejectsContextWorkspaceAndExecutionSubstitution(t *testing.T) {
	t.Parallel()
	execution, executionDigest := teamInputExecutionFixture(t)
	tests := []struct {
		name   string
		mutate func(*CompileRequest)
	}{
		{
			name: "execution digest",
			mutate: func(request *CompileRequest) {
				request.ExecutionDigest = testDigest("9")
			},
		},
		{
			name: "goal binding",
			mutate: func(request *CompileRequest) {
				request.Context.GoalDigest = testDigest("8")
			},
		},
		{
			name: "context snapshot identity",
			mutate: func(request *CompileRequest) {
				request.Context.SnapshotID = uuid.NewString()
			},
		},
		{
			name: "secret in summary",
			mutate: func(request *CompileRequest) {
				request.Context.GoalSummary =
					"Use api_key=abcdefghijk for the task."
			},
		},
		{
			name: "missing dependency",
			mutate: func(request *CompileRequest) {
				request.Context.Dependencies = nil
			},
		},
		{
			name: "dependency step substitution",
			mutate: func(request *CompileRequest) {
				request.Context.Dependencies[0].TaskStepID =
					uuid.NewString()
			},
		},
		{
			name: "workspace digest format",
			mutate: func(request *CompileRequest) {
				request.Workspace.Digest = "not-a-digest"
			},
		},
		{
			name: "workspace identity",
			mutate: func(request *CompileRequest) {
				request.Workspace.SnapshotID = "not-a-snapshot"
			},
		},
		{
			name: "role",
			mutate: func(request *CompileRequest) {
				request.RoleID = "not-approved"
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			request := teamInputCompileRequest(
				execution,
				executionDigest,
			)
			testCase.mutate(&request)
			compiled, err := Compile(request)
			compiled.Destroy()
			if err == nil {
				t.Fatal("substituted Team Worker input was accepted")
			}
		})
	}
}

func TestCompiledInputDestroyClearsTransientPayloads(t *testing.T) {
	t.Parallel()
	execution, executionDigest := teamInputExecutionFixture(t)
	compiled, err := Compile(
		teamInputCompileRequest(execution, executionDigest),
	)
	if err != nil {
		t.Fatal(err)
	}
	contextBytes := compiled.ContextBytes
	manifestBytes := compiled.ManifestBytes
	executionBytes := compiled.ExecutionBytes
	compiled.Destroy()
	if !reflect.DeepEqual(compiled, CompiledInput{}) {
		t.Fatalf("destroyed compiled input = %#v", compiled)
	}
	for _, payload := range [][]byte{
		contextBytes,
		manifestBytes,
		executionBytes,
	} {
		for _, value := range payload {
			if value != 0 {
				t.Fatal("transient Team Worker payload was not cleared")
			}
		}
	}
}

func teamInputCompileRequest(
	execution teamexecution.ExecutionV1,
	executionDigest string,
) CompileRequest {
	implement := execution.Roles[0]
	return CompileRequest{
		Execution:       execution,
		ExecutionDigest: executionDigest,
		RoleID:          execution.Roles[1].RoleID,
		Context: ContextInput{
			SnapshotID: mustContextSnapshotID(
				execution.ExecutionID,
				execution.Roles[1].RoleID,
			),
			GoalDigest: execution.GoalDigest,
			GoalSummary: "Implement and independently review the approved " +
				"change.",
			Constraints: []string{
				"Do not modify the main branch.",
				"Run focused tests.",
			},
			Dependencies: []DependencyResultV1{{
				RoleID:       implement.RoleID,
				TaskStepID:   implement.TaskStepID,
				ResultDigest: testDigest("6"),
				Summary:      "The implementation patch and tests are ready.",
			}},
			Artifacts: []ArtifactRefV1{
				{
					ArtifactID: uuid.NewSHA1(
						uuid.MustParse(execution.ExecutionID),
						[]byte("artifact:requirements"),
					).String(),
					Digest:    testDigest("4"),
					MediaType: "application/json",
					Purpose:   "Approved requirements snapshot.",
				},
				{
					ArtifactID: uuid.NewSHA1(
						uuid.MustParse(execution.ExecutionID),
						[]byte("artifact:patch"),
					).String(),
					Digest:    testDigest("5"),
					MediaType: "application/x-tar",
					Purpose:   "Dependency workspace snapshot.",
				},
			},
		},
		Workspace: WorkspaceSnapshot{
			SnapshotID: mustWorkspaceSnapshotID(
				execution.ExecutionID,
				execution.Roles[1].RoleID,
			),
			Digest:    testDigest("3"),
			SizeBytes: 10 << 20,
		},
	}
}

func teamInputExecutionFixture(
	t *testing.T,
) (teamexecution.ExecutionV1, string) {
	t.Helper()
	executionID := uuid.NewString()
	taskID := uuid.NewString()
	roles := []teamexecution.RoleV1{
		teamInputRoleFixture(
			t,
			executionID,
			taskID,
			"implement",
			nil,
			teamplan.WorkspaceIsolated,
		),
		teamInputRoleFixture(
			t,
			executionID,
			taskID,
			"review",
			[]string{"implement"},
			teamplan.WorkspaceReadOnly,
		),
	}
	execution := teamexecution.ExecutionV1{
		SchemaVersion:       teamexecution.SchemaV1,
		ExecutionID:         executionID,
		OwnerID:             "owner-a",
		TaskID:              taskID,
		PlanID:              uuid.NewString(),
		PlanRevision:        1,
		PlanDigest:          testDigest("a"),
		ApprovalID:          uuid.NewString(),
		ApprovalSignerKeyID: "device-a",
		GoalDigest:          testDigest("b"),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       uuid.NewString(),
			ConnectionRevision: 1,
			AccountID:          "123456789012",
		},
		Region:                "us-east-2",
		CatalogRevision:       testDigest("c"),
		PolicyRevision:        testDigest("d"),
		PricingSnapshotID:     uuid.NewString(),
		PricingSnapshotDigest: testDigest("e"),
		WorkerCount:           2,
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
			8,
			0,
			0,
			0,
			time.UTC,
		),
		Roles: roles,
	}
	if err := execution.Validate(); err != nil {
		t.Fatalf("invalid Team Execution fixture: %v", err)
	}
	digest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return execution, digest
}

func teamInputRoleFixture(
	t *testing.T,
	executionID,
	taskID,
	roleID string,
	dependencies []string,
	workspace teamplan.WorkspaceMode,
) teamexecution.RoleV1 {
	t.Helper()
	executionUUID := uuid.MustParse(executionID)
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
	workClass := teamplan.WorkSoftwareImplementation
	capability := teamplan.CapabilityGit
	objective := "Implement the approved change in an isolated workspace."
	if roleID == "review" {
		workClass = teamplan.WorkSoftwareReview
		capability = teamplan.CapabilityCodeReview
		objective = "Review the approved implementation and produce findings."
	}
	return teamexecution.RoleV1{
		RoleID:               roleID,
		Title:                strings.ToUpper(roleID[:1]) + roleID[1:],
		Objective:            objective,
		WorkClass:            workClass,
		RequiredCapabilities: []teamplan.Capability{capability},
		Workspace:            workspace,
		DependsOnRoleIDs:     append([]string(nil), dependencies...),
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
		RuntimeImageDigest: testDigest("1"),
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

func testDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func mustWorkspaceSnapshotID(executionID, roleID string) string {
	value, err := WorkspaceSnapshotID(executionID, roleID)
	if err != nil {
		panic(err)
	}
	return value
}

func mustContextSnapshotID(executionID, roleID string) string {
	value, err := ContextSnapshotID(executionID, roleID)
	if err != nil {
		panic(err)
	}
	return value
}
