package workerrunner

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

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestRuntimeExecuteActionUsesClosedAdapterRegistry(t *testing.T) {
	t.Parallel()
	executor := &runnerRuntimeExecutor{result: workerruntime.Result{
		Usage: workerruntime.Usage{InputTokens: 20, OutputTokens: 10},
		Artifacts: []workerruntime.Artifact{{
			Name: "final.json", MediaType: "application/json",
			Content: []byte(`{"status":"completed"}`),
		}},
	}}
	runtimes, err := workerruntime.NewRegistry(executor)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRuntimeExecuteAction(runtimes)
	if err != nil {
		t.Fatal(err)
	}
	action := ActionV1{
		ID: "implement", Kind: RuntimeExecuteActionKind,
		TimeoutSeconds: 60,
		Runtime:        &RuntimeExecuteInputV1{Task: validRuntimeTask()},
	}
	result, err := handler.Execute(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyActionResult(&result)
	if result.Status != "succeeded" || result.Runtime == nil ||
		len(result.Runtime.Artifacts) != 1 {
		t.Fatalf("runtime result = %+v", result)
	}
	action.Noop = &NoopInputV1{}
	if !errors.Is(handler.Validate(action), ErrInvalidBundle) {
		t.Fatal("runtime action with a second input type was accepted")
	}
}

func TestRunnerUploadsRuntimeArtifactsAndReturnsManifest(t *testing.T) {
	t.Parallel()
	execution := validRuntimeBundle(t)
	runner, config, control, objects := runnerFixture(t, execution)
	control.assignment.TaskId = validRuntimeTask().TaskID
	executor := &runnerRuntimeExecutor{result: workerruntime.Result{
		Usage: workerruntime.Usage{
			InputTokens: 100, CachedInputTokens: 20,
			OutputTokens: 40, ReasoningOutputTokens: 10,
		},
		Artifacts: []workerruntime.Artifact{{
			Name: "final.json", MediaType: "application/json",
			Content: []byte(`{"status":"completed","summary":"done"}`),
		}},
	}}
	runtimes, err := workerruntime.NewRegistry(executor)
	if err != nil {
		t.Fatal(err)
	}
	runtimeAction, err := NewRuntimeExecuteAction(runtimes)
	if err != nil {
		t.Fatal(err)
	}
	runner.Registry, err = NewRegistry(runtimeAction)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if result.ResultRef == "" ||
		strings.Join(result.CompletedActions, ",") != "implement" {
		t.Fatalf("runner result = %+v", result)
	}

	objects.mu.Lock()
	defer objects.mu.Unlock()
	finalRaw := objects.objects[result.ResultRef]
	var final ResultManifestV2
	if json.Unmarshal(finalRaw, &final) != nil ||
		final.SchemaVersion != ResultManifestSchemaV2 ||
		len(final.RuntimeResults) != 1 ||
		len(final.RuntimeResults[0].Artifacts) != 1 {
		t.Fatalf("final runtime manifest = %s", finalRaw)
	}
	artifact := final.RuntimeResults[0].Artifacts[0]
	if !strings.HasPrefix(
		artifact.Ref,
		"s3://worker-bucket/deployments/test/artifacts/runtime-a1-e9-implement-",
	) || string(objects.objects[artifact.Ref]) !=
		`{"status":"completed","summary":"done"}` {
		t.Fatalf("runtime artifact claim = %+v", artifact)
	}

	withoutFinal := final
	withoutFinal.RuntimeResults = append(
		[]RuntimeActionResultV1(nil), final.RuntimeResults...,
	)
	withoutFinal.RuntimeResults[0].Artifacts = append(
		[]RuntimeArtifactClaimV1(nil),
		final.RuntimeResults[0].Artifacts...,
	)
	claim := &withoutFinal.RuntimeResults[0].Artifacts[0]
	digest, err := parseRuntimeDigest(claim.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	claim.Name = "report.json"
	claim.Ref, err = scopedRuntimeArtifactRef(
		control.assignment.GetAccess(), claim.Attempt,
		claim.LeaseEpoch, "implement", claim.Name,
		claim.MediaType, digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutFinal.Validate(
		resultExpectationFromAssignment(control.assignment),
	); !errors.Is(err, ErrInvalidBundle) {
		t.Fatal("runtime manifest without final.json was accepted")
	}

	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.checkpoints) != 1 {
		t.Fatalf("checkpoints = %v", control.checkpoints)
	}
	var checkpoint checkpointV1
	if json.Unmarshal(objects.objects[control.checkpoints[0]], &checkpoint) != nil ||
		checkpoint.SchemaVersion != checkpointSchemaV2 ||
		len(checkpoint.RuntimeResults) != 1 ||
		checkpoint.RuntimeResults[0].Artifacts[0].Ref != artifact.Ref {
		t.Fatalf("runtime checkpoint = %+v", checkpoint)
	}
}

func TestRunnerRejectsRuntimeTaskMismatchBeforeAdapterExecution(t *testing.T) {
	t.Parallel()
	runner, config, control, _ := runnerFixture(t, validRuntimeBundle(t))
	executor := &runnerRuntimeExecutor{result: workerruntime.Result{
		Artifacts: []workerruntime.Artifact{{
			Name: "final.json", MediaType: "application/json",
			Content: []byte(`{"status":"completed"}`),
		}},
	}}
	runtimes, err := workerruntime.NewRegistry(executor)
	if err != nil {
		t.Fatal(err)
	}
	runtimeAction, err := NewRuntimeExecuteAction(runtimes)
	if err != nil {
		t.Fatal(err)
	}
	runner.Registry, err = NewRegistry(runtimeAction)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), config)
	if !errors.Is(err, ErrInvalidBundle) ||
		result.Outcome != agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED {
		t.Fatalf("mismatched runtime task result=%+v error=%v", result, err)
	}
	if executor.calls != 0 {
		t.Fatal("runtime adapter ran for a mismatched Task")
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.completion == nil ||
		control.completion.GetOutcome() !=
			agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED {
		t.Fatalf("completion = %+v", control.completion)
	}
}

func TestExecutionBundleRejectsTooManyRuntimeActions(t *testing.T) {
	t.Parallel()
	recipeDigest := sha256.Sum256(
		[]byte(`{"schema_version":1,"kind":"test-recipe"}`),
	)
	actions := make([]ActionV1, MaxRuntimeResultsPerManifest+1)
	for index := range actions {
		task := validRuntimeTask()
		task.RoleID = fmt.Sprintf("role-%d", index)
		actions[index] = ActionV1{
			ID:   fmt.Sprintf("runtime-%d", index),
			Kind: RuntimeExecuteActionKind, TimeoutSeconds: 2,
			Runtime: &RuntimeExecuteInputV1{Task: task},
		}
	}
	raw, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: executionBundleSchemaV1,
		RecipeSHA256:  hex.EncodeToString(recipeDigest[:]),
		Actions:       actions,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseExecutionBundle(
		raw, recipeDigest[:], 10*time.Second,
	); !errors.Is(err, ErrInvalidBundle) {
		t.Fatal("execution bundle exceeded runtime result capacity")
	}
}

func TestActionResultStatusIsBoundToActionKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		action ActionV1
		status string
		valid  bool
	}{
		{
			action: ActionV1{Runtime: &RuntimeExecuteInputV1{}},
			status: "succeeded", valid: true,
		},
		{
			action: ActionV1{Input: &InputMaterializeInputV1{}},
			status: "materialized", valid: true,
		},
		{
			action: ActionV1{Installer: &InstallerExecuteInputV1{}},
			status: installer.StatusExecuted, valid: true,
		},
		{
			action: ActionV1{Noop: &NoopInputV1{}},
			status: "ok", valid: true,
		},
		{
			action: ActionV1{Runtime: &RuntimeExecuteInputV1{}},
			status: "ok",
		},
	}
	for _, test := range tests {
		if got := validActionResultStatus(
			test.action, test.status,
		); got != test.valid {
			t.Fatalf(
				"status %q valid=%v want=%v",
				test.status, got, test.valid,
			)
		}
	}
}

func validRuntimeBundle(t *testing.T) []byte {
	t.Helper()
	recipeDigest := sha256.Sum256(
		[]byte(`{"schema_version":1,"kind":"test-recipe"}`),
	)
	encoded, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1,
		RecipeSHA256:  hex.EncodeToString(recipeDigest[:]),
		Actions: []ActionV1{{
			ID: "implement", Kind: RuntimeExecuteActionKind,
			TimeoutSeconds: 2,
			Runtime:        &RuntimeExecuteInputV1{Task: validRuntimeTask()},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validRuntimeTask() workerruntime.TaskV1 {
	return workerruntime.TaskV1{
		SchemaVersion:    workerruntime.TaskSchemaV1,
		TaskID:           "11111111-1111-4111-8111-111111111111",
		RoleID:           "implement-api",
		Adapter:          workerruntime.AdapterCodexV1,
		RuntimeReleaseID: "22222222-2222-4222-8222-222222222222",
		RuntimeVersion:   "0.144.1",
		RuntimeImageDigest: "sha256:" +
			string(bytes.Repeat([]byte{'a'}, 64)),
		ContextDigest: "sha256:" +
			string(bytes.Repeat([]byte{'b'}, 64)),
		WorkspaceMode: workerruntime.WorkspaceIsolated,
		WorkspaceDigest: "sha256:" +
			string(bytes.Repeat([]byte{'c'}, 64)),
		Objective:      "Implement the approved API change and run tests.",
		ModelProfileID: "openai-codex",
		ModelProvider:  "openai",
		Model:          "gpt-5.3-codex",
		ModelInterface: workerruntime.ModelOpenAIResponses,
		CredentialSlot: "model-token",
		IncludePatch:   true,
	}
}

type runnerRuntimeExecutor struct {
	result workerruntime.Result
	err    error
	calls  int
}

func (*runnerRuntimeExecutor) Adapter() workerruntime.Adapter {
	return workerruntime.AdapterCodexV1
}

func (*runnerRuntimeExecutor) ValidateTask(
	task workerruntime.TaskV1,
) error {
	if task.Adapter != workerruntime.AdapterCodexV1 {
		return workerruntime.ErrUnsupported
	}
	return task.Validate()
}

func (executor *runnerRuntimeExecutor) Execute(
	context.Context,
	workerruntime.TaskV1,
) (workerruntime.Result, error) {
	executor.calls++
	result := executor.result
	result.Artifacts = make(
		[]workerruntime.Artifact,
		len(executor.result.Artifacts),
	)
	for index, artifact := range executor.result.Artifacts {
		result.Artifacts[index] = artifact
		result.Artifacts[index].Content = bytes.Clone(artifact.Content)
	}
	return result, executor.err
}
