package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestSSHWorkerStoreLoadsConfirmedTurnSnapshotAndAtomicallyResumesConversation(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	if _, err := h.confirmation.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: offer.Confirmation.Revision, At: h.now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	task, _, err := h.tasks.ClaimNextDue(h.ctx, uuid.NewString(), h.now.Add(2*time.Second), 30*time.Minute, 4)
	if err != nil || task.ID != offer.Task.ID {
		t.Fatalf("claim task=%+v err=%v", task, err)
	}
	store, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.Begin(h.ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	if run.Plan.Objective != h.command.Objective || run.Plan.AWS != offer.Plan.AWS ||
		run.Plan.Compute != offer.Plan.Compute || run.ModelSnapshot.APIKey != "test" ||
		run.ModelSnapshot.Digest() != h.lease.Turn.ProfileSnapshot.Digest() ||
		!strings.HasPrefix(run.ConfirmationProof, offer.Confirmation.ConfirmationID+":") {
		t.Fatalf("run lost immutable authority: %+v snapshot=%s", run, run.ModelSnapshot)
	}
	artifactID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	artifact := sshflow.Artifact{ArtifactID: artifactID, ExecutionID: offer.Execution.ExecutionID,
		Kind: "file", Name: "report.html", MediaType: "text/html",
		RelativePath: "cloud-worker/artifacts/" + offer.Execution.ExecutionID + "/report.html",
		SizeBytes:    21, SHA256: digest}
	if err = store.Complete(h.ctx, run, sshflow.Result{Summary: "remote deployment finished",
		WorkerID: "i-0123456789abcdef0", Artifacts: []sshflow.Artifact{artifact}}); err != nil {
		t.Fatal(err)
	}
	terminalTask, err := h.tasks.GetTask(h.ctx, task.ID)
	if err != nil || terminalTask.Status != coretask.StatusSucceeded || terminalTask.Result == nil ||
		len(terminalTask.Result.Files) != 1 || terminalTask.Result.Files[0].Path != artifact.RelativePath {
		t.Fatalf("task=%+v err=%v", terminalTask, err)
	}
	turn, err := h.conversation.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil || turn.State != core.TurnAccepted || turn.DispatchState != "" {
		t.Fatalf("turn=%+v err=%v", turn, err)
	}
	events, err := h.conversation.LoadTurnEvents(h.ctx, offer.Plan.TurnID, 0, 20)
	if err != nil || len(events) < 4 || events[len(events)-2].Kind != core.TurnEventToolCall ||
		events[len(events)-1].Kind != core.TurnEventToolResult || events[len(events)-1].ToolResult == nil ||
		!strings.Contains(events[len(events)-1].ToolResult.Content, `"persistent_worker":true`) {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	var completion struct {
		WorkerID         string `json:"worker_id"`
		PersistentWorker bool   `json:"persistent_worker"`
		NextAction       struct {
			Kind      string `json:"kind"`
			Operation string `json:"operation"`
			WorkerID  string `json:"worker_id"`
			Default   string `json:"default"`
			Question  string `json:"question"`
		} `json:"next_action"`
	}
	if err = json.Unmarshal([]byte(events[len(events)-1].ToolResult.Content), &completion); err != nil ||
		completion.WorkerID != "i-0123456789abcdef0" || !completion.PersistentWorker ||
		completion.NextAction.Kind != "confirm_destroy_worker" || completion.NextAction.Operation != "destroy_worker" ||
		completion.NextAction.WorkerID != completion.WorkerID || completion.NextAction.Default != "retain" ||
		!strings.Contains(completion.NextAction.Question, "whether to destroy") {
		t.Fatalf("completion=%+v err=%v", completion, err)
	}
	var relativePath, executionID, workerState string
	if err = h.store.pool.QueryRow(h.ctx, `SELECT payload_json->>'relative_path',payload_json->>'execution_id'
		FROM core_execution_v2_records WHERE owner_id=$1 AND resource_type='artifact' AND resource_id=$2`,
		h.owner, artifactID).Scan(&relativePath, &executionID); err != nil {
		t.Fatal(err)
	}
	if err = h.store.pool.QueryRow(h.ctx, `SELECT execution_json->>'state' FROM core_cloud_worker_executions WHERE execution_id=$1`,
		offer.Execution.ExecutionID).Scan(&workerState); err != nil {
		t.Fatal(err)
	}
	if relativePath != artifact.RelativePath || executionID != offer.Execution.ExecutionID ||
		workerState != string(cloudworker.StateSucceeded) {
		t.Fatalf("artifact path=%q execution=%q state=%q", relativePath, executionID, workerState)
	}
}

func TestSSHWorkerContinuationPersistsRetainedWorkerNextAction(t *testing.T) {
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	plan := cloudworker.Plan{TaskID: uuid.NewString(), PlanID: uuid.NewString(), ExecutionID: uuid.NewString()}
	_, result, err := sshWorkerContinuation(
		&core.ModelRunResult{ToolCalls: []core.ToolCall{call}},
		plan,
		cloudworker.StateSucceeded,
		"deployment complete",
		sshflow.Result{WorkerID: "worker-one"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var completion struct {
		WorkerID         string `json:"worker_id"`
		PersistentWorker bool   `json:"persistent_worker"`
		NextAction       struct {
			Kind      string `json:"kind"`
			Operation string `json:"operation"`
			WorkerID  string `json:"worker_id"`
			Default   string `json:"default"`
			Question  string `json:"question"`
		} `json:"next_action"`
	}
	if err = json.Unmarshal([]byte(result.Content), &completion); err != nil ||
		completion.WorkerID != "worker-one" || !completion.PersistentWorker ||
		completion.NextAction.Kind != "confirm_destroy_worker" || completion.NextAction.Operation != "destroy_worker" ||
		completion.NextAction.WorkerID != completion.WorkerID || completion.NextAction.Default != "retain" ||
		!strings.Contains(completion.NextAction.Question, "whether to destroy") {
		t.Fatalf("completion=%+v err=%v", completion, err)
	}
}
