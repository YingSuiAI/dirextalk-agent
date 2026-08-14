package postgres

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

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
