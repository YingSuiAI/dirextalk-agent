package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestCloudWorkerContinuationTellsCentralApprovalWasCompleted(t *testing.T) {
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{"objective":"write answer.txt","workspace_mode":"none"}`}
	message := core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "I prepared a priced plan and am waiting for approval.", ToolCalls: []core.ToolCall{call}, CreatedAt: time.Now().UTC(), ModelProfileID: uuid.NewString()}
	envelope, err := newDurableTurnDispatchEnvelope(core.ModelRunResult{Message: message, ToolCalls: []core.ToolCall{call}})
	if err != nil {
		t.Fatal(err)
	}
	dispatchRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	plan := cloudworker.Plan{TaskID: uuid.NewString(), PlanID: uuid.NewString()}
	execution := cloudworker.Execution{ExecutionID: uuid.NewString()}
	_, result, err := cloudWorkerContinuation(dispatchRaw, plan, execution, cloudworker.StateSucceeded, "answer.txt contains 42", &cloudworker.ProviderResult{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var payload cloudWorkerContinuationPayload
	if err = json.Unmarshal([]byte(result.Content), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.UserApprovalCompleted || !strings.Contains(payload.CentralInstruction, "approval was completed") ||
		!strings.Contains(payload.CentralInstruction, "do not claim") ||
		!strings.Contains(payload.CentralInstruction, "language of the user's current request") ||
		!strings.Contains(payload.CentralInstruction, "audit every explicit requirement") ||
		!strings.Contains(payload.CentralInstruction, "Treat the Worker report as a claim, not proof") ||
		!strings.Contains(payload.CentralInstruction, "missing, renamed, unsupported, or unverified requirements") {
		t.Fatalf("Central approval authority missing: %+v", payload)
	}
}
