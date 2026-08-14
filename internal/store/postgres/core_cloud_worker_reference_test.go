package postgres

import (
	"reflect"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

func TestCloudWorkerReferencesUseKindSpecificFields(t *testing.T) {
	plan := cloudworker.Plan{
		AccountGeneration: 7,
		TaskID:            "11111111-1111-4111-8111-111111111111",
		PlanID:            "22222222-2222-4222-8222-222222222222",
		Revision:          3,
		Status:            "waiting_user",
		ConfirmationID:    "33333333-3333-4333-8333-333333333333",
	}
	execution := cloudworker.Execution{
		RunID:       "44444444-4444-4444-8444-444444444444",
		ExecutionID: "55555555-5555-4555-8555-555555555555",
		WorkerID:    "66666666-6666-4666-8666-666666666666",
		Revision:    4,
		State:       cloudworker.StateRunning,
	}
	common := core.Reference{AccountGeneration: 7, TaskID: plan.TaskID, PlanID: plan.PlanID, PlanRevision: 3}
	wantPlan := common
	wantPlan.Kind, wantPlan.Status = "execution_plan", "waiting_user"
	wantRun := common
	wantRun.Kind, wantRun.RunID, wantRun.RunRevision = "execution_run", execution.RunID, 4
	wantRun.ExecutionID, wantRun.WorkerID, wantRun.Status = execution.ExecutionID, execution.WorkerID, "running"
	wantConfirmation := common
	wantConfirmation.Kind, wantConfirmation.ConfirmationID = "execution_confirmation", plan.ConfirmationID
	wantConfirmation.ConfirmationRevision, wantConfirmation.State = 5, "confirmed"
	want := []core.Reference{wantPlan, wantRun, wantConfirmation}

	got := cloudWorkerReferences(plan, execution, 5, "confirmed")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Cloud Worker references\ngot:  %#v\nwant: %#v", got, want)
	}
	for _, reference := range got {
		if err := reference.Validate(); err != nil {
			t.Fatalf("generated %s reference rejected: %#v: %v", reference.Kind, reference, err)
		}
	}
}
