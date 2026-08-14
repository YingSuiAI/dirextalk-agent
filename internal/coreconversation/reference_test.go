package coreconversation

import (
	"strings"
	"testing"
)

func TestReferenceValidateKeepsGenericExecutionV2AndServiceBinding(t *testing.T) {
	digest := strings.Repeat("a", 64)
	planID := "11111111-1111-4111-8111-111111111111"
	runID := "22222222-2222-4222-8222-222222222222"
	stageID := "33333333-3333-4333-8333-333333333333"
	targetID := "44444444-4444-4444-8444-444444444444"
	confirmationID := "55555555-5555-4555-8555-555555555555"
	deploymentID := "77777777-7777-4777-8777-777777777777"
	projectID := "88888888-8888-4888-8888-888888888888"

	values := []Reference{
		{Kind: "execution_plan", PlanID: planID, PlanRevision: 4, PlanDigest: digest},
		{Kind: "execution_run", RunID: runID, RunRevision: 2, RunDigest: digest, PlanID: planID, PlanRevision: 4, PlanDigest: digest, DeploymentID: deploymentID, Status: "waiting_user"},
		{Kind: "execution_confirmation", ConfirmationID: confirmationID, PlanID: planID, PlanRevision: 4, PlanDigest: digest, RunID: runID, RunRevision: 2, RunDigest: digest, StageID: stageID, StageRevision: 1, StageDigest: digest, TargetID: targetID, TargetRevision: 3, TargetDigest: digest},
		{Kind: "execution_confirmation", ConfirmationID: confirmationID, ConfirmationRevision: 1, BindingDigest: digest, PlanID: planID, PlanRevision: 4, PlanDigest: digest, RunID: runID, RunRevision: 2, StageID: stageID, StageRevision: 1, StageDigest: digest, TargetID: targetID, TargetRevision: 3, TargetDigest: digest, PreviewDigest: digest, State: "pending", RiskLevel: "high", GateType: "owner_confirmation"},
		{Kind: "service_binding", BindingID: "66666666-6666-4666-8666-666666666666", BindingRevision: 2, BindingDigest: digest, DeploymentID: deploymentID, ProjectID: projectID, RunID: runID, TargetID: targetID, TargetRevision: 3, TargetDigest: digest},
	}
	for _, value := range values {
		if err := value.Validate(); err != nil {
			t.Fatalf("reference %s rejected: %#v: %v", value.Kind, value, err)
		}
	}
}

func TestReferenceValidateCloudWorkerKindMatrix(t *testing.T) {
	base := Reference{TaskID: "99999999-9999-4999-8999-999999999999", AccountGeneration: 7,
		PlanID: "11111111-1111-4111-8111-111111111111", PlanRevision: 1}
	plan := base
	plan.Kind, plan.Status = "execution_plan", "waiting_user"
	run := base
	run.Kind, run.RunID, run.RunRevision = "execution_run", "22222222-2222-4222-8222-222222222222", 2
	run.ExecutionID, run.WorkerID, run.Status = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "queued"
	confirmation := base
	confirmation.Kind, confirmation.ConfirmationID = "execution_confirmation", "55555555-5555-4555-8555-555555555555"
	confirmation.ConfirmationRevision, confirmation.State = 1, "pending"
	for _, reference := range []Reference{plan, run, confirmation} {
		if err := reference.Validate(); err != nil {
			t.Fatalf("strict Cloud Worker %s reference rejected: %#v: %v", reference.Kind, reference, err)
		}
	}

	withGenericField := run
	withGenericField.DeploymentID = "77777777-7777-4777-8777-777777777777"
	if withGenericField.Validate() == nil {
		t.Fatal("Cloud Worker reference accepted a generic-only deployment_id")
	}
	missingTask := run
	missingTask.TaskID = ""
	if missingTask.Validate() == nil {
		t.Fatal("partial Cloud Worker reference fell through to generic validation")
	}
	withRetiredDigest := run
	withRetiredDigest.PlanDigest = strings.Repeat("b", 64)
	if withRetiredDigest.Validate() == nil {
		t.Fatal("Cloud Worker reference accepted a retired digest")
	}
	planWithRun := plan
	planWithRun.RunID = run.RunID
	if planWithRun.Validate() == nil {
		t.Fatal("Cloud Worker plan reference accepted a run field")
	}
	runWithConfirmation := run
	runWithConfirmation.ConfirmationID = confirmation.ConfirmationID
	if runWithConfirmation.Validate() == nil {
		t.Fatal("Cloud Worker run reference accepted a confirmation field")
	}
	confirmationWithExecution := confirmation
	confirmationWithExecution.ExecutionID = run.ExecutionID
	if confirmationWithExecution.Validate() == nil {
		t.Fatal("Cloud Worker confirmation reference accepted an execution field")
	}
}
