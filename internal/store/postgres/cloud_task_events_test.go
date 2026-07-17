package postgres

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestCloudTaskSummaryV1IsClosedAndDeSecreted(t *testing.T) {
	t.Parallel()
	taskID, stepID, planID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	updatedAt := time.Date(2026, time.July, 17, 9, 0, 0, 123456789, time.FixedZone("not-utc", 8*60*60))
	projection := cloudDialogueProjection{OwnerID: "project-owner", ConnectionID: uuid.NewString(), PlanID: planID}
	taskSummary := newCloudTaskSummary(task.Task{
		TaskID: taskID, OwnerID: projection.OwnerID, ExecutionStatus: task.ExecutionFinished,
		OutcomeStatus: task.OutcomeSucceeded, Revision: 7, UpdatedAt: updatedAt,
	}, projection, cloudStageReadyForConfirmation)
	stepSummary := newCloudStepSummary(task.Step{
		TaskID: taskID, StepID: stepID, ExecutionStatus: task.ExecutionFinished,
		OutcomeStatus: task.OutcomeFailed, Revision: 3, UpdatedAt: updatedAt,
	}, projection, cloudStageQuote)

	assertCloudTaskSummaryJSON(t, taskSummary, []string{
		"schema_version", "task_id", "owner_id", "execution_status", "outcome_status", "current_stage",
		"related_plan_id", "revision", "updated_at",
	})
	assertCloudTaskSummaryJSON(t, stepSummary, []string{
		"schema_version", "task_id", "step_id", "owner_id", "execution_status", "outcome_status", "current_stage",
		"related_plan_id", "error_code", "revision", "updated_at",
	})
	if !taskSummary.UpdatedAt.Equal(updatedAt.UTC()) || !stepSummary.UpdatedAt.Equal(updatedAt.UTC()) {
		t.Fatal("Cloud Task summary did not canonicalize timestamp to UTC")
	}
	if stepSummary.ErrorCode != "task_failed" {
		t.Fatalf("failed Step error code=%q", stepSummary.ErrorCode)
	}
}

func TestCloudTaskProjectionUsesFixedStageAndErrorVocabulary(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		cloudskill.StepResearchOfficialSources:   cloudStageResearch,
		cloudskill.StepDraftRecipe:               cloudStageRecipe,
		cloudskill.StepPrepareResourceCandidates: cloudStageQuote,
	} {
		if got, ok := cloudStageForStepName(name); !ok || got != want {
			t.Fatalf("stage %q = %q/%t, want %q/true", name, got, ok, want)
		}
	}
	if _, ok := cloudStageForStepName("worker-controlled stage"); ok {
		t.Fatal("untrusted Step name became a public Cloud stage")
	}
	for outcome, want := range map[task.OutcomeStatus]string{
		task.OutcomeFailed:      "task_failed",
		task.OutcomeCanceled:    "task_canceled",
		task.OutcomeTimedOut:    "task_timed_out",
		task.OutcomeInterrupted: "task_interrupted",
	} {
		if got := cloudTaskErrorCode(outcome); got != want {
			t.Fatalf("outcome %q error code=%q want %q", outcome, got, want)
		}
	}
	if got := cloudTaskErrorCode(task.OutcomeSucceeded); got != "" {
		t.Fatalf("successful outcome error code=%q", got)
	}
}

func assertCloudTaskSummaryJSON(t *testing.T, summary cloudTaskSummaryV1, wantKeys []string) {
	t.Helper()
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	slices.Sort(wantKeys)
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("Cloud Task summary keys=%v want %v encoded=%s", keys, wantKeys, encoded)
	}
}
