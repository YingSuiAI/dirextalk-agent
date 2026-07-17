package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	cloudTaskChangedEvent    = "cloud.task.changed"
	cloudStepChangedEvent    = "cloud.step.changed"
	cloudTaskSummarySchemaV1 = 1

	cloudStageResearch             = "research"
	cloudStageRecipe               = "recipe"
	cloudStageQuote                = "quote"
	cloudStageWaitingUser          = "waiting_user"
	cloudStageReadyForConfirmation = "ready_for_confirmation"
	cloudStageFinished             = "finished"
)

var errCloudTaskProjectionInvalid = errors.New("cloud task projection is invalid")

// cloudDialogueProjection is deliberately narrower than a generic planning
// session. Only the server-created cloud-goal-<request-id> session can emit
// public Cloud Task facts; an arbitrary Chat planning session remains private
// to the generic Agent event stream.
type cloudDialogueProjection struct {
	OwnerID      string
	ConnectionID string
	PlanID       string
}

// cloudTaskSummaryV1 is intentionally a closed schema. Keep cloud-provider,
// Worker, evidence, and chat fields out of this type so they cannot enter the
// Cloud projection by an incidental struct expansion.
type cloudTaskSummaryV1 struct {
	SchemaVersion   int                  `json:"schema_version"`
	TaskID          string               `json:"task_id"`
	StepID          string               `json:"step_id,omitempty"`
	OwnerID         string               `json:"owner_id"`
	ExecutionStatus task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
	CurrentStage    string               `json:"current_stage"`
	RelatedPlanID   string               `json:"related_plan_id,omitempty"`
	ErrorCode       string               `json:"error_code,omitempty"`
	Revision        int64                `json:"revision"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

func newCloudTaskSummary(item task.Task, projection cloudDialogueProjection, stage string) cloudTaskSummaryV1 {
	return cloudTaskSummaryV1{
		SchemaVersion: cloudTaskSummarySchemaV1, TaskID: item.TaskID, OwnerID: item.OwnerID,
		ExecutionStatus: item.ExecutionStatus, OutcomeStatus: item.OutcomeStatus, CurrentStage: stage,
		RelatedPlanID: projection.PlanID, ErrorCode: cloudTaskErrorCode(item.OutcomeStatus),
		Revision: item.Revision, UpdatedAt: item.UpdatedAt.UTC(),
	}
}

func newCloudStepSummary(step task.Step, projection cloudDialogueProjection, stage string) cloudTaskSummaryV1 {
	return cloudTaskSummaryV1{
		SchemaVersion: cloudTaskSummarySchemaV1, TaskID: step.TaskID, StepID: step.StepID, OwnerID: projection.OwnerID,
		ExecutionStatus: step.ExecutionStatus, OutcomeStatus: step.OutcomeStatus, CurrentStage: stage,
		RelatedPlanID: projection.PlanID, ErrorCode: cloudTaskErrorCode(step.OutcomeStatus),
		Revision: step.Revision, UpdatedAt: step.UpdatedAt.UTC(),
	}
}

// appendCloudTaskChangedIfDialogue adds the stable, de-secreted Cloud task
// projection beside the generic Task event. It must be called only after the
// task mutation is visible in the same transaction. Exact idempotency replays
// return before their mutation reaches this helper, so no duplicate Cloud
// event can be created by a replay.
func appendCloudTaskChangedIfDialogue(ctx context.Context, tx pgx.Tx, item task.Task) error {
	projection, found, err := loadCloudDialogueProjection(ctx, tx, item.TaskID)
	if err != nil || !found {
		return err
	}
	if projection.OwnerID != item.OwnerID {
		return errCloudTaskProjectionInvalid
	}
	stage, err := cloudTaskStage(ctx, tx, item, projection.PlanID)
	if err != nil {
		return err
	}
	taskID, err := uuid.Parse(item.TaskID)
	if err != nil || taskID == uuid.Nil || taskID.String() != item.TaskID || item.Revision < 1 {
		return errCloudTaskProjectionInvalid
	}
	summary := newCloudTaskSummary(item, projection, stage)
	return appendCloudFactEvent(ctx, tx, taskID, "cloud_task", cloudTaskChangedEvent, uint64(item.Revision), summary)
}

// appendCloudStepChangedIfDialogue emits only a fixed stage enum. In
// particular, it never copies task Step names, checkpoint/result references,
// Worker IDs, provider IDs, or any Worker-controlled material to the outbox.
func appendCloudStepChangedIfDialogue(ctx context.Context, tx pgx.Tx, step task.Step) error {
	projection, found, err := loadCloudDialogueProjection(ctx, tx, step.TaskID)
	if err != nil || !found {
		return err
	}
	stage, ok := cloudStageForStepName(step.Name)
	if !ok || step.Revision < 1 {
		return errCloudTaskProjectionInvalid
	}
	stepID, err := uuid.Parse(step.StepID)
	if err != nil || stepID == uuid.Nil || stepID.String() != step.StepID {
		return errCloudTaskProjectionInvalid
	}
	summary := newCloudStepSummary(step, projection, stage)
	return appendCloudFactEvent(ctx, tx, stepID, "cloud_step", cloudStepChangedEvent, uint64(step.Revision), summary)
}

func loadCloudDialogueProjection(ctx context.Context, tx pgx.Tx, rawTaskID string) (cloudDialogueProjection, bool, error) {
	taskID, err := uuid.Parse(rawTaskID)
	if err != nil || taskID == uuid.Nil || taskID.String() != rawTaskID {
		return cloudDialogueProjection{}, false, errCloudTaskProjectionInvalid
	}
	rows, err := tx.Query(ctx, `
		SELECT task.owner_id, session.connection_id, COALESCE(task.approved_plan_id::text,'')
		FROM tasks task
		JOIN planning_sessions session ON session.task_id=task.task_id
		WHERE task.task_id=$1
		  AND session.owner_id=task.owner_id
		  AND session.connection_id<>''
		  AND session.conversation_id='cloud-goal-' || replace(session.request_id::text,'-','')
		ORDER BY session.session_id
		LIMIT 2`, taskID)
	if err != nil {
		return cloudDialogueProjection{}, false, fmt.Errorf("read Cloud dialogue task binding: %w", err)
	}
	defer rows.Close()
	var matches []cloudDialogueProjection
	for rows.Next() {
		var projection cloudDialogueProjection
		if err := rows.Scan(&projection.OwnerID, &projection.ConnectionID, &projection.PlanID); err != nil {
			return cloudDialogueProjection{}, false, fmt.Errorf("scan Cloud dialogue task binding: %w", err)
		}
		matches = append(matches, projection)
	}
	if err := rows.Err(); err != nil {
		return cloudDialogueProjection{}, false, fmt.Errorf("iterate Cloud dialogue task binding: %w", err)
	}
	if len(matches) == 0 {
		return cloudDialogueProjection{}, false, nil
	}
	if len(matches) != 1 || matches[0].OwnerID == "" || matches[0].ConnectionID == "" {
		return cloudDialogueProjection{}, false, errCloudTaskProjectionInvalid
	}
	if matches[0].PlanID == "" {
		return matches[0], true, nil
	}
	planID, err := uuid.Parse(matches[0].PlanID)
	if err != nil || planID == uuid.Nil || planID.String() != matches[0].PlanID {
		return cloudDialogueProjection{}, false, errCloudTaskProjectionInvalid
	}
	agentInstanceID, err := cloudTaskAgentInstanceID(ctx, tx)
	if err != nil {
		return cloudDialogueProjection{}, false, err
	}
	var exactPlan bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM cloud_plans
			WHERE plan_id=$1 AND agent_instance_id=$2 AND owner_id=$3 AND connection_id=$4 AND task_id=$5
		)`, planID, agentInstanceID, matches[0].OwnerID, matches[0].ConnectionID, taskID).Scan(&exactPlan)
	if err != nil {
		return cloudDialogueProjection{}, false, fmt.Errorf("read Cloud dialogue Plan binding: %w", err)
	}
	if !exactPlan {
		return cloudDialogueProjection{}, false, errCloudTaskProjectionInvalid
	}
	return matches[0], true, nil
}

// resolveCloudGoalPlanForCompletion is the only writer for the pre-existing
// tasks.approved_plan_id field in the Cloud Goal flow. The Plan has already
// been persisted by the typed planning materializer, but it becomes a Task
// reference only in this same final-step completion transaction. This prevents
// a response-loss retry from publishing a fabricated or cross-owner Plan ID.
func resolveCloudGoalPlanForCompletion(
	ctx context.Context,
	tx pgx.Tx,
	rawTaskID string,
	step task.Step,
	command task.CompleteStepCommand,
) (string, error) {
	planID := strings.TrimSpace(command.RelatedPlanID)
	if planID == "" {
		return "", nil
	}
	if command.Outcome != task.OutcomeSucceeded || step.TaskID != rawTaskID || step.Name != cloudskill.StepPrepareResourceCandidates ||
		strings.TrimSpace(command.ResultRef) != "cloud://plan/"+planID {
		return "", task.ErrInvalid
	}
	parsedPlanID, err := uuid.Parse(planID)
	if err != nil || parsedPlanID == uuid.Nil || parsedPlanID.String() != planID {
		return "", task.ErrInvalid
	}
	parsedTaskID, err := uuid.Parse(rawTaskID)
	if err != nil || parsedTaskID == uuid.Nil || parsedTaskID.String() != rawTaskID {
		return "", task.ErrInvalid
	}
	projection, found, err := loadCloudDialogueProjection(ctx, tx, rawTaskID)
	if err != nil {
		return "", err
	}
	if !found || projection.PlanID != "" {
		return "", task.ErrInvalid
	}
	agentInstanceID, err := cloudTaskAgentInstanceID(ctx, tx)
	if err != nil {
		return "", err
	}
	var exactReadyPlan bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM cloud_plans
			WHERE plan_id=$1 AND agent_instance_id=$2 AND owner_id=$3 AND connection_id=$4
			  AND task_id=$5 AND status='ready_for_confirmation'
		)`, parsedPlanID, agentInstanceID, projection.OwnerID, projection.ConnectionID, parsedTaskID).Scan(&exactReadyPlan)
	if err != nil {
		return "", fmt.Errorf("read completed Cloud Goal Plan binding: %w", err)
	}
	if !exactReadyPlan {
		return "", task.ErrInvalid
	}
	return parsedPlanID.String(), nil
}

func cloudTaskAgentInstanceID(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT agent_instance_id FROM agent_instance_metadata ORDER BY agent_instance_id LIMIT 2`)
	if err != nil {
		return uuid.Nil, fmt.Errorf("read Cloud task Agent instance: %w", err)
	}
	defer rows.Close()
	var values []uuid.UUID
	for rows.Next() {
		var value uuid.UUID
		if err := rows.Scan(&value); err != nil {
			return uuid.Nil, fmt.Errorf("scan Cloud task Agent instance: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, fmt.Errorf("iterate Cloud task Agent instance: %w", err)
	}
	if len(values) != 1 || values[0] == uuid.Nil {
		return uuid.Nil, errCloudTaskProjectionInvalid
	}
	return values[0], nil
}

func cloudTaskStage(ctx context.Context, tx pgx.Tx, item task.Task, planID string) (string, error) {
	if item.ExecutionStatus == task.ExecutionWaitingUser {
		return cloudStageWaitingUser, nil
	}
	if item.ExecutionStatus == task.ExecutionFinished {
		if item.OutcomeStatus == task.OutcomeSucceeded && planID != "" {
			return cloudStageReadyForConfirmation, nil
		}
		return cloudStageFinished, nil
	}
	if planID != "" && item.ExecutionStatus == task.ExecutionAwaitingApproval {
		return cloudStageReadyForConfirmation, nil
	}
	if item.CurrentStepID != "" {
		return cloudStageForTaskStep(ctx, tx, item.TaskID, item.CurrentStepID)
	}
	if item.ExecutionStatus != task.ExecutionPlanning && item.ExecutionStatus != task.ExecutionQueued &&
		item.ExecutionStatus != task.ExecutionRunning && item.ExecutionStatus != task.ExecutionVerifying &&
		item.ExecutionStatus != task.ExecutionDraft && item.ExecutionStatus != task.ExecutionAwaitingApproval {
		return "", errCloudTaskProjectionInvalid
	}
	rows, err := tx.Query(ctx, `
		SELECT name, execution_status, outcome_status
		FROM task_steps
		WHERE task_id=$1
		ORDER BY CASE name
			WHEN $2 THEN 1
			WHEN $3 THEN 2
			WHEN $4 THEN 3
			ELSE 4
		END, step_id`, item.TaskID,
		cloudskill.StepResearchOfficialSources, cloudskill.StepDraftRecipe, cloudskill.StepPrepareResourceCandidates)
	if err != nil {
		return "", fmt.Errorf("read Cloud dialogue task stages: %w", err)
	}
	defer rows.Close()
	var found bool
	for rows.Next() {
		var name string
		var execution task.ExecutionStatus
		var outcome task.OutcomeStatus
		if err := rows.Scan(&name, &execution, &outcome); err != nil {
			return "", fmt.Errorf("scan Cloud dialogue task stage: %w", err)
		}
		stage, ok := cloudStageForStepName(name)
		if !ok {
			return "", errCloudTaskProjectionInvalid
		}
		found = true
		if execution != task.ExecutionFinished || outcome != task.OutcomeSucceeded {
			return stage, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate Cloud dialogue task stages: %w", err)
	}
	if !found {
		return "", errCloudTaskProjectionInvalid
	}
	return "", errCloudTaskProjectionInvalid
}

func cloudStageForTaskStep(ctx context.Context, tx pgx.Tx, taskID, stepID string) (string, error) {
	var name string
	err := tx.QueryRow(ctx, `SELECT name FROM task_steps WHERE task_id=$1 AND step_id=$2`, taskID, stepID).Scan(&name)
	if err != nil {
		return "", fmt.Errorf("read Cloud dialogue current stage: %w", err)
	}
	stage, ok := cloudStageForStepName(name)
	if !ok {
		return "", errCloudTaskProjectionInvalid
	}
	return stage, nil
}

func cloudStageForStepName(name string) (string, bool) {
	switch name {
	case cloudskill.StepResearchOfficialSources:
		return cloudStageResearch, true
	case cloudskill.StepDraftRecipe:
		return cloudStageRecipe, true
	case cloudskill.StepPrepareResourceCandidates:
		return cloudStageQuote, true
	default:
		return "", false
	}
}

func cloudTaskErrorCode(outcome task.OutcomeStatus) string {
	switch outcome {
	case task.OutcomeFailed:
		return "task_failed"
	case task.OutcomeCanceled:
		return "task_canceled"
	case task.OutcomeTimedOut:
		return "task_timed_out"
	case task.OutcomeInterrupted:
		return "task_interrupted"
	default:
		return ""
	}
}
