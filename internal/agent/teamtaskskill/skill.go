package teamtaskskill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

const (
	ToolStatus                   = runtimeapi.CloudDialogueToolTeamTaskStatus
	ToolCancel                   = runtimeapi.CloudDialogueToolTeamTaskCancel
	taskLifecycleSummarySchemaV1 = "dirextalk.agent.team-task-lifecycle-summary/v1"
	completionReportSchemaV1     = "dirextalk.agent.team-task-completion-report/v1"
	maxModelVisibleResultBytes   = 64 << 10
	maxToolCallIDBytes           = 512
	resourceCleanupNotVerified   = "not_verified"
	maxCompletionFinalsPerRole   = 1
	maxCompletionListItems       = 4
	maxCompletionSummaryBytes    = 1024
	maxCompletionTextBytes       = 384
)

type Skill struct {
	dependencies Dependencies
}

var _ runtimeapi.ToolProvider = (*Skill)(nil)

func New(dependencies Dependencies) (*Skill, error) {
	if dependencies.Lifecycle == nil {
		return nil, ErrInvalidDependencies
	}
	return &Skill{dependencies: dependencies}, nil
}

func (skill *Skill) Tools(
	ctx context.Context,
	request runtimeapi.ToolRequest,
) ([]runtimeapi.Tool, error) {
	if skill == nil || skill.dependencies.Lifecycle == nil {
		return nil, ErrInvalidDependencies
	}
	scope, err := callScopeFromContext(ctx)
	if err != nil {
		return nil, err
	}
	requestID, parseErr := uuid.Parse(request.RequestID)
	if parseErr != nil ||
		requestID == uuid.Nil ||
		requestID.String() != request.RequestID ||
		request.OwnerID != scope.OwnerID ||
		strings.TrimSpace(request.ConversationID) == "" {
		return nil, ErrInvocationScopeMismatch
	}

	return []runtimeapi.Tool{
		{
			Definition: modelapi.Tool{
				Name:        ToolStatus,
				Description: "Read the authoritative server status of one existing Task owned by this user. When a successful Team execution has completed finalization, the result includes a verified, de-secreted, bounded completion report with Worker summaries, deliverables, tests, risks, and usage for the Central Agent to summarize. This read does not independently prove that cloud resources are absent or destroyed; cleanup verification remains explicit.",
				InputSchema: taskIDInputSchema(),
			},
			Run: func(
				runCtx context.Context,
				invocation runtimeapi.ToolInvocation,
			) (runtimeapi.ToolResult, error) {
				if err := validateInvocation(request, invocation, ToolStatus); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				input, err := decodeTaskInput(invocation.Arguments)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				current, err := skill.dependencies.Lifecycle.GetTeamTask(
					runCtx,
					StatusRequest{OwnerID: scope.OwnerID, TaskID: input.TaskID},
				)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				state := CancelNotRequested
				if current.ExecutionStatus == task.ExecutionFinished &&
					current.OutcomeStatus == task.OutcomeCanceled {
					state = CancelAlreadyCanceled
				}
				planValue, planFound, planErr :=
					skill.dependencies.Lifecycle.FindTeamTaskPlan(
						runCtx,
						StatusRequest{
							OwnerID: scope.OwnerID,
							TaskID:  input.TaskID,
						},
					)
				if planErr != nil {
					return runtimeapi.ToolResult{}, planErr
				}
				var plan *teamorchestration.PlanFact
				if planFound {
					plan = &planValue
				}
				var report *teamreport.Fact
				if current.ExecutionStatus == task.ExecutionFinished &&
					current.OutcomeStatus == task.OutcomeSucceeded {
					value, found, reportErr :=
						skill.dependencies.Lifecycle.FindTeamTaskReport(
							runCtx,
							StatusRequest{
								OwnerID: scope.OwnerID,
								TaskID:  input.TaskID,
							},
						)
					if reportErr != nil {
						return runtimeapi.ToolResult{}, reportErr
					}
					if found {
						report = &value
					}
				}
				return lifecycleResult(
					"status",
					current,
					state,
					scope.OwnerID,
					plan,
					report,
				)
			},
		},
		{
			Definition: modelapi.Tool{
				Name:        ToolCancel,
				Description: "Cancel one existing Task owned by this user, only after the user explicitly asks to stop or cancel it. This commits Task cancellation and initiates the existing cleanup controller; it does not itself verify that cloud resources have been destroyed.",
				InputSchema: taskIDInputSchema(),
			},
			Run: func(
				runCtx context.Context,
				invocation runtimeapi.ToolInvocation,
			) (runtimeapi.ToolResult, error) {
				if err := validateInvocation(request, invocation, ToolCancel); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				input, err := decodeTaskInput(invocation.Arguments)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				idempotencyKey := uuid.NewSHA1(
					requestID,
					[]byte("team-task-cancel/v1\x00"+invocation.ToolCallID),
				).String()
				canceled, err := skill.dependencies.Lifecycle.CancelTeamTask(
					runCtx,
					CancelRequest{
						IdempotencyKey: idempotencyKey,
						OwnerID:        scope.OwnerID,
						TaskID:         input.TaskID,
					},
				)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				return lifecycleResult(
					"cancel",
					canceled.Task,
					canceled.State,
					scope.OwnerID,
					nil,
					nil,
				)
			},
		},
	}, nil
}

type taskInput struct {
	TaskID string `json:"task_id"`
}

func decodeTaskInput(raw json.RawMessage) (taskInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input taskInput
	if err := decoder.Decode(&input); err != nil {
		return taskInput{}, ErrInvalidArguments
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return taskInput{}, ErrInvalidArguments
	}
	parsed, err := uuid.Parse(input.TaskID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != input.TaskID {
		return taskInput{}, ErrInvalidArguments
	}
	return input, nil
}

func validateInvocation(
	request runtimeapi.ToolRequest,
	invocation runtimeapi.ToolInvocation,
	name string,
) error {
	toolCallID := strings.TrimSpace(invocation.ToolCallID)
	if invocation.RequestID != request.RequestID ||
		invocation.OwnerID != request.OwnerID ||
		invocation.ConversationID != request.ConversationID ||
		invocation.Name != name ||
		toolCallID == "" ||
		toolCallID != invocation.ToolCallID ||
		len(toolCallID) > maxToolCallIDBytes {
		return ErrInvocationScopeMismatch
	}
	return nil
}

type lifecycleView struct {
	SchemaVersion               string                `json:"schema_version"`
	Operation                   string                `json:"operation"`
	TaskID                      string                `json:"task_id"`
	ExecutionStatus             task.ExecutionStatus  `json:"execution_status"`
	OutcomeStatus               task.OutcomeStatus    `json:"outcome_status"`
	Revision                    int64                 `json:"revision"`
	Terminal                    bool                  `json:"terminal"`
	CancellationState           string                `json:"cancellation_state"`
	CancellationCommitted       bool                  `json:"cancellation_committed"`
	ResourceCleanupVerification string                `json:"resource_cleanup_verification"`
	CloudResourcesAbsent        *bool                 `json:"cloud_resources_absent"`
	CompletionReportAvailable   bool                  `json:"completion_report_available"`
	CompletionReportPending     bool                  `json:"completion_report_pending"`
	PlanID                      string                `json:"plan_id,omitempty"`
	PlanRevision                uint64                `json:"plan_revision,omitempty"`
	PlanStatus                  string                `json:"plan_status,omitempty"`
	CompletionReport            *completionReportView `json:"completion_report,omitempty"`
}

type completionReportView struct {
	SchemaVersion string               `json:"schema_version"`
	ExecutionID   string               `json:"execution_id"`
	PlanID        string               `json:"plan_id"`
	PlanRevision  uint64               `json:"plan_revision"`
	ReportDigest  string               `json:"report_digest"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Roles         []completionRoleView `json:"roles"`
	TotalUsage    workerruntime.Usage  `json:"total_usage"`
	Truncated     bool                 `json:"truncated"`
}

type completionRoleView struct {
	RoleID              string                `json:"role_id"`
	Title               string                `json:"title"`
	Outcome             task.OutcomeStatus    `json:"outcome"`
	Finals              []completionFinalView `json:"finals"`
	OmittedFinals       int                   `json:"omitted_finals"`
	ContentWasTruncated bool                  `json:"content_was_truncated"`
}

type completionFinalView struct {
	ActionID       string              `json:"action_id"`
	Status         string              `json:"status"`
	Summary        string              `json:"summary"`
	Deliverables   []string            `json:"deliverables"`
	Tests          []string            `json:"tests"`
	Risks          []string            `json:"risks"`
	Usage          workerruntime.Usage `json:"usage"`
	ArtifactSHA256 string              `json:"artifact_sha256"`
}

func lifecycleResult(
	operation string,
	current task.Task,
	cancelState CancelState,
	ownerID string,
	plan *teamorchestration.PlanFact,
	report *teamreport.Fact,
) (runtimeapi.ToolResult, error) {
	if !validTaskFact(current, ownerID) ||
		(operation != "status" && operation != "cancel") ||
		!validCancelState(operation, cancelState, current) {
		return runtimeapi.ToolResult{}, ErrInvalidPortResponse
	}
	committed := cancelState == CancelCommitted ||
		cancelState == CancelAlreadyCanceled
	completion, err := compactCompletionReport(current, ownerID, report)
	if err != nil {
		return runtimeapi.ToolResult{}, err
	}
	if err := validateTaskPlanReference(current, ownerID, plan); err != nil {
		return runtimeapi.ToolResult{}, err
	}
	if completion != nil &&
		plan != nil &&
		(completion.PlanID != plan.Plan.PlanID ||
			completion.PlanRevision != plan.Plan.Revision) {
		return runtimeapi.ToolResult{}, ErrInvalidPortResponse
	}
	completionPending := current.ExecutionStatus == task.ExecutionFinished &&
		current.OutcomeStatus == task.OutcomeSucceeded &&
		completion == nil
	view := lifecycleView{
		SchemaVersion:               taskLifecycleSummarySchemaV1,
		Operation:                   operation,
		TaskID:                      current.TaskID,
		ExecutionStatus:             current.ExecutionStatus,
		OutcomeStatus:               current.OutcomeStatus,
		Revision:                    current.Revision,
		Terminal:                    current.ExecutionStatus == task.ExecutionFinished,
		CancellationState:           string(cancelState),
		CancellationCommitted:       committed,
		ResourceCleanupVerification: resourceCleanupNotVerified,
		CloudResourcesAbsent:        nil,
		CompletionReportAvailable:   completion != nil,
		CompletionReportPending:     completionPending,
		CompletionReport:            completion,
	}
	if plan != nil {
		view.PlanID = plan.Plan.PlanID
		view.PlanRevision = plan.Plan.Revision
		view.PlanStatus = string(plan.Status)
	}
	encoded, err := json.Marshal(view)
	if err != nil ||
		len(encoded) > maxModelVisibleResultBytes ||
		security.ContainsLikelySecret(string(encoded)) {
		return runtimeapi.ToolResult{}, ErrModelVisibleResultTooLarge
	}
	result := runtimeapi.ToolResult{
		Content:        string(encoded),
		RelatedTaskIDs: []string{current.TaskID},
	}
	if plan != nil {
		result.RelatedPlanIDs = []string{plan.Plan.PlanID}
	} else if completion != nil {
		result.RelatedPlanIDs = []string{completion.PlanID}
	}
	return result, nil
}

func validateTaskPlanReference(
	current task.Task,
	ownerID string,
	fact *teamorchestration.PlanFact,
) error {
	if fact == nil {
		return nil
	}
	planID, err := uuid.Parse(fact.Plan.PlanID)
	if err != nil ||
		planID == uuid.Nil ||
		planID.String() != fact.Plan.PlanID ||
		fact.TaskID != current.TaskID ||
		fact.Plan.OwnerID != ownerID ||
		fact.Plan.Revision == 0 ||
		fact.RecordRevision == 0 {
		return ErrInvalidPortResponse
	}
	switch fact.Status {
	case teamorchestration.PlanReadyForConfirmation,
		teamorchestration.PlanApproved,
		teamorchestration.PlanExpired,
		teamorchestration.PlanSuperseded,
		teamorchestration.PlanExecuting,
		teamorchestration.PlanCompleted,
		teamorchestration.PlanFailed,
		teamorchestration.PlanCanceled:
		return nil
	default:
		return ErrInvalidPortResponse
	}
}

func compactCompletionReport(
	current task.Task,
	ownerID string,
	fact *teamreport.Fact,
) (*completionReportView, error) {
	if fact == nil {
		return nil, nil
	}
	if fact.Validate() != nil ||
		fact.Report.OwnerID != ownerID ||
		fact.Report.TaskID != current.TaskID ||
		current.ExecutionStatus != task.ExecutionFinished ||
		current.OutcomeStatus != task.OutcomeSucceeded {
		return nil, ErrInvalidPortResponse
	}
	view := &completionReportView{
		SchemaVersion: completionReportSchemaV1,
		ExecutionID:   fact.Report.ExecutionID,
		PlanID:        fact.Report.PlanID,
		PlanRevision:  fact.Report.PlanRevision,
		ReportDigest:  fact.ReportDigest,
		GeneratedAt:   fact.GeneratedAt,
		Roles:         make([]completionRoleView, 0, len(fact.Report.Roles)),
		TotalUsage:    fact.Report.TotalUsage,
	}
	for _, role := range fact.Report.Roles {
		title, titleTruncated := compactText(
			role.Title,
			maxCompletionTextBytes,
		)
		projected := completionRoleView{
			RoleID:              role.RoleID,
			Title:               title,
			Outcome:             role.Outcome,
			Finals:              make([]completionFinalView, 0, 1),
			OmittedFinals:       max(0, len(role.Finals)-maxCompletionFinalsPerRole),
			ContentWasTruncated: titleTruncated,
		}
		for index, final := range role.Finals {
			if index >= maxCompletionFinalsPerRole {
				break
			}
			summary, summaryTruncated := compactText(
				final.Summary,
				maxCompletionSummaryBytes,
			)
			deliverables, deliverablesTruncated := compactList(
				final.Deliverables,
			)
			tests, testsTruncated := compactList(final.Tests)
			risks, risksTruncated := compactList(final.Risks)
			projected.ContentWasTruncated =
				projected.ContentWasTruncated ||
					summaryTruncated || deliverablesTruncated ||
					testsTruncated || risksTruncated
			projected.Finals = append(
				projected.Finals,
				completionFinalView{
					ActionID:       final.ActionID,
					Status:         final.Status,
					Summary:        summary,
					Deliverables:   deliverables,
					Tests:          tests,
					Risks:          risks,
					Usage:          final.Usage,
					ArtifactSHA256: final.ArtifactSHA256,
				},
			)
		}
		if projected.OmittedFinals > 0 ||
			projected.ContentWasTruncated {
			view.Truncated = true
		}
		view.Roles = append(view.Roles, projected)
	}
	return view, nil
}

func compactList(values []string) ([]string, bool) {
	limit := min(len(values), maxCompletionListItems)
	result := make([]string, 0, limit)
	truncated := len(values) > limit
	for _, value := range values[:limit] {
		compacted, shortened := compactText(
			value,
			maxCompletionTextBytes,
		)
		result = append(result, compacted)
		truncated = truncated || shortened
	}
	return result, truncated
}

func compactText(value string, maximumBytes int) (string, bool) {
	if len(value) <= maximumBytes {
		return value, false
	}
	cut := maximumBytes - 3
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return strings.TrimSpace(value[:cut]) + "...", true
}

func validTaskFact(current task.Task, ownerID string) bool {
	parsed, err := uuid.Parse(current.TaskID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != current.TaskID ||
		current.OwnerID != ownerID ||
		current.Revision < 1 {
		return false
	}
	switch current.ExecutionStatus {
	case task.ExecutionDraft,
		task.ExecutionPlanning,
		task.ExecutionAwaitingApproval,
		task.ExecutionQueued,
		task.ExecutionRunning,
		task.ExecutionWaitingUser,
		task.ExecutionVerifying:
		return current.OutcomeStatus == task.OutcomePending
	case task.ExecutionFinished:
		switch current.OutcomeStatus {
		case task.OutcomeSucceeded,
			task.OutcomeFailed,
			task.OutcomeCanceled,
			task.OutcomeTimedOut,
			task.OutcomeInterrupted:
			return true
		}
	}
	return false
}

func validCancelState(
	operation string,
	state CancelState,
	current task.Task,
) bool {
	if operation == "status" {
		return state == CancelNotRequested ||
			(state == CancelAlreadyCanceled &&
				current.ExecutionStatus == task.ExecutionFinished &&
				current.OutcomeStatus == task.OutcomeCanceled)
	}
	switch state {
	case CancelCommitted, CancelAlreadyCanceled:
		return current.ExecutionStatus == task.ExecutionFinished &&
			current.OutcomeStatus == task.OutcomeCanceled
	case CancelNotApplicableTerminal:
		return current.ExecutionStatus == task.ExecutionFinished &&
			current.OutcomeStatus != task.OutcomeCanceled
	default:
		return false
	}
}

func taskIDInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"task_id"},
		"properties": map[string]any{
			"task_id": map[string]any{
				"type":        "string",
				"description": "Canonical Task UUID returned by a prior trusted tool or task card.",
				"pattern":     "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
			},
		},
	}
}
