package teamtaskskill

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

const (
	teamTaskTestRequestID = "61bf1ec0-2605-4d9a-a28c-84ec2f86b524"
	teamTaskTestTaskID    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

type lifecycleStub struct {
	current       task.Task
	cancelState   CancelState
	statusRequest StatusRequest
	reportRequest StatusRequest
	planRequest   StatusRequest
	cancelRequest CancelRequest
	report        teamreport.Fact
	reportFound   bool
	plan          teamorchestration.PlanFact
	planFound     bool
}

func (stub *lifecycleStub) GetTeamTask(
	_ context.Context,
	request StatusRequest,
) (task.Task, error) {
	stub.statusRequest = request
	return stub.current, nil
}

func (stub *lifecycleStub) FindTeamTaskReport(
	_ context.Context,
	request StatusRequest,
) (teamreport.Fact, bool, error) {
	stub.reportRequest = request
	return stub.report, stub.reportFound, nil
}

func (stub *lifecycleStub) FindTeamTaskPlan(
	_ context.Context,
	request StatusRequest,
) (teamorchestration.PlanFact, bool, error) {
	stub.planRequest = request
	return stub.plan, stub.planFound, nil
}

func (stub *lifecycleStub) CancelTeamTask(
	_ context.Context,
	request CancelRequest,
) (CancelFact, error) {
	stub.cancelRequest = request
	return CancelFact{Task: stub.current, State: stub.cancelState}, nil
}

func TestSkillReturnsVerifiedCompactCompletionReport(t *testing.T) {
	t.Parallel()
	executionID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	planID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	artifactDigest := "sha256:" + strings.Repeat("a", 64)
	evidenceDigest := "sha256:" + strings.Repeat("b", 64)
	planDigest := "sha256:" + strings.Repeat("c", 64)
	report := teamreport.ReportV1{
		SchemaVersion: teamreport.SchemaV1,
		ExecutionID:   executionID,
		OwnerID:       "owner-1",
		TaskID:        teamTaskTestTaskID,
		PlanID:        planID,
		PlanRevision:  2,
		PlanDigest:    planDigest,
		Roles: []teamreport.RoleV1{{
			RoleID:               "builder",
			Title:                "Build and verify the requested artifact",
			RuntimeFamily:        teamplan.RuntimePi,
			RuntimeAdapter:       workerruntime.AdapterPiV1,
			Outcome:              task.OutcomeSucceeded,
			ResultEvidenceDigest: evidenceDigest,
			Finals: []teamreport.FinalV1{{
				ActionID:       "implementation",
				Adapter:        workerruntime.AdapterPiV1,
				Usage:          workerruntime.Usage{InputTokens: 120, OutputTokens: 40},
				Status:         "completed",
				Summary:        "Implemented the CLI and verified the executable.",
				Deliverables:   []string{"source archive", "linux binary"},
				Tests:          []string{"go test ./... passed"},
				Risks:          []string{"No Windows build was requested"},
				ArtifactSHA256: artifactDigest,
			}},
		}},
		TotalUsage: workerruntime.Usage{InputTokens: 120, OutputTokens: 40},
	}
	reportDigest, err := report.Digest()
	if err != nil {
		t.Fatal(err)
	}
	stub := &lifecycleStub{
		current: task.Task{
			TaskID:          teamTaskTestTaskID,
			OwnerID:         "owner-1",
			ExecutionStatus: task.ExecutionFinished,
			OutcomeStatus:   task.OutcomeSucceeded,
			Revision:        9,
		},
		reportFound: true,
		report: teamreport.Fact{
			Report:       report,
			ReportDigest: reportDigest,
			GeneratedAt: time.Date(
				2026,
				time.August,
				3,
				4,
				0,
				0,
				0,
				time.UTC,
			),
		},
	}
	skill, err := New(Dependencies{Lifecycle: stub})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(
		context.Background(),
		CallScope{OwnerID: "owner-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:      teamTaskTestRequestID,
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "status-completed",
			Name:           ToolStatus,
			Arguments: json.RawMessage(
				`{"task_id":"` + teamTaskTestTaskID + `"}`,
			),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		CompletionReportAvailable bool `json:"completion_report_available"`
		CompletionReportPending   bool `json:"completion_report_pending"`
		CompletionReport          struct {
			SchemaVersion string `json:"schema_version"`
			ExecutionID   string `json:"execution_id"`
			ReportDigest  string `json:"report_digest"`
			Roles         []struct {
				Finals []struct {
					Summary      string   `json:"summary"`
					Deliverables []string `json:"deliverables"`
					Tests        []string `json:"tests"`
				} `json:"finals"`
			} `json:"roles"`
		} `json:"completion_report"`
	}
	if err := json.Unmarshal([]byte(result.Content), &view); err != nil ||
		!view.CompletionReportAvailable ||
		view.CompletionReportPending ||
		view.CompletionReport.SchemaVersion != completionReportSchemaV1 ||
		view.CompletionReport.ExecutionID != executionID ||
		view.CompletionReport.ReportDigest != reportDigest ||
		len(view.CompletionReport.Roles) != 1 ||
		len(view.CompletionReport.Roles[0].Finals) != 1 ||
		view.CompletionReport.Roles[0].Finals[0].Summary !=
			"Implemented the CLI and verified the executable." ||
		len(view.CompletionReport.Roles[0].Finals[0].Deliverables) != 2 ||
		len(view.CompletionReport.Roles[0].Finals[0].Tests) != 1 ||
		stub.reportRequest != (StatusRequest{
			OwnerID: "owner-1",
			TaskID:  teamTaskTestTaskID,
		}) ||
		len(result.RelatedPlanIDs) != 1 ||
		result.RelatedPlanIDs[0] != planID {
		t.Fatalf(
			"completion view=%#v request=%#v result=%#v error=%v",
			view,
			stub.reportRequest,
			result,
			err,
		)
	}
}

func TestSkillStatusLinksAwaitingTaskToExactApprovalPlan(t *testing.T) {
	t.Parallel()
	planID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	stub := &lifecycleStub{
		current: task.Task{
			TaskID:          teamTaskTestTaskID,
			OwnerID:         "owner-1",
			ExecutionStatus: task.ExecutionAwaitingApproval,
			OutcomeStatus:   task.OutcomePending,
			Revision:        2,
		},
		planFound: true,
		plan: teamorchestration.PlanFact{
			TaskID: teamTaskTestTaskID,
			Plan: teamplan.Plan{
				PlanID:   planID,
				Revision: 1,
				OwnerID:  "owner-1",
			},
			Status:         teamorchestration.PlanReadyForConfirmation,
			RecordRevision: 1,
		},
	}
	skill, err := New(Dependencies{Lifecycle: stub})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(
		context.Background(),
		CallScope{OwnerID: "owner-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:      teamTaskTestRequestID,
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil || len(tools) != 2 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	result, err := tools[0].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "status-plan-link",
			Name:           ToolStatus,
			Arguments: []byte(
				`{"task_id":"` + teamTaskTestTaskID + `"}`,
			),
		},
	)
	var view struct {
		PlanID       string `json:"plan_id"`
		PlanRevision uint64 `json:"plan_revision"`
		PlanStatus   string `json:"plan_status"`
	}
	if err != nil ||
		json.Unmarshal([]byte(result.Content), &view) != nil ||
		view.PlanID != planID ||
		view.PlanRevision != 1 ||
		view.PlanStatus != string(teamorchestration.PlanReadyForConfirmation) ||
		stub.planRequest != (StatusRequest{
			OwnerID: "owner-1",
			TaskID:  teamTaskTestTaskID,
		}) ||
		len(result.RelatedTaskIDs) != 1 ||
		result.RelatedTaskIDs[0] != teamTaskTestTaskID ||
		len(result.RelatedPlanIDs) != 1 ||
		result.RelatedPlanIDs[0] != planID {
		t.Fatalf(
			"plan status view=%#v request=%#v result=%#v error=%v",
			view,
			stub.planRequest,
			result,
			err,
		)
	}
}

func TestLifecycleResultMarksSuccessfulReportFinalizationPending(t *testing.T) {
	t.Parallel()
	result, err := lifecycleResult(
		"status",
		task.Task{
			TaskID:          teamTaskTestTaskID,
			OwnerID:         "owner-1",
			ExecutionStatus: task.ExecutionFinished,
			OutcomeStatus:   task.OutcomeSucceeded,
			Revision:        7,
		},
		CancelNotRequested,
		"owner-1",
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		CompletionReportAvailable bool `json:"completion_report_available"`
		CompletionReportPending   bool `json:"completion_report_pending"`
		CompletionReport          any  `json:"completion_report"`
	}
	if err := json.Unmarshal([]byte(result.Content), &view); err != nil ||
		view.CompletionReportAvailable ||
		!view.CompletionReportPending ||
		view.CompletionReport != nil {
		t.Fatalf("pending completion view=%#v error=%v", view, err)
	}
}

func TestLifecycleResultBoundsMaximumValidTeamReport(t *testing.T) {
	t.Parallel()
	const ownerID = "owner-1"
	longText := strings.TrimSpace(
		strings.Repeat("bounded result text ", 400),
	)
	list := make([]string, 64)
	for index := range list {
		list[index] = fmt.Sprintf(
			"result item %02d %s",
			index,
			strings.Repeat("x", 240),
		)
	}
	report := teamreport.ReportV1{
		SchemaVersion: teamreport.SchemaV1,
		ExecutionID:   "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		OwnerID:       ownerID,
		TaskID:        teamTaskTestTaskID,
		PlanID:        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		PlanRevision:  2,
		PlanDigest:    "sha256:" + strings.Repeat("c", 64),
		Roles:         make([]teamreport.RoleV1, 0, 8),
	}
	for roleIndex := 0; roleIndex < 8; roleIndex++ {
		role := teamreport.RoleV1{
			RoleID:               fmt.Sprintf("role-%c", 'a'+roleIndex),
			Title:                longText,
			RuntimeFamily:        teamplan.RuntimePi,
			RuntimeAdapter:       workerruntime.AdapterPiV1,
			Outcome:              task.OutcomeSucceeded,
			ResultEvidenceDigest: "sha256:" + strings.Repeat("b", 64),
			Finals:               make([]teamreport.FinalV1, 0, 8),
		}
		for finalIndex := 0; finalIndex < 8; finalIndex++ {
			role.Finals = append(role.Finals, teamreport.FinalV1{
				ActionID: fmt.Sprintf(
					"action-%d",
					finalIndex,
				),
				Adapter:        workerruntime.AdapterPiV1,
				Usage:          workerruntime.Usage{},
				Status:         "completed",
				Summary:        longText,
				Deliverables:   slices.Clone(list),
				Tests:          slices.Clone(list),
				Risks:          slices.Clone(list),
				ArtifactSHA256: "sha256:" + strings.Repeat("a", 64),
			})
		}
		report.Roles = append(report.Roles, role)
	}
	digest, err := report.Digest()
	if err != nil {
		t.Fatal(err)
	}
	result, err := lifecycleResult(
		"status",
		task.Task{
			TaskID:          teamTaskTestTaskID,
			OwnerID:         ownerID,
			ExecutionStatus: task.ExecutionFinished,
			OutcomeStatus:   task.OutcomeSucceeded,
			Revision:        8,
		},
		CancelNotRequested,
		ownerID,
		nil,
		&teamreport.Fact{
			Report:       report,
			ReportDigest: digest,
			GeneratedAt: time.Date(
				2026,
				time.August,
				3,
				4,
				0,
				0,
				0,
				time.UTC,
			),
		},
	)
	if err != nil || len(result.Content) > maxModelVisibleResultBytes {
		t.Fatalf(
			"maximum report result bytes=%d error=%v",
			len(result.Content),
			err,
		)
	}
	var view struct {
		CompletionReport struct {
			Truncated bool `json:"truncated"`
			Roles     []struct {
				OmittedFinals int `json:"omitted_finals"`
				Finals        []struct {
					Deliverables []string `json:"deliverables"`
				} `json:"finals"`
			} `json:"roles"`
		} `json:"completion_report"`
	}
	if err := json.Unmarshal([]byte(result.Content), &view); err != nil ||
		!view.CompletionReport.Truncated ||
		len(view.CompletionReport.Roles) != 8 ||
		view.CompletionReport.Roles[0].OmittedFinals != 7 ||
		len(view.CompletionReport.Roles[0].Finals) != 1 ||
		len(view.CompletionReport.Roles[0].Finals[0].Deliverables) !=
			maxCompletionListItems {
		t.Fatalf("bounded completion view=%#v error=%v", view, err)
	}
}

func TestSkillReadsAndCancelsOnlyExactTaskWithoutClaimingCleanup(t *testing.T) {
	t.Parallel()
	stub := &lifecycleStub{current: task.Task{
		TaskID:          teamTaskTestTaskID,
		OwnerID:         "owner-1",
		ExecutionStatus: task.ExecutionRunning,
		OutcomeStatus:   task.OutcomePending,
		Revision:        3,
	}}
	skill, err := New(Dependencies{Lifecycle: stub})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(
		context.Background(),
		CallScope{OwnerID: "owner-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:      teamTaskTestRequestID,
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil || len(tools) != 2 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	byName := map[string]runtimeapi.Tool{}
	for _, tool := range tools {
		byName[tool.Definition.Name] = tool
		if tool.Definition.InputSchema["additionalProperties"] != false {
			t.Fatalf("open tool schema = %#v", tool.Definition.InputSchema)
		}
	}
	arguments := json.RawMessage(`{"task_id":"` + teamTaskTestTaskID + `"}`)
	statusResult, err := byName[ToolStatus].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "status-call",
			Name:           ToolStatus,
			Arguments:      arguments,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var statusView map[string]any
	if json.Unmarshal([]byte(statusResult.Content), &statusView) != nil ||
		statusView["operation"] != "status" ||
		statusView["cancellation_state"] != string(CancelNotRequested) ||
		statusView["cancellation_committed"] != false ||
		statusView["resource_cleanup_verification"] != resourceCleanupNotVerified ||
		statusView["cloud_resources_absent"] != nil ||
		len(statusResult.RelatedTaskIDs) != 1 ||
		statusResult.RelatedTaskIDs[0] != teamTaskTestTaskID ||
		stub.statusRequest != (StatusRequest{OwnerID: "owner-1", TaskID: teamTaskTestTaskID}) {
		t.Fatalf("status result = %#v request=%#v", statusView, stub.statusRequest)
	}

	stub.current.ExecutionStatus = task.ExecutionFinished
	stub.current.OutcomeStatus = task.OutcomeCanceled
	stub.current.Revision = 4
	stub.cancelState = CancelCommitted
	cancelResult, err := byName[ToolCancel].Run(
		context.Background(),
		runtimeapi.ToolInvocation{
			RequestID:      request.RequestID,
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			ToolCallID:     "cancel-call",
			Name:           ToolCancel,
			Arguments:      arguments,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := uuid.NewSHA1(
		uuid.MustParse(request.RequestID),
		[]byte("team-task-cancel/v1\x00cancel-call"),
	).String()
	var cancelView map[string]any
	if json.Unmarshal([]byte(cancelResult.Content), &cancelView) != nil ||
		cancelView["operation"] != "cancel" ||
		cancelView["cancellation_state"] != string(CancelCommitted) ||
		cancelView["cancellation_committed"] != true ||
		cancelView["resource_cleanup_verification"] != resourceCleanupNotVerified ||
		cancelView["cloud_resources_absent"] != nil ||
		stub.cancelRequest.IdempotencyKey != wantKey ||
		stub.cancelRequest.OwnerID != request.OwnerID ||
		stub.cancelRequest.TaskID != teamTaskTestTaskID {
		t.Fatalf("cancel result = %#v request=%#v", cancelView, stub.cancelRequest)
	}
}

func TestSkillRejectsUnknownArgumentsAndForeignPortFacts(t *testing.T) {
	t.Parallel()
	stub := &lifecycleStub{current: task.Task{
		TaskID:          teamTaskTestTaskID,
		OwnerID:         "owner-2",
		ExecutionStatus: task.ExecutionRunning,
		OutcomeStatus:   task.OutcomePending,
		Revision:        1,
	}}
	skill, err := New(Dependencies{Lifecycle: stub})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BindCallScope(
		context.Background(),
		CallScope{OwnerID: "owner-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{
		RequestID:      teamTaskTestRequestID,
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
	}
	tools, err := skill.Tools(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
		RequestID: request.RequestID, OwnerID: request.OwnerID,
		ConversationID: request.ConversationID, ToolCallID: "call-1",
		Name: ToolStatus,
		Arguments: json.RawMessage(
			`{"task_id":"` + teamTaskTestTaskID + `","owner_id":"owner-2"}`,
		),
	})
	if !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("unknown argument error = %v", err)
	}
	_, err = tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
		RequestID: request.RequestID, OwnerID: request.OwnerID,
		ConversationID: request.ConversationID, ToolCallID: "call-2",
		Name: ToolStatus,
		Arguments: json.RawMessage(
			`{"task_id":"` + teamTaskTestTaskID + `"}`,
		),
	})
	if !errors.Is(err, ErrInvalidPortResponse) {
		t.Fatalf("foreign fact error = %v", err)
	}
}
