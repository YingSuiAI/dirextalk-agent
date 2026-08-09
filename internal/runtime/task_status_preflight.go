package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/google/uuid"
)

const maximumTaskStatusPreflightCandidates = 6

var historicalEntityIDPattern = regexp.MustCompile(
	`\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-8][0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}\b`,
)

type taskStatusPreflightView struct {
	TaskID                    string          `json:"task_id"`
	ExecutionStatus           string          `json:"execution_status"`
	OutcomeStatus             string          `json:"outcome_status"`
	Revision                  int64           `json:"revision"`
	Terminal                  bool            `json:"terminal"`
	CompletionReportAvailable bool            `json:"completion_report_available"`
	CompletionReportPending   bool            `json:"completion_report_pending"`
	CompletionReport          json.RawMessage `json:"completion_report,omitempty"`
	PlanID                    string          `json:"plan_id,omitempty"`
	PlanRevision              uint64          `json:"plan_revision,omitempty"`
	PlanStatus                string          `json:"plan_status,omitempty"`
}

type taskStatusPreflightResult struct {
	ProjectProfile string
	Messages       []modelapi.Message
}

func trustedTaskStatusPreflight(
	ctx context.Context,
	tools toolSet,
	messages []modelapi.Message,
) taskStatusPreflightResult {
	if _, available := tools.byName[CloudDialogueToolTeamTaskStatus]; !available {
		return taskStatusPreflightResult{}
	}
	for index, taskID := range historicalTaskStatusCandidates(messages) {
		arguments, err := json.Marshal(map[string]string{"task_id": taskID})
		if err != nil {
			return taskStatusPreflightResult{}
		}
		call := modelapi.ToolCall{
			ID:   fmt.Sprintf("trusted-task-status-preflight-%d", index+1),
			Type: "function",
			Function: modelapi.FunctionCall{
				Name:      CloudDialogueToolTeamTaskStatus,
				Arguments: string(arguments),
			},
		}
		execution := runTool(ctx, call, tools)
		if execution.IsError ||
			len(execution.RelatedTaskIDs) != 1 ||
			execution.RelatedTaskIDs[0] != taskID {
			continue
		}
		var view taskStatusPreflightView
		if json.Unmarshal([]byte(execution.Content), &view) != nil ||
			!validTaskStatusPreflight(view, taskID) {
			continue
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			return taskStatusPreflightResult{}
		}
		return taskStatusPreflightResult{
			ProjectProfile: "Trusted prior-Task status preflight (authoritative server read; older conversation text is stale if it conflicts). " +
				"This read precedes the latest user message and is not evidence that the latest message asks about this Task. Use it only when the latest message explicitly inspects, continues, retries, or cancels that Task. A new deliverable remains a new request even when it reuses the same project name. A terminal Task or failed, canceled, timed_out, or interrupted outcome MUST NOT be reused or described as awaiting approval:\n" +
				string(encoded),
			Messages: []modelapi.Message{
				{
					Role:      modelapi.RoleAssistant,
					ToolCalls: []modelapi.ToolCall{call},
				},
				{
					Role:       modelapi.RoleTool,
					Name:       CloudDialogueToolTeamTaskStatus,
					ToolCallID: call.ID,
					Content:    string(encoded),
				},
			},
		}
	}
	return taskStatusPreflightResult{}
}

func insertTaskStatusPreflightBeforeLatestUser(
	messages []modelapi.Message,
	preflight []modelapi.Message,
) []modelapi.Message {
	if len(preflight) == 0 {
		return messages
	}
	insertAt := len(messages)
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Role == modelapi.RoleUser {
			insertAt = index
			break
		}
	}
	result := make([]modelapi.Message, 0, len(messages)+len(preflight))
	result = append(result, messages[:insertAt]...)
	result = append(result, preflight...)
	result = append(result, messages[insertAt:]...)
	return result
}

func historicalTaskStatusCandidates(messages []modelapi.Message) []string {
	result := make([]string, 0, maximumTaskStatusPreflightCandidates)
	seen := make(map[string]struct{}, maximumTaskStatusPreflightCandidates)
	for messageIndex := len(messages) - 1; messageIndex >= 0; messageIndex-- {
		message := messages[messageIndex]
		if message.Role != modelapi.RoleAssistant &&
			message.Role != modelapi.RoleTool {
			continue
		}
		values := []string{message.Content}
		for _, call := range message.ToolCalls {
			values = append(values, call.Function.Arguments)
		}
		for _, value := range values {
			for _, candidate := range historicalEntityIDPattern.FindAllString(value, -1) {
				candidate = strings.ToLower(candidate)
				parsed, err := uuid.Parse(candidate)
				if err != nil || parsed == uuid.Nil || parsed.String() != candidate {
					continue
				}
				if _, duplicate := seen[candidate]; duplicate {
					continue
				}
				seen[candidate] = struct{}{}
				result = append(result, candidate)
				if len(result) == maximumTaskStatusPreflightCandidates {
					return result
				}
			}
		}
	}
	return result
}

func validTaskStatusPreflight(
	view taskStatusPreflightView,
	expectedTaskID string,
) bool {
	if view.TaskID != expectedTaskID ||
		view.Revision <= 0 ||
		!validPreflightExecutionStatus(view.ExecutionStatus) ||
		!validPreflightOutcomeStatus(view.OutcomeStatus) {
		return false
	}
	if view.Terminal != (view.ExecutionStatus == "finished") {
		return false
	}
	if view.CompletionReportAvailable {
		if view.CompletionReportPending ||
			len(view.CompletionReport) == 0 ||
			!json.Valid(view.CompletionReport) {
			return false
		}
	} else if len(view.CompletionReport) != 0 ||
		(view.CompletionReportPending && !view.Terminal) {
		return false
	}
	if view.PlanID == "" {
		return view.PlanRevision == 0 && view.PlanStatus == ""
	}
	parsed, err := uuid.Parse(view.PlanID)
	return err == nil && parsed != uuid.Nil &&
		parsed.String() == view.PlanID &&
		view.PlanRevision > 0 &&
		strings.TrimSpace(view.PlanStatus) == view.PlanStatus &&
		view.PlanStatus != ""
}

func validPreflightExecutionStatus(value string) bool {
	switch value {
	case "draft", "planning", "awaiting_approval", "queued", "running",
		"waiting_user", "verifying", "finished":
		return true
	default:
		return false
	}
}

func validPreflightOutcomeStatus(value string) bool {
	switch value {
	case "pending", "succeeded", "failed", "canceled", "timed_out",
		"interrupted":
		return true
	default:
		return false
	}
}
