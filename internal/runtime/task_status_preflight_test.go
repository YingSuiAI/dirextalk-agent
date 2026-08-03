package runtime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

func TestHistoricalTaskStatusCandidatesExcludeUserSuppliedIDs(t *testing.T) {
	t.Parallel()
	taskID := "019fc569-5b66-74d2-bb69-c3308175f109"
	planID := "6286a407-f890-5f32-8369-5e966e663a06"
	userID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	got := historicalTaskStatusCandidates([]modelapi.Message{
		{Role: modelapi.RoleUser, Content: "inspect " + userID},
		{Role: modelapi.RoleAssistant, Content: "Task " + taskID + " plan " + planID},
		{Role: modelapi.RoleTool, Content: `{"task_id":"` + taskID + `"}`},
	})
	if len(got) != 2 || got[0] != taskID || got[1] != planID {
		t.Fatalf("historical candidates = %#v", got)
	}
}

func TestTrustedTaskStatusPreflightUsesAuthoritativeStatus(t *testing.T) {
	t.Parallel()
	taskID := "019fc569-5b66-74d2-bb69-c3308175f109"
	planID := "6286a407-f890-5f32-8369-5e966e663a06"
	calls := 0
	set := toolSet{
		request: ToolRequest{
			RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			OwnerID:   "owner-1", ConversationID: "conversation-1",
		},
		byName: map[string]Tool{
			CloudDialogueToolTeamTaskStatus: {
				Definition: modelapi.Tool{Name: CloudDialogueToolTeamTaskStatus},
				Run: func(_ context.Context, invocation ToolInvocation) (ToolResult, error) {
					calls++
					var input struct {
						TaskID string `json:"task_id"`
					}
					if json.Unmarshal(invocation.Arguments, &input) != nil || input.TaskID != taskID {
						t.Fatalf("status input = %s", invocation.Arguments)
					}
					return ToolResult{
						Content:        `{"schema_version":"dirextalk.agent.team-task-lifecycle-summary/v1","operation":"status","task_id":"` + taskID + `","execution_status":"finished","outcome_status":"failed","revision":6,"terminal":true,"plan_id":"` + planID + `","plan_revision":2,"plan_status":"approved"}`,
						RelatedTaskIDs: []string{taskID}, RelatedPlanIDs: []string{planID},
					}, nil
				},
			},
		},
	}
	preflight := trustedTaskStatusPreflight(
		context.Background(),
		set,
		[]modelapi.Message{{
			Role:    modelapi.RoleAssistant,
			Content: "Task " + taskID + " is awaiting approval; plan " + planID,
		}},
	)
	if calls != 1 ||
		!strings.Contains(preflight.ProjectProfile, `"execution_status":"finished"`) ||
		!strings.Contains(preflight.ProjectProfile, `"outcome_status":"failed"`) ||
		len(preflight.Messages) != 2 ||
		len(preflight.Messages[0].ToolCalls) != 1 ||
		preflight.Messages[0].ToolCalls[0].Function.Name != CloudDialogueToolTeamTaskStatus ||
		preflight.Messages[1].Role != modelapi.RoleTool ||
		preflight.Messages[1].ToolCallID != preflight.Messages[0].ToolCalls[0].ID ||
		strings.Contains(preflight.Messages[1].Content, "awaiting approval") ||
		preflight.Messages[1].Content != `{"task_id":"`+taskID+`","execution_status":"finished","outcome_status":"failed","revision":6,"terminal":true,"plan_id":"`+planID+`","plan_revision":2,"plan_status":"approved"}` {
		t.Fatalf("preflight calls=%d result=%#v", calls, preflight)
	}
}

func TestTrustedTaskStatusPreflightRejectsMismatchedResult(t *testing.T) {
	t.Parallel()
	taskID := "019fc569-5b66-74d2-bb69-c3308175f109"
	set := toolSet{
		request: ToolRequest{
			RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			OwnerID:   "owner-1", ConversationID: "conversation-1",
		},
		byName: map[string]Tool{
			CloudDialogueToolTeamTaskStatus: {
				Definition: modelapi.Tool{Name: CloudDialogueToolTeamTaskStatus},
				Run: func(context.Context, ToolInvocation) (ToolResult, error) {
					return ToolResult{
						Content:        `{"task_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","execution_status":"finished","outcome_status":"failed","revision":1,"terminal":true}`,
						RelatedTaskIDs: []string{taskID},
					}, nil
				},
			},
		},
	}
	if got := trustedTaskStatusPreflight(
		context.Background(),
		set,
		[]modelapi.Message{{Role: modelapi.RoleAssistant, Content: taskID}},
	); got.ProjectProfile != "" || len(got.Messages) != 0 {
		t.Fatalf("mismatched status was injected: %#v", got)
	}
}

func TestCloudDialoguePreflightScansRequestHistory(t *testing.T) {
	t.Parallel()
	taskID := "019fc569-5b66-74d2-bb69-c3308175f109"
	planID := "6286a407-f890-5f32-8369-5e966e663a06"
	config := validTestConfig()
	config.MemoryDisabled = true
	statusCalls := 0
	engine := &scriptedEngine{generate: func(
		_ context.Context,
		request EngineRequest,
	) (EngineResult, error) {
		if len(request.Messages) < 3 ||
			!strings.Contains(
				request.Messages[0].Content,
				"Trusted current Task status preflight",
			) ||
			!strings.Contains(
				request.Messages[0].Content,
				`"execution_status":"finished"`,
			) ||
			!strings.Contains(
				request.Messages[0].Content,
				`"outcome_status":"failed"`,
			) {
			t.Fatalf("authoritative preflight missing: %#v", request.Messages)
		}
		assistantCall := request.Messages[len(request.Messages)-2]
		toolResult := request.Messages[len(request.Messages)-1]
		if assistantCall.Role != modelapi.RoleAssistant ||
			len(assistantCall.ToolCalls) != 1 ||
			assistantCall.ToolCalls[0].Function.Name != CloudDialogueToolTeamTaskStatus ||
			toolResult.Role != modelapi.RoleTool ||
			toolResult.ToolCallID != assistantCall.ToolCalls[0].ID ||
			!strings.Contains(toolResult.Content, `"execution_status":"finished"`) ||
			!strings.Contains(toolResult.Content, `"outcome_status":"failed"`) {
			t.Fatalf("authoritative tool result is not the latest context: %#v", request.Messages)
		}
		return finalEngineResult("new task required"), nil
	}}
	dependencies := testDependencies(
		engine,
		&recordingConversationRepository{},
		config,
	)
	dependencies.Tools = ToolProviderFunc(func(
		_ context.Context,
		_ ToolRequest,
	) ([]Tool, error) {
		tools := make([]Tool, 0, len(CloudDialogueToolNames()))
		for _, name := range CloudDialogueToolNames() {
			toolName := name
			tool := Tool{
				Definition: modelapi.Tool{
					Name:        toolName,
					InputSchema: map[string]any{"type": "object"},
				},
				Run: func(context.Context, ToolInvocation) (ToolResult, error) {
					return ToolResult{Content: `{}`}, nil
				},
			}
			if toolName == CloudDialogueToolTeamTaskStatus {
				tool.Run = func(
					_ context.Context,
					invocation ToolInvocation,
				) (ToolResult, error) {
					statusCalls++
					var input struct {
						TaskID string `json:"task_id"`
					}
					if json.Unmarshal(invocation.Arguments, &input) != nil ||
						input.TaskID != taskID {
						t.Fatalf("status input = %s", invocation.Arguments)
					}
					return ToolResult{
						Content:        `{"task_id":"` + taskID + `","execution_status":"finished","outcome_status":"failed","revision":6,"terminal":true,"plan_id":"` + planID + `","plan_revision":2,"plan_status":"approved"}`,
						RelatedTaskIDs: []string{taskID},
						RelatedPlanIDs: []string{planID},
					}, nil
				}
			}
			tools = append(tools, tool)
		}
		return tools, nil
	})
	runtime := mustTestRuntime(t, dependencies)
	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID:      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
		Messages: []modelapi.Message{
			{
				Role: modelapi.RoleAssistant,
				Content: "Task " + taskID + " is awaiting approval; plan " +
					planID,
			},
			{
				Role:    modelapi.RoleUser,
				Content: "build a separate new deliverable",
			},
		},
		CloudDialogue: &CloudDialogueScope{
			ConnectionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCalls != 1 {
		t.Fatalf("status calls = %d", statusCalls)
	}
}
