package coreconversation

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func TestScheduledWorkflowAllowsOnlyDeclaredOrderedSinglePassCalls(t *testing.T) {
	tests := []struct {
		name       string
		capability coretask.ScheduledCapability
		calls      []string
		wantReady  bool
	}{
		{name: "note has no tools", capability: coretask.ScheduledCapabilityScheduledNote, wantReady: true},
		{name: "summary direct room", capability: coretask.ScheduledCapabilityChatSummary, calls: []string{"mcp__message__dirextalk_messages_list"}, wantReady: true},
		{name: "summary lookup first", capability: coretask.ScheduledCapabilityChatSummary, calls: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list"}, wantReady: true},
		{name: "web research", capability: coretask.ScheduledCapabilityWebResearch, calls: []string{"web_search"}, wantReady: true},
		{name: "room message direct room", capability: coretask.ScheduledCapabilityRoomMessage, calls: []string{"mcp__message__dirextalk_messages_send"}, wantReady: true},
		{name: "contact report search", capability: coretask.ScheduledCapabilityContactReport, calls: []string{"mcp__message__dirextalk_contacts_search"}, wantReady: true},
		{name: "room member direct room", capability: coretask.ScheduledCapabilityRoomMemberReport, calls: []string{"mcp__message__dirextalk_room_members_list"}, wantReady: true},
		{name: "summary delivery", capability: coretask.ScheduledCapabilityChatSummaryDelivery, calls: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send"}, wantReady: true},
		{name: "web digest delivery", capability: coretask.ScheduledCapabilityWebDigestDelivery, calls: []string{"web_search", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send"}, wantReady: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := newScheduledWorkflowState(test.capability)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range test.calls {
				if err = state.acceptCall(ToolCall{Name: name, Arguments: `{}`}, &ToolResult{}); err != nil {
					t.Fatalf("call %q rejected: %v", name, err)
				}
			}
			if state.ReadyForFinal() != test.wantReady {
				t.Fatalf("state=%+v ready=%v", state, state.ReadyForFinal())
			}
		})
	}
}

func TestScheduledWorkflowPendingCallIsAdmittedButNotComplete(t *testing.T) {
	call := ToolCall{ID: "call-1", Name: "web_search", Arguments: `{"query":"dirextalk"}`}
	workflow := NewScheduledTurnWorkflow(coretask.ScheduledCapabilityWebResearch)
	state, err := scheduledWorkflowStateFor(workflow, map[string]turnToolCallAuthority{
		call.ID: {call: call, state: turnToolCallPending, callSequence: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.ReadyForFinal() || state.RequiresToolFreeFinalization() {
		t.Fatal("pending admitted call was treated as completed")
	}
	result := ToolResult{CallID: call.ID, ToolName: call.Name, Content: "done", Outcome: ToolOutcomeSuccess}
	state, err = scheduledWorkflowStateFor(workflow, map[string]turnToolCallAuthority{
		call.ID: {call: call, state: turnToolCallTerminal, result: &result, callSequence: 1, resultSequence: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !state.ReadyForFinal() || !state.RequiresToolFreeFinalization() {
		t.Fatal("terminal result did not make scheduled workflow ready for finalization")
	}
}

func TestScheduledWorkflowRejectsRepeatOrderAndMutationEscape(t *testing.T) {
	tests := []struct {
		name       string
		capability coretask.ScheduledCapability
		calls      []string
	}{
		{name: "summary read repeats", capability: coretask.ScheduledCapabilityChatSummary, calls: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_list"}},
		{name: "summary lookup after read", capability: coretask.ScheduledCapabilityChatSummary, calls: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}},
		{name: "delivery send before read", capability: coretask.ScheduledCapabilityChatSummaryDelivery, calls: []string{"mcp__message__dirextalk_messages_send"}},
		{name: "delivery mutation repeats", capability: coretask.ScheduledCapabilityChatSummaryDelivery, calls: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send", "mcp__message__dirextalk_messages_send"}},
		{name: "web digest sends before search", capability: coretask.ScheduledCapabilityWebDigestDelivery, calls: []string{"mcp__message__dirextalk_messages_send"}},
		{name: "undeclared knowledge", capability: coretask.ScheduledCapabilityWebResearch, calls: []string{"knowledge_search"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := newScheduledWorkflowState(test.capability)
			if err != nil {
				t.Fatal(err)
			}
			for index, name := range test.calls {
				err = state.acceptCall(ToolCall{Name: name, Arguments: `{}`}, nil)
				if err != nil {
					if index != len(test.calls)-1 {
						t.Fatalf("call %d %q rejected before expected boundary: %v", index, name, err)
					}
					return
				}
			}
			t.Fatal("invalid sequence was accepted")
		})
	}
}

func TestScheduledChannelCommentsRequireDistinctSelectedPostIdentity(t *testing.T) {
	state, err := newScheduledWorkflowState(coretask.ScheduledCapabilityChannelDigest)
	if err != nil {
		t.Fatal(err)
	}
	posts := ToolResult{References: []Reference{
		{Kind: "channel_post", RoomID: "!channel:example.test", ChannelID: "channel-1", PostID: "post-1"},
		{Kind: "channel_post", RoomID: "!channel:example.test", ChannelID: "channel-1", PostID: "post-2"},
	}}
	if err = state.acceptCall(ToolCall{Name: "mcp__message__dirextalk_channel_posts_list", Arguments: `{"room_id":"!channel:example.test"}`}, &posts); err != nil {
		t.Fatal(err)
	}
	if !state.ReadyForFinal() {
		t.Fatal("channel posts read did not make digest ready for final Markdown")
	}
	if err = state.acceptCall(ToolCall{Name: "mcp__message__dirextalk_channel_comments_list", Arguments: `{"post_id":"post-1","limit":20}`}, nil); err != nil {
		t.Fatalf("selected post rejected: %v", err)
	}
	if err = state.acceptCall(ToolCall{Name: "mcp__message__dirextalk_channel_comments_list", Arguments: `{"limit":50,"post_id":"post-1"}`}, nil); err == nil {
		t.Fatal("same post escaped at-most-once through argument variation")
	}
	if err = state.acceptCall(ToolCall{Name: "mcp__message__dirextalk_channel_comments_list", Arguments: `{"post_id":"post-3"}`}, nil); err == nil {
		t.Fatal("unselected post was accepted")
	}
	if err = state.acceptCall(ToolCall{Name: "mcp__message__dirextalk_channel_comments_list", Arguments: `{"post_id":"post-2"}`}, nil); err != nil {
		t.Fatalf("second distinct selected post rejected: %v", err)
	}
}

func TestStaticSiteCorrectionPermitsOnlyOneForcedPublish(t *testing.T) {
	for _, calls := range [][]ToolCall{
		{{Name: "knowledge_search", Arguments: `{}`}},
		{{Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}, {Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}},
		{{Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}, {Name: "web_search", Arguments: `{}`}},
		{{Name: "web_search", Arguments: `{}`}, {Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}},
	} {
		if validateStaticSiteCorrectionCalls(coremodel.IntrinsicStaticSitePublishToolName, calls) == nil {
			t.Fatalf("invalid correction calls accepted: %+v", calls)
		}
	}
	if err := validateStaticSiteCorrectionCalls(coremodel.IntrinsicStaticSitePublishToolName, []ToolCall{{Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}}); err != nil {
		t.Fatalf("single correction rejected: %v", err)
	}
}

func TestTurnRuntimeSnapshotBindsClosedScheduledWorkflow(t *testing.T) {
	workflow := NewScheduledTurnWorkflow(coretask.ScheduledCapabilityChatSummary)
	if workflow.Validate() != nil {
		t.Fatalf("workflow=%+v", workflow)
	}
	invalid := workflow
	invalid.ScheduledCapability = "future"
	if invalid.Validate() == nil {
		t.Fatalf("unknown workflow accepted: %+v", invalid)
	}
	if NewScheduledTurnWorkflow(coretask.ScheduledCapability("")).Validate() == nil {
		t.Fatal("empty scheduled workflow accepted")
	}
}
