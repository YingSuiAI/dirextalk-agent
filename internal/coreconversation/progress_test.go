package coreconversation

import (
	"reflect"
	"testing"
)

func TestProgressObservationUsesTrustedReferencesAndIgnoresTransportWrappers(t *testing.T) {
	first := ToolResult{
		CallID: "call-a", ToolName: "inspect_room",
		Content:    `{"call_id":"one","updated_at":"2026-08-18T01:00:00Z","healthy":true}`,
		References: []Reference{{Kind: "room", RoomID: "!room:example.test", RoomType: "agent", Title: "Old title", Preview: "old preview"}},
	}
	second := first
	second.CallID = "call-b"
	second.Content = ` { "healthy": true, "updated_at": "later", "call_id": "two" } `
	second.References[0].Title = "New presentation title"
	second.References[0].Preview = "new presentation preview"
	a, structured, err := ProgressObservationForToolResult(first)
	if err != nil || !structured {
		t.Fatalf("first observation structured=%v err=%v", structured, err)
	}
	b, structured, err := ProgressObservationForToolResult(second)
	if err != nil || !structured {
		t.Fatalf("second observation structured=%v err=%v", structured, err)
	}
	if a.EffectiveDigest != b.EffectiveDigest || !reflect.DeepEqual(a.ExternalResourceState, b.ExternalResourceState) {
		t.Fatalf("transport-only wrapper drift changed progress: first=%+v second=%+v", a, b)
	}
	second.References[0].RoomType = "agent_unhealthy"
	c, structured, err := ProgressObservationForToolResult(second)
	if err != nil || !structured || c.EffectiveDigest == b.EffectiveDigest {
		t.Fatalf("resource state did not reset progress: structured=%v err=%v before=%s after=%s", structured, err, b.EffectiveDigest, c.EffectiveDigest)
	}
}

func TestProgressObservationRequiresStructuredRuntimeAuthority(t *testing.T) {
	result := ToolResult{CallID: "call", ToolName: "plain_tool", Content: "unchanged"}
	observation, structured, err := ProgressObservationForToolResult(result)
	if err != nil || structured || !reflect.DeepEqual(observation, ProgressObservation{}) {
		t.Fatalf("unstructured result observation=%+v structured=%v err=%v", observation, structured, err)
	}
}
