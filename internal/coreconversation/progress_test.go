package coreconversation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
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

func TestProgressObservationUsesStableWebAndKnowledgeEvidenceIdentity(t *testing.T) {
	contentDigest := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		tool      string
		reference Reference
	}{
		{
			name: "web source", tool: "web_search",
			reference: Reference{Kind: "web_source", SourceID: "https://example.test/report", ContentDigest: contentDigest, Title: "First title", Preview: "First excerpt"},
		},
		{
			name: "knowledge chunk", tool: "knowledge_search",
			reference: Reference{Kind: "knowledge_chunk", SourceID: uuid.NewString(), ChunkID: "section:4", ContentDigest: contentDigest, Title: "Source name", Preview: "First snippet"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := ToolResult{CallID: "call-a", ToolName: test.tool, Content: `{"items":[{"score":0.99}]}`, References: []Reference{test.reference}}.
				WithObservation(ToolOutcomeSuccess, "first presentation", ToolMutationNone)
			second := first
			second.CallID = "call-b"
			second.Content = `{"items":[{"score":0.51}],"query":"a paraphrase"}`
			second.Summary = "rewritten presentation"
			second.References = cloneReferences(first.References)
			second.References[0].Title = "Rewritten title"
			second.References[0].Preview = "Rewritten snippet"
			a, structured, err := ProgressObservationForToolResult(first)
			if err != nil || !structured {
				t.Fatalf("first structured=%v err=%v", structured, err)
			}
			b, structured, err := ProgressObservationForToolResult(second)
			if err != nil || !structured || a.EffectiveDigest != b.EffectiveDigest {
				t.Fatalf("presentation/query rewrite escaped semantic identity: first=%+v second=%+v structured=%v err=%v", a, b, structured, err)
			}
			second.References[0].ContentDigest = strings.Repeat("b", 64)
			c, structured, err := ProgressObservationForToolResult(second)
			if err != nil || !structured || c.EffectiveDigest == b.EffectiveDigest {
				t.Fatalf("new evidence digest was not progress: before=%s after=%s structured=%v err=%v", b.EffectiveDigest, c.EffectiveDigest, structured, err)
			}
		})
	}
}

func TestProgressObservationPresentationCannotReorderEvidenceIdentity(t *testing.T) {
	first := ToolResult{
		CallID: "call-a", ToolName: "inspect_rooms", Content: `{"rooms":2}`,
		References: []Reference{
			{Kind: "room", RoomID: "!alpha:example.test", RoomType: "group", Title: "Zulu", Preview: "second presentation"},
			{Kind: "room", RoomID: "!beta:example.test", RoomType: "group", Title: "Alpha", Preview: "first presentation"},
		},
	}.WithObservation(ToolOutcomeSuccess, "first presentation", ToolMutationNone)
	second := first
	second.CallID = "call-b"
	second.References = cloneReferences(first.References)
	second.References[0].Title, second.References[0].Preview = "Alpha", "first presentation"
	second.References[1].Title, second.References[1].Preview = "Zulu", "second presentation"
	a, structured, err := ProgressObservationForToolResult(first)
	if err != nil || !structured {
		t.Fatalf("first structured=%v err=%v", structured, err)
	}
	b, structured, err := ProgressObservationForToolResult(second)
	if err != nil || !structured || a.EffectiveDigest != b.EffectiveDigest {
		t.Fatalf("presentation ordering changed semantic digest: first=%+v second=%+v structured=%v err=%v", a, b, structured, err)
	}
}

func TestCanonicalWebSourceIdentityRejectsEquivalentSpellings(t *testing.T) {
	want := "https://example.test/path?a=1&b=2#ignored"
	canonical, ok := CanonicalWebSourceID(want)
	if !ok || canonical != "https://example.test/path?a=1&b=2" {
		t.Fatalf("canonical=%q ok=%v", canonical, ok)
	}
	for _, equivalent := range []string{
		"HTTPS://EXAMPLE.TEST:443/path?b=2&a=1",
		"https://example.test./path?a=1&b=2#other",
	} {
		got, valid := CanonicalWebSourceID(equivalent)
		if !valid || got != canonical {
			t.Fatalf("equivalent=%q canonical=%q valid=%v want=%q", equivalent, got, valid, canonical)
		}
		if (Reference{Kind: "web_source", SourceID: equivalent, ContentDigest: strings.Repeat("a", 64)}).Validate() == nil {
			t.Fatalf("noncanonical identity was accepted: %q", equivalent)
		}
	}
}

func TestProgressObservationCanonicalizesPaginationMutationAndWorkerState(t *testing.T) {
	room := Reference{Kind: "room", RoomID: "!progress:example.test", RoomType: "group"}
	page := ToolResult{CallID: "page-a", ToolName: "messages_list", Content: `{"items":[1]}`, Cursor: "cursor-a", References: []Reference{room}}.
		WithObservation(ToolOutcomePartial, "one page", ToolMutationNone)
	first, structured, err := ProgressObservationForToolResult(page)
	if err != nil || !structured {
		t.Fatalf("page structured=%v err=%v", structured, err)
	}
	page.CallID, page.Content, page.Summary = "page-b", `{"items":[1],"wrapper":"changed"}`, "rewritten page"
	same, structured, err := ProgressObservationForToolResult(page)
	if err != nil || !structured || same.EffectiveDigest != first.EffectiveDigest {
		t.Fatalf("same cursor/evidence changed identity: first=%+v same=%+v err=%v", first, same, err)
	}
	page.Cursor = "cursor-b"
	next, structured, err := ProgressObservationForToolResult(page)
	if err != nil || !structured || next.EffectiveDigest == first.EffectiveDigest {
		t.Fatalf("new cursor was not progress: first=%+v next=%+v err=%v", first, next, err)
	}

	receipt := Reference{Kind: "room", RoomID: "!mutation:example.test", RoomType: "group"}
	mutation := ToolResult{CallID: "mut-a", ToolName: "messages_send", Content: `{"event_id":"$one"}`, StateChanged: true, References: []Reference{receipt}}.
		WithObservation(ToolOutcomeSuccess, "sent", ToolMutationChanged)
	mutA, structured, err := ProgressObservationForToolResult(mutation)
	if err != nil || !structured {
		t.Fatalf("mutation structured=%v err=%v", structured, err)
	}
	mutation.CallID, mutation.Content, mutation.Summary = "mut-b", `{"event_id":"$rewrapped"}`, "sent again"
	mutB, structured, err := ProgressObservationForToolResult(mutation)
	if err != nil || !structured || mutA.EffectiveDigest != mutB.EffectiveDigest {
		t.Fatalf("same authoritative mutation resource escaped identity: first=%+v second=%+v err=%v", mutA, mutB, err)
	}
	mutation.References[0].RoomType = "group_updated"
	mutC, structured, err := ProgressObservationForToolResult(mutation)
	if err != nil || !structured || mutC.EffectiveDigest == mutB.EffectiveDigest {
		t.Fatalf("new resource state was not progress: before=%+v after=%+v err=%v", mutB, mutC, err)
	}

	taskID, planID, runID, executionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	worker := ToolResult{CallID: "worker-a", ToolName: "cloud_worker_propose", Content: `{"status":"running"}`, References: []Reference{{
		Kind: "execution_run", AccountGeneration: 1, TaskID: taskID, PlanID: planID, PlanRevision: 1,
		RunID: runID, RunRevision: 1, ExecutionID: executionID, Status: "running",
	}}}.WithObservation(ToolOutcomeSuccess, "worker running", ToolMutationChanged)
	workerA, structured, err := ProgressObservationForToolResult(worker)
	if err != nil || !structured {
		t.Fatalf("worker structured=%v err=%v", structured, err)
	}
	worker.CallID, worker.Content, worker.Summary = "worker-b", `{"status":"running","poll":2}`, "still running"
	workerB, structured, err := ProgressObservationForToolResult(worker)
	if err != nil || !structured || workerA.EffectiveDigest != workerB.EffectiveDigest {
		t.Fatalf("same worker state escaped identity: first=%+v second=%+v err=%v", workerA, workerB, err)
	}
	worker.References[0].RunRevision++
	worker.References[0].Status = "succeeded"
	workerC, structured, err := ProgressObservationForToolResult(worker)
	if err != nil || !structured || workerC.EffectiveDigest == workerB.EffectiveDigest {
		t.Fatalf("worker transition was not progress: before=%+v after=%+v err=%v", workerB, workerC, err)
	}
}
