package coreconversation

import (
	"context"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestTurnDispatchDirectiveOnlyReducesAdmittedCapabilities(t *testing.T) {
	profile := testTurnSnapshot()
	intrinsic := ResolvedIntrinsic{
		Tool: coremodel.Tool{Name: coremodel.IntrinsicStaticSitePublishToolName, InputSchema: map[string]any{"type": "object"}},
		Execute: func(_ context.Context, _ IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
			return IntrinsicExecutionResult{}, nil
		},
	}
	selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"web_search"}}
	extension := ExtensionExecutionSnapshot{Selection: selection, ToolNames: []string{"web_search"}}
	runtime, err := NewTurnRuntimeSnapshot("frozen", profile, []ResolvedIntrinsic{intrinsic}, strings.Repeat("b", 64), "")
	if err != nil {
		t.Fatal(err)
	}

	valid := []TurnDispatchDirective{
		DefaultTurnDispatchDirective(),
		NewTurnDispatchDirective(TurnDispatchGuidanceLoopNudge, TurnDispatchToolsAdmitted, ""),
		NewTurnDispatchDirective(TurnDispatchGuidanceLoopSynthesis, TurnDispatchToolsNone, ""),
		NewTurnDispatchDirective(TurnDispatchGuidanceNone, TurnDispatchToolsAdmitted, "web_search"),
		NewTurnDispatchDirective(TurnDispatchGuidanceNone, TurnDispatchToolsAdmitted, coremodel.IntrinsicStaticSitePublishToolName),
	}
	for _, directive := range valid {
		if err = directive.ValidateFor(runtime, []ExtensionExecutionSnapshot{extension}); err != nil || directive.Digest() == "" {
			t.Fatalf("valid directive=%+v err=%v", directive, err)
		}
	}

	invalid := []TurnDispatchDirective{
		NewTurnDispatchDirective(TurnDispatchGuidanceLoopSynthesis, TurnDispatchToolsAdmitted, ""),
		NewTurnDispatchDirective(TurnDispatchGuidanceNone, TurnDispatchToolsNone, ""),
		NewTurnDispatchDirective(TurnDispatchGuidanceLoopNudge, TurnDispatchToolsAdmitted, "web_search"),
		NewTurnDispatchDirective(TurnDispatchGuidanceNone, TurnDispatchToolsAdmitted, "not_admitted"),
		{Version: TurnDispatchDirectiveVersion + 1, Guidance: TurnDispatchGuidanceNone, ToolMode: TurnDispatchToolsAdmitted},
	}
	for _, directive := range invalid {
		if err = directive.ValidateFor(runtime, []ExtensionExecutionSnapshot{extension}); err == nil {
			t.Fatalf("invalid directive accepted: %+v", directive)
		}
	}
}
