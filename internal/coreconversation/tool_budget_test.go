package coreconversation

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

func budgetCalls(names ...string) []ToolCall {
	calls := make([]ToolCall, 0, len(names))
	for index, name := range names {
		calls = append(calls, ToolCall{ID: string(rune('a' + index)), Name: name})
	}
	return calls
}

func TestToolRoundBudgetCostChargesReadOnlyRoundsOnce(t *testing.T) {
	cost, delivers := toolRoundBudgetCost(
		budgetCalls("web_search", "web_search", "web_search", "web_search", "web_search"),
		map[string]bool{"web_search": true},
	)
	if cost != 1 || delivers {
		t.Fatalf("read-only round cost=%d delivers=%v", cost, delivers)
	}

	cost, delivers = toolRoundBudgetCost(
		budgetCalls("web_search", "local_mutation", "another_mutation"),
		map[string]bool{"web_search": true},
	)
	if cost != 3 || delivers {
		t.Fatalf("mixed round cost=%d delivers=%v", cost, delivers)
	}
}

func TestToolRoundBudgetCostExemptsTerminalIntrinsics(t *testing.T) {
	cost, delivers := toolRoundBudgetCost(
		budgetCalls(coremodel.IntrinsicStaticSitePublishToolName),
		nil,
	)
	if cost != 0 || !delivers {
		t.Fatalf("publish round cost=%d delivers=%v", cost, delivers)
	}

	// Read-only intrinsics are charged once per round like extension reads.
	cost, delivers = toolRoundBudgetCost(
		budgetCalls(coremodel.IntrinsicStaticSiteReadToolName, coremodel.IntrinsicCloudWorkerInventoryToolName),
		nil,
	)
	if cost != 1 || delivers {
		t.Fatalf("read-only intrinsic round cost=%d delivers=%v", cost, delivers)
	}

	// Observation intrinsics still cost a call: they can loop.
	cost, delivers = toolRoundBudgetCost(
		budgetCalls(coremodel.IntrinsicCloudWorkerRunToolName, coremodel.IntrinsicCloudWorkerDomainBindToolName),
		nil,
	)
	if cost != 2 || delivers {
		t.Fatalf("observation intrinsic round cost=%d delivers=%v", cost, delivers)
	}
}

func TestReadOnlyExtensionToolsUsesSnapshotReadOnly(t *testing.T) {
	readOnly := ExtensionExecutionSnapshot{
		Selection: ExtensionSelection{Kind: ExtensionMCP, ID: "ro", AllowedTools: []string{"lookup"}},
		ToolNames: []string{"lookup", "search"}, ReadOnly: true,
	}
	writing := ExtensionExecutionSnapshot{
		Selection: ExtensionSelection{Kind: ExtensionMCP, ID: "rw", AllowedTools: []string{"mutate"}},
		ToolNames: []string{"mutate"}, ReadOnly: false,
	}

	names := readOnlyExtensionTools([]ExtensionExecutionSnapshot{readOnly, writing})
	if !names["lookup"] || !names["search"] || names["mutate"] {
		t.Fatalf("read-only extension tool names=%v", names)
	}
}

func TestToolBudgetKeepsADeliveryWindowForTerminalIntrinsics(t *testing.T) {
	const cap = 100

	// Ordinary work stops the moment the budget is spent.
	if !preRoundBudgetFinalizes(cap, cap, false, 0) {
		t.Fatal("a spent budget without a delivery intrinsic must finalize")
	}
	// A standing delivery intrinsic buys the first delivery rounds ...
	if preRoundBudgetFinalizes(cap, cap, true, 0) ||
		preRoundBudgetFinalizes(cap, cap, true, maxPostBudgetToolDeliveryRounds-1) {
		t.Fatal("the delivery window closed early")
	}
	// ... but not an unbounded loop.
	if !preRoundBudgetFinalizes(cap, cap, true, maxPostBudgetToolDeliveryRounds) {
		t.Fatal("the delivery window must close after its bounded rounds")
	}
	// Under budget, nothing finalizes.
	if preRoundBudgetFinalizes(cap-1, cap, false, 0) {
		t.Fatal("a turn with budget left must not finalize")
	}
}

func TestRoundBudgetKeepsTheDeliveringRound(t *testing.T) {
	const cap = 100

	// A round that fits never finalizes.
	if roundBudgetFinalizes(cap-5, cap, 5, false, 0) {
		t.Fatal("a round inside the budget must run")
	}
	// An over-budget round without delivery stops the turn.
	if !roundBudgetFinalizes(cap, cap, 1, false, 0) {
		t.Fatal("an over-budget round without a delivery must finalize")
	}
	// The delivering round runs even with the budget spent, inside the window.
	if roundBudgetFinalizes(cap, cap, 0, true, 0) {
		t.Fatal("a delivering round must run inside the delivery window")
	}
	if roundBudgetFinalizes(cap, cap, 3, true, maxPostBudgetToolDeliveryRounds-1) {
		t.Fatal("a delivering round must run inside the delivery window")
	}
	// Outside the window it stops, even when it delivers.
	if !roundBudgetFinalizes(cap, cap, 0, true, maxPostBudgetToolDeliveryRounds) {
		t.Fatal("the delivery window must close")
	}
}
