package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// toolRoundBudgetCost reports what one model round costs against the turn's
// tool-call budget, and whether the round delivers the turn through a terminal
// intrinsic.
//
// Two rules keep a long task from starving its own delivery step:
//
//   - Read-only work is exploration. A round of parallel reads costs one call,
//     however many reads it contains, so a long research phase cannot spend the
//     budget that the answer itself still needs.
//   - Terminal intrinsics commit the turn, so they cannot extend a tool loop
//     and are never billed. The presence of one is reported separately so the
//     caller can let a delivering round run even when the ordinary budget is
//     already spent; otherwise the model can no longer publish, run, or
//     schedule what it just built.
func toolRoundBudgetCost(
	calls []ToolCall,
	readOnlyExtensions map[string]bool,
) (cost uint32, delivers bool) {
	sawReadOnly := false
	for _, call := range calls {
		switch {
		case coremodel.IsTerminalIntrinsicToolName(call.Name):
			delivers = true
		case coremodel.IsReadOnlyIntrinsicToolName(call.Name), readOnlyExtensions[call.Name]:
			sawReadOnly = true
		default:
			cost++
		}
	}
	if sawReadOnly {
		cost++
	}
	return cost, delivers
}

// finalizationKeepsDeliveryTools reports whether one finalization reason
// stopped the turn before the model could deliver its result. Those
// dispatches keep the terminal intrinsics: publishing a page, creating a
// schedule, or proposing a Worker commits the turn, so the delivered result
// cannot be replaced by a tools-disabled synthesis that only describes it.
func finalizationKeepsDeliveryTools(reason TurnFinalizationReason) bool {
	switch reason {
	case TurnFinalizationInvalidOutput, TurnFinalizationToolBudget:
		return true
	default:
		return false
	}
}

// runtimeSnapshotAdmitsDeliveryIntrinsic reports whether the turn's immutable
// runtime snapshot ever admitted an intrinsic that delivers a result.
func runtimeSnapshotAdmitsDeliveryIntrinsic(snapshot *TurnRuntimeSnapshot) bool {
	if snapshot == nil {
		return false
	}
	for _, tool := range snapshot.IntrinsicTools {
		if coremodel.IsTerminalIntrinsicToolName(tool.Name) {
			return true
		}
	}
	return false
}

// terminalIntrinsics keeps only the delivery intrinsics of an admitted set.
func terminalIntrinsics(tools []ResolvedIntrinsic) []ResolvedIntrinsic {
	result := make([]ResolvedIntrinsic, 0, len(tools))
	for _, tool := range tools {
		if coremodel.IsTerminalIntrinsicToolName(tool.Tool.Name) {
			result = append(result, tool)
		}
	}
	return result
}

// readOnlyExtensionTools names the model-facing tools whose extension snapshot
// is read-only, so MCP and Skill tools are accounted for the same way.
func readOnlyExtensionTools(
	snapshots []ExtensionExecutionSnapshot,
) map[string]bool {
	names := make(map[string]bool)
	for _, snapshot := range snapshots {
		if !snapshot.ReadOnly {
			continue
		}
		for _, name := range append(
			append([]string(nil), snapshot.ToolNames...),
			snapshot.Selection.AllowedTools...,
		) {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				names[trimmed] = true
			}
		}
	}
	return names
}

// preRoundBudgetFinalizes decides whether a turn with a spent tool budget has
// to synthesize now or may still run a delivery round.
//
// The window is bounded: once [maxPostBudgetToolDeliveryRounds] rounds already
// ran with the budget spent, the turn finalizes even if a delivery intrinsic is
// still advertised, so a model that never delivers cannot loop on the budget.
func preRoundBudgetFinalizes(
	spent uint32,
	cap uint32,
	deliveryAvailable bool,
	postBudgetRounds uint32,
) bool {
	if spent < cap {
		return false
	}
	return !deliveryAvailable || postBudgetRounds >= maxPostBudgetToolDeliveryRounds
}

// roundBudgetFinalizes decides whether the round the model just produced fits
// the remaining budget.
//
// A round that delivers through a terminal intrinsic may exceed it: the
// intrinsic commits the turn, so it cannot extend the loop, and refusing it
// would throw away the work the user asked for (publishing the page, running
// the Worker, creating the schedule).
func roundBudgetFinalizes(
	spent uint32,
	cap uint32,
	roundCost uint32,
	delivers bool,
	postBudgetRounds uint32,
) bool {
	if delivers {
		// Delivery is free and commits the turn, so it may spend the last of the
		// budget. The window is still bounded, because a delivery that keeps
		// failing must end in a synthesis instead of looping.
		return spent >= cap && postBudgetRounds >= maxPostBudgetToolDeliveryRounds
	}
	return spent+roundCost > cap
}
