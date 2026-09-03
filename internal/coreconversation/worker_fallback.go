package coreconversation

import (
	"encoding/json"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// A Worker outcome proves the remote execution, not the rest of the user's
// request. Deterministic fallback never promotes partial model prose or the
// internal Worker report into evidence that a follow-up mutation succeeded.
func workerOutcomeFallback(results []ToolResult, reason TurnFinalizationReason, code, summary string) (string, bool) {
	for i := len(results) - 1; i >= 0; i-- {
		result := results[i]
		if result.ToolName != coremodel.IntrinsicCloudWorkerProposeToolName || result.Validate() != nil {
			continue
		}
		var outcome struct {
			Schema      string `json:"schema"`
			Status      string `json:"status"`
			ExecutionID string `json:"execution_id"`
		}
		if json.Unmarshal([]byte(result.Content), &outcome) != nil || outcome.Schema != "dirextalk.ssh-worker-completion/v1" ||
			!validUUID(outcome.ExecutionID) || (outcome.Status != "succeeded" && outcome.Status != "failed") {
			continue
		}
		completed := "- Worker execution " + outcome.Status + "."
		escape := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "[", "\\[", "]", "\\]", "`", "\\`", "*", "\\*", "_", "\\_")
		for _, reference := range result.References {
			if reference.Kind != "execution_artifact" || reference.RecordKind != "cloud_worker" ||
				reference.ExecutionID != outcome.ExecutionID || reference.Validate() != nil {
				continue
			}
			completed += "\n- [" + escape.Replace(reference.Name) + "](dirextalk-artifact://cloud_worker/" + reference.ArtifactID + ")"
		}
		best := "- The recorded Worker outcome is preserved. Actual billed cost is unavailable; running compute and retained storage may continue to incur charges."
		incomplete := "- The Worker result alone does not confirm requested follow-up actions, such as sending a report.\n- A complete final answer remains unavailable."
		return formatTerminalFallback(completed, best, incomplete, reason, code, summary), true
	}
	return "", false
}
