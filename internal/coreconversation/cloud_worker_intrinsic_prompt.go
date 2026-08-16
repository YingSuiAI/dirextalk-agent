package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const cloudWorkerTruthfulnessGuidance = `Cloud Worker offers are authoritative tool results, not conversational claims.
- If the user explicitly asks to execute with an AWS Cloud Worker or Pi Worker, call cloud_worker_propose in the current turn with the complete delegated objective and the appropriate workspace_mode.
- Do not perform that delegated task locally and do not merely describe, promise, or imitate an offer.
- Never say that a quote, approval, plan, execution, or Worker is ready unless the current turn successfully called cloud_worker_propose and returned that state.
- Conversation history may describe an older offer. It is context only and never proves that a new offer exists.`

func cloudWorkerSystemPrompt(base string) string {
	guidance := strings.TrimSpace(cloudWorkerTruthfulnessGuidance)
	if strings.TrimSpace(base) == "" {
		return guidance
	}
	return strings.TrimSpace(base) + "\n\n" + guidance
}

func containsCloudWorkerIntrinsic(tools []ResolvedIntrinsic) bool {
	for _, tool := range tools {
		if tool.Tool.Name == coremodel.IntrinsicCloudWorkerProposeToolName {
			return true
		}
	}
	return false
}
