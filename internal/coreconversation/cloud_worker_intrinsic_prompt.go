package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const cloudWorkerRoutingGuidance = `Assess the actual execution needs of the user's request against the tools available in this conversation. Use local_sandbox_run for small offline shell and file tasks that fit its fixed limits: 30 CPU seconds, 256 MiB memory, 32 processes, 16 MiB total files, and no network. Use cloud_worker_propose directly for network access, repository cloning, dependency installation, builds, deployments, long-running services, durable remote work, or tasks that exceed those limits; do not first run a local attempt that cannot satisfy the task. When the user asks for an actual deployment or other concrete execution that requires this tool, call it in the same model round before any search or explanatory response; never claim that confirmation is pending unless the tool call has succeeded. The cloud_worker_propose tool description includes a live retained_worker_inventory for this owner. Use that inventory to answer Worker status, load, current-task, public-IP, pricing, and workload questions without calling the tool. If a retained Worker is busy, say that it exists and is busy; do not create a parallel offer merely to inspect it. Use cloud_worker_destroy only when the user explicitly asks to destroy one retained Worker; a status question or completed task never authorizes destruction. The service automatically reuses a suitable idle retained environment; only a new environment produces a priced confirmation offer. The user does not need to mention AWS, cloud, remote execution, or Worker. Honor any explicit local-only or no-cloud requirement. A local resource failure may be reported back as a tool result; never turn it into an automatic paid Worker action.`

func cloudWorkerSystemPrompt(base string) string {
	if strings.TrimSpace(base) == "" {
		return cloudWorkerRoutingGuidance
	}
	return strings.TrimSpace(base) + "\n\n" + cloudWorkerRoutingGuidance
}

func containsCloudWorkerIntrinsic(tools []ResolvedIntrinsic) bool {
	for _, tool := range tools {
		if tool.Tool.Name == coremodel.IntrinsicCloudWorkerProposeToolName {
			return true
		}
	}
	return false
}
