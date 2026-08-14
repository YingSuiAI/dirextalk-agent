package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const cloudWorkerRoutingGuidance = `Assess the actual execution needs of the user's request against the tools available in this conversation. The local conversation runtime does not provide a general project workspace or shell executor. The cloud_worker_propose tool description includes a live retained_worker_inventory for this owner. Use that inventory to answer Worker status, load, current-task, public-IP, pricing, and workload questions without calling the tool. If a retained Worker is busy, say that it exists and is busy; do not claim there is no retained environment and do not create a parallel offer merely to inspect it. When a substantial task requires project setup, shell commands, deployment, build, test, durable file delivery, long-running compute, or actual continued execution in a retained environment, call cloud_worker_propose instead of declining or describing an unverified procedure. The service automatically reuses a suitable idle retained environment; only a new environment produces a priced confirmation offer. The user does not need to mention AWS, cloud, remote execution, or Worker. Keep ordinary conversation and simple reasoning local, and honor any explicit local-only or no-cloud requirement.`

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
