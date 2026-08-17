package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const cloudWorkerRoutingGuidance = `Assess the request against the available tools. Prefer the smallest sufficient tool path. Use specialized tools first: use web_search for lightweight web research, local_sandbox_run for small offline shell or file transformations, and static_site_publish for a self-contained HTML result. Research plus report or static-page generation is not by itself a reason to start a Worker. After a successful web_search, lightweight research or report work must synthesize the available evidence and state any gaps. Do not use Cloud Worker solely to improve completeness, exactness, freshness, or repeat the same research through another path.

The local sandbox is limited to 30 CPU seconds, 256 MiB memory, 32 processes, 16 MiB total files, and no network. Use cloud_worker_propose only for required network or execution unavailable from specialized tools, including repository cloning, dependency installation, builds, deployments, long-running services, durable remote work, or work exceeding those limits. Skip a local attempt that cannot satisfy the task. If the user asks only for a conceptual plan or forbids starting Worker work, answer directly without calling the tool. Follow-up work requiring a Worker's workspace or artifacts must reuse that retained Worker; local_sandbox_run cannot access the Worker filesystem.

Use the live retained_worker_inventory to answer status, load, current-task, public-IP, pricing, and workload questions without a tool call. If a retained Worker is busy, report it instead of creating another offer for inspection. Use cloud_worker_destroy only on an explicit request to destroy one retained Worker. The user does not need to mention AWS, cloud, remote execution, or Worker. Honor explicit local-only or no-cloud requirements. Never turn a local resource failure into an automatic paid Worker action. Do not repeat an identical local_sandbox_run after a local resource failure in the same turn; report the limit or choose a genuinely different path.`

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
