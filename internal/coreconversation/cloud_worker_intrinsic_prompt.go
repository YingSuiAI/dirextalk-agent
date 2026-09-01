package coreconversation

import (
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const cloudWorkerRoutingGuidance = `Assess the request against the available tools. Prefer the smallest sufficient tool path. Use specialized tools first: use web_search for lightweight web research, local_sandbox_run for small offline shell or file transformations, and static_site_publish for a self-contained HTML result. Research plus report or static-page generation is not by itself a reason to start a Worker. After a successful web_search, lightweight research or report work must synthesize the available evidence and state any gaps. Do not use Cloud Worker solely to improve completeness, exactness, freshness, or repeat the same research through another path.

The local sandbox is limited to 30 CPU seconds, 256 MiB memory, 32 processes, 16 MiB total files, and no network. Use cloud_worker_propose only for required network or execution unavailable from specialized tools, including repository cloning, dependency installation, builds, deployments, long-running services, durable remote work, or work exceeding those limits. Skip a local attempt that cannot satisfy the task. If the user asks only for a conceptual plan or forbids starting Worker work, answer directly without calling the tool. Follow-up work requiring a Worker's workspace or artifacts must reuse that retained Worker; local_sandbox_run cannot access the Worker filesystem.

GitHub MCP is the direct path for advertised reads and only the lightweight writes mcp__github__issue_write, mcp__github__add_issue_comment, and mcp__github__merge_pull_request. Any repository code workflow—including cloning a public or private repository, creating a branch or ref, changing or deleting files, installing dependencies, editing, testing, committing, pushing, or creating or updating a code pull request—must use cloud_worker_propose so it runs behind owner confirmation with the task-scoped GitHub credential. Do not claim that GitHub code changes are unavailable merely because direct MCP file, ref, or pull-request creation tools are intentionally absent.

Before recommending or proposing compute for a named model, resolve and verify the exact available model tag or artifact, quantization or precision, published size, inference or training runtime, operating-system and accelerator/driver compatibility, context length, expected concurrency, and whether CPU offload is permitted. Calculate independent minimum vCPU, system memory, assigned accelerator memory, and disk working set, including model-loading peaks, KV cache or training state, runtime workspace, downloads, expanded or converted copies, caches, temporary files, outputs, and explicit headroom. A fractional GPU contributes only its assigned memory. Never infer capacity from a model family name, count a full physical GPU for a fractional instance, silently assume CPU offload, or recommend a paid instance when an exact artifact or critical compatibility/capacity fact remains unverified. Compare cost only among shapes satisfying every hard minimum. On a follow-up or retry, infer the workload from the full conversation and continue from still-applicable sourced evidence and decisions already established there. A later empty or low-relevance search is not evidence that an earlier verified fact is false; re-check facts that are missing, conflicting, or freshness-sensitive, and revise earlier evidence only when newer authoritative evidence contradicts it.

Call cloud_worker_inventory to read current status, load, current-task, public-IP, pricing, exact workload IDs, and capacity data before selecting, changing, or destroying a retained Worker. A hostname-only change for an already deployed service must use cloud_worker_domain_bind or cloud_worker_domain_unbind with the exact worker_id and workload_id from inventory; never use cloud_worker_propose and never create another Worker quote for that change. Use the exact worker_id returned by inventory for destruction. If a retained Worker is busy, report it instead of creating another offer for inspection. Use cloud_worker_destroy only on an explicit request to destroy one retained Worker. The user does not need to mention AWS, cloud, remote execution, or Worker. Honor explicit local-only or no-cloud requirements. Never turn a local resource failure into an automatic paid Worker action. Do not repeat an identical local_sandbox_run after a local resource failure in the same turn; report the limit or choose a genuinely different path.`

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
