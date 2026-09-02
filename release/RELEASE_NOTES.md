# Dirextalk Agent release notes

## Unreleased

## v1.0.199

1. Keep Cloud Worker runtime, task status, logs, and artifacts under reboot-persistent storage, install and verify the CPU coding-tool baseline once per Worker, and recover retained results without unrelated fresh AWS discovery.
2. Select AWS's official Ubuntu NVIDIA DLAMI for supported GPU Workers, dynamically include its live root-snapshot minimum in the confirmed EBS quote, and reject incompatible GPU families or post-confirmation image growth before launch.
3. Allow explicitly requested cleanup of stale Busy Workers while preserving the active-execution destroy fence.

## v1.0.198

1. Preserve the accepted runtime snapshot when a terminal Cloud Worker enters Central synthesis, preventing context-bound extension guidance from causing a runtime incompatibility failure after successful Worker completion.

## v1.0.197

1. Treat Cloud Worker terminal stdout as internal evidence and require Central to synthesize a concise user-facing response in the latest user's language instead of copying the report.
2. Stop creating generic completion-report artifacts for new Worker runs and hide historical stdout, stderr, final-report, completion-report, and final JSON transport files from Central while preserving requested file deliverables and server-side diagnostics.

## v1.0.196

1. Validate new or stored GitHub PATs atomically when enabling the integration, discover the official hosted GitHub MCP catalog, and expose safe reads plus explicit issue, comment, and pull-request merge operations without leaking credentials or replaying ambiguous writes.
2. Route repository clone, branch, edit, test, commit, push, and code pull-request workflows through the confirmation-gated Cloud Worker with its task-scoped GitHub credential, and fix the embedded Git credential configuration used for authenticated private repository access.

## v1.0.195

1. Keep Web Search evidence private and remove the separate source list from terminal Agent messages, while retaining concise descriptive Markdown links in the answer body.

## v1.0.194

1. Require DeepSeek V4 thinking requests to use standard structured tool choice, and quarantine additional DSML, XML, and model-template text tool envelopes without parsing or executing them.
2. Preserve bounded recovery after repeated text-shaped tool output so a failed tool result still reaches a normal tools-disabled final response instead of stalling the turn.

## v1.0.193

1. Preflight retained Worker domain bindings against the existing Route53 A record before any Worker, security-group, workload-state, or DNS mutation, and report differing IPv4 or TTL values as an actionable unchanged tool outcome instead of an unknown mutation.

## v1.0.192

1. Accept live AWS instance specifications whose actual vCPU or system memory exceeds the request schema's minimum-field limits, allowing large multi-GPU shapes to satisfy verified model workloads.

## v1.0.191

1. Continue model-deployment retries from the full conversation and retain still-applicable sourced evidence instead of treating an empty or low-relevance search as contradictory evidence.
2. Report AWS compute-selection and pricing failures proven to occur before proposal persistence as redacted unchanged outcomes, including the safe failing stage, while keeping unproven mutation failures unknown.

## v1.0.190

1. Require named model workloads to verify the exact artifact, runtime compatibility, context, concurrency, offload policy, and independent CPU, system-memory, accelerator-memory, and disk working sets before proposing paid compute.
2. Select and reuse GPU Workers only when their live assigned accelerator memory satisfies the verified minimum, including fractional GPU shapes, and expose the concrete accelerator name and memory in public plans.
3. Add the default model-deployment sizing Skill and preserve bounded rejected Worker configuration context for later conversation turns.

## v1.0.189

1. Detect AWS vCPU quota exhaustion without retrying deterministic launch failures, request the required quota increase through Service Quotas, and surface actionable terminal feedback instead of leaving Cloud Worker provisioning stuck.
2. Propagate terminal tool and task failures to the client through durable turn completion, including after client disconnects or runtime lease recovery.
3. Keep failed or incomplete Cloud Worker artifacts destroyable while preserving exact resource ownership and mutation fences.

## v1.0.188

1. Support GPU, Neuron, FPGA, media, and any-accelerator Cloud Worker requirements through live AWS instance metadata while preventing incompatible retained Worker reuse.
2. Raise interactive conversations to 24 model rounds, 20 minutes, and 20 tool calls, while preserving a final tool-free summary when a limit is reached.
3. Return sanitized failed-tool observations to the model so it can continue or summarize completed work; keep persistence, authority, and consistency failures terminal.

## v1.0.187

1. Continue bounded GitHub MCP reads across paginated tool results, accept safe embedded text resources, and keep provider payloads, cursors, arguments, and credentials out of public tool events.
2. Quarantine text-shaped tool-call envelopes and retry once through the structured protocol without executing model text; keep DeepSeek thinking requests compatible by omitting the unsupported `tool_choice` field.

## v1.0.186

1. Preserve existing Worker plans, confirmations, and proposal replays across upgrades from v1.0.184 and v1.0.185 without rewriting historical authorization.
2. Keep GitHub optional: unconfigured or disabled GitHub does not block ordinary Worker tasks or resolve their credentials, while explicitly bound tasks retain their credential-version checks.

## v1.0.185

1. Add encrypted, owner- and revision-fenced GitHub PAT configuration, official read-only GitHub MCP browsing, and confirmed Cloud Worker Git/PR credential delivery.
2. Improve bounded Pi subagent reliability and normalize Web Search evidence into concise source-backed synthesis instead of raw provider fragments.

## v1.0.184

1. Project partial Cloud Worker records as provisioning instead of available so the server page reports their real lifecycle state.
2. Allow owner-confirmed server deletion to reach the serialized Worker destroy fence for orphaned provisioning records, while active creation remains protected by the provider lock.

## v1.0.183

1. Make formal release verification provision and capability-check its own digest-pinned pgvector PostgreSQL 18 container, eliminating external test-database image drift.
2. Default local Agent stacks to the same pgvector baseline required by migrations and Knowledge vector storage.
3. Refresh the original Cloud Worker quote references when a task is canceled so both the offer card and terminal message show the authoritative final state.

## v1.0.182

1. Select a default subnet only from availability zones that currently offer the confirmed EC2 instance type, preventing unsupported-zone launch loops.
2. Terminalize deterministic AWS client rejections instead of treating them as ambiguous mutations, while preserving read-back recovery for genuinely uncertain outcomes.
3. Refresh the original Cloud Worker quote references as confirmation and execution advance so clients no longer display an authorized run as pending confirmation.

## v1.0.181

1. Exclude the primary Agent node's immutable backend-service row from server artifact totals so summary counts match the user-visible artifact list.

## v1.0.180

1. Make retained-service domain binding publish a complete Worker HTTPS route by reconciling the pinned-SSH Caddy proxy, public 80/443 rules, Route53 record, and direct-to-Worker TLS health before committing success.
2. Keep failed publication stages fenced and retryable, and never replace a pre-existing unmanaged Worker Caddy configuration.

## v1.0.179

1. Return exact retained-service workload IDs and bounded status details from `cloud_worker_inventory` so hostname changes can target the already deployed service.
2. Reject hostname-only changes for existing services before pricing when the model selects `cloud_worker_propose`, and direct the turn to `cloud_worker_domain_bind` or `cloud_worker_domain_unbind` instead of creating another Worker quote.

## v1.0.178

1. Enforce durable convergence for scheduled and constrained workflows so admitted Message MCP and Web Search steps complete before synthesis, repeated no-progress paths terminate, and successful turns finalize as nonempty Markdown without exposing hidden reasoning.
2. Persist versioned execution policies, tool observations, and compact working context across retries, restarts, lease transfer, and steering while preserving validated constraints and resource identities.
3. Bound model-provider latency and degrade optional memory-recall failures without discarding otherwise valid Native turn progress.
4. Keep Worker artifact reads outside inventory cleanup and use Dirextalk as the canonical primary server name without changing external resource identities.

## v1.0.177

1. Persist each model dispatch directive under the current Turn lease so loop guidance, forced admitted tools, and final synthesis survive retry and restart without expanding the frozen runtime.
2. Route Chat and StreamChat through the same durable Turn execution owner as StartTurn, preserving ordered lifecycle replay while RPC disconnect only detaches observation.
3. Adopt Agent Data Plane V2 server inventory scopes so correctly scoped owner tickets can discover server and artifact operations with typed missing-scope errors.

## v1.0.176

1. Distinguish self-contained scheduled notes from Matrix and Web summaries, require successful external reads before claiming data is absent, return nonempty Markdown, and render Web citations as descriptive links.

## v1.0.175

1. Give each scheduled capability a trusted single-pass tool sequence so summaries and research stop after one read or search and delivery stops after one send, while retaining Markdown-only output.

## v1.0.174

1. Admit scheduled Message MCP and Web Search turns with their durable owner fence without fabricating an invalid Product Capability call context.

## v1.0.173

1. Keep the filesystem-isolated timezone regression compatible with supported Go toolchains by resolving GOROOT through `go env` and failing closed on invalid zoneinfo sources.

## v1.0.172

1. Require supported natural-language schedule creation to invoke `agent_schedule_create` exactly once, and fail closed instead of committing a model-invented schedule ID or success receipt.
2. Persist conversation, tool, and embedding defaults independently in stable profile creation order, preserving valid selections while advancing and wrapping after an invalid or deleted selection and recovering legacy-null bindings.
3. Resolve schedule creation and every occurrence through the converged conversation default so configured profiles remain usable without freezing the creating Turn's model or changing Markdown-only scheduled output.

## v1.0.171

1. Resolve each Native scheduled occurrence against the current default conversation model while exact replay and reclaim retain the committed occurrence snapshot.
2. Pin the credential version, request dialect, and model kind with the rest of the execution contract so scheduled turns can enter the model and use their captured Message MCP or Web Search tool closure.
3. Reject unavailable defaults without partial occurrence state and expose bounded scheduled-snapshot or turn-admission failures without leaking provider details.

## v1.0.170

1. Embed timezone data and execute due schedules through real durable Native Agent turns with immutable occurrence and timezone context.
2. Admit exactly nine scheduled workflows, including ordered multi-source `web_digest_delivery`, with no generic extension escape hatch.
3. Pin persisted and live tools to each workflow's exact closure, disable Core intrinsics for background turns, and retain durable loop convergence without blindly retrying unknown writes.
4. Expose successful schedule results and history as the committed assistant Markdown only, without JSON configuration or duplicate transcript messages.

## v1.0.169

1. Report the immutable Agent release version from the unauthenticated internal health endpoint without coupling version observation to runner readiness.
2. Require OCI identity, all three binary versions, and the live Agent HTTP release version to match before a stable image or `latest` tag can succeed.

## v1.0.168

1. Expose each durable Turn identity on its Agent-owned conversation history messages so clients can reconcile optimistic response bubbles with server-owned message IDs across active recovery and terminal readback.

## v1.0.167

1. Execute retained Worker Route 53 bind and unbind tools directly from the authoritative Native turn without a second client confirmation, while preserving exact identity revalidation, provider read-back, and idempotent retry after commit failure.
2. Reject hostnames that are not owned by a matching public Route 53 hosted zone in the current verified AWS account with explicit correctable guidance and no DNS write.

## v1.0.166

1. Add durable Native Agent tools to bind or unbind Route 53 domains for retained Worker services after deployment, with exact identity fencing, explicit confirmation, replay-safe recovery, and provider read-back.
2. Limit each owner account generation to four retained SSH Workers and report the updated capacity consistently.

## v1.0.165

1. Restore missing `cpu`, `memory`, and `pids` controllers from each runner's own delegated cgroup during readiness, while preserving fail-closed validation and the existing host delegation boundary.

## v1.0.164

1. Classify Message MCP tools from complete standard annotations, retain the catalog through bounded transient discovery failures, omit unavailable catalogs without blocking ordinary chat, and retry only annotated reads while never replaying mutations after ambiguous outcomes.
2. Require an explicit provider request dialect and allow one physical provider retry only before any output is visible, while freezing the complete admitted runtime and fencing every attempt across restart and lease transfer.
3. Detect durable no-progress runtime loops from structured observations and preserve a schema-constrained working context whose user constraints and validated resource or receipt identities cannot be rewritten during compaction.
4. Adopt the generated Agent Data Plane V2 operation, error, and SSE contracts with closed redacted error envelopes, explicit operation/turn/conversation identities, validated cursors, durable replay, and terminal projections.

## v1.0.163

1. Resolve Message MCP conversation references against validated Matrix room IDs and retain bounded reference aggregation.

## v1.0.162

1. Restore Native Agent access to Message Server MCP tools by loading the stable protected Agent token, while preventing ambiguous mutation retries and preserving tool snapshots across Agent restarts.
2. Filter AWS Price List candidates through the deployment Region's current EC2 instance-type offerings before describing their specifications, so retired SKUs cannot abort Worker proposals.
3. Classify AWS compute-selection failures by pricing, offerings, and instance-type description stages without exposing provider credentials or signed request details.

## v1.0.161

1. Make Native Agent session tickets, forced refresh, SSE cursor validation, replay, and terminal outcomes deterministic across expiry, reconnect, and ambiguous mutations.
2. Keep OpenAI-compatible model discovery and conversation dispatch on one API root, reject invalid HTML provider responses, and preserve precise non-replayable failure outcomes.
3. Bind Cloud Worker pricing, proposal, Route 53, EC2, and execution to the authenticated deployment-node Region while retaining exact credential account, identity, and revision fences.
4. Bound Native turn execution, provider streams, tool loops, sandbox output, and remote result collection while preserving durable recovery without duplicate SSH execution.
5. Preserve current model lifecycle, pinned Skill integrity, tool contracts, and reasoning/event projections across historical use and resumed conversations.

## v1.0.158

1. Force the provider-native `static_site_publish` tool choice after its dedicated invalid-HTML correction, retaining that retry across partial output and clearing it after the next valid intrinsic result.
2. Route malformed bounded arguments from a known intrinsic into its existing correctable result without weakening unknown or extension tool validation.
3. Project OpenRouter's positive direct or nested `max_completion_tokens` into the closed public model catalog.

## v1.0.157

1. Continue from durable partial model output when a provider stream truncates, fails, or idles after producing progress, while preserving zero-delta failures as terminal and never dispatching a cut-off tool call.

## v1.0.156

1. Continue output-limited responses from an explicit model-visible suffix request so long reasoning, text, and tool work resume without restarting or repeating prior fragments.
2. Correct an invalid static-page call by requesting the complete HTML argument immediately, without another analysis or draft loop.

## v1.0.155

1. Continue provider output-limit responses from durable text and reasoning fragments with the full accepted tool context, while keeping true transport truncation distinct and never executing a cut-off tool call.
2. Raise the Native conversation emergency fuse to 500 provider dispatches and 24 hours of cumulative model-active time so it does not constrain legitimate long-running work.

## v1.0.154

1. Recover narrowly from exact repeated tool action/result loops: preserve every accepted tool during the first correction, then use one tool-free synthesis pass only if the same exact or A/B loop continues; different actions or results and post-steer work remain fully capable.

## v1.0.153

1. Keep completed lightweight Web Search research, summaries, reports, and static pages off Cloud Worker while preserving escalation for required builds, deployments, services, and unavailable execution capabilities.

## v1.0.152

1. Replay one provider assistant response containing reasoning, content, and multiple tool calls as its original batch followed by matching tool results, preserving provider-compatible order across confirmation and restart.
2. Treat OpenAI-compatible `finish_reason=length` as a truncated response after preserving its final delta, rather than committing an incomplete reasoning-only response as successful.

## v1.0.151

1. Guide Web Search turns to use one sufficiently broad query, reserve follow-up searches for distinct missing facts, and synthesize available evidence instead of looping over equivalent queries for exhaustive confirmation.

## v1.0.150

1. Prefer existing lightweight web research, local transformation, and static-site tools before proposing a paid Cloud Worker; network-backed research or HTML output alone no longer justifies remote execution.

## v1.0.149

1. Preserve DeepSeek-compatible `reasoning_content` across tool-call rounds so the provider accepts the follow-up request and the conversation can reach a final answer.
2. Report deterministic provider HTTP 4xx rejections as `provider_rejected` instead of an unknown dispatch outcome.

## v1.0.148

1. Bound each durable conversation turn to 32 model dispatches and 30 minutes of cumulative model execution, with a visible terminal result when the budget is exhausted.
2. Apply an 8,192-token default to conversation profiles and immutable turn snapshots that do not specify an output limit.
3. Accept OpenAI-compatible streams that finish with a non-empty `finish_reason`, including an unterminated final SSE frame, while preserving final text and tool calls.
4. Coalesce durable reasoning deltas without changing their order across steer boundaries, and allow stopped Cloud Worker turns without a conversation-tool attempt record.

## v1.0.147

1. Preserve a prompt-derived first-turn title and durable stop summary when a retained Cloud Worker turn is canceled.

## v1.0.146

1. Stop the exact remote SSH runtime when a canceled task invalidates progress before the WorkerPool lease-renewal tick.
2. Keep a retained Worker busy through service publication, Route53, and TLS verification, releasing it only after finalization.
3. Reject retained-service reuse before remote execution when the existing workload definition or hostname binding conflicts.

## v1.0.145

1. Execute every suitable retained Worker reuse directly, including persistent services and hostname publication, while preserving confirmation for first Worker creation.
2. Make Native Agent stop cancel queued or running retained-Worker executions while preserving the Worker for later reuse.

## v1.0.144

1. Preserve a durable prompt-derived conversation title when a planning-only Cloud Worker intrinsic completes without a title-model call.

## v1.0.143

1. Replace a provisional conversation title left by a stopped first turn when the next turn completes successfully, using the earliest durable prompt without overwriting user-assigned titles.
2. Require an explicit Cloud Worker execution intent so planning-only requests cannot start a retained Worker, while preserving immediate reuse for actual execution.
3. Keep live estimated and maximum costs for finite retained jobs, omit those open-ended fields for persistent services, and continue exposing the hourly price for both.

## v1.0.142

1. Preserve empty Native Agent conversation history, conversation lists, turn lists, and attachment collections as JSON arrays so first-fresh clients can start chat without a null-shape failure.

## v1.0.141

1. Restore owner-visible durable turn prompts, safe attachment presentation, steer boundaries, reasoning segments, and immediate provisional conversation titles from Agent authority after cache loss or SSE reconnect.

## v1.0.140

1. Omit zero-byte Worker stdout, stderr, and result files before remote transfer and local artifact metadata creation, while preserving non-empty deliverables.

## v1.0.139

1. Preserve explicit zero estimated and maximum costs in Cloud Worker confirmation quotes, so retained Worker reuse remains a valid public DTO and renders from authoritative history.

## v1.0.138

1. Move the Native Agent chat data plane to durable HTTP writes, resumable SSE, and authoritative Agent-owned history while preserving cancellation, continuation, reasoning, Task, Plan, and attachment projections.
2. Publish Cloud Worker tools whenever the Native HTTP data plane is enabled, including complete confirmation, progress, result, artifact, and historical references.
3. Allow local isolated commands to run for up to ten minutes while retaining the existing CPU budget, and avoid repeating an identical local resource failure within one model turn.

## v1.0.101

1. Commit a successful SSH Worker report directly to its durable conversation turn, preserving task, plan, run, and artifact references without a second model dispatch.

## v1.0.100

1. Accept the public Execution V2 page-size ceiling of 200 for Worker plans and runs, matching the Message Server contract and allowing the real Worker flow to read its baseline before quoting.

## v1.0.99

1. Route provider-neutral task requirements through the single dynamic Ubuntu 24.04 SSH Worker path, prefer an exact compatible retained Worker before new-instance selection, and bind reuse to that Worker identity.
2. Remove deploy-time AWS enablement, fixed Worker defaults, explicit-cloud routing, task-specific reporting, and retained-Worker cleanup cost inflation.
3. Preserve failed and partial Agent turns in conversation history, recover terminal Worker continuations without unavailable request-scoped extensions, and normalize attachment-free read-only proposals.

## v1.0.97

1. Rebind the existing Cloud Worker confirmation reservation when an expired task lease is reclaimed, so the same durable execution resumes instead of being mislabeled as a model failure.
2. Retry transient SSH status, log, and artifact reads, resume an idempotent remote start only when it is definitively absent, and release local Worker state after cancellation.

## v1.0.96

1. Use the curl already provided by Amazon Linux 2023 and bound oversized SSH bootstrap errors before durable terminalization, preventing package conflicts from leaving Worker runs stuck in provisioning.

## v1.0.95

1. Keep the Cloud Worker pricing and authorization token ceiling separate from Pi request configuration, so an unset profile uses Pi's maintained 16,384-token default instead of an unrelated quote limit.

## v1.0.94

1. Use the quote-bound Worker token limit when a model profile leaves its output-token limit unset, so ordinary provider-default profiles can execute confirmed remote tasks.

## v1.0.93

1. Isolate each durable confirmation expiry candidate so one stale Worker projection remains retryable while valid siblings commit and the Agent lifecycle stays available.
2. Treat an expired memory-consolidation observation lease as record-scoped ownership loss without hiding repository failures or terminating the Knowledge cleaner.

## v1.0.92

1. Finish expired Worker offers safely after their owning conversation has been deleted.
2. Select the smallest matching AWS compute shape from live pricing and launch the confirmed SSH Worker from that single quote without a second pricing pass.
3. Remove the retired CloudFormation, S3, KMS, AMI, WorkerControl, model-relay, execution-gate, staging, retention, and legacy runtime paths while retaining credential-owned SSH Workers, local artifacts, persistent services, and explicit teardown.

## v1.0.91

1. Complete expired Cloud Worker confirmation, task, and execution state even when the owning conversation was deleted, without terminating the Agent runtime.
2. Identify the failing runtime component in Core lifecycle errors.

## v1.0.90

1. Publish the current reusable Worker plan and run DTOs without retired digests, infrastructure details, or private credential references.
2. Expose the exact pre-run Worker identity and live quote in owner confirmation while keeping internal authorization material private.
3. Keep plan, run, and confirmation chat references kind-specific and digest-free.
4. Treat the public run identity independently from the internal execution identity across reads, events, cancellation, and completion delivery.

## v1.0.89

1. Route substantial project, shell, deployment, build, test, artifact, and long-running tasks to the priced Cloud Worker offer when the published local toolset cannot execute them, without requiring cloud-specific wording.
2. Stop real Worker acceptance immediately when a durable turn completes without the expected priced offer instead of reconnecting and masking the terminal result.

## v1.0.88

1. Close a caught-up capability operation watch immediately when the authoritative operation is already terminal, so durable clients cannot hang after observing the terminal cursor.
2. Log only stable model-provider failure classes with operation and profile identities, without provider URLs, credentials, request content, model names, or response bodies.
3. Keep real Worker acceptance on the current one-POST durable turn plus resumable SSE transport and never reconnect after an error or cancelled terminal frame.

## v1.0.87

1. Include the SSH client required by retained AWS Workers in the production Agent image.
2. Publish the Cloud Worker plan, run, and artifact surface whenever the dynamic Worker runtime is composed, without requiring an unrelated deployment-time Execution V2 toggle.
3. Resume real Worker acceptance streams from their durable sequence cursor and use the configured conversation model default.

## v1.0.86

1. Use each Agent's verified AWS credential to quote and create SSH Workers without deployment-time Worker infrastructure, S3, KMS, or fixed AMI configuration.
2. Reuse compatible idle Workers without a new-server quote, while preserving live pricing and owner confirmation before each new Worker is created.
3. Support explicit job and persistent service workloads, live Worker load and cost status, and Agent-local result and artifact delivery.
4. Support optional Route 53 A-record binding, public-port publication, IP reconciliation, unbinding, and DNS cleanup before Worker destruction.

## v1.0.85

1. Resume durable turns without re-exposing intrinsic tools that were not accepted for the original model step.
2. Let substantial project, shell, deployment, test, isolated-workspace, and long-running tasks propose a priced Cloud Worker without requiring cloud-specific wording, while preserving owner confirmation before AWS execution.
3. Support an empty isolated writable Worker workspace for projects fetched from an authorized remote source; read-only workspaces still require exact current-turn inputs.

## v1.0.84

1. Return committed AWS credential updates without a cancellable post-commit read, so successful uploads do not report a false failure.
2. Enforce exactly one active AWS credential and reject concurrent or subsequent creates until the current credential is deleted.
3. Disable implicit CloudFormation mutation retries and let durable state plus explicit readback resolve uncertain provider responses.
4. Project model catalog entries from stable public fields before checking those fields for secret material.

## v1.0.83

1. Seed two network-free, read-only MCP installations that return live server UTC time and kernel load information through the isolated extension runner.

## v1.0.82

1. Bind the empty static-site list cursor as SQL NULL so the authenticated first page and subsequent cursor pages load correctly on PostgreSQL.

## v1.0.81

1. Return completed Cloud Worker results to the originating durable conversation with related tasks, plans, references, artifacts, and bounded deliverable context.
2. Add current static-site release listing and exact owner-scoped deletion through the Agent capability catalog.
3. Keep Cloud Worker execution explicit and remove the retired local-budget fallback path.

## v1.0.80

1. Dispatch Native Agent Product reads through the existing direct read-only path instead of extension preparation.
2. Persist user-visible assistant text deltas for live durable conversation progress without exposing provider reasoning.

## v1.0.79

1. Keep model profiles on the four current role-specific defaults and remove the superseded generic default field.
2. Remove retired capability aliases and stale Agent configuration fields.

## v1.0.78

1. Add exact update and delete operations for active structured memory facts.
2. Remove superseded Knowledge-memory CRUD, capability aliases, and legacy parameter fallbacks.
3. Keep the Agent capability catalog aligned with the current Message Server product actions.

## v1.0.74

1. Generate a concise first-turn conversation title with the configured tool model and fall back to the first user sentence.
2. Persist generated titles atomically for durable conversations without overwriting user-assigned titles.

## v1.0.73

1. Return absolute public URLs for generated static sites.
2. Prefix all bundled Skill identifiers with `dirextalk-`.

## v1.0.72

1. Allow long-running static-site publication to commit with the renewed current turn lease.

## v1.0.71

1. Establish the independent Agent Core runtime, durable conversations, Tasks, schedules, Knowledge and long-term memory.
2. Add pinned MCP and Skills lifecycle management, four default built-in Skills, and isolated three-slot local execution.
3. Add managed Node/npm MCP installation with exact versions, disabled lifecycle scripts, fixed quotas, and redacted public receipts.
4. Add durable Cloud Worker, AWS and Execution V2 boundaries without sharing Agent credentials or state with Message Server.
5. Add single-file static-site publication and progress-aware long-running Native Agent turns.
6. Add opt-in structured memory controls with durable fact and interaction records while retaining semantic retrieval.
7. Keep the image labels and all three binary versions aligned, and promote `latest` only after the matching GitHub Release succeeds.
