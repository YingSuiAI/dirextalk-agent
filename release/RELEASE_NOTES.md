# Dirextalk Agent release notes

## Unreleased

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
