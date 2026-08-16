# Dirextalk Agent release notes

## Unreleased

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
