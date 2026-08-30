# Core v1 delivery tracker

This is the single detailed record of Agent implementation status, verification
evidence, and remaining release gates. Contract details live in the
[architecture](architecture.md), [API contract](api-contract.md), [Core v1
specification](core-v1-development-spec.md), [Message Server integration
contract](message-server-integration-development-contract.md), and
[Execution V2 contract](execution-v2.md).

## Implemented at HEAD

- Streamable HTTP MCP tool results retain ordered plain text and embedded
  textual resources instead of dropping file bodies returned through
  `resource.text`. Resource metadata is validated without URI dereferencing,
  binary bodies remain excluded, and the combined redacted 32 KiB projection
  reports truncation explicitly. Focused protocol tests reproduce the official
  hosted GitHub file-result shape and cover ordering, malformed resources,
  binary exclusion, redaction, UTF-8-safe bounding, and propagation through
  the GitHub conversation resolver.
- Cloud Worker GitHub access remains opt-in: absent, disabled, or tokenless
  frontend configuration creates an ordinary unbound plan and never blocks its
  proposal, confirmation, reuse, or start. The v1.0.184 and deployed v1.0.185
  unbound digest/confirmation encodings are both verified in-place, while an
  explicitly bound plan remains strictly revision-fenced.
- Native GitHub MCP snapshots are context-bound. Continuation and recovery
  rehydrate them from the authenticated owner/account/config/credential context
  without querying installed-extension storage, while retaining exact accepted
  snapshot and tool-schema digest checks.
- Core-only `dirextalk-agent` entrypoint with `migrate` and `serve`.
- TLS 1.3 gRPC authentication, health/reflection, capability discovery, and
  PostgreSQL-backed profiles, conversations, Tasks, events, schedules,
  confirmations, and fenced recovery. The private outbound Product Capability
  mTLS client explicitly bypasses ambient HTTP(S) proxy settings.
- Provider-backed model catalog and durable Eino conversation/Task execution.
- Revision-fenced profile sync treats an identical hydrated profile as a no-op,
  so reconnects do not invalidate an already published conversation pin.
- Native Chat/StreamChat and durable StartTurn now include the current prompt
  in the provider request and perform bounded long-term-memory recall on every
  turn. The model-only envelope combines relevance-ranked current user facts,
  their recent conflict-preserving timeline, and exact-promoted-revision
  semantic Knowledge passages; current facts explicitly outrank stale
  passages and the envelope is not persisted or returned.
- All current automatic turn recall is optional and bounded to three seconds.
  A live timeout or dependency failure persists one closed
  `memory_recall_degraded` warning, continues the same turn without memory, and
  never retries recall for that turn, including after restart. Watch,
  StreamChat, and Capability streaming
  project the warning distinctly without adding it to model input, transcript,
  tool output, runtime JSON, or final Markdown; parent cancellation emits no
  warning and starts no provider dispatch. Authenticated explicit
  `agent.memory.v1` operations remain fail closed, and no current admitted turn
  marks recall as authorization- or safety-required.
- Chat, StreamChat, and StartTurn now enter one durable Turn execution owner.
  Unary Chat returns the authoritative terminal Turn response, while StreamChat
  projects the persisted accepted/model/tool/confirmation/Worker/steer/terminal
  event order. RPC disconnect detaches observation without canceling accepted
  work; explicit CancelTurn remains the only stop mutation. The legacy Chat
  lease-driven model-step/tool-execution path and second model executor have
  been removed from the service.
- Successful exchanges atomically enqueue restart-safe memory consolidation.
  A bounded model extraction records explicit durable user facts only; repeated
  values confirm, changed values supersede with validity history, and explicit
  retractions close the active fact. Provider failures retry without rolling
  back the already committed conversation. A lost observation lease leaves the
  durable record for its current owner or expiry retry instead of terminating
  the lifecycle cleaner.
- Structured conversation memory is owner opt-in and disabled on fresh state.
  `agent.memory.v1` exposes the current toggle, embedding readiness/model,
  revision, bounded facts, conflict timeline, and pending/failed observation
  counters. Enabling without a configured embedding profile fails with a typed
  precondition; disabling capture/recall preserves durable memory data, and
  clearing the active embedding binding also turns the opt-in off.
- The same-origin Agent HTTP data plane validates short-lived scoped session
  tickets and owns Native chat, attachments, confirmations, Worker operations,
  history, recovery, and SSE. `start_turn` returns only after durable turn
  admission, while execution and `Last-Event-ID` replay use the authoritative
  conversation-turn ledger independently of the POST lifecycle. Operation and
  turn streams advertise a three-second reconnect delay, emit 12-second idle
  heartbeats, and terminate on cancellation or transport write failure without
  changing durable event sequences. The shared Agent Data Plane V2 contract at
  immutable `dirextalk-capability-api v1.2.0` supplies generated session,
  scope, operation, error, and SSE DTOs; the Agent consumes its shared vectors
  directly and no longer keeps a local v1 fixture. The four typed ticket errors
  distinguish expired, stale-generation, invalid, and missing-scope tickets,
  and dual SSE cursors must match or fail with `AGENT_CURSOR_CONFLICT` before streaming.
  Typed operation/store/turn failures map to
  fixed HTTP statuses and safe messages; unclassified capability failures
  become a redacted 502, unavailable failures become 503, and SSE
  projection/store errors do not expose their causes. HTTP, polling, and SSE
  terminal errors share the closed generated envelope; `Retry-After` and
  `retry_after_ms` represent the same delay, and Turn receipts/frames validate
  explicit equal operation and turn identities.
- Native turns persist execution-policy version, mode, and admitted values, and
  use those values through the same durable counters during recovery.
  Interactive admits 8 dispatches, 5 model-active minutes, and 8 tool calls;
  deep, scheduled, and Worker orchestration admit 24/20/20. Supported safe
  historical values remain executable after preset changes, while unsupported
  or unsafe policies fail before claim/event mutation. Worker-owned runtime and
  Task limits remain independent. Tool results with validated runtime references persist
  versioned progress observations in the immediate-result or deferred-resume
  transaction. Three repetitions of a semantic cycle of length one through
  four atomically prepare a durable tools-disabled Markdown finalization;
  argument/presentation wrappers do not count as progress, restart preserves
  the cycle, and steer resets it. Results without
  structured observations retain conservative exact/A-B loop recovery.
  Tools-disabled finalization validates and reuses the admitted frozen runtime
  and compiled prompt without resolving current extensions or intrinsics, then
  removes every tool only from the provider request. Message/GitHub MCP routing
  guidance therefore cannot disappear and falsely trigger
  `TURN_RUNTIME_INCOMPATIBLE` after a tool-budget stop.
  Conversation compaction now persists a versioned structured WorkingContext;
  protected user goals/constraints and runtime resource/receipt identities use
  a separate digest CAS, while only decisions, steps, and last-failure summaries
  are compressor-owned. At existing-conversation Turn admission, a deterministic
  frozen-envelope estimate automatically advances the smallest completed safe
  transcript prefix above the 80% input-budget threshold. The new offset,
  total-prefix provenance, and protected digest are persisted in the same
  transaction as the Turn without advancing public conversation revision;
  stale revision, prior context, transcript count, or boundary IDs reject the
  admission. Explicit owner compression remains revision-bearing. The model no
  longer receives the free-form summary.
  Gemini-generated tool-call IDs are unique against the prior transcript, and
  adjacent Anthropic tool results use one ordered result-message batch. Debug
  formatting of immutable execution snapshots omits both credentials and the
  complete system prompt.
- Every physical Native provider dispatch now has nonrenewing 15-second first-
  payload, 90-second first-meaningful-action, and five-minute absolute
  deadlines beneath the admitted model-active budget. Deadline failures enter
  the existing single tools-disabled finalization path. Provider reasoning
  remains adapter-internal and may bridge only the next live tools-admitted
  continuation once; it is absent from public DTOs, Protobuf, durable deltas,
  model-result envelopes, transcripts, history, and restart state.
- Native runtime admission and execution now compile one byte-identical fixed
  highest-priority platform policy before the JSON-encoded subordinate profile.
  Model-facing copies of every executable tool end in one canonical
  untrusted-content/stop-retry-finalization suffix, and intrinsics add the
  final-call-in-round suffix; source catalogs, schemas, order, and forced-tool
  identity do not change, and the context estimator charges the same text. An
  intrinsic-before-trailing-call batch durably records every call as invalid
  but executes none, admits one corrected intrinsic-only retry through the
  existing correction ledger, and tools-none finalizes a repeated violation as
  Markdown. A secret-free, injectable terminal convergence observer emits once
  per root supervisor/execution invocation without retaining a permanent
  per-Service turn map; durable `turn_id` supports cross-restart downstream
  deduplication alongside `duration_ms`, `deadline_class`, `useful_markdown`,
  `runtime_incompatible`, `model_dispatch_count`, `tool_call_count`,
  `directive_count`, `repeat_count`, `finalization_reason`, `fallback_used`,
  `recall_degraded`, and durable Worker `worker_poll_count`.
- Built-in local sandbox output is capped at 64 KiB per stream even when
  `os/exec` selects an optimized reader path, and its structured result reports
  explicit `stdout_truncated` and `stderr_truncated` booleans. Requested result
  files remain collected and verified by the outer isolated execution path.
- Pull requests and pushes to `main` run the independent read-only focused
  branch workflow with stable check names `focused-core`, `focused-race`,
  `focused-postgres`, and `runtime-loop-scheduled`. The first runs both affected
  conversation/runtime packages, the race lane targets policy correction and
  terminal observation, PostgreSQL uses PG18+pgvector for the restart fence,
  and the scheduled lane exercises its closed runtime loop. Stable tag checks
  retain the repository-wide test/vet/build/Buf/static-analysis/vulnerability
  gates; release publication remains a separate manual workflow.
- Revision-fenced `agent.chat.v1/steer_turn` now persists additional user
  guidance in the current turn ledger. It interrupts a provider generation
  before tool publication, preserves an unconfirmed or already dispatched
  Cloud Worker offer and its lease, and applies deferred guidance with ordinary
  tool results in the next
  model round. For SSH Workers, deferred instructions and readable text
  attachments observed before the remote runtime starts are appended to its
  objective at that single start boundary; the terminal result records their
  steer IDs. Later guidance is consumed with the terminal Worker result by one
  normal model round in the same durable turn, which may answer or reuse the
  retained Worker; the flow never queues a successor turn.
- Agent-owned encrypted Tavily Web Search configuration and guarded dispatch.
  Read-only tool execution errors return to the next model round for
  correction instead of terminating the conversation; an unrecoverable
  dispatch failure still preserves the user prompt and failed response in
  durable history.
- Agent-owned typed text tools with virtual revision-zero built-ins, durable
  full-list configuration/replay, explicit Tool-profile resolution, and
  bounded non-conversational model/search execution through the owner-client
  `agent.text_tools.v1` Capability.
- Owner-client image text extraction and locale translation through
  `agent.image_tools.v1`, with dedicated bounded PostgreSQL uploads, atomic
  consume-and-byte-clear, strict Tool-profile image-modality gates, fixed safe
  prompts, and no conversation/history/Task persistence.
- MCP/Skill lifecycle with isolated extension-runner execution and one fixed
  three-slot local sandbox capacity shared by durable claim admission and the
  runner process. Official Registry remotes are accepted only when the manifest
  declares exactly one
  header-free `streamable-http` endpoint; other header or transport shapes
  fail closed because the current runtime cannot reproduce them losslessly.
- Four immutable, network-free Dirextalk built-in Skills use the existing
  extension installation model. Fresh state seeds them once; removal remains
  removed across restart, while explicit reinstall continues through the
  reviewed confirmation lifecycle. Native turns resolve the selected pinned
  `SKILL.md` once and inject it as one instruction block without a fake tool.
  GitHub and skills.sh remain available as separately pinned external sources.
- Two default, network-free, read-only MCP installations expose live server
  time and server load through the same isolated MCP lifecycle and durable
  one-time seed semantics as other installed extensions.
- Authenticated Native conversations automatically load the fixed Message
  Server Streamable HTTP MCP catalog. Its stable bootstrap bearer is read from
  a protected mounted file for every request, the synthetic catalog snapshot
  is schema-bound, and recorded dispatches are never replayed after an unknown
  mutation outcome.
- Knowledge mounts, uploads, indexing, semantic-search composition,
  and the bounded read-only `knowledge_search` Native conversation tool.
  Semantic generations now use pgvector inside Agent PostgreSQL with exact
  binding-filtered cosine search, fixed 64 MiB aggregate/16 MiB source content
  limits, and the closed Knowledge quota status/error contract.
- App-managed AWS credentials with STS identity verification, plus
  `WorkloadService` planning/confirmation with a fenced `WORKLOAD` Task.
- Optional `agent.worker.v1` has closed owner-client list/get/destroy for the
  maximum-four persistent SSH Worker pool. Separate Native conversation
  `cloud_worker_domain_bind` and `cloud_worker_domain_unbind` tools use the
  authoritative turn's direct execution path and exact Route53 adapters, with
  no second confirmation, Task, action card, or `waiting_confirmation` state.
  Each call revalidates the exact owner, account, credential, Worker, workload,
  zone, and record identity before provider mutation and read-back. Active and
  last-removed record state makes a post-mutation/final-turn-commit retry an
  idempotent provider reconciliation with another read-back. Bind accepts only
  a matching public Route53 zone in the current verified account; private,
  external/manual, cross-account, and no-match cases perform no Apply/write and
  return an explicit correctable tool error. A successful bind additionally
  requires pinned-SSH reconciliation of the Agent-managed Worker Caddy route,
  public 80/443 security-group reconciliation, direct-to-Worker HTTPS health
  proof, and closure of the original workload port; focused regressions cover
  proxy-before-DNS ordering, staged failure recovery, exact Worker fencing, and
  fixed-script validation. Inventory
  reports the current ordinary public IPv4 and optional
  workload/domain state, never EIP. Worker creation, reuse, observation, and
  destroy require the Worker manager and verified-credential ports; optional
  Route53 operations additionally require a usable same-account hosted zone.
- `agent.servers.v1` and migration 23 provide the unified server/artifact
  inventory: the immutable Agent node and baseline backend-service artifact,
  named/created retained Workers, four newly-created artifact projections,
  owner-scoped pagination, user-visible artifact totals that exclude the
  baseline backend-service row, and one catalog-aware Worker destruction
  cascade.
- Neutral Capability Knowledge mutations now require explicit UUID idempotency
  keys, and AWS credential tests have durable, secret-free replay receipts.
  Provider tests use a persisted claim outside database locks; same-key active
  retries poll through the persisted 30-second lease plus completion grace and
  replay completed or deterministic failed receipts, while crash or completion
  uncertainty fails closed without lease takeover. Credential revisions and
  their first verified AWS identity remain immutable across rotation and soft
  disable; a different account or principal proof fails closed.
- Unified Agent image and split Compose services for Core, extension runner,
  and Core Runner; the latter has nonce/full readiness and descriptor-only
  sealed-result boundaries.
- Unified image builds validate and inject the immutable release version into
  the Core binary; authenticated instance info and `agent.info.v1/get_backends`
  report it separately from the `v1` API protocol version.
- Versioned, Buf-lint-clean Protobufs and focused Core contract tests.
- Durable model role defaults include an independent conversation-kind tool
  profile binding across memory/PostgreSQL stores, Protobuf, and
  `agent.models.v1` sync/list schemas and results; speech/embedding bindings
  are rejected and no conversation-default fallback is synthesized.
- Model updates and tombstone deletes remain available after historical
  conversation or snapshotted Task use. Tombstones preserve revision history
  while clearing live credentials; only future schedule/Knowledge consumers
  retain the profile-in-use gate. Generic Task terminal transitions release
  their now-historical active-reference rows.
- Closed Capability conversation/history DTOs, conversation-bound newest-first
  history cursors, strict UUID mutation keys, typed/redacted domain failures,
  and post-composition durable-turn recovery.
- Native durable turns expose the canonical public `turn_id` through
  `list_turns` together with the original start `idempotency_key`, and use the
  turn id as the durable Capability operation identity. Typed `stop_turn`
  binds only the authoritative turn id and its own idempotency key and returns
  the public turn projection plus that cancellation idempotency key.
- Native owner history now recovers each durable turn prompt and non-sensitive
  attachment presentation from Agent authority, persists the same presentation
  on completed/failed user transcript messages, and gives an untitled first
  turn an immediate deterministic provisional title that normal title
  generation may replace. Durable SSE also retains accepted steer boundaries,
  instruction text, and steer attachment presentation for cache-free reasoning
  segment recovery.
- Empty Native chat history, conversation, turn, and attachment collections
  retain their array wire shape through the direct HTTP data plane.
- Native durable turns expose the Core-owned `agent_schedule_create` intrinsic
  with model input limited to a concise sole card title, schedule
  intent/trigger/timeout, and the closed `scheduled_note`, `chat_summary`,
  `web_research`, `room_message`, `contact_report`, `room_member_report`,
  `channel_digest`, `chat_summary_delivery`, or ordered two-source
  `web_digest_delivery` capability. The last sends a Matrix message to a
  group/channel room and does not create a channel post. `scheduled_note`
  records Native Markdown without promising push delivery. Turn authority
  supplies owner generation and conversation; the schedule stores no model
  binding. PostgreSQL requires a valid explicit default conversation model at
  creation, then resolves and pins the then-current default independently for
  each occurrence while exact replay/reclaim reuses that occurrence snapshot.
  Missing or invalid defaults fail closed without fallback, occurrence write,
  silent skip, or auto-pause. PostgreSQL commits the
  schedule/replay and terminal transcript/event as one deterministic,
  replay-safe transaction. Creation now requires each capability's exact
  source-bound creating-Turn tools and returns a correctable no-write rejection
  for unknown or unavailable workflows. Due occurrences now execute through
  deterministic, replay-safe Native Turns, retaining and exposing only the
  selected capability's exact Message MCP or Tavily tools. Installed MCP/Skill,
  unrelated catalog tools, Product Capability, semantic Knowledge, and every
  Core intrinsic are excluded. Occurrence prompts bind the immutable scheduled
  UTC time and persisted timezone rather than execution wall-clock time; Matrix
  writes are dispatch-recorded and unknown outcomes are never blindly retried.
  Successful Task
  output is the single committed assistant Markdown in `result.text`, without
  JSON configuration or a duplicate assistant message. Scheduled snapshot and
  Native Turn admission failures use bounded stage-specific failure codes
  instead of leaking provider errors through the generic model failure.
- `agent.schedules.v1/list_outputs` now exposes a closed, newest-first,
  cursor-paginated occurrence result projection after schedule identity
  revalidation. It joins authoritative current Task status/result/failure
  fields directly, uses canonical schedule-bound cursors, retains soft-deleted
  Task history, and excludes templates, payloads, snapshots, authority, and
  secrets.
- The current Cloud Worker path uses a real `CLOUD_WORKER` CoreTask and
  CoreConfirmation with the sole App-uploaded, STS-verified AWS credential.
  Resource placement, live pricing, Route53, and execution use the deployment
  node's identity-verified AWS Region; the credential's default Region remains
  metadata and cannot redirect Worker resources. Missing host Region withholds
  Cloud Worker publication while keeping the rest of Agent available.
  New Worker creation uses a fresh EC2/EBS quote and exact owner confirmation;
  retained idle Workers are reused without another creation. The manager
  supports at most four ordinary-public-IPv4 EC2 Workers, discovers the current
  Canonical official Ubuntu 24.04 LTS image and default network live, and copies
  remote results into Agent-owned local artifact storage. It has no EIP, S3/KMS,
  custom AMI, WorkerControl, model relay, or deploy-time account/credential binding.
  Worker/execution records are bound to the authenticated owner/account
  generation; historical provisioning recovery is read-only, partial cleanup
  is retryable, and one unavailable AWS observation no longer hides the rest
  of the retained inventory. Static model tool definitions now expose a
  separate bounded, durably recorded read-only `cloud_worker_inventory` result
  instead of embedding live state. SSH uses a persistent per-Worker host-key pin,
  `RemoteCompleted`/`CollectOnly` prevents workload restart during collection
  recovery, persisted deterministic `TaskFailed` remains terminal while
  identity-fenced release bookkeeping reconciles without SSH, and logs plus
  artifacts consume one result-byte budget.
- The toolchain is Go 1.26.6. Security-driven dependency updates include gRPC
  1.82.1, `x/net` 0.55.0, and `x/text` 0.39.0, with their required supporting
  Go modules refreshed.
- Confirmation expiry processes each durable candidate in its own transaction.
  A stale binding or CAS conflict remains unchanged and is reported for retry,
  while other expired confirmations in the same sweep still commit; repository
  and infrastructure failures continue to stop the cleaner.

## Verification commands

```text
go test ./...
go vet ./...
staticcheck -checks=SA* ./...
govulncheck ./...
go build ./cmd/dirextalk-agent ./cmd/dirextalk-extension-runner ./cmd/dirextalk-core-runner
buf lint
go test -race ./internal/coreconversation ./internal/coremodel ./internal/agenthttp ./internal/coreextension/execution ./internal/coreworkload/runner ./internal/cloudworker/sshworker ./cmd/dirextalk-builtin-mcp
git diff --check
```

Opt-in PostgreSQL integration tests use `AGENT_TEST_POSTGRES_DSN`; Knowledge
integration also accepts `DIREXTALK_TEST_DATABASE_URL`. The opt-in Linux
isolation lane requires a delegated cgroup-v2 subtree and user/mount namespace
support.

## Verified evidence

- On **2026-08-30**, builtin MCP version identity was extended to bind both
  the inspected tool-catalog digest and the immutable published artifact
  digest. Repacking an executable with an unchanged catalog now creates a
  distinct immutable version instead of colliding with a historical primary
  key and preventing Agent restart. The PostgreSQL regression covers exact
  replay, same-content repack, later catalog change, and the durable removal
  fence.
- On **2026-08-30**, a focused regression reproduced Native continuation
  routing an accepted `github-mcp` snapshot through installed-extension
  storage, then passed after GitHub MCP joined the context-bound resolver set.
  The same classification is covered when a succeeded Cloud Worker turn
  finalizes without a second model dispatch. The full Core conversation and
  Core GitHub suites, Linux GitHub resolver tests, full Linux `go vet`, all
  three production command builds, Buf lint, and diff checks passed.
- On **2026-08-30**, tool-enabled Native model steps gained a validation-before-
  publication boundary. Model-authored narration accompanying a structured tool
  call stays private, and a protocol-shaped DSML envelope is quarantined even
  after a natural-language prefix or across fragmented streaming. The detector
  preserves fenced, inline-code, and quoted repository examples; quarantined
  text is never parsed into executable authority. Core records
  `MODEL_TOOL_CALL_FORMAT_INVALID` and retries once with fixed structured-call
  guidance. If that retry also fails, Core now performs a tools-disabled best-
  evidence synthesis instead of immediately showing the technical compatibility
  fallback; the guard and its single recovery retry remain active, never restore
  tools, and still converge deterministically if the provider repeats the
  invalid format. Focused Linux runtime, Core conversation, Capability, and
  PostgreSQL unit tests passed together with focused `go vet`, the production
  Agent command build, and diff checks. This is code-level evidence and does not
  claim a new deployment.
- On **2026-08-30**, Native public tool progress stopped projecting model-authored
  arguments, exact result content, cursors, or result references. Web Search
  keeps normalized fetched evidence in the private model transcript but now
  projects only canonical source identity, digest, and bounded title; Flutter
  renders that source as a compact external link and ignores legacy web preview
  bodies. Focused Linux Capability/Web Search tests, Flutter reference/coordinator/
  Agent-page tests, and targeted Dart analysis passed. This is code-level
  evidence and does not claim a new deployment.
- On **2026-08-20**, existing-conversation Turn admission gained deterministic
  automatic WorkingContext compaction from the frozen profile input budget,
  compiled prompt, selected Skill instructions, and admitted tool schemas. The
  planner preserves the largest safe transcript suffix, protects total-prefix
  provenance, leaves public conversation revision and Turn/runtime identity
  unchanged, and persists with the accepted Turn. Core and model-runtime suites
  passed 329 tests; the PostgreSQL unit suite passed 39 tests. Focused
  PostgreSQL 18 + pgvector acceptance proved atomic restart-stable admission,
  protected-context CAS, owner/account preservation, and rejection of stale
  conversation revision, prior offset/digest, transcript count, and all three
  boundary IDs. Focused vet and diff checks passed. One local unified-image
  candidate (`sha256:42801b8ceedecfd8e5d0697a77f364a482182ce2b64503942e27d28948459a35`)
  reported `v1.0.177` from all three production binaries, applied the fresh
  PG18+pgvector migration bundle through schema version 27, and returned that
  exact version from live `/agent/v1/health`; the candidate and its isolated
  probe resources were removed after verification.
- On **2026-08-20**, scheduled execution began binding its closed persisted
  capability into the immutable Turn runtime and enforcing the corresponding
  single-pass state machine from durable tool-call sequence. Stable
  `web_source` and `knowledge_chunk` references now bind canonical source and
  chunk identities plus content digests, and semantic no-progress recognizes
  repeated cycles of length one through four before durable tools-disabled
  Markdown finalization. Focused PostgreSQL 18 + pgvector restart tests proved
  exact-once replay of an admitted pending scheduled tool, one tools-none
  consumer call for a produced `tool_loop_no_progress` intent with no replay after
  completion, and exactly one forced static-site correction before final
  Markdown. Focused Core, resolver, RPC, migration, and PostgreSQL suites passed.
  P2-4 accumulated Core/conversation runtime verification passed 336 tests, and
  five selective correction/terminal-observation race tests passed. The
  non-vacuous `runtime-loop-scheduled` selection exercised 8 Core runtime, 6
  Core Task, and 4 Core conversation tests. A real PostgreSQL 18 + pgvector
  restart test proved that the invalid intrinsic-order batch executes nothing,
  one corrected intrinsic-only continuation creates exactly one schedule after
  restart, and another restart does not replay it. One local unified-image
  candidate (`sha256:79e4831746fb03e4d42b5f26a5bfd54a0b7ce52764f5e8a994dfd809c6390b67`)
  reported `v1.0.177` from all three production binaries, applied the fresh
  migration ledger through version/count 27/27, and returned exactly
  `{"status":"ok","release_version":"v1.0.177"}` from live
  `/agent/v1/health`; the candidate and all isolated probe resources were
  removed after verification.
- On **2026-08-20**, every physical model dispatch gained a separate durable
  directive that may add bounded loop guidance, force one already-admitted
  tool, or remove all tools for final synthesis without changing the immutable
  Turn runtime capability envelope. PostgreSQL binds the directive to the
  owner/account generation, Turn revision, dispatch epoch, lease, attempt, and
  runtime digest; provider retry copies the same directive and restart reloads
  it through those fences. Focused Core and migration suites passed 211 tests,
  and 10 focused PostgreSQL 18 + pgvector cases covered loop nudge/synthesis,
  tool-budget and static-site finalization, restart, retry, steer, and durable
  progress behavior.
- On **2026-08-19**, Native schedules stopped retaining the creating Turn's
  model profile. Schedule creation now requires a valid explicit conversation
  default without storing a schedule profile reference; each occurrence
  transaction pins the then-current default's exact revision, credential
  version, request dialect, model kind, configuration, and secret reference.
  Exact trigger replay/reclaim retains that occurrence snapshot, while later
  occurrences observe later defaults. Missing defaults fail without writing an
  occurrence/Task. Focused Core/runtime/conversation/Agent suites passed 533
  tests; the focused PostgreSQL 18 + pgvector schedule/profile integration set
  passed; the full Go suite passed 1878 tests; `go vet ./...`,
  `go build ./cmd/...`, and diff checks passed.
- On **2026-08-19**, scheduled Native workflows gained the closed nine-
  capability creation gate (`scheduled_note`, `chat_summary`, `web_research`,
  `room_message`, `contact_report`, `room_member_report`, `channel_digest`,
  `chat_summary_delivery`, and ordered multi-source `web_digest_delivery`) with
  exact creating-Turn tool requirements, correctable no-write rejection,
  persisted capability identity, and sole-card-title guidance. The schedules
  capability also gained closed newest-first `list_outputs` history with stable tuple
  pagination and safe current Task result/failure projection. A focused
  PostgreSQL 18 + pgvector run exercised equal-time UUID ordering, two-page
  no-duplicate traversal, schedule-bound canonical cursors, soft-deleted Task
  history, and terminal/current projections. The six affected package suites
  passed 723 tests, the full Go suite passed 1874 tests, and `go vet ./...`,
  `go build ./cmd/...`, and diff checks passed.
- On **2026-08-18**, immediate tool-result and deferred-resume transactions
  began persisting versioned progress observations. Focused tests cover
  wrapper/presentation-insensitive digests, state-change reset, unstructured
  fallback, restart continuity, steer reset, the third-observation terminal
  event, and shared immediate/deferred windows. Context compaction now rebuilds
  a schema-constrained WorkingContext from the retained transcript, protects
  exact user/resource/receipt fields with a separate CAS digest, and excludes
  the legacy free-form summary from model input. `go test ./...` passed 1733
  tests, the maintained race lane passed 455 tests, and vet, SA staticcheck,
  govulncheck 1.7.0, command builds, Buf lint, and diff checks passed. The new
  PostgreSQL transaction/CAS cases remain opt-in because
  `AGENT_TEST_POSTGRES_DSN` was not configured in this environment.
- On **2026-08-18**, durable Turn admission began atomically freezing the
  compiled system prompt, explicit request dialect/profile configuration,
  intrinsic schemas, extension/attachment identity, and execution policy.
  Each physical provider attempt now consumes the 24-attempt fuse before
  dispatch. Only pre-output 408/429/502/503/504 or confirmed dial failures may
  retry once, with bounded `Retry-After`; visible output and ambiguous
  transport outcomes never replay. Focused unit/race checks cover retry
  allowlisting, delta/tool-call replay denial, exact-once retry, budget
  accounting, runtime mismatch, deterministic restart input, and admission
  failure. PostgreSQL transition/fencing coverage remains opt-in through
  `AGENT_TEST_POSTGRES_DSN`.
- On **2026-08-18**, the automatic Message MCP catalog began deriving strict
  read/unsafe-mutation effects from the complete standard annotation set and
  binding those effects into immutable catalog identity. Five-minute fresh and
  one-hour stale-if-error caching keeps ordinary chat available during MCP
  discovery outages; exact-catalog re-discovery permits one safe read retry,
  while writes remain single-dispatch with outcome-unknown projection. Focused
  tests cover missing/contradictory annotations, effect drift, cache expiry,
  discovery degradation, retry fencing, and a stateless handler recreation
  without `Mcp-Session-Id`.
- On **2026-08-17**, Native conversation profiles gained a single positive
  8192-token output default. Turns enforce 24 provider dispatches, 20 minutes of
  model-active time excluding tool and Worker time, and 20 accepted tool calls.
  Focused regressions cover conservative exact/A-B loop recovery, tool-free
  final synthesis, full SSE event framing, provider error classes, safe HTTP
  error projection, static read-only Worker inventory, SSH host-key persistence,
  collection-only recovery, and the shared Worker result-byte ceiling.
  Provider deltas retain bounded coalescing with final flush, and
  OpenAI-compatible streams accept explicit nonempty `finish_reason` before
  clean EOF while still rejecting unmarked truncation.
- On **2026-08-17**, OpenAI-compatible bare origins normalize to `/v1`, keeping
  model discovery and completion on one API root and rejecting successful HTML
  landing pages as invalid provider responses. Pinned Skill bytes retain their
  immutable raw digest while CRLF and bare CR normalize to LF before prompt
  validation. Focused regressions cover the production failure shape where a
  gateway root returned HTML and every model turn ended without a delta.
- On **2026-08-17**, the PR workflow adds pinned `staticcheck` 0.7.0 and
  `govulncheck` 1.7.0 plus a bounded high-risk race lane. Go 1.26.6, gRPC
  1.82.1, `x/net` 0.55.0, and `x/text` 0.39.0 close the reachable findings that
  motivated the dependency refresh. This is repository-level verification and
  does not claim a new deployment or cross-repository acceptance run.
- On **2026-08-11**, durable Native conversation rounds accepted ordered
  multi-tool batches. Focused unit and PostgreSQL 18 tests covered a built-in
  Web Search result followed by a confirmed local MCP call in the same retained
  model result, a compact private at-most-once dispatch fence, real
  confirm/claim/begin/finish service restart recovery, strict call/result
  pairing, next-round release only after every result, and remote conversation
  work bypassing the durable local sandbox lane. The rollout gate requires zero
  nonterminal turns using the superseded raw dispatch-result shape.
- On **2026-08-11**, focused PostgreSQL 18 + pgvector tests concurrently
  claimed four local sandbox Tasks and proved exactly three running plus one
  queued, remote/static lane bypass, durable restart behavior, and lease
  reclaim without overselling. Extension Runner capacity and its aggregate
  1 GiB container-memory bound also passed focused Linux tests.
- On **2026-08-07**, focused extension, MCP HTTP, and Agent Capability tests
  covered exact header-free official-registry inspection, installation without
  secret input, credential-free invocation, omitted Authorization headers,
  fail-closed declared headers, and write-only public secret inputs. The
  opt-in PostgreSQL execution integration test carries the public remote
  through persisted install, `RequestTask`, confirmation, claim, and `Resolve`.
- Linux isolation verification passed in privileged cgroup-v2 and non-root
  delegated systemd scopes, covering detached roots, hidden host/config paths,
  denied network, explicit secret exposure, descendant cancellation,
  `cgroup.kill`, `populated 0`, workspace cleanup, and zero residue.
- Runner-focused tests, focused command/config/app tests, command builds, and
  the non-root delegated isolation test passed without provider credentials.
- On **2026-08-06**, focused Capability/Core AWS tests covered missing and
  malformed Knowledge keys, exact replay, changed-binding conflicts, bounded
  same-key retries, failed receipts, cancellation fencing, and out-of-order
  monotonic completion. The PostgreSQL restart/replay test is opt-in through
  `AGENT_TEST_POSTGRES_DSN` and skips when PG18 is unavailable.
- On **2026-08-06**, the full Agent test suite passed against PostgreSQL 18.
  The recall integration lane covered 129 promoted memory sources in bounded
  batches and verified that private recall creates no
  `core_knowledge_list_snapshots` row. Focused Chat/StreamChat and StartTurn
  tests verified exact prompt delivery, user-level transient recall,
  fail-closed provider dispatch, and no conversation persistence of recalled
  snippets. `buf lint`, `go vet ./...`, and `go build ./cmd/...` also passed.
- On **2026-08-06**, PostgreSQL 18 integration tests verified that Native Chat
  skips stale memory promotions after an embedding-profile ID or revision
  change, reports them as stale rather than indexed, and requeues a source
  whose active embedding profile revision advanced. Empty exact-binding recall
  remained a successful empty context without calling the semantic backend.
- On **2026-08-20**, focused Core and RPC tests verified the Chat/StreamChat
  durable adapter, terminal replay after service recreation, ordered lifecycle
  projection, profile-pin rotation, title atomicity, and disconnect-without-stop
  behavior. Focused PostgreSQL 18 + pgvector tests exercised Chat, StreamChat,
  and StartTurn through the same persisted cancellation and precharged model
  budget terminals (`canceled` and `model_budget_exhausted`).
- On **2026-08-20**, Native-turn terminal finalization replaced ordinary
  provider/budget/no-progress failed terminals with one persisted, independent,
  tools-disabled final provider attempt and deterministic four-section Markdown
  fallback. The ordinary fuse remains 24 dispatches and 20 minutes; migration
  25 permits only the separately fenced sequence 25 and persists immutable
  finalization intent. Focused Core and PostgreSQL 18 + pgvector tests cover
  provider/invalid-output fallback, durable partial preservation, dispatch and
  active-time exhaustion, intent-before-dispatch restart, and no replay after a
  final dispatch has started.
- On **2026-08-20**, Native tool results adopted the closed
  `dirextalk.tool-observation/v1` contract with explicit outcomes, bounded
  read-only retry and invalid-argument correction, mutation state, summaries,
  references, and cursors. Observation-free results fail closed; mutating
  failures without an unchanged receipt become `unknown_mutation`. Migration
  26 constrains terminal attempt observations. Focused Core and PostgreSQL 18
  + pgvector tests cover steer reset, retry/correction exhaustion, malformed
  observation rejection, restart projection exactly once, tools-disabled
  finalization, Message MCP mutation uncertainty, Worker-only deferred
  follow-up, 30-second retry-delay bounds/cancellation, read-only uncertainty,
  and Worker continuation.
- On **2026-08-20**, admitted execution policy v1 replaced equality checks
  against binary defaults. `Chat`, `StreamChat`, and `StartTurn` now accept the
  optional closed interactive/deep/worker-orchestration selector while trusted
  scheduled Tasks bind scheduled mode. Runtime snapshots persist bounded mode,
  dispatch, active-time, and tool-call values; Service and PostgreSQL execute
  those values directly. Interactive uses 8/5 minutes/8 and the three extended
  modes use 24/20 minutes/20. Unsupported or unsafe stored policies fail before
  claim mutation, and Cloud Worker runtime limits remain independently owned.
- On **2026-08-20**, focused Core lifecycle tests verified the dispatch-local
  first-payload, meaningful-action, and absolute deadlines, equal-expiration
  ownership by the admitted model-active budget, one finalization after
  reasoning-only or incomplete-tool timeout, and parent-cancellation priority.
  Focused runtime, Capability, and RPC tests verified live-only one-shot tool-
  round reasoning continuity and the absence/reservation of public
  `reasoning_content`; five affected packages also passed compile-only checks.
  Eight focused PostgreSQL 18 + pgvector cases included a real 15-second
  first-payload watchdog, finalization across service restart exactly once,
  durable-envelope exclusion, and loss of live-only continuity after restart.
  A local unified-image candidate (`sha256:42a9198f02a1620e0d674ef7e2976f519bbd8e33a1872817a28d51dfea24de41`)
  reported the same version from all three production binaries, applied a
  fresh migration ledger through version/count 27/27, and returned the exact
  version from live `/agent/v1/health`; the candidate and isolated probe
  resources were removed after verification.
- On **2026-08-20**, the Agent pinned `dirextalk-capability-api v1.2.0` and
  recognized its generated `agent:servers:read`, `agent:servers:write`, and
  `agent:servers:destroy` scopes. Focused descriptor, HTTP catalog, typed
  forbidden-error, and shared-conformance tests verify that server inventory
  operations are published only to correctly scoped owner tickets.
- On **2026-08-14**, the current Cloud Worker tests cover proposal-time live
  selection and pricing, deterministic offer/confirmation binding, dynamic AWS
  credential readiness, SSH execution, retained Worker identity, local artifact
  reads/downloads, and owner/account-generation isolation. The retired custom
  AMI, S3/KMS staging/result, WorkerControl, model-relay, provider-graph,
  pre-launch repricing, and automatic cleanup paths have been removed. These
  tests use fakes or SDK test doubles and perform no AWS mutation.
- On **2026-08-13**, the active implementation replaced that historical
  inbound/custom-image path with the persistent SSH Worker manager. Focused
  tests covered AWS-owned AL2023/default-network discovery, ordinary public IPv4,
  maximum-four capacity, confirmed creation, retained idle reuse, explicit
  destroy, reconnectable task status/log/artifact commands, live server-load
  observation, and local artifact storage. This evidence is code-level and
  does not claim a new live AWS mutation.
- On **2026-08-14**, current focused tests cover Canonical official Ubuntu 24.04
  image discovery and its `ubuntu` SSH/bootstrap contract. This evidence is
  code-level and does not claim a live Ubuntu Worker mutation.
- On **2026-08-15**, the s3 production-shaped acceptance used the App-uploaded
  AWS credential in account `066107820442`, performed a fresh `ap-east-1`
  quote and one owner confirmation, created one Canonical Ubuntu 24.04 SSH
  Worker with an ordinary public IPv4, observed task status and server load,
  downloaded a verified Agent-local artifact, retained and reused the same
  Worker without a second creation confirmation, then explicitly destroyed it.
  Independent AWS read-back proved the EC2 instance terminated and its key pair
  and security group absent; no S3 path was used. The same deployment also ran
  a real Native Agent local-sandbox turn with one HTTP admission and resumable
  SSE through `done`, persisted three local artifact references, and verified
  get/download/delete against Agent-owned host storage.
- On **2026-08-15**, focused regressions reproduce and fix intrinsic execution
  after a turn heartbeat renews the lease epoch, using the production schedule
  argument shape. Worker Task and turn status events now expose real preparation,
  provisioning, connection, execution, collection, and verification phases. The embedded
  runtime test also proves a session-changing descendant is removed when the
  remote execution budget expires. This is code-level evidence and performs no
  AWS mutation.
- On **2026-08-16**, the Cloud Worker intrinsic gained a required execution
  intent. Focused tests prove that proposal-only requests commit a non-executing
  summary without crossing the offer or retained-Worker boundary, while finite
  retained jobs keep live estimated and maximum costs and persistent services
  expose only their hourly price. This evidence performs no AWS mutation.
- On **2026-08-18**, the Agent pinned `dirextalk-capability-api v1.1.0` and
  replaced handwritten session-adjacent operation/error/SSE transport shapes
  with generated Agent Data Plane V2 DTOs and scope/category/state constants.
  Focused conformance reads all shared valid and invalid vectors from the pinned
  module, rejects unknown error details and invalid Turn identities, proves
  polling/SSE error parity, and proves `Retry-After` rounding from
  `retry_after_ms`. The former repository-local v1 fixture was removed. The
  full suite passed 1,748 tests, the maintained high-risk race lane passed 469
  tests, and vet, SA staticcheck 0.7.0, govulncheck 1.7.0, command builds, Buf
  lint, and diff checks passed.

## Remaining release gates

- Two isolated Compose-project E2E verification is not recorded here.
- Live `workload.core_runner` workload execution is not recorded.
- Production `cloud_worker_propose` accepts either an explicit cloud command
  or versioned Native scheduler evidence that the local conversation runtime
  lacks a general project/shell executor. The model may therefore propose a
  priced Worker for a substantial project task without cloud wording. Model
  arguments, timeouts, and failed local execution are not evidence; local-only
  and cloud vetoes remain authoritative, and execution still waits for owner
  confirmation before any AWS mutation.
  Focused intrinsic, deterministic evidence-binding, empty-write materializer,
  command composition, and pure PostgreSQL package tests cover this path; live
  AWS mutation remains a separate authorized acceptance step.
- Route53 bind/unbind acceptance remains optional and separate from Worker
  readiness.

These gates are evidence requirements, not fallback behavior: a missing proof
keeps the corresponding capability unpublished while planning and unrelated
ready capabilities remain available.
