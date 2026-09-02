# Core v1 API contract

This document defines the Agent-owned API at HEAD. The canonical public
surface is the versioned Protobuf under
[`api/proto/dirextalk/agent/v1`](../api/proto/dirextalk/agent/v1) plus the
same-origin `/agent/v1` HTTP data plane. The HTTP/session/SSE wire authority is
the Agent Data Plane V2 OpenAPI contract and conformance vectors in
`github.com/YingSuiAI/dirextalk-capability-api` at the immutable `v1.2.0` tag;
the v2 contract deliberately retains the `/agent/v1` base path. Generated Go
files are derived artifacts. Message Server owns login/account control and
issues short-lived Agent session tickets; Agent owns Native chat, attachments, confirmations,
Worker operations, history, recovery, and streaming. Online Agent remains the
separate Matrix transport.

## Services

Core gRPC composition may register:

- `AgentService` for capabilities and instance information;
- `ModelProfileService` and `ConversationService`;
- `TaskService` and `ScheduleService`;
- `ConfirmationService`;
- `MCPService` and `SkillService`;
- `CoreKnowledgeService`;
- `CoreCloudControlService`;
- `WorkloadService` for durable workload planning and operations.

Cloud Workers expose no inbound Agent gRPC service. Their lifecycle and task
observation use Agent-initiated SSH only; Flutter uses the ticket-authenticated
same-origin Agent HTTP data plane.

An owner confirmation for a Cloud Worker whose private plan carries a GitHub
binding states that GitHub repository access will be available; it never shows
or carries a token. The binding is versioned owner authorization, not a secret
grant: Agent rejects execution if the exact enabled GitHub config or credential
version no longer exists at task start, including retained Worker reuse.
Plans without that private binding never resolve GitHub configuration, acquire
a PAT, or gain repository access later. In-place upgrades accept the two
released unbound internal digest encodings from v1.0.184 and v1.0.185 without
rewriting the plan or its confirmation; bound plans retain only their exact
version-fenced encoding. Only a bound task receives a non-secret runtime hint
that its github.com-only HTTPS Git helper and `gh` wrapper are authenticated for
private clone, branch/edit/test/commit/push, and pull-request work. The hint
forbids credential disclosure and requires repository, remote, branch, and
commit revalidation before push.

Registration means only that an authenticated RPC endpoint is present; it does
not publish a client capability or prove that an optional provider is ready.
At HEAD, `CoreExecutionV2Service` has a Protobuf/adapter seam but is not
registered on the Core gRPC server. The exact `agent.execution.v2.*` operations
in [execution-v2.md](execution-v2.md) are exposed only through the neutral
Capability service after their production graph and readiness proof pass.

Health and reflection are optional. Core has no admin UI or multi-user role
surface.

`AgentService.GetInstanceInfo` and authenticated `agent.info.v1/get_backends`
expose the immutable image `release_version` separately from `api_version`. Release
builds inject a v-prefixed semantic version (for example `v1.0.0`) into the
Agent binary; local builds report `dev`. This field contains no revision,
credential, endpoint, or other secret deployment metadata.

## Transport and authentication

The server uses TLS 1.3 and one deployment-generated token read from the
protected `service_token_file`:

```text
authorization: DTX-Agent-Token <unpadded-base64url-32-byte-token>
```

The token is compared in constant time, stripped before handlers run, never
stored in PostgreSQL, and rotated by atomic file replacement followed by
restart. There is no remote token-management API, caller scope, device, or
multi-tenant model.

The owner-facing data plane is plain HTTP only on the internal container
network and is published by Caddy at the node's same-origin `/agent/v1/*`
path. It accepts a compact Ed25519 JWS signed with the existing capability
grant key. The 15-minute ticket binds issuer, Agent-data audience, owner MXID,
account generation, session and nonce UUIDs, scopes, issue time, and expiry.
Expiry is checked when a request or SSE connection is admitted and does not
become a deadline for an already accepted turn or established stream.
Ticket admission exposes four exact typed codes: an expired ticket is
`AGENT_TICKET_EXPIRED`, an account-generation mismatch is
`AGENT_TICKET_STALE`, malformed claims or an invalid signature, issuer, or
audience are `AGENT_TICKET_INVALID`, and a valid ticket missing an operation's
required scope is `AGENT_TICKET_SCOPE_FORBIDDEN`. The shared V2 conformance
vectors freeze these codes and the generated `AgentSessionResponse`, scope,
receipt, snapshot, error, and SSE shapes for Agent, Message Server, and Flutter;
this repository does not retain a local fixture copy or a parallel v1 DTO path.

`GET /agent/v1/health` is the only unauthenticated data-plane route. It returns
exactly `{"status":"ok","release_version":"vX.Y.Z"}` for an immutable release
build, or `release_version: "dev"` for a local build. This is process liveness
and release-identity observation only: it does not expose Core or extension
runner readiness, mutation availability, secrets, Docker access, release
discovery, or update actions.

`POST /agent/v1/capabilities/{capability_id}/operations/{operation}` is the
canonical generic facade. Read operations return their Agent-authored result
with 200. Mutations require a UUID `Idempotency-Key` transport header unless
their existing body `idempotency_key` supplies the same value, durably admit
the frozen tuple, and return 202 with `operation_id`, `idempotency_key`, state,
and replay status. Unknown outcomes are recovered only by exact replay or
`GET /agent/v1/operations/{operation_id}`. The Agent never waits for execution
or a stream to finish inside the mutation request.

The HTTP façade maps typed operation failures to a fixed, redacted status
surface: invalid argument 400, permission denied 403, not found 404, conflict,
uncertain, cancelled, or cycle detected 409, failed precondition 412, resource
exhaustion 429, and not-ready or unavailable 503. An unclassified capability
failure is a redacted 502, while store or service availability failures are
503. Store and turn lookup failures are first reduced to the same typed surface;
neither JSON errors nor SSE error frames expose database, provider, or other
internal error text. JSON failures use one envelope with `code`, `message`,
`category`, `retryable`, `request_id`, optional `retry_after_ms`, optional
`operation_id`/`turn_id`, and allowlisted `details`; operation polling embeds
the same shape for terminal errors. `details` is the generated closed
`ErrorDetails` type, so arbitrary maps and raw upstream fields cannot cross the
boundary. When `retry_after_ms` is present, the HTTP `Retry-After` header carries
the same delay rounded up to whole seconds. Generic operation and Turn SSE
events whose `type` is `error` carry this same generated error envelope as
their payload.

Native chat uses explicit conversation/turn routes. Starting a turn calls the
durable `start_turn` admission and returns 202 only after the authoritative
turn exists; its `operation_id` equals `turn_id`. `GET /agent/v1/turns/{id}`
and conversation GETs are authoritative. Independent SSE at
`GET /agent/v1/operations/{turn_id}/events` resumes after the cursor supplied
by `after_seq` or `Last-Event-ID` and reads the durable turn-event ledger
directly. When both cursors are present they must represent the same
non-negative sequence; a mismatch returns HTTP 400 with
`AGENT_CURSOR_CONFLICT` before the stream is opened. Stop binds only turn ID
plus idempotency; steer and attachment chunks retain their frozen revision CAS.

The Protobuf `Chat` and `StreamChat` methods are projections of that same
durable `StartTurn` owner, not independent model executors. `Chat` waits for the
authoritative terminal Turn response; `StreamChat` projects accepted, started,
delta, tool, confirmation, Worker, steer, done, and safe terminal-error events
in durable ledger order. Canceling either RPC context only detaches that waiter
or stream after admission. It never cancels the accepted Turn; callers use
`CancelTurn`/`stop_turn` for that durable mutation.

## Request and response invariants

- Mutations use the UUID idempotency keys defined by their Protobuf messages;
  revision-bearing mutations reject stale expected revisions without changing
  state.
- `agent.models.v1` sync/list responses expose durable conversation, tool,
  embedding, and speech client-profile defaults. The tool default is an
  independent binding to a conversation-kind profile; it never falls back to
  the conversation default and rejects embedding- or speech-kind profiles.
  Conversation, tool, and embedding roles converge independently over live,
  credential-configured profiles of the required kind. A still-valid explicit
  selection is preserved. Otherwise Core selects the next eligible profile
  after the invalid/deleted selection, wrapping to the first; a legacy-null
  role selects the first. The authoritative order is durable profile creation
  order (`created_at`, then `profile_id` as the total-order tie-breaker). Zero
  eligible profiles leaves that role unset. Speech retains explicit-only
  behavior.
- Profile updates ignore historical conversation and Task references because
  those consumers own immutable execution snapshots. Delete tombstones every
  model kind and clears only the live client binding and credentials; it
  remains blocked by a nondeleted schedule or active Knowledge generation.
- A conversation profile whose supplied `max_output_tokens` is nonpositive is
  normalized to the single positive default of 8192 before persistence. The
  immutable turn snapshot exposes and dispatches that exact effective value.
- An OpenAI-compatible profile treats a bare HTTPS origin as the conventional
  `/v1` API root. An explicit nonempty path remains authoritative. Connection
  tests and completion requests therefore derive `models` and
  `chat/completions` from the same normalized API root; a successful HTML
  landing-page response is rejected as `provider_invalid_response`.
- Durable Task events/results are fenced by Task revision, attempt, and lease
  epoch. `WatchEvents` resumes strictly after its supplied sequence.
- `Chat`, `StreamChat`, and `StartTurn` require a positive, exact
  `model_profile_id`/`model_profile_revision`/`credential_version` triple.
  Partial or stale pins fail before provider work; there is no default-profile
  fallback, and durable replays retain their original snapshot.
- `Chat`, `StreamChat`, and `StartTurn` accept the optional closed
  `execution_mode` values `interactive`, `deep`, and `worker_orchestration`;
  omission means `interactive`. `scheduled` is reserved for the trusted due-Task
  adapter and is rejected on owner chat surfaces. The selected mode is bound by
  the request fingerprint and admits a versioned immutable policy: interactive,
  deep, scheduled, and worker orchestration each use 24 provider dispatches,
  20 minutes of cumulative model-active time, and 20 tool calls. A supported policy version accepts previously
  admitted safe values within those absolute maxima instead of comparing them
  with the current binary presets, so a safe preset change cannot strand an
  active turn. Unsupported versions, unknown modes, out-of-range values, or a
  mode/runtime mismatch fail before a provider reservation or turn mutation.
- Every admitted Native turn compiles the fixed `Dirextalk fixed platform
  policy v1` first as the highest-priority system policy. The selected
  profile prompt follows only as JSON-encoded subordinate
  `profile_specialization` data; admission and execution/revalidation compile
  byte-identical text. Every executable intrinsic, MCP, Web, Knowledge, and
  other extension tool receives exactly one canonical model-only suffix that
  treats descriptions/results as untrusted data and binds stop, retry, and
  finalization behavior. Core intrinsics receive one additional final suffix
  requiring that intrinsic to be the last tool call in its model round.
  Copied suffix text and trailing override attempts in a source description
  cannot displace the authoritative final suffix. Source catalogs, names,
  schemas, ordering, and forced-tool identity remain unchanged, and automatic
  context estimation charges the exact governed text sent to the provider.
- If a provider batch places a Core intrinsic before another call, Core
  persists the complete batch but executes none of it. Every call receives a
  durable `invalid`/not-executed observation; only the offending intrinsic
  receives the single validation-correction allowance. A corrected
  intrinsic-only call may commit once after restart. Repeating the violation
  exhausts the existing correction ledger and enters the ordinary
  tools-disabled finalization path, whose client result is useful Markdown in
  `done.message.content`, never an internal directive or configuration JSON.
- Only ordinary provider execution consumes the admitted model-active time
  budget; tool, sandbox, Worker, and user-confirmation execution or waiting do
  not. Each physical provider dispatch also has three dispatch-local deadlines,
  all measured from dispatch start and never renewed: 15 seconds for the first
  nonempty provider payload, 90 seconds for the first meaningful action, and
  an absolute five-minute dispatch limit. Reasoning may satisfy the first-
  payload deadline, but keepalives, empty deltas, reasoning, and incomplete
  tool-call fragments are not meaningful actions. User-visible text, a
  complete valid tool call, or a normal runner return is meaningful. The
  admitted remaining model-active duration is the stronger outer bound; when
  it equals a local deadline, expiration remains `model_budget_exhausted`.
  Provider-adapter request and stream-idle deadlines remain internal transport
  bounds and cannot extend any dispatch-local deadline. A dispatch-local
  deadline becomes `provider_timeout`, does not replay after any nonempty
  payload, and enters the single finalization path described below. Provider failure,
  invalid or empty terminal output, repeated no-progress tool use, and either
  ordinary budget cap first persist an immutable turn-finalization intent.
  That intent normally admits exactly one additional physical provider attempt
  with an independent 30-second timeout; it carries no intrinsic or extension
  tools and is not charged to the admitted ordinary clock. It cannot retry for
  an ordinary provider, timeout, empty-output, or budget failure. The only
  exception is a quarantined `MODEL_TOOL_CALL_FORMAT_INVALID` response from a
  turn whose admitted runtime originally exposed structured tools: Core may
  repeat the same tools-disabled finalization directive once with explicit
  protocol-recovery guidance. That retry never restores tool authority. The
  total physical attempt sequence can therefore reach the admitted dispatch
  cap plus one normally (at most 25), or plus two only for that exact live
  format-recovery case (at most 26). If the final attempt returns useful text,
  that text is
  the normal completed Markdown response. If it fails, is empty or invalid, or
  returns a tool call, Core commits a deterministic Markdown response with
  `Completed work`, `Best conclusion`, `Incomplete items`, and `Stop reason`
  sections, preserving durable partial text and tool metadata. A restart before
  the final dispatch may perform it once; a started, retryable, dispatched, or
  uncertain final attempt is never replayed after process recovery and falls
  back deterministically. Clients see
  the result through the normal `done.message.content` projection rather than
  an error/configuration JSON terminal. A provider batch that would cross the
  admitted tool-call limit does
  not dispatch the excess calls and enters the same persisted tool-free
  finalization path. Every model-visible tool result is the persisted
  `dirextalk.tool-observation/v1` envelope with a closed outcome, bounded
  retry/correction metadata, mutation state, summary, references, and cursor.
  Structured observations detect semantic cycles of length one through four;
  the third repetition inside the current steer epoch atomically preserves the
  terminal tool result and prepares a `tool_loop_no_progress` finalization
  intent. Restart
  consumes that intent with exactly one tools-disabled Markdown synthesis and
  never replays it after completion. Presentation text, query wrappers, and
  transport identities do not count as progress.
  Core retries only explicit `retryable` read-only observations once, honors
  no more than 30 seconds of retry delay without overwriting a
  producer-consumed retry, and permits one `invalid` argument correction.
  Exhausted correction/retry,
  `auth`, `user_input`, `fatal`, and `unknown_mutation` observations enter the
  same tools-disabled finalization path; a same-turn steer resets that tool
  supervisor window. Observation-free provider results fail closed rather
  than being inferred from content or `is_error`.
  Evidence-bearing references expose stable provenance through
  `CoreConversationReference.source_id`, `chunk_id`, and `content_digest`.
  Private Web Search tool results use `web_source` with a canonical URL source
  identity (lowercase scheme/host, no default port or fragment, `/` for an
  empty path, and sorted query parameters) plus the result-content digest and
  a bounded display title.
  They never place fetched page bodies or search snippets in a public
  reference preview. Terminal public answers omit `web_source` references;
  user-visible sources appear only as descriptive Markdown links synthesized
  into `done.message.content`. Knowledge results use
  `knowledge_chunk` with the durable source/chunk identities and passage
  digest. These identities, rather than titles, previews, or snippets, feed
  progress detection.
  An unapplied same-turn steer deferred during a failed Cloud Worker call may
  admit only one forced `cloud_worker_propose` follow-up; that dispatch exposes
  no extension or unrelated intrinsic tool.
- Each root supervisor/execution invocation produces at most one secret-free
  structured convergence record when its Native turn becomes terminal. Core
  retains no permanent per-Service turn map; durable `turn_id` lets downstream
  consumers deduplicate records across process restarts.
  The record is rebuilt from the terminal Turn, event history, and finalization
  intent and contains only `duration_ms`, `deadline_class`,
  `useful_markdown`, `runtime_incompatible`, `model_dispatch_count`,
  `tool_call_count`, `directive_count`, `repeat_count`,
  `finalization_reason`, `fallback_used`, `recall_degraded`, and
  `worker_poll_count`. `directive_count` is the one persisted directive per
  physical dispatch; Worker polls count durable `cloud_worker_inventory` call
  events rather than tool-authored result content. No prompt, response text,
  tool arguments, provider reasoning, runtime JSON, or credential is logged.
- Provider adapters preserve provider-issued tool-call IDs. When Gemini omits
  an ID, Core allocates one that cannot collide with any tool call already in
  the frozen request transcript, for both unary and streaming responses.
  Consecutive Anthropic tool results are emitted as one user message containing
  the complete ordered `tool_result` block batch.
- Model profile create/sync requires an explicit `request_dialect`, and update
  requires it even when unchanged. Profile reads return the selected dialect;
  durable execution snapshots and their digests bind it so a model name never
  selects request behavior implicitly.
- Native conversation progress durably publishes only validated assistant
  `delta` text. When the admitted runtime exposes tools, the adapter keeps all
  model-authored content private until the complete provider step is known. A
  step containing structured tool calls publishes no model-authored text; only
  a completed, tool-free final answer is released as bounded coalesced public
  text. Provider reasoning is absent from public messages, stream events, Capability JSON,
  RPC projections, conversation history, failed transcripts, and every durable
  model-result envelope. A complete model step publishes the existing
  `tool_call` event only after the model step and tool identity are durable, and
  before the extension is dispatched. The public event contains only call ID,
  tool name, and optional execution ID; it never contains model-authored
  arguments. A successful call is followed by a public `tool_result` progress
  event containing only call/tool identity, outcome/error state, mutation
  state, and bounded summary. Exact result content, cursors, and result
  references remain private to the durable model transcript. Terminal `done`
  returns authoritative non-Web answer references; Web sources are represented
  only by descriptive Markdown links in the answer body. An ordinary Core
  intrinsic
  failure becomes a bounded terminal tool observation and enters the existing
  tools-disabled synthesis, so completed work and gaps return through normal
  `done`. Integrity, persistence, and dispatch-authority failures retain
  failed-turn semantics. Durable turns
  persist the same public ordering while their private pending/dispatched
  envelope remains the at-most-once authority and is never exposed as an
  additional client event. Provider replay reconstructs one assistant message
  containing the model round's content and complete tool-call batch, followed
  by the matching tool-result messages in call order. An OpenAI-compatible
  adapter may parse provider reasoning internally and pass it once, in live
  process memory only, to the immediately following non-finalization,
  tools-admitted continuation of that same turn. It is consumed once, omitted
  from tools-disabled finalization, and unavailable after restart, cancel,
  steer, supervisor exit, or service close.
- OpenAI-compatible streams accept either `[DONE]` or a nonempty first-choice
  `finish_reason` as an explicit terminal signal. A clean EOF after that signal
  preserves the final content/tool-call delta. If a stream truncation, request
  failure, or idle timeout occurs after content or a complete tool delta,
  Core durably closes that side-effect-free output fragment and continues the
  same turn; the same failure before such output remains terminal. The `length`
  finish reason uses the same continuation with the frozen model context and
  full accepted tool catalog. An incomplete tool-call fragment is never
  dispatched; the next model round must issue it again as one complete call.
  OpenAI-compatible provider reasoning is parsed only for the bounded live-only
  continuity described above. The adapter parses complete SSE events rather
  than individual lines: CRLF is accepted, comments and non-`data` fields are
  ignored, and multiple `data` fields are joined in order before JSON decoding.
  Provider failures retain a typed internal
  taxonomy for cancellation, request/deadline timeout, idle timeout, HTTP 429,
  other HTTP 4xx, HTTP 5xx, unavailable transport, invalid response, truncated
  stream, and output limit. Safe diagnostics collapse status failures to their
  HTTP class and never include response bodies. A provider HTTP 4xx, including
  429, is classified as `provider_rejected`; timeouts become
  `provider_timeout`, invalid local completion input becomes
  `invalid_model_request`, and invalid or prematurely terminated provider
  streams retain the distinct `provider_invalid_response` or
  `provider_stream_truncated` code. An unclassified transport or 5xx outcome
  remains `provider_uncertain`. Before visible output, the one ordinary retry
  described below remains available. After that ordinary path stops, these
  classifications become the stop reason for the single no-tools finalization
  attempt or its completed Markdown fallback; they do not by themselves expose
  a failed-turn JSON result. Unknown external tool side effects and
  authorization become explicit terminal tool observations; integrity and
  persistence failures retain failed-turn semantics.
- When a turn's admitted runtime exposes tools, an OpenAI-compatible response
  that has no structured `message.tool_calls` but contains a known
  protocol-shaped DSML, XML, or model-template tool envelope in the ordinary
  content channel is never parsed as a call,
  published as assistant text, or executed. Detection covers a natural-language
  prefix, fragmented streaming, and a truncated bare envelope while excluding
  Markdown fenced, inline-code, and quoted examples. The adapter quarantines
  the complete provider response, records `MODEL_TOOL_CALL_FORMAT_INVALID`, and
  permits one dispatch-local retry with fixed guidance requiring standard
  OpenAI-compatible `tool_calls`. If that retry repeats the failure, Core
  persists a tools-disabled finalization and asks the model to produce the best
  useful answer from evidence already retained in the private transcript. The
  guard remains active during this finalization; one repeated format failure may
  retry the same tools-disabled directive with ordinary-answer guidance, and a
  further failure completes through deterministic Markdown. No retry restores
  tool authority, and text inside the candidate is never promoted into a tool
  call. Structured tool calls remain the sole execution authority.
- The DeepSeek compatibility adapter does not add a second executable
  protocol. For the first-party DeepSeek API and DeepSeek models reached
  through an OpenAI-compatible gateway, a tools-admitted request carries fixed
  platform guidance that ordinary content is non-executable and an explicit
  `tool_choice: auto`. After a quarantined text-protocol response, the single
  correction attempt uses `tool_choice: required`; an already-authorized named
  tool remains the stronger exact choice. DeepSeek's reasoning request dialect
  uses the same `auto`/`required`/named selection because the current official
  V4 Chat Completions contract supports structured tool calls in thinking mode.
  These controls affect provider output
  shape only and never bypass tool schema validation, accepted snapshots,
  permissions, confirmations, or the text quarantine. DeepSeek strict mode is
  not enabled by silently changing a configured endpoint to its beta API.
- Recent tool-loop recovery is deliberately conservative and resets at an
  accepted steer. It recognizes only repeated canonical action/result pairs or
  exact A/B alternation. Argument object key order and harmless unquoted local
  shell whitespace are equivalent, while quoted shell content remains exact;
  result identity ignores only transport call IDs and timestamps. Three equal
  pairs or six alternating pairs add corrective guidance without removing
  tools. Only a fourth equal pair or eighth alternating pair makes the next
  provider request tool-free for one-pass synthesis. Different arguments or
  results remain progress.
- On every Native conversation turn, `Chat`, `StreamChat`, and `StartTurn`
  compose two memory layers before model dispatch. Working memory remains the
  versioned structured `WorkingContext` plus the recent authoritative
  transcript window; the free-form summary is not model input. Before accepting
  an existing-conversation Turn, Core estimates the frozen model envelope as
  `ceil(total UTF-8 bytes / 4)` using the compiled system prompt, current
  prompt, structured WorkingContext JSON, retained transcript payloads,
  selected Skill instructions, and admitted intrinsic/extension tool schemas.
  When that estimate exceeds 80% of
  `context_window - max_output_tokens`, Core projects the smallest completed
  transcript prefix that brings the retained envelope under the threshold,
  without splitting an assistant tool-call/result round. If no suffix fits, it
  projects the whole completed prefix. The projection, message offset, source
  scope, and superseded protected digest are persisted atomically with Turn
  admission without advancing the public conversation revision; PostgreSQL
  rechecks that revision, the prior offset/digest, transcript count, and
  boundary message IDs under the admission lock. Unknown/nonpositive model
  input budgets disable automatic compaction. Explicit owner
  `compress_context` remains a public revision-bearing mutation. The complete
  transcript remains authoritative and is never deleted. Long-term memory
  combines relevance-ranked current user facts with a bounded newest-first
  fact timeline. Current facts take precedence over older timeline entries.
  The bounded envelope is inserted as
  explicitly delimited model-only reference data before the current prompt; it
  is never copied into conversation messages, turn/event payloads, public
  Knowledge cursor snapshots, logs, or Capability results. Every current
  automatic per-turn recall is optional and has a fixed internal three-second
  deadline. A timeout or dependency failure while the turn remains live
  appends one closed `memory_recall_degraded` warning, continues the same turn
  without recalled memory, and never retries recall for that turn, including
  after restart. The warning is projected as distinct safe progress through Watch,
  StreamChat, and Capability streaming; it is never a delta, tool result,
  model input, transcript message, runtime snapshot, or final Markdown field.
  Parent/service cancellation wins without a warning or provider dispatch. An
  empty recall remains a successful empty context. Authenticated explicit
  `agent.memory.v1` operations remain fail closed. No current admitted turn
  declares recall as an authorization or safety prerequisite; any future
  required recall must be represented by immutable admitted state rather than
  inferred from prompt text, execution mode, or tool selection.
- Every successfully committed Native exchange atomically creates a private
  consolidation observation. A restart-safe worker uses the selected
  conversation model to extract only explicit durable user facts. Facts use a
  stable subject/predicate identity: the same value confirms the current fact,
  a different value supersedes it, and an explicit negation retracts it. The
  previous row is retained with a validity end time and an append-only
  `added`, `confirmed`, `replaced`, or `retracted` event. Extraction failures
  are retried with a bounded durable lease and never roll back the completed
  chat. Secrets, assistant assertions, transient requests, guesses, and
  sensitive inferences are excluded by the extraction contract.
- Automatic structured conversation memory starts disabled. The owner-client
  `agent.memory.v1/get_config`, `update_config`, `status`, `update_fact`, and
  `delete_fact` operations expose the only long-term-memory surface. Config
  changes use revision fencing; fact edits and retractions fence the exact
  immutable active fact ID. Mutations use UUID idempotency. Editing preserves
  subject, predicate, kind, and confidence while creating a replacement fact
  plus a `replaced` timeline event; deleting retracts the exact active fact and
  appends a `retracted` event. Enabling requires the current
  Knowledge embedding binding to resolve to a non-deleted embedding profile
  with configured credentials. Disabling preserves facts and the complete
  conflict timeline but returns an empty structured-memory recall and stops new
  observations; Knowledge search and durable conversation history keep their
  independent contracts. Timeline events publish separate RFC3339
  `effective_at` and `observed_at` clocks.
- Authenticated Native conversations also receive one Agent-owned, read-only
  `knowledge_search` model tool when Knowledge is enabled. It searches only
  ready sources with promoted bindings that match the active embedding
  profile revision and collection digest. The tool accepts a bounded query,
  optional source IDs, and a result limit; it returns bounded passages plus
  secret-free embedding provenance and never calls back through Product
  Capability.
- Authenticated durable Native turns receive the Core-owned
  `agent_schedule_create` intrinsic when the PostgreSQL conversation/schedule
  store is composed. A supported creation request must invoke it exactly once;
  only its successful atomic commit may emit the reserved `Scheduled ...
  (schedule_id: ...)` receipt. A model-only success receipt fails the Turn and
  writes no response or schedule. Unsupported workflows are refused without a
  tool call. Model input is limited to a concise human-readable `name`
  (the sole schedule-card title), `goal`, required closed `capability`, exactly
  one `run_at` or `cron` plus IANA `timezone`, and optional
  `timeout_seconds`. The closed capabilities are:
  `scheduled_note` (no tools), `chat_summary` (`message-mcp`:
  `dirextalk_rooms_search`, `dirextalk_messages_list`), `web_research`
  (`builtin:web_search:tavily`: `web_search`), `room_message`
  (`message-mcp`: `dirextalk_rooms_search`, `dirextalk_messages_send`),
  `contact_report` (`message-mcp`: `dirextalk_contacts_list`,
  `dirextalk_contacts_search`), `room_member_report` (`message-mcp`:
  `dirextalk_rooms_search`, `dirextalk_room_members_list`), `channel_digest`
  (`message-mcp`: `dirextalk_rooms_search`, `dirextalk_channel_posts_list`,
  `dirextalk_channel_comments_list`), and `chat_summary_delivery`
  (`message-mcp`: `dirextalk_rooms_search`, `dirextalk_messages_list`,
  `dirextalk_messages_send`), plus the ordered two-source
  `web_digest_delivery` (`builtin:web_search:tavily`: `web_search`, then
  `message-mcp`: `dirextalk_rooms_search`, `dirextalk_messages_send`). It sends
  one Matrix message to a group/channel room and never creates a channel post.
  Core checks those exact creating-Turn snapshot
  bindings before normalization or persistence. Unknown workflows, wrong
  sources, and missing tools return a bounded correctable intrinsic error and
  write no schedule row; installed extensions are not a generic scheduled-
  workflow escape hatch.
  Owner, account generation, and conversation are injected from the fenced
  turn lease. A valid converged default conversation model is required when the
  schedule is accepted, but the schedule template persists an empty
  `model_profile_id`; it never freezes the model used by the creating Turn.
  Owner and generation persist only in the typed
  `task_template.payload.agent` authority object; credentials and
  attachment/Knowledge references are not accepted. The internal payload also
  snapshots only the exact provider-facing tools required by the selected
  capability; `scheduled_note` persists an explicitly empty set. Installed
  MCP/Skill, unrelated Message MCP, Product Capability, and semantic Knowledge
  bindings are excluded. Due Tasks revalidate the retained snapshot, filter the
  live resolver catalog back to that exact tool set, and fail closed on drift.
  Each occurrence transaction converges, resolves, and locks the current default
  conversation model, then pins its exact profile id, revision, credential
  version, request dialect, model kind, configuration, and protected secret
  reference in that occurrence Task. Exact `trigger_now` replay and Task
  retry/reclaim reuse the committed Task snapshot even if the default changes;
  a later occurrence uses the later default. Legacy-null and invalid bindings
  first converge by the same stable creation order; only zero eligible
  conversation profiles rejects creation or blocks later materialization,
  without creating an occurrence/Task, silent skip, or auto-pause.
  A due schedule delegates through the durable Native Turn executor with
  deterministic request/turn identities derived from the occurrence Task.
  Its trusted prompt binds the immutable occurrence `Task.AvailableAt` in UTC,
  the persisted schedule timezone, and the corresponding local timestamp;
  relative windows are evaluated from that occurrence rather than delayed
  execution wall-clock time. The same trusted prompt supplies capability-level
  single-pass execution guidance: room lookup is skipped when an exact room ID
  is already present and otherwise attempted at most once; summary message
  reads are attempted at most once; Web research performs one focused
  `web_search`; delivery workflows synthesize before one message send. A
  model-issued tool call is not repeated with altered arguments after error,
  insufficient data, or unknown completion; any provider-internal safe retry
  remains below that model-call boundary. The immutable scheduled Turn runtime
  also binds the persisted capability as a closed constrained workflow. Core
  rebuilds admitted-call state from durable call sequence, permits at most one
  new scheduled call per provider round, and counts any terminal observation
  as completion. A restart may dispatch only the exact single persisted
  pending call; it cannot reauthorize a batch, changed call, terminal
  duplicate, or out-of-order tool. Channel-comment reads additionally require
  a distinct `post_id` projected by the preceding posts-list result. At a
  capability's forced terminal boundary, Core performs one no-tools Markdown
  synthesis. `contact_report` after a contacts-list result and
  `channel_digest` after a posts-list result may instead use the ordinary
  request to return final Markdown or issue only their still-admitted optional
  search/distinct-comment reads. Crash recovery therefore resumes the same
  prompt and transcript commit. A successful
  Task exposes exactly the committed assistant Markdown as `result.text` and
  leaves `result.json` empty; it does not append another assistant message.
  Background execution carries only the persisted owner and positive account
  generation, with no synthesized Product Capability grant or scope. Its
  immutable runtime policy exposes no Core intrinsics, preventing nested
  schedule creation, static-site publication, Cloud Worker actions, or other
  unrelated side effects.
  `scheduled_note` is visible as Native conversation/schedule-history Markdown
  and does not promise Matrix or operating-system push delivery. The
  `room_message`, `chat_summary_delivery`, and `web_digest_delivery` Matrix
  writes are dispatch-recorded before the provider call; an unknown completion
  result is returned as an error observation and is never retried blindly.
  Schedule creation, its replay receipt,
  both transcript messages, terminal turn response, and done event commit in
  one transaction. Schedule and idempotency identities are deterministic from
  the accepted turn/request/tool-call identity, so an uncertain same-call retry
  replays without creating another schedule.
- `agent.schedules.v1/list_outputs` is an `agent:schedules:read` operation. It
  requires `schedule_id`, accepts a 1..200 `page_size` and opaque
  `page_token`, revalidates the live schedule before reading, and returns
  newest-first occurrence output ordered by
  `(scheduled_for, occurrence_id)` descending with a stable descending tuple
  cursor. Tokens are canonical (surrounding whitespace is invalid) and bound to
  the requested `schedule_id`, so they cannot be replayed across schedules.
  Each closed item exposes only `occurrence_id`, `task_id`,
  `scheduled_for`, current Task `status`, `created_at`, `updated_at`, optional
  safe Task `result`, and optional `failure_code`/`failure_summary`. Task
  payloads, goals, model or extension snapshots, owner authority, and secrets
  are never projected. Soft-deleted Task rows remain readable through their
  immutable schedule occurrence.
- Authenticated durable Native turns receive `static_site_publish` only when
  the Agent-owned static-site root passes startup readiness. The model supplies
  one self-contained UTF-8 `html` document of at most 192 KiB; it never
  supplies a path, URL, site identity, archive, or storage credential. Core
  derives immutable site/release UUIDs from the fenced owner, conversation,
  turn, request, and tool-call identities, publishes exactly `index.html`, and
  records its digest, size, and `/.sites/{site_id}/{release_id}/` path before
  atomically completing the turn with the absolute
  `https://<node-domain>/.sites/{site_id}/{release_id}/` URL. Same-call
  recovery verifies and reuses the
  exact file and PostgreSQL receipt. The embedded `publish-static-site` skill
  instructs the model to produce semantic, responsive, self-contained HTML;
  the edge sandbox CSP blocks scripts, forms, external subresources, and
  programmatic network access even when generated markup drifts.
- Ready static-site composition publishes `agent.static_sites.v1` for the
  authenticated owner. `list_releases` accepts only bounded page input and
  returns `site_id`, `release_id`, `conversation_id`, server-produced
  `public_url`/`public_path`, `size_bytes`, and `created_at`.
  `delete_release` accepts exactly `release_id` plus a UUID
  `idempotency_key`, removes only the receipt-derived release, and returns
  `{release_id,deleted,replayed}`. Public page bytes remain available through
  the absolute URL; no second download operation exists.
- Capability conversation reads use a closed Flutter-facing projection.
  Conversations expose only id/title/revision/timestamps/status; history
  exposes only user/assistant messages with durable sequence, terminal status,
  additive owning `turn_id` when the message belongs to a durable Turn,
  references, and attachment presentation
  (`source_id`, `kind`, `name`, `mime_type`, and `size_bytes`). Attachment
  content, digest, source revision, status, and expiry remain private. The first history page
  contains the newest bounded messages in ascending sequence order, and its
  opaque cursor is bound to the conversation id and prior sequence. Empty
  `messages`, `conversations`, `turns`, and attachment collections are JSON
  arrays, never `null`.
- Capability `agent.chat.v1/list_turns` accepts only a canonical conversation
  UUID, an optional opaque page token of at most 4,096 bytes, and an optional
  limit from 1 through 1,000. Its closed result projects exactly `turn_id`,
  the original start `idempotency_key`, `conversation_id`, `state`, `revision`,
  `last_sequence`, `terminal_code`, `terminal_summary`, `created_at`, and
  `updated_at`, durable `prompt`, and the same non-sensitive attachment
  presentation. Request fingerprints, model/profile data, credentials, and
  execution snapshots never cross the Capability boundary.
- Capability `agent.chat.v1/stop_turn` is the monotonic durable-turn
  cancellation mutation. It accepts exactly `idempotency_key` and `turn_id`,
  calls the conversation service cancellation
  path, and returns only the same public turn metadata plus the cancellation
  request `idempotency_key`. The request is bound to the immutable turn ID and
  replays after later turn state changes; it does not use the changing turn
  revision. It does not alias generic Capability operation cancellation or
  accept unknown fields; the owner-visible prompt and attachment presentation
  remain recoverable while profile and execution bindings stay private. When
  the turn is parked on an active Cloud Worker execution, the same mutation
  cancels that execution and its Task without destroying the retained Worker.
- Capability `agent.chat.v1/steer_turn` appends one non-empty instruction to
  the same accepted/running durable turn, or to a confirmation-waiting turn
  whose current Cloud Worker offer is unconfirmed, queued, or running. It
  accepts exactly a mutation `idempotency_key`, `turn_id`, positive
  `expected_revision`, and
  `instruction` plus optional `accepted_attachment_ids` (at most four). The
  mutation UUID is also the attachment `turn_request_id`; Agent consumes the
  committed sources atomically with the steer event. Before a tool call becomes public, the store records the
  instruction, advances the turn revision, invalidates the active provider
  lease, and cancels that provider context. Once a tool call is public or
  dispatched, the same mutation preserves its authority and lease. Ordinary
  tool results continue with the recorded instruction in the next model round.
  The immutable SSH Worker runtime has no guidance channel after the remote Pi
  process starts. During provisioning, or while a resumed runtime is still
  `not_started`, Agent resolves deferred instructions and readable text
  attachments once at the SSH runtime-start boundary and appends them to the
  objective before starting Pi. The terminal Worker result records the exact
  applied steer mutation IDs. Guidance arriving after that boundary remains an
  explicit conversation follow-up, and terminal success includes a truthful
  notice only for those unapplied mutations. Core never re-proposes the Worker,
  re-runs the intrinsic, or creates a successor turn. The typed
  result returns the original turn idempotency identity plus the separate steer
  mutation receipt; owner-visible prompt and attachment presentation remain
  recoverable while profile data stays private.
  Durable SSE replay emits each accepted steer as `kind=steered` with the
  original turn idempotency key, separate `steer_idempotency_key`, instruction
  text, non-sensitive attachment presentation, revision, status, and timestamp;
  its SSE sequence remains the `Last-Event-ID` recovery cursor.
- Every accepted operation or turn SSE stream begins with `retry: 3000`, emits
  a comment heartbeat every 12 seconds while idle, and stops on request
  cancellation or a failed write/flush. Heartbeats do not advance the durable
  event cursor or alter replay semantics.
- Turn SSE data envelopes always carry independent `operation_id`, `turn_id`,
  and `conversation_id` fields. This version still requires the operation and
  turn identifiers to be equal, and the Agent projection rejects missing,
  invalid, or unequal identities before emitting a frame; consumers must still
  parse and validate both.
- Capability `agent.chat.v1/start_turn` admits the same durable conversation
  turn exposed by `get_turn` and `list_turns`, then returns without watching
  execution. Its HTTP `operation_id` is the public `turn_id`; the request id
  remains the distinct client-message idempotency identity. Disconnecting an
  SSE consumer does not cancel execution; only `stop_turn` requests
  cancellation of that exact durable turn. A Cloud Worker lifecycle change is
  projected on SSE as `kind=worker_status` with only the existing turn
  identity and revision, event `created_at`, exact `execution_id`, and canonical
  `status`. New execution offers still use the separate
  `waiting_confirmation` event. The Worker projection is written in the same
  transaction as `queued`, `provisioning`, `running`, and terminal execution
  changes; it is not synthesized by polling.
- Accepting the first turn of an untitled conversation immediately persists a
  deterministic, normalized, bounded prompt-prefix title. Successful first-turn
  title generation may replace that provisional value; later user titles are
  not overwritten. If that first turn is stopped before it commits a message,
  the next successful turn still uses the earliest durable turn prompt to
  replace the provisional value with the generated title.
- Stored credentials are write-only from ordinary read/list APIs. Responses
  expose status, fingerprints, revisions, or binding digests, never secret
  bytes. Agent-owned secret fields use the configured encrypted-at-rest store.
  Exactly one credential may be active: concurrent creates are serialized and
  a second create is rejected until the current credential is deleted.
- Optional `agent.worker.v1` publishes only after the persistent SSH Worker
  manager, bounded three-Region placement, and the sole current verified AWS
  credential source are composed; the host deployment Region is optional.
  `list_workers` and `get_worker` expose the exact
  AWS resource identity, observed EC2 state and ordinary auto-assigned public
  IPv4, Worker/task phase, server load and last-seen time, live hourly quote,
  availability and optional workload hostname/managed-domain status. An
  unavailable historical
  credential or one failed AWS observation is projected on that retained
  Worker without hiding other records. At most four retained Workers may exist
  for one authenticated owner/account generation across credential revisions;
  a destroying Worker whose compute resources are already gone does not occupy
  a slot while DNS cleanup is retried. A domain is optional per workload.
  Native Agent conversations expose separate `cloud_worker_domain_bind` and
  `cloud_worker_domain_unbind` model tools after Worker creation; they are not
  owner-client `agent.worker.v1` mutations. Bind accepts only `worker_id`,
  `workload_id`, and `hostname`; unbind accepts only `worker_id` and
  `workload_id`. The authoritative Native turn executes each call directly; it
  creates no second confirmation, Task, action card, or `waiting_confirmation`
  state. Each call resolves and revalidates the exact owner generation, AWS
  account, credential revision, Worker resource identity, workload, hosted zone,
  A record, and intent digest. Bind maps a 300-second A record to the
  authoritatively observed current public IPv4 only when the hostname has a
  longest-suffix matching public Route53 hosted zone visible through the
  current verified AWS account. Before publishing that record, bind reconciles
  the exact Agent-managed Caddy reverse proxy over the Worker's pinned SSH
  identity and opens public ports 80 and 443. It then verifies HTTPS directly
  against the authoritative Worker IPv4, closes the workload's direct public
  port, and only then commits the binding and successful tool result. A proxy,
  security-group, DNS, or HTTPS failure leaves the exact staged identity for an
  idempotent retry and cannot be reported as a successful binding. It accepts
  no private, external/manual, or cross-account zone fallback. No match returns
  an explicit correctable tool
  error before Apply, provider write, binding persistence, or turn-success
  commit. Before any Worker proxy, security-group, workload-state, or DNS
  mutation, bind reads the existing A record. A differing IPv4 or TTL is not
  overwritten and returns the existing and intended values as a correctable
  `user_input` tool observation with `mutation_state=unchanged`. Unbind deletes only the exact
  persisted record and may proceed while the Worker is unavailable. Both verify
  the owning account and provider read-back and refuse to
  overwrite or remove a changed record. Initial service creation may still
  return manual A-record instructions when it cannot publish DNS; the later
  domain-bind tool never uses that fallback. Bind state and the last exact removed
  record are retained locally so a retry after Route53 mutation but before the
  final turn commit reconciles the same provider result idempotently and
  read-backs it again. Route53 support may be unavailable
  when the current account/zone is not configured; this does not suppress Worker creation,
  reuse, list, get, or destroy. There is no EIP field or operation. `destroy_worker`
  requires its explicit confirmation literal and the complete identity
  returned by list/get; a changed resource identity fails closed, while busy,
  provisioning, and unavailable Workers remain destroyable. A known retained
  Worker is resolved from local identity without requiring SSH or a live status
  probe. Once that authorization and exact identity are resolved, Agent persists
  the destroy intent, cancels and drains execution, completes exact EC2 and
  security-group/key cleanup, then removes and reads back owned Route53 records
  and completes local cleanup in a bounded server-owned context; a client disconnect
  does not cancel the accepted cleanup.
  If credentials rotate after a provisioning intent, recovery only discovers
  and persists resources carrying that intent's exact tags so partial resources
  remain destroyable; it never creates a missing resource or resumes execution.
  A successful retained-Worker completion durably records its exact
  `worker_id` and a structured `next_action` bound to that same ID asking
  whether to run `destroy_worker`; retain is the default and the completion
  itself never destroys the Worker. The client resolves that ID through the
  current Worker inventory before offering the existing identity-bound destroy
  action. Deleting a credential revision is rejected while that revision has a
  retained Worker. Account deprovision is rejected before destructive mutation
  while any retained Worker remains on the Agent, including an older owner or
  account generation; the owner must destroy every such Worker and retry.
- Always-ready `agent.servers.v1` is the owner-client inventory projection for
  the primary Agent node and retained Workers. `list_servers` pins the immutable
  `agent_instance_metadata` identity first and orders Workers by persisted
  creation time and ID; its `artifact_count` includes only user-visible
  deliverables and excludes the primary node's immutable backend-service row;
  `get_server` resolves one stable server ID;
  `list_artifacts` pages the server-bound catalog with the non-deletable Agent
  backend service first; `delete_artifact` deletes only static pages and local
  or Worker execution files through their owning repository; `destroy_server`
  rejects the primary node but permits explicit destruction of busy Workers. The
  `core_server_artifacts` catalog is the authoritative binding/index, not an
  artifact body store. New static pages, sandbox files, Worker files, services,
  and domain changes update it; pre-migration history is not backfilled. All
  Worker destroy surfaces converge on one exact-identity cascade that marks the
  catalog deleting, stops execution and removes service/DNS/AWS state and indexed
  execution bodies and catalog rows before finalizing and reading back Worker
  absence. Until all cleanup succeeds, the Worker stays visible as destroying
  so artifact, DNS, or local-key failures can be retried. Conversation,
  Task, run, and audit records are retained. Before catalog cleanup, destruction
  closes unfinished durable Task/run publication under the same fence as terminal
  result publication, so a late result cannot restore deleted attachments.
  Already absent Workers and repeated
  exact cleanup requests succeed; infrastructure or identity failures remain
  explicit errors and leave retryable cleanup state.
- Every `agent.knowledge.v1` mutation, including `index_sources`, requires an
  explicit canonical UUID `idempotency_key`; missing or malformed keys are
  rejected, while read operations do not require one. Neutral
  `agent.aws.v1/test_credential` binds `credential_id`, `expected_revision`,
  and its UUID key to a durable, secret-free replay. The provider call runs
  outside database transactions and row locks. A same-key retry observing an
  active claim polls until its persisted 30-second lease plus short completion
  grace, then replays the completed result or deterministic provider-failure
  receipt; an abandoned or completion-uncertain claim becomes fail-closed and
  is never taken over for a second STS request. Credential verification
  timestamps and replay receipts are monotonic when different keys complete
  out of order. There is no separate non-keyed credential test RPC.
- Neutral Capability model-profile mutations and conversation mutations also
  require explicit canonical UUID idempotency keys. Missing or malformed keys
  are rejected rather than replaced with adapter-generated identities.
- Knowledge upload fields include declared size and whole-content SHA-256;
  chunks carry contiguous ordinal/offset and per-chunk digests. Commit rejects
  revision, size, or digest drift. Search cursors retain the secret-free
  embedding provenance used for their page.
- Knowledge vectors are stored in Agent PostgreSQL through pgvector. Process
  configuration supplies only the vector dimension; endpoint, collection, and
  content-quota settings are not public configuration. The aggregate indexable
  content limit is 64 MiB, each source is limited to 16 MiB, and uploading
  reservations count toward the aggregate. Status returns
  `quota_used_bytes`, `quota_limit_bytes`, `quota_remaining_bytes`, and
  `max_source_bytes`. Only aggregate exhaustion returns
  `RESOURCE_EXHAUSTED` with the safe message
  `Knowledge content quota is exhausted` and detail code
  `knowledge_quota_exceeded`; parser and per-source limit failures remain
  `INVALID_ARGUMENT`.
- `agent.web_search.v1` exposes `get_config`, `update_config`, and `test` for
  the typed Tavily provider. Only `update_config` accepts the write-only key;
  chat requests carry no `tool_credentials` envelope.
- `agent.text_tools.v1` is an owner-client-only Capability with `get_config`
  (READ), `update_config` (MUTATION), and `execute` (MUTATION). Configuration
  is a full ordered-list replacement: at most 32 items, at most six enabled
  items, unique stable built-in or canonical UUID IDs, and contiguous order.
  Revision zero is a virtual disabled global config containing the four
  server-authored translation, summary, explanation, and search defaults;
  search alone defaults disabled. The first update must expect revision zero.
  An update that makes the global configuration and search enabled is accepted
  only when the same owner/account generation already has enabled Tavily Web
  Search with a valid server-side credential. Disabling either layer does not
  require a search credential. `execute` rechecks that fence and fails closed
  if Web Search is later disabled, cleared, rotated, or unavailable. `execute`
  accepts only `tool_id`, selected text, and the required current UI output
  language (`zh` or `en`). Stable built-ins bind their complete response to
  that language, so translation never guesses a target language from model
  context; UUID custom tools retain their authored prompt. Execution resolves
  the explicit `default_tool_client_profile_id`
  conversation profile and current credential server-side with no fallback,
  and never writes conversation, history, Task, or execution replay state.
  Search alone uses the fenced Tavily path with at most five results, bounds
  the provider query to Tavily's 1,000-rune limit while preserving the full
  selected text for the model, and sends its evidence as separate untrusted
  model context. Model execution is one
  shot, limited to 60 seconds and 64 KiB of output.
  Because `execute` is a Capability MUTATION, the common operation ledger
  retains the bounded output/sources JSON as its ordinary plaintext result and
  event receipt until ledger/account cleanup; deprovision purges it. The
  ledger always stores request JSON as `{}`, so selected text is not durable.
  Pending or running calls interrupted by restart become `uncertain` and are
  never automatically dispatched again.
- `agent.image_tools.v1` is the owner-client-only, five-operation image text
  boundary: `upload_begin`, `upload_append`, `upload_commit`, `extract_text`,
  and `translate_text`. JPEG, PNG, and WebP bytes use a dedicated PostgreSQL
  source store with an 8 MiB image limit, 1 MiB canonical chunks, SHA-256
  verification, 30-minute expiry, and exact owner/account-generation/image-
  request binding. A committed source is atomically consumed once and its
  database bytes are cleared before the provider call. Execution requires the
  global text-tool switch, the explicit conversation-kind Tool default, a
  current credential, and advertised `image` input modality; there is no
  profile or conversation fallback. Fixed server prompts provide only text
  extraction and translation to a canonical BCP-47 locale. Calls create no
  conversation, history, Task, or image replay rows outside bounded upload
  idempotency receipts; the common Capability ledger persists request `{}`.
- Unknown enum values, malformed UUIDs, invalid digests, and unsupported
  combinations fail closed as `INVALID_ARGUMENT` or `FAILED_PRECONDITION`.

`TaskService` and `ScheduleService` use one durable Task/event path for
background model, extension, Knowledge, and AWS work. `ConfirmationService`
is the common explicit-confirmation boundary for side-effecting MCP/Skill and
typed cloud operations. `WorkloadService` uses the distinct `WORKLOAD` Task
kind and owner-only operation/event/actual read-back actions. The single
ephemeral Pi path uses `CLOUD_WORKER`; its payload pins plan/revision/digest,
confirmation, conversation/turn, quote, execution digest, and account generation;
while the real CoreTask claim and launch material separately pin attempt and
lease epoch.

`SkillService` exposes the same pinned lifecycle for `builtin`, `skills_sh`,
and `github` sources. Empty Skill discovery selects `builtin`; empty MCP
discovery selects `official_registry`. Built-in Skills are seeded exactly once
as ordinary installed records under the public identifiers
`dirextalk-research-and-verify`, `dirextalk-review-code`,
`dirextalk-verify-delivery`, and `dirextalk-write-technical-docs`. Uninstall
keeps the seed fence, so a process
restart cannot recreate the installation; an owner may explicitly discover
and reinstall the current built-in version.
When the owner selects an installed Skill for a Native conversation, the Agent
reads the exact pinned artifact at admission and injects all selected Skills
once as one clearly delimited user-role guidance block; Skill content never
receives system-message authority. Skill selection does not synthesize
an MCP tool or create a parallel execution path.
Two network-free, read-only built-in MCP installations are also seeded once:
`dirextalk-server-time` exposes `server_time`, and `dirextalk-server-load`
exposes `server_load`. They use ordinary installed-extension records, the
isolated runner, MCP discovery, and MCP execution. Their durable seed fence
has the same uninstall semantics as built-in Skills.

Managed Node MCP is current-only `stdio_node`. `npm` candidates require one
exact package version and verified immutable integrity; GitHub candidates
require one exact commit. Lifecycle script declarations stay bound to the
immutable source, while both lock-only resolution and offline installation
disable script execution. Runtime network, native add-ons, mutable tags/ranges,
and host Git are rejected. Provider and dependency-resolution HTTP clients use
the public-IP-fenced direct transport and ignore ambient process proxy
variables; a managed outbound proxy requires a future explicit validated
contract. Durable limits are 32 live
extensions, one install/update lifecycle, 64 MiB and 8,192 files per published
Node artifact, and 512 MiB total Node storage. Admission failures publish only
`extension_install_busy`, `extension_installation_limit`, or
`extension_node_storage_quota`. Installed version output contains the closed
eight-field `node_artifact` receipt with `lifecycle_scripts_disabled=true` and
never exposes prepared paths, cleanup tokens, tools, or internal
artifact/input/entry/lock digests. Empty installation/version grants and Node
stdio arguments are canonical JSON arrays, never `null` or omitted. Only
queued, running, and waiting-user task snapshots pin an installed artifact;
terminal task snapshots remain audit records and do not block a
revision-fenced uninstall.

Cloud Worker offers are created only by the Core intrinsic
`cloud_worker_propose` during an authoritative conversation turn. Public
clients use `agent.execution.v2.plans.get/list`,
`agent.execution.v2.runs.get/list/cancel/events`, and
`agent.execution.v2.artifacts.get/download/delete`; they use
`agent.core.confirmations.get/list/confirm/reject` for authorization. Every
tool call declares `intent=execute` or `intent=proposal_only`. Execute preserves
normal retained-Worker reuse and new-Worker confirmation behavior. Proposal-only
commits a non-executing plan summary before pricing or offer persistence and
creates no plan, execution, Task, confirmation, or Worker action. Every executing
proposal carries minimum vCPU, system memory, disk, estimated runtime, and an optional
closed provider-neutral accelerator class rather than an AWS instance type.
The accelerator class is GPU, Neuron, FPGA, media, or any accelerator; omission
leaves compute unconstrained. GPU proposals additionally carry a verified non-zero
minimum accelerator-memory working set; named model artifacts must be resolved
and sized before the proposal. Agent intersects current-generation Linux on-demand
products with actual regional offerings and live accelerator metadata and selects the cheapest satisfying
x86_64 shape in one of three Worker Regions: `ap-northeast-1`, `us-west-1`, or
`eu-west-3`. New placement lazily measures the three regional AWS EC2 HTTPS
endpoints concurrently after credential verification, with normal TLS checks
and a three-second bound, selecting the lowest successful duration. This is
endpoint connection/response-header latency, not a Worker latency guarantee.
If all endpoints fail, approximate great-circle distance from the optional
deployment-owned host Region selects the closest supported Region; an absent
or unrecognized host Region selects uniformly at random. Measurements and their
selected Region are cached for five minutes, with concurrent resolution
coalesced and expired entries refreshed on demand. Cancellation does not cache
a choice. Existing plans and Workers retain their exact recorded Region after
restart or changed placement, including Regions outside those three candidates
for observation, exact credential resolution, and cleanup. New-resource creation
remains restricted to the three candidates, including provisioning recovery;
all account/credential/revision fences still apply. A missing host Region never
disables composition, and the uploaded credential's default Region is not
resource-placement authority.
Every proposal performs a fresh AWS Price List read for that
exact EC2 shape and gp3 volume. The quote is not served from a persisted pricing
catalog. Confirmation exposes the exact shape, accelerator name and assigned
accelerator memory when present, and hourly compute price. A
bounded job also exposes its estimated cost and maximum authorized cost; a
persistent service omits those two open-ended values. Confirmation validates
the offer revision and expiry; after confirmation the task executes directly
without a second pricing or replacement-offer pass.
Reusing an already retained idle Worker requires its actual vCPU, memory, disk,
and persisted accelerator class to satisfy the request; absent accelerator
metadata never satisfies an accelerator request. The model-facing tool definitions are static and
contain no live Worker identity or state. The separate read-only
`cloud_worker_inventory` intrinsic revalidates the current turn owner and
account generation at execution, then returns an at-most-4-KiB
`cloud_worker_inventory/v1` `ToolResult` containing bounded current capacity,
status, task, address, pricing, load, and workload summaries. Each included
workload summary carries its exact `workload_id`, kind, phase, active state,
health, and optional port/hostname; per-Worker workload truncation is explicit.
That result is
durably recorded as nonterminal ordinary tool history and flows to the next
model round.
The model uses it to declare actual minimums and prefer an adequate idle Worker.
For an existing service's hostname-only change, it must use the exact inventory
IDs with `cloud_worker_domain_bind` or `cloud_worker_domain_unbind`; the proposal
intrinsic rejects that route before pricing so it cannot create a second Worker
quote.
Reuse needs no creation confirmation and executes directly for jobs, persistent
services, and hostname publication, but Agent still reads and displays its live
ongoing hourly cost. Worker destruction is a
separate explicit owner-confirmed operation. The owner may invoke it from the
Worker management surface or explicitly ask the Native Agent to destroy one
of the retained Worker IDs returned by `cloud_worker_inventory`. The static
destroy schema accepts that exact UUID plus its confirmation literal; the
conversation intrinsic accepts no provider identity from the model, re-resolves
the exact stored Worker under the current owner/account generation, and commits
the terminal conversation response only after destruction completes.
The intrinsic may create a priced offer for an explicit cloud request or when
trusted Native scheduler evidence proves that the local conversation runtime
lacks the general project/shell executor required by a substantial task. The
model may select it without cloud or remote wording, but model text and local
failures are not capability evidence. Cloud/local-only vetoes remain binding,
and AWS resources start only after the owner confirms the pending quote. The
manager supports no more than four retained Workers for one authenticated
owner/account generation across credential revisions. CPU and GPU Workers use
the exact public Dirextalk AMI pinned by the Agent's embedded Region/flavor release
catalog. Entries are added only after live image qualification and bind publisher
`066107820442`, schema, release/Pi versions and the GPU supported-family set.
Discovery checks that exact AMI ID and publisher, public visibility and supported
architecture; it does not read customer SSM parameters or unshared publisher tags.
It then reads the AMI's actual root device and snapshot minimum before
pricing and binds the greater requested/minimum size into the confirmed
ComputeSpec. Missing, incompatible, and unverified images fail distinctly with
no generic-image fallback. Launch re-resolves the catalog image and rejects for a fresh
quote instead of silently increasing volume size. Runtime discovery reads the default VPC, intersects its available default subnets with the selected instance
type's current availability-zone offerings, assigns an ordinary public IPv4,
and uses outbound SSH. First contact uses `accept-new` into a persistent `known_hosts`
file beside the Worker private key; later connections require that pinned host
key. The file must be a single-link, owner-owned regular file with mode 0600,
is opened without following symlinks, and is removed with the Worker key.
Image identity and publication controls remain internal provider data. Runtime state persists under
`/var/lib/dirextalk-worker`; retained execution recovery occurs before fresh
image/network/public-egress discovery. There is no EIP, frontend AMI control,
S3/KMS, WorkerControl callback, model relay, Worker domain, or
deployment-time binding. Terminal Worker output returns to the same durable
turn as a tool result with related task/plan IDs and local Agent-owned artifact
metadata. Remote workload completion is persisted before result collection.
When collection or its sink fails transiently, recovery sets `CollectOnly` from
that `RemoteCompleted` fence and may retry logs/artifacts without preparing or
starting the remote workload again; deterministic invalid or over-budget
results and provider client rejections persist `TaskFailed` and release the
retained Worker. Only an outcome that may have committed a provider mutation
remains recoverable as uncertain. A same-ID retry
of that failure remains terminal and never invokes SSH; it may only reconcile
Worker-release bookkeeping after exact owner, account-generation, credential,
Worker, and execution identity checks. Logs plus artifacts share the
execution's single result-byte budget, so artifact reads cannot exceed
the bytes remaining after logs. The proposal's estimated runtime covers
environment setup,
dependencies, model execution, the full requested active run or observation
duration, result collection, and reasonable margin rather than treating an
explicitly requested duration as the whole execution budget. Worker terminal
stdout is an internal report returned as tool evidence, never the user-facing
answer. Core performs a tools-disabled synthesis from that evidence and uses
the latest user message's language unless that message explicitly requests
another language. It does not paste or lightly reformat the report.

`agent.chat.v1/upload_attachment_begin` requires `kind` (`image`, `file`, or
`workspace_archive`) and a matching approved `mime_type`. A turn accepts at
most four sources, at most one workspace archive, and at most 8 MiB combined;
each source remains immutably bound to owner, account generation, turn request,
revision, size, and SHA-256. Workspace archives use the single constrained
tar+gzip media type and are never exposed as arbitrary local paths.
Conversation model input supports JPEG, PNG, WebP, UTF-8 `text/plain`, and
UTF-8 `text/markdown`. Text is framed as untrusted attachment content. PDF and
other document formats are explicitly unsupported in Core v1 and are not sent
to a provider.

`agent.execution.v2.artifacts.get/download/delete` manage Cloud Worker and
local sandbox artifacts in one Agent-owned local repository. Their closed
requests contain `record_kind=cloud_worker|local_sandbox` and one artifact
UUID; download also carries a bounded offset below the output ceiling and a
bounded chunk limit, while delete requires an idempotency key. Each call
revalidates owner/account generation, the selected namespace, and the stored
identity. Download revalidates size and SHA-256 before returning bytes. Delete
uses a durable receipt so an exact retry completes partial removal or returns
the original success. It removes only that artifact's metadata and bytes; it
does not delete an execution, task, run, sandbox, or Worker. These operations
do not contact AWS, create a download lease, or expose a remote filesystem
path.

## Capability and readiness semantics

Registration is not publication. `AgentService.GetCapabilities` and the
neutral Capability registry expose a descriptor only when its production graph
and required readiness proof are complete; configuration-disabled or partial
domains stay absent and fail closed when selected.

- `workload.core_runner` requires its nonce-backed full local isolation proof.
- `agent.execution.v2` publishes only the nine plan/run/artifact
  operations listed above. Readiness is evaluated from its
  PostgreSQL task/confirmation stores, local artifact repository, SSH manager,
  and the sole current STS-verified AWS credential. It does not depend on a
  deploy-time account, Region, AMI, network, Route53 zone, private listener, or
  artifact service. See [execution-v2.md](execution-v2.md).

The remote runner persists task state and logs by task ID. Agent uses separate,
short SSH commands to start work, query status and server load, read logs from
an offset, and list or download artifacts. SSH disconnect does not erase the
remote task or require a long-lived callback connection. Job and service
workloads share this protocol; service lifetime is independent of the
conversation turn until the owner stops it or destroys its Worker.

Flutter discovers and calls Agent-owned capabilities through the scoped HTTP
catalog. The one fixed Message Server Streamable HTTP MCP source exposes
ProductCore contacts, rooms, messages, and channels to authenticated Native
conversations with the deployment-owned `agent_token`; it is not a second
Agent catalog or execution ledger. Product Capability callbacks retain their
separate asynchronous mTLS direction, and the two services keep separate
databases, credentials, and execution histories.

## Contract changes

### GitHub configuration

`agent.github.v1` owns an optional GitHub PAT for one authenticated owner and
account generation. `get_config` uses `agent:mcp:read`; `update_config` and
`test` use `agent:mcp:write`. Reads expose only `enabled`,
`github_token_configured`, a non-secret `github_token_hint`, revision and
timestamps. Updates are idempotent and compare `expected_revision`; the PAT is
write-only and may only be removed through `github_token_clear`. The service
encrypts the PAT with AAD bound to owner, generation, credential version and
config revision, and tests it against GitHub's authenticated identity endpoint.

When an enabled configuration has a PAT, Core automatically resolves the
official hosted GitHub MCP at
`https://api.githubcopilot.com/mcp/x/all` using that PAT as a Bearer credential.
Core does not send restrictive `X-MCP-Toolsets` or `X-MCP-Readonly` headers and
discovers the complete catalog advertised by that exact trusted endpoint.
Core admits every tool the official server explicitly advertises as read-only,
plus the Dirextalk mutation allowlist `issue_write`, `add_issue_comment`, and
`merge_pull_request`, whose names match the official server documentation.
File/content/ref/branch writes,
workflow triggers, pull-request creation or code changes, and every other
unsafe mutation are excluded from the model catalog. Repository clone/edit/
test/commit/push and code pull-request workflows route to the confirmation-
gated Cloud Worker. Malformed, duplicate, or empty accepted catalogs fail
closed. Generic MCP effect classification remains strict. At this exact trusted
GitHub boundary, `readOnlyHint=true` is retained when no supplied
`destructiveHint=true` or `idempotentHint=false` contradicts it; missing
optional annotations are allowed. Every admitted mutation remains unsafe and
is never retried after an ambiguous dispatch.
The synthetic MCP snapshot uses Core's dispatch-recorded inline path and does
not claim the installed-extension confirmation lane. Disabled or tokenless
configuration exposes no GitHub MCP tools. Existing enabled/configured rows
without a historical `tested_at` timestamp remain available during upgrade;
every new PAT installed while enabled and every disabled-to-enabled transition
is identity-tested atomically by `update_config`. Credential resolution
rechecks the authenticated owner, account generation and immutable config/
credential revision immediately before each MCP request. A failed atomic
enable test commits no config, credential, revision, or idempotency result. On
every Turn continuation or recovery, the accepted GitHub MCP snapshot is rehydrated from
that authenticated context instead of being routed through durable installed-
extension storage; its exact immutable snapshot and accepted tool-schema
digests must still match. The MCP path keeps the PAT server-side and write-only
and never copies it into model context, logs, or a process environment. A
separately confirmed bound Worker receives it only through the task-scoped
secret-dispatch path described above.

The shared Streamable HTTP MCP adapter projects ordered `text` content and
embedded textual `resource.text` content into the model-visible tool result.
An embedded resource requires a bounded absolute URI and valid optional MIME
type; the URI is presentation metadata only and is never dereferenced. Binary
`resource.blob` and other non-text content stay outside the conversation
boundary. The combined result passes through the existing credential
redaction and one shared 32 KiB model-visible limit, with an explicit
truncation notice so the model can request a narrower read instead of assuming
that a partial file is complete.

Core is a fresh-state service with no legacy public-API or database
compatibility path, except the explicit internal Cloud Worker v1.0.184/v1.0.185
unbound-plan encoding support above. Any Protobuf or schema change updates this
contract and focused boundary tests in the same change.
