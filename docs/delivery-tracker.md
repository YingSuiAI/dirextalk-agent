# Core v1 delivery tracker

This is the single detailed record of Agent implementation status, verification
evidence, and remaining release gates. Contract details live in the
[architecture](architecture.md), [API contract](api-contract.md), [Core v1
specification](core-v1-development-spec.md), [Message Server integration
contract](message-server-integration-development-contract.md), and
[Execution V2 contract](execution-v2.md).

## Implemented at HEAD

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
- Neutral `agent.chat.v1/stream_chat` now executes through the same durable
  conversation-turn ledger used by list, cancellation, replay, and recovery;
  its Capability operation identity is the public turn identity while the
  client-message request identity remains a separate idempotency fence.
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
  reviewed confirmation lifecycle. GitHub and skills.sh remain available as
  separately pinned external sources.
- Two default, network-free, read-only MCP installations expose live server
  time and server load through the same isolated MCP lifecycle and durable
  one-time seed semantics as other installed extensions.
- Knowledge mounts, uploads, indexing, semantic-search composition,
  and the bounded read-only `knowledge_search` Native conversation tool.
  Semantic generations now use pgvector inside Agent PostgreSQL with exact
  binding-filtered cosine search, fixed 64 MiB aggregate/16 MiB source content
  limits, and the closed Knowledge quota status/error contract.
- App-managed AWS credentials with STS identity verification, plus
  `WorkloadService` planning/confirmation with a fenced `WORKLOAD` Task.
- Optional `agent.worker.v1` has closed owner-client list/get/destroy and
  Route53 bind/unbind adapters for the maximum-five persistent SSH Worker
  pool. It reports the current ordinary public IPv4 and optional
  workload/domain state, never EIP. Worker creation, reuse, observation, and
  destroy require the Worker manager and verified-credential ports; optional
  Route53 operations additionally require a usable same-account hosted zone.
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
- Closed Capability conversation/history DTOs, conversation-bound newest-first
  history cursors, strict UUID mutation keys, typed/redacted domain failures,
  and post-composition durable-turn recovery.
- Native durable turns expose the canonical public `turn_id` through
  `list_turns` together with the original start `idempotency_key`, and use the
  turn id as the durable Capability operation identity. Typed `stop_turn`
  performs a revision-fenced conversation cancellation and returns only the
  public turn projection plus its cancellation idempotency key. A release
  preflight compares every Message Server readiness-baseline action, binding,
  and schema pin against the actual Agent descriptor constructors and reports
  all catalog differences in one run.
- Native durable turns expose the Core-owned `agent_schedule_create` intrinsic
  with model input limited to schedule intent/trigger/timeout. Turn authority
  supplies owner generation, conversation, and profile; PostgreSQL commits the
  schedule/replay and terminal transcript/event as one deterministic,
  replay-safe transaction.
- The current Cloud Worker path uses a real `CLOUD_WORKER` CoreTask and
  CoreConfirmation with the sole App-uploaded, STS-verified AWS credential.
  New Worker creation uses a fresh EC2/EBS quote and exact owner confirmation;
  retained idle Workers are reused without another creation. The manager
  supports at most five ordinary-public-IPv4 EC2 Workers, discovers the current
  Canonical official Ubuntu 24.04 LTS image and default network live, and copies
  remote results into Agent-owned local artifact storage. It has no EIP, S3/KMS,
  custom AMI, WorkerControl, model relay, or deployment-time Worker binding.
  Worker/execution records are bound to the authenticated owner/account
  generation; historical provisioning recovery is read-only, partial cleanup
  is retryable, and one unavailable AWS observation no longer hides the rest
  of the retained inventory.
- Confirmation expiry processes each durable candidate in its own transaction.
  A stale binding or CAS conflict remains unchanged and is reported for retry,
  while other expired confirmations in the same sweep still commit; repository
  and infrastructure failures continue to stop the cleaner.

## Verification commands

```text
go test ./...
go vet ./...
DIREXTALK_MESSAGE_SERVER_ROOT=../dirextalk-message-server go test ./internal/agentcapability -run '^TestMessageServerBaselineCatalogPreflight$' -count=1 -v
go build ./cmd/dirextalk-agent ./cmd/dirextalk-extension-runner ./cmd/dirextalk-core-runner
buf lint
git diff --check
```

Opt-in PostgreSQL integration tests use `AGENT_TEST_POSTGRES_DSN`; Knowledge
integration also accepts `DIREXTALK_TEST_DATABASE_URL`. The opt-in Linux
isolation lane requires a delegated cgroup-v2 subtree and user/mount namespace
support.

## Verified evidence

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
- On **2026-08-08**, the release catalog preflight checked all 66 current
  Message Server readiness-baseline actions against 11 actual Agent descriptor
  constructors with no remaining missing binding, operation, or schema digest.
  Focused tests also covered strict typed turn cancellation, revision/key
  forwarding, closed output, unknown fields, and the pinned stop/list schemas.
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
  maximum-five capacity, confirmed creation, retained idle reuse, explicit
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
