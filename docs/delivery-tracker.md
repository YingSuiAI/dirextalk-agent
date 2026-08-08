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
  confirmations, and fenced recovery.
- Provider-backed model catalog and durable Eino conversation/Task execution.
- Native Chat/StreamChat and durable StartTurn now include the current prompt
  in the provider request and perform first-conversation long-term-memory
  recall through a private, snapshot-free semantic read. Recall is bounded,
  memory-only, exact-promoted-revision, user-level untrusted context and is not
  persisted or returned.
- Neutral `agent.chat.v1/stream_chat` now executes through the same durable
  conversation-turn ledger used by list, cancellation, replay, and recovery;
  its Capability operation identity is the public turn identity while the
  client-message request identity remains a separate idempotency fence.
- Agent-owned encrypted Tavily Web Search configuration and guarded dispatch.
- Agent-owned typed text tools with virtual revision-zero built-ins, durable
  full-list configuration/replay, explicit Tool-profile resolution, and
  bounded non-conversational model/search execution through the owner-client
  `agent.text_tools.v1` Capability.
- Owner-client image text extraction and locale translation through
  `agent.image_tools.v1`, with dedicated bounded PostgreSQL uploads, atomic
  consume-and-byte-clear, strict Tool-profile image-modality gates, fixed safe
  prompts, and no conversation/history/Task persistence.
- MCP/Skill lifecycle with isolated extension-runner execution. Official
  Registry remotes are accepted only when the manifest declares exactly one
  header-free `streamable-http` endpoint; other header or transport shapes
  fail closed because the current runtime cannot reproduce them losslessly.
- Knowledge mounts, uploads, memory, indexing, semantic-search composition,
  and the bounded read-only `knowledge_search` Native conversation tool.
  Semantic generations now use pgvector inside Agent PostgreSQL with exact
  binding-filtered cosine search, fixed 64 MiB aggregate/16 MiB source content
  limits, and the closed Knowledge quota status/error contract.
- Typed Core AWS credentials, plans, confirmation-bound CloudControl changes,
  and `WorkloadService` planning/confirmation with a fenced `WORKLOAD` Task.
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
  the Core binary; authenticated instance info and `agent.info.v1` status
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
- Native durable turns expose the Core-owned `agent.schedule.create` intrinsic
  with model input limited to schedule intent/trigger/timeout. Turn authority
  supplies owner generation, conversation, and profile; PostgreSQL commits the
  schedule/replay and terminal transcript/event as one deterministic,
  replay-safe transaction.
- The single Cloud Worker source path uses `ephemeral-pi-task` /
  `pi_json_task_v1`, a real `CLOUD_WORKER` CoreTask and CoreConfirmation,
  atomic conversation offer/outbox persistence, private WorkerControl fencing,
  an exact-version result collector, and a typed eight-resource AWS ledger with
  Reaper cleanup. It does not replace the local sandbox, MCP, Skills,
  Knowledge, Conversation Tools, Extension Runner, or light-task worker pool.
- Generic Execution V2 run creation/retry now uses a real
  `EXECUTION_V2_RUN` CoreTask and CoreConfirmation. The public confirmation
  aliases and public `runs.reconcile` operation are absent; provider recovery is
  controller-owned.

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
- On **2026-07-25**, the explicitly authorized real AWS lane used the typed
  `CoreCloudControlService` in `us-east-1` to create and read back one tagged
  idle SQS queue in one CloudFormation stack, then confirm/delete it. Independent
  deletion verification and a post-run prefix audit found zero active stacks or
  queues. This evidence covers Core CloudControl only. It is not Cloud Worker,
  Worker AMI, one-EC2/one-Worker/one-Pi, artifact collection, or Cloud Worker
  inventory-zero evidence and must not be used as such.
- On **2026-08-07**, `go test ./internal/cloudworker/... -count=1` passed. The
  fake/provider qualification covers deterministic plan/quote binding and hard
  cost ceilings, requote/drift fences, one-dispatch recovery, Worker identity
  and stale-lease rejection, Pi canonical-final/token limits, exact-version S3
  staging/result collection, controlled egress contracts, eight-resource
  cleanup, Reaper fault injection, and bounded public artifact download. The
  download lane verifies complete exact-version content before slicing, strict
  chunk/range/digest output, owner/account-generation isolation, retention and
  Cleaner races, and AWS credential drift before and after the read. These
  tests use fakes or SDK test doubles and perform no AWS mutation.
- On **2026-08-07**, `go test ./internal/store/postgres -run 'CloudWorker' -count=1`
  passed against the local PostgreSQL 18 test service. In particular,
  `TestCloudWorkerFreshStateIntrinsicToVerifiedCompletionWithoutAWSMutation`
  passed the fresh-state path from `cloud_worker.propose` through atomic offer,
  owner confirmation, one fake provider dispatch, real PostgreSQL-backed
  WorkerControl challenge/claim/heartbeat/complete, canonical Pi final parsing,
  exact-version central validation, eight `verified_destroyed` resource
  projections, one conversation result message, and one durable completion
  outbox record. The provider in this test deliberately constructs no AWS SDK
  client, so this is fake/provider qualification rather than live-cloud proof.
- On **2026-08-08**, the complete Agent suite passed with PostgreSQL 18:
  `GOFLAGS=-buildvcs=false go test ./...`, `go vet ./...`,
  `GOFLAGS=-buildvcs=false go build ./cmd/...`, `buf lint`, and
  `git diff --check`. The `GOFLAGS` override disables only Go VCS stamping,
  which otherwise resolves the parent `/home/adam` Git directory instead of
  this linked worktree; it does not change compiled source or test behavior.
  Focused fresh-state tests additionally covered atomic Cloud Worker offer
  creation, exact credential-revision restart recovery, output-version journal
  cleanup, and the final second S3 inventory proof. No real AWS mutation was
  performed.

## Remaining release gates

- Two isolated Compose-project E2E verification is not recorded here.
- Live `workload.aws_ssm` and `workload.aws_ecs` acceptance is not recorded;
  their exact target/readiness probes remain per-operation gates.
- Live `workload.core_runner` workload execution is not recorded.
- Generic non-Cloud-Worker Execution V2 provider mutations still require their
  exact typed route, target proof, and configured CloudFormation service role;
  live generic AWS provision/read-back acceptance is not recorded.
- Production `cloud_worker.propose` accepts an explicit cloud command and one
  structural local-budget case: the frozen turn contains a validated workspace
  archive, while the versioned Native runtime policy has no general workspace
  executor. Its deterministic evidence binds owner/account generation,
  turn/request/conversation/revision, prompt digest, profile snapshot, attachment
  snapshot, and policy revision. All other budget cases remain fail-closed;
  transient concurrency, model arguments, timeouts, and failed local execution
  never become budget evidence.
- No Worker AMI has been built, booted, or qualified from the immutable
  `deploy/cloud-worker` inputs. Repository contract tests and a fake/provider
  pass do not establish an AMI digest as production-ready.
- No real Cloud Worker AWS mutation has been executed. The required authorized
  disposable account, Region, credential revision, Worker AMI, and explicit
  cost ceiling have not been supplied for this lane.
- The fresh-state real-cloud acceptance remains open: App conversation offer,
  user confirmation, exactly one EC2/Worker/Pi, exact artifact collection,
  verified cleanup, unique result delivery, and an independent post-run AWS
  inventory proving zero temporary EC2, EBS, ENI, EIP, security group, IAM
  role/profile, and stack resources. No inventory-zero evidence package exists
  for Cloud Worker yet.

These gates are evidence requirements, not fallback behavior: a missing proof
keeps the corresponding capability unpublished while planning and unrelated
ready capabilities remain available.
