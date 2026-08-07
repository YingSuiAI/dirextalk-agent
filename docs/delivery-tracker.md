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
- Agent-owned encrypted Tavily Web Search configuration and guarded dispatch.
- MCP/Skill lifecycle with isolated extension-runner execution.
- Knowledge mounts, uploads, memory, indexing, and semantic-search composition.
- Typed Core AWS credentials, plans, confirmation-bound CloudControl changes,
  and `WorkloadService` planning/confirmation with a fenced `WORKLOAD` Task.
- Neutral Capability Knowledge mutations now require explicit UUID idempotency
  keys, and AWS credential tests have durable, secret-free replay receipts.
  Provider tests use a persisted claim outside database locks; same-key active
  retries poll through the persisted 30-second lease plus completion grace and
  replay completed or deterministic failed receipts, while crash or completion
  uncertainty fails closed without lease takeover. Different-key completions
  preserve monotonic credential verification timestamps.
- Unified Agent image and split Compose services for Core, extension runner,
  and Core Runner; the latter has nonce/full readiness and descriptor-only
  sealed-result boundaries.
- Agent Task execution no longer terminates at eight model/tool rounds.
  Newly created snapshots pin a versioned five-repeat no-progress watchdog;
  durable model/tool ledgers allow rounds 0-511, with 512 retained only as a
  non-configurable internal safety fuse. Identical tool work and the safety
  fuse have separate stable terminal classifications.
- Unified image builds validate and inject the immutable release version into
  the Core binary; authenticated instance info and `agent.info.v1` status
  report it separately from the `v1` API protocol version.
- Versioned, Buf-lint-clean Protobufs and focused Core contract tests.
- Closed Capability conversation/history DTOs, conversation-bound newest-first
  history cursors, strict UUID mutation keys, typed/redacted domain failures,
  and post-composition durable-turn recovery.

## Verification commands

```text
go test ./...
go vet ./...
go build ./cmd/dirextalk-agent ./cmd/dirextalk-extension-runner ./cmd/dirextalk-core-runner
buf lint
git diff --check
```

Opt-in PostgreSQL integration tests use `AGENT_TEST_POSTGRES_DSN`; Knowledge
integration also accepts `DIREXTALK_TEST_DATABASE_URL`. The opt-in Linux
isolation lane requires a delegated cgroup-v2 subtree and user/mount namespace
support.

## Verified evidence

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
  queues. This evidence covers Core CloudControl only.

## Remaining release gates

- Two isolated Compose-project E2E verification is not recorded here.
- Live `workload.aws_ssm` and `workload.aws_ecs` acceptance is not recorded;
  their exact target/readiness probes remain per-operation gates.
- Live `workload.core_runner` workload execution is not recorded.
- `agent.execution.v2` source composition and focused provider/fence tests are
  present, but publication still requires `core_execution_v2_enabled`, every
  typed route, the exact target proof, and the configured CloudFormation service
  role; live AWS provision/read-back acceptance is not recorded.
- PostgreSQL 18 acceptance of the migration chain through migration 4, snapshot
  policy pinning, and durable round persistence at rounds 8 and 511 passed on
  **2026-08-07**. Focused domain/migration tests, Windows execution of the
  isolated beyond-eight and no-progress bounded-loop cases, and Linux
  cross-builds for `coreruntime` and the PostgreSQL store also passed. Full
  Linux package execution and restart/replay acceptance remain to be recorded.

These gates are evidence requirements, not fallback behavior: a missing proof
keeps the corresponding capability unpublished while planning and unrelated
ready capabilities remain available.
