# Dirextalk Agent Goal And Delivery Tracker

## Goal

Deliver an independent, reusable, single-tenant `dirextalk-agent` service that owns Eino reasoning, durable task decomposition, typed AWS planning and control, exclusive Cloud Workers, recipes, monitoring, recovery, managed assets, and verified destruction. Message Server remains a compatible product façade; Flutter remains connected to Message Server.

This is the only implementation tracker for this goal. Work from the highest-priority incomplete stage, update it only at a coherent stage boundary, and never mark a capability complete merely because an internal package compiles.

## Fixed Decisions

- One Agent instance serves one project and one Agent-owned PostgreSQL database/role; no central multi-tenant SaaS in this delivery. Dirextalk reuses the Message Server PostgreSQL 18 server/container but creates a separate database and role—never a second default PostgreSQL container and never shared schemas, credentials, or migrations.
- The Agent public API is versioned Protobuf/gRPC only. Other projects may deploy the same container and consume the same API.
- Caller services authenticate with pairwise scoped Service Keys. A Service Key cannot approve spending, network exposure, secret delivery, managed acceptance, or destruction.
- High-risk transitions require an Ed25519 device approval over deterministic CBOR, plan hash, revision, quote, connection, owner, complete capability scope, and expiry.
- The control service is one non-root process/container. It uses Go AWS SDK v2 through typed provider methods and never exposes AWS CLI, arbitrary AWS APIs, user shell, or Docker socket to Eino.
- Root automation runs only on one-deployment-one-exclusive-EC2 Workers. Workers have deployment-scoped artifact/log/secret access and no IAM/EC2/EBS control permission.
- PostgreSQL is the local fact source. AWS tags plus a DynamoDB manifest mirror and AWS-side Reaper preserve resource ownership and expiry recovery when Agent/DB is unavailable.
- Uploaded root/admin AK/SK is accepted only through encrypted one-time bootstrap, used to establish a minimal IAM source user and roles, zeroed, and never persisted. The new source key is locally envelope-encrypted and only assumes the fixed Control Role via STS.
- Ephemeral resources default to plan-bound auto-destroy 30 minutes after terminal state. Managed resources are never auto-destroyed and require owner, cost alert, monitoring, maintenance, backup, and destroy entry.
- First release executor kinds are `CONTROL_PLANE` and `CLOUD_WORKER`. Connect, agent-connector, vNext Run, central multi-tenancy, multi-cloud, distributed training, EKS, and SageMaker are out of scope.
- Existing deployer, updater, and release scripts remain untouched. Agent container/CloudFormation assets live only in this repository. No Node/npm implementation is added.
- Real images use immutable prerelease tags and digests; `latest` and `v1.0.3` are forbidden.

## P0 — Repository, Contract, Authentication, And Durable Task Kernel

Observable acceptance: a TLS gRPC caller with a valid scoped Service Key can create, read, list, cancel, and cursor-watch a PostgreSQL-backed Task; invalid/revoked keys, duplicate-conflicting idempotency, and stale revisions fail closed; restart does not lose facts or duplicate events.

- [x] Initialize independent Git repository on `adam/0714` and run `codegraph init .`.
- [x] Add repository ownership/security instructions, Go module, Buf configuration, versioned `dirextalk.agent.v1` source, architecture/API documentation, and this tracker.
- [x] Freeze P0 protobuf messages and generate Go stubs from the repository-owned source.
- [x] Implement TLS gRPC server configuration with fail-closed production defaults and standard health service.
- [x] Implement pairwise `DTX-Service-Key <key_id>.<secret>` parsing, peppered digest verification, scopes, expiration, constant-time comparison, revocation, rotation overlap, and metadata/log redaction.
- [x] Implement PostgreSQL-owned migrations for immutable instance metadata, credentials, Task, Step, dependency, attempt/lease, idempotency, Event, and Outbox facts.
- [x] Implement Task/Step domain validation, UUID idempotency, payload conflict detection, expected-revision fencing, transactionally emitted events, and durable pagination/cursor resume.
- [x] Implement gRPC Task/Admin services and explicit `UNIMPLEMENTED` capability responses for later Runtime/Cloud/Worker surfaces without claiming unavailable execution.
- [x] Add boundary tests for authentication, scope denial, idempotency, stale revision, restart persistence, event cursor resume, and secret-canary logging/storage.
- [x] Pass P0 focused tests, PostgreSQL 18 integration lane, Buf lint, command builds, diff review, test curation, and code-economy closeout.

## P1 — Generic Eino Runtime And Native Cloud Dispatcher

Observable acceptance: a caller can hold a generic conversation that creates a durable planning Task and RecipeDraft without Matrix/ProductCore assumptions; the LLM can draft/research/query status but cannot approve or invoke provider/credential/shell capabilities.

- [x] Migrate the reusable Eino runtime from Message Server while removing Matrix, ProductCore, MXID, Flutter deep links, Dirextalk room/contact assumptions, and local runtime shell execution.
- [x] Define generic runtime configuration: project profile, model/secret reference, context window, system policy, MCP/tool providers, knowledge references, and private recipe catalog.
- [x] Implement RuntimeService Chat/StreamChat, conversation persistence, safe cancellation, context trimming, and model failure recovery.
- [x] Implement the native Go `cloud-dispatcher` Skill for goal analysis, official-source research, de-secreted RecipeDraft, three resource candidates, quote request, plan draft, and status explanation.
- [x] Restrict Skill ports to typed draft/list/get/status operations; exclude credential material, device signing, provider mutation, raw AWS SDK, arbitrary HTTP credentials, and shell.
- [x] Store Recipe source URL, retrieval time, official/repository identity, version/commit, artifact digest, license, hardware/data requirements, steps, adaptive limits, timeout/checkpoint, root/network/secret/volume declarations, probes, pairing, operations, backup/restore, rollback, and destroy contract.
- [x] Keep OpenClaw, knowledge nodes, websites, databases, models, and training as natural-language recipes/acceptance scenarios rather than built-in product templates.
- [x] Pass P1 runtime/Skill boundary tests, secret canary, focused build, accumulated review, and documentation closeout.

P1 closeout evidence (2026-07-16): full Go tests/vet/command builds and Buf generation/lint passed; affected packages and the real PostgreSQL 18 E2E passed under the race detector; official-source receipts, stateless completion, context-window enforcement, named model-profile credential audiences, restart replay, and structured Task references were exercised. The integration lane reused the existing PostgreSQL 18 service, then independently read back zero temporary Agent databases, roles, or schemas.

## P2 — AWS Foundation, Direct STS Provider, Worker, And Reaper

Observable acceptance: after encrypted credential bootstrap and device-approved quote, Agent creates one tagged EC2 Worker, resumes through disconnect/restart, records external evidence, and either transfers it to Managed or verifies every ephemeral dependency destroyed; Agent loss still permits AWS-side expiry recovery.

### Connection And Foundation

- [x] Implement Agent-side X25519 one-time bootstrap sessions with 10-minute expiry, single upload/consume, request binding, and memory zeroing.
- [x] Complete opaque Message Server forwarding through the P3 ciphertext tunnel; Message Server never decrypts or persists plaintext, and post-upload retries cannot reissue the one-time upload capability.
- [x] Accept AWS root/admin credentials only for bootstrap; call STS identity read-back and show account/Region before foundation confirmation.
- [x] Create deterministic minimal IAM source user, fixed Control Role, Worker Role/Profile, Foundation service role, and locally envelope-encrypted source key; daily operations use short STS sessions.
- [x] Migrate valid Go/CloudFormation/root-bootstrap contracts from the old Connection Stack into `awsfoundation`; remove Broker Lambda/API Gateway command indirection and do not migrate historical JS/npm code.
- [ ] Provision scoped S3 artifacts/logs, KMS, Secrets Manager layout, DynamoDB resource-manifest mirror, CloudWatch, EventBridge, and Go Reaper Lambda.
- [ ] Require a fresh admin bootstrap for foundation upgrade/full teardown; incomplete IAM/stack removal remains `destroy_blocked`.

### Quote And Approval

- [x] Implement typed Price List, EC2 Offerings, quotas, On-Demand/EBS/IPv4/log/snapshot/entry/traffic estimates and three candidate profiles.
- [x] Store `quoted_at`, 15-minute `valid_until`, currency, hourly/monthly estimate, maximum launch amount, assumptions, and excluded costs.
- [x] Install an owner's first approval device only through the local mounted-public-key bootstrap; exact replay is idempotent and a second device is atomically rejected.
- [ ] Define device-signed approval-device rotation/revocation. Reserved remote Admin RPCs and generic SecretBootstrap completion remain fail closed until their complete signature bindings are frozen.
- [x] Implement deterministic CBOR Go/Dart golden vectors and device signatures binding plan, revision, quote, connection, Recipe, resources, network, secrets, integration, retention, and expiry.
- [x] Requote when price expires or any approved Region/spec/image/network/secret/cost scope changes.

### Provisioning And Worker

- [x] For the current EC2/EBS/ENI/SG scope, persist mutation intent before every AWS-created dependency; use deterministic names, ClientToken, mandatory ownership/retention/deadline tags, response reconciliation, and read-back. The implicit RunInstances root EBS volume has a separate deterministic ledger fact, provider read-back, manifest entry, and Reaper path.
- [ ] Build and publish digest-pinned non-root Agent and exclusive-VM Worker images/archives without AWS CLI or Docker socket. All official `linux/amd64` base images are pinned to reviewed child-manifest digests, and the closed Go ECR/release/AMI tools, recoverable build intents, independent AMI/root-snapshot attestation, durable active-release catalog, and quote binding are implemented. No real ECR push or Worker AMI build/verify/destroy has been executed yet; this item and P2 remain incomplete.
- [x] Implement Worker enrollment, outbound TLS gRPC, deployment-bound credential, lease epoch, exact-Step task claim, heartbeat, checkpoint, result/evidence, cancellation, late-result rejection, and process restart resume.
- [ ] Deliver Worker artifacts/logs/checkpoints through scoped S3/CloudWatch paths and deliver only deployment-declared service secrets.
- [ ] Implement external health/readiness/semantic probes; mark Worker-local root logs as untrusted claims.

### Resource Lifecycle

- [ ] Implement EC2/EBS/ENI/EIP/SG/endpoint/snapshot resource ledger and dependency-order destruction with independent read-back.
- [ ] Mirror resource graph and expiry policy to DynamoDB before exposing active state; wire the tracked PostgreSQL generation/replay adapter into production composition.
- [x] For the current EC2/EBS/ENI/SG scope, make Reaper delete only approved expired ephemeral manifests, require exact per-resource owner/task/deployment/plan/approval/resource-ID tags, independently read back each resource, and never delete Managed assets.
- [x] For the current EC2/EBS/ENI/SG scope, implement public device-approved manual Deployment destruction with an exact signed resource graph, durable operation recovery, revision fencing, dependency-order provider calls, blocked retry, and verified-absent read-back. Managed and unknown resource types fail closed.
- [ ] Implement retry/backoff, orphan detection by tags, `destroy_blocked`, stale-controller alerts, and re-import after Agent/DB loss.
- [ ] Require Managed acceptance to bind owner, cost alert, monitor, maintenance, restart, backup/restore, upgrade/rollback, and destroy contracts.
- [ ] Implement pairing as resumable `waiting_user` with sensitive payload available only through on-demand encrypted retrieval.
- [x] Pass P2 fake-provider, AWS SDK contract, PostgreSQL recovery, Worker fault, Reaper, idempotency, lifecycle, and security tests for the implemented first-validation scope.

P2 first-validation evidence (through 2026-07-16): encrypted bootstrap, typed quote/approval, deterministic Foundation construction, direct STS adapters, EC2/EBS/ENI/SG provider operations, independently tracked root EBS, response-loss reconciliation, startup Foundation-operation recovery, STS/IMDS Worker identity, exact-Step Task/Worker synchronization, process-level checkpoint resume, scoped S3 artifact binding, deployment-monotonic DynamoDB manifests, strict Reaper authorization, automatic ephemeral scheduling, and a hardened locally buildable Worker rootfs exist behind a default-off `AGENT_ENABLE_AWS_CONTROL` gate. The repository also contains fixed immutable ECR preparation, digest-first image publication, deterministic rootfs export, recoverable Worker AMI build/attestation/verify/destroy, and an active release catalog that binds quotes by Agent instance/account/Region/architecture. The completed checks prove local/fake-provider and operator-tool contract behavior, not an executed or safe real-AWS release.

P2 remaining work, in priority order:

1. Use the closed operator tools in an authorized disposable account to publish the digest-pinned Agent/Worker/Reaper artifacts, create and verify the fixed Worker AMI, import its publication into the active catalog, and destroy the test AMI/snapshot with read-back. The three ECR repositories remain explicitly owned Managed release infrastructure rather than per-test cleanup targets.
2. Add startup replay for pending/failed PostgreSQL-to-DynamoDB manifest generations; retain orphan re-import and stale-controller handling as explicit recovery work.
3. Add an independent device-approved Foundation onboarding transition, then implement approved Foundation upgrade/full teardown and complete blocked-remediation workflows; operator release credentials are not a substitute for product approval.
4. Keep the privileged installer socket disabled while adding per-deployment trust material, Worker request construction, and separately approved typed install/mount/execute actions beyond `installer.verify` and `worker.noop`; then add persistent encrypted EBS data delivery, deployment-scoped service secrets, and external liveness/readiness/semantic probes.
5. Add Managed acceptance, service operation, pairing, backup/restore, and the remaining destroy-blocked remediation workflows. Public device-approved manual destruction is complete for the current EC2/EBS/ENI/SG scope.
6. Complete EIP/endpoint/snapshot lifecycle support, orphan re-import, stale-controller alerts, retry policy, Foundation upgrade, and full teardown.
7. Replace the direct CloudWatch Worker-log policy: `${aws:userid}` contains `:` for assumed EC2 roles, while CloudWatch log stream names cannot use `:`. Direct Worker CloudWatch logging must not be claimed until this is redesigned.
8. Complete the remaining P3 Cloud façade, event projection, cutover preflight, and client workload views before any conversation-driven or OpenClaw/knowledge-node acceptance claim.

Deferred from the current release-tooling slice, but required before real acceptance: an independent Foundation-onboarding approval and dynamic installer trust provisioning/execution. The current installer only verifies a pre-staged artifact and its socket remains disabled.

## P3 — Message Server Façade And Flutter Workflow

Observable acceptance: existing Dirextalk clients keep their ProductCore/WS contract while Agent/Cloud facts and execution come exclusively from gRPC; AWS CSV never leaves the client unencrypted; task/resource/service state survives WS reconnect and revision gaps.

### Message Server

- [x] Add TLS gRPC Agent client using a mounted pairwise Service Key; never pass it to Matrix, MCP, Eino prompts, or ProductCore payloads.
- [ ] Preserve existing `agent.*` and `cloud.*` public actions/error shapes while mapping Agent runtime/cloud operations to typed RPCs.
- [ ] Keep password, Matrix Agent session/identity/room/status, contacts, rooms, messages, members, channels, ProductCore WS, Matrix projection, and Dirextalk `/mcp` in Message Server.
- [ ] Split `agent.config`: runtime/model/Skill/MCP/knowledge fields in Agent; display/avatar/room policies in Message Server.
- [ ] Convert `agent.runtime.install/run` to quoted/approved Cloud Worker Tasks; never execute them in Message Server or Agent control container.
- [ ] Persist Agent event cursor and project de-secreted summaries into ProductCore events; ignore duplicate/older revisions and refresh only the entity with a detected gap.
- [x] Implement encrypted SecretBootstrap ciphertext tunnel; Message Server never decrypts, logs, stores, or retries plaintext.
- [x] Bind an uploaded AWS bootstrap session to the owner-scoped durable Role Plan, proxy typed STS identity preview over Agent gRPC, and expose only short-lived persisted evidence without creating a Connection or Foundation.
- [ ] Add no-active-resource/data preflight before direct cutover; fail closed rather than dropping live resource facts.

P3 first-validation slice completed on 2026-07-16: Message Server can delegate only ordinary Chat/StreamChat to the independent Agent over TLS 1.3 with a mounted pairwise Service Key and stable protocol-independent owner ID. Flutter now sends a stable conversation UUID, per-request UUID idempotency key, and persisted exact conversation revision; invalid stream terminal sequences fail closed. The default remains the local Runner, and non-Chat runtime actions stay local.

P3 second-validation slice completed on 2026-07-16: `cloud.deployments.list/get` can use the same Agent gRPC connection without granting mutation capability. Agent returns durable Plan/Connection relationships from `cloud_launch_operations`, keeps Worker and Deployment cursor domains separate, and composes a monotonic read-model revision/time from Worker plus retained resource facts. Message Server consumes all pages with bounded/cycle-safe traversal and preserves the existing ProductCore nine-field Deployment and 404 shapes. Unlinked historical Worker rows remain visible only through Worker status and are never fabricated as Deployments.

P3 third-validation slice completed on 2026-07-16: Flutter parses an AWS CSV including an optional Session Token, creates the Agent-compatible X25519/HKDF-SHA256/AES-256-GCM envelope from server-authoritative AAD fields, and sends only ciphertext through the fixed same-origin owner-only HTTP tunnel. Message Server never routes the upload through ProductCore, WS, durable operations, or plaintext handling; Agent atomically removes the one-time upload-token replay material after upload. Lost-response Create retries return the same token only while `awaiting_upload`; `uploaded` retries return only a public descriptor and Flutter stops at “waiting for identity verification” without claiming a Connection, Foundation, or billable resource. Go/Dart golden vectors, owner/auth/revision/size checks, race tests, real PostgreSQL token cleanup, and Flutter widget flow passed. Agent also exposes owner-scoped durable Connection get/list with a distinct owner-bound cursor so later Foundation response-loss reconciliation has a factual read path.

P3 fourth-validation slice completed on 2026-07-16: after encrypted upload, Message Server reloads the exact owner-scoped Role Plan, derives Region and connection target server-side, calls Agent `PreviewAwsIdentity`, validates the persisted session/revision/owner/target/Region/time evidence, then re-reads the Role Plan before returning it. Agent performs typed STS `GetCallerIdentity` without consuming the bootstrap secret and read-backs the evidence from PostgreSQL. Flutter strictly parses and displays `identity_verified`, supports same-plan retry, and explicitly states that no Connection, Foundation, EC2, or billable compute resource exists yet. Agent tokens and WS cannot call the action; HTTP responses are `no-store`. Focused PostgreSQL, gRPC/ProductCore race, Go vet/Buf, Flutter model/widget, analyze, and diff checks passed.

P3 fifth-validation slice completed on 2026-07-16: Agent Approval-v1 now binds the mounted Ed25519 device trust root, canonical signer key ID, deterministic CBOR Plan/Approval bytes, quote and full capability scopes, and a canonical Connection UUID with exact Go/Dart golden vectors. Message Server exposes typed prepare/approve/Establish/read-back operations, merges owner-scoped Agent Plan/Connection lists with legacy local facts, and routes canonical entities to Agent without globally replacing legacy workflows. Agent treats a successful Foundation operation as a durable outbox and compensates a missing exact launch intent after restart and during runtime. Flutter requires current identity evidence before signing, accepts only `active` as success, preserves the original idempotency reservation across unknown-result, preview outage, and bootstrap expiry, and replays the accepted approval without persisting its signature. Focused Go/Flutter tests, race, vet/analyze, command builds, real PostgreSQL restart/handoff coverage, cross-language golden comparison, secret-canary scan, and accumulated P0-P2 review passed.

P3 sixth-validation slice completed on 2026-07-16: an owner can prepare and device-sign a canonical manual Deployment-destroy challenge through the existing HTTP-only ProductCore façade. Agent persists the exact EC2/EBS/ENI/SG graph and approval before provider work, recovers approved/destroying/blocked operations after restart, and reports success only after every signed provider identifier is independently absent. Message Server remains a stateless projection and preserves legacy non-UUID destruction; Flutter keeps one signature and idempotency reservation through ambiguous and blocked results, supports partial-resource recovery, and never renders provider identifiers. Go/Message/Dart golden and empty-DAG-root encoding agree; first-concurrent PostgreSQL create/approve replay, migration 12, revision fencing, race/vet/build/analyze, and a focused security/spec review passed.

Deferred before remote Chat or Cloud can be enabled in a release:

1. Publish the new Agent module and replace the temporary sibling `go.mod` replacement with an immutable remote version; a single-repository Message Server container build is not yet reproducible.
2. Migrate model/runtime configuration and encrypted model secrets to Agent so Flutter no longer sends the legacy request-scoped `model_profile`; the current adapter discards that envelope before gRPC only to preserve local-Runner compatibility.
3. Add typed Cloud dialogue, Knowledge/Embedding, and attachment contracts. The remote adapter intentionally rejects those modes instead of silently dropping behavior.
4. Add conversation cursor reconciliation for the crash window after Agent commits a response but before Flutter persists the returned revision; current normal reconnect/session persistence is covered, but that cross-device/reinstall recovery path is not.
5. Complete the remaining Cloud façade (`cloud.bootstrap`, Services, Recipes, Alerts), durable Agent event cursor/projection, and cutover preflight below. Owner-scoped Plan, Connection, and Deployment list/get plus device-approved Establish are complete.
6. Add a full pending-to-active Flutter widget E2E and approved-quote expiry/requote/supersede UX; current model, HTTP, signature, read-back, and unknown-result recovery boundaries are covered.

### Flutter

- [ ] Preserve Message Server-only networking and existing `/agent/workloads`, plan, service, and Agent chat navigation.
- [x] Add local AWS CSV parsing (including optional Session Token), X25519 encryption, best-effort buffer clearing, secure device approval keys, and no plaintext persistence/logging.
- [x] Show strict STS caller-identity evidence after upload while keeping `identity_verified` distinct from an active Connection, Foundation, or billable state.
- [ ] Add an optional pasted AK/SK/Session Token entry without weakening buffer clearing or logging guarantees.
- [ ] Display goal/Task/Step progress, three quotes, Region, estimated cost, exclusions, retention deadline, execution/outcome/resource axes, Managed status, owner, alerts, health, pairing, logs, Recipe, operations, and destroy-blocked evidence.
- [x] Label confirmation as “确认创建并开始计费” and state that estimates are not hard budgets, failure/pairing may still bill, and ingress requires separate approval.
- [ ] Implement revision-aware WS reducer, entity-only gap refresh, Cloud projection rebuild after cursor reset, and disconnect/reconnect tests.

### Cutover And Cleanup

- [ ] After parity and preflight, remove migrated Eino/cloud/orchestrator/worker code and old Agent/Cloud fact tables from Message Server; retain only façade/integration code.
- [ ] Update workspace `PROJECTS.md`, `COMMANDS.md`, ownership/routing docs, and run workspace doctor.
- [ ] Verify obsolete deployer Cloud worktree is clean and patch-equivalent before `git worktree remove`; do not edit active deployer/updater/release scripts.
- [ ] Pass Message Server focused tests/build, Flutter focused reducer/widget tests/analyze/build, secret canary, contract compatibility, and accumulated cross-repository review.

## P4 — Isolated Deployment And Real Acceptance

Observable acceptance: the actual Agent, not an operator issuing AWS commands, completes conversation-driven plan/confirm/deploy/monitor/restart/manage/destroy workflows in an authorized disposable AWS account, followed by independent proof of zero unowned resources.

- [ ] Build and push immutable prerelease Agent/Worker/Reaper artifacts such as `v0.1.0-alpha.20260716.1-<sha>`; record digests and reject empty/`latest`/`v1.0.3` tags.
- [ ] Deploy the Agent control container to isolated a8 staging and create its separate database/role in the existing PostgreSQL 18 service, using only new-repository deployment assets.
- [ ] Mount the authorized DeepSeek token as a secret file, select `deepseekv4-pro`, and prove it never appears in logs/events/state.
- [ ] Through Flutter/Message Server conversation, upload the authorized local AWS credential file, show account/Region/price, and complete real device-signed confirmation.
- [ ] Conversationally deploy official OpenClaw, complete manual pairing, verify health, restart recovery, status/operation plans, Managed acceptance, and approved destruction.
- [ ] Conversationally deploy an official knowledge node on encrypted EBS, ingest sample documents, query them, restart, and prove data persists.
- [ ] Run an ephemeral compile/test Task with a short approved expiry, prove Agent auto-destroy and separately exercise AWS Reaper failover.
- [ ] Independently read back EC2, EBS, ENI, EIP, SG, endpoints, snapshots, Secrets, S3/DynamoDB manifests, IAM/bootstrap artifacts, and tags; destroy test resources and prove no unowned billing resource remains.
- [ ] Perform final code-economy pass, one accumulated standards/spec/security review, required full/release checks, tracker closeout, focused commits in each repository, and push repositories that have configured remotes.

## Post-MVP Priority

- [ ] Add single-node GPU inference and local-model mounts with encrypted S3/EBS transfer and verified model readiness.
- [ ] Add single-node LoRA/batch training with checkpoint/resume and result deduplication.
- [ ] Expose Spot only for Recipes that pass interruption, checkpoint/resume, maximum-retry, and cleanup tests.

## Explicitly Deferred

- Connect/vNext execution and scoped enrollment integration.
- Central/shared multi-tenancy, RLS tenant administration, SaaS billing, and project self-provisioning.
- Multi-cloud, shared Workers, distributed training, EKS, SageMaker, automatic Marketplace subscription/EULA, and arbitrary AWS API access.
