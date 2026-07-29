# Architecture

`dirextalk-agent` is a reusable, single-tenant service. Its Agent-owned PostgreSQL database is the durable source of truth. In Dirextalk it reuses the existing PostgreSQL 18 server/container but has a separate database, role, migration ledger, and backup/restore boundary from Message Server. Other projects may point it at their own PostgreSQL 18 service. The public boundary is TLS gRPC; caller services authenticate with pairwise service keys, while high-risk cloud transitions require a separately verified device approval.

The implemented control process contains the Eino runtime, durable Task/Step kernel, planning-only cloud dispatcher, CloudControl façade, typed AWS provider, reconciliation loops, Worker control, and gRPC services. It runs non-root and cannot execute user shell commands. The current exclusive-VM Worker supervisor is also non-root and receives no IAM/EC2/EBS control permission; privileged execution remains a separate, approval-bound root daemon inside that VM.

The first release does not integrate Connect or vNext Run. Matrix, ProductCore, Flutter navigation, and Dirextalk-specific user identity remain integration concerns outside this repository.

The reviewed target for evolving the current exclusive diagnostic Worker into
a bounded multi-runtime Worker team is documented in
[`native-agent-v2-system-plan.md`](native-agent-v2-system-plan.md). That
document defines the target architecture and acceptance boundaries; this file
and `delivery-tracker.md` continue to describe implemented facts and delivery
state.

## P0 durable boundary

The TLS gRPC interceptor authenticates a pairwise credential and replaces raw authorization metadata with a typed caller principal. Mutation handlers derive their idempotency namespace from that principal; owner IDs remain protocol-neutral project data rather than authentication material. Bootstrap reconciliation is idempotent for the same key/client/digest and may atomically narrow that credential's scopes with a revisioned audit event. It cannot add or replace scopes, reactivate a key, change client identity, or change secret material; privilege expansion requires explicit key rotation.

PostgreSQL owns immutable instance metadata, migration checksums, credentials, tasks, steps, dependencies, attempts, leases, idempotency snapshots, events, and Outbox rows. Entity mutation, response snapshot, event, and Outbox payload commit in one transaction. Events are projections of facts, not an in-memory ordering source. Restart recovery reconstructs services from PostgreSQL and resumes from the caller's durable event cursor without repurchasing or duplicating work.

Task cancellation and failed-step termination fence every nonterminal Step/Attempt before returning. Neither the current Worker supervisor nor a later exclusive-VM privileged executor can therefore extend an old lease or submit a late checkpoint/result after cancellation. Worker RPC uses outbound TLS, deployment credentials, attempt and lease-epoch fencing, and synchronizes claim, heartbeat, checkpoint, evidence, and completion back into the durable Task/Step state machine.

Server shutdown first reports `NOT_SERVING`, waits for active streams within a bounded grace period, then force-stops them when the deadline expires. Database DSNs and private key material enter only through protected mounted files. Generated caller credentials leave only in an X25519 recipient envelope; plaintext credential material is neither logged nor stored.

## P1 runtime and planning boundary

`RuntimeService` persists project/model configuration per protocol-neutral `owner_id`. Public callers select a server-owned `profile_id`; the strict `AGENT_MODEL_PROFILES_FILE` catalog immutably binds provider, model, HTTPS endpoint, mounted credential reference, context window, and output ceiling. Callers may only apply bounded sampling/output overrides. The same binding is checked again when Chat constructs the provider client, before resolving a mounted secret or issuing network traffic. The mounted resolver accepts `mounted:<name>`, confines resolution to `AGENT_MOUNTED_SECRETS_DIR`, and never places resolved bytes in runtime configuration, prompts, events, or PostgreSQL. Optional `AGENT_MCP_SERVERS_FILE` contains only strict, trusted HTTPS Streamable HTTP MCP endpoint metadata and mounted secret references.

The Native Agent v2 Team Plan path remains internal and adds no public RPC. If
both runtime-catalog paths are configured, startup reads protected regular
files, verifies the canonical Ed25519 signature and qualification evidence,
and constructs one immutable trusted compiler. Its public request type omits
runtime releases and catalog revision, so those values cannot come from model,
RPC, or stored request input. A Plan is rejected after the startup catalog
revision changes or when an assignment no longer matches its exact qualified
release. Leaving both paths empty preserves the existing single-Worker
behavior; configuring only one path or an invalid catalog prevents startup.

The Team Plan approval domain is separate from the frozen single-Worker Cloud
Plan v1/v2 vectors. A Team Plan uses an explicit deterministic-CBOR projection
with integral-second durations and a versioned digest domain. Its five-minute
Ed25519 challenge copies the plan/owner/catalog/pricing revisions, quote
window, Worker count and peak concurrency, wall-time range, cost range, and
hard budget. Verification recomputes the complete Plan digest and rejects any
revision, runtime image, model, resource, estimate, dependency, or budget
drift. The challenge is currently a domain contract only: PostgreSQL storage,
device-registry coordination, protobuf, Message Server, and Flutter signing
remain closed until their separate implementation and golden-vector checks.

`Chat` and `StreamChat` run through the same native Eino ReAct engine. Runtime request and tool-call ledgers are caller-scoped and lease-fenced. The coordinator binds the effective memory mode before execution, with disabled persistence remaining sticky after lease recovery; stateless requests never create a conversation row. Every model round is bounded by the catalog profile's context window and preserves the system policy, newest user input, and complete tool-call/result groups. The final conversation update and versioned response snapshot commit atomically, so an exact retry or process restart returns the original response without re-running the model or tools. Structured Task/Plan references survive tool replay and response replay, but streaming exposes them only in the final `Done` after commit. Raw reasoning, tool arguments, and raw tool results are not part of the public stream.

One process-local run budget covers both interactive Eino calls and queued Cloud Goal planning. The 2 vCPU / 2 GiB profile admits two local model-backed runs in total and at most one background run. Completed idempotent response replay bypasses admission because it does not invoke a model. A new interactive request that cannot acquire capacity releases its durable request lease and returns retryable gRPC `RESOURCE_EXHAUSTED`; a background planner that cannot acquire capacity leaves the Step unleased in PostgreSQL for a later poll. The Go heap target and container CPU/memory/PID limits provide a second boundary, but PostgreSQL remains the task truth and no in-memory admission counter is used for recovery or ordering.

The native `cloud-dispatcher` receives trusted owner, conversation, Recipe, connection, and retention bindings from the application context rather than model arguments. The user-facing runtime conversation remains only the Agent memory key; the Skill derives the request-bound `cloud-goal-<uuid>` planning conversation admitted by the durable dispatcher and never persists the chat key as queue identity. Its ports can create/read a research Task, read status/Recipe state, and submit a validated experimental draft. The initial model-visible result explicitly reports that no Worker has started, no Plan is ready, and signed approval remains required. Before submission can advance the fixed `research_official_sources -> draft_recipe -> prepare_resource_candidates` control-plane DAG, every Recipe source URL, retrieval time, and content digest must match a completed `official_source_fetch` receipt in the same authenticated runtime request; PostgreSQL binds that provenance to the concrete research Task and the step records a digest-addressed evidence reference. The content digest identifies fetched documentation and remains distinct from the installable artifact digest and queryless `artifact_url`. Only a server-bound Recipe ID using the reserved retained-Knowledge prefix exposes the five query-distinct URLs for the 2,429-byte immutable release manifest or permits exact matching receipts to select the server-owned Knowledge Recipe. A separate reserved Worker-diagnostic prefix selects a fixed one-step `worker.noop` Recipe and three bounded capacities for low-cost control-plane acceptance; it has no installer, secret, volume, data, listener, ingress, integration, or managed-acceptance capability. For either server-owned profile, trusted code invokes only the fixed research URLs through the same durable receipt-producing tool and persists the canonical sources without asking the model to select or transcribe them. A generic Goal cannot activate either profile through model-selected evidence. Large binary URLs never enter the research tool. Submission then stores a digest-addressed `RecipeDraft` and exactly three provider-neutral candidates. Connection, quote, device approval, and launch are separate trusted CloudControl operations; the Skill still has no credential, approval, provider mutation, arbitrary AWS API, or shell port.

For the Worker control-plane diagnostic only, trusted Runtime code may derive the reserved diagnostic Recipe from the canonical request UUID when an already-bound Cloud Dialogue request's latest user message passes a closed intent matcher. The matcher considers only the current text after the fixed reply wrapper, caps it at 2,048 Unicode code points, requires both Worker identity and diagnostic/acceptance language, and rejects explicit negation/cancellation, named runtimes, databases, knowledge workloads, installation, build, compilation, training, and fine-tuning. Neither the caller nor the model can provide the Connection ID or Recipe ID. A real workload remains on the independent Recipe-resolution path, and even the diagnostic path still requires quote and device approval before AWS mutation.

In Dirextalk, Agent and Message Server share the PostgreSQL 18 server/container to avoid another database process, but use distinct databases, roles, credentials, migrations, and backup/restore ownership. Integration tests exercise the same topology by creating a temporary sibling Agent database and role and proving both are removed. PostgreSQL 16 and a second PostgreSQL container are not part of this architecture.

## P2 first-validation cloud execution

`CloudControlService` now exposes encrypted AWS identity preview, typed quote/plan/device approval, connection establishment, and de-secreted deployment/resource/Worker status. The Agent persists an approved launch before direct STS operations, uses deterministic client tokens and mandatory tags, verifies AWS read-back, binds a Worker to its EC2 STS principal, and writes expiry manifests to DynamoDB. EC2 launch persists both the instance intent and a deterministic root-EBS intent before `RunInstances`; the root volume receives its own ownership tags, provider read-back, resource fact, manifest entry, and Reaper path. The repository-local Worker OCI/rootfs artifact runs the supervisor as fixed UID/GID `65532`, verifies its static binary digest, and provides a pre-baked exclusive-VM AMI boundary. Its control channel is outbound TLS 1.3 `grpcs`; scoped STS/S3 HTTPS and IMDSv2 remain necessary AWS data/identity channels. After device approval, the control plane resolves only an exact official HTTPS source through a DNS-pinned, no-proxy/no-redirect client, verifies size and SHA-256, and publishes a versioned SSE-KMS object. EC2 user-data repeats the deployment key, version, KMS ARN, digest, size, Recipe digest, and root target under a signed artifact manifest. The root bootstrap uses the instance role to stream, independently verify, fsync, and atomically materialize every artifact before it writes trust or enables the socket. The separate root daemon accepts only signed `installer.verify` and `installer.execute` requests; execution selects an exact command ID/argv/cwd/timeout, journals replay/interruption durably, and receives the real VM-root abilities required for package installation, systemd, mounts, and approved HTTPS/DNS egress. Heartbeats atomically replace grants at the exact durable lease expiry, and the runner reads the current grant before every privileged action. A plan, approval, command, artifact, or Recipe change rotates trust; the root journal fences lower epochs and prevents a terminal operation from running again.

Release tooling is a closed operator boundary, not a gRPC, Skill, shell, or arbitrary AWS surface. `dirextalk-ecrctl` prepares the three fixed immutable release ECR repositories and a short-lived private Docker session; its separate Osaka-only build-source prepare/seed/verify surfaces own one retained `dirextalk-build-sources` repository that is excluded from release manifests. Direct release preparation only read-verifies that preseeded catalog, and every build consumes its digest-bound private BuildKit, frontend, Go, and Reaper sources. `dirextalk-releasectl` publishes content by digest before reconciling an immutable prerelease tag and emits the release manifest plus deterministic Worker rootfs outside the repository. The read-only `dirextalk-worker-ami prepare` command confirms STS account/Region, derives the deterministic Foundation stack, reads back its exact release outputs, resolves only the newest unambiguous public Canonical Ubuntu 24.04 LTS amd64 EBS/HVM AMI owned by `099720109477`, and writes a protected build-request v2 bound to those facts and the release/rootfs digests. `build` then persists a build intent, builds and independently attests the AMI/root snapshot, and provides repeatable verify and read-back-confirmed destroy operations. A v2 builder receives no public address or IAM profile. Before launch, the operator creates only a tagged regional S3 Gateway endpoint on the read-back Foundation route table and one tagged TCP/443 egress rule to the exact regional S3 prefix list; it persists endpoint/rule provider IDs before launch. Cleanup terminates the builder first, proves its EBS/ENI absence, revokes the rule, deletes the endpoint, and independently proves the endpoint, rule, and endpoint-created route absent. Access denial, response loss, timeout, ambiguity, malformed IDs, or missing evidence fail closed and leave protected intent/evidence sidecars for recovery. Build-request v1 remains available only through the explicit compatibility flag and cannot be mistaken for the v2 private-reachability contract. All AWS clients use the standard SDK credential chain. The ECR repositories are retained Managed release infrastructure and are not removed by session cleanup, a partial publish, or Worker AMI destruction.

At startup, an optional protected `AGENT_WORKER_AMI_PUBLICATION_FILE` is strictly revalidated and imported into PostgreSQL. Exact re-import is idempotent; a different valid publication supersedes the previous active entry without deleting its audit record. The active release is selected by Agent instance, AWS account, Region, and architecture, and the quote engine replaces caller input with the catalog-owned AMI ID and digest. No matching active release makes the quote unavailable. This startup import configures release selection; it is not proof that a real publication has been executed.

The retained Knowledge runtime is a separate single-host boundary inside the
exclusive Worker. The signed root installer consumes only the canonical
preinstalled artifact root and a `root:root` `0400` Qdrant API-key SecretSlot,
mounts all mutable state under one encryption-required persistent volume, and
runs Qdrant over verified TLS on loopback plus the adapter over an authorized
Unix socket. Its installation acceptance runs a real store/search/persistence
probe before Worker completion. Retained-Recipe Managed acceptance atomically
closes only after its deterministic internal binder creates or reads back the
exact revision-one Knowledge config. Public `knowledge.write` is update-only:
it cannot create revision one or select another owner/binding. Deployment,
Managed service, Recipe digest, and embedding profile are immutable;
revision-fenced owner updates may toggle only `enabled`. Response-loss replay
is idempotent and any binding drift fails closed.

Every fixed local lifecycle command holds one nonblocking lock. Backup captures
only Qdrant and adapter data on the encrypted retained volume and uses a
fsynced rotation journal that preserves the last-known-good snapshot across
each rename boundary. Restore uses a durable swap journal that keeps the
previous live state until restart and semantic verification succeed. Upgrade
repairs the complete immutable v1 binary/model/adapter tree after backup,
rollback restores the durable data backup, and destroy first validates exact
installed unit files plus inactive systemd read-back before removing only fixed
Knowledge-owned roots. The upstream SecretSlot source is preserved. This local
backup complements rather than replaces the independently approved AWS snapshot
boundary.

Migration 41 makes cross-store recovery explicit without making PostgreSQL a
second content store. The live Knowledge binding carries a positive data epoch
and the last verified backend-generation digest. Backup and upgrade freeze a
canonical, normalized snapshot of source, upload, and chunk metadata while the
execution reservation holds; the successful Worker receipt binds that catalog
digest to the backend generation. Restore and rollback select that retained
generation before execution and accept only an exact generation read-back.
Their terminal transaction restores the catalog, advances the epoch, reconciles
receiving uploads, CASes the Knowledge binding and Managed service, and releases
the reservation as one commit. The catalog contains identifiers and bounded
descriptive/digest/revision metadata only. Content, queries, staged bytes,
vectors, API keys, and TLS material stay in the encrypted Knowledge runtime.
New mutations and idempotent mutation replays are both rejected while this
cross-store fence is active.

A generation-changing crash remains recovery-pending behind that same fence
until the root helper signs an independently observed target or pre-swap
generation. The target closes normally. A recovered pre-swap generation closes
restore/rollback as failed with `recovered_original_generation`, leaves the
service active, and atomically records the observed generation before releasing
the reservation. Root-helper journal identity excludes only recovery transport
freshness; after lease rotation it re-observes the terminal generation and
re-signs the receipt for the current lease without rerunning the installer.

Post-Managed Knowledge lifecycle is a separate high-risk control path. Prepare
derives a deterministic scope from the current owner, deployment, Managed
service, Knowledge binding, Recipe, execution bundle, installed manifest, and
revisions; Approve verifies a device signature and atomically rechecks those
facts before scheduling one closed Worker action. The root-helper capability,
journal, Worker result, and receipt repeat that exact action and never carry
caller-selected argv, environment, or paths. Successful operations advance the
Managed revision; successful destroy also disables the exact Knowledge binding.
A failed destroy becomes durable `destroy_blocked` and can resume only from a
fresh approval. A separate 65-minute maintenance lease covers every declared
command without widening the general Worker lease. Before capability issuance,
a durable execution reservation serializes the signed Managed-service and
Knowledge-binding revisions against public updates; terminal completion CASes
both revisions and releases the reservation atomically. Health observations
remain durable while reserved, but cannot change the fenced service revision.

Real-cloud acceptance is still intentionally narrower than a production workload. On 2026-07-29, an authorized disposable Osaka run published immutable Agent/Worker release artifacts, selected and verified Worker AMI `ami-03892c3704d674bc1`, launched one `t3.small` diagnostic Worker, completed one lease-fenced `worker.noop` action, persisted a versioned SSE-KMS result with exact SHA-256 read-back, and then independently proved the EC2 instance, root EBS volume, ENI, security group, and public-address resource absent. The result object remains retained evidence after compute destruction. This proves the fixed diagnostic control loop, not OpenClaw, Hermes, Knowledge, Managed service, or arbitrary workload execution. Production Foundation onboarding still needs an independently device-approved transition, the current bootstrap root credential must be rotated out, and the full App approval/result workflow remains pending. Encrypted approved EBS volumes and deployment-scoped secret materialization are bound through the Worker bootstrap. A separately device-approved ALB/TLS entry route now uses its own private external-readiness monitor and evidence history, while the original service liveness/readiness/semantic monitor remains the sole source of public and Managed health. Direct Worker CloudWatch delivery remains absent: the Worker records its current lease-bound reference and sends only a closed session-authenticated milestone, while Agent revalidates it and derives the exact stream before using the Control Role. Remaining Managed/pairing façades and client cutover still need completion. Until those boundaries are implemented and exercised through the product, the repository does not claim a deployable OpenClaw or knowledge-node workflow.
