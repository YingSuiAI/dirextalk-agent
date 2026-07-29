# Worker Runtime Qualification

## 1. Purpose

This document defines the production gate for a named Agent runtime installed
inside an exclusive Dirextalk Cloud Worker. A runtime is selectable by Team
Plan only after its exact release has passed every gate below.

The first implemented adapter is `codex_exec_task_v1`. This does not mean a
production Codex image is currently qualified.

## 2. Shared Runtime Contract

Every runtime receives one immutable `worker-runtime-task/v1` containing:

- Task and role identity.
- Qualified runtime release ID, version, image digest, and adapter.
- Context and workspace digests.
- Bounded objective.
- Qualified model profile, provider, model, and interface.
- A logical credential slot, never credential bytes.
- Whether a workspace patch is required.

The contract has no executable, shell, arbitrary argv, environment, endpoint,
filesystem path, AWS operation, or raw secret field.

Every runtime returns:

- Token usage.
- Exactly one bounded `final.json`.
- Up to three additional JSON or UTF-8 text artifacts.
- At most 8 MiB across the complete runtime result.

The Worker runner, not the runtime, chooses S3 references and uploads outputs.
Only SHA-256-bound object claims enter Worker Control RPC.

## 3. Fixed Image Layout

A qualified Codex image uses these fixed paths:

```text
/opt/dirextalk-worker/runtimes/codex/bin/codex
/opt/dirextalk-worker/runtime-contexts/<sha256>.json
/var/lib/dirextalk-worker/workspaces/<sha256>/
/var/lib/dirextalk-worker/runtime-state/
/etc/dirextalk-service-secrets/<slot>
/etc/dirextalk-worker/runtime-installation.json
/etc/dirextalk-worker/runtime.env
```

`runtime.env` may contain only:

```text
DIREXTALK_WORKER_RUNTIME_INSTALLATION_FILE=/etc/dirextalk-worker/runtime-installation.json
```

The installation manifest is root-owned, immutable to the Worker UID, strict
JSON, and secret-free. It binds:

- Exact Codex release and executable digest.
- Exact runtime image digest.
- Exact qualified model profiles and credential slots.
- Fixed context, workspace, state, Git, and search paths.
- `ephemeral-task-token/v1` credential policy.

If the optional environment file is absent, the current diagnostic Worker
behavior remains unchanged and named runtime actions fail as unregistered.
If it is present but invalid, Worker startup fails closed.

## 4. Codex Invocation

The adapter constructs fixed arguments in code:

- Non-interactive `codex exec`.
- JSONL events and a strict final output schema.
- Ephemeral session storage.
- No user config, plugins, apps, MCP configuration, exec-policy rules, web
  search, nested Agent delegation, hooks, goals, or tool suggestions.
- Approval policy `never`.
- `read-only` or `workspace-write` sandbox derived from the approved workspace
  mode. `danger-full-access` is never used.
- Model selected only from the root-owned qualified installation.
- Objective and context through standard input, never argv.
- Closed child-process environment with login-shell loading disabled.

The adapter retains only:

- `thread.started` and one `turn.completed` usage fact.
- Canonical `final.json`.
- A bounded Git patch when the Plan requires repository writes.

Full Codex JSONL, stderr, model reasoning, shell transcripts, and tool output
are not uploaded.

## 5. Credential Gate

The mounted value must be an individual task token, not a reusable provider
account key.

Required controls:

1. Token scope is one Agent instance, deployment, role, model profile, and
   budget.
2. Token expires no later than the approved role maximum duration plus bounded
   startup grace.
3. Token is revoked on completion, cancellation, timeout, or destroy.
4. Tool subprocesses have no general outbound network access.
5. Artifact and log scanning rejects likely credential material.
6. The image qualification test attempts to read process environment,
   `/proc`, Codex state, and mounted secret paths from a model-invoked tool.
7. A failed isolation test disables the release.

The current adapter has a separate secret-environment channel because current
Codex non-interactive authentication consumes a process credential. A release
must not be marked production-qualified until the task-scoped token and
tool-process isolation tests above pass on the actual AMI.

## 6. Result Recovery

The Worker final manifest binds:

- Deployment, Worker, Task, and Step IDs.
- Attempt and lease epoch.
- Recipe and execution-bundle digests.
- Ordered completed actions.
- Runtime adapter, usage, artifact name, media type, size, digest, and S3 ref.

Runtime artifact refs are deterministic from attempt, lease, action, artifact
name, and content digest. Checkpoints retain prior artifact claims, so a later
lease can finish the manifest without losing already-uploaded output.

The Central Agent Result Collector:

1. Requires a succeeded finished deployment.
2. Finds the exact persisted typed result-object evidence.
3. Downloads and verifies result size and SHA-256.
4. Strictly parses the bound manifest.
5. Downloads only each `final.json` for synthesis.
6. Leaves patches and other large artifacts in S3 for explicit later use.

Transport verification does not make Worker output trusted. A separate
Validator must pass before the output can become verified evidence or Canonical
Memory.

## 7. Qualification Matrix

Each runtime release must provide immutable evidence for:

| Gate | Required evidence |
| --- | --- |
| Source | Source URL, commit, version, license decision |
| Build | Reproducible build provenance and executable SHA-256 |
| Supply chain | SBOM and vulnerability scan |
| Adapter | Contract, cancellation, timeout, output, and malformed-stream tests |
| Sandbox | Read/write boundary and no danger bypass |
| Secrets | Task-token scope, expiry, revocation, and tool-process isolation |
| Resources | Peak RSS, CPU, disk, and file-descriptor limits |
| Startup | Runtime ready check, not only process started |
| Recovery | Checkpoint resume and idempotent artifact upload |
| Network | Model endpoint only; no inbound listener or arbitrary egress |
| Cleanup | Process tree stopped, state removed, token revoked, VM destroyed |
| Rollback | Previous qualified image retained and catalog-disable tested |

## 8. Acceptance Targets

Targets remain estimates until measured on the released AMI:

- Worker process ready after EC2 launch: 35-90 seconds expected, 180 seconds
  hard qualification ceiling.
- Runtime installation during launch: zero. Runtime and dependencies are baked
  into the image.
- Cancellation observed by runtime: at most one heartbeat interval.
- Runtime process tree termination after cancellation: at most 5 seconds.
- Central result-manifest availability after Worker completion: at most 15
  seconds.
- Worker peak memory excluding the selected external Agent runtime: under
  256 MiB.

The 2-core, 2-GiB Central Agent does not run Codex, Claude Code, Hermes,
OpenClaw, or OpenCode locally. It stores control facts and fetches bounded final
artifacts; high-memory execution remains on ephemeral Workers.

## 9. Current Status

Implemented locally:

- Shared Task/Result contract and closed adapter registry.
- Fixed Codex invocation adapter and structured output parser.
- Bounded process runner with process-group cancellation.
- Fixed-root context/workspace/credential resolution.
- Git patch collection.
- Runtime Worker action, checkpointed artifact claims, and result manifest.
- Root-owned optional runtime installation loading.
- Central transport-integrity Result Collector.

Not implemented or not accepted:

- Production Codex AMI and signed qualified catalog record.
- Task-scoped model-token issuer and revocation service.
- Team Plan assignment-to-Recipe/context/workspace/secret materializer.
- Multi-Worker DAG dispatcher and Team Plan lifecycle transitions.
- Central Validator and synthesis wiring.
- Central Agent-driven runtime execution and demo2 end-to-end acceptance.

## 10. Development Validation Record

On 2026-07-29 the current branch passed:

- Focused normal and race tests for `workerruntime`, `workerrunner`,
  `workerresult`, and the Cloud Worker command.
- Focused `go vet`.
- Complete Linux/amd64 cross-compilation.
- A local CLI startup probe against Codex CLI 0.144.1 that accepted the exact
  strict configuration and reached API authentication without plugin sync.
- A complete `go test -mod=readonly -p=1 ./...` on a disposable
  Amazon Linux 2023 `m7i.large` instance with Go 1.26.5; the recorded exit
  code was zero.

Native macOS `go test ./...` still stops in the pre-existing
`internal/knowledgeinstaller` package because its secure-path functions exist
only in `secure_paths_linux.go`. The packages changed by this slice pass
normally on macOS, and the complete repository passes compilation and tests on
the target Linux platform.

The disposable validation used task
`236481c5-6a78-4d80-9a72-9cb42a45dee8`. Four short attempts were created:
the first two stopped before testing because of bootstrap-script environment
errors, the third ran to a terminal state but its final exit status was lost
after automatic termination, and the fourth produced the retained zero exit
code.
All four instances are terminated. Independent read-back found zero tagged
EBS volumes, zero attached ENIs, and zero objects under the task's temporary
S3 prefix.

This validates the code on a higher-memory Linux Worker. It does not validate
Central Agent dispatch, a qualified runtime AMI, real Codex model credentials,
multi-Worker orchestration, App approval, or demo2.
