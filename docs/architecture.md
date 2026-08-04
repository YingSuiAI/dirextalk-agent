# Core v1 architecture

Dirextalk Agent is a private process for one user and one Dirextalk deployment.
The composition root is `cmd/dirextalk-agent`; the extension runner is a
separate command and process boundary. The service owns Agent data and does
not share a business-server database or execution history.

## Runtime shape

```text
TLS gRPC client
      |
      v
CoreServer (token interceptor, optional health/reflection)
      |
      +-- Model profiles / conversations
      +-- Tasks / schedules / confirmations
      +-- MCP / Skills lifecycle and execution
      +-- Knowledge sources and indexing
      +-- Typed AWS control
      |
      v
PostgreSQL  <---- durable state, snapshots, leases, events, digests
      |
      +-- Core worker pool and scheduler
      +-- Qdrant through the Knowledge semantic ports
      +-- extension-runner through an authenticated Unix socket
```

`serveCore` constructs the graph before starting workers. Disabled optional
domains are absent from the gRPC server and their Task kinds fail closed when
selected. There is one durable Task/event path for background model,
extension, Knowledge, and AWS work.

## Boundaries

### Authentication

TLS 1.3 protects the gRPC listener. `service_token_file` is the only caller
credential. The token is loaded from a protected file, compared in constant
time, and never persisted in PostgreSQL. Rotation is file replacement plus
restart; there is no remote credential manager.

### Persistence

`migrations` is the schema authority. PostgreSQL stores durable domain facts,
immutable execution snapshots, revisions, leases, confirmation bindings,
artifact/content digests, and relative managed-file paths. Secret values are
not returned by ordinary reads. Large files and installed artifacts remain in
configured Agent-owned roots.

### Task execution

The worker claims a Task with `(task_id, attempt, lease_epoch, revision)` and
commits progress/results through fenced transitions. Recovery resumes durable
state rather than creating a parallel history. Schedules create independent
Tasks and provide no priority, graph, or pool semantics.

Model execution resolves the exact profile revision and protected secret
revision recorded in the Task snapshot. MCP, Skill, Knowledge, attachment,
and AWS work is dispatched through the same Task boundary.

Conversation and Agent Task model calls use an Eino `ToolCallingChatModel`
adapter for provider-neutral messages, tool schemas, unary calls, and streams.
The durable Task ledger stays outside that adapter and fences every model/tool
round, so Eino does not hide dispatch, replay, cancellation, or uncertain
outcomes inside an in-memory graph.

### MCP and Skills

Installation and lifecycle operations are confirmation-bound to immutable source
pins, version/content/artifact digests, schemas, network grants, and secret
bindings. Local stdio and Skill code run only in the separate
`cmd/dirextalk-extension-runner` process under its deployment-owned UID. The
Agent connects through a credential-checked Unix `SOCK_SEQPACKET` socket and
passes only sealed or root-bound descriptors. Each run creates user, PID, IPC,
network, mount, and filesystem isolation; executes inside a detached tmpfs root
with a read-only install, no-exec task workspace, empty environment, and only
the explicitly granted secret files; then drops capabilities and installs a
seccomp filter before `exec`.

A delegated cgroup-v2 subtree enforces memory, zero swap, process, and CPU
limits for the complete process tree. Cancellation uses `cgroup.kill`, waits
for `populated 0`, and requires successful cgroup removal before reporting
cleanup complete. A pidfd is retained only as a fallback when the group kill
write itself fails. Cleanup uncertainty is a terminal cleanup failure, not a
successful cancellation. If any isolation primitive is unavailable, execution
is unavailable and is never moved into the Agent process. Remote MCP uses only
the exact confirmed HTTPS endpoint and purpose-bound credential binding.

### Knowledge

Knowledge content is behind root-bound content/file ports. PostgreSQL owns
source metadata, upload state, revisions, and index bindings; Qdrant is reached
through the semantic vector port. Task context validates exact source content
and index bindings before search results are added to the model input.

### AWS

Core AWS uses typed SDK clients and PostgreSQL-backed credentials, plans,
quotes, and change coordination. Credential secret fields are AES-256-GCM
sealed before persistence with a mode-0400, raw 32-byte master key from
`core_secret_master_key_file`; key version, nonce, ciphertext, and field-bound AAD
are the only durable secret representation. Operations that can create, update,
expose, spend, or destroy resources require a durable user confirmation before
the provider call. Provider errors and uncertain outcomes remain fenced and
reconcilable. SDK credential material exists only for the request-local call.

## Explicit non-goals

Core v1 does not implement product adapters, REST, an admin UI, multi-user
RBAC, Agent clusters/pools, task priority, graph authoring, or deployment
automation. Those concerns belong outside this service or to a separately
approved contract.
