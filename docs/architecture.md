# Core v1 architecture

Dirextalk Agent is a private process for one user and one Dirextalk
deployment. It is the Agent-owned runtime outside Message Server. Message
Server is the owner-authenticated proxy for Flutter; Online Agent's Matrix
room is a separate transport from Native Agent Core.

## Runtime topology

```text
Flutter (owner access_token)
      |
      v
Message Server ProductCore + Native Agent stream facade
      |  authenticated Capability boundary
      v
CoreServer (TLS token interceptor, optional health/reflection)
      |
      +-- model profiles / conversations / Tasks / schedules
      +-- confirmations / MCP / Skills / Knowledge / typed AWS
      +-- worker pool and scheduler
      +-- PostgreSQL for durable state, snapshots, leases, events, digests
      +-- pgvector in Agent-owned PostgreSQL through the Knowledge semantic ports
      +-- extension-runner through an authenticated Unix socket
      +-- Core Runner through a separate authenticated Unix socket
      +-- persistent SSH Worker manager / local artifact repository
              |
              +-- outbound SSH to at most five ordinary EC2 Workers
```

`serveCore` composes enabled domains before starting workers. Optional domains
are absent from the public registry until their composition and readiness
checks pass. Background model, extension, Knowledge, and AWS work use the same
durable Task/event path; the Agent never creates a parallel execution history.
Local Agent/MCP/Skill/Knowledge work remains on the existing sandbox and worker
pool. Cloud Worker readiness is derived at request time from the sole active
AWS credential uploaded and verified through the App; deployment configuration
does not bind a Worker account, Region, image, network, domain, or credential.
Before creating a new Worker, the Agent reads the current AWS EC2 and EBS price,
presents the exact quote, and performs no AWS mutation until the owner confirms
it. Reusing an existing idle Worker does not create infrastructure and does not
require another creation quote. A retained Worker is destroyed only by an
explicit owner action.

The Worker manager supports at most five retained Workers for the current
credential. It discovers the newest AWS-owned Amazon Linux 2023 image and the
account's default VPC/subnet at runtime, creates one EC2 instance with an
ordinary auto-assigned public IPv4, and connects from Agent by outbound SSH.
There is no EIP, custom AMI, inbound Worker API, WorkerControl listener, model
relay, S3/KMS artifact path, or deploy-time Worker injection. Jobs and service
workloads persist status and logs on the Worker so a later SSH connection can
resume observation. Result files are copied into the Agent-owned local artifact
repository. Optional Route53 binding is an explicit management action and is
not required to create, reuse, or observe a Worker.

The durable scheduler and Extension Runner share the current fixed capacity of
three process-starting local sandbox Tasks. The immutable Task payload
identifies that lane at creation; Claim does not consult mutable extension
projections. A fourth local execution stays queued, but remote MCP calls,
non-executable static Skill reads, and unrelated Tasks can continue. Lease
expiry and restart use the same persisted lane state, so no in-memory semaphore
is an authority and no local failure automatically authorizes a paid Cloud
Worker.

## Ownership

- Agent owns its PostgreSQL database, files, credentials, model/conversation
  state, Tasks, confirmations, Knowledge, Web Search, AWS, Execution V2, and
  runner processes.
- Message Server owns owner authentication, ProductCore action envelopes,
  Native Agent stream frames, and Product Capability callbacks. It does not
  share the Agent database or execution history.
- Flutter owns the user experience and local projection only. It calls Message
  Server, not the Agent listener. Online Agent history and status remain in the
  real Matrix `agent_room_id` transport.

## Data and security boundaries

PostgreSQL is the schema authority for durable Agent state; configured Agent
roots hold large files and artifacts, with relative paths and digests persisted
in the database. Mutable credentials are Agent-owned, protected at rest, and
write-only from ordinary reads. Detailed profile, Knowledge, Web Search, and
Execution V2 invariants are defined in the [API contract](api-contract.md),
[Core v1 specification](core-v1-development-spec.md), and
[Execution V2 contract](execution-v2.md).

The gRPC listener uses TLS 1.3 and one protected deployment token. The token is
compared in constant time, never persisted, and rotated by atomic file
replacement followed by restart. There is no remote token-management API,
multi-tenant authorization, or caller-scope model.

MCP and Skill execution uses a separate isolated extension runner. Core Runner
work uses a separate descriptor-only boundary. Neither runner receives the
Agent database connection or raw Agent credentials, and unavailable isolation
fails closed rather than falling back in-process. A Cloud Worker receives no
Agent database, AWS secret, local MCP registry, Skills registry, or Extension
Runner. The task's selected model credential is supplied only to the remote Pi
process and is not written to the Worker script, logs, status, or artifacts.
Natural-language objectives are passed to Pi as input data and are never
executed as shell source. The Agent authenticates each outbound SSH connection
with Agent-owned SSH key material and copies bounded results back to its own
data root.

## Non-goals

Core v1 does not add REST, an admin UI, multi-user RBAC, Agent clusters/pools,
task priority, graph authoring, or deployment automation.
