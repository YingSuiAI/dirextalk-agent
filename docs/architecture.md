# Core v1 architecture

Dirextalk Agent is a private process for one user and one Dirextalk
deployment. It is the Agent-owned runtime outside Message Server. Message
Server authenticates the owner and issues a short-lived Agent session ticket;
the same-origin edge forwards Native Agent data requests directly to Agent.
Online Agent's Matrix room is a separate transport from Native Agent Core.

## Runtime topology

```text
Flutter -- login/account --> Message Server -- short-lived session ticket
   |
   +-- same-origin /agent/v1/* --> Caddy --> Agent HTTP data plane
                                             |
                                             v
                                      Agent-owned domains
      |
      +-- model profiles / conversations / Tasks / schedules
      +-- confirmations / MCP / Skills / Knowledge / AWS credentials
      +-- worker pool and scheduler
      +-- PostgreSQL for durable state, snapshots, leases, events, digests
      +-- pgvector in Agent-owned PostgreSQL through the Knowledge semantic ports
      +-- extension-runner through an authenticated Unix socket
      +-- Core Runner through a separate authenticated Unix socket
      +-- persistent SSH Worker manager / local artifact repository
              |
              +-- outbound SSH to at most four ordinary EC2 Workers
```

`serveCore` composes enabled domains before starting workers. Optional domains
are absent from the public registry until their composition and readiness
checks pass. Background model, extension, Knowledge, and AWS work use the same
durable Task/event path; the Agent never creates a parallel execution history.
Local Agent/MCP/Skill/Knowledge work remains on the existing sandbox and worker
pool. Cloud Worker readiness requires both the sole active AWS credential
uploaded and verified through the App and the host-owned, identity-verified AWS
Region supplied by deployment. The uploaded credential's default Region remains
credential metadata and cannot redirect Worker resources. Deployment does not
bind a Worker account, image, network, domain, or credential.
Before creating a new Worker, the Agent reads the current AWS EC2 and EBS price,
presents the exact quote, and performs no AWS mutation until the owner confirms
it. Reusing an existing idle Worker does not create infrastructure and does not
require another creation quote. A retained Worker is destroyed only by an
explicit owner action, either through the owner client management operation or
the Native Agent's owner-scoped `cloud_worker_destroy` intrinsic.

The Worker manager supports at most four retained Workers for the current
credential. CPU and GPU Workers use public, versioned Dirextalk Ubuntu 24.04
images published by Dirextalk in the Worker's AWS Region. The CPU recipe starts
from Canonical Ubuntu; the GPU recipe starts from AWS's Ubuntu 24.04 OSS NVIDIA
Driver DLAMI and records the exact base image, root snapshot minimum, and
supported GPU families discovered at release time. Agent resolves only its
embedded `internal/cloudworker/workerimage/public-releases.json` catalog, which
pins qualified Region/flavor AMI IDs, schema, release/Pi versions and GPU families
from publisher account `066107820442`. Discovery requires that exact AMI and
publisher, public visibility, supported architecture and live root mapping.
Customer accounts need neither publisher SSM access nor shared AMI tags; SSM
candidate/current/previous pointers are publisher-only release bookkeeping.
Missing, unverified, or incompatible
images fail before an offer with a maintainer-actionable error; there is no
generic-image fallback. For both flavors, the confirmed storage quantity is the
greater of the model's actual disk requirement and the selected AMI's live root
snapshot minimum. Launch resolves and validates the catalog image again and requires
a fresh quote if its minimum grew; it never silently increases confirmed
storage. The Agent discovers
the account's default VPC/subnet at runtime, creates one EC2 instance with an
ordinary auto-assigned public IPv4, and connects by outbound SSH. There is no
EIP, frontend-selectable AMI, inbound Worker
API, WorkerControl listener, model relay, S3/KMS artifact path, or deploy-time
Worker injection. Jobs and service
workloads persist status and logs under `/var/lib/dirextalk-worker` so reboot or
a later SSH connection can resume observation. The verified image preinstalls
the pinned Pi runtime, uv/uvx, Caddy, Python, Node, Git/GitHub CLI, Go, build
tools, static-web extraction utilities, PDF authoring/inspection tools, and
common shell utilities; every task verifies the immutable image manifest and
commands without installing or downloading the baseline. Result files are
copied into the Agent-owned local artifact repository. Optional Route53 binding
is an explicit management action and is not required to create, reuse, or
observe a Worker.

The durable scheduler and Extension Runner share the current fixed capacity of
three process-starting local sandbox Tasks. The immutable Task payload
identifies that lane at creation; Claim does not consult mutable extension
projections. A fourth local execution stays queued, but remote MCP calls,
non-executable static Skill reads, and unrelated Tasks can continue. Lease
expiry and restart use the same persisted lane state, so no in-memory semaphore
is an authority and no local failure automatically authorizes a paid Cloud
Worker.

Schedules created by a Native turn remain on the same durable conversation
architecture when they become due. The schedule stores no model-profile
binding. Its occurrence transaction resolves and locks the current explicit
default conversation model and pins the exact profile revision, credential
version, request dialect, model kind, configuration, and protected secret
reference into that occurrence Task; replay/reclaim reuses the committed
snapshot while a later occurrence may select a later default. Missing or
invalid defaults fail closed without a fallback or occurrence write. The
occurrence Task also carries redacted
snapshots for installed MCP/Skills and the owner-bound Message MCP and Web
Search catalogs, revalidates them through the live resolver, and starts one
deterministically identified Native Turn. Product Capability and semantic
Knowledge are not inherited because their request-time authority is absent.
Only the persisted owner/account generation enters the background capability
context. Task recovery resumes the same turn, and successful Task presentation
is exactly that turn's committed assistant Markdown rather than a second JSON
response or transcript write.

## Ownership

- Agent owns its PostgreSQL database, files, credentials, model/conversation
  state, Tasks, confirmations, Knowledge, Web Search, AWS credentials, Cloud
  Worker execution views, and
  runner processes.
- Message Server owns owner authentication, account control, short-lived Agent
  session-ticket issuance, and Product Capability callbacks. It does not share
  the Agent database or execution history.
- Flutter owns the user experience and local projection. It uses the node's
  same-origin `/agent/v1/*` route and never receives the internal listener or
  long-lived Agent service token. Online Agent history and status remain in the
  real Matrix `agent_room_id` transport.

## Data and security boundaries

PostgreSQL is the schema authority for durable Agent state; configured Agent
roots hold large files and artifacts, with relative paths and digests persisted
in the database. Mutable credentials are Agent-owned, protected at rest, and
write-only from ordinary reads. Detailed profile, Knowledge, Web Search, and
Execution V2 invariants are defined in the [API contract](api-contract.md),
[Core v1 specification](core-v1-development-spec.md), and
[Execution V2 contract](execution-v2.md).

The private gRPC listener uses TLS 1.3 and one protected deployment token. The token is
compared in constant time, never persisted, and rotated by atomic file
replacement followed by restart. The same-origin HTTP data plane validates
15-minute compact Ed25519 session tickets signed with the existing capability
grant key. Tickets bind owner, account generation, session, audience, scopes,
issue time, and expiry; they are admission credentials, not execution
deadlines. There is no remote token-management API or multi-tenant role model.

MCP and Skill execution uses a separate isolated extension runner. Core Runner
work uses a separate descriptor-only boundary. Neither runner receives the
Agent database connection or raw Agent credentials, and unavailable isolation
fails closed rather than falling back in-process. A Cloud Worker receives no
Agent database, AWS secret, local MCP registry, Skills registry, or Extension
Runner. The task's selected model credential is supplied only to the remote Pi
process and is not written to the Worker script, logs, status, or artifacts.
Only an enabled frontend GitHub configuration with a configured token adds a
private non-secret GitHub binding to a Worker plan (owner/generation,
configuration and credential versions, and digest). An absent, disabled, or
tokenless configuration leaves ordinary Worker plans and starts entirely
GitHub-free; a later configuration change never adds access to an existing
unbound plan.
Immediately before every task start, including retained-Worker reuse, Agent
re-resolves that exact binding and fails closed after rotation, clear, disable,
or deprovision. The PAT crosses SSH stdin once, is task-scoped mode 0600, is
available through a github.com-only Git helper and process-local `gh` wrapper,
and is removed on completion, error, or cancellation. The runner does not
intentionally serialize it into durable plans, task specs, command arguments,
scripts, ordinary logs, or Pi's inherited environment; ordinary runner output
is exact-token redacted. Only when that task-scoped credential file exists, Pi
receives a non-secret capability hint that HTTPS Git and `gh` are authenticated
for private clone, branch/edit/test/commit/push, and pull-request work. The hint
requires credential non-disclosure and repository/remote/branch/commit
revalidation before every push. The Worker is nevertheless a trusted delegate:
Pi runs as the same user and can invoke the Git credential helper, so least-
privilege selected-repository, short-expiry PATs are required. Rotation blocks
future starts but cannot revoke an already-started run or prevent transformed
credential exfiltration.
The remote Pi runtime is Pi `v0.84.4` and may expose only the vendored
server-owned subagent extension derived from Pi `v0.84.1` and compatibility-
checked against `v0.84.4`. It is loaded explicitly while extension
discovery remains disabled, and it discovers only server-owned agent
definitions under the Worker `PI_CODING_AGENT_DIR`. It never reads project
agent definitions or workflow prompts. Parallel delegation is bounded to eight
tasks and four concurrent subprocesses; child work requiring concurrent writes
must use separate worktrees and branches, then revalidate and integrate through
the parent worktree.
Third-party Pi Skill discovery remains disabled because Skills run with full
Worker permissions. Future Skills must be checksum-pinned, source-reviewed and
selected per task before the runtime passes an explicit `--skill` path.
Natural-language objectives are passed to Pi as input data and are never
executed as shell source. The Agent authenticates each outbound SSH connection
with Agent-owned SSH key material and copies bounded results back to its own
data root.

## Non-goals

Core v1 does not add an admin UI, multi-user RBAC, Agent clusters/pools, task
priority, graph authoring, or deployment automation.
