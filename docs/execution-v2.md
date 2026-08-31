# Agent-owned Execution V2

`agent.execution.v2.*` is the public read and management surface for Agent-owned execution. Flutter calls it through the ticket-authenticated same-origin Agent HTTP data plane; Message Server does not keep or proxy Agent plans, runs, confirmations, Worker state, AWS credentials, or artifact bodies.

## Cloud Worker authority

Cloud Worker plans are created only inside an authoritative Native Agent turn by `cloud_worker_propose`. A client cannot create a Worker run directly. The proposal atomically creates the plan, execution, `CLOUD_WORKER` CoreTask, and pending CoreConfirmation.

The intrinsic input has one explicit intent. `execute` enters the normal offer
and retained-Worker path. `proposal_only` commits a non-executing plan summary
before provider pricing or durable offer creation; it creates no plan, Task,
confirmation, execution, or Worker action.

The intrinsic may propose cloud execution for an explicit request or when trusted scheduler evidence proves that a substantial selected task exceeds the local runtime. Model text and a local failure are not authority. A cloud or local-only veto rejects the path.

The intrinsic supplies minimum vCPU, memory, disk, estimated runtime, and an optional provider-neutral accelerator class, never an AWS instance type. The closed accelerator classes are GPU, Neuron, FPGA, media, or any accelerator; omission leaves compute unconstrained. Agent reads current-generation Linux on-demand products, intersects them with actual EC2 offerings and live instance-type accelerator metadata in the deployment host's identity-verified AWS Region, and chooses the cheapest x86_64 shape satisfying the request. The selected concrete accelerator class is persisted with the retained Worker; an accelerator request never reuses a Worker whose accelerator class is absent or incompatible. The uploaded credential's default Region is metadata, not placement authority. The plan and confirmation expose the selected exact shape, accelerator class when present, Region, and hourly compute price. Bounded jobs also expose estimated cost and maximum authorized cost; persistent services omit those two open-ended values.

Creating a Worker requires a fresh AWS Price List quote for EC2 and gp3 storage. The owner confirms that exact quote once before the Agent creates a key pair, security group, or instance. Reusing an idle retained Worker is allowed only when its actual vCPU, memory, and disk meet the new request. It executes directly without another confirmation, including persistent services and hostname publication, while its ongoing hourly cost is still read live and displayed. Destroying a Worker is a separate owner-confirmed action.

Worker destruction is available through the owner-facing management action and
the Core-owned `cloud_worker_destroy` conversation intrinsic. The intrinsic is
published only when the live owner inventory contains a retained Worker,
accepts one enumerated Worker ID, re-resolves its full identity from Agent
storage, and commits a final chat response after the idempotent destroy path
completes. Status or load questions never authorize destruction.

## Persistent SSH Workers

The Agent manages at most four retained Workers for the authenticated owner and account generation. It uses the sole active AWS credential uploaded and STS-verified through the App, discovers the newest Canonical official Ubuntu 24.04 LTS image and the account's default VPC, and selects only a default subnet whose availability zone currently offers the confirmed instance type. It creates an ordinary EC2 instance with an auto-assigned public IPv4. A provider client rejection is a deterministic terminal failure; only an outcome that may have committed a provider mutation remains recoverable as uncertain.

`RunInstances` performs one physical launch attempt. When EC2 rejects that
attempt with `VcpuLimitExceeded`, Agent first proves that the confirmed instance
does not exist, maps its family to the exact regional On-Demand vCPU quota, and
uses the same still-current Worker-creation confirmation to request only the
additional vCPUs required by that instance. An existing pending request at or
above that value is reused instead of duplicated. The Worker execution then
fails terminally with `aws_quota_increase_pending` when the request was accepted,
or `aws_quota_insufficient` with the exact Service Quotas console URL and
required IAM actions when it could not be submitted. The retained intent is
marked failed and destroyable; quota review never keeps a Task or turn in a
provisioning loop. Every Service Quotas read/write and lost-response read-back
revalidates the exact AWS account, Region, credential revision, and confirmation.

The Agent connects by outbound SSH with Agent-owned key material. There is no inbound Agent callback, EIP, custom AMI, S3/KMS artifact path, WorkerControl service, model relay, or deploy-time Worker configuration.

Remote work is durable by task ID. The Agent uses short SSH operations to:

- start a job or service;
- query status and server load;
- read logs from an offset;
- list and download artifacts;
- stop a workload or destroy the Worker.

A dropped SSH connection does not erase remote state or authorize a duplicate start. Jobs terminalize when their remote task finishes. Stopping the owning turn cancels its active execution without destroying the retained Worker. Services may remain active across turns until the owner stops them or destroys the Worker.

A Worker remains busy until service persistence, public-port changes, optional
Route53 publication, and TLS verification finish. Reuse of an existing service
requires the same workload port and health path, and cannot claim a hostname
already bound to another workload on that Worker.

When a service execution includes a user-requested hostname, Agent
keeps the application on an unused localhost port and manages an Ubuntu Caddy
reverse proxy with exact-host on-demand TLS that persists after the model run.
Certificate issuance starts only when the host probes HTTPS after DNS
read-back. Agent opens only ports 80 and 443, then uses the App-uploaded
credential to find the longest matching public
Route53 hosted zone and UPSERT an A record to the Worker's current public IPv4.
For a new Worker, its single creation confirmation also covers the hostname;
reuse publishes the hostname directly without another confirmation. Agent reports
HTTPS ready only after a bounded public health probe succeeds. If no matching
zone is available, the service still succeeds and returns the IPv4 and manual
A-record instructions. Independently of service creation, a Native Agent
conversation may later call `cloud_worker_domain_bind` or
`cloud_worker_domain_unbind` for an exact retained Worker workload. The model
provides only resource arguments; the authoritative Native turn executes the
call directly and creates no second confirmation, Task, action card, or
`waiting_confirmation` state. Bind resolves the matching hosted zone on
the Agent and targets the Worker's authoritatively observed current public
IPv4 only for a longest-suffix matching public Route53 zone owned by the
current verified AWS account. Private, external/manual, and cross-account
zones have no fallback; no match yields an explicit correctable tool error with
no Apply, provider write, binding persistence, or turn-success commit. Manual
DNS instructions remain only an initial service-deployment outcome. Unbind uses the exact persisted record and remains available when the
Worker itself is unavailable. Before mutation and every Route53 call, Agent
revalidates the resolved owner generation, AWS account, current credential
revision, Worker resource identity, workload, zone, and record. Both mutations
verify the owning account and Route53 provider read-back. Bind also reconciles
the exact managed Caddy reverse proxy over the pinned Worker SSH identity,
opens 80 and 443, proves HTTPS directly against that Worker's authoritative
IPv4, and closes the direct workload port before committing success. Proxy,
port, DNS, and HTTPS failures retain the staged identity for an idempotent
retry and never yield a successful domain tool result. Agent retains the
active binding or last exact removed-record receipt so a retry after provider
mutation but before final turn commit idempotently reconciles and reads back the
same record again. Route53 is not required for Worker creation,
reuse, observation, or ordinary jobs.

## Results and artifacts

Terminal output is returned to the original durable turn as the `cloud_worker_propose` tool result. Central resumes that turn and writes the user-facing answer.
The same turn also receives canonical `worker_status` progress for queued,
provisioning, running, and terminal execution transitions. Long remote runs
repeat the durable running phase periodically. Each event contains only the
turn identity/revision/timestamp plus execution ID, status, and optional phase;
it does not duplicate Worker inventory or require client polling.

Cloud Worker and local sandbox result files use the same Agent-owned local artifact repository with separate internal namespaces. Existing Cloud Worker metadata and deterministic artifact IDs remain unchanged. Public artifact metadata contains stable IDs, media type, size, and SHA-256, never a Worker or sandbox filesystem path. The artifact request `record_kind` selects the namespace, and `agent.execution.v2.artifacts.download` revalidates the stored identity before returning bounded chunks. Artifact reads do not contact AWS.
Zero-byte stdout, stderr, and result files are omitted before remote transfer and before local artifact metadata is created.

`agent.execution.v2.artifacts.delete` requires an idempotency key and removes only the selected artifact metadata and bytes. A durable deletion receipt completes partial removal after restart and makes an exact retry return the original successful result. It does not delete or stop the associated execution, task, run, sandbox, or Worker.

## Public operations and recovery

Clients read plans, runs, events, and artifacts through `agent.execution.v2.*`, and authorize spend through `agent.core.confirmations.*`. Public references are links and invalidation metadata, not mutation authority.

Task leases, confirmation state, run events, Worker inventory, remote task state, and local artifact records remain durable. Restart and reconnect observe the original Worker and task. An uncertain external response is resolved by reading the same provider or remote identity; it is never permission to create or start a replacement.

Execution V2 exposes nine operations:
`plans.get/list`, `runs.get/list/cancel/events`, and
`artifacts.get/download/delete`. Plan and run operations accept only
`record_kind=cloud_worker`; artifact operations accept `cloud_worker` or
`local_sandbox`. There is no generic provider, CloudFormation,
SSM/ECS workload, secret, deployment, target, or service-binding route.
Readiness depends on the Cloud Worker stores, local artifact repository, SSH
manager, current App-uploaded AWS credential, and the host-owned deployment
Region. It does not depend on a deploy-time account, image, network, domain, or
private listener.
