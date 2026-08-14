# Agent-owned Execution V2

`agent.execution.v2.*` is the public read and management surface for Agent-owned execution. Message Server authenticates the owner and proxies operations; it does not keep Agent plans, runs, confirmations, Worker state, AWS credentials, or artifact bodies.

## Cloud Worker authority

Cloud Worker plans are created only inside an authoritative Native Agent turn by `cloud_worker_propose`. A client cannot create a Worker run directly. The proposal atomically creates the plan, execution, `CLOUD_WORKER` CoreTask, and pending CoreConfirmation.

The intrinsic may propose cloud execution for an explicit request or when trusted scheduler evidence proves that a substantial selected task exceeds the local runtime. Model text and a local failure are not authority. A cloud or local-only veto rejects the path.

The intrinsic supplies minimum vCPU, memory, disk, and estimated runtime, never an AWS instance type. Agent reads current-generation Linux on-demand products, intersects them with actual regional EC2 offerings, and chooses the cheapest x86_64 shape satisfying the request. The plan and confirmation expose the selected exact shape, hourly compute price, estimated cost, and maximum authorized cost.

Creating a Worker requires a fresh AWS Price List quote for EC2 and gp3 storage. The owner confirms that exact quote once before the Agent creates a key pair, security group, or instance. Reusing an idle retained Worker is allowed only when its actual vCPU, memory, and disk meet the new request. It needs no creation confirmation, but its ongoing hourly cost is still read live and displayed. Destroying a Worker is a separate owner-confirmed action.

## Persistent SSH Workers

The Agent manages at most five retained Workers for the authenticated owner and account generation. It uses the sole active AWS credential uploaded and STS-verified through the App, discovers the newest AWS-owned Amazon Linux 2023 image and the account's default VPC/subnet, and creates an ordinary EC2 instance with an auto-assigned public IPv4.

The Agent connects by outbound SSH with Agent-owned key material. There is no inbound Agent callback, EIP, custom AMI, S3/KMS artifact path, WorkerControl service, model relay, or deploy-time Worker configuration.

Remote work is durable by task ID. The Agent uses short SSH operations to:

- start a job or service;
- query status and server load;
- read logs from an offset;
- list and download artifacts;
- stop a workload or destroy the Worker.

A dropped SSH connection does not erase remote state or authorize a duplicate start. Jobs terminalize when their remote task finishes. Services may remain active across turns until the owner stops them or destroys the Worker.

Optional Route53 binding is an explicit management action for a service that needs a domain. It is not required for Worker creation, reuse, observation, or ordinary jobs.

## Results and artifacts

Terminal output is returned to the original durable turn as the `cloud_worker_propose` tool result. Central resumes that turn and writes the user-facing answer.

Result files are copied into the Agent-owned local artifact repository. Public artifact metadata contains stable IDs, media type, size, and SHA-256, never a Worker filesystem path. `agent.execution.v2.artifacts.download` revalidates owner/account generation and the stored relative path, size, and digest before returning bounded chunks. Artifact reads do not contact AWS.

## Public operations and recovery

Clients read plans, runs, events, and artifacts through `agent.execution.v2.*`, and authorize spend through `agent.core.confirmations.*`. Public references are links and invalidation metadata, not mutation authority.

Task leases, confirmation state, run events, Worker inventory, remote task state, and local artifact records remain durable. Restart and reconnect observe the original Worker and task. An uncertain external response is resolved by reading the same provider or remote identity; it is never permission to create or start a replacement.

Execution V2 exposes exactly eight Cloud Worker operations:
`plans.get/list`, `runs.get/list/cancel/events`, and
`artifacts.get/download`. There is no generic provider, CloudFormation,
SSM/ECS workload, secret, deployment, target, or service-binding route.
Readiness depends only on the Cloud Worker stores, local artifact repository,
SSH manager, and current App-uploaded AWS credential. It does not depend on a
deploy-time account, Region, image, network, domain, or private listener.
