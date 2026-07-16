# Fixed Worker AMI rootfs contract

This directory is the repository-local bootstrap artifact for an exclusive EC2
Worker VM. The immutable Worker OCI image contains the static supervisor and
installer-verifier binaries, their SHA-256 sidecars, the CA bundle, and these OS
definitions. A trusted AMI build exports that root filesystem, installs the
definitions at the paths below, runs `systemd-sysusers` and `systemd-tmpfiles`,
and enables the Worker plus its fail-closed trust bootstrap before the AMI is
created. The installer socket itself remains disabled in the AMI and is enabled
only after the first boot atomically materializes valid per-deployment trust:

| Source in OCI rootfs | Fixed AMI destination |
|---|---|
| `/usr/local/bin/dirextalk-cloud-worker` | same path, root-owned mode `0555` |
| `/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256` | same path, root-owned mode `0444` |
| `/usr/local/bin/dirextalk-worker-installer` | same path, root-owned mode `0555` |
| `/usr/local/share/dirextalk-worker/dirextalk-worker-installer.sha256` | same path, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service` | `/etc/systemd/system/dirextalk-cloud-worker.service`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service` | `/etc/systemd/system/dirextalk-worker-installer.service`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer-bootstrap.service` | `/etc/systemd/system/dirextalk-worker-installer-bootstrap.service`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket` | `/etc/systemd/system/dirextalk-worker-installer.socket`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers` | `/etc/sysusers.d/dirextalk-worker.conf`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles` | `/etc/tmpfiles.d/dirextalk-worker.conf`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles` | `/etc/tmpfiles.d/dirextalk-installer.conf`, root-owned mode `0444` |

The resulting AMI must not contain AWS CLI, Node/npm, Docker/containerd, a
Docker socket, a general-purpose Worker wrapper, or deployment secrets. The
service runs the supervisor as fixed UID/GID `65532`, drops all capabilities,
denies socket binding, and verifies the static binary digest before any AWS or
control-plane call. EC2 user-data is not cloud-init shell: the provider supplies
the strict non-secret `dirextalk.agent.worker-bootstrap/v1` JSON consumed from
IMDSv2 by the pre-enabled Worker and root trust bootstrap. The privileged path
does not use AWS CLI or stored credentials: it reads the strict manifest from
IMDSv2, obtains the instance role through IMDSv2, and fetches only the exact
versioned S3 objects declared by that manifest with the embedded Go SDK.

The instance security group has no inbound rule. The control-plane connection
is credential-free outbound `grpcs://` with TLS 1.3. The Worker also requires
link-local IMDSv2 and scoped outbound HTTPS to AWS STS and S3; therefore “only
outbound gRPC” describes the Agent control channel, not all network traffic.
Its instance role must remain limited to identity proof and deployment-scoped
objects.

## Privileged installer boundary

`dirextalk-worker-installer.socket` is the only interface to the root daemon:
`/run/dirextalk-installer/installer.sock`, owned by
`root:dirextalk-worker` with mode `0620`. The Worker supervisor remains UID/GID
`65532`; it can connect and write a length-prefixed canonical-CBOR request but
cannot read or replace the root trust file, the daemon binary, or approved
artifact targets. The daemon accepts exactly two actions, `installer.verify`
and `installer.execute`. It is the explicitly approved root boundary inside an
exclusive VM, so its child can install packages, write systemd/service files,
mount approved volumes, and use the VM network. Hard isolation comes from the
exclusive instance, the signed Recipe/plan/command, the deployment-scoped IAM
role, and SG egress limited to DNS/HTTPS; hostname declarations are audited
scope rather than a security sandbox that root could not bypass.

Every request carries an Ed25519-signed `InstallerPlanV1`. The stable plan binds
the Agent instance, deployment, task, approved plan hash, approval, Recipe
digest, allowed artifact digests and root-owned target paths, secret
references, network/port/volume declarations, exact command argv, working
directory, timeout and per-command artifact/volume/secret refs, and expiry. An
execute request also carries a separately signed, short-lived `LeaseGrantV1`
binding trust, plan digest, stable operation ID, command ID, lease epoch, issue
time, and exact lease expiry. The mutable selector is only `command_id`; the
request has no runtime argv,
environment, working-directory, AWS parameter, or shell fragment field. The
daemon invokes argv directly without shell joining, and `argv[0]` must be a
referenced digest-locked artifact; that artifact may itself be a reviewed
installer script with a fixed shebang. Child processes receive
only the fixed safe `PATH`; output and internal errors are discarded. The request binding
and signed binding must exactly equal the root-owned canonical
`/etc/dirextalk-installer/trust.cbor`. That single root:root `0400` file binds
the trust ID, Ed25519 public key, deployment, plan hash, Recipe digest and daemon
configuration, so key/config rotation is atomic. Requests are capped at 256 KiB;
unknown actions, non-canonical CBOR, stale signatures, path traversal, symlinks,
non-root-owned or writable path components, size changes, and SHA-256 mismatches
fail closed. Responses never contain target paths, secret references, or
internal errors. Before execution, every referenced artifact is rechecked by
size, root ownership and SHA-256 digest.

Execution is fenced by a root-owned append-only journal at
`/var/lib/dirextalk-installer/execution.journal`. The running record is fsynced
before starting a child and the terminal result is fsynced afterwards. An exact
idempotency-key/stable-operation-digest retry returns the recorded de-secreted
result. Lease epochs are fsynced monotonically, so a lower epoch is rejected. A
new lease grant for the same operation can read its terminal result but cannot
run it again. A running record found after restart is converted to `interrupted`
and is likewise never automatically executed again; an intentional retry needs
a newly approved operation capability rather than a new lease alone.

This action does not expose separate arbitrary copy, unpack, mount, port,
secret, or runtime-argument APIs. The signed installer artifact may perform
the exact approved installation inside its exclusive VM. The Worker supervisor validates an immutable
per-deployment capability and exact LeaseGrant against its current assignment
and constructs the deterministic local request using only the selected
`command_id`. Heartbeats rotate the complete grant set to the exact durable
lease expiry, and the runner reads the current grant immediately before every
privileged action. The deadline is the minimum of command timeout, capability
expiry, and grant expiry. A root oneshot disables the socket first, reads the
small optional trust plus versioned artifact sources from strict IMDSv2
user-data, validates their deployment/plan/Recipe manifest, downloads only
the exact SSE-KMS S3 versions through the instance role, and atomically writes
root:root `0500` artifacts followed by `trust.cbor`. Any read, validation,
checksum, fsync, rename, cleanup, or activation failure leaves the socket
disabled. A Recipe without an installer capability omits these fields, starts
the unprivileged Worker, and keeps the socket disabled. This repository still
does not claim an OpenClaw or knowledge-node deployment until immutable images,
persistent volumes, secrets, probes, and product-driven real-AWS acceptance are complete.

## Release, attestation, and recovery boundary

The repository now includes a closed Go publication path. The immutable release
tool emits this deterministic rootfs together with a release manifest, and
`dirextalk-worker-ami build` uploads the exact archive through a versioned,
SSE-KMS object, creates the fixed image in a preflighted private build
environment, and independently binds the AMI ID, architecture, root snapshot,
release-manifest digest, rootfs digest, and Worker binary digest. The build
writes an intent before AWS mutation; an exact rerun resumes or verifies the
same publication. `verify` repeats the AWS read-back and attestation, while
`destroy` requires an explicit account/image-digest confirmation and reports
success only after the AMI and snapshot are absent.

The resulting publication can be mounted as
`AGENT_WORKER_AMI_PUBLICATION_FILE`. Agent startup strictly validates it and
imports it into a durable active-release catalog keyed by Agent instance, AWS
account, Region, and architecture. Quote preparation uses only that catalog and
fails closed when no matching publication exists; a client or Skill cannot
provide its own AMI.

These tools use the standard AWS SDK credential chain and are described in the
[container operator flow](../README.md#immutable-release-operator-flow). They
have not yet been executed against the authorized real ECR/EC2 environment, so
P2 real-cloud acceptance remains incomplete and `AGENT_ENABLE_AWS_CONTROL` must
stay off for production launches. Base container images also still require
digest pinning. Do not substitute runtime downloads, mutable S3 keys, `latest`,
`v1.0.3`, or a manually edited AMI.

The Worker/root bridge executes and checkpoints an exact signed command. The
provider emits the exact trust and artifact-source fields; bootstrap safely
materializes them before socket activation; claim, recovery, and heartbeat
rotate grants without extending the durable lease. Deployment secret
resolution, persistent-volume mounts, durable external-probe results, and
optional separately typed copy/unpack/mount/service helpers remain required.
