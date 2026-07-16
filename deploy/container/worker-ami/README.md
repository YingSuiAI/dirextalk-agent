# Fixed Worker AMI rootfs contract

This directory is the repository-local bootstrap artifact for an exclusive EC2
Worker VM. The immutable Worker OCI image contains the static supervisor and
installer-verifier binaries, their SHA-256 sidecars, the CA bundle, and these OS
definitions. A trusted AMI build exports that root filesystem, installs the
definitions at the paths below, runs `systemd-sysusers` and `systemd-tmpfiles`,
and enables the Worker service before the AMI is created. The installer socket
remains disabled until the trusted per-deployment binding path described below
is implemented:

| Source in OCI rootfs | Fixed AMI destination |
|---|---|
| `/usr/local/bin/dirextalk-cloud-worker` | same path, root-owned mode `0555` |
| `/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256` | same path, root-owned mode `0444` |
| `/usr/local/bin/dirextalk-worker-installer` | same path, root-owned mode `0555` |
| `/usr/local/share/dirextalk-worker/dirextalk-worker-installer.sha256` | same path, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service` | `/etc/systemd/system/dirextalk-cloud-worker.service`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service` | `/etc/systemd/system/dirextalk-worker-installer.service`, root-owned mode `0444` |
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
IMDSv2 by the pre-enabled service.

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
cannot read or replace the root trust files, the daemon binary, or approved
artifact targets. The daemon has no IP network namespace or inherited cloud
environment, retains its systemd hardening, and accepts exactly two actions:
`installer.verify` and `installer.execute`.

Every request carries an Ed25519-signed `InstallerPlanV1`. The plan binds the
Agent instance, deployment, task, approved plan hash, approval, lease epoch,
Recipe digest, allowed artifact digests and root-owned target paths, secret
references, network/port/volume declarations, exact command argv, working
directory, timeout and per-command artifact/volume/secret refs, and expiry. An
execute request supplies only the signed `command_id`; it has no argv,
environment, working-directory, AWS parameter, or shell fragment field. The
daemon invokes argv directly without shell joining, although an explicitly
signed `/bin/sh -ceu ...` argv remains a valid command. Child processes receive
only the fixed safe `PATH`; output and internal errors are discarded. The request binding
and signed binding must exactly equal the root-owned
`/etc/dirextalk-installer/binding.cbor`. The trust key is read from
`/etc/dirextalk-installer/approval-public-key`. Requests are capped at 256 KiB;
unknown actions, non-canonical CBOR, stale signatures, path traversal, symlinks,
non-root-owned or writable path components, size changes, and SHA-256 mismatches
fail closed. Responses never contain target paths, secret references, or
internal errors. Before execution, every referenced artifact is rechecked by
size, root ownership and SHA-256 digest.

Execution is fenced by a root-owned append-only journal at
`/var/lib/dirextalk-installer/execution.journal`. The running record is fsynced
before starting a child and the terminal result is fsynced afterwards. An exact
idempotency-key/request-digest retry returns the recorded de-secreted result; a
different digest conflicts. A running record found after restart is converted
to `interrupted` and is never automatically executed again, so the upper task
must resume from its own checkpoint with a newly approved step/key.

This action does not copy, unpack, mount, expose a port, resolve a secret ref,
or add runtime arguments. The current Worker supervisor does not yet construct
installer requests, and no trusted bootstrap currently writes the
per-deployment binding or approval key; therefore the socket must not be
enabled by a production AMI build until that wiring exists. This repository
does not yet claim an OpenClaw or knowledge-node deployment.

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

The root daemon can now execute an exact signed command, but the Worker does
not yet construct its request and the socket is disabled in the AMI build.
Per-deployment trust provisioning, artifact delivery, secret resolution,
copy/unpack/mount actions, and Worker checkpoint integration remain required.
