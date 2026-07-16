# Fixed Worker AMI rootfs contract

This directory is the repository-local bootstrap artifact for an exclusive EC2
Worker VM. The immutable Worker OCI image contains the static binary, its
SHA-256 sidecar, CA bundle, and these three OS definitions. A trusted AMI build
exports that root filesystem, installs the definitions at the paths below, runs
`systemd-sysusers` and `systemd-tmpfiles`, and enables the service before the AMI
is created:

| Source in OCI rootfs | Fixed AMI destination |
|---|---|
| `/usr/local/bin/dirextalk-cloud-worker` | same path, root-owned mode `0555` |
| `/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256` | same path, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service` | `/etc/systemd/system/dirextalk-cloud-worker.service`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers` | `/etc/sysusers.d/dirextalk-worker.conf`, root-owned mode `0444` |
| `/usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles` | `/etc/tmpfiles.d/dirextalk-worker.conf`, root-owned mode `0444` |

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

## Fail-closed release limitation

This rootfs is locally buildable and digest-verifiable, but it is not an AMI
publisher. The current cloud provider accepts an approved AMI ID and an
approval-bound digest without independently proving that the registered AMI
was built from this exact rootfs digest. Until an AMI build attestation is
stored and the provider read-back binds the AMI ID, architecture, root snapshot,
and approved digest, `AGENT_ENABLE_AWS_CONTROL` must remain `false` for real
AWS launches. Do not substitute runtime downloads, mutable S3 keys, `latest`,
`v1.0.3`, or a manually edited AMI.
