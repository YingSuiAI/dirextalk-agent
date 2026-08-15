# Ephemeral Pi Worker image input

This directory builds the immutable root filesystem and the only reviewed
rootfs-to-AMI installation path for exactly one
`ephemeral-pi-task` / `pi_json_task_v1` Worker. It contains only the Worker
binary, the independent privileged execution Gate, the pinned Pi release, the
single result extension, a deployment-pinned WorkerControl CA, the read-only
qualification command, and hardened systemd units. It intentionally contains no
Agent configuration, local model credential, MCP, Skill, Knowledge,
Extension Runner, installer, SSM agent, maintenance service, or inbound
listener.

The build requires an explicit semantic AMI release digest, a private
WorkerControl trust bundle, and a distinct private controlled-proxy trust
bundle. The proxy CA is never trusted for the inner WorkerControl, model, or
S3 TLS connection. Example rootfs build and deterministic bundle (it creates
no AWS resources):

```text
rootfs_dir=$(mktemp -d)
bundle_dir=$(mktemp -d)
docker buildx build \
  --output "type=local,dest=$rootfs_dir" \
  --build-arg GO_BUILD_BASE=golang:1.26-alpine \
	  --build-arg AMI_DIGEST=<64-lowercase-hex-release-digest> \
	  --secret id=dirextalk_control_plane_ca,src=/absolute/path/worker-control-ca.pem \
	  --secret id=dirextalk_outbound_proxy_ca,src=/absolute/path/outbound-proxy-ca.pem \
	  -f deploy/cloud-worker/worker.Containerfile .
sh deploy/cloud-worker/package-rootfs-bundle.sh \
  --source-root "$rootfs_dir" \
  --output-tar "$bundle_dir/dirextalk-cloud-worker-rootfs.tar" \
  --output-sha256 "$bundle_dir/dirextalk-cloud-worker-rootfs.tar.sha256"
```

`rootfs-files.allowlist` is the complete payload contract. The packager
rejects every undeclared file, symlink, hardlink, or special file and emits a
normalized tar. The allowlist is itself inside the SHA-bound tar. The
installer accepts no default target and revalidates each source leaf and
digest before and after copying it, then verifies the destination owner,
mode, link count, and digest.

## Rootfs to candidate AMI

`worker-ami.pkr.hcl` pins Packer `1.16.0` and the HashiCorp Amazon plugin
`1.8.1`. Exact source AMI ID and owner, Region, VPC, subnet, build Security
Group, KMS key, instance type, root device, source SSH user, semantic AMI
digest, rootfs tar SHA-256, and nftables NEVRA are all required inputs. There
is no `most_recent` discovery. The build instance has no public IP, uses
private-IP SSH through the caller-supplied build Security Group, requires
IMDSv2, and uses an encrypted gp3 root volume under the explicit KMS key. It
does not use SSM. SSH exists only while Packer provisions the source image;
the resulting image masks SSH, SSM, cockpit, HTTP, and nginx units and Packer
removes its authorized key.

The pinned source AMI must already provide `rpm`, `systemd`,
`systemd-analyze`, `systemd-sysusers`, `readelf`, `getcap`, `ss`, and the usual
POSIX utilities and the exact supplied `nftables` NEVRA. The installer only
verifies that immutable source-AMI input with `rpm -q`; it never consults a
mutable package repository. A different nftables build requires a newly
qualified explicit source AMI ID. Missing tools or observations fail closed;
there is no unpinned fallback. The qualified Amazon Linux source also supplies
the root-owned, non-symlink system trust bundle at
`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`; the Worker payload does
not replace the source image's system roots.

The semantic `ami_digest` must equal canonical `installation.json`; it is
tagged on the AMI, build instance, root volume, and snapshot. The distinct
`rootfs_sha256` binds the exact uploaded tar and is tagged on the same AWS
objects. Syntax-only checks perform no AWS call or mutation:

```text
packer init deploy/cloud-worker/worker-ami.pkr.hcl
packer fmt -check deploy/cloud-worker/worker-ami.pkr.hcl
packer validate -syntax-only deploy/cloud-worker/worker-ami.pkr.hcl
```

With all real build variables supplied, also run full plugin-schema validation
as `packer validate -evaluate-datasources=false ...`; datasource evaluation
must remain disabled so validation cannot contact AWS.

`build-worker-ami.sh` is the only AMI publication entry point. Direct
`packer build` is forbidden. The wrapper revalidates STS `target_account_id`
before every AWS read and again immediately before Packer, reads back the
exact source AMI owner/shape, customer KMS key, VPC, private subnet, and build
Security Groups, then re-reads the build SG immediately before mutation. The
build SG must contain exactly one ingress rule: TCP/22 from one explicit
same-account, same-VPC Packer source SG. CIDR, IPv6, prefix-list, non-22, and
additional ingress are rejected. It must have zero egress; the stateful SSH
return path remains available while the build instance cannot initiate
network traffic. `packer build` may run through this wrapper only with the
explicit disposable account and cost authorization required by the execution
contract.
Amazon plugin `1.8.1` has no native target-account allowlist in the
`amazon-ebs` schema, so the wrapper must not be bypassed; one-time credentials
and the external disposable-account Gate remain part of publication
authorization.

When Packer runs on a same-VPC build host, transfer one digest-bound build
context instead of checking this repository out on that host. The context
contains the exact rootfs tar, Packer template, installer, allowlist, and the
only authorized build wrapper while excluding credentials and mutable package
inputs:

```text
sh deploy/cloud-worker/package-ami-build-context.sh \
  --rootfs-tar /absolute/path/dirextalk-cloud-worker-rootfs.tar \
  --rootfs-sha256 <rootfs-tar-sha256> \
  --output-tar /absolute/path/dirextalk-cloud-worker-ami-context.tar \
  --output-sha256 /absolute/path/dirextalk-cloud-worker-ami-context.tar.sha256
```

Verify the outer digest before extraction and the included
`deploy/cloud-worker/context.sha256` immediately afterwards. Run the included
`build-worker-ami.sh` from the extracted context root; it still requires the
exact account, Region, VPC, private subnet, source AMI, KMS key, and two
read-back Security Groups. The build host or transfer channel never supplies
an authorization fallback, and the context is Region-neutral.

The produced `/usr/local/share/dirextalk-cloud-worker/installation.json` is
canonical JSON. At startup the Worker matches its AMI, Worker, aggregate Pi,
Pi executable, result extension, host-network policy, and all three CA digests
against immutable EC2 user data before contacting WorkerControl.

For a `write` task, the Worker takes an in-memory workspace baseline before
starting Pi and emits only the delta afterwards. `workspace.delta.tar.gz` contains
`meta/delta.json` followed by declared entries under
`files/<canonical-workspace-path>`; deletions exist only as typed manifest
records. Unchanged inputs are not copied into the archive. `changes.patch` is
optional and non-authoritative: it may be omitted when it exceeds its bound or
fails the public-text safety check while the authoritative delta remains
valid. Both the encoded archive and its manifest-plus-file expanded content
are bounded, and the Agent repeats the structural validation on the exact S3
version before freezing an artifact. The Worker keeps the baseline root dirfd
open and resolves traversal and reads with Linux `openat2` beneath that fd,
rejecting symlinks, magic links, mount crossings, hardlinks, and root identity
replacement. Delta collection begins only after the execution gate proves the
Worker cgroup contains no Pi or tool descendant.

The execution Gate is a separate root-owned systemd service and is the only
image process with `CAP_SYS_ADMIN` (plus `CAP_KILL` for fenced cleanup and
`CAP_SYS_PTRACE` for reading the exact cross-UID Worker executable through
`/proc/<pid>/exe`). The
long-running Worker retains only `CAP_SETUID`/`CAP_SETGID`, and Pi receives no
capability. The Gate uses `FAN_OPEN_EXEC_PERM` against the executable file
already opened by the kernel, verifies device/inode/SHA-256, proves the first
root Pi, then permits ordinary tools and any number of exact pinned-image Pi
children inside the delegated task cgroup. It binds registration to the Worker UID/PID, boot ID,
process start ticks, exact systemd cgroup, execution/task/attempt, and lease
epoch. A missing Gate, missing `nft`, or failed unit assertion makes the
required service fail; it is never an optional skipped prerequisite.

The pinned Pi ELF is `root:dirextalk-cloud-worker` mode `0551`. The Worker can
read and hash it through its supplementary Worker group, while the Pi UID is
execute-only and is spawned with an empty supplementary-group set. This is a
required part of the pinned-image fence: Linux fanotify does not emit an
executable permission event when a task invokes the ELF `PT_INTERP` directly
and supplies Pi as ordinary input. The execute-only boundary makes that input open fail,
and the offline AMI qualification runs the fixed-SHA Pi 0.83.0 both directly
and through its interpreter, then checks the live Pi groups and descriptors.

Before result parsing or workspace collection, the Worker requires a canonical
terminal proof with at least one authorized pinned Pi exec, only the Worker
remaining in the cgroup, and zero Pi/tool descendants. Pi child Agents have no
artificial count, depth, or lifetime cap. A copied executable, path replacement,
cgroup identity drift, stale lease, daemonized descendant,
cancellation, or Gate failure is fail-closed. The Gate kills fenced cgroup
members other than the Worker during cancellation and never exposes its proof
as public Execution V2 diagnostics.

Current Plans also have no cumulative model-token budget. Pi uses the selected
model profile's context window and per-request output limit. If the provider stops a Pi turn for output
length before the final result is submitted, the result extension asks the
same Pi session to continue; this can repeat until completion, cancellation,
or the execution deadline. A positive cumulative limit is accepted only when
recovering a historical signed Plan that already contained one.

Every x86 release candidate also runs the tagged
`TestRealUnlimitedPinnedPiProcessTreeUnderExecGate` qualification with separate
Gate and Worker executables in a dedicated systemd cgroup. The fixture launches
nested pinned-image processes and ordinary tools, lets the root exit first, and
requires the terminal proof to wait for every child to drain. This keeps the
no-count/no-depth/no-child-lifetime contract covered by the real Linux
`fanotify`, UID transition, cgroup, and process lifecycle rather than only by a
mock.

The final AMI process must:

- inherit the exact prequalified `nftables` NEVRA from the explicit source
  AMI and install only the SHA-bound rootfs as root;
- run `systemd-sysusers`, creating distinct `dirextalk-cloud-worker` and
  `dirextalk-pi` Unix identities;
- enable `dirextalk-cloud-worker-network.service` before
  `dirextalk-cloud-worker.service` and preserve all root-owned modes;
- disable SSM and every inbound service;
- configure the instance Security Group with only the plan-bound DNS resolver
  CIDRs and controlled TLS proxy CIDRs; and
- keep S3 bucket keys disabled for the versioned staging/artifact bucket so
  the exact object ARN KMS encryption-context policy remains effective.

Packer runs the `offline` qualification phase before snapshotting. A fresh
candidate must still use the real immutable Worker JSON as its exact EC2 user
data; user data is not a maintenance script or a second command channel. The
enabled boot graph performs qualification before the Worker without SSH or
SSM: the execution Gate first runs its production fanotify permission probe,
then `dirextalk-cloud-worker-boot-qualification.service` invokes the bound
read-only image/network checks. The Worker unit then runs a pre-start Gate ping
as the real Worker UID with the exact Worker capability set, and finally the
Worker verifies that set again before reading the immutable bootstrap. Preserve
all four PASS records from EC2 console output:

```text
[cloud-worker-exec-gate] fanotify_qualification=pass
cloud-worker candidate boot prequalification: PASS
[cloud-worker] exec_gate_qualification=pass
[cloud-worker] startup_qualification=pass
```

The boot graph requires the network and Gate units active before the
qualification service and the qualification service complete before the
Worker. It verifies exact Gate and Worker process capabilities, the
root/65531 Gate socket boundary, unlimited Worker/Gate process accounting, the
exact default-drop Pi nftables chain, and no non-loopback TCP or UDP listener.
It has no skip path.
The Packer build SG is never reused at runtime.
Independently read back the candidate Worker Security Group and require zero
ingress rules; a host listener check cannot prove AWS policy.

Repository qualification (no AWS mutation) includes:

```text
go test ./internal/cloudworker/execgate -count=1
go test ./internal/cloudworker/runtime ./internal/cloudworker/worker -count=1
go test ./internal/cloudworker/control ./internal/rpcapi -count=1
sh -n deploy/cloud-worker/package-rootfs-bundle.sh
sh -n deploy/cloud-worker/install-rootfs.sh
sh -n deploy/cloud-worker/qualify-image.sh
sh -n deploy/cloud-worker/build-worker-ami.sh
shellcheck deploy/cloud-worker/*.sh
```

`TestFanotifyExecPermissionExternalAMIGate` intentionally skips on an ordinary
host without root plus `CAP_SYS_ADMIN`. That skip is acceptable only for local
repository checks. The candidate Linux AMI/kernel runs the same production
`QualifyFanotifyExecPermission` path from the Gate's mandatory `ExecStartPre`;
its console PASS is the non-skipped external proof. Boot qualification must
then prove the network and Gate units are active before the Worker, the Worker
has no `CAP_SYS_ADMIN`, Pi has no effective/permitted/inheritable capability,
the Gate socket is root-owned and group-accessible only to UID/GID `65531`,
and no SSH/SSM or inbound listener is enabled. A missing PASS or observation
leaves the AMI unqualified.

The AMI build renders a fixed host nftables policy and qualification compares
its digest with the immutable Core AWS release profile. Runtime user data
cannot replace this policy. The Pi UID is fixed at `65532`; its chain is
default-drop, rejects loopback and instance-metadata ranges, and permits only
DNS plus outbound HTTPS. The per-task Security Group limits DNS to the VPC
resolver and permits direct HTTPS model calls. Pi receives the selected model
base URL and user-configured provider key through its private runtime config;
Central does not relay or inspect model requests or responses. WorkerControl
and S3 still use the Worker-owned outbound proxy and private trust bundle.
No private CA is added to system roots or exposed to Pi.
Environment variables are not treated as the IMDS or egress security boundary.

Publishing an AMI or launching EC2 is a separate explicitly authorized
operation. A qualification build, fake provider test, or successful image
assembly does not publish production readiness and performs no AWS mutation.
