# Official Team Pi Worker Release

This directory defines only the official Agent Core v1 Team Pi Worker release
artifact. It contains the `dirextalk-cloud-worker` binary, the qualified Pi
0.83.0 runtime, the accepted `dirextalk_submit_result` extension, and a
hardened systemd service sidecar.

It is not an AWS provisioner, an AMI builder, an installer, a deployer, a
pairing service, a Knowledge Worker, or a maintenance control plane. Task 9
adds the typed AWS lifecycle, Task 10 adds durable Team reconciliation and
result verification, and Task 13 composes and qualifies the production
Agent Core v1 capability.

## Pinned release inputs

| Artifact | SHA-256 |
| --- | --- |
| Debian 12 slim Linux amd64 base manifest | `362e64223cc0da95422b3b13c045186fc0a81250e765d31c025fbddf257f6143` |
| Debian git package | `1:2.39.5-0+deb12u3` |
| Debian CA package | `20230311+deb12u1` |
| Debian libcap tools package | `1:2.66-4+deb12u3+b1` |
| `pi-linux-x64.tar.gz` for Pi 0.83.0 | `b0625eb623197b0afe20c870d21ef2f34481f1504e5777df3f698a66c7636f5f` |
| Pi executable | `c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a` |
| Pi `package.json` | `e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf` |
| Pi `photon_rs_bg.wasm` | `10468181565c56004c867f3a4af96f89a0ef5a63a72f2b5fb12c1f1992a3615c` |
| Pi dark theme | `d3e86b44313cc77abb26b3245857290bdec12a2d1f91ec4b8a30ca1d90aea328` |
| Pi light theme | `97321584a745e75113f08dd1b751bc2a70da28f132b242f1ae5c23816c5e10bc` |
| Pi theme schema | `51839872e9cca2ed8804a040b6222a10d0fd5bf6f241b5a4b2824fbb98f3abd1` |
| `dirextalk-result.ts` | `39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9` |

The Containerfile verifies every listed digest during the build. It builds
only `cmd/dirextalk-cloud-worker` and `cmd/dirextalk-pi-sandbox`; no installer
or AMI tooling is compiled or copied into the image. Each generated binary has
an immutable digest sidecar under `/usr/local/share/dirextalk-worker` for the
release and composition qualification added in Task 13.

The image and systemd sidecar expose the same closed runtime configuration:
`DIREXTALK_PI_EXECUTABLE`, `DIREXTALK_PI_EXECUTABLE_SHA256`,
`DIREXTALK_PI_EXTENSION`, `DIREXTALK_PI_EXTENSION_SHA256`,
`DIREXTALK_PI_SANDBOX`, `DIREXTALK_PI_SANDBOX_SHA256_FILE`,
`DIREXTALK_PI_STATE_ROOT`, and `DIREXTALK_PI_SEARCH_PATH`. SHA-256 values use
the canonical 64-character lowercase hexadecimal form expected by the Worker
runtime; paths are fixed absolute paths and contain no credential material.

The Worker never executes Pi directly. It verifies the dedicated sandbox
launcher against its immutable sidecar and starts that child through the
kernel credential path as Pi UID `65533`, shared GID `65532`, with no
supplementary groups. The launcher rejects any other real, effective, or saved
identity, drops all inherited capabilities, requires Landlock ABI 2, applies a
deny-by-default filesystem policy, closes inherited file descriptors, and
executes only the fixed official Pi path. Only runtime state and the current
workspace are group-accessible, while mTLS, secret, and receipt paths remain
owned by the parent Worker with mode `0700/0600`. On ABI 2 kernels it
also installs a minimal seccomp filter that rejects path-based `truncate(2)`,
covering the one protected-file mutation added to Landlock in ABI 3. Pi and every
bash/git descendant can access the pinned runtime, required system files, and
the current job/workspace only. The mTLS, receipt, one-time secret, and parent
process paths are outside that view; missing Landlock support fails closed.

Task 9 must materialize each task workspace as Worker UID/GID `65532:65532`.
Before launch, the Worker walks that exact workspace without following
symlinks, rejects foreign owners, hard-linked regular files, and special
files, then grants shared group access to directories and regular files while
preserving executable intent. Shell/test/git roles receive one process-local
Git `safe.directory` entry bound to the exact workspace; no global Git config
is modified. The Landlock policy grants workspace writes only when the role's
closed capability list explicitly contains `repository.write`; shell, test,
and Git capabilities alone receive read/execute access. Files created by Pi
inherit shared GID `65532` under umask `007`. Before result collection, the
parent normalizes Worker- and Pi-owned entries to the shared group while
preserving executable intent. Its only effective capabilities are sufficient
to recover and remove Pi-owned private entries; any normalization or task-root
cleanup failure stops completion rather than leaving an untracked workspace.

After extraction, Task 9 computes the canonical materialized-tree digest used
by `DIREXTALK_WORKER_WORKSPACE_SHA256`. This domain-separated digest covers
relative paths, entry kinds, executable intent, safe symlink targets, regular
file sizes, and file bytes under fixed limits. It is distinct from the archive
or object download digest. The Worker recomputes it from the real workspace
before consuming the model credential or launching Pi. TLS, context, manifest,
secret, receipt, runtime-state, and both fixed binary digest sidecars must be
outside `/var/lib/dirextalk-worker/workspaces`; overlapping configuration is
rejected before any credential is opened.

## Runtime boundary

The pinned Debian 12 runtime supplies the glibc loader required by Pi 0.83.0,
plus bash and git for qualified shell/test/git roles. The final image runs as
UID/GID `65532:65532`; package mutation is unavailable to that non-root
identity. A container runtime must grant the parent entrypoint only
`CAP_SETUID`, `CAP_SETGID`, and `CAP_KILL`; the systemd sidecar declares that
exact set. The image pins the same effective file capability on the immutable
Worker binary so a non-root OCI entrypoint can receive only those capabilities
when the runtime bounding set allows them; Pi receives none. The root
filesystem may be mounted read-only when `/var/lib/dirextalk-worker` is a
writable private volume. Runtime state, workspaces, temporary files, and HOME
remain under that directory with shared mode `0770`; control, receipt, and
secret directories remain parent-only. No credential belongs in the image.

The systemd unit binds no socket, requests only `CAP_SETUID`, `CAP_SETGID`, and
`CAP_KILL` for the parent Worker, and permits only Unix, IPv4, and IPv6 address
families required for local process control, DNS, and outbound TLS. It has no
SSH, SSM, inbound listener, installer, or maintenance dependency. Local stdout
and stderr go only to the host journal; Central receives progress and final
results through the closed Worker protocol, never by streaming process logs.
Both the unit and the Worker binary require the numeric Worker identity
`65532:65532`; a name-service remap or any foreign supplementary group fails
closed before configuration or credentials are opened. Task 9 rootfs creation
must install matching `dirextalk-worker` passwd/group records with UID/GID
`65532:65532`; systemd rejects the unit with `217/USER` when those fixed
records are absent.

`/etc/dirextalk-worker/worker.env` is a required host-provided configuration
file. Task 9 provisioning owns its creation and must restrict it to the
following closed field names:

- `DIREXTALK_WORKER_CONTROL_ENDPOINT`
- `DIREXTALK_WORKER_TLS_SERVER_NAME`
- `DIREXTALK_WORKER_TLS_CA_FILE`
- `DIREXTALK_WORKER_TLS_CERT_FILE`
- `DIREXTALK_WORKER_TLS_KEY_FILE`
- `DIREXTALK_WORKER_EXECUTION_ID`
- `DIREXTALK_WORKER_ROLE_ID`
- `DIREXTALK_WORKER_ATTEMPT`
- `DIREXTALK_WORKER_IDEMPOTENCY_KEY`
- `DIREXTALK_WORKER_MODEL_PROVIDER`
- `DIREXTALK_WORKER_MODEL`
- `DIREXTALK_WORKER_MODEL_REVISION`
- `DIREXTALK_WORKER_CREDENTIAL_REVISION`
- `DIREXTALK_WORKER_CONTEXT_FILE`
- `DIREXTALK_WORKER_CONTEXT_SHA256`
- `DIREXTALK_WORKER_INPUT_MANIFEST_FILE`
- `DIREXTALK_WORKER_INPUT_MANIFEST_SHA256`
- `DIREXTALK_WORKER_SECRET_ROOT`
- `DIREXTALK_WORKER_WORKSPACE_SHA256`
- `DIREXTALK_WORKER_RECEIPT_ROOT`
- `DIREXTALK_WORKER_WORKSPACE`
- `DIREXTALK_WORKER_RPC_TIMEOUT`
- `DIREXTALK_PI_TIMEOUT`

The model credential itself must never appear in this environment file. Task 9
materializes it only as `model-credential` in the task-scoped `0700` secret
root. The Worker accepts only an owned, regular, single-link `0600` file,
unlinks and syncs its directory before reading the already-open descriptor,
and starts Pi only after the credential path no longer exists. The credential,
its revision, the model binding, the canonical context, the input manifest,
and the workspace digest are all covered by one runtime-context digest. The
release artifact does not create cloud resources or credentials.

Before Pi starts, the Worker atomically stores and fsyncs a `launch_committed`
receipt containing the exact fence-bound `execution_uncertain` completion. A
restart loads and locks this receipt before Pi runtime initialization, never
runs Pi again, and submits only the stored request. A completed run is first
stored as `completion_pending` and becomes `completion_acked` only after exact
response validation. Central may accept that stored completion after lease TTL
expiry only while the same Worker, execution, role, attempt, and lease epoch
remain current; a replacement attempt or epoch still fences the old process.
