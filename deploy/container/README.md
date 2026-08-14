# Dirextalk Agent containers

These assets deploy one independent Core instance with its own private
PostgreSQL database and named volumes. The unified Agent runtime image contains
the `dirextalk-agent`, `dirextalk-extension-runner`, and
`dirextalk-core-runner` executables plus the verified static shell used by Core
Runner. The three runtime services select the same immutable image reference
while retaining separate UID, socket, install root, workspace root, network,
and delegated cgroup boundaries.

## Build

Build the unified runtime image from one source revision. The Containerfile
uses a digest-pinned Go toolchain and produces a `scratch` image with no
package manager, runtime downloads, or host socket:

```text
docker build -f deploy/container/agent.Containerfile -t "$AGENT_IMAGE" .
```

The release pipeline should replace local tags with immutable registry
references containing a digest before sharing them with another deployment.

## Local stack

Generate protected files and a non-secret Compose environment (the output
directory is ignored by Git):

```text
cd /path/to/dirextalk-agent
deploy/container/scripts/bootstrap-local.sh "$PWD/.run.local" dirextalk-agent:local
deploy/container/scripts/preflight-local.sh "$PWD/deploy/container/compose.local.yaml" "$PWD/.run.local/.env"
docker compose --env-file "$PWD/.run.local/.env" -f "$PWD/deploy/container/compose.local.yaml" config --quiet
docker compose --env-file "$PWD/.run.local/.env" -f "$PWD/deploy/container/compose.local.yaml" up -d
deploy/container/scripts/readiness.sh "$PWD/deploy/container/compose.local.yaml" core "$PWD/.run.local/.env"
```

The bootstrap arguments are `OUTPUT_DIR [AGENT_IMAGE] [POSTGRES_IMAGE]
[TLS_SERVER_NAME]`; the default Agent image is `dirextalk-agent:local`. The
generated `DIREXTALK_AGENT_IMAGE_IMMUTABLE` value is the only Agent image
reference. The local Compose file starts `core`, `extension-runner`, and
`core-runner` as three separate containers by default and overrides each
runner's entrypoint to its explicit binary in that same image.

The bootstrap output and every path written to `.env` are absolute, so the
Compose command may subsequently be run from another directory.

Each bootstrap creates a unique stack namespace (`DIREXTALK_AGENT_STACK_NAME`,
default `dirextalk-agent-<instance-id-prefix>`) and derives every local network,
named volume, and delegated cgroup root from it. Compose requires those names
from the generated `.env`; do not reuse an `.env` between stacks.

Runner containers also receive per-stack systemd cgroup parents through
`DIREXTALK_EXTENSION_CGROUP_PARENT` and `DIREXTALK_CORE_RUNNER_CGROUP_PARENT`.
Bootstrap derives safe `<stack>-extension.slice` and
`<stack>-core-runner.slice` defaults; explicit values must be single-line
`[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?\.slice` names. Native Linux E2E hosts should use the systemd
cgroup driver with those delegated slices. The default stack renders all three
runtime containers with their isolated entrypoints. Both runner cgroup binds
set `create_host_path: false`: Compose refuses to start if the host paths are
missing or are ordinary directories, and each runner readiness probe still
requires a real delegated cgroup-v2 subtree. WSL Docker cgroupfs environments
without delegated subtrees are therefore rejected; provision the roots on a
native systemd+cgroup-v2 host before running `up`.
If an existing protected environment predates these parent variables, bootstrap
replays the migration with a protected journal and backups; interrupted runs
complete or restore the environment before normal validation and reuse.

The optional isolated surfaces are strict, immutable bootstrap controls:
`DIREXTALK_CORE_EXTENSION_ENABLED` and `DIREXTALK_CORE_WORKLOAD_ENABLED` accept
only `true` or `false` and default to `false`; the unified image fixes runner
UIDs at `65531` and `65530` (overrides are rejected); runner sockets default to
`/run/dirextalk-agent/extension-runner.sock` and
`/run/dirextalk-core-runner/runner.sock`. Invalid values are rejected before
any output directory is created. The selected values are written to both the
non-secret Core YAML and the hashed `.manifest` artifact. Enabling a surface
does not change the container topology: both runners start with Core after
their socket and delegated cgroup roots are provisioned. Each runner has a
scratch-image healthcheck: Core Runner uses its nonce-backed UDS
readiness probe; the extension runner uses its nonce-bound UDS readiness
protocol plus ownership checks. Wait for both runner healthchecks before
starting or recreating Core when the corresponding runner readiness checks
pass.

Bootstrap also writes `instance-id` as a protected, newline-terminated
artifact and exposes its absolute path as `DIREXTALK_AGENT_INSTANCE_ID_FILE`.
The Message Server two-project local harness uses that artifact together with
`tls-cert` and `service-token` to configure its SNI, CA, expected instance ID,
and authenticated caller without copying secret values into YAML.

The stack has no published Core port. Core joins internal `agent_private` and
`agent_caller` networks plus `agent_egress` for configured model/AWS HTTPS
authorities. PostgreSQL remains on the private network only. Both extension and
Core Runner use `network_mode: none`; a future Message Server joins
`agent_caller`, never the database network.
PostgreSQL is not shared with a business service, and no data directory or
Docker socket is mounted.

All secret values are files mounted read-only at runtime. The YAML contains only
the instance ID, feature gates, and file paths. `core_secret_master_key_file`
points to a strict mode-0400 raw 32-byte key for every durable Core secret
envelope; PostgreSQL receives only encrypted credential and snapshot fields.
`migrate` completes before
`core` starts and reads the same database URL file and image revision as Core.

The readiness probe is authenticated and checks `AgentService` instance ID,
API version, and the `agent.info`, `model.profile`, and `conversation`
capabilities. The standard gRPC health service, when enabled, is not used as a
readiness claim. `TLS_SERVER_NAME` (the fourth bootstrap argument, default
`localhost`) is placed in the certificate SAN and in the Core readiness SNI.
For a two-project deployment, the Message Server caller must join the
`DIREXTALK_AGENT_CALLER_NETWORK_NAME` network and use exactly the same
`P2P_AGENT_CORE_SERVER_NAME`, CA certificate (`tls-cert`), and service token
file (`service-token`) as Core; it addresses `core:9443` on that network.

The standalone production Compose file intentionally remains Core-only for
external PostgreSQL. The complete three-container deployment topology is
owned by the Message Server split-agent Compose deployment.

## Extension runner seam

The `agent_runner_workspaces` volume is the single shared execution workspace
root used by the Agent and isolated extension runner. It is runner-owned with
the exact identity `65531:65532` and mode `0770`; the Agent reaches it through
its group and binds it into the account purge registry. Staging remains a
separate Agent-private root.

Keep `core_extension_enabled: false` until a Linux host delegates a private
cgroup-v2 subtree to UID `65531` and the socket/install/workspace volume
ownership has been provisioned for UIDs `65531` and `65532`. The runner binary
is included in the unified Agent image; its isolation seam remains explicit.
The runner never receives a
host socket or Core database volume. The `extension-socket-init` service repairs
socket ownership before the Runner starts. The `extension-runner-data-init`
service likewise repairs the runner-owned install/state roots to
`65531:65531` mode `0700` and the shared execution workspace root to
`65531:65532` mode `0770` before the Runner validates those trust boundaries.
The runner container is capped at 2 CPUs, 1 GiB memory, and 256 processes; this
outer service budget leaves headroom above the current 1-CPU, 256 MiB,
32-process per-run cgroup. The Unix packet server admits at most 64 connections
and one execution, applies fixed request-read and response-write deadlines, and
fails a run when stdout, stderr, workspace, or declared result output exceeds
its current request budget instead of reporting truncated success.

## Core Runner seam

`core_workload_enabled` stays `false` by default. Enabling it requires the
Core Runner service, the same immutable Agent image, private socket volume,
and a cgroup-v2 subtree delegated to runner UID `65530`; Core runs as UID
`65532` and must use the matching socket and `core_workload_runner_uid`.
The runner has no network, database, Docker socket, Agent secrets, or host
mounts beyond that delegated cgroup subtree.

Core advertises `workload.core_runner` only after the runner's nonce-backed
full readiness probe succeeds. The proof exercises its user namespace, exact
tmpfs writable quota, seccomp, cgroup create/attach/reap, and sealed result
path. A failure leaves workload planning RPCs registered but execution handler
and capability disabled. Configure a genuinely delegated subtree; a mounted
but non-delegated `/sys/fs/cgroup` is not sufficient.

The passed transient systemd delegated-cgroup isolation test is not a
two-Compose end-to-end or real workload acceptance. Two-Compose E2E and live
Core Runner workload acceptance are still pending.
