# Dirextalk Agent Core containers

These assets deploy one independent Core instance with its own private
PostgreSQL database and named volumes. The Core image and migration command use
the same immutable image reference. The extension runner is a separate image,
UID, socket, install root, workspace root, and delegated cgroup subtree.

## Build

Build both binaries from the same source revision. The Dockerfiles use a
digest-pinned Go toolchain and produce `scratch` images with no shell, package
manager, runtime downloads, or host socket:

```text
docker build -f deploy/container/agent.Containerfile -t "$CORE_IMAGE" .
docker build -f deploy/container/extension-runner.Containerfile -t "$RUNNER_IMAGE" .
```

The release pipeline should replace local tags with immutable registry
references containing a digest before sharing them with another deployment.

## Local stack

Generate protected files and a non-secret Compose environment (the output
directory is ignored by Git):

```text
cd /path/to/dirextalk-agent
deploy/container/scripts/bootstrap-local.sh "$PWD/.run.local" dirextalk-agent-core:local dirextalk-extension-runner:local
docker compose --env-file "$PWD/.run.local/.env" -f "$PWD/deploy/container/compose.local.yaml" config --quiet
docker compose --env-file "$PWD/.run.local/.env" -f "$PWD/deploy/container/compose.local.yaml" up -d
deploy/container/scripts/readiness.sh "$PWD/deploy/container/compose.local.yaml" core "$PWD/.run.local/.env"
```

The bootstrap output and every path written to `.env` are absolute, so the
Compose command may subsequently be run from another directory.

Bootstrap also writes `instance-id` as a protected, newline-terminated
artifact and exposes its absolute path as `DIREXTALK_AGENT_INSTANCE_ID_FILE`.
The Message Server two-project local harness uses that artifact together with
`tls-cert` and `service-token` to configure its SNI, CA, expected instance ID,
and authenticated caller without copying secret values into YAML.

The stack has no published Core port. Core joins internal `agent_private` and
`agent_caller` networks plus `agent_egress` for configured model/AWS HTTPS
authorities. PostgreSQL and the extension runner remain on the private network
only; a future Message Server joins `agent_caller`, never the database network.
PostgreSQL is not shared with a business service, and no data directory or
Docker socket is mounted.

All secret values are files mounted read-only at runtime. The YAML contains only
the instance ID, feature gates, and file paths. `migrate` completes before
`core` starts and reads the same database URL file and image revision as Core.

The readiness probe is authenticated and checks `AgentService` instance ID,
API version, and the `agent.info`, `model.profile`, and `conversation`
capabilities. The standard gRPC health service, when enabled, is not used as a
readiness claim. `TLS_SERVER_NAME` (the fifth bootstrap argument, default
`localhost`) is placed in the certificate SAN and in the Core readiness SNI.
For a two-project deployment, the Message Server caller must join the
`DIREXTALK_AGENT_CALLER_NETWORK_NAME` network and use exactly the same
`P2P_AGENT_CORE_SERVER_NAME`, CA certificate (`tls-cert`), and service token
file (`service-token`) as Core; it addresses `core:9443` on that network.

The production Compose file puts external PostgreSQL on the separately
managed `agent_database` network, joined only by Core and `migrate`.

## Extension runner seam

Keep `core_extension_enabled: false` until a Linux host delegates a private
cgroup-v2 subtree to UID `65531` and the socket/install/workspace volume
ownership has been provisioned for UIDs `65531` and `65532`. The runner image
is included in the baseline so this seam is explicit; enabling it remains a
separate workload-runner integration acceptance. The runner never receives a
host socket or Core database volume. With the `extensions` profile,
`extension-socket-init` repairs socket ownership before the Runner starts.

## Core Runner seam

`core_workload_enabled` stays `false` by default. Enabling it requires the
`core-runner` Compose profile, immutable Core Runner image, private socket
volume, and a cgroup-v2 subtree delegated to runner UID `65530`; Core runs as
UID `65532` and must use the matching socket and `core_workload_runner_uid`.
The runner has no network, database, Docker socket, Agent secrets, or host
mounts beyond that delegated cgroup subtree.

Core advertises `workload.core_runner` only after the runner's nonce-backed
full readiness probe succeeds. The proof exercises its user namespace, exact
tmpfs writable quota, seccomp, cgroup create/attach/reap, and sealed result
path. A failure leaves workload planning RPCs registered but execution handler
and capability disabled. Configure a genuinely delegated subtree; a mounted
but non-delegated `/sys/fs/cgroup` is not sufficient.

The passed transient systemd delegated-cgroup isolation test is not a
two-Compose end-to-end or real workload acceptance. Production SSM/ECS
registry wiring, two-Compose E2E, and live Core Runner workload acceptance are
still pending.
