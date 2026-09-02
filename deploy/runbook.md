# Core deployment runbook

## Provision

Create one protected directory per Agent instance and generate a database URL,
PostgreSQL password, TLS certificate/key, 32-byte service token, and raw
32-byte Core secret master key with
`deploy/container/scripts/bootstrap-local.sh` from the Agent project directory.
The script writes absolute paths and an exact 43-byte canonical token with no
trailing newline. Keep the directory outside the
repository or below an ignored local path. Set file mode `0400`; do not copy
secret bytes into YAML, environment files, image layers, or PostgreSQL.

Use a unique PostgreSQL database, role, named data volume, and instance ID for
each Core. Do not attach the project to another service's database or data
volume. Keep the private Compose network internal and do not publish Core gRPC
to the host.

The generated `core-secret-master-key` is mounted as
`/run/secrets/core_secret_master_key` and referenced only by
`core_secret_master_key_file`. Keep it mode `0400`; Core reads it for durable
secret envelopes (AWS credentials, model/provider credentials, chat/turn
snapshots, extensions, and execution.v2). Rotating the key without a compatible re-encryption
operation intentionally fails closed rather than attempting to read old rows
with an unknown key.

## Start and upgrade

Pin the unified Agent runtime image to the exact source revision and registry
digest. Run `docker compose ... config --quiet`, then start the local stack.
Before `config` or `up`, run
`deploy/container/scripts/preflight-local.sh /absolute/path/deploy/container/compose.local.yaml /absolute/path/.run.local/.env`;
it verifies the Docker systemd cgroup driver and both delegated cgroup-v2
roots without creating host paths.
`migrate` must finish successfully before `core` is started; the default local
Compose topology also starts the isolated extension and Core Runner services
from that same image. An upgrade uses the new Agent image for migration,
serving, and both runners; do not mix revisions.

After start, run `deploy/container/scripts/readiness.sh /absolute/path/deploy/container/compose.local.yaml core /absolute/path/.run.local/.env` from any directory. A successful result proves TLS,
service-token authentication, instance identity, API version, and minimum Core
capabilities. A successful TCP connect or unauthenticated gRPC health response
is not sufficient.

After rotating any protected input file, refresh the UID-owned volumes and
recreate Core with:

```text
deploy/container/scripts/rotate-local.sh /absolute/path/deploy/container/compose.local.yaml /absolute/path/.run.local/.env
```

For a two-project private-network check, use the local `agent_caller` network or
pre-create the production caller network named by
`DIREXTALK_AGENT_CALLER_NETWORK_NAME`. The caller reaches `core:9443` there and
must pair the exact `P2P_AGENT_CORE_SERVER_NAME`, CA certificate, and service
token mounted into Core. The readiness SNI must equal that name; a SAN or token
mismatch is rejected.

Production external PostgreSQL belongs on
`DIREXTALK_AGENT_DATABASE_NETWORK_NAME`, joined only by Core and `migrate`; the
caller must never join that database network.

For the external-PostgreSQL Compose file, the one-shot fence is explicit:

```text
docker compose --env-file /absolute/path/.env -f /absolute/path/deploy/container/compose.yaml up --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file /absolute/path/.env -f /absolute/path/deploy/container/compose.yaml up -d core
```

The second command is refused by Compose unless `migrate` completed
successfully with the same immutable Agent runtime image revision.

## Rotation

Write a new certificate/key or service token beside the current file with mode
`0400`, atomically rename each file into place, then rerun the rotation workflow
so `secret-init` refreshes the UID-owned volumes, Core is force-recreated, and
the authenticated readiness probe runs:

```text
deploy/container/scripts/rotate-local.sh /absolute/path/deploy/container/compose.local.yaml /absolute/path/.run.local/.env
```

Do not restart Core manually or replace only the host files: the mounted named
volumes retain the previous bytes until `secret-init` runs. Keep the old
material only until all callers have reconnected, then remove it from the
protected directory.

## Backup and rollback

Back up the Agent-owned PostgreSQL database and its data/artifact volumes using
the approved PostgreSQL and filesystem procedures. Record the image digest,
instance ID, migration version, and backup timestamp together. Roll back by
restoring the matching image and database backup; never run a newer migration
image against an older restored data volume without an explicit compatibility
review.

## Cloud Worker images

Cloud Worker images are maintained independently from the Agent container at
`deploy/cloud-worker`. Operators first render an immutable CPU or GPU release
from the official Region-local parent parameter, inspect the captured parent
AMI/parameter/root-volume evidence and generated checksums, then create and run
the on-demand EC2 Image Builder resources with a non-root release identity. Do
not use the Agent host deployer, frontend configuration, or a mutable image name
to select a Worker image.

Only a standard Image Builder build whose post-snapshot tests pass may populate
the candidate parameter. Those tests cover the toolchain, pinned Pi startup,
offline Git clone/edit/test work, GPU driver/CUDA/containerd/SOCI state where
applicable, reboot persistence under `/var/lib/dirextalk-worker`, and credential,
history, cache and build-key residue. Promote candidate to current only through
the repository command, which preserves the previous pointer for rollback and
performs exact AWS identity and AMI read-back. Distribution is public and
limited to the explicitly supplied Region allowlist; the first cross-Region copy
and its snapshot incur storage/transfer cost. See `deploy/cloud-worker/README.md`
for build, promotion, rollback and cleanup commands, IAM/network prerequisites,
checksums, and cost controls.

After live qualification and public publication succeed, update the embedded
`internal/cloudworker/workerimage/public-releases.json` with the exact qualified
Region/flavor AMI identities and release metadata, then release the Agent. Its
consumer uses that immutable catalog and publisher `066107820442`, not the
publisher's SSM pointers or tags. A catalog rollback likewise requires an Agent
release; already-qualified retained Workers remain reusable.

## Runner integration

The extension and Core Runner services use fixed UIDs `65531` and `65530`,
authenticated Unix `SOCK_SEQPACKET` sockets, private install/workspace/state roots, and delegated
cgroup-v2 subtrees. Provision both delegated roots before starting the default
local Compose stack; its bind mounts refuse to auto-create ordinary directories
and each runner readiness probe fails closed on a non-cgroup filesystem. WSL
Docker cgroupfs hosts without delegated subtrees are unsupported; use a native
systemd+cgroup-v2 host. Feature flags remain disabled until the corresponding
isolation and cancellation/cleanup acceptance lanes are complete. No fallback
execution inside Core is permitted.
