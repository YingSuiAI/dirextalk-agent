# Core deployment runbook

## Provision

Create one protected directory per Agent instance and generate a database URL,
PostgreSQL password, TLS certificate/key, and 32-byte service token with
`deploy/container/scripts/bootstrap-local.sh` from the Agent project directory.
The script writes absolute paths and an exact 43-byte canonical token with no
trailing newline. Keep the directory outside the
repository or below an ignored local path. Set file mode `0400`; do not copy
secret bytes into YAML, environment files, image layers, or PostgreSQL.

Use a unique PostgreSQL database, role, named data volume, and instance ID for
each Core. Do not attach the project to another service's database or data
volume. Keep the private Compose network internal and do not publish Core gRPC
to the host.

## Start and upgrade

Pin both Core and extension-runner images to the exact source revision and
registry digest. Run `docker compose ... config --quiet`, then start the local
stack. `migrate` must finish successfully before `core` is started. An upgrade
uses the new Core image for both migration and serving; do not mix revisions.

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
successfully with the same immutable Core image revision.

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

## Runner integration

The extension runner requires a distinct UID, an authenticated Unix
`SOCK_SEQPACKET` socket, private install/workspace/state roots, and a delegated
cgroup-v2 subtree. Keep the runner disabled until those host prerequisites and
the cancellation/cleanup acceptance lane are complete. No fallback execution
inside Core is permitted.
