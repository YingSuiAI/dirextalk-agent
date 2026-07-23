# Dirextalk Agent containers

This directory owns the Agent repository's runtime images and Compose assets.
It does not modify the legacy deployer, updater, Message Server, or another
service's PostgreSQL container.

## Runtime boundaries

| Asset | Boundary |
| --- | --- |
| `agent.Containerfile` | Static non-root Agent binary in `scratch`, with CA roots and a TLS gRPC health probe. No shell, package manager, AWS CLI, Node, Docker client, or socket. |
| `worker.Containerfile` | Static non-root Worker/rootfs source for an exclusive VM; it is not a local Compose service. |
| `reaper.Containerfile` | Static AWS Lambda runtime image; it is not a local Compose service. |
| `compose.local.yaml` | Local PostgreSQL 18 + one-shot migration + one-shot Service Key bootstrap + Agent stack. |
| `compose.yaml` | Production-style single Agent service that uses caller-owned external PostgreSQL. |

All runtime images require an immutable prerelease tag plus registry digest.
`latest`, stable mutable tags, Docker sockets, and runtime downloads are not
deployment inputs.

## Agent configuration and secrets

The Agent reads strict YAML at `/etc/dirextalk-agent/config.yaml`. Start from
[`config/config.example.yaml`](config/config.example.yaml), put it in a
protected host location, and mount it read-only. It contains only non-secret
settings and mounted-file paths.

The Agent needs separate mounted files for at least:

- PostgreSQL DSN
- TLS certificate and private key
- Service Key pepper and 32-byte master key
- initial bootstrap Service Key

The model-profile catalog and model runtime-secret directory are separate
read-only binds. Keep the runtime-secret directory at
`/run/dirextalk/mounted-secrets`; do not point it at `/run/secrets`, because
`mounted:<name>` references must not resolve database, TLS, bootstrap, or
master-key files.

Only image references, host paths, database name/user, and listener port are
Compose interpolation inputs. Secret *values* are supplied from host files as
Docker secrets, not from environment variables or `.env` files.

## Local multi-container stack

`compose.local.yaml` starts, in order:

```text
PostgreSQL 18 (persistent named volume)
  └─ migrate (one-shot)
       └─ bootstrap-service-key (one-shot, idempotent)
            └─ agent
```

It requires an immutable PostgreSQL 18 image reference, an immutable Agent
image reference, the YAML config path, model-profile/runtime-secret paths, and
the host secret-file paths. In particular, the Agent DSN and PostgreSQL
password are separate Docker secret files; use the same least-privilege role
and consistent credentials in both.

```text
docker compose -f deploy/container/compose.local.yaml config --quiet
docker compose -f deploy/container/compose.local.yaml up -d
```

The stack intentionally does not start a Worker or Reaper locally. Worker root
automation belongs to a deployed exclusive VM; Reaper belongs to the AWS-side
expiry path.

## External PostgreSQL deployment

`compose.yaml` contains one hardened Agent service. It never creates,
restarts, inspects, or owns PostgreSQL. The caller must provision an
Agent-specific database and least-privilege role, then use the same config and
secret mount layout:

```text
docker compose -f deploy/container/compose.yaml config --quiet
docker compose -f deploy/container/compose.yaml run --rm agent migrate
docker compose -f deploy/container/compose.yaml run --rm agent bootstrap-service-key
docker compose -f deploy/container/compose.yaml up -d agent
```

Use `compose.shared-postgres.yaml` only to join an existing Docker network. It
adds the stable `dirextalk-agent` alias and does not change database ownership.

The Agent healthcheck makes a TLS 1.3 standard gRPC health RPC only to its own
loopback listener. `grpc_healthcheck_server_name` in YAML must match a SAN in
the mounted certificate.

## AWS gate and release operation

`enable_aws_control` is `false` by default. Enabling it additionally requires
the immutable Reaper image, the frozen Worker-control endpoint, and the
appropriate private-link configuration in YAML. It is not production-ready
until the real ECR publication and AMI lifecycle acceptance described in
[the delivery status](../../docs/delivery-tracker.md) has passed.

Release procedures are deliberately separate from runtime Compose operation:

- [Agent-only image release](../../docs/agent-image-release.md)
- [Artifact-origin release](../../docs/artifact-origin-release.md)
- [Managed ECR verification](../../docs/ecr-managed-release.md)
- [Worker AMI release](../../docs/worker-ami-release.md)
- [Fixed Worker AMI rootfs contract](worker-ami/README.md)

The release tools use the standard AWS SDK credential chain only in an
authorized operator context. They are not gRPC, Runtime, Skill, or Compose
surfaces.
