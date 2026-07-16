# Dirextalk Agent container artifacts

These files build only the new `dirextalk-agent` repository. They are not
shared with the legacy deployer, updater, or release scripts.

## Runtime boundaries

| Image | Runtime boundary |
|---|---|
| `agent.Containerfile` | Static Agent binary and CA bundle in `scratch`; fixed UID/GID `65532`, no shell, AWS CLI, Node, package manager, Docker client, or Docker socket. |
| `worker.Containerfile` | Static Worker supervisor, binary digest sidecar, CA bundle, and fixed-AMI systemd assets in `scratch`; fixed UID/GID `65532`, no shell, Docker client/daemon/socket, AWS CLI, Node, or package manager. |
| `reaper.Containerfile` | Static `lambda.norpc` Go binary on the AWS `provided.al2023` OS-only Lambda image. |

The first-validation Worker supervisor is deliberately non-root. The current
typed `worker.noop` action needs no elevated privilege. A later service-install
executor must introduce a separately approved, narrowly scoped privilege
boundary inside the exclusive VM; changing the supervisor back to root is not
an acceptable shortcut. The Worker image does not weaken its cloud boundary:
its instance role and principal-scoped S3 paths still define what it can
access. Direct Worker
CloudWatch logging is intentionally disabled until a stream-scoped policy is
available; it must not be inferred from the presence of the log group.

## Build

Build from the repository root. These commands create local images only and do
not push them:

```powershell
$Tag = "v0.1.0-alpha.20260716.1-$((git rev-parse --short=12 HEAD))"
$Revision = git rev-parse HEAD
docker buildx build --load --platform linux/amd64 -f deploy/container/agent.Containerfile -t "dirextalk-agent-local:$Tag" .
docker buildx build --load --platform linux/amd64 --build-arg "VERSION=$Tag" --build-arg "REVISION=$Revision" -f deploy/container/worker.Containerfile -t "dirextalk-worker-local:$Tag" .
docker buildx build --load --platform linux/amd64 --provenance=false -f deploy/container/reaper.Containerfile -t "dirextalk-reaper-local:$Tag" .
```

Use `linux/arm64` consistently when targeting ARM64. The Reaper build uses
`--provenance=false` because AWS Lambda requires that form for container-image
compatibility. The Worker build rejects missing or mutable/stable version
metadata before compiling and writes a SHA-256 sidecar for the exact static
binary. Worker startup recomputes that digest before it reads EC2 user-data or
contacts AWS.

Deployment references must have both a prerelease tag and the registry digest,
for example:

```text
registry.example/dirextalk-agent:v0.1.0-alpha.20260716.1-abcdef123456@sha256:<64 lowercase hex characters>
```

`latest`, `v1.0.3`, stable tags without `alpha`/`beta`/`rc`, and references
without `@sha256:` are rejected deployment inputs. A caller can apply this
preflight without printing the references:

```powershell
$Pattern = '^.+:v\d+\.\d+\.\d+-(alpha|beta|rc)[A-Za-z0-9.-]*-[0-9a-f]{7,40}@sha256:[0-9a-f]{64}$'
$Refs = @($env:DIREXTALK_AGENT_IMAGE_IMMUTABLE_PRERELEASE_WITH_DIGEST, $env:DIREXTALK_WORKER_IMAGE_IMMUTABLE_PRERELEASE_WITH_DIGEST, $env:DIREXTALK_REAPER_IMAGE_IMMUTABLE_PRERELEASE_WITH_DIGEST)
if ($Refs.Count -ne 3 -or $Refs.Where({ [string]::IsNullOrWhiteSpace($_) -or $_ -notmatch $Pattern -or $_ -match ':(latest|v1\.0\.3)@' }).Count -ne 0) { throw 'immutable prerelease image references are required' }
$BootstrapInputs = @($env:AGENT_POSTGRES_DSN, $env:AGENT_BOOTSTRAP_SERVICE_KEY, $env:AGENT_BOOTSTRAP_CLIENT_ID)
if ($BootstrapInputs.Where({ [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) { throw 'external PostgreSQL and bootstrap service-key inputs are required' }
```

## External-PostgreSQL Compose example

`compose.yaml` contains only the Agent service. It never creates PostgreSQL.
The caller supplies `AGENT_POSTGRES_DSN`; Compose mounts it as a mode-`0400`
secret and the Agent reads it through `AGENT_DATABASE_URL_FILE`. TLS material,
the service-key pepper, the master key, and `AGENT_BOOTSTRAP_SERVICE_KEY` follow
the same mounted-secret path and are not present in the YAML.

`AGENT_BOOTSTRAP_CLIENT_ID` is a required non-secret caller identifier.
`AGENT_BOOTSTRAP_SCOPES` defaults to `admin` for the first key and can be
overridden explicitly. The bootstrap key value must use the service-key file
format accepted by the Agent; never place it in `.env` or the Compose YAML.

The Agent image variable uses the explicit
`*_IMMUTABLE_PRERELEASE_WITH_DIGEST` name. The full three-image preflight above
is required for AWS validation/release work; local P0/P1 validation needs only
the Agent image. `AGENT_ENABLE_AWS_CONTROL` defaults to `false`, so the Reaper
image and Worker control endpoint may be omitted. Enabling AWS control makes
both mandatory and applies the immutable-prerelease validation. Keep the gate
off until the P2 blockers in `docs/delivery-tracker.md` are closed.

After supplying the required environment variables and protected bind mounts:

```powershell
docker compose -f deploy/container/compose.yaml config --quiet
docker compose -f deploy/container/compose.yaml run --rm agent migrate
docker compose -f deploy/container/compose.yaml run --rm agent bootstrap-service-key
docker compose -f deploy/container/compose.yaml up -d agent
```

The model-profile file and runtime-secret directory must be readable by UID
`65532` and remain read-only. No host Docker socket should be mounted into the
Agent or Worker.

## Fixed Worker AMI bootstrap assets

`worker.Containerfile` also carries the repository-owned files under
`worker-ami/`. An AMI build may export this scratch image's root filesystem,
install the sysusers/tmpfiles/systemd definitions, and enable
`dirextalk-cloud-worker.service`. Docker or another OCI tool is permitted on
the trusted build host only; the resulting EC2 image contains no container
runtime or socket. See [worker-ami/README.md](worker-ami/README.md) for the
fixed-AMI contract and the remaining fail-closed limitation.
