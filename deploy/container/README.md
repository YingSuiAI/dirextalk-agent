# Dirextalk Agent container artifacts

These files build only the new `dirextalk-agent` repository. They are not
shared with the legacy deployer, updater, or release scripts.

## Runtime boundaries

| Image | Runtime boundary |
|---|---|
| `agent.Containerfile` | Static Agent binary and CA bundle in `scratch`; fixed UID/GID `65532`, no shell, AWS CLI, Node, package manager, Docker client, or Docker socket. The image-local Docker health check makes a TLS 1.3 standard gRPC health RPC only to the Agent's loopback listener. |
| `worker.Containerfile` | Static Worker supervisor, binary digest sidecar, CA bundle, and fixed-AMI systemd assets in `scratch`; fixed UID/GID `65532`, no shell, Docker client/daemon/socket, AWS CLI, Node, or package manager. |
| `reaper.Containerfile` | Static `lambda.norpc` Go binary on the AWS `provided.al2023` OS-only Lambda image. |

Every build source is locked to the reviewed official `linux/amd64` child
manifest in the canonical Go catalog. Release builds consume only the
digest-bound copies in the retained private `dirextalk-build-sources`
repository. The Containerfiles have no external registry literal, syntax
directive, mutable default, or fallback: the publisher supplies
`BUILDKIT_SYNTAX`, `GO_BUILD_BASE`, and, for Reaper,
`REAPER_RUNTIME_BASE` from a verified ECR session.

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

Build through the closed release commands below. Direct Containerfile builds
are intentionally incomplete without the verified private-source arguments.

The first-validation artifact set is intentionally `linux/amd64` only. ARM64
must not be published until every external base is separately pinned to its
official `linux/arm64` child manifest and the artifact boundary test is
updated. The Reaper build uses `--provenance=false` because AWS Lambda requires
that form for container-image compatibility. The Worker build rejects missing or mutable/stable version
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

The Agent image defaults to `serve`; its existing migration and one-time
bootstrap entry points remain subcommands, for example
`docker compose ... run --rm agent migrate` through the Compose form below.
Its image-level health command is `dirextalk-agent healthcheck`. It reads no
database or private-key material, calls only the loopback gRPC listener, and
requires `AGENT_GRPC_HEALTHCHECK_SERVER_NAME` to match a DNS or IP SAN in the
mounted `AGENT_TLS_CERT_FILE`. It uses the system certificate roots plus that
mounted public certificate chain. If a non-default listener is necessary,
`AGENT_GRPC_HEALTHCHECK_ADDRESS` may contain only an IP loopback address using
the exact `AGENT_GRPC_LISTEN` port.

## Immutable release operator flow

The repository provides closed Go tools for the first-validation release path.
They use the standard AWS SDK credential chain; there are no AK/SK, profile,
rootkey, or arbitrary AWS arguments. Run them from a clean repository checkout
and place session descriptors, manifests, rootfs archives, AMI requests, and
publications in a protected directory outside the checkout:

```powershell
$Revision = (git rev-parse HEAD).Trim()
if (git status --porcelain) { throw 'release checkout must be clean' }
$ReleaseDate = (Get-Date).ToUniversalTime().ToString("yyyyMMdd")
$Tag = "v0.1.0-alpha.$ReleaseDate.1-$($Revision.Substring(0, 12))"
$Region = "<region>"
$AccountID = "<12-digit-account-id>"
$Out = Join-Path ([IO.Path]::GetTempPath()) "dirextalk-release-$Tag"
New-Item -ItemType Directory -Path $Out -ErrorAction Stop | Out-Null
$Session = Join-Path $Out "ecr-session.json"

$PreparedJSON = & go run ./cmd/dirextalk-ecrctl prepare --region $Region --account-id $AccountID --builder-mode direct --session-output $Session
if ($LASTEXITCODE -ne 0) { throw 'ECR preparation failed' }
$Prepared = $PreparedJSON | ConvertFrom-Json
$AgentRepository = ($Prepared.repositories | Where-Object component -eq 'agent').uri
$WorkerRepository = ($Prepared.repositories | Where-Object component -eq 'worker').uri
$ReaperRepository = ($Prepared.repositories | Where-Object component -eq 'reaper').uri
$ReleaseManifest = Join-Path $Out "release-manifest.json"
$WorkerRootFS = Join-Path $Out "worker-rootfs.tar"

& go run ./cmd/dirextalk-releasectl publish --release-tag $Tag --architecture amd64 `
  --agent-repository $AgentRepository --worker-repository $WorkerRepository `
  --reaper-repository $ReaperRepository --manifest-output $ReleaseManifest `
  --rootfs-output $WorkerRootFS --ecr-session $Session
if ($LASTEXITCODE -ne 0) { throw 'immutable release publication failed' }
& go run ./cmd/dirextalk-artifactctl validate --input $ReleaseManifest
if ($LASTEXITCODE -ne 0) { throw 'release manifest verification failed' }
```

Before the first release in the Osaka (`ap-northeast-3`) release Region, an authorized operator uses the
three explicit build-source surfaces:

```powershell
go run ./cmd/dirextalk-ecrctl sources-prepare --region $Region --account-id $AccountID
go run ./cmd/dirextalk-ecrctl sources-seed --region $Region --account-id $AccountID
go run ./cmd/dirextalk-ecrctl sources-verify --region $Region --account-id $AccountID
```

`sources-prepare` creates and strictly reads back only the separate retained
source repository. `sources-seed` is the only surface that downloads and
uploads the closed catalog; it verifies the raw child manifest, media type,
config platform, every blob digest, digest-preserving ECR upload, immutable
tag, and independent ECR readback. `sources-verify` is read-only. None of the
three commands accepts a repository, tag, digest, source URL, credential, or
local-path override.

Release `prepare` creates or strictly reads back only `dirextalk-agent`,
`dirextalk-cloud-worker`, and `dirextalk-aws-reaper`, then writes a private,
short-lived, single-use Docker session descriptor. Direct preparation also
read-verifies the already seeded source repository and never creates or seeds
it. `publish` claims that
session and removes both the temporary Docker authorization directory and the
descriptor on success or failure. If a prepared session is abandoned before
publication, remove it with:

```powershell
go run ./cmd/dirextalk-ecrctl cleanup --session $Session
```

`--builder-mode direct` creates a private-session-scoped `docker-container`
builder from the verified private BuildKit child digest; it neither imports
the operator's normal Docker
configuration nor forwards inherited proxy, AWS, or `BUILDX_*` environment
variables. It accepts only the current credential-free Docker-internal proxy
discovered through Docker read-back and binds that value only to the
task-owned builder. The publisher selects it explicitly, and cleanup must
complete external container/volume read-back before the single-use ECR session
can be removed.
A failed source verification or activation preflight is a release blocker, not
authorization to bypass the private source or cleanup contract.

The opt-in live resolver lane is:

```text
AGENT_TEST_DIRECT_BUILDER=1 \
AGENT_TEST_DIRECT_BUILDER_ACCOUNT_ID=<12-digit-Osaka-ECR-account> \
go test ./internal/releaseecr -run '^TestDirectBuilderLivePrivateBuildSources$' -count=1 -v
```

It uses the SDK default credential chain, read-verifies the preseeded source
catalog, and exercises the same direct builder. Because release preparation
may create missing fixed release repositories, run it only with explicit
authority for the intended account.

This cleanup does not delete ECR repositories. They are retained Managed
release infrastructure and need an explicit owner and lifecycle outside a
single test or AMI. A publish interrupted before its final manifest can be
retried from the same clean revision and tag after preparing a new session;
content is pushed by digest first, and an already observed tag is accepted only
when its digest is exact. A different digest is an immutable-tag conflict: do
not overwrite it, and use a new prerelease tag. If the final manifest already
exists, validate and retain it instead of overwriting it.

Prepare the strict `dirextalk.agent.worker-ami-build-request/v1` JSON outside
the repository with paths to the release manifest and Worker rootfs, then run:

```powershell
$BuildRequest = Join-Path $Out "worker-ami-build-request.json"
$Publication = Join-Path $Out "worker-ami-publication.json"
go run ./cmd/dirextalk-worker-ami build --request $BuildRequest --output $Publication
go run ./cmd/dirextalk-worker-ami verify --manifest $Publication
```

`build` writes a recoverable intent beside the publication before AWS
mutation. Repeating the exact request and output resumes or verifies the same
AMI instead of creating an untracked replacement. `verify` is repeatable and
re-attests the AMI, architecture, root snapshot, release/rootfs/binary digests,
and AWS identity. Keep the publication until cleanup has been proven. To remove
the AMI, provide a strict `dirextalk.agent.worker-ami-destroy-request/v1` file
that confirms the publication path, AWS account, and image digest, then run:

```powershell
$DestroyRequest = Join-Path $Out "worker-ami-destroy-request.json"
go run ./cmd/dirextalk-worker-ami destroy --request $DestroyRequest
```

Destroy succeeds only after independent absence read-back for the AMI and root
snapshot; an interrupted or blocked destroy is rerun with the same confirmation
rather than reported as complete.

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
The host gRPC publish defaults to `127.0.0.1:9443`; set
`AGENT_GRPC_BIND_ADDRESS` only when an explicitly reviewed network path needs a
different bind. `AGENT_GRPC_HEALTHCHECK_SERVER_NAME` is also required: supply a
non-secret DNS or IP SAN from `AGENT_TLS_CERT_PEM`, so the inherited image
health check validates the mounted TLS certificate instead of bypassing its
identity. Callers on `compose.shared-postgres.yaml` should use the Docker
network alias and do not require a public host listener.

The Agent image variable uses the explicit
`*_IMMUTABLE_PRERELEASE_WITH_DIGEST` name. The full three-image preflight above
is required for AWS validation/release work; local P0/P1 validation needs only
the Agent image. `AGENT_ENABLE_AWS_CONTROL` defaults to `false`, so the Reaper
image and Worker control endpoint may be omitted. Enabling AWS control requires
the immutable Reaper image and exact
`grpcs://worker-control.y1.dirextalk.ai:443` endpoint. For the initial operator
reconciliation only, leave `AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME` empty
and `AGENT_ENABLE_MANAGED_PREPARATION_AWS=false`; the Agent starts with
identity preview but all Worker-Control-dependent mutation and signing paths
fail with a capability-not-ready precondition. After reconciliation, set the
exact `com.amazonaws.vpce.ap-northeast-3.vpce-svc-<17 lowercase hex>` service
name and recreate the Agent container without changing `AGENT_INSTANCE_ID` or
its database. Keep Managed preparation false until that restart succeeds. Keep
the AWS gate off until the P2 blockers in `docs/delivery-tracker.md` are
closed.

After a Worker AMI has been built and verified, mount its publication read-only
and set `AGENT_WORKER_AMI_PUBLICATION_FILE` to that container path. Startup
strictly validates and imports it into the durable active-release catalog.
Exact startup replay is idempotent; a new valid publication supersedes only the
matching Agent-instance/account/Region/architecture slot and retains the old
audit row. Cloud quote preparation fails closed if no matching active release
exists. A configured file or successful import is not evidence that real ECR
publication/AMI acceptance has run.

After supplying the required environment variables and protected bind mounts:

```powershell
docker compose -f deploy/container/compose.yaml config --quiet
docker compose -f deploy/container/compose.yaml run --rm agent migrate
docker compose -f deploy/container/compose.yaml run --rm agent bootstrap-service-key
docker compose -f deploy/container/compose.yaml up -d agent
```

When Agent reuses a PostgreSQL server already owned by another Compose project,
add `compose.shared-postgres.yaml` and set `AGENT_UPSTREAM_NETWORK` to that
project's existing Docker network. The overlay attaches Agent with the stable
network alias `dirextalk-agent` (overridable through `AGENT_NETWORK_ALIAS`) and
does not create, restart, inspect credentials from, or otherwise own the
PostgreSQL container. Agent still uses its own database, role, migration ledger,
and backup boundary inside that PostgreSQL server.

```powershell
docker compose `
  -f deploy/container/compose.yaml `
  -f deploy/container/compose.shared-postgres.yaml `
  config --quiet
```

The model-profile file and runtime-secret directory must be readable by UID
`65532` and remain read-only. No host Docker socket should be mounted into the
Agent or Worker.

## Fixed Worker AMI bootstrap assets

`worker.Containerfile` also carries the repository-owned files under
`worker-ami/`. The release tool exports this scratch image's deterministic root
filesystem, and the AMI tool installs the sysusers/tmpfiles/systemd definitions
and enables `dirextalk-cloud-worker.service`. Docker/BuildKit is permitted on
the trusted release host only; the resulting EC2 image contains no container
runtime or socket. The privileged installer socket remains disabled. Its
daemon can verify pre-staged bytes and execute only an exact command selected
by ID from the same signed plan, with durable idempotency/interruption state;
the Worker does not yet provision trust or construct that request. A separately
approved production Foundation onboarding and per-deployment installer wiring
remain deferred gates. See
[worker-ami/README.md](worker-ami/README.md) for the fixed-AMI contract.
