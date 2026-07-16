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
docker buildx build --load --platform linux/amd64 --build-arg "VERSION=$Tag" --build-arg "REVISION=$Revision" -f deploy/container/agent.Containerfile -t "dirextalk-agent-local:$Tag" .
docker buildx build --load --platform linux/amd64 --build-arg "VERSION=$Tag" --build-arg "REVISION=$Revision" -f deploy/container/worker.Containerfile -t "dirextalk-worker-local:$Tag" .
docker buildx build --load --platform linux/amd64 --provenance=false --build-arg "VERSION=$Tag" --build-arg "REVISION=$Revision" -f deploy/container/reaper.Containerfile -t "dirextalk-reaper-local:$Tag" .
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

$PreparedJSON = & go run ./cmd/dirextalk-ecrctl prepare --region $Region --account-id $AccountID --session-output $Session
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

`prepare` creates or strictly reads back only `dirextalk-agent`,
`dirextalk-cloud-worker`, and `dirextalk-aws-reaper`, then writes a private,
short-lived, single-use Docker session descriptor. `publish` claims that
session and removes both the temporary Docker authorization directory and the
descriptor on success or failure. If a prepared session is abandoned before
publication, remove it with:

```powershell
go run ./cmd/dirextalk-ecrctl cleanup --session $Session
```

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

The Agent image variable uses the explicit
`*_IMMUTABLE_PRERELEASE_WITH_DIGEST` name. The full three-image preflight above
is required for AWS validation/release work; local P0/P1 validation needs only
the Agent image. `AGENT_ENABLE_AWS_CONTROL` defaults to `false`, so the Reaper
image and Worker control endpoint may be omitted. Enabling AWS control makes
both mandatory and applies the immutable-prerelease validation. Keep the gate
off until the P2 blockers in `docs/delivery-tracker.md` are closed.

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

The model-profile file and runtime-secret directory must be readable by UID
`65532` and remain read-only. No host Docker socket should be mounted into the
Agent or Worker.

## Fixed Worker AMI bootstrap assets

`worker.Containerfile` also carries the repository-owned files under
`worker-ami/`. The release tool exports this scratch image's deterministic root
filesystem, and the AMI tool installs the sysusers/tmpfiles/systemd definitions
and enables `dirextalk-cloud-worker.service`. Docker/BuildKit is permitted on
the trusted release host only; the resulting EC2 image contains no container
runtime or socket. The privileged installer socket remains disabled and its
daemon only verifies pre-staged bytes. Base-container digest pinning, a
separately approved production Foundation onboarding, and dynamic installer
trust/execution remain deferred gates. See
[worker-ami/README.md](worker-ami/README.md) for the fixed-AMI contract.
