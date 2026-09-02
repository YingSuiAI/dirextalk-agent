# Stable Agent release contract

The formal Agent version is canonical `vX.Y.Z`. One release binds one reviewed
`main` commit, its RFC3339 commit timestamp, one `linux/amd64` Docker version
tag, one annotated Git tag, and one matching formal GitHub Release.

## Repository authority

- `internal/buildinfo.CurrentReleaseVersion` is the checked-in current version.
- `release/vX.Y.Z.json` binds that version to the current Agent schema and
  compatibility floor.
- `release/RELEASE_NOTES.md` contains the exact formal Release body.
- `migrations.CurrentVersion` is the schema authority.

Repository metadata does not select an upgrade target or minimum Message
Server. The deployment-owned central `agents` channel remains the only upgrade
authorization. Agent releases do not depend on a sibling Message Server
checkout or its retired action/schema catalog.

## Verification and publication

Run the repository scripts in order:

```text
bash scripts/release/prepare.sh vX.Y.Z
bash scripts/release/verify.sh vX.Y.Z
bash scripts/release/publish.sh vX.Y.Z
```

Prepare requires a clean Agent `main` whose `HEAD` exactly equals
`origin/main`, matching current metadata, and matching notes. Verify runs the
Agent Go suite against a script-owned, digest-pinned `pgvector/pgvector:pg18`
container on an ephemeral loopback port, builds all commands,
builds the unified image, checks its version/revision/created labels, and
requires all three production binaries to print the requested version. It then
runs the Agent against an isolated, ephemeral PostgreSQL instance and requires
the unauthenticated HTTP health response to report that same `release_version`.
Canonical local evidence is bound to the commit and version tag.

Publish revalidates the clean, synchronized `main` source and its prepare and
verify evidence. Buildx publishes the requested `linux/amd64` version tag, then
the script pulls that tag and rechecks its version/revision/created labels and
all three production binaries. It creates or reuses the matching annotated Git
tag and formal GitHub Release. Only after the GitHub Release succeeds does it
move `dirextalk/agent:latest` to the released version tag, pull `latest`, and
repeat the same label, binary, and running HTTP probes. The probe containers
receive no Docker socket and are removed after each check. A failed build,
version-tag pull or probe, tag push, or GitHub Release leaves `latest`
untouched; a failed final pulled-`latest` probe prevents release success.

The release contract deliberately does not require registry digest comparison,
attestation or SBOM parsing, cross-job local image identity, `latest` history
ordering, or registry race simulation. The checked-in version, source revision,
image labels, executable versions, running HTTP `release_version`, Git tag,
GitHub Release, and pulled `latest` probe are the maintained release identity.

The formal GitHub Release title is `Dirextalk Agent vX.Y.Z`, its body is the
checked-in version section. Publication requires explicit authorization;
prepare and verify do not push or create external state.

## Cloud Worker image release

Cloud Worker AMIs have a separate product-runtime release contract under
`deploy/cloud-worker`. An Agent source release does not imply that either AMI
was built or published. Each CPU/GPU image release pins its parent AMI identity,
component and recipe versions, Pi version and SHA-256, tool manifest, test
component, distribution allowlist, and output tags. Image Builder writes only a
candidate pointer. The publication command independently revalidates the AWS
account, Region, candidate AMI owner, recipe/build identity, tags and live root
mapping before moving `current` to `previous` and the verified candidate to
`current`. Rollback first validates both pointers in every allowlisted Region,
then swaps them Region-locally while journaling their exact prior values.

These SSM pointers and AMI tags are publisher-only release bookkeeping, not a
customer discovery API. After successful live qualification and publication,
record the exact Region/flavor output AMI IDs, schema, release/Pi versions,
successful-test status and supported GPU families in
`internal/cloudworker/workerimage/public-releases.json`, owned by publisher
`066107820442`. An Agent release embeds that catalog and checks exact ID,
publisher and public visibility using each customer's credentials; AMI tags
are not shared across accounts. Catalog promotion or rollback requires an Agent
release. Never add unqualified candidates, placeholder AMI IDs or private images;
an absent entry fails closed before offering paid compute. Retained Worker
provenance does not depend on the current catalog entry.

The Worker placement allowlist is Tokyo (`ap-northeast-1`), Northern California
(`us-west-1`), and Paris (`eu-west-3`). Each Region needs its own qualified public
CPU and GPU catalog entries before an Agent release enables the three-Region
placement policy. Adding coverage does not require rebuilding unchanged runtime
inputs: copy the exact qualified AMI, preserve its source build ARN and runtime
provenance, and independently verify the copy's AWS-reported source AMI/Region,
owner, root snapshot, release metadata, availability and public permissions.
Exercise the regional production consumer and CPU boot/reboot tool checks before
catalog promotion; report GPU source qualification separately from any regional
GPU hardware test. Publication does not inherit source sharing permissions.
Record copy request tokens, exact output IDs and regional pointer versions, and
restore temporarily relaxed public-access protection after sharing. New regional
pointers must not overwrite an unrelated current or candidate release.

Build and publish require a non-root operator, least-privilege Image Builder
instance profile, explicit network/KMS/Region inputs, and an acknowledged cost
ceiling. The process is manual and concurrency-one by default. Cleanup preserves
the exact Region-local current and previous AMIs for each flavor and removes
older tagged outputs only after revalidating every AMI and snapshot owner; an
Image Builder lifecycle count is not the authority because counts are scoped per
recipe version.
