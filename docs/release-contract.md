# Stable Agent release contract

The formal Agent version is canonical `vX.Y.Z`. One release binds one reviewed
`main` commit, its RFC3339 commit timestamp, one single-platform OCI index under
the Docker version tag, one annotated Git tag, and one matching formal GitHub
Release.

## Repository authority

- `internal/buildinfo.CurrentReleaseVersion` is the checked-in current version.
- `release/vX.Y.Z.json` binds that version to the current Agent schema and
  compatibility floor.
- `release/RELEASE_NOTES.md` contains the exact formal Release body.
- `migrations.CurrentVersion` is the schema authority.

Repository metadata does not select an upgrade target or minimum Message
Server. The deployment-owned central `agents` channel remains the only upgrade
authorization. A formal release additionally runs the Agent catalog preflight
against a clean Message Server checkout whose `HEAD` equals its `origin/main`.

## Verification and publication

Run the repository scripts in order:

```text
bash scripts/release/prepare.sh vX.Y.Z
bash scripts/release/verify.sh vX.Y.Z
bash scripts/release/publish.sh vX.Y.Z
```

Prepare requires a clean Agent `main` whose `HEAD` exactly equals
`origin/main`, matching current metadata, and matching notes. Verify runs the
Go suite with the sibling Message Server catalog input, builds all commands,
builds the unified image, checks its version/revision/created labels, and
requires all three production binaries to print the requested version.
Canonical local evidence is bound to the commit and image ID.

Publish revalidates every precondition and refuses a local or remote tag,
formal Release, image, notes, or evidence drift. Buildx publishes an OCI index
containing exactly `linux/amd64` plus its standard attestations. Publication
then requires its build metadata digest to equal the registry index digest,
pulls that immutable digest, rechecks the OCI labels and all three binaries,
creates or verifies the annotated Git tag and exact formal GitHub Release, and
only then promotes that same index without a rebuild to
`dirextalk/agent:latest`. The version and latest tags must resolve to the
identical immutable digest. An exact retry reuses the already validated version
index instead of rebuilding provenance; a conflicting duplicate fails before
the mutable deployment tag moves. An already exact `latest` is not rewritten,
and publication refuses to replace a newer canonical `latest` version with an
older release. Docker Hub publication credentials are single-writer authority;
the workflow concurrency lock plus immediate pre/postcondition checks detect
external tag drift but cannot provide registry-side compare-and-swap.

The formal GitHub Release title is `Dirextalk Agent vX.Y.Z`, its body is the
checked-in version section, and it has no assets. Publication requires explicit
authorization; prepare and verify do not push or create external state.
