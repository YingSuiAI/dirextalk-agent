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
Canonical local evidence is bound to the commit and version tag.

Publish revalidates the clean, synchronized `main` source and its prepare and
verify evidence. Buildx publishes the requested `linux/amd64` version tag, then
the script pulls that tag and rechecks its version/revision/created labels and
all three production binaries. It creates or reuses the matching annotated Git
tag and formal GitHub Release. Only after the GitHub Release succeeds does it
move `dirextalk/agent:latest` to the released version tag, pull `latest`, and
repeat the same label and binary probes. A failed build, pull, probe, tag push,
or GitHub Release leaves `latest` untouched.

The release contract deliberately does not require registry digest comparison,
attestation or SBOM parsing, cross-job local image identity, `latest` history
ordering, or registry race simulation. The checked-in version, source revision,
image labels, executable versions, Git tag, GitHub Release, and pulled `latest`
probe are the maintained release identity.

The formal GitHub Release title is `Dirextalk Agent vX.Y.Z`, its body is the
checked-in version section. Publication requires explicit authorization;
prepare and verify do not push or create external state.
