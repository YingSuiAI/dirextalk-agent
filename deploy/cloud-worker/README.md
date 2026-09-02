# Dirextalk Worker AMI release 1.1.4

This directory is the Agent-owned, operator-run EC2 Image Builder release
surface for the persistent SSH Worker. It does not change the server host AMI,
run from the deployer, or expose AMI choices to clients.

The two images are Ubuntu 24.04 x86_64 images. CPU starts from Canonical's
public SSM parameter. GPU starts from AWS's public Ubuntu 24.04 Base OSS NVIDIA
Driver GPU DLAMI parameter and retains its NVIDIA driver, CUDA, NVIDIA Container
Toolkit, containerd, nerdctl, and SOCI installation. The renderer resolves the
exact parent AMI, root device, and backing snapshot size before creating a
recipe. Its block mapping deliberately omits `volumeSize`: Image Builder must
inherit the parent snapshot minimum while keeping the public image root volume
unencrypted on gp3. The generated recipe records the observed minimum and fails if a generated
mapping ever supplies a smaller size.

## Release contents

- `release.json`: frozen image, Pi, uv, parent, plugin, and SSM contract.
- `components/install.yaml.in`: build component for the common toolchain,
  checksummed Pi and uv/uvx binaries, static-web/PDF tooling, state root,
  manifest, and credential/cache cleanup.
- `components/plugin.yaml.in`: separate checksummed reviewed Pi plugin catalog;
  the split keeps every inline Image Builder component below 16,000 characters.
- `components/test.yaml.in`: Image Builder test component, including a real
  reboot between persistence assertions.
- `scripts/render-release.sh`: offline renderer and live read-only parent
  resolver. It writes complete AWS CLI JSON payloads and a checksum manifest.
- `scripts/manage-release.sh`: identity-fenced create/build/publish/cleanup
  entrypoint. AWS mutations require both `--execute` and `--confirm-costs`.
- `tests/static-test.sh`: offline contract tests with a fake AWS CLI.

The only reviewed default Pi plugin is the reduced Dirextalk subagent extension
already vendored by the SSH Worker. It is MIT-licensed and pinned to upstream
commit `53fa77ccd8a279eb87e92294ef3687b03ff80112`; the renderer verifies both
vendored file digests. Its reduced surface remains derived from Pi `v0.84.1`
and has been compared with the upstream `v0.84.4` example; the intervening
changes concern project-agent discovery and inherited model settings that this
server-owned variant does not use. The image installs it into a catalog, not a
user's Pi configuration. A task enables it by copying the catalog entry and agent file
into that task's `PI_CODING_AGENT_DIR`, or disables it by omitting that copy.
No token or configuration is baked into the image. High-privilege and
task-specific marketplace plugins are intentionally absent.

| Plugin | Decision | Maintenance, permission, offline, and size assessment |
| --- | --- | --- |
| reduced `dirextalk-subagent` | default catalog entry | Existing server-vendored source; Pi `v0.84.1` provenance, validated with Pi `v0.84.4`; MIT; 8,269 bytes; no added dependency; works offline; only server-owned agents are discovered. |
| `pi-review` 1.2.1 | reject | Community session/slash-command workflow is not general Worker runtime value. |
| `pi-subagents` 0.63.0 | reject | Duplicates the reviewed extension, is about 5 MB, and has broader behavior. |
| `cc-safety-net` 2.3.1 | opt-in only after audit | Its configuration can fail open; it is not safe as an image-wide default. |
| `pi-lens` 4.1.3 | reject | About 24 MB with native/download lifecycle hooks, weakening offline reproducibility. |
| `rpiv-todo` 2.9.0 | reject | TUI/session behavior duplicates task state and is not a general prerequisite. |

Any future addition must pin the package version, tar SHA-256, registry
integrity, upstream commit or SLSA provenance, and the complete mirrored
dependency closure. Install lifecycle scripts remain disabled unless separately
audited. Runtime plugin installation and baked credentials are prohibited.

The common image also includes pinned `uv`/`uvx`, plus Ubuntu-packaged
`httpx`, Beautiful Soup, lxml, html2text, w3m and xmllint for static or
server-rendered web content. PDF authoring and inspection use Pandoc,
WeasyPrint, Poppler (`pdfinfo`/`pdftotext`) and qpdf. These cover deterministic
non-browser extraction and PDF workflows without downloading a Python
environment at task start. Chromium/Playwright is not a default because its
large browser payload and rapid security-update cadence require a separately
owned release track.

Pi Skills execute with the Worker's full permissions. Therefore no third-party
Skill is silently enabled image-wide: the runner continues to disable discovery,
and only checksum-pinned, source-reviewed, task-selected Skills may later enter
the catalog. A proposed Skill must document its tools, network and filesystem
effects, license, upstream revision and offline behavior; instructions that only
restate the preinstalled CLI help are not accepted.

## Render without AWS access

This produces auditable placeholders, payload shapes, checksums, and manual
commands without contacting AWS:

```bash
deploy/cloud-worker/scripts/render-release.sh \
  --offline --account-id 123456789012 --region us-east-1 \
  --flavor cpu --distribution-regions us-east-1,us-west-2 \
  --instance-profile DirextalkWorkerImageBuilder \
  --subnet-id subnet-REPLACE --security-group-id sg-REPLACE \
  --output-dir /tmp/dirextalk-worker-ami-cpu
```

Review `manual-commands.sh`, replace every `REPLACE_*` value, rerun the live
read-only render, and compare `SHA256SUMS`. The generated files contain no
credentials. The output directory is disposable and must not be committed.

## Live read-only render and authorized execution

Use one explicit AWS profile and region. The live renderer calls STS, SSM,
EC2 image/snapshot discovery, and instance-type offering discovery only:

```bash
AWS_PROFILE=release deploy/cloud-worker/scripts/render-release.sh \
  --account-id 123456789012 --region us-east-1 --flavor cpu \
  --distribution-regions us-east-1,us-west-2 \
  --instance-profile DirextalkWorkerImageBuilder \
  --subnet-id subnet-0123456789abcdef0 \
  --security-group-id sg-0123456789abcdef0 \
  --output-dir /tmp/dirextalk-worker-ami-cpu
```

The operator must review the resolved account, source Region, parent AMI owner
and snapshot minimum, build instance type, explicit distribution Region
allowlist, generated payloads,
public unencrypted snapshot policy, and cost impact. Creation and build are
separate explicit actions:

```bash
AWS_PROFILE=release deploy/cloud-worker/scripts/manage-release.sh create \
  --bundle /tmp/dirextalk-worker-ami-cpu --execute --confirm-costs
AWS_PROFILE=release deploy/cloud-worker/scripts/manage-release.sh build \
  --bundle /tmp/dirextalk-worker-ami-cpu --execute --confirm-costs
```

`build` starts one on-demand pipeline execution. Infrastructure configuration
uses the selected single build type, no key pair, IMDSv2, termination on
failure, and the supplied private subnet/security group. The security group is
required to have zero ingress, and the subnet must disable automatic public
IPv4 assignment. Private SSM, Image Builder, package, GitHub, and
container-registry connectivity is an operator-owned prerequisite; the scripts
never add routes or broaden network rules.

Every successful create is appended immediately to
`creation-journal.ndjson`; this preserves exact ARNs if a later create step
fails. Stop on partial failure and use those exact ARNs for authorized manual
cleanup rather than rediscovering resources by mutable name.

After Image Builder reports success, independently inspect its tests and exact
output AMIs. Image Builder writes the candidate parameter in each allowlisted
Region as part of distribution. Promotion requires every candidate to match
that Region's exact output AMI, verifies its owner, state, tags, public launch
permission, and public unencrypted root snapshot, then advances `current` to
`previous` and candidate to `current` with
Region-local read-back after every write:

```bash
AWS_PROFILE=release deploy/cloud-worker/scripts/manage-release.sh publish \
  --bundle /tmp/dirextalk-worker-ami-cpu --image-build-version-arn \
  arn:aws:imagebuilder:us-east-1:123456789012:image/dirextalk-worker-cpu-1-1-4/1.1.4/1 \
  --execute --confirm-costs
```

These owner-account pointers are release bookkeeping, not a customer-account
discovery API. The application reads its embedded public release catalog,
then verifies the exact AMI ID, trusted publisher, public permission, and live
root mapping through EC2. Update the catalog only after successful promotion.
The `/imagebuilder/` prefix permits distribution through the AWS-managed
Image Builder service-linked role without a custom SSM write policy.
Rollback validates `current` and `previous` in every allowlisted Region before
changing any pointer, then swaps them Region-locally. It writes the exact old
values to `rollback-journal.ndjson` before each Region mutation so an operator
can recover a partially completed cross-Region rollback without rediscovery:

```bash
AWS_PROFILE=release deploy/cloud-worker/scripts/manage-release.sh rollback \
  --bundle /tmp/dirextalk-worker-ami-cpu --execute --confirm-costs
```

Cleanup protects the exact current and previous AMIs, deregisters older matching
release images, then deletes only snapshots proven to belong to those exact
images and account:

```bash
AWS_PROFILE=release deploy/cloud-worker/scripts/manage-release.sh cleanup \
  --bundle /tmp/dirextalk-worker-ami-cpu --execute --confirm-costs
```

`--distribution-regions` is a required explicit safety boundary when more than
the source Region is desired. The renderer validates canonical Region names,
sorts and deduplicates them, requires the source Region, records the final list
in `render.json`, and never infers an additional Region. Image Builder creates
an unencrypted public AMI in each listed Region and writes the owner-account
candidate SSM parameter there. Before promotion, independently verify the exact
output snapshot and explicitly grant public snapshot permission if distribution
has not done so. AMI and snapshot block-public-access settings must permit the
requested sharing; restore any temporarily relaxed account setting after
publication without revoking existing release permissions. Any AWS account can
launch the AMI in that Region; owner-account SSM pointers remain operator-only
promotion and retention state. Publish and cleanup revalidate
the same STS account and explicit Region before every regional read or write.
Retain only current plus one previous AMI per flavor in every listed Region.

The application's supported placement Regions and regional-copy acceptance
requirements are defined in [the release contract](../../docs/release-contract.md).
For a new Image Builder release, distribute to
`ap-northeast-1,eu-west-3,us-west-1`. Expanding an unchanged, already-qualified
release instead uses ordinary EC2 AMI copies, preserving exact source-build
provenance without reinstalling the runtime or requesting a paid completion
window. Keep copy receipts and independent regional acceptance with the release
evidence. Such copies are not additional outputs of the original Image Builder
build ARN: do not present them to `manage-release.sh publish` as if they were.
Create the new Regions' owner-only candidate/current pointers without
overwriting existing values, then update the embedded catalog after acceptance.

## Image tests and operational evidence

The test component validates every required tool and captures its version; Pi
must print `0.84.4`, while uv and uvx must print `0.12.9`. It creates an offline
uv virtual environment, exercises httpx/Beautiful Soup/lxml against an in-memory
response, and converts Markdown through HTML to PDF before checking its
structure and extracted text with qpdf and Poppler. It also creates a local bare
Git repository, clones it without a network, edits code, and runs Python and
Node tests. GPU images additionally
require working NVIDIA/CUDA tooling, NVIDIA Container Toolkit, containerd,
nerdctl, and a loaded SOCI snapshotter plugin. The post-snapshot GPU test also
runs `nvidia-smi` inside the exact `nvidia/cuda:12.8.1-base-ubuntu24.04` amd64
container digest frozen in `release.json`. It writes a nonce under
`/var/lib/dirextalk-worker`, performs an Image Builder-managed reboot, and
requires the same inode content after boot. Finally it fails on credential,
shell-history, nonempty or symlinked authorized-key, package-cache, or build-key
residue. Empty boot-created authorized-key files and normal operating-system
temporary directories are not build residue. The offline regression gate runs
the actual test scripts against success, negative, and infrastructure-failure
fixtures, including large producer output under shell pipefail.

Successful Image Builder component/test execution is necessary but not enough
to publish: `publish` also requires the exact build-version ARN to be AVAILABLE,
the recipe ARN to match the rendered recipe, one output AMI in the same account
and Region, public AMI and snapshot permissions, an unencrypted root snapshot,
and all five common immutable output tags:

```text
DirextalkWorkerImageSchema=1
DirextalkWorkerImageFlavor=cpu|gpu
DirextalkWorkerImageVersion=1.1.4
DirextalkPiVersion=0.84.4
DirextalkImageTested=true
```

GPU adds `DirextalkGPUSupportedFamilies`, parsed strictly from the exact live
parent Description clause beginning `Supported EC2 instances:` and ending
before `. Release notes:`. The original Description and normalized lowercase
comma list are retained in `render.json`; publication requires the output tag
to equal that list.

If IAM, quota, private connectivity, or distribution policy blocks execution,
stop. Keep the rendered bundle and `SHA256SUMS` as the handoff; do not bypass
the denied control or substitute a different account, Region, parent, instance
type, or public network.
