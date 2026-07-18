# Dirextalk Knowledge Adapter

This Agent release subtree contains the retained single-host Knowledge runtime used by a
Dirextalk Managed deployment:

- a Python 3.12 `intfloat/multilingual-e5-small` adapter reachable only through a group-authorized
  Unix socket;
- a narrow HTTPS client for a loopback-only Qdrant v1.18.3 process;
- a static Go installer with the exact `install-v1`, `restart-v1`,
  `semantic-probe-v1`, `stop-v1`, `backup-v1`, `restore-v1`, `upgrade-v1`,
  `rollback-v1`, and `destroy-v1` commands;
- locked artifact provenance, an offline Python dependency bundle workflow,
  and a real-model release-golden hook.

The runtime has no general URL, path, header, model, backend, or command input.
The only adapter network destination is `https://127.0.0.1:6333`, authenticated
by a fixed API-key file and a locally generated CA. Qdrant persists on the
Managed encrypted volume. The adapter keeps its idempotency ledger and a
secure-delete attachment staging database there; committed segment text and
vectors live in Qdrant, and staged bytes are cleared after durable commit.

## Runtime layout

| Purpose | Fixed path |
| --- | --- |
| Signed installer inputs | `/usr/local/share/dirextalk-worker/artifacts` |
| Qdrant API-key SecretSlot | `/etc/dirextalk-service-secrets/qdrant-api-key` (`root:root`, `0400`) |
| Installed release | `/opt/dirextalk/knowledge/releases/v1` |
| Persistent data | `/var/lib/dirextalk-knowledge` |
| Installed Qdrant API key | `/var/lib/dirextalk-knowledge/secrets/qdrant-api-key` |
| Qdrant CA | `/var/lib/dirextalk-knowledge/tls/ca.crt` |
| Adapter socket | `/run/dirextalk-knowledge/adapter.sock` |

On Linux, install/upgrade preflight and managed-file creation open the fixed
root and each parent descriptor-relative with `openat2`, `RESOLVE_BENEATH`,
`RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `O_NOFOLLOW`. Required
inputs and managed targets must remain the expected regular file or directory
with exact ownership and mode. Restore/rollback independently accept only
canonical backup members beneath the fixed adapter and Qdrant roots, reject
links and unsupported entries, and open copied files no-follow. Cleanup accepts
only compiled absolute targets, refuses `/` and the resolved installer root,
and removes a link itself rather than following it outside the target. No
caller can supply a replacement path.

Production starts the adapter as:

```text
/usr/bin/python3.12 -I -S -B /opt/dirextalk/knowledge/current/adapter/main.py
```

`main.py` inserts only the fixed release package and sealed `pydeps` paths.
The application itself imports no third-party package other than the exact
locked NumPy, Tokenizers, and ONNX Runtime releases.

## Protocol

Requests are one 4-byte big-endian length-prefixed JSON object per connection,
bounded to 8,388,608 bytes. Unknown fields are rejected. Owner IDs are bounded
opaque strings; binding/source/upload/chunk/revision/operation identifiers are
canonical, non-nil RFC 4122 UUID strings. Mutations bind one `operation_id`,
`idempotency_key`, operation name, revision, and canonical request digest; an
idempotency-key replay with any changed binding is rejected.

The closed relay operation set is:

- `stage_chunk`
- `commit_attachment`
- `store_memory`
- `delete`
- `search`
- `status`

There is no operation for fetching a URL, opening a path, changing a header,
selecting a model/backend, or executing a command. Content and query values are
never logged. Every operation carries exact owner and binding fences; attachment
operations additionally fence source, upload, revision, chunk identity/index,
size, and SHA-256. `status` carries the optional persistence challenge. See
`docs/protocol-v1.md` and `docs/protocol-v1-vectors.json` for independently
implementable request shapes and fixed relay vectors.

## Offline deterministic release

`dependencies/python.lock.json` pins the three CPython 3.12 x86_64 wheels by
filename, size, and SHA-256. Place those exact wheels in a temporary directory
and run:

```text
python3.12 -I -S -B scripts/build_adapter_bundle.py WHEEL_DIRECTORY OUTPUT_TAR
```

The builder verifies every wheel before safe extraction and emits a
deterministic bundle containing an SPDX 2.3 JSON SBOM. It accepts only reviewed
Python source members. Wheels, the 470 MB model, and release archives are
deliberately ignored and must not be committed.

Build the model bundle only from the five files pinned in
`provenance/model-files-v1.json` (the same protected input directory may also
contain the separately pinned Qdrant archive):

```text
python3.12 -I -S -B scripts/build_model_bundle.py UPSTREAM_DIRECTORY multilingual-e5-small.tar.gz
```

Build the static Linux/amd64 installer without VCS or build-ID variability:

```text
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -buildvcs=false -trimpath -ldflags='-buildid=' \
  -o dirextalk-knowledge-installer ../../cmd/dirextalk-knowledge-installer
```

Then bind the sealed adapter into canonical provenance and bind the five
deployable artifacts into the small public research manifest:

```text
python3.12 -I -S -B scripts/build_provenance.py \
  dirextalk-knowledge-adapter.tar.gz provenance-v1.json
python3.12 -I -S -B scripts/build_release_manifest.py \
  dirextalk-knowledge-installer \
  qdrant-x86_64-unknown-linux-musl.tar.gz \
  multilingual-e5-small.tar.gz \
  dirextalk-knowledge-adapter.tar.gz \
  provenance-v1.json \
  dirextalk-knowledge-release.v1.json
```

Run each builder and the Go build twice into new paths and compare complete
SHA-256 digests before publication. `provenance/release-v1.json` records the
current generated provenance; `internal/knowledgeprofile/release.v1.json`
contains the exact small release manifest consumed by planning. The protected
release directory is the publish input and must remain outside Git.

The pinned upstream coordinates are the Qdrant v1.18.3 release asset
`https://github.com/qdrant/qdrant/releases/download/v1.18.3/qdrant-x86_64-unknown-linux-musl.tar.gz`
and Hugging Face repository `intfloat/multilingual-e5-small` at immutable
revision `0e60b8d9d2166d80387f86e3b48ec9ced55f4d15`. The 470 MB ONNX and 17 MB
tokenizer evidence belongs to that multilingual repository—not
`intfloat/e5-small-v2`—and tests reject that mislabeling.

## Recipe and Knowledge binding

The first-party planning profile fetches only the 2,429-byte immutable release
manifest, once per distinct `?artifact=<id>` evidence URL. It never asks the
research tool to download Qdrant, the model, the adapter, provenance, or the
installer. Each Recipe source keeps that small research URL separate from its
queryless `artifact_url`; cloud execution resolves and verifies the latter.

The retained experimental Recipe installs only the five catalog artifacts,
mounts an encryption-required persistent volume at
`/var/lib/dirextalk-knowledge`, delivers the API key through the fixed SecretSlot,
and runs `install-v1` followed by `semantic-probe-v1`. The semantic probe proves
the exact model/provider, Qdrant collection health, retained write, filtered
search, and persistence read-back. Managed preparation later selects the
signed `restart-v1` command. The same closed Recipe also declares fixed
`stop-v1`, `backup-v1`, `restore-v1`, `upgrade-v1`, `rollback-v1`, and
`destroy-v1` lifecycle commands; none accepts caller-selected paths, arguments,
or environment. After Managed acceptance, the Agent exposes these actions only
through deterministic owner/device approval bound to the exact deployment,
Managed service, Knowledge binding, Recipe, execution bundle, installed
manifest, action, and current revisions. The Worker/root-helper capability,
journal, and receipt repeat that closed action. A failed destroy is persisted
as `destroy_blocked` and requires a fresh approval before remediation.

After a retained deployment passes device-approved Managed acceptance, the
Agent creates the Knowledge binding with the exact Deployment UUID, Managed
Service UUID, accepted Recipe digest, and
`local-multilingual-e5-small-v1`. Those immutable facts are the only binding
accepted by the Agent Knowledge service; neither an endpoint nor an API key is
accepted through the Knowledge API.

The public authenticated gRPC `KnowledgeService.PutKnowledgeConfig` method
requires the `knowledge.write` scope and is update-only. It rejects
`expected_revision = 0`, unknown bindings, owner drift, and cross-binding
selectors. Revision-one creation is reserved to the internal Managed-acceptance
binder, which derives a new binding UUID from the accepted retained Recipe.
Subsequent public writes must repeat the same Deployment UUID, Managed Service
UUID, Recipe digest, and embedding profile with the current revision; only
`enabled` may change. The PostgreSQL mutation is idempotent and rejects identity
replacement. It also rejects updates while an owner/device-approved lifecycle
operation holds the exact binding's durable execution reservation.

Managed acceptance succeeds only after the exact revision-one Knowledge config
exists or a retry reads back the same immutable binding. A lost response is
recovered by read-back; an existing conflicting binding fails closed. Other
profiles are not given a Knowledge config by this coordinator.

`backup-v1` writes a verified local snapshot of Qdrant and adapter data on the
encrypted retained volume, explicitly excluding secret and TLS paths. A
fsynced rotation journal covers every durable rename phase and preserves the
last-known-good backup across interruption.
`restore-v1` uses a durable swap journal and retains the previous live state
until restart and the semantic probe succeed. `upgrade-v1` repairs this exact
immutable v1 release tree—including the binary, model, and adapter—after a
backup; `rollback-v1` restores the durable data backup. Every public lifecycle
command holds one nonblocking lock. Destroy validates the exact installed
systemd units and inactive service-manager read-back before deleting any fixed
Knowledge-owned root. These first-release operations do not select arbitrary
binary versions, and local backup does not replace the independent AWS snapshot
recovery layer.

Migration 41 coordinates the Qdrant/adapter state with PostgreSQL without
copying payloads into the control plane. The binding has a positive
`data_epoch` and optional verified backend-generation digest. When `backup-v1`
or `upgrade-v1` crosses the execution fence, the Agent snapshots the exact
normalized source/upload/chunk catalog and its canonical digest. Successful
completion retains that catalog against the Worker-observed generation.
`restore-v1` and `rollback-v1` fence the newest retained generation before the
root command and require the same generation in its successful receipt.

The snapshot rows contain only IDs, status, media type/title, byte counts,
content and chunk digests, backend point IDs, ordinals/offsets, revisions, and
timestamps. PostgreSQL stores no document/query content, staged chunk bytes,
vectors, API keys, TLS private material, or runtime database. While a lifecycle
reservation is active, both new Knowledge mutations and exact idempotent
mutation replays fail closed. Restore/rollback completion revalidates the
catalog digest, replaces the live metadata catalog, increments the data epoch,
rebases receiving uploads to the new binding revision, CASes binding and
Managed-service state, records completion, and releases the reservation in one
PostgreSQL transaction. Any mismatch rolls back that complete reconciliation.

Once restore/rollback/upgrade crosses the execution fence, an unsigned Worker
failure remains recovery-pending and cannot release the reservation. Root must
first sign an independently observed generation: the fenced target completes
normally, while a recovered pre-swap generation closes restore/rollback as
failed with `recovered_original_generation`, keeps the service active, and
records that observed generation atomically. If the Worker lease changes after
the root journal already holds a terminal recovery receipt, the helper
re-observes the same generation and re-signs the receipt at the current lease
epoch without invoking the installer again.

## Verification lanes

`make verify` runs fake-runtime Python boundary tests, Go installer tests, a
static build, and Python compilation. It does not download or load the model.

`make release-golden` is an explicit slow/release lane. It requires the already
installed pinned model at the fixed production paths and a separately reviewed
golden vector file at
`/usr/local/share/dirextalk-worker/artifacts/release-golden-v1.json`. Missing artifacts
fail closed; the hook never downloads or records a replacement golden.

Real deployment still requires an immutable committed/tagged Agent revision,
publication and independent CloudFront verification receipts for all five
runtime artifacts plus the release manifest, a digest-pinned Worker AMI that
contains this installer path, and an encrypted Qdrant API-key bootstrap secret.
Local deterministic generation alone does not claim those external facts.
