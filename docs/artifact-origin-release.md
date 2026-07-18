# Immutable first-party artifact origin

`dirextalk-artifact-originctl` owns the fixed first-party origin used by the
Knowledge Worker installer. It is separate from deployment-scoped Foundation
artifact storage: it publishes reviewed public binaries and model files at
stable SHA-256 paths under `https://artifacts.y1.dirextalk.ai`.

This is retained release infrastructure and creates billable AWS resources.
The fixed storage Region is Osaka (`ap-northeast-3`); the ACM certificate and
CloudFront stack are in `us-east-1`, as required by CloudFront. The templates
create a versioned private S3 bucket encrypted by a rotating KMS key, one
CloudFront distribution with Origin Access Control, the DNS-validated ACM
certificate, and Route53 A/AAAA aliases. They do not enable S3 Object Lock.
The bucket and KMS key use `Retain`, so deleting a stack does not delete the
published objects or key.

## Security and transport contract

- The S3 bucket blocks public access and insecure transport. Every publisher
  write must name the exact KMS key and use an S3 bucket key.
- A reversible bucket-policy deny blocks object and object-version deletion,
  preventing a delete marker from reopening a previously used SHA path. This
  is deliberately not S3 Object Lock or compliance retention.
- CloudFront can read objects only after the storage stack is updated with the
  exact distribution ARN. The same exact ARN fences KMS decrypt permission.
- The distribution allows only `GET` and `HEAD`, uses HTTPS-only viewers,
  forwards no viewer cookies, headers, or query strings, and disables compression.
  Missing-object error responses are not cached.
- Public keys are derived, never supplied:
  `sha256/<64 lowercase hex digest>/<reviewed filename>`. Publication uses
  an exact version-history read plus `If-None-Match: *`; an existing version,
  delete marker, or current key is never overwritten or adopted by the write
  command.
- After a successful conditional write, the tool independently checks S3
  version ID, metadata, length, checksum, encryption, and KMS key, then issues
  a queryless, no-redirect CloudFront `GET` and verifies HTTP 200, exact
  `Content-Length`, identity encoding, and the complete SHA-256 digest.
- AWS credentials come only from the Go SDK default credential chain. No
  credential, session token, caller ARN, local path, or provider error is
  written to receipts or stdout.

## Recoverable two-Region preparation

Obtain the existing Route53 hosted-zone ID for `dirextalk.ai`, choose a new
protected receipt path, and run:

```text
dirextalk-artifact-originctl prepare \
  --account-id <12-digit-account-id> \
  --region ap-northeast-3 \
  --domain artifacts.y1.dirextalk.ai \
  --hosted-zone-id <route53-zone-id> \
  --receipt-output <new-protected-origin-receipt.json>
```

The command performs three fail-closed phases:

1. Create storage without any CloudFront grant, or read back an existing exact
   stack with the fixed ownership tags.
2. Create/update and read back the `us-east-1` edge stack bound to that exact
   bucket and alias.
3. Update/read back the Osaka storage stack with the resulting exact
   distribution ARN.

Every stack request token is derived from the fixed stack name, embedded
template, sorted parameters, and sorted tags. A rerun resumes from the current
stable stack state. It never clears an existing distribution binding while
reconciling. Create/update rollback or an ownership/tag/ARN/output mismatch
fails closed for operator review; the tool has no stack, bucket, object, key,
certificate, distribution, or DNS delete operation.

The receipt is created with `0600` and `O_EXCL`. Preserve it as release
evidence. A later rerun must use a new output path; successful reconciliation
does not overwrite earlier evidence.

## Pinned Knowledge catalog

The binary embeds the reviewed catalog from
`deploy/awsartifactorigin/knowledge-artifacts.v1.json`. It does not download
upstream files. Obtain each file independently from its catalog source, then
publish only after its local size and SHA-256 match:

| Artifact ID | Reviewed revision | Bytes | SHA-256 |
|---|---:|---:|---|
| `qdrant-linux-amd64` | signed `v1.18.3`, commit `db8fa43fcb6aedec1e739487e17a99731b74590a` | 30,745,357 | `b4faedcdf8c9577bf1c8f2ab9b454636b87e056c116c99d49bd4f9fb2e634285` |
| `multilingual-e5-small-onnx` | `0e60b8d9d2166d80387f86e3b48ec9ced55f4d15` | 470,268,510 | `ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665` |
| `multilingual-e5-small-tokenizer` | same E5 revision | 17,082,730 | `0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39` |
| `multilingual-e5-small-config` | same E5 revision | 655 | `69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959` |
| `multilingual-e5-small-tokenizer-config` | same E5 revision | 443 | `a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b` |
| `multilingual-e5-small-special-tokens` | same E5 revision | 167 | `d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7` |

The first six rows are independently retained upstream inputs. The Knowledge
Recipe installs the following deterministic derived release set instead of
asking the planning research tool to fetch those large bytes:

| Artifact ID | Local release file | Bytes | SHA-256 |
|---|---:|---:|---|
| `knowledge-installer-linux-amd64` | `derived/dirextalk-knowledge-installer` | 7,376,597 | `ddfd0578bec82f1051ded9c49f90ce552b6284b4b0a30f09c12a663d79feae86` |
| `multilingual-e5-small-bundle` | `derived/multilingual-e5-small.tar.gz` | 299,428,899 | `ccf5b7e718151700b91a8fc632628a75a5756ddc18452e888e6f8950c0a5d198` |
| `knowledge-adapter-bundle` | `derived/dirextalk-knowledge-adapter.tar.gz` | 43,111,084 | `61ef32ad69a4fed9fbf7444d34358f433dae9cbbb8ff47bc34b6871bad03eeb5` |
| `knowledge-provenance-v1` | `derived/provenance-v1.json` | 1,090 | `58e3b6217b30cecb46908ccf87900fbbed331acb825d8380ad0fab43a32072c2` |
| `knowledge-release-manifest-v1` | `derived/dirextalk-knowledge-release.v1.json` | 2,429 | `78a75a2974a6282f90cb749b373c4c48959ec9c348d2e2f4f15ea0a6abf5e4e3` |

Qdrant itself remains the catalog's pinned upstream release archive and is the
fifth runtime artifact. Build the derived rows with the fixed offline commands
in `deploy/knowledge-adapter/README.md`, build every output twice, and require
complete digest equality before publishing. Generated archives, binaries, and
operator receipts remain in a protected release directory outside Git.

Publish one item at a time:

```text
dirextalk-artifact-originctl publish \
  --account-id <12-digit-account-id> \
  --region ap-northeast-3 \
  --origin-receipt <verified-origin-receipt.json> \
  --artifact-id <catalog-artifact-id> \
  --file <reviewed-local-file> \
  --receipt-output <new-protected-artifact-receipt.json>
```

CloudFront verification reads the complete object, including the 470 MB ONNX
file, and therefore incurs request/data-transfer charges. A successful result
contains the exact queryless public URL, S3 version ID, digest, and size.

For a runnable Knowledge release, publish and retain a new `0600` receipt for
the installer, Qdrant archive, model bundle, adapter bundle, and provenance
first. Publish the small release manifest last, after all five exact public
paths have verified. The retained planning profile uses five distinct
`?artifact=<id>` research URLs that all resolve to that same 2,429-byte
manifest; query strings are not forwarded to the origin. `artifact_url`
remains a separate queryless SHA path, so `official_source_fetch` never reads a
30-299 MB runtime binary.

If the conditional S3 write succeeded but the process lost its response, do
not rerun `publish`: it will report an immutable conflict. Resolve the outcome
without another write:

```text
dirextalk-artifact-originctl verify \
  --account-id <12-digit-account-id> \
  --region ap-northeast-3 \
  --origin-receipt <verified-origin-receipt.json> \
  --artifact-id <catalog-artifact-id> \
  --file <reviewed-local-file> \
  --receipt-output <new-protected-artifact-receipt.json>
```

`verify` performs only the S3 and CloudFront read-back. It never creates a new
version. Keep every publication receipt; Knowledge Recipes and installers must
use only those exact queryless artifact SHA paths and must continue rejecting
artifact redirects, query-bearing artifact URLs, length drift, and digest
drift. The query-bearing small-manifest research URLs are evidence only and are
never passed to the installer resolver.
