# Managed ECR Release Verification

The fixed private repositories `dirextalk-agent`,
`dirextalk-cloud-worker`, and `dirextalk-aws-reaper` are retained Managed
release infrastructure. Publisher-session cleanup, a failed publication, and
Worker AMI cleanup never remove a repository or image.

## Repository contract

`dirextalk-ecrctl prepare` preserves its v1 receipt shape and creates only the
three fixed repositories. Every newly created repository must have immutable
tags, scan-on-push, ECR AES-256 encryption, its exact regional/account ARN and
URI, and exactly these ownership tags:

```text
managed_by=dirextalk-agent
component=release-registry
artifact=agent|worker|reaper
retention=managed_retained
```

An existing repository with a missing, changed, duplicate, or extra tag fails
closed. In particular, a repository created under the earlier three-tag
contract is not adopted or modified automatically. This CLI has no reconcile
or migration mutation. Migrating such a repository requires a separate,
reviewed operator change that proves the intended account, Region, ARN,
configuration, and prior ownership before establishing the exact four-tag
contract; rerun preparation and verification afterward.

## Read-only managed receipt

After publishing a complete release manifest, independently verify the retained
repositories and image bindings:

```text
dirextalk-ecrctl verify-managed \
  --region <aws-region> \
  --account-id <12-digit-account-id> \
  --release-manifest <release-manifest.json> \
  --receipt-output <new-protected-managed-receipt.json>
```

The command uses only the AWS SDK default credential chain. It first confirms
the exact STS account and configured Region, then validates each fixed
repository's ARN, URI, configuration, and exact ownership tags. The supplied
strict release manifest must bind all three images to that exact ECR registry,
fixed repository name, immutable release tag, and digest. A narrow image
read-back then proves each tag resolves to the manifest digest.

Verification has no repository/image create, tag-mutation,
authorization-token, publication, or delete provider operation. It never invokes
`BatchDeleteImage` or `DeleteRepository`. Success writes a new `0600` receipt
without overwriting prior evidence and emits the same typed, de-secreted JSON
to stdout. The receipt contains no caller ARN, provider error, credential
source, authorization token, Docker session, or mutable repository input.
