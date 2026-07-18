# Worker AMI Release Operator

`dirextalk-worker-ami` is a closed, operator-only AWS SDK tool. It is not an
Agent RPC, Eino tool, Skill surface, arbitrary EC2 client, or credential
transport. Run it only from the committed release checkout and an authorized
operator context using the standard AWS SDK credential chain.

## Prepare a build-request v2

Preparation is read-only. It confirms the exact STS account and Region,
derives the deterministic Foundation stack from `agent_instance_id`, reads
back the stable stack and release outputs, resolves the isolated VPC/subnet/
security-group/route-table facts and regional S3 prefix list, and selects the
newest unambiguous public Canonical Ubuntu 24.04 LTS amd64 EBS/HVM AMI owned by
AWS account `099720109477`. It then re-verifies the release manifest and
Worker rootfs bytes and writes a new `0600` build request without replacing an
existing file.

Canonical's scheduled future `DeprecationTime` does not make an otherwise
current image ineligible; a malformed, current, or past deprecation time does.
The image must expose exactly one `gp3` root EBS mapping with a valid snapshot,
positive size, and delete-on-termination. Additional mappings are accepted only
when they are non-EBS `ephemeralN` virtual devices. The public source snapshot
may be unencrypted; `RunInstances` still replaces the root mapping with the
required encrypted, delete-on-termination `gp3` builder volume.

```text
dirextalk-worker-ami prepare \
  --account-id <12-digit-account-id> \
  --region <aws-region> \
  --agent-instance-id <canonical-agent-uuid> \
  --release-manifest <protected-release-manifest-path> \
  --rootfs-archive <protected-worker-rootfs-path> \
  --output <new-protected-build-request-v2-path>
```

The v2 document contains no CIDR, public-Internet test switch, credential,
profile, presigned URL, or arbitrary endpoint/service input. Build re-reads
the Foundation outputs, base AMI, route table, S3 prefix list, bucket
versioning/encryption, release manifest, and rootfs before mutation, so a
replaced file or changed provider fact fails closed.

## Build, verify, and destroy

```text
dirextalk-worker-ami build \
  --request <protected-build-request-v2-path> \
  --output <new-publication-manifest-path>

dirextalk-worker-ami verify \
  --manifest <publication-manifest-path>

dirextalk-worker-ami destroy \
  --request <strict-destroy-request-v2-path>
```

Build writes protected recovery files beside the publication output before it
can lose the corresponding provider facts:

- `.build-intent` binds the raw and normalized request digests;
- `.builder-reachability` binds the exact S3 Gateway endpoint and TCP/443
  security-group-rule IDs; and
- `.builder-cleanup` binds the exact builder, root EBS, and ENI IDs.

The builder has no public address and no IAM instance profile. Its only
temporary route is the tagged S3 Gateway endpoint on the exact Foundation
route table, and its only usable egress is TCP/443 to the exact AWS-managed
regional S3 prefix list. Cleanup always terminates and reads back the builder,
EBS, and ENI first, then revokes the rule, deletes the endpoint, and proves the
rule, endpoint, and S3 route absent. A response-lost operation is reconciled by
deterministic scope and exact tags; multiple matches, access denial, scope
drift, or incomplete evidence never selects or deletes a guessed resource.

Build-request v1 is retained solely for an explicit compatibility operation:

```text
dirextalk-worker-ami build --allow-legacy-v1 \
  --request <legacy-build-request-v1-path> \
  --output <new-publication-manifest-path>
```

The compatibility switch does not convert v1 into the v2 private-network
contract. Do not use it for real release evidence.
