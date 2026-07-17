# Agent-only Image Release

`dirextalk-agent-imagectl` is a closed operator tool for the single
`dirextalk-agent` OCI image. It is intentionally separate from
`dirextalk-ecrctl`/`dirextalk-releasectl`, whose bundle workflow prepares or
publishes the Agent, Worker, Reaper, Worker rootfs, and later AMI inputs.

This tool is release preparation only. It is not P4, does not create or attest
a Worker AMI, does not publish Worker/Reaper/rootfs artifacts, and does not
claim a managed deployment.

## Preconditions

- Run from a clean Agent repository root on the exact Git revision represented
  by the prerelease tag.
- Use a supported Docker Buildx installation capable of `linux/amd64` (or the
  requested supported architecture) image builds.
- Supply the intended AWS Region and account ID explicitly. The Go AWS SDK
  default credential chain performs the identity check; the tool accepts no
  access key, secret key, token, profile path, or AWS CLI input.
- Use a protected local path for the one-time ECR Docker session descriptor.
  It is not a host-runtime credential and must be consumed or cleaned.

## Closed flow

```text
dirextalk-agent-imagectl prepare \
  --region <aws-region> \
  --account-id <12-digit-account-id> \
  --session-output <protected-local-session-path>

dirextalk-agent-imagectl publish \
  --release-tag <immutable-prerelease-bound-to-git-revision> \
  --architecture amd64 \
  --ecr-session <protected-local-session-path>
```

`prepare` can create and then strictly read back only the fixed private
`dirextalk-agent` ECR repository. It requires immutable tags, scan-on-push,
AES-256 ECR encryption, and exact ownership tags. Its stdout is a safe
preparation receipt; the short-lived Docker authorization remains only in the
protected session directory.

`publish` derives the repository from the authenticated registry host and has
no repository, Worker, Reaper, rootfs, or AMI flag. It uploads the Agent image
by digest first, creates the immutable prerelease tag only after that upload,
and reads the tag back. Its stdout receipt includes the exact
`<repository>:<tag>@sha256:<digest>` image reference. It rejects a dirty or
changing Git checkout, a tag not bound to the current revision, an existing
tag with a different digest, credential-shaped coordinates, and any attempt to
override the fixed Agent repository.

If publication does not consume the session, clean it explicitly:

```text
dirextalk-agent-imagectl cleanup --session <protected-local-session-path>
```

## Deployment boundary intentionally not closed here

Private ECR image publication does not safely authorize a remote host to pull
the image. This tool deliberately does not create a runtime IAM user/role,
does not emit an ECR authorization token for a server, and never writes a
credential into cloud-init, Docker Compose, user data, repository files, or a
release receipt. A later deployment stage must use a separately approved,
least-privilege runtime pull mechanism with rotation/read-back evidence, or a
separately approved public-artifact policy. Until that exists, do not represent
an Agent-only receipt as a remotely pullable image deployment.
