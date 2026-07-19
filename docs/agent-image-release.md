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
- Use a supported Docker Buildx installation capable of `linux/amd64` image
  builds. Other architectures are rejected.
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
  --builder-mode direct \
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

`--builder-mode direct` first read-verifies the separately prepared and seeded
`dirextalk-build-sources` repository. It then creates a task-owned
`docker-container` builder inside the fresh `DOCKER_CONFIG`, using only the
verified private BuildKit child digest.
It reads the existing Docker Desktop proxy endpoint, accepts only the
credential-free `http.docker.internal` HTTP endpoint with matching HTTP/HTTPS
configuration, injects it only into the task-owned builder process, and proves
the private frontend and Go-base resolver path before returning the session. The endpoint is
not persisted in the session descriptor, marker, receipt, or repository.
Build and registry operations name that builder explicitly. Session cleanup
removes and reads back the builder container and state volume before removing
the authorization directory, including after publication failure or
cancellation. A pre-existing builder/container/volume with the derived name
fails closed and is never adopted. Omitting the flag can still prepare the
legacy embedded-builder session shape, but the closed private-source publisher
rejects that unverified session; current release publication requires direct
mode.

`publish` derives the repository from the authenticated registry host and has
no repository, Worker, Reaper, rootfs, or AMI flag. It uploads the Agent image
by digest first, creates the immutable prerelease tag only after that upload,
and reads the tag back. Its stdout receipt includes the exact
`<repository>:<tag>@sha256:<digest>` image reference. It rejects a dirty or
changing Git checkout, a tag not bound to the current revision, an existing
tag with a different digest, credential-shaped coordinates, and any attempt to
override the fixed Agent repository. Publication is `linux/amd64` only and
injects the verified private frontend and Go-base references on every build.

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
