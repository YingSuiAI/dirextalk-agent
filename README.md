# Dirextalk Agent

Dirextalk Agent is a reusable, single-tenant control service for persistent AI tasks and typed cloud workloads. It exposes a versioned gRPC API, stores durable facts in PostgreSQL, and uses Eino with typed tools to prepare deployment plans. Privileged execution runs only in an exclusive Cloud Worker VM and never in the control container.

The control container does not depend on Matrix or ProductCore and does not run arbitrary user commands. Projects integrate through a pairwise service key and keep their own user-facing transport and authentication.

## Current delivery

P0 provides service-key authentication, durable Task/Step state, idempotency, revision and lease fencing, and cursor-resumable events. P1 adds persisted runtime configuration and conversations, `RuntimeService.Chat`/`StreamChat`, the native Eino runtime, mounted model-secret references, optional Streamable HTTP MCP configuration, and the planning-only `cloud-dispatcher` Skill.

The P2 first-validation build adds encrypted one-time AWS bootstrap, typed live pricing and quota evidence, device-signed plans, deterministic Foundation contracts, direct STS control, durable EC2 mutation intents, STS/IMDS-bound Worker enrollment, Task/Worker checkpoint synchronization, scoped artifacts, resource manifests, automatic ephemeral cleanup, and the AWS-side Reaper. Agent, Worker, and Reaper container definitions are repository-local and contain no Node, AWS CLI, or Docker socket dependency. Closed Go operator tools now prepare the fixed immutable ECR repositories, publish digest-bound prerelease images plus a deterministic Worker rootfs, and build, attest, verify, or destroy a fixed Worker AMI with AWS read-back.

This build is locally and fake-provider testable. AWS mutations remain fail-closed unless `AGENT_ENABLE_AWS_CONTROL=true` is explicitly configured. An approved Recipe can now resolve an exact official HTTPS artifact, publish it as a versioned SSE-KMS S3 object, bind its digest and target into EC2 user-data, materialize it atomically as root before enabling the installer socket, and execute only its signed `command_id`. Worker heartbeats rotate installer grants to the exact durable lease, so long multi-step installs do not outlive or lose their authorization. The root daemon has the package, filesystem, mount, systemd, and network abilities expected inside an exclusive VM; the signed artifact/command and AWS resource/network scope remain the control boundary, not a false domain sandbox. Persistent data volumes, deployment-scoped secrets, and separately fenced service/public-entry external-probe evidence are implemented locally, but the release and AMI paths have not yet been executed against the authorized real ECR/EC2 environment, and Managed operations plus client cutover remain incomplete. This repository therefore still does not claim a real OpenClaw or knowledge-node deployment. Detailed progress is tracked in [docs/delivery-tracker.md](docs/delivery-tracker.md).

## Development

Requirements: Go 1.26, Buf, Protobuf compiler, and the workspace PostgreSQL 18 service for integration tests.

```powershell
buf generate
go test ./...
go build ./cmd/...
```

For a release-preparation path that builds and publishes only the Agent
container (without Worker/Reaper/rootfs/AMI artifacts), see
[docs/agent-image-release.md](docs/agent-image-release.md). It intentionally
does not provide remote-host ECR pull credentials.

Production startup requires TLS certificate/key files, a PostgreSQL DSN, an immutable instance ID, a service-key pepper file, and an initial service-key file. Secret values must be mounted as files rather than supplied in command arguments.

## Operation

The control process has five commands: `migrate`, `bootstrap-service-key`, `bootstrap-approval-device`, `healthcheck`, and `serve`. The first three and `serve` use the same immutable `AGENT_INSTANCE_ID` and read the PostgreSQL DSN from `AGENT_DATABASE_URL_FILE`; the legacy plaintext `AGENT_DATABASE_URL` environment variable is deliberately ignored.

`serve` additionally requires:

- `AGENT_GRPC_LISTEN` (defaults to `:9443`).
- `AGENT_TLS_CERT_FILE` and a protected `AGENT_TLS_KEY_FILE`.
- `AGENT_SERVICE_KEY_PEPPER_FILE` containing at least 32 bytes of random material.
- `AGENT_MOUNTED_SECRETS_DIR`, whose protected files are addressed only as opaque `mounted:<name>` references.
- `AGENT_MODEL_PROFILES_FILE`, a strict, secret-free JSON catalog that binds each public `profile_id` to one provider, model, HTTPS endpoint, mounted credential reference, context window, and maximum output-token limit.
- Optional `AGENT_MCP_SERVERS_FILE`, containing trusted, secret-free HTTPS MCP endpoint metadata and optional mounted secret references.

`healthcheck` is the image-local, no-database readiness command. It performs the standard unauthenticated gRPC health RPC through TLS 1.3, defaults to `127.0.0.1` on the `AGENT_GRPC_LISTEN` port, and accepts an optional `AGENT_GRPC_HEALTHCHECK_ADDRESS` only when it is an IP loopback address on that same port. `AGENT_GRPC_HEALTHCHECK_SERVER_NAME` is required and must be an exact DNS or IP SAN from `AGENT_TLS_CERT_FILE`; the command combines the system roots with that mounted public certificate chain and never reads the TLS private key or a service key. The production image invokes this command through its Docker `HEALTHCHECK` metadata.

AWS control remains default-off. When enabled, `AGENT_AWS_REAPER_IMAGE_URI` must be an immutable prerelease reference with a registry digest and `AGENT_WORKER_CONTROL_ENDPOINT` must be a credential-free `grpcs://` endpoint. An optional protected `AGENT_WORKER_AMI_PUBLICATION_FILE` imports one independently attested Worker AMI publication at startup. The durable active-release catalog is scoped by Agent instance, AWS account, Region, and architecture; quoting fails closed when no matching active release exists, and callers cannot supply an AMI ID directly.

Callers select a configured model by `profile_id`; they cannot choose or recombine its endpoint and credential reference. A minimal catalog is `{"schema_version":1,"profiles":[{"profile_id":"deepseek-v4","provider":"deepseek","model":"deepseekv4-pro","base_url":"https://api.deepseek.com/v1","secret_ref":"mounted:deepseek-token","context_window":65536,"max_output_tokens":8192}]}`. Keep credential bytes only in the referenced mounted file.

`bootstrap-service-key` additionally requires a protected `AGENT_BOOTSTRAP_SERVICE_KEY_FILE`, `AGENT_BOOTSTRAP_CLIENT_ID`, and optional comma-separated `AGENT_BOOTSTRAP_SCOPES`. The key file contains `key_id.<32-byte-base64url-secret>`. Generate it outside the process, mount it read-only, and never place its value in shell history, Compose YAML, logs, or source control.

`bootstrap-approval-device` is the one-time, local trust-anchor command for an owner's first approval device. It requires `AGENT_APPROVAL_DEVICE_OWNER_ID`, `AGENT_APPROVAL_DEVICE_KEY_ID`, a canonical UUID `AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY`, a future RFC3339 `AGENT_APPROVAL_DEVICE_EXPIRES_AT`, and `AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE` pointing to a protected read-only file. The file may contain the exact 32-byte raw Ed25519 public key (binary or unpadded base64url) or the strict RFC 8410 Ed25519 SubjectPublicKeyInfo exported by Flutter (DER or standard base64); other algorithms, parameters, private keys, and trailing fields are rejected. `AGENT_APPROVAL_DEVICE_KEY_ID` must equal `cloud-device-` plus the first 24 lowercase hexadecimal characters of SHA-256 over that raw public key, exactly matching Flutter; aliases fail closed. An exact rerun is idempotent; any different second device for that owner is rejected. Service Keys cannot call the reserved remote register/revoke RPCs.

On Linux, DSN, TLS private key, pepper, and bootstrap key files must be regular files without group/world permission bits. Run `migrate` before bootstrap or serve; startup rejects a database owned by another `agent_instance_id` or a migration whose recorded checksum differs.

PostgreSQL integration checks are opt-in through `AGENT_TEST_POSTGRES_DSN`. The P1 lane verifies the complete TLS gRPC/Eino/planning flow against PostgreSQL 18, including official-source evidence, structured Task references, exact replay, restart recovery, event cursors, secret canaries, stateless completion, and database/role cleanup.

The Agent requires an independent logical database and role, not an independent PostgreSQL process. A Dirextalk deployment should reuse the existing Message Server PostgreSQL 18 server/container and create a separate Agent database and least-privilege role. Agent and Message Server must not share a database, schema, role, migration ledger, or credentials. No PostgreSQL 16 or second PostgreSQL container is required.
