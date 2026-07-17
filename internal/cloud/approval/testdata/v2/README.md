# Approval V2 golden vectors

These fixtures freeze the first device-visible service-operation Plan contract.
They are a separate canonical-CBOR and signing-payload domain; V1 fixtures
remain immutable.

`plan.json` is a complete `dirextalk.agent.cloud.plan/v2` input. It contains
one closed S3 PrivateLink template and one ephemeral volume snapshot template.
The canonical Plan hash is in `plan.hash`.

The corresponding unsigned approval uses:

- `approval_id`: `approval-2`
- `challenge_id`: `challenge-2`
- `signer_key_id`: `approval-key-id.txt`
- `expires_at`: `2026-07-16T08:05:00Z`

The approval schema is `dirextalk.agent.cloud.approval/v2`; its payload domain
is `dirextalk.agent.cloud.approval-signing-payload/v2`. Reconstruct the
canonical payload from the Plan and approval metadata, then compare its
SHA-256 with `approval-signing-payload.sha256`. The included deterministic
Ed25519 public key and signature provide a second byte-level compatibility
check without distributing private key material.

Do not change these outputs in place. A future wire or signing encoding needs
a new schema and a new fixture directory.
