# Approval V1 golden vectors

These language-neutral fixtures pin the deterministic RFC 8949 CBOR contract
owned by Go and reproduced by Dart clients. After this cross-language freeze,
the v1 fixture bytes are an immutable compatibility boundary; any encoding
change requires a new schema and payload domain rather than replacing these
files.

- `plan.json` is the complete public `PlanV1` input.
- `plan.cbor.hex` is `PlanV1.CanonicalCBOR()`; mutable plan status is excluded
  from the signed hash projection.
- `plan.hash` is the lowercase algorithm-qualified SHA-256 plan hash.
- `approval-signing-payload.cbor.hex` is the unsigned Ed25519 message.
- `approval-signing-payload.sha256` and `approval-signature.base64url` make
  cross-language failures easier to isolate. The signature uses the 32-byte
  seed `00 01 ... 1f`; that seed is test data only.
- `approval-public-key.raw.base64url` and
  `approval-public-key.spki.base64` are the same test key in the Agent's raw
  format and Flutter's strict RFC 8410 SubjectPublicKeyInfo format.
- `approval-key-id.txt` is `cloud-device-` followed by the first 24 lowercase
  hexadecimal characters of SHA-256 over the raw 32-byte public key. The local
  trust-anchor bootstrap rejects aliases that do not exactly match this ID.

## Exact v1 encoding

`PlanV1.CanonicalCBOR()` hashes this projection: `schema_version`,
`hash_algorithm`, `agent_instance_id`, `owner_id`, `plan_id`, `revision`,
`connection_id`, `recipe`, `quote`, `resource_scope`, `network_scope`,
`secret_scope`, `integration_scope`, and `retention_scope`. Mutable Plan
`status` is deliberately excluded. The digest is lowercase
`sha256:<64-hex>` over those CBOR bytes.

The Ed25519 message is the deterministic CBOR encoding of
`approvalSigningDocumentV1`: `payload_schema`, `hash_algorithm`,
`approval_id`, `agent_instance_id`, `owner_id`, `plan_id`, `plan_revision`,
`plan_hash`, `connection_id`, `recipe_digest`, `quote_id`, `quote_digest`,
`quote_scope_digest`, `quote_candidate_id`, `quote_valid_until`,
`resource_scope`, `network_scope`, `secret_scope`, `integration_scope`,
`retention_scope`, `challenge_id`, `signer_key_id`, and `expires_at`.
`signature` is never part of the message. The exact `payload_schema` value
`dirextalk.agent.cloud.approval-signing-payload/v1` is the in-band domain
separator; the verifier reconstructs it and never accepts a caller-selected
domain.

Both documents first use their JSON field projection, then RFC 8949 core
deterministic CBOR. Map keys are sorted by the bytewise lexical order of each
key's deterministic CBOR encoding. Unsigned and signed integers use CBOR major
types 0 and 1 with the shortest valid width; floating point is forbidden.
Timestamps are normalized to UTC and encoded as Go RFC3339Nano text strings,
without CBOR tag 0/1. Authority-issued live timestamps are truncated to
microseconds before persistence/signing so PostgreSQL, protobuf, and Dart do
not disagree. Availability zones, ingress ports, secret references,
integrations, and integration scopes are sorted by the Go normalization rules
before encoding. Money remains integer micro-units.

No credential or private production material is present in these fixtures.
