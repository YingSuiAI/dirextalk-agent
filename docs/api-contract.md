# API Contract

The canonical contract is `api/proto/dirextalk/agent/v1/agent.proto`.

- Every mutation accepts a UUID idempotency key.
- Revision-protected mutations reject stale expected revisions.
- `WatchEvents` resumes strictly after the supplied durable sequence.
- Ordinary service authentication cannot authorize cloud spending or destructive transitions.
- Secret material is accepted only by the encrypted bootstrap service and never appears in events or summaries.
- Enum zero values are invalid/unknown and must fail closed when used in mutations.

## P0 authentication

Calls use `authorization: DTX-Service-Key <key_id>.<secret>`. `key_id` is 1–128 ASCII letters, digits, `_`, or `-`; `secret` is exactly 32 random bytes encoded as unpadded base64url. PostgreSQL stores only an HMAC-SHA256 digest made with the mounted server pepper. Authentication performs a constant-time digest comparison, checks active/expiry state and method scope, and removes the authorization metadata before invoking unary or streaming handlers.

Every idempotency record is namespaced by operation, authenticated client ID, authenticated credential ID, and UUID key. Reusing a key with an equivalent canonical request returns the original versioned response snapshot; changing the request in the same caller namespace returns `ALREADY_EXISTS`. A different pairwise caller may independently reuse the UUID.

`AdminService.CreateServiceKey` generates a fresh random secret. The response never has a plaintext secret field: it contains a `ServiceKeyDelivery` encrypted to the request's X25519 public key with HKDF-SHA256 and AES-256-GCM. `associated_data` binds the operation, caller credential/client, idempotency key, returned credential/key, requested client/scopes/expiry, and recipient key. The encrypted delivery is the only response material persisted for exact replay. Revocation uses `expected_revision`; overlapping keys remain valid independently until their own expiry or revocation.

## P0 task and event facts

Task creation and cancellation atomically persist their idempotency response, entity changes, durable event, and identical Outbox payload. A Task may include an internal Step DAG; unknown dependencies, duplicate IDs, self edges, and multi-node cycles are rejected before persistence. Lease acquisition, renewal, checkpoint, completion, expiry reacquisition, and cancellation all fence by worker, attempt, and monotonically increasing `lease_epoch`; stale workers cannot commit results.

Task event `summary_json` schema version 1 contains the complete de-secreted projection: task/owner IDs, execution/outcome/retention, current step, approved plan, revision, timestamps, and actor client/credential IDs. Cancellation adds only a redacted reason. Step summaries are independently versioned. `WatchEvents(after_seq)` emits facts strictly after the durable global sequence and supports reconnect after server/store restart.

P0 implements Task and Admin behavior. Runtime and Cloud capability queries truthfully return disabled flags; Chat, encrypted secret bootstrap, and Worker RPCs remain `UNIMPLEMENTED` until their delivery stages.
