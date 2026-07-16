# Approval V1 golden vectors

These language-neutral fixtures pin the deterministic RFC 8949 CBOR contract
used by Go and future Dart clients.

- `plan.json` is the complete public `PlanV1` input.
- `plan.cbor.hex` is `PlanV1.CanonicalCBOR()`; mutable plan status is excluded
  from the signed hash projection.
- `plan.hash` is the lowercase algorithm-qualified SHA-256 plan hash.
- `approval-signing-payload.cbor.hex` is the unsigned Ed25519 message.
- `approval-signing-payload.sha256` and `approval-signature.base64url` make
  cross-language failures easier to isolate. The signature uses the 32-byte
  seed `00 01 ... 1f`; that seed is test data only.

All timestamps are UTC and all money contracts use integer micro-units. No
credential or private production material is present.
