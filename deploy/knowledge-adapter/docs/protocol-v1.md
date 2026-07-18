# Knowledge private-relay protocol v1

The adapter accepts one request on the fixed Unix socket
`/run/dirextalk-knowledge/adapter.sock`. It never listens on TCP. The kernel
socket mode and an `SO_PEERCRED` check both restrict access to root or members
of the fixed `dirextalk-worker` group. A peer whose `/proc/<pid>/status` identity
cannot be bound back to the kernel credential is denied. This makes the
authenticated private Go relay the only non-root caller.

## Framing and envelope

One connection carries one request and one response. Each frame is a 4-byte
unsigned big-endian length followed by UTF-8 JSON. Request payloads are bounded
to 8,388,608 bytes (enough for the public 1 MiB memory after worst-case JSON
escaping); responses to 1,048,576 bytes. Empty/partial/oversized frames,
invalid UTF-8, duplicate/unknown semantic fields, non-finite numbers, and
noncanonical UUIDs fail closed.

Every request has exactly:

```json
{"version":1,"operation_id":"<uuid>","operation":"<closed-name>","body":{}}
```

Mutations also have `idempotency_key`. UUIDs are canonical lowercase, non-nil
RFC 4122 strings. A durable ledger binds the idempotency key to the exact
operation ID, operation name, revision, and SHA-256 of canonical request JSON.
Only an exact replay succeeds; changing an owner, binding, source, upload,
chunk, revision, size, digest, or content under the same key is a conflict.

Every body requires `owner_id` and `binding_id`. `owner_id` is the public
contract's opaque nonempty UTF-8 string bounded to 255 bytes; it is deliberately
not interpreted as a UUID. Binding/source/upload/chunk/revision identifiers are
canonical UUIDs. They are data-access fences,
not user-selectable backend configuration. Qdrant filters always include both;
delete also includes `source_id`. The adapter never accepts a URL, filesystem
path, network header, model/backend selector, or command.

## Closed operations

`stage_chunk` is a mutation with this exact body:

```text
owner_id, binding_id, source_id, upload_id, chunk_id, revision_id,
offset_bytes, chunk_index, declared_size_bytes, content_base64, content_size,
content_sha256
```

Chunks are nonempty bytes encoded as canonical standard padded base64, at most
262,144 decoded bytes. They need not be independently valid UTF-8 because the
public upload stream may split a code point. Index is 0–255. The relay supplies
the exact byte offset and declared aggregate size (1–67,108,864); a stage is
rejected if the chunk crosses that boundary. The adapter recomputes decoded
size and SHA-256 before persisting. A chunk ID and the
`(owner,binding,upload,index)` tuple are both unique and immutable. Final chunk
count is intentionally absent because the relay does not know it until commit.

`commit_attachment` is a mutation with:

```text
owner_id, binding_id, source_id, upload_id, revision_id, title, media_type,
chunk_count, content_size, content_sha256, metadata?
```

The adapter requires every contiguous staged chunk with identical fences,
requires contiguous indices and byte offsets with one identical declared size,
reassembles at most 67,108,864 bytes, and independently verifies aggregate size
and SHA-256 before validating aggregate UTF-8 and embedding/upsert. Media type is one of `text/plain`,
`text/markdown`, or `application/json`. Metadata has at most 32 lowercase
bounded keys and string/integer/boolean scalar values. Successful commit clears
staged content after its idempotency result is durable. The full validated text
is split at UTF-8 character boundaries on a 2,048-byte target (a segment may
extend by at most three bytes to keep its final Unicode scalar intact),
so a large attachment is not sent to Qdrant as one oversized payload. Segment
point UUIDs are deterministic UUIDv5 values over the exact owner, binding,
source, and segment index; the first is returned as `point_id`, together with
`indexed_segment_count`. The point is always a canonical UUID and the count is
positive. Every nonfinal segment contains at least 2,048 bytes, so the maximum
count is `ceil(indexed UTF-8 bytes / 2048)`; attachment indexed text includes
title plus two separator bytes, making its public bound 32,769. All segments repeat the aggregate revision/size/digest
evidence and are removed by the fenced source delete.

`store_memory` is a mutation with:

```text
owner_id, binding_id, memory_id, revision_id, content, content_size,
content_sha256
```

Memory is nonempty UTF-8 up to 1,048,576 bytes. Size/digest are recomputed.
`memory_id` remains the source fence, while the response contains the distinct
canonical first segment `point_id` and positive `indexed_segment_count` (at most
`ceil(memory UTF-8 bytes / 2048)`, maximum 512).

`delete` is a mutation with:

```text
owner_id, binding_id, source_id, revision_id
```

It deletes only points matching all three owner/binding/source fences.

`search` is read-only with:

```text
owner_id, binding_id, query, limit, source_ids?
```

Query is nonempty UTF-8 up to 16,384 bytes, limit is 1–50, and at most 50 unique
source UUIDs may further narrow the mandatory owner/binding filter. Results
contain point/owner/binding/source/revision IDs, kind, bounded text, finite
score in the public `[0,1]` range, and source size/SHA-256 evidence; never
vectors. Qdrant cosine `[-1,1]` is deterministically mapped with
`(cosine + 1) / 2`; only a `1e-6` floating-rounding overrun is clamped, while a
larger out-of-range dependency response fails closed.

`status` is read-only with owner/binding and an optional challenge:

```text
owner_id, binding_id,
challenge?: {point_id, source_id, revision_id, content_size, content_sha256}
```

Empty-challenge status verifies model/provider/collection readiness. A challenge
also reads the exact point and compares every owner/binding/source/revision/
size/digest fence, returning `persistence.verified: true`. This is the retained
encrypted-volume restart acceptance seam without adding an unbounded read API.

## Response result schemas

Successful results are closed adapter-owned objects:

```text
stage_chunk:
  owner_id, binding_id, source_id, upload_id, chunk_id, revision_id,
  offset_bytes, chunk_index, declared_size_bytes, content_size,
  content_sha256, staged=true
commit_attachment:
  owner_id, binding_id, point_id, source_id, upload_id, revision_id,
  kind="attachment", chunk_count, content_size, content_sha256,
  indexed_segment_count
store_memory:
  owner_id, binding_id, point_id, source_id, revision_id, kind="memory",
  content_size, content_sha256, indexed_segment_count
delete:
  owner_id, binding_id, source_id, revision_id, deleted=true
search:
  results[{point_id, owner_id, binding_id, source_id, revision_id, kind,
           content, content_truncated, score, content_size, content_sha256}]
status:
  owner_id, binding_id, ready, model, model_revision, dimensions,
  execution_provider, collection, status, persistence?
```

Every returned `point_id` is a canonical non-nil UUID. Both indexed mutation
results require an integer `indexed_segment_count` in their operation-specific
positive bound (attachment 1–32,769; memory 1–512). A relay must persist the
returned first point ID instead of substituting the source ID.

## Privacy and diagnostics

Document/chunk/memory text, queries, vector bytes, and the Qdrant API key are
never logged or placed in installer arguments, environment, service units, or
the idempotency ledger. Protocol errors contain only a closed error code and a
safe field label. Search content is an intended authenticated response, not a
diagnostic. The staging database temporarily persists attachment content on the
same protected Managed volume and removes it after successful commit.

`protocol-v1-vectors.json` contains compact canonical JSON request/response
vectors. A Go relay should encode the object with normal JSON semantics, apply
the frame prefix to the resulting UTF-8 bytes, and assert the response binding;
it must not log the frame.

Error responses use only these codes: `invalid_request`,
`idempotency_conflict`, `invalid_content`, `dependency_unavailable`,
`persistence_mismatch`, `unauthorized`, and `internal_error`. `field` is a safe
schema label and never the rejected value. If framing fails before a request ID
is available, the response uses the all-zero UUID.
