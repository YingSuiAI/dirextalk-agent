import json
import hashlib
import base64
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapter"))

from dirextalk_knowledge.errors import InvalidRequest
from dirextalk_knowledge.protocol import (
    MAX_REQUEST_BYTES,
    decode_request,
    recv_frame,
    send_frame,
)


OPERATION_ID = "11111111-1111-4111-8111-111111111111"
IDEMPOTENCY_KEY = "22222222-2222-4222-8222-222222222222"
SOURCE_ID = "33333333-3333-4333-8333-333333333333"
CONTENT_ID = "44444444-4444-4444-8444-444444444444"
REVISION_ID = "55555555-5555-4555-8555-555555555555"
OWNER_ID = "66666666-6666-4666-8666-666666666666"
BINDING_ID = "77777777-7777-4777-8777-777777777777"
UPLOAD_ID = "88888888-8888-4888-8888-888888888888"
CHUNK_ID = "99999999-9999-4999-8999-999999999999"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class ProtocolTests(unittest.TestCase):
    def mutation(self):
        content = "retained knowledge"
        return {
            "version": 1,
            "operation_id": OPERATION_ID,
            "idempotency_key": IDEMPOTENCY_KEY,
            "operation": "stage_chunk",
            "body": {
                "owner_id": OWNER_ID,
                "binding_id": BINDING_ID,
                "source_id": SOURCE_ID,
                "upload_id": UPLOAD_ID,
                "chunk_id": CHUNK_ID,
                "revision_id": REVISION_ID,
                "offset_bytes": 0,
                "chunk_index": 0,
                "declared_size_bytes": len(content.encode()),
                "content_base64": base64.b64encode(content.encode()).decode(),
                "content_size": len(content.encode()),
                "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            },
        }

    def test_accepts_exact_mutation_and_canonicalizes_stably(self):
        request = decode_request(encoded(self.mutation()))
        self.assertEqual(request.operation_id, OPERATION_ID)
        self.assertEqual(request.idempotency_key, IDEMPOTENCY_KEY)
        self.assertEqual(
            decode_request(request.canonical_bytes()).canonical_bytes(),
            request.canonical_bytes(),
        )

    def test_rejects_unknown_field_noncanonical_uuid_and_oversized_content(self):
        cases = []
        unknown = self.mutation()
        unknown["url"] = "https://example.invalid"
        cases.append(unknown)
        uuid_case = self.mutation()
        uuid_case["operation_id"] = "A1111111-1111-4111-8111-111111111111"
        cases.append(uuid_case)
        content_case = self.mutation()
        content_case["body"]["content_base64"] = base64.b64encode(b"x" * 262_145).decode()
        content_case["body"]["content_size"] = 262_145
        content_case["body"]["declared_size_bytes"] = 262_145
        content_case["body"]["content_sha256"] = hashlib.sha256(b"x" * 262_145).hexdigest()
        cases.append(content_case)
        backend = self.mutation()
        backend["body"]["backend"] = "other"
        cases.append(backend)
        for value in cases:
            with self.subTest(value=list(value)):
                with self.assertRaises(InvalidRequest):
                    decode_request(encoded(value))

    def test_search_bounds_and_rejects_nan(self):
        value = {
            "version": 1,
            "operation_id": OPERATION_ID,
            "operation": "search",
            "body": {"owner_id": OWNER_ID, "binding_id": BINDING_ID, "query": "q", "limit": 51},
        }
        with self.assertRaises(InvalidRequest):
            decode_request(encoded(value))
        with self.assertRaises(InvalidRequest):
            decode_request(
                b'{"version":1,"operation_id":"11111111-1111-4111-8111-111111111111",'
                b'"operation":"search","body":{"owner_id":"66666666-6666-4666-8666-666666666666",'
                b'"binding_id":"77777777-7777-4777-8777-777777777777","query":"q","limit":NaN}}'
            )
        duplicate = encoded(value).replace(b'"version":1', b'"version":1,"version":1')
        with self.assertRaises(InvalidRequest):
            decode_request(duplicate)

    def test_version_is_an_integer_and_text_must_be_unicode_scalar_values(self):
        float_version = self.mutation()
        float_version["version"] = 1.0
        with self.assertRaises(InvalidRequest):
            decode_request(encoded(float_version))

        lone_surrogate = self.mutation()
        lone_surrogate["body"]["owner_id"] = "owner\ud800"
        payload = json.dumps(lone_surrogate).encode("utf-8")
        with self.assertRaises(InvalidRequest):
            decode_request(payload)

    def test_content_digest_size_and_chunk_fences_are_exact(self):
        for field, value in (
            ("content_size", 1),
            ("content_sha256", "0" * 64),
            ("chunk_index", 256),
            ("offset_bytes", 1),
            ("declared_size_bytes", 1),
        ):
            case = self.mutation()
            case["body"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(InvalidRequest):
                    decode_request(encoded(case))

    def test_owner_is_bounded_opaque_not_uuid(self):
        case = self.mutation()
        case["body"]["owner_id"] = "tenant:customer@example"
        self.assertEqual(
            decode_request(encoded(case)).body["owner_id"],
            "tenant:customer@example",
        )
        case["body"]["owner_id"] = "x" * 256
        with self.assertRaises(InvalidRequest):
            decode_request(encoded(case))

    def test_frame_round_trip_and_length_limit(self):
        left, right = socket.socketpair()
        with left, right:
            send_frame(left, {"ok": True})
            payload = recv_frame(right)
            self.assertEqual(json.loads(payload), {"ok": True})
        left, right = socket.socketpair()
        with left, right:
            left.sendall(struct.pack(">I", MAX_REQUEST_BYTES + 1))
            with self.assertRaises(InvalidRequest):
                recv_frame(right)

    def test_published_relay_vectors_validate(self):
        vectors_path = Path(__file__).resolve().parents[1] / "docs/protocol-v1-vectors.json"
        vectors = json.loads(vectors_path.read_text(encoding="utf-8"))["vectors"]
        for vector in vectors:
            with self.subTest(name=vector["name"]):
                parsed = decode_request(encoded(vector["request"]))
                self.assertEqual(parsed.operation_id, vector["request"]["operation_id"])


if __name__ == "__main__":
    unittest.main()
