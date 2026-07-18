import json
import hashlib
import base64
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapter"))

from dirextalk_knowledge.errors import (
    Conflict,
    DependencyUnavailable,
    InvalidContent,
    PersistenceMismatch,
)
from dirextalk_knowledge.ledger import Ledger
from dirextalk_knowledge.protocol import decode_request
from dirextalk_knowledge.service import (
    MAX_ATTACHMENT_SEGMENTS,
    MAX_MEMORY_SEGMENTS,
    KnowledgeService,
    _normalize_cosine,
    _point_id,
    _split_text,
)
from dirextalk_knowledge.staging import StagingStore


OP = "11111111-1111-4111-8111-111111111111"
KEY = "22222222-2222-4222-8222-222222222222"
MEMORY = "33333333-3333-4333-8333-333333333333"
REVISION = "44444444-4444-4444-8444-444444444444"
OWNER = "55555555-5555-4555-8555-555555555555"
BINDING = "66666666-6666-4666-8666-666666666666"
UPLOAD = "77777777-7777-4777-8777-777777777777"
CHUNK = "88888888-8888-4888-8888-888888888888"


class FakeEmbedder:
    def passage(self, text):
        return [1.0] + [0.0] * 383

    def query(self, text):
        return [1.0] + [0.0] * 383


class FakeQdrant:
    def __init__(self):
        self.points = {}
        self.upserts = 0
        self.health = "green"

    def ensure_collection(self):
        pass

    def upsert(self, point_id, vector, payload):
        self.upserts += 1
        self.points[point_id] = {"id": point_id, "payload": payload, "score": 1.0}

    def upsert_many(self, points):
        for point_id, vector, payload in points:
            self.upsert(point_id, vector, payload)

    def delete(self, owner_id, binding_id, source_id):
        self.points = {
            key: value
            for key, value in self.points.items()
            if not (
                value["payload"]["owner_id"] == owner_id
                and value["payload"]["binding_id"] == binding_id
                and value["payload"]["source_id"] == source_id
            )
        }

    def search(self, vector, limit, owner_id, binding_id, source_ids):
        points = [
            value
            for value in self.points.values()
            if value["payload"]["owner_id"] == owner_id
            and value["payload"]["binding_id"] == binding_id
        ]
        if source_ids:
            points = [
                item for item in points if item["payload"]["source_id"] in source_ids
            ]
        return points[:limit]

    def get_point(self, point_id):
        return self.points.get(point_id)

    def status(self):
        return {"collection": "dirextalk_knowledge_v1", "status": self.health}


def request(value):
    return decode_request(json.dumps(value).encode())


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.ledger_path = Path(self.temporary.name) / "ledger.sqlite3"
        self.ledger = Ledger(self.ledger_path)
        self.staging = StagingStore(Path(self.temporary.name) / "staging.sqlite3")
        self.qdrant = FakeQdrant()
        self.service = KnowledgeService(
            FakeEmbedder(), self.qdrant, self.ledger, self.staging
        )

    def tearDown(self):
        self.ledger.close()
        self.staging.close()
        self.temporary.cleanup()

    def memory_request(self, content="persistent memory"):
        content_bytes = content.encode()
        return {
            "version": 1,
            "operation_id": OP,
            "idempotency_key": KEY,
            "operation": "store_memory",
            "body": {
                "owner_id": OWNER,
                "binding_id": BINDING,
                "memory_id": MEMORY,
                "revision_id": REVISION,
                "content": content,
                "content_size": len(content_bytes),
                "content_sha256": hashlib.sha256(content_bytes).hexdigest(),
            },
        }

    def test_mutation_is_exactly_idempotent_and_ledger_omits_content(self):
        parsed = request(self.memory_request())
        first = self.service.handle(parsed)
        second = self.service.handle(parsed)
        self.assertEqual(first, second)
        self.assertEqual(self.qdrant.upserts, 1)
        self.assertEqual(str(uuid.UUID(first["point_id"])), first["point_id"])
        self.assertGreaterEqual(first["indexed_segment_count"], 1)
        self.assertLessEqual(first["indexed_segment_count"], 512)
        self.assertNotEqual(first["point_id"], MEMORY)
        ledger_bytes = self.ledger_path.read_bytes()
        self.assertNotIn(b"persistent memory", ledger_bytes)

        changed = self.memory_request("changed secret")
        with self.assertRaises(Conflict):
            self.service.handle(request(changed))

    def test_search_and_persistence_challenge_use_revision_binding(self):
        stored = self.service.handle(request(self.memory_request()))
        point_id = stored["point_id"]
        self.qdrant.points[point_id]["score"] = -1.0
        search = request(
            {
                "version": 1,
                "operation_id": "55555555-5555-4555-8555-555555555555",
                "operation": "search",
                "body": {"owner_id": OWNER, "binding_id": BINDING, "query": "memory", "limit": 1},
            }
        )
        search_result = self.service.handle(search)["results"][0]
        self.assertEqual(search_result["point_id"], point_id)
        self.assertEqual(search_result["score"], 0.0)
        challenge = request(
            {
                "version": 1,
                "operation_id": "66666666-6666-4666-8666-666666666666",
                "operation": "status",
                "body": {
                    "owner_id": OWNER,
                    "binding_id": BINDING,
                    "challenge": {
                        "point_id": point_id,
                        "source_id": MEMORY,
                        "revision_id": REVISION,
                        "content_size": len(b"persistent memory"),
                        "content_sha256": hashlib.sha256(b"persistent memory").hexdigest(),
                    },
                },
            }
        )
        self.assertTrue(self.service.handle(challenge)["persistence"]["verified"])
        wrong = request(
            {
                "version": 1,
                "operation_id": "77777777-7777-4777-8777-777777777777",
                "operation": "status",
                "body": {
                    "owner_id": OWNER,
                    "binding_id": BINDING,
                    "challenge": {
                        "point_id": point_id,
                        "source_id": MEMORY,
                        "revision_id": "88888888-8888-4888-8888-888888888888",
                        "content_size": len(b"persistent memory"),
                        "content_sha256": hashlib.sha256(b"persistent memory").hexdigest(),
                    },
                },
            }
        )
        with self.assertRaises(PersistenceMismatch):
            self.service.handle(wrong)

        self.qdrant.points[point_id]["id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(PersistenceMismatch):
            self.service.handle(challenge)

    def test_status_reports_unhealthy_collection_as_not_ready(self):
        self.qdrant.health = "red"
        status = request(
            {
                "version": 1,
                "operation_id": "12345678-1234-4234-8234-123456789abc",
                "operation": "status",
                "body": {"owner_id": OWNER, "binding_id": BINDING},
            }
        )
        result = self.service.handle(status)
        self.assertEqual(result["status"], "red")
        self.assertFalse(result["ready"])

    def test_search_rejects_dependency_payload_that_breaks_source_filter(self):
        stored = self.service.handle(request(self.memory_request()))
        point = self.qdrant.points[stored["point_id"]]
        original_search = self.qdrant.search
        self.qdrant.search = lambda *args: [point]
        search = request(
            {
                "version": 1,
                "operation_id": "13572468-1234-4234-8234-123456789abc",
                "operation": "search",
                "body": {
                    "owner_id": OWNER,
                    "binding_id": BINDING,
                    "query": "memory",
                    "limit": 1,
                    "source_ids": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
                },
            }
        )
        try:
            with self.assertRaises(DependencyUnavailable):
                self.service.handle(search)
        finally:
            self.qdrant.search = original_search

    def test_staged_attachment_commits_only_exact_fenced_digest(self):
        content = "chunked retained attachment"
        digest = hashlib.sha256(content.encode()).hexdigest()
        staged = request(
            {
                "version": 1,
                "operation_id": "99999999-9999-4999-8999-999999999999",
                "idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "operation": "stage_chunk",
                "body": {
                    "owner_id": OWNER,
                    "binding_id": BINDING,
                    "source_id": MEMORY,
                    "upload_id": UPLOAD,
                    "chunk_id": CHUNK,
                    "revision_id": REVISION,
                    "offset_bytes": 0,
                    "chunk_index": 0,
                    "declared_size_bytes": len(content.encode()),
                    "content_base64": base64.b64encode(content.encode()).decode(),
                    "content_size": len(content.encode()),
                    "content_sha256": digest,
                },
            }
        )
        self.assertTrue(self.service.handle(staged)["staged"])
        committed = request(
            {
                "version": 1,
                "operation_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "idempotency_key": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "operation": "commit_attachment",
                "body": {
                    "owner_id": OWNER,
                    "binding_id": BINDING,
                    "source_id": MEMORY,
                    "upload_id": UPLOAD,
                    "revision_id": REVISION,
                    "title": "attachment",
                    "media_type": "text/plain",
                    "chunk_count": 1,
                    "content_size": len(content.encode()),
                    "content_sha256": digest,
                },
            }
        )
        result = self.service.handle(committed)
        self.assertEqual(result["content_sha256"], digest)
        self.assertEqual(result["source_id"], MEMORY)
        self.assertNotEqual(result["point_id"], MEMORY)
        self.assertEqual(str(uuid.UUID(result["point_id"])), result["point_id"])
        self.assertGreaterEqual(result["indexed_segment_count"], 1)
        self.assertLessEqual(result["indexed_segment_count"], 32769)

    def test_chunks_may_split_utf8_but_commit_validates_aggregate(self):
        aggregate = "prefix😀suffix".encode("utf-8")
        chunks = (aggregate[:8], aggregate[8:])
        for index, chunk in enumerate(chunks):
            stage = {
                "version": 1,
                "operation_id": f"10000000-0000-4000-8000-00000000000{index}",
                "idempotency_key": f"20000000-0000-4000-8000-00000000000{index}",
                "operation": "stage_chunk",
                "body": {
                    "owner_id": OWNER,
                    "binding_id": BINDING,
                    "source_id": MEMORY,
                    "upload_id": UPLOAD,
                    "chunk_id": f"30000000-0000-4000-8000-00000000000{index}",
                    "revision_id": REVISION,
                    "offset_bytes": sum(len(item) for item in chunks[:index]),
                    "chunk_index": index,
                    "declared_size_bytes": len(aggregate),
                    "content_base64": base64.b64encode(chunk).decode(),
                    "content_size": len(chunk),
                    "content_sha256": hashlib.sha256(chunk).hexdigest(),
                },
            }
            self.service.handle(request(stage))
        commit = {
            "version": 1,
            "operation_id": "40000000-0000-4000-8000-000000000000",
            "idempotency_key": "50000000-0000-4000-8000-000000000000",
            "operation": "commit_attachment",
            "body": {
                "owner_id": OWNER,
                "binding_id": BINDING,
                "source_id": MEMORY,
                "upload_id": UPLOAD,
                "revision_id": REVISION,
                "title": "split UTF-8",
                "media_type": "text/plain",
                "chunk_count": 2,
                "content_size": len(aggregate),
                "content_sha256": hashlib.sha256(aggregate).hexdigest(),
            },
        }
        result = self.service.handle(request(commit))
        self.assertEqual(result["chunk_count"], 2)

    def test_commit_rejects_invalid_aggregate_utf8_safely(self):
        chunk = b"\xff"
        stage = {
            "version": 1,
            "operation_id": "60000000-0000-4000-8000-000000000000",
            "idempotency_key": "70000000-0000-4000-8000-000000000000",
            "operation": "stage_chunk",
            "body": {
                "owner_id": OWNER,
                "binding_id": BINDING,
                "source_id": MEMORY,
                "upload_id": UPLOAD,
                "chunk_id": "80000000-0000-4000-8000-000000000000",
                "revision_id": REVISION,
                "offset_bytes": 0,
                "chunk_index": 0,
                "declared_size_bytes": 1,
                "content_base64": base64.b64encode(chunk).decode(),
                "content_size": 1,
                "content_sha256": hashlib.sha256(chunk).hexdigest(),
            },
        }
        self.service.handle(request(stage))
        commit = {
            "version": 1,
            "operation_id": "90000000-0000-4000-8000-000000000000",
            "idempotency_key": "a0000000-0000-4000-8000-000000000000",
            "operation": "commit_attachment",
            "body": {
                "owner_id": OWNER,
                "binding_id": BINDING,
                "source_id": MEMORY,
                "upload_id": UPLOAD,
                "revision_id": REVISION,
                "title": "invalid",
                "media_type": "text/plain",
                "chunk_count": 1,
                "content_size": 1,
                "content_sha256": hashlib.sha256(chunk).hexdigest(),
            },
        }
        with self.assertRaises(InvalidContent):
            self.service.handle(request(commit))

    def test_cosine_score_normalization_is_public_range_bounded(self):
        for raw, expected in ((-1.0, 0.0), (0.0, 0.5), (1.0, 1.0), (1.0000001, 1.0)):
            with self.subTest(raw=raw):
                self.assertEqual(_normalize_cosine(raw), expected)
        with self.assertRaises(DependencyUnavailable):
            _normalize_cosine(1.01)

    def test_segment_count_bounds_and_utf8_reassembly(self):
        value = "a" * 2047 + "😀" + "b" * 2050
        segments = _split_text(value)
        self.assertEqual("".join(segments), value)
        self.assertTrue(all(len(item.encode()) <= 2051 for item in segments))
        self.assertEqual(MAX_MEMORY_SEGMENTS, 512)
        self.assertEqual(MAX_ATTACHMENT_SEGMENTS, 32769)
        first = _point_id("owner-a", BINDING, MEMORY, 0)
        self.assertEqual(first, _point_id("owner-a", BINDING, MEMORY, 0))
        self.assertNotEqual(first, _point_id("owner-b", BINDING, MEMORY, 0))
        self.assertEqual(str(uuid.UUID(first)), first)

    def test_only_first_segment_retains_optional_source_metadata(self):
        base_payload = {
            "owner_id": OWNER,
            "binding_id": BINDING,
            "source_id": MEMORY,
            "revision_id": REVISION,
            "kind": "attachment",
            "media_type": "text/plain",
            "title": "title",
            "metadata": {"topic": "retained"},
            "content_size": 2050,
            "content_sha256": "a" * 64,
        }
        count, first = self.service._index_content(
            OWNER, BINDING, MEMORY, "x" * 2050, base_payload
        )
        self.assertEqual(count, 2)
        self.assertIn("metadata", self.qdrant.points[first]["payload"])
        second = self.qdrant.points[_point_id(OWNER, BINDING, MEMORY, 1)]["payload"]
        self.assertNotIn("metadata", second)
        self.assertNotIn("title", second)
        self.assertNotIn("media_type", second)


class StoragePathTests(unittest.TestCase):
    def test_ledger_rejects_symlink_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"")
            link = root / "ledger.sqlite3"
            link.symlink_to(target)
            with self.assertRaises(DependencyUnavailable):
                Ledger(link)

    def test_staging_commit_rejects_noncontiguous_offsets(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = StagingStore(Path(temporary) / "staging.sqlite3")
            try:
                for index, offset in ((0, 0), (1, 2)):
                    chunk = b"x"
                    store.stage(
                        {
                            "owner_id": OWNER,
                            "binding_id": BINDING,
                            "source_id": MEMORY,
                            "upload_id": UPLOAD,
                            "chunk_id": f"d0000000-0000-4000-8000-00000000000{index}",
                            "revision_id": REVISION,
                            "offset_bytes": offset,
                            "chunk_index": index,
                            "declared_size_bytes": 2,
                            "content_base64": base64.b64encode(chunk).decode(),
                            "content_size": 1,
                            "content_sha256": hashlib.sha256(chunk).hexdigest(),
                        }
                    )
                with self.assertRaises(Conflict):
                    store.load(
                        {
                            "owner_id": OWNER,
                            "binding_id": BINDING,
                            "source_id": MEMORY,
                            "upload_id": UPLOAD,
                            "revision_id": REVISION,
                            "chunk_count": 2,
                            "content_size": 2,
                        }
                    )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
