import json
import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapter"))

from dirextalk_knowledge.errors import DependencyUnavailable
from dirextalk_knowledge.qdrant import QdrantClient


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.responses = []

    def request(self, method, path, body, headers):
        self.calls.append((method, path, body, headers))
        return self.responses.pop(0)


class QdrantTests(unittest.TestCase):
    def test_creates_only_fixed_384_cosine_collection(self):
        transport = FakeTransport()
        transport.responses = [(404, b"{}"), (200, b'{"result":true}')] + [
            (200, b'{"result":true}')
        ] * 3
        QdrantClient(transport).ensure_collection()
        self.assertEqual(
            [call[:2] for call in transport.calls],
            [
                ("GET", "/collections/dirextalk_knowledge_v1"),
                ("PUT", "/collections/dirextalk_knowledge_v1"),
                ("PUT", "/collections/dirextalk_knowledge_v1/index?wait=true"),
                ("PUT", "/collections/dirextalk_knowledge_v1/index?wait=true"),
                ("PUT", "/collections/dirextalk_knowledge_v1/index?wait=true"),
            ],
        )
        self.assertEqual(
            json.loads(transport.calls[1][2]),
            {"vectors": {"distance": "Cosine", "size": 384}},
        )
        self.assertEqual(
            [json.loads(call[2])["field_name"] for call in transport.calls[2:]],
            ["owner_id", "binding_id", "source_id"],
        )

    def test_rejects_existing_wrong_schema_and_nonfinite_vector(self):
        transport = FakeTransport()
        transport.responses = [
            (
                200,
                b'{"result":{"config":{"params":{"vectors":{"size":768,"distance":"Cosine"}}}}}',
            )
        ]
        with self.assertRaises(DependencyUnavailable):
            QdrantClient(transport).ensure_collection()
        with self.assertRaises(DependencyUnavailable):
            QdrantClient(transport).upsert(
                "11111111-1111-4111-8111-111111111111",
                [math.nan] * 384,
                {},
            )

    def test_search_never_requests_vectors_and_uses_bounded_filter(self):
        transport = FakeTransport()
        transport.responses = [
            (
                200,
                b'{"result":{"points":[{"id":"11111111-1111-4111-8111-111111111111",'
                b'"score":0.9,"payload":{"source_id":"22222222-2222-4222-8222-222222222222"}}]}}',
            )
        ]
        result = QdrantClient(transport).search(
            [0.0] * 384,
            2,
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
            ["22222222-2222-4222-8222-222222222222"],
        )
        request = json.loads(transport.calls[0][2])
        self.assertFalse(request["with_vector"])
        self.assertEqual(request["limit"], 2)
        self.assertEqual(len(request["filter"]["must"]), 3)
        self.assertEqual(len(result), 1)

    def test_search_rejects_noncanonical_dependency_point_id(self):
        transport = FakeTransport()
        transport.responses = [
            (
                200,
                b'{"result":{"points":[{"id":"NOT-A-UUID","score":0.9,"payload":{}}]}}',
            )
        ]
        with self.assertRaises(DependencyUnavailable):
            QdrantClient(transport).search(
                [0.0] * 384,
                1,
                "owner",
                "44444444-4444-4444-8444-444444444444",
                None,
            )

    def test_batched_upsert_is_bounded(self):
        transport = FakeTransport()
        transport.responses = [(200, b'{"result":true}')]
        point = (
            "11111111-1111-4111-8111-111111111111",
            [0.0] * 384,
            {"owner_id": "owner"},
        )
        second = (
            "22222222-2222-4222-8222-222222222222",
            [0.0] * 384,
            {"owner_id": "owner"},
        )
        QdrantClient(transport).upsert_many([point, second])
        self.assertEqual(len(json.loads(transport.calls[0][2])["points"]), 2)
        with self.assertRaises(DependencyUnavailable):
            QdrantClient(transport).upsert_many([point] * 65)


if __name__ == "__main__":
    unittest.main()
