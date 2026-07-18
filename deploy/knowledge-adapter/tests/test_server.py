import json
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapter"))

from dirextalk_knowledge.protocol import recv_frame
from dirextalk_knowledge.server import Server


OPERATION_ID = "11111111-1111-4111-8111-111111111111"


class AllowPeer:
    def authorize(self, connection):
        return True


class UnusedService:
    def handle(self, request):
        raise AssertionError("invalid request reached the service")


class ServerTests(unittest.TestCase):
    def test_valid_envelope_operation_id_is_preserved_on_body_error(self):
        request = {
            "version": 1,
            "operation_id": OPERATION_ID,
            "operation": "search",
            "body": {
                "owner_id": "owner",
                "binding_id": "22222222-2222-4222-8222-222222222222",
                "query": "q",
                "limit": 0,
            },
        }
        payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
        left, right = socket.socketpair()
        with left, right:
            left.sendall(struct.pack(">I", len(payload)) + payload)
            Server(UnusedService(), AllowPeer()).handle_connection(right)
            response = json.loads(recv_frame(left))
        self.assertFalse(response["ok"])
        self.assertEqual(response["operation_id"], OPERATION_ID)
        self.assertEqual(response["error"], {"code": "invalid_request", "field": "limit"})


if __name__ == "__main__":
    unittest.main()
