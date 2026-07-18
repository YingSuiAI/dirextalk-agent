"""Single-request Unix-socket server with safe error responses."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from .auth import PeerAuthorizer, secure_bound_socket
from .errors import AdapterError, InvalidRequest
from .protocol import (
    ZERO_OPERATION_ID,
    decode_request,
    recv_frame,
    send_frame,
)
from .service import KnowledgeService

SOCKET_PATH = Path("/run/dirextalk-knowledge/adapter.sock")


class Server:
    def __init__(
        self,
        service: KnowledgeService,
        authorizer: PeerAuthorizer,
        socket_path: Path = SOCKET_PATH,
    ) -> None:
        self._service = service
        self._authorizer = authorizer
        self._socket_path = socket_path

    def serve_forever(self) -> None:
        listener = secure_bound_socket(
            self._socket_path, self._authorizer.allowed_gid
        )
        try:
            while True:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(15.0)
                    self.handle_connection(connection)
        finally:
            listener.close()
            self._socket_path.unlink(missing_ok=True)

    def handle_connection(self, connection: socket.socket) -> None:
        if not self._authorizer.authorize(connection):
            self._safe_send_error(connection, ZERO_OPERATION_ID, "unauthorized", "peer")
            return
        operation_id = ZERO_OPERATION_ID
        try:
            request = decode_request(recv_frame(connection))
            operation_id = request.operation_id
            result = self._service.handle(request)
            send_frame(
                connection,
                {
                    "version": 1,
                    "operation_id": operation_id,
                    "ok": True,
                    "result": result,
                },
            )
        except AdapterError as exc:
            self._safe_send_error(
                connection, exc.operation_id or operation_id, exc.code, exc.field
            )
        except (OSError, TimeoutError, RuntimeError, ValueError):
            self._safe_send_error(
                connection, operation_id, "internal_error", "runtime"
            )

    @staticmethod
    def _safe_send_error(
        connection: socket.socket, operation_id: str, code: str, field: str
    ) -> None:
        try:
            send_frame(
                connection,
                {
                    "version": 1,
                    "operation_id": operation_id,
                    "ok": False,
                    "error": {"code": code, "field": field},
                },
            )
        except (OSError, RuntimeError):
            pass
