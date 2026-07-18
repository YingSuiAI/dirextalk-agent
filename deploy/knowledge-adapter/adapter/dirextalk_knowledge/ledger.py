"""Durable exact idempotency binding without persisting content or vectors."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Callable

from .errors import Conflict, DependencyUnavailable
from .database import prepare_database_path, protect_database_file
from .protocol import Request

LEDGER_PATH = Path("/var/lib/dirextalk-knowledge/adapter/idempotency.sqlite3")


class Ledger:
    def __init__(self, path: Path = LEDGER_PATH) -> None:
        self._path = path
        prepare_database_path(path, "ledger")
        old_umask = os.umask(0o077)
        try:
            self._database = sqlite3.connect(
                path, timeout=5.0, isolation_level=None, check_same_thread=True
            )
        except sqlite3.Error as exc:
            raise DependencyUnavailable("ledger") from exc
        finally:
            os.umask(old_umask)
        protect_database_file(path, "ledger")
        try:
            self._database.execute("PRAGMA journal_mode=WAL")
            self._database.execute("PRAGMA synchronous=FULL")
            self._database.execute("PRAGMA foreign_keys=ON")
            self._database.execute("PRAGMA busy_timeout=5000")
            self._database.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_v1 (
                    idempotency_key TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    revision_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                ) STRICT
                """
            )
        except sqlite3.Error as exc:
            raise DependencyUnavailable("ledger") from exc

    def close(self) -> None:
        self._database.close()

    def execute(
        self, request: Request, action: Callable[[], dict[str, Any]]
    ) -> dict[str, Any]:
        if request.idempotency_key is None:
            raise RuntimeError("idempotency required")
        revision_id = request.body["revision_id"]
        request_digest = hashlib.sha256(request.canonical_bytes()).hexdigest()
        try:
            row = self._database.execute(
                """
                SELECT operation_id, operation, revision_id, request_sha256,
                       response_json
                FROM idempotency_v1 WHERE idempotency_key = ?
                """,
                (request.idempotency_key,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise DependencyUnavailable("ledger") from exc
        if row is not None:
            if row[:4] != (
                request.operation_id,
                request.operation,
                revision_id,
                request_digest,
            ):
                raise Conflict()
            try:
                value = json.loads(row[4])
            except (TypeError, ValueError) as exc:
                raise DependencyUnavailable("ledger") from exc
            if not isinstance(value, dict):
                raise DependencyUnavailable("ledger")
            return value

        response = action()
        response_json = json.dumps(
            response,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        try:
            self._database.execute("BEGIN IMMEDIATE")
            existing = self._database.execute(
                "SELECT request_sha256 FROM idempotency_v1 WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            if existing is not None:
                self._database.execute("ROLLBACK")
                raise Conflict()
            self._database.execute(
                """
                INSERT INTO idempotency_v1 (
                    idempotency_key, operation_id, operation, revision_id,
                    request_sha256, response_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    request.idempotency_key,
                    request.operation_id,
                    request.operation,
                    revision_id,
                    request_digest,
                    response_json,
                ),
            )
            self._database.execute("COMMIT")
        except Conflict:
            raise
        except sqlite3.Error as exc:
            try:
                self._database.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DependencyUnavailable("ledger") from exc
        return response
