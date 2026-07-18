"""Persistent, fenced attachment chunks awaiting an exact commit."""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Any

from .errors import Conflict, DependencyUnavailable
from .database import prepare_database_path, protect_database_file

STAGING_PATH = Path("/var/lib/dirextalk-knowledge/adapter/staging.sqlite3")


class StagingStore:
    def __init__(self, path: Path = STAGING_PATH) -> None:
        self._path = path
        prepare_database_path(path, "staging")
        old_umask = os.umask(0o077)
        try:
            self._database = sqlite3.connect(
                path, timeout=5.0, isolation_level=None, check_same_thread=True
            )
        except sqlite3.Error as exc:
            raise DependencyUnavailable("staging") from exc
        finally:
            os.umask(old_umask)
        protect_database_file(path, "staging")
        try:
            self._database.execute("PRAGMA journal_mode=WAL")
            self._database.execute("PRAGMA synchronous=FULL")
            self._database.execute("PRAGMA secure_delete=ON")
            self._database.execute("PRAGMA busy_timeout=5000")
            self._database.execute(
                """
                CREATE TABLE IF NOT EXISTS attachment_chunks_v1 (
                    owner_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    upload_id TEXT NOT NULL,
                    chunk_id TEXT NOT NULL UNIQUE,
                    revision_id TEXT NOT NULL,
                    offset_bytes INTEGER NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    declared_size_bytes INTEGER NOT NULL,
                    content_size INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY (owner_id, binding_id, upload_id, chunk_index)
                ) STRICT
                """
            )
        except sqlite3.Error as exc:
            raise DependencyUnavailable("staging") from exc

    def close(self) -> None:
        self._database.close()

    def stage(self, body: dict[str, Any]) -> None:
        binding = (
            body["owner_id"],
            body["binding_id"],
            body["source_id"],
            body["upload_id"],
            body["chunk_id"],
            body["revision_id"],
            body["offset_bytes"],
            body["chunk_index"],
            body["declared_size_bytes"],
            body["content_size"],
            body["content_sha256"],
            base64.b64decode(body["content_base64"], validate=True),
        )
        try:
            row = self._database.execute(
                """
                SELECT owner_id, binding_id, source_id, upload_id, chunk_id,
                       revision_id, offset_bytes, chunk_index, declared_size_bytes, content_size,
                       content_sha256, content
                FROM attachment_chunks_v1
                WHERE (owner_id = ? AND binding_id = ? AND upload_id = ? AND chunk_index = ?)
                   OR chunk_id = ?
                """,
                (
                    body["owner_id"],
                    body["binding_id"],
                    body["upload_id"],
                    body["chunk_index"],
                    body["chunk_id"],
                ),
            ).fetchone()
            if row is not None:
                if row != binding:
                    raise Conflict("chunk_id")
                return
            self._database.execute(
                """
                INSERT INTO attachment_chunks_v1 (
                    owner_id, binding_id, source_id, upload_id, chunk_id,
                    revision_id, offset_bytes, chunk_index, declared_size_bytes, content_size,
                    content_sha256, content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                binding,
            )
        except Conflict:
            raise
        except sqlite3.IntegrityError as exc:
            raise Conflict("chunk_id") from exc
        except sqlite3.Error as exc:
            raise DependencyUnavailable("staging") from exc

    def load(self, body: dict[str, Any]) -> list[bytes]:
        try:
            rows = self._database.execute(
                """
                SELECT source_id, revision_id, offset_bytes, chunk_index, declared_size_bytes,
                       content_size, content_sha256, content
                FROM attachment_chunks_v1
                WHERE owner_id = ? AND binding_id = ? AND upload_id = ?
                ORDER BY chunk_index
                """,
                (body["owner_id"], body["binding_id"], body["upload_id"]),
            ).fetchall()
        except sqlite3.Error as exc:
            raise DependencyUnavailable("staging") from exc
        if len(rows) != body["chunk_count"]:
            raise Conflict("chunk_count")
        chunks: list[bytes] = []
        expected_offset = 0
        for expected_index, row in enumerate(rows):
            if (
                row[0] != body["source_id"]
                or row[1] != body["revision_id"]
                or row[2] != expected_offset
                or row[3] != expected_index
                or row[4] != body["content_size"]
                or row[5] != len(row[7])
                or row[6] != hashlib.sha256(row[7]).hexdigest()
            ):
                raise Conflict("upload_id")
            chunk = bytes(row[7])
            chunks.append(chunk)
            expected_offset += len(chunk)
        if expected_offset != body["content_size"]:
            raise Conflict("content_size")
        return chunks

    def delete_upload(self, owner_id: str, binding_id: str, upload_id: str) -> None:
        try:
            self._database.execute(
                "DELETE FROM attachment_chunks_v1 WHERE owner_id = ? AND binding_id = ? AND upload_id = ?",
                (owner_id, binding_id, upload_id),
            )
            self._database.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error as exc:
            raise DependencyUnavailable("staging") from exc
