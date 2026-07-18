"""Strict, bounded protocol validation and framing."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import uuid
from dataclasses import dataclass
from typing import Any

from .errors import InvalidRequest

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 1_048_576
MAX_CONTENT_BYTES = 1_048_576
MAX_CHUNK_BYTES = 262_144
MAX_ATTACHMENT_BYTES = 64 * 1024 * 1024
MAX_CHUNKS = 256
MAX_QUERY_BYTES = 16_384
MAX_TITLE_BYTES = 1_024
MAX_RESULT_LIMIT = 50
MAX_SOURCE_FILTERS = 50
ZERO_OPERATION_ID = "00000000-0000-0000-0000-000000000000"

MUTATIONS = frozenset(
    {"stage_chunk", "commit_attachment", "store_memory", "delete"}
)
OPERATIONS = MUTATIONS | frozenset(
    {"search", "status"}
)
MEDIA_TYPES = frozenset({"text/plain", "text/markdown", "application/json"})
_METADATA_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class Request:
    operation_id: str
    operation: str
    body: dict[str, Any]
    idempotency_key: str | None = None

    def canonical_bytes(self) -> bytes:
        value: dict[str, Any] = {
            "body": self.body,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "version": PROTOCOL_VERSION,
        }
        if self.idempotency_key is not None:
            value["idempotency_key"] = self.idempotency_key
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def decode_request(payload: bytes) -> Request:
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise InvalidRequest("frame")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidRequest("json") from exc
    if not isinstance(value, dict):
        raise InvalidRequest("request")
    operation_id = ZERO_OPERATION_ID
    try:
        operation_id = canonical_uuid(value.get("operation_id"), "operation_id")
        operation = value.get("operation")
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise InvalidRequest("operation")
        expected = {"version", "operation_id", "operation", "body"}
        if operation in MUTATIONS:
            expected.add("idempotency_key")
        _exact_keys(value, expected, "request")
        version = value["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != PROTOCOL_VERSION
        ):
            raise InvalidRequest("version")

        idempotency_key = None
        if operation in MUTATIONS:
            idempotency_key = canonical_uuid(
                value["idempotency_key"], "idempotency_key"
            )
        body = _validate_body(operation, value["body"])
        return Request(operation_id, operation, body, idempotency_key)
    except InvalidRequest as exc:
        if exc.operation_id is None and operation_id != ZERO_OPERATION_ID:
            exc.operation_id = operation_id
        raise


def canonical_uuid(value: Any, field: str) -> str:
    if not is_canonical_uuid(value):
        raise InvalidRequest(field)
    assert isinstance(value, str)
    return value


def is_canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value and parsed.variant == uuid.RFC_4122


def _validate_body(operation: str, body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise InvalidRequest("body")
    if operation == "stage_chunk":
        _exact_keys(
            body,
            {
                "owner_id",
                "binding_id",
                "source_id",
                "upload_id",
                "chunk_id",
                "revision_id",
                "offset_bytes",
                "chunk_index",
                "declared_size_bytes",
                "content_base64",
                "content_size",
                "content_sha256",
            },
            "body",
        )
        content_base64, content_bytes = strict_base64(body["content_base64"])
        content_size = bounded_integer(body["content_size"], 1, MAX_CHUNK_BYTES, "content_size")
        if content_size != len(content_bytes):
            raise InvalidRequest("content_size")
        if sha256_string(body["content_sha256"], "content_sha256") != hashlib.sha256(content_bytes).hexdigest():
            raise InvalidRequest("content_sha256")
        declared_size = bounded_integer(body["declared_size_bytes"], 1, MAX_ATTACHMENT_BYTES, "declared_size_bytes")
        offset = bounded_integer(body["offset_bytes"], 0, declared_size - 1, "offset_bytes")
        if offset + content_size > declared_size:
            raise InvalidRequest("offset_bytes")
        chunk_index = bounded_integer(body["chunk_index"], 0, MAX_CHUNKS - 1, "chunk_index")
        return {
            "owner_id": owner_id(body["owner_id"]),
            "binding_id": canonical_uuid(body["binding_id"], "binding_id"),
            "source_id": canonical_uuid(body["source_id"], "source_id"),
            "upload_id": canonical_uuid(body["upload_id"], "upload_id"),
            "chunk_id": canonical_uuid(body["chunk_id"], "chunk_id"),
            "revision_id": canonical_uuid(body["revision_id"], "revision_id"),
            "offset_bytes": offset,
            "chunk_index": chunk_index,
            "declared_size_bytes": declared_size,
            "content_base64": content_base64,
            "content_size": content_size,
            "content_sha256": body["content_sha256"],
        }
    if operation == "commit_attachment":
        _exact_keys(
            body,
            {
                "owner_id",
                "binding_id",
                "source_id",
                "upload_id",
                "revision_id",
                "title",
                "media_type",
                "chunk_count",
                "content_size",
                "content_sha256",
            },
            "body",
            optional={"metadata"},
        )
        result = {
            "owner_id": owner_id(body["owner_id"]),
            "binding_id": canonical_uuid(body["binding_id"], "binding_id"),
            "source_id": canonical_uuid(body["source_id"], "source_id"),
            "upload_id": canonical_uuid(body["upload_id"], "upload_id"),
            "revision_id": canonical_uuid(body["revision_id"], "revision_id"),
            "title": bounded_text(body["title"], MAX_TITLE_BYTES, "title"),
            "media_type": media_type(body["media_type"]),
            "chunk_count": bounded_integer(body["chunk_count"], 1, MAX_CHUNKS, "chunk_count"),
            "content_size": bounded_integer(body["content_size"], 1, MAX_ATTACHMENT_BYTES, "content_size"),
            "content_sha256": sha256_string(body["content_sha256"], "content_sha256"),
        }
        if "metadata" in body:
            result["metadata"] = metadata(body["metadata"])
        return result
    if operation == "store_memory":
        _exact_keys(
            body,
            {"owner_id", "binding_id", "memory_id", "revision_id", "content", "content_size", "content_sha256"},
            "body",
        )
        content = bounded_text(body["content"], MAX_CONTENT_BYTES, "content")
        content_bytes = content.encode("utf-8")
        content_size = bounded_integer(body["content_size"], 1, MAX_CONTENT_BYTES, "content_size")
        if content_size != len(content_bytes):
            raise InvalidRequest("content_size")
        if sha256_string(body["content_sha256"], "content_sha256") != hashlib.sha256(content_bytes).hexdigest():
            raise InvalidRequest("content_sha256")
        return {
            "owner_id": owner_id(body["owner_id"]),
            "binding_id": canonical_uuid(body["binding_id"], "binding_id"),
            "memory_id": canonical_uuid(body["memory_id"], "memory_id"),
            "revision_id": canonical_uuid(body["revision_id"], "revision_id"),
            "content": content,
            "content_size": content_size,
            "content_sha256": body["content_sha256"],
        }
    if operation == "delete":
        _exact_keys(body, {"owner_id", "binding_id", "source_id", "revision_id"}, "body")
        return {
            "owner_id": owner_id(body["owner_id"]),
            "binding_id": canonical_uuid(body["binding_id"], "binding_id"),
            "source_id": canonical_uuid(body["source_id"], "source_id"),
            "revision_id": canonical_uuid(body["revision_id"], "revision_id"),
        }
    if operation == "search":
        _exact_keys(body, {"owner_id", "binding_id", "query", "limit"}, "body", optional={"source_ids"})
        limit = body["limit"]
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > MAX_RESULT_LIMIT
        ):
            raise InvalidRequest("limit")
        result = {
            "owner_id": owner_id(body["owner_id"]),
            "binding_id": canonical_uuid(body["binding_id"], "binding_id"),
            "query": bounded_text(body["query"], MAX_QUERY_BYTES, "query"),
            "limit": limit,
        }
        if "source_ids" in body:
            values = body["source_ids"]
            if (
                not isinstance(values, list)
                or not values
                or len(values) > MAX_SOURCE_FILTERS
            ):
                raise InvalidRequest("source_ids")
            parsed = [canonical_uuid(item, "source_ids") for item in values]
            if len(set(parsed)) != len(parsed):
                raise InvalidRequest("source_ids")
            result["source_ids"] = parsed
        return result
    if operation == "status":
        _exact_keys(body, {"owner_id", "binding_id"}, "body", optional={"challenge"})
        result = {
            "owner_id": owner_id(body["owner_id"]),
            "binding_id": canonical_uuid(body["binding_id"], "binding_id"),
        }
        if "challenge" in body:
            challenge = body["challenge"]
            if not isinstance(challenge, dict):
                raise InvalidRequest("challenge")
            _exact_keys(challenge, {"point_id", "source_id", "revision_id", "content_size", "content_sha256"}, "challenge")
            result["challenge"] = {
                "point_id": canonical_uuid(challenge["point_id"], "point_id"),
                "source_id": canonical_uuid(challenge["source_id"], "source_id"),
                "revision_id": canonical_uuid(challenge["revision_id"], "revision_id"),
                "content_size": bounded_integer(challenge["content_size"], 1, MAX_ATTACHMENT_BYTES, "content_size"),
                "content_sha256": sha256_string(challenge["content_sha256"], "content_sha256"),
            }
        return result
    raise InvalidRequest("operation")


def _exact_keys(
    value: dict[str, Any],
    required: set[str],
    field: str,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise InvalidRequest(field)


def bounded_text(value: Any, maximum: int, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidRequest(field)
    if _utf8_length(value, field) > maximum:
        raise InvalidRequest(field)
    return value


def owner_id(value: Any) -> str:
    if not isinstance(value, str) or not value or _utf8_length(value, "owner_id") > 255:
        raise InvalidRequest("owner_id")
    return value


def _utf8_length(value: str, field: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise InvalidRequest(field) from exc


def strict_base64(value: Any) -> tuple[str, bytes]:
    if not isinstance(value, str) or not value or len(value) > 349_528:
        raise InvalidRequest("content_base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InvalidRequest("content_base64") from exc
    if (
        not decoded
        or len(decoded) > MAX_CHUNK_BYTES
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise InvalidRequest("content_base64")
    return value, decoded


def media_type(value: Any) -> str:
    if not isinstance(value, str) or value not in MEDIA_TYPES:
        raise InvalidRequest("media_type")
    return value


def bounded_integer(value: Any, minimum: int, maximum: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise InvalidRequest(field)
    return value


def sha256_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise InvalidRequest(field)
    return value


def metadata(value: Any) -> dict[str, str | int | bool]:
    if not isinstance(value, dict) or len(value) > 32:
        raise InvalidRequest("metadata")
    result: dict[str, str | int | bool] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _METADATA_KEY.fullmatch(key):
            raise InvalidRequest("metadata")
        if isinstance(item, str):
            result[key] = bounded_text(item, 1_024, "metadata")
        elif isinstance(item, bool):
            result[key] = item
        elif isinstance(item, int) and -(2**53) < item < 2**53:
            result[key] = item
        else:
            raise InvalidRequest("metadata")
    return result


def recv_frame(sock: Any) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_REQUEST_BYTES:
        raise InvalidRequest("frame")
    return _recv_exact(sock, length)


def send_frame(sock: Any, value: dict[str, Any]) -> None:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RuntimeError("response is not finite JSON") from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("response exceeds fixed limit")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock: Any, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise InvalidRequest("frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
