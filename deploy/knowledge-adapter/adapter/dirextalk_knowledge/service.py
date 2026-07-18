"""Closed Knowledge operations over embedding, Qdrant, and idempotency."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .embedding import E5Embedder, model_status

from .errors import Conflict, DependencyUnavailable, InvalidContent, PersistenceMismatch
from .ledger import Ledger
from .protocol import MAX_ATTACHMENT_BYTES, MAX_CONTENT_BYTES, Request, is_canonical_uuid
from .qdrant import QdrantClient
from .staging import StagingStore

POINT_NAMESPACE = uuid.UUID("a8ae6ba7-16cf-4f87-9858-0e13dcf06d89")
INDEX_SEGMENT_BYTES = 2_048
MAX_ATTACHMENT_SEGMENTS = 32_769
MAX_MEMORY_SEGMENTS = 512


class KnowledgeService:
    def __init__(
        self,
        embedder: E5Embedder,
        qdrant: QdrantClient,
        ledger: Ledger,
        staging: StagingStore,
    ) -> None:
        self._embedder = embedder
        self._qdrant = qdrant
        self._ledger = ledger
        self._staging = staging

    def initialize(self) -> None:
        self._qdrant.ensure_collection()

    def handle(self, request: Request) -> dict[str, Any]:
        operation = request.operation
        if operation == "stage_chunk":
            return self._ledger.execute(request, lambda: self._stage_chunk(request.body))
        if operation == "commit_attachment":
            result = self._ledger.execute(
                request, lambda: self._commit_attachment(request.body)
            )
            self._staging.delete_upload(
                request.body["owner_id"],
                request.body["binding_id"],
                request.body["upload_id"],
            )
            return result
        if operation == "store_memory":
            return self._ledger.execute(request, lambda: self._store_memory(request.body))
        if operation == "delete":
            return self._ledger.execute(request, lambda: self._delete(request.body))
        if operation == "search":
            return self._search(request.body)
        if operation == "status":
            result = {
                "owner_id": request.body["owner_id"],
                "binding_id": request.body["binding_id"],
            }
            result.update(model_status())
            qdrant_status = self._qdrant.status()
            result.update(qdrant_status)
            result["ready"] = qdrant_status["status"] in {"green", "yellow"}
            if "challenge" in request.body:
                result.update(self._persistence_challenge(request.body))
            return result
        raise RuntimeError("validated operation not implemented")

    def _stage_chunk(self, body: dict[str, Any]) -> dict[str, Any]:
        self._staging.stage(body)
        return {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "source_id": body["source_id"],
            "upload_id": body["upload_id"],
            "chunk_id": body["chunk_id"],
            "revision_id": body["revision_id"],
            "offset_bytes": body["offset_bytes"],
            "chunk_index": body["chunk_index"],
            "declared_size_bytes": body["declared_size_bytes"],
            "content_size": body["content_size"],
            "content_sha256": body["content_sha256"],
            "staged": True,
        }

    def _commit_attachment(self, body: dict[str, Any]) -> dict[str, Any]:
        chunks = self._staging.load(body)
        content_bytes = b"".join(chunks)
        if (
            len(content_bytes) != body["content_size"]
            or hashlib.sha256(content_bytes).hexdigest()
            != body["content_sha256"]
        ):
            raise Conflict("content_sha256")
        try:
            content = content_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise InvalidContent() from exc
        if body["media_type"] == "application/json":
            try:
                json.loads(
                    content,
                    parse_constant=_reject_json_constant,
                    object_pairs_hook=_unique_json_object,
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise InvalidContent() from exc
        text = body["title"] + "\n\n" + content
        payload = {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "source_id": body["source_id"],
            "revision_id": body["revision_id"],
            "kind": "attachment",
            "media_type": body["media_type"],
            "title": body["title"],
            "content_size": body["content_size"],
            "content_sha256": body["content_sha256"],
        }
        if "metadata" in body:
            payload["metadata"] = body["metadata"]
        indexed_segments, point_id = self._index_content(
            body["owner_id"], body["binding_id"], body["source_id"], text, payload
        )
        if indexed_segments < 1 or indexed_segments > MAX_ATTACHMENT_SEGMENTS:
            raise DependencyUnavailable("index_segments")
        return {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "point_id": point_id,
            "source_id": body["source_id"],
            "upload_id": body["upload_id"],
            "revision_id": body["revision_id"],
            "kind": "attachment",
            "chunk_count": body["chunk_count"],
            "content_size": body["content_size"],
            "content_sha256": body["content_sha256"],
            "indexed_segment_count": indexed_segments,
        }

    def _store_memory(self, body: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "source_id": body["memory_id"],
            "revision_id": body["revision_id"],
            "kind": "memory",
            "media_type": "text/plain",
            "content_size": body["content_size"],
            "content_sha256": body["content_sha256"],
        }
        indexed_segments, point_id = self._index_content(
            body["owner_id"],
            body["binding_id"],
            body["memory_id"],
            body["content"],
            payload,
        )
        if indexed_segments < 1 or indexed_segments > MAX_MEMORY_SEGMENTS:
            raise DependencyUnavailable("index_segments")
        return {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "point_id": point_id,
            "source_id": body["memory_id"],
            "revision_id": body["revision_id"],
            "kind": "memory",
            "content_size": body["content_size"],
            "content_sha256": body["content_sha256"],
            "indexed_segment_count": indexed_segments,
        }

    def _delete(self, body: dict[str, Any]) -> dict[str, Any]:
        self._qdrant.delete(body["owner_id"], body["binding_id"], body["source_id"])
        return {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "source_id": body["source_id"],
            "revision_id": body["revision_id"],
            "deleted": True,
        }

    def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        points = self._qdrant.search(
            self._embedder.query(body["query"]),
            body["limit"],
            body["owner_id"],
            body["binding_id"],
            body.get("source_ids"),
        )
        results: list[dict[str, Any]] = []
        for point in points:
            payload = _validated_search_point(point, body)
            content, truncated = _bounded_excerpt(payload["content"])
            results.append(
                {
                    "point_id": point["id"],
                    "owner_id": payload["owner_id"],
                    "binding_id": payload["binding_id"],
                    "source_id": payload["source_id"],
                    "revision_id": payload["revision_id"],
                    "kind": payload["kind"],
                    "content": content,
                    "content_truncated": truncated,
                    "score": _normalize_cosine(point["score"]),
                    "content_size": payload["content_size"],
                    "content_sha256": payload["content_sha256"],
                }
            )
        return {"results": results}

    def _persistence_challenge(self, body: dict[str, Any]) -> dict[str, Any]:
        challenge = body["challenge"]
        point = self._qdrant.get_point(challenge["point_id"])
        if (
            not isinstance(point, dict)
            or point.get("id") != challenge["point_id"]
            or not isinstance(point.get("payload"), dict)
        ):
            raise PersistenceMismatch()
        payload = point["payload"]
        expected = {
            "owner_id": body["owner_id"],
            "binding_id": body["binding_id"],
            "source_id": challenge["source_id"],
            "revision_id": challenge["revision_id"],
            "content_size": challenge["content_size"],
            "content_sha256": challenge["content_sha256"],
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise PersistenceMismatch()
        return {
            "persistence": {
                "point_id": challenge["point_id"],
                "source_id": challenge["source_id"],
                "revision_id": challenge["revision_id"],
                "content_size": challenge["content_size"],
                "content_sha256": challenge["content_sha256"],
                "verified": True,
            }
        }

    def _index_content(
        self,
        owner_id: str,
        binding_id: str,
        source_id: str,
        text: str,
        base_payload: dict[str, Any],
    ) -> tuple[int, str]:
        segments = _split_text(text)
        self._qdrant.delete(owner_id, binding_id, source_id)
        batch: list[tuple[str, list[float], dict[str, Any]]] = []
        first_point_id = ""
        for index, segment in enumerate(segments):
            point_id = _point_id(owner_id, binding_id, source_id, index)
            if not first_point_id:
                first_point_id = point_id
            payload = dict(base_payload)
            if index > 0:
                for field in ("media_type", "metadata", "title"):
                    payload.pop(field, None)
            payload["content"] = segment
            payload["segment_index"] = index
            payload["segment_count"] = len(segments)
            batch.append((point_id, self._embedder.passage(segment), payload))
            if len(batch) == 64:
                self._qdrant.upsert_many(batch)
                batch = []
        if batch:
            self._qdrant.upsert_many(batch)
        return len(segments), first_point_id


def _bounded_excerpt(value: str, maximum: int = 16_384) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value, False
    truncated = encoded[:maximum]
    while True:
        try:
            return truncated.decode("utf-8", errors="strict"), True
        except UnicodeDecodeError as exc:
            truncated = truncated[: exc.start]


def _validated_search_point(
    point: dict[str, Any], body: dict[str, Any]
) -> dict[str, Any]:
    if (
        not isinstance(point, dict)
        or not is_canonical_uuid(point.get("id"))
        or not isinstance(point.get("payload"), dict)
    ):
        raise DependencyUnavailable("qdrant_response")
    payload = point["payload"]
    string_fields = (
        "owner_id",
        "binding_id",
        "source_id",
        "revision_id",
        "kind",
        "content",
        "content_sha256",
    )
    if not all(isinstance(payload.get(field), str) for field in string_fields):
        raise DependencyUnavailable("qdrant_response")
    if (
        payload["owner_id"] != body["owner_id"]
        or payload["binding_id"] != body["binding_id"]
        or not is_canonical_uuid(payload["source_id"])
        or not is_canonical_uuid(payload["revision_id"])
        or payload["kind"] not in {"attachment", "memory"}
        or len(payload["content_sha256"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in payload["content_sha256"]
        )
    ):
        raise DependencyUnavailable("qdrant_response")
    if body.get("source_ids") and payload["source_id"] not in body["source_ids"]:
        raise DependencyUnavailable("qdrant_response")
    maximum_size = (
        MAX_CONTENT_BYTES if payload["kind"] == "memory" else MAX_ATTACHMENT_BYTES
    )
    content_size = payload.get("content_size")
    segment_index = payload.get("segment_index")
    segment_count = payload.get("segment_count")
    maximum_segments = (
        MAX_MEMORY_SEGMENTS
        if payload["kind"] == "memory"
        else MAX_ATTACHMENT_SEGMENTS
    )
    if (
        not isinstance(content_size, int)
        or isinstance(content_size, bool)
        or content_size < 1
        or content_size > maximum_size
        or not isinstance(segment_index, int)
        or isinstance(segment_index, bool)
        or not isinstance(segment_count, int)
        or isinstance(segment_count, bool)
        or segment_count < 1
        or segment_count > maximum_segments
        or segment_index < 0
        or segment_index >= segment_count
    ):
        raise DependencyUnavailable("qdrant_response")
    try:
        content_bytes = payload["content"].encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise DependencyUnavailable("qdrant_response") from exc
    if not content_bytes or len(content_bytes) > INDEX_SEGMENT_BYTES + 3:
        raise DependencyUnavailable("qdrant_response")
    return payload


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-finite number")


def _normalize_cosine(value: float) -> float:
    epsilon = 1e-6
    if value < -1.0 - epsilon or value > 1.0 + epsilon:
        raise DependencyUnavailable("qdrant_response")
    bounded = min(1.0, max(-1.0, value))
    return (bounded + 1.0) / 2.0


def _point_id(owner_id: str, binding_id: str, source_id: str, index: int) -> str:
    name = json.dumps(
        [owner_id, binding_id, source_id, index],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return str(uuid.uuid5(POINT_NAMESPACE, name))


def _split_text(value: str, maximum_bytes: int = INDEX_SEGMENT_BYTES) -> list[str]:
    if maximum_bytes < 4:
        raise ValueError("segment bound is too small")
    segments: list[str] = []
    current: list[str] = []
    size = 0
    for character in value:
        encoded_size = len(character.encode("utf-8"))
        if current and size >= maximum_bytes:
            segments.append("".join(current))
            current = []
            size = 0
        current.append(character)
        size += encoded_size
    if current:
        segments.append("".join(current))
    if not segments:
        raise InvalidContent()
    return segments
