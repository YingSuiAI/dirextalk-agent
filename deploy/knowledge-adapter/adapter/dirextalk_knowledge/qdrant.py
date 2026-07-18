"""Narrow fixed-destination Qdrant REST client."""

from __future__ import annotations

import http.client
import json
import math
import os
import ssl
import stat
from pathlib import Path
from typing import Any, Protocol

from . import VECTOR_DIMENSIONS
from .errors import DependencyUnavailable
from .protocol import is_canonical_uuid

QDRANT_HOST = "127.0.0.1"
QDRANT_PORT = 6333
QDRANT_COLLECTION = "dirextalk_knowledge_v1"
QDRANT_API_KEY_PATH = Path(
    "/var/lib/dirextalk-knowledge/secrets/qdrant-api-key"
)
QDRANT_CA_PATH = Path("/var/lib/dirextalk-knowledge/tls/ca.crt")
MAX_QDRANT_RESPONSE_BYTES = 1_048_576


class Transport(Protocol):
    def request(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        ...


class HTTPSLoopbackTransport:
    def __init__(self) -> None:
        _require_protected_regular_file(QDRANT_CA_PATH, maximum_mode=0o644)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cafile=str(QDRANT_CA_PATH))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        self._context = context

    def request(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        if method not in {"GET", "PUT", "POST"} or not path.startswith(
            "/collections/dirextalk_knowledge_v1"
        ):
            raise DependencyUnavailable("qdrant_request")
        api_key = _read_api_key(QDRANT_API_KEY_PATH)
        fixed_headers = {"Accept": "application/json", "api-key": api_key}
        fixed_headers.update(headers)
        connection = http.client.HTTPSConnection(
            QDRANT_HOST,
            QDRANT_PORT,
            timeout=10.0,
            context=self._context,
        )
        try:
            connection.request(method, path, body=body, headers=fixed_headers)
            response = connection.getresponse()
            length = response.getheader("Content-Length")
            if length is not None and int(length) > MAX_QDRANT_RESPONSE_BYTES:
                raise DependencyUnavailable("qdrant_response")
            payload = response.read(MAX_QDRANT_RESPONSE_BYTES + 1)
            if len(payload) > MAX_QDRANT_RESPONSE_BYTES:
                raise DependencyUnavailable("qdrant_response")
            return response.status, payload
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            raise DependencyUnavailable("qdrant") from exc
        finally:
            connection.close()


class QdrantClient:
    def __init__(self, transport: Transport | None = None) -> None:
        self._transport = transport or HTTPSLoopbackTransport()

    def ensure_collection(self) -> None:
        status, payload = self._request("GET", self._collection_path())
        if status == 404:
            status, payload = self._request(
                "PUT",
                self._collection_path(),
                {"vectors": {"size": VECTOR_DIMENSIONS, "distance": "Cosine"}},
            )
            if status not in (200, 201):
                raise DependencyUnavailable("qdrant_collection")
            self._ensure_payload_indexes()
            return
        if status != 200:
            raise DependencyUnavailable("qdrant_collection")
        result = _json_object(payload).get("result")
        try:
            vectors = result["config"]["params"]["vectors"]
            size = vectors["size"]
            distance = vectors["distance"]
        except (KeyError, TypeError) as exc:
            raise DependencyUnavailable("qdrant_schema") from exc
        if size != VECTOR_DIMENSIONS or distance != "Cosine":
            raise DependencyUnavailable("qdrant_schema")
        self._ensure_payload_indexes()

    def _ensure_payload_indexes(self) -> None:
        for field in ("owner_id", "binding_id", "source_id"):
            status, _ = self._request(
                "PUT",
                self._collection_path("/index?wait=true"),
                {"field_name": field, "field_schema": "keyword"},
            )
            if status not in (200, 201):
                raise DependencyUnavailable("qdrant_schema")

    def upsert(
        self, point_id: str, vector: list[float], payload: dict[str, Any]
    ) -> None:
        self.upsert_many([(point_id, vector, payload)])

    def upsert_many(
        self, points: list[tuple[str, list[float], dict[str, Any]]]
    ) -> None:
        if not points or len(points) > 64:
            raise DependencyUnavailable("qdrant_request")
        encoded_points: list[dict[str, Any]] = []
        point_ids: set[str] = set()
        for point_id, vector, payload in points:
            if (
                point_id in point_ids
                or len(vector) != VECTOR_DIMENSIONS
                or not all(map(math.isfinite, vector))
            ):
                raise DependencyUnavailable("vector")
            point_ids.add(point_id)
            encoded_points.append(
                {"id": point_id, "vector": vector, "payload": payload}
            )
        status, _ = self._request(
            "PUT",
            self._collection_path("/points?wait=true"),
            {"points": encoded_points},
        )
        if status not in (200, 201):
            raise DependencyUnavailable("qdrant_upsert")

    def delete(self, owner_id: str, binding_id: str, source_id: str) -> None:
        status, _ = self._request(
            "POST",
            self._collection_path("/points/delete?wait=true"),
            {
                "filter": {
                    "must": [
                        {"key": "owner_id", "match": {"value": owner_id}},
                        {"key": "binding_id", "match": {"value": binding_id}},
                        {"key": "source_id", "match": {"value": source_id}}
                    ]
                }
            },
        )
        if status != 200:
            raise DependencyUnavailable("qdrant_delete")

    def search(
        self,
        vector: list[float],
        limit: int,
        owner_id: str,
        binding_id: str,
        source_ids: list[str] | None,
    ) -> list[dict[str, Any]]:
        request: dict[str, Any] = {
            "query": vector,
            "limit": limit,
            "with_payload": True,
            "with_vector": False,
        }
        must = [
            {"key": "owner_id", "match": {"value": owner_id}},
            {"key": "binding_id", "match": {"value": binding_id}},
        ]
        if source_ids:
            must.append({"key": "source_id", "match": {"any": source_ids}})
        request["filter"] = {"must": must}
        status, payload = self._request(
            "POST", self._collection_path("/points/query"), request
        )
        if status != 200:
            raise DependencyUnavailable("qdrant_search")
        value = _json_object(payload).get("result")
        if isinstance(value, dict):
            value = value.get("points")
        if not isinstance(value, list) or len(value) > limit:
            raise DependencyUnavailable("qdrant_response")
        return [_validate_point(item, with_score=True) for item in value]

    def get_point(self, point_id: str) -> dict[str, Any] | None:
        status, payload = self._request(
            "GET", self._collection_path("/points/" + point_id)
        )
        if status == 404:
            return None
        if status != 200:
            raise DependencyUnavailable("qdrant_read")
        value = _json_object(payload).get("result")
        return _validate_point(value, with_score=False)

    def status(self) -> dict[str, Any]:
        status, payload = self._request("GET", self._collection_path())
        if status != 200:
            raise DependencyUnavailable("qdrant_status")
        value = _json_object(payload).get("result")
        if not isinstance(value, dict):
            raise DependencyUnavailable("qdrant_response")
        state = value.get("status")
        if state not in {"green", "yellow", "red", "grey"}:
            raise DependencyUnavailable("qdrant_response")
        return {"collection": QDRANT_COLLECTION, "status": state}

    def _collection_path(self, suffix: str = "") -> str:
        return "/collections/" + QDRANT_COLLECTION + suffix

    def _request(
        self, method: str, path: str, value: dict[str, Any] | None = None
    ) -> tuple[int, bytes]:
        body = None
        headers: dict[str, str] = {}
        if value is not None:
            try:
                body = json.dumps(
                    value,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            except (ValueError, TypeError) as exc:
                raise DependencyUnavailable("qdrant_request") from exc
            headers["Content-Type"] = "application/json"
        return self._transport.request(method, path, body, headers)


def _read_api_key(path: Path) -> str:
    _require_protected_regular_file(path, maximum_mode=0o640)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            value = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DependencyUnavailable("qdrant_credentials") from exc
    if len(value) < 32 or len(value) > 256 or not all(
        48 <= item <= 57 or 65 <= item <= 90 or 97 <= item <= 122 or item in (45, 95)
        for item in value
    ):
        raise DependencyUnavailable("qdrant_credentials")
    return value.decode("ascii")


def _require_protected_regular_file(path: Path, maximum_mode: int) -> None:
    try:
        result = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DependencyUnavailable("qdrant_files") from exc
    if (
        not stat.S_ISREG(result.st_mode)
        or result.st_uid != 0
        or result.st_mode & ~maximum_mode & 0o777
    ):
        raise DependencyUnavailable("qdrant_files")


def _json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DependencyUnavailable("qdrant_response") from exc
    if not isinstance(value, dict):
        raise DependencyUnavailable("qdrant_response")
    return value


def _validate_point(value: Any, with_score: bool) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("payload"), dict):
        raise DependencyUnavailable("qdrant_response")
    result = {"id": value.get("id"), "payload": value["payload"]}
    if not is_canonical_uuid(result["id"]):
        raise DependencyUnavailable("qdrant_response")
    if with_score:
        score = value.get("score")
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            raise DependencyUnavailable("qdrant_response")
        score = float(score)
        if not math.isfinite(score):
            raise DependencyUnavailable("qdrant_response")
        result["score"] = score
    return result
