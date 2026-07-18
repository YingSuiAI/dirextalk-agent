#!/usr/bin/python3.12
"""Fail-closed real-model release lane; never downloads or records a golden."""

import hashlib
import json
import math
import struct
import sys

sys.path.extend(
    [
        "/opt/dirextalk/knowledge/current/adapter",
        "/opt/dirextalk/knowledge/current/pydeps",
    ]
)

from dirextalk_knowledge import MODEL_REVISION, VECTOR_DIMENSIONS  # noqa: E402
from dirextalk_knowledge.embedding import production_embedder  # noqa: E402

GOLDEN_PATH = "/usr/local/share/dirextalk-worker/artifacts/release-golden-v1.json"


def vector_digest(vector: list[float]) -> str:
    payload = b"".join(struct.pack("<f", value) for value in vector)
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    with open(GOLDEN_PATH, "r", encoding="utf-8") as handle:
        golden = json.load(handle)
    if set(golden) != {"schema_version", "model_revision", "cases"}:
        raise SystemExit("invalid golden schema")
    if golden["schema_version"] != 1 or golden["model_revision"] != MODEL_REVISION:
        raise SystemExit("golden revision mismatch")
    cases = golden["cases"]
    if not isinstance(cases, list) or len(cases) < 2 or len(cases) > 16:
        raise SystemExit("invalid golden cases")
    embedder = production_embedder()
    for case in cases:
        if set(case) != {"kind", "text", "sha256_f32le"}:
            raise SystemExit("invalid golden case")
        if (
            not isinstance(case["text"], str)
            or not case["text"]
            or len(case["text"].encode("utf-8")) > 16_384
            or not isinstance(case["sha256_f32le"], str)
            or len(case["sha256_f32le"]) != 64
            or any(character not in "0123456789abcdef" for character in case["sha256_f32le"])
        ):
            raise SystemExit("invalid golden value")
        if case["kind"] == "query":
            vector = embedder.query(case["text"])
        elif case["kind"] == "passage":
            vector = embedder.passage(case["text"])
        else:
            raise SystemExit("invalid golden kind")
        if (
            len(vector) != VECTOR_DIMENSIONS
            or not all(math.isfinite(value) for value in vector)
            or abs(sum(value * value for value in vector) - 1.0) > 1e-5
            or vector_digest(vector) != case["sha256_f32le"]
        ):
            raise SystemExit("golden mismatch")
    print("release golden verified")


if __name__ == "__main__":
    main()
