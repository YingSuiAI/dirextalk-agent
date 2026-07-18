#!/usr/bin/python3.12
"""Bind the exact deployable Knowledge artifacts into one small research manifest."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

SCHEMA = "dirextalk.knowledge.release/v1"
ORIGIN = "https://artifacts.y1.dirextalk.ai"
ARTIFACTS = (
    ("knowledge-installer-linux-amd64", "dirextalk-knowledge-installer", "application/octet-stream", "Proprietary"),
    ("qdrant-linux-amd64", "qdrant-x86_64-unknown-linux-musl.tar.gz", "application/gzip", "Apache-2.0"),
    ("multilingual-e5-small-bundle", "multilingual-e5-small.tar.gz", "application/gzip", "MIT"),
    ("knowledge-adapter-bundle", "dirextalk-knowledge-adapter.tar.gz", "application/gzip", "Proprietary"),
    ("knowledge-provenance-v1", "provenance-v1.json", "application/json", "Proprietary"),
)


class ReleaseError(Exception):
    """The supplied release set is incomplete, ambiguous, or unsafe."""


def file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def build_release_manifest(inputs: list[Path], output: Path) -> tuple[int, str]:
    if len(inputs) != len(ARTIFACTS):
        raise ReleaseError("the exact five Knowledge release artifacts are required")
    output = output.resolve()
    if output.exists() or output.name != "dirextalk-knowledge-release.v1.json":
        raise ReleaseError("invalid or existing release manifest output")
    artifacts = []
    for candidate, (artifact_id, name, media_type, license_name) in zip(inputs, ARTIFACTS, strict=True):
        candidate = candidate.resolve(strict=True)
        if candidate.is_symlink() or not candidate.is_file() or candidate.name != name:
            raise ReleaseError("release artifact name or type mismatch")
        size, sha256 = file_digest(candidate)
        if size < 1:
            raise ReleaseError("empty release artifact")
        artifacts.append(
            {
                "id": artifact_id,
                "name": name,
                "size_bytes": size,
                "sha256": sha256,
                "media_type": media_type,
                "license": license_name,
                "url": f"{ORIGIN}/sha256/{sha256}/{name}",
            }
        )
    value = {
        "schema_version": SCHEMA,
        "release_id": "dirextalk-knowledge-v1",
        "embedding_profile_id": "local-multilingual-e5-small-v1",
        "artifacts": artifacts,
        "runtime": {
            "artifact_root": "/usr/local/share/dirextalk-worker/artifacts",
            "persistent_volume_mount": "/var/lib/dirextalk-knowledge",
            "qdrant_api_key_secret_path": "/etc/dirextalk-service-secrets/qdrant-api-key",
            "adapter_socket": "/run/dirextalk-knowledge/adapter.sock",
            "installer_commands": [
                "install-v1",
                "restart-v1",
                "semantic-probe-v1",
                "stop-v1",
                "backup-v1",
                "restore-v1",
                "upgrade-v1",
                "rollback-v1",
                "destroy-v1",
            ],
        },
    }
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    created = False
    old_umask = os.umask(0o022)
    try:
        with output.open("xb") as handle:
            created = True
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if created:
            try:
                output.unlink()
            except OSError:
                pass
        raise
    finally:
        os.umask(old_umask)
    return file_digest(output)


def main() -> None:
    if len(sys.argv) != 7:
        raise SystemExit(
            "usage: build_release_manifest.py INSTALLER QDRANT MODEL_BUNDLE ADAPTER_BUNDLE PROVENANCE OUTPUT_JSON"
        )
    try:
        size, sha256 = build_release_manifest([Path(value) for value in sys.argv[1:6]], Path(sys.argv[6]))
    except ReleaseError as error:
        raise SystemExit(str(error)) from error
    print(json.dumps({"path": str(Path(sys.argv[6]).resolve()), "size": size, "sha256": sha256}, sort_keys=True))


if __name__ == "__main__":
    main()
