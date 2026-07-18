#!/usr/bin/python3.12
"""Generate canonical Knowledge provenance for one sealed adapter bundle."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_MANIFEST = ROOT / "provenance/model-files-v1.json"
ADAPTER_VERSION = "knowledge-adapter-v1"
QDRANT = {
    "name": "qdrant-x86_64-unknown-linux-musl.tar.gz",
    "version": "1.18.3",
    "size": 30_745_357,
    "sha256": "b4faedcdf8c9577bf1c8f2ab9b454636b87e056c116c99d49bd4f9fb2e634285",
}


class ReleaseError(Exception):
    """The release input is unsafe or does not match the fixed contract."""


def file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def build_provenance(adapter_bundle: Path, output: Path, model_manifest_path: Path = MODEL_MANIFEST) -> tuple[int, str]:
    adapter_bundle = adapter_bundle.resolve(strict=True)
    output = output.resolve()
    if adapter_bundle.is_symlink() or not adapter_bundle.is_file() or adapter_bundle.name != "dirextalk-knowledge-adapter.tar.gz" or output.exists():
        raise ReleaseError("invalid adapter bundle or existing output")
    try:
        model = json.loads(model_manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("invalid model provenance") from error
    if set(model) != {"model", "revision", "files"} or model["model"] != "intfloat/multilingual-e5-small" or not isinstance(model["files"], list):
        raise ReleaseError("invalid model provenance")
    adapter_size, adapter_sha256 = file_digest(adapter_bundle)
    value = {
        "schema_version": 1,
        "qdrant": QDRANT,
        "model": {
            "repository": model["model"],
            "revision": model["revision"],
            "files": model["files"],
        },
        "adapter_bundle": {
            "name": adapter_bundle.name,
            "version": ADAPTER_VERSION,
            "size": adapter_size,
            "sha256": adapter_sha256,
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
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_provenance.py ADAPTER_BUNDLE OUTPUT_JSON")
    try:
        size, sha256 = build_provenance(Path(sys.argv[1]), Path(sys.argv[2]))
    except ReleaseError as error:
        raise SystemExit(str(error)) from error
    print(json.dumps({"path": str(Path(sys.argv[2]).resolve()), "size": size, "sha256": sha256}, sort_keys=True))


if __name__ == "__main__":
    main()
