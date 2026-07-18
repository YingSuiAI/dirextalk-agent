#!/usr/bin/python3.12
"""Build the deterministic multilingual-e5-small archive from pinned files."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "provenance/model-files-v1.json"
MAX_MODEL_FILE = 512 * 1024 * 1024
MAX_MODEL_TOTAL = 512 * 1024 * 1024
REVIEWED_NON_MODEL_INPUTS = {"qdrant-x86_64-unknown-linux-musl.tar.gz"}


class ReleaseError(Exception):
    """The reviewed release input set is incomplete or has drifted."""


def file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def load_manifest(path: Path) -> list[dict[str, object]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("invalid model file manifest") from error
    if set(value) != {"model", "revision", "files"} or not isinstance(value["files"], list) or not value["files"]:
        raise ReleaseError("invalid model file manifest")
    seen_paths: set[str] = set()
    seen_sources: set[str] = set()
    total = 0
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ReleaseError("invalid model file manifest")
        member = item["path"]
        size = item["size"]
        sha256 = item["sha256"]
        if not isinstance(member, str) or not isinstance(size, int) or isinstance(size, bool) or not isinstance(sha256, str):
            raise ReleaseError("invalid model file manifest")
        pure = PurePosixPath(member)
        source_name = pure.name
        if (
            pure.is_absolute()
            or not pure.parts
            or ".." in pure.parts
            or "" in pure.parts
            or "\\" in member
            or member in seen_paths
            or source_name in seen_sources
            or size < 1
            or size > MAX_MODEL_FILE
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise ReleaseError("invalid model file manifest")
        total += size
        if total > MAX_MODEL_TOTAL:
            raise ReleaseError("model files exceed release bound")
        seen_paths.add(member)
        seen_sources.add(source_name)
    return value["files"]


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    info.mode = 0o755 if directory else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    return info


def build_model_bundle(source_directory: Path, output: Path, manifest_path: Path = MANIFEST_PATH) -> tuple[int, str]:
    source_directory = source_directory.resolve(strict=True)
    output = output.resolve()
    files = load_manifest(manifest_path)
    if not source_directory.is_dir() or output.exists():
        raise ReleaseError("invalid model input or existing output")
    expected_names = {PurePosixPath(str(item["path"])).name for item in files}
    actual_names: set[str] = set()
    for candidate in source_directory.iterdir():
        if candidate.is_symlink() or not candidate.is_file():
            raise ReleaseError("model input directory contains an unreviewed member")
        actual_names.add(candidate.name)
    if actual_names - REVIEWED_NON_MODEL_INPUTS != expected_names:
        raise ReleaseError("model input set does not exactly match provenance")
    for item in files:
        candidate = source_directory / PurePosixPath(str(item["path"])).name
        size, sha256 = file_digest(candidate)
        if size != item["size"] or sha256 != item["sha256"]:
            raise ReleaseError("model file provenance mismatch")

    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    created = False
    old_umask = os.umask(0o022)
    try:
        with output.open("xb") as raw:
            created = True
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", compresslevel=1, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    directories = sorted({parent.as_posix() for item in files for parent in PurePosixPath(str(item["path"])).parents if parent.as_posix() != "."})
                    for directory in directories:
                        archive.addfile(_tar_info(directory, directory=True))
                    for item in sorted(files, key=lambda value: str(value["path"])):
                        member = str(item["path"])
                        candidate = source_directory / PurePosixPath(member).name
                        with candidate.open("rb") as handle:
                            archive.addfile(_tar_info(member, directory=False, size=int(item["size"])), handle)
            raw.flush()
            os.fsync(raw.fileno())
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
        raise SystemExit("usage: build_model_bundle.py MODEL_FILE_DIRECTORY OUTPUT_TAR")
    try:
        size, sha256 = build_model_bundle(Path(sys.argv[1]), Path(sys.argv[2]))
    except ReleaseError as error:
        raise SystemExit(str(error)) from error
    print(json.dumps({"path": str(Path(sys.argv[2]).resolve()), "size": size, "sha256": sha256}, sort_keys=True))


if __name__ == "__main__":
    main()
