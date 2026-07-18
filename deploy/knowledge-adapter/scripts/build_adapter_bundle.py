#!/usr/bin/python3.12
"""Build a deterministic sealed adapter bundle from the exact locked wheels."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "dependencies/python.lock.json"
MAX_WHEEL_MEMBER = 128 * 1024 * 1024
MAX_WHEEL_TOTAL = 512 * 1024 * 1024


def digest(path: Path) -> tuple[int, str]:
    result = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            result.update(chunk)
    return size, result.hexdigest()


def add_tree(archive: tarfile.TarFile, source: Path, prefix: str) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise SystemExit("source symlink is not allowed")
        relative = path.relative_to(source).as_posix()
        parts = PurePosixPath(relative).parts
        if any(part == "__pycache__" or part.startswith(".") for part in parts):
            raise SystemExit("unreviewed adapter source member")
        if path.is_file() and path.suffix != ".py":
            raise SystemExit("unreviewed adapter source member")
        name = prefix + "/" + relative
        info = archive.gettarinfo(str(path), arcname=name)
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mtime = 0
        info.mode = 0o755 if path.is_dir() else 0o644
        if path.is_file():
            with path.open("rb") as handle:
                archive.addfile(info, handle)
        elif path.is_dir():
            archive.addfile(info)
        else:
            raise SystemExit("unsupported source file")


def add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(payload))


def add_wheel(
    archive: tarfile.TarFile,
    wheel: Path,
    seen: set[str],
    expanded_total: list[int],
) -> None:
    with zipfile.ZipFile(wheel) as source_archive:
        for member in sorted(source_archive.infolist(), key=lambda item: item.filename):
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (
                not member.filename
                or path.is_absolute()
                or ".." in path.parts
                or "" in path.parts
                or "\\" in member.filename
                or member.filename in seen
                or member.file_size > MAX_WHEEL_MEMBER
                or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)))
            ):
                raise SystemExit("unsafe or duplicate wheel member")
            seen.add(member.filename)
            expanded_total[0] += member.file_size
            if expanded_total[0] > MAX_WHEEL_TOTAL:
                raise SystemExit("wheel content exceeds limit")
            name = "pydeps/" + member.filename.rstrip("/")
            info = tarfile.TarInfo(name)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            if member.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
                continue
            info.mode = 0o644
            info.size = member.file_size
            with source_archive.open(member) as source:
                archive.addfile(info, source)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_adapter_bundle.py WHEEL_DIRECTORY OUTPUT_TAR")
    wheel_directory = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    if not wheel_directory.is_dir() or output.exists():
        raise SystemExit("invalid input or existing output")
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if set(lock) != {"schema_version", "python", "platform", "packages"}:
        raise SystemExit("invalid dependency lock")
    expected_names = {item["filename"] for item in lock["packages"]}
    actual_names = {path.name for path in wheel_directory.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise SystemExit("wheel set does not exactly match lock")

    for package in lock["packages"]:
        wheel = wheel_directory / package["filename"]
        size, sha256 = digest(wheel)
        if size != package["size"] or sha256 != package["sha256"]:
            raise SystemExit("wheel provenance mismatch")

    sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "dirextalk-knowledge-adapter-python-v1",
            "documentNamespace": "https://dirextalk.ai/sbom/knowledge-adapter/v1",
            "creationInfo": {
                "created": "1970-01-01T00:00:00Z",
                "creators": ["Tool: scripts/build_adapter_bundle.py"],
            },
            "packages": [
                {
                    "name": item["name"],
                    "SPDXID": "SPDXRef-Package-" + item["name"],
                    "versionInfo": item["version"],
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": item["sha256"]}
                    ],
                }
                for item in lock["packages"]
            ],
    }
    manifest = {
            "schema_version": 1,
            "python": "3.12",
            "entrypoint": "adapter/main.py",
            "dependencies": [
                {"name": item["name"], "version": item["version"]}
                for item in lock["packages"]
            ],
    }
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    old_umask = os.umask(0o022)
    try:
        with output.open("xb") as raw:
            # Fast gzip keeps the sealed native payload deterministic without
            # making the offline release step CPU-bound.
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", compresslevel=1, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    add_tree(archive, ROOT / "adapter", "adapter")
                    add_bytes(archive, "pydeps/.sealed", b"")
                    seen: set[str] = set()
                    expanded_total = [0]
                    for package in lock["packages"]:
                        add_wheel(
                            archive,
                            wheel_directory / package["filename"],
                            seen,
                            expanded_total,
                        )
                    add_bytes(
                        archive,
                        "adapter-manifest.json",
                        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                        + b"\n",
                    )
                    add_bytes(
                        archive,
                        "dependency-lock.json",
                        json.dumps(lock, sort_keys=True, separators=(",", ":")).encode()
                        + b"\n",
                    )
                    add_bytes(
                        archive,
                        "sbom.spdx.json",
                        json.dumps(sbom, sort_keys=True, separators=(",", ":")).encode()
                        + b"\n",
                    )
    finally:
        os.umask(old_umask)
    size, sha256 = digest(output)
    print(json.dumps({"path": str(output), "size": size, "sha256": sha256}))


if __name__ == "__main__":
    main()
