"""Protected local SQLite path checks shared by durable stores."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import DependencyUnavailable


def prepare_database_path(path: Path, field: str) -> None:
    parent = path.parent
    parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        parent_info = parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise DependencyUnavailable(field) from exc
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or parent_info.st_mode & 0o022
    ):
        raise DependencyUnavailable(field)
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DependencyUnavailable(field) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise DependencyUnavailable(field)


def protect_database_file(path: Path, field: str) -> None:
    try:
        os.chmod(path, 0o600, follow_symlinks=False)
    except OSError as exc:
        raise DependencyUnavailable(field) from exc
