"""Linux SO_PEERCRED plus fixed-group authorization."""

from __future__ import annotations

import grp
import os
import socket
import struct
from pathlib import Path

AGENT_GROUP = "dirextalk-worker"


class PeerAuthorizer:
    def __init__(self, allowed_gid: int | None = None) -> None:
        self._allowed_gid = (
            grp.getgrnam(AGENT_GROUP).gr_gid if allowed_gid is None else allowed_gid
        )

    @property
    def allowed_gid(self) -> int:
        return self._allowed_gid

    def authorize(self, connection: socket.socket) -> bool:
        try:
            raw = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", raw)
        except (OSError, struct.error):
            return False
        if uid == 0:
            return True
        if pid <= 0:
            return False
        if gid == self._allowed_gid:
            return self._proc_identity_matches(pid, uid, gid, require_group=False)
        return self._proc_identity_matches(pid, uid, gid, require_group=True)

    def _proc_identity_matches(
        self, pid: int, uid: int, gid: int, require_group: bool
    ) -> bool:
        try:
            status = (Path("/proc") / str(pid) / "status").read_text(
                encoding="ascii", errors="strict"
            )
        except (OSError, UnicodeError):
            return False
        parsed: dict[str, list[int]] = {}
        for line in status.splitlines():
            name, separator, values = line.partition(":")
            if separator and name in {"Uid", "Gid", "Groups"}:
                try:
                    parsed[name] = [int(value) for value in values.split()]
                except ValueError:
                    return False
        if not parsed.get("Uid") or not parsed.get("Gid"):
            return False
        if parsed["Uid"][0] != uid or parsed["Gid"][0] != gid:
            return False
        return not require_group or self._allowed_gid in parsed.get("Groups", [])


def prepare_socket_path(path: Path, group_id: int) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        try:
            result = path.lstat()
        except OSError as exc:
            raise RuntimeError("cannot inspect socket") from exc
        if not stat_is_socket(result.st_mode) or result.st_uid != os.geteuid():
            raise RuntimeError("unsafe existing socket path")
        path.unlink()
    # Ownership and mode are applied immediately after bind by the server.


def secure_bound_socket(path: Path, group_id: int) -> socket.socket:
    prepare_socket_path(path, group_id)
    old_umask = os.umask(0o117)
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
    except Exception:
        try:
            listener.close()
        except UnboundLocalError:
            pass
        raise
    finally:
        os.umask(old_umask)
    try:
        os.chown(path, os.geteuid(), group_id, follow_symlinks=False)
        os.chmod(path, 0o660, follow_symlinks=False)
        listener.listen(16)
        return listener
    except Exception:
        listener.close()
        path.unlink(missing_ok=True)
        raise


def stat_is_socket(mode: int) -> bool:
    import stat

    return stat.S_ISSOCK(mode)
