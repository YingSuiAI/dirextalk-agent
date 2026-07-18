import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapter"))

from dirextalk_knowledge.auth import PeerAuthorizer, secure_bound_socket


class AuthorizationTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux SO_PEERCRED required")
    def test_authorizes_exact_current_peer_group(self):
        left, right = socket.socketpair()
        with left, right:
            self.assertTrue(PeerAuthorizer(os.getgid()).authorize(right))

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux SO_PEERCRED required")
    def test_bound_socket_accepts_real_peer_uid_and_gid(self):
        with self.subTest(uid=os.getuid(), gid=os.getgid()):
            import tempfile

            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "adapter.sock"
                listener = secure_bound_socket(path, os.getgid())
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        "import socket,sys;s=socket.socket(socket.AF_UNIX);"
                        "s.connect(sys.argv[1]);s.sendall(b'x');s.close()",
                        str(path),
                    ],
                    close_fds=True,
                )
                try:
                    connection, _ = listener.accept()
                    with connection:
                        self.assertTrue(
                            PeerAuthorizer(os.getgid()).authorize(connection)
                        )
                        self.assertEqual(connection.recv(1), b"x")
                    self.assertEqual(child.wait(timeout=5), 0)
                finally:
                    listener.close()
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux SO_PEERCRED required")
    def test_rejects_unrelated_group_for_nonroot(self):
        if os.getuid() == 0:
            self.skipTest("root is intentionally authorized")
        left, right = socket.socketpair()
        with left, right:
            self.assertFalse(PeerAuthorizer(2**31 - 1).authorize(right))


if __name__ == "__main__":
    unittest.main()
