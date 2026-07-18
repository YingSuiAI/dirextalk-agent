import importlib.util
import stat
import sys
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build_adapter_bundle.py"
SPEC = importlib.util.spec_from_file_location("bundle_builder", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
bundle_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle_builder)


class BundleBuilderTests(unittest.TestCase):
    def test_wheel_stream_rejects_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traversal = root / "traversal.whl"
            with zipfile.ZipFile(traversal, "w") as archive:
                archive.writestr("../escape", "secret")
            with tarfile.open(root / "one.tar", "w") as output:
                with self.assertRaises(SystemExit):
                    bundle_builder.add_wheel(output, traversal, set(), [0])

            symlink = root / "symlink.whl"
            with zipfile.ZipFile(symlink, "w") as archive:
                info = zipfile.ZipInfo("package/link")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, "/etc/passwd")
            with tarfile.open(root / "two.tar", "w") as output:
                with self.assertRaises(SystemExit):
                    bundle_builder.add_wheel(output, symlink, set(), [0])

    def test_adapter_tree_rejects_unreviewed_generated_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "adapter"
            source.mkdir()
            (source / "main.py").write_text("pass\n", encoding="utf-8")
            (source / ".coverage").write_text("generated", encoding="utf-8")
            with tarfile.open(root / "adapter.tar", "w") as output:
                with self.assertRaises(SystemExit):
                    bundle_builder.add_tree(output, source, "adapter")


if __name__ == "__main__":
    unittest.main()
