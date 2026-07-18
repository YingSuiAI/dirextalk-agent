import gzip
import hashlib
import importlib.util
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


def load_script(name: str):
    script = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


model_builder = load_script("build_model_bundle")
provenance_builder = load_script("build_provenance")
release_builder = load_script("build_release_manifest")


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class ReleaseBuilderTests(unittest.TestCase):
    def test_model_bundle_is_deterministic_and_metadata_is_sealed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            files = {"model.onnx": b"model-bytes", "tokenizer.json": b"{}\n"}
            for name, payload in files.items():
                (source / name).write_bytes(payload)
            (source / "qdrant-x86_64-unknown-linux-musl.tar.gz").write_bytes(b"reviewed separately")
            manifest = root / "model-files.json"
            manifest.write_text(
                json.dumps(
                    {
                        "model": "example/model",
                        "revision": "a" * 40,
                        "files": [
                            {"path": "onnx/model.onnx", "size": len(files["model.onnx"]), "sha256": sha256(files["model.onnx"])},
                            {"path": "tokenizer.json", "size": len(files["tokenizer.json"]), "sha256": sha256(files["tokenizer.json"])},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            first, second = root / "first.tar.gz", root / "second.tar.gz"
            model_builder.build_model_bundle(source, first, manifest)
            model_builder.build_model_bundle(source, second, manifest)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with gzip.open(first, "rb") as expanded:
                with tarfile.open(fileobj=expanded, mode="r:") as archive:
                    members = archive.getmembers()
                    self.assertEqual([member.name for member in members], ["onnx", "onnx/model.onnx", "tokenizer.json"])
                    for member in members:
                        self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                        self.assertEqual(member.mode, 0o755 if member.isdir() else 0o644)

            (source / "tokenizer.json").write_bytes(b"drift")
            with self.assertRaises(model_builder.ReleaseError):
                model_builder.build_model_bundle(source, root / "drift.tar.gz", manifest)

            (source / "unreviewed.bin").write_bytes(b"unexpected")
            with self.assertRaises(model_builder.ReleaseError):
                model_builder.build_model_bundle(source, root / "extra.tar.gz", manifest)

    def test_provenance_is_canonical_and_binds_adapter_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = root / "dirextalk-knowledge-adapter.tar.gz"
            adapter.write_bytes(b"sealed-adapter")
            model_manifest = root / "model-files.json"
            model_manifest.write_text(
                json.dumps({"model": "intfloat/multilingual-e5-small", "revision": "a" * 40, "files": []}),
                encoding="utf-8",
            )
            first, second = root / "first.json", root / "second.json"
            provenance_builder.build_provenance(adapter, first, model_manifest)
            provenance_builder.build_provenance(adapter, second, model_manifest)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            value = json.loads(first.read_bytes())
            self.assertEqual(value["adapter_bundle"]["sha256"], sha256(b"sealed-adapter"))
            self.assertEqual(value["adapter_bundle"]["version"], provenance_builder.ADAPTER_VERSION)
            self.assertEqual(first.read_bytes(), json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def test_release_manifest_binds_fixed_urls_and_runtime_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = []
            for _, name, _, _ in release_builder.ARTIFACTS:
                path = root / name
                path.write_bytes((name + "\n").encode())
                inputs.append(path)
            output = root / "dirextalk-knowledge-release.v1.json"
            release_builder.build_release_manifest(inputs, output)
            value = json.loads(output.read_bytes())
            self.assertEqual(value["schema_version"], release_builder.SCHEMA)
            self.assertEqual(value["runtime"]["persistent_volume_mount"], "/var/lib/dirextalk-knowledge")
            self.assertEqual(value["runtime"]["qdrant_api_key_secret_path"], "/etc/dirextalk-service-secrets/qdrant-api-key")
            self.assertEqual(
                value["runtime"]["installer_commands"],
                ["install-v1", "restart-v1", "semantic-probe-v1", "stop-v1", "backup-v1", "restore-v1", "upgrade-v1", "rollback-v1", "destroy-v1"],
            )
            for item in value["artifacts"]:
                self.assertEqual(item["url"], f"{release_builder.ORIGIN}/sha256/{item['sha256']}/{item['name']}")


if __name__ == "__main__":
    unittest.main()
