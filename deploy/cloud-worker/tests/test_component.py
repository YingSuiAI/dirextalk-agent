#!/usr/bin/env python3
"""Run the Image Builder shell consumers offline, including large producer output."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


COMPONENT = Path(__file__).resolve().parents[1] / "components/test.yaml.in"


def shell_step(name):
    source = COMPONENT.read_text()
    step = source.split(f"      - name: {name}\n", 1)[1]
    step = step.split("\n      - name:", 1)[0]
    return textwrap.dedent(step.split("            - |\n", 1)[1])


GPU_STUBS = r"""
nvidia-smi() { :; }
nvcc() { :; }
nvidia-ctk() { :; }
nvidia-container-cli() { :; }
containerd() { :; }
soci-snapshotter-grpc() { :; }
systemctl() { :; }
nerdctl() { printf 'nerdctl:%s\n' "$*"; }
ctr() {
  test "$*" = 'plugins ls' || return 98
  awk -v mode="$PLUGIN_MODE" -v rows="$PLUGIN_ROWS" 'BEGIN {
    print "TYPE ID PLATFORMS STATUS"
    if (mode == "unhealthy") print "io.containerd.snapshotter.v1 soci linux/amd64 error"
    else if (mode == "wrong-id") print "io.containerd.snapshotter.v1 soci-other linux/amd64 ok"
    else if (mode == "wrong-type") print "io.containerd.service.v1 soci - ok"
    else print "io.containerd.snapshotter.v1 soci linux/amd64 ok"
    for (i = 0; i < rows; i++) print "io.containerd.service.v1 unrelated - ok"
    if (mode == "producer-error") exit 42
  }'
}
"""


class GPUComponentTest(unittest.TestCase):
    def run_step(self, name, mode, rows=100000):
        with tempfile.TemporaryDirectory(prefix="dirextalk-component-test-") as root:
            state = Path(root) / "state"
            state.mkdir()
            (state / ".image-builder-persistence-probe").write_text("previous-boot\nnonce\n")
            script = shell_step(name).replace("__FLAVOR__", "gpu")
            script = script.replace("/var/lib/dirextalk-worker", str(state))
            return subprocess.run(
                ["bash", "-c", GPU_STUBS + script],
                env={**os.environ, "PLUGIN_MODE": mode, "PLUGIN_ROWS": str(rows)},
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_healthy_plugin_consumes_all_output_before_and_after_reboot(self):
        for name in ("VerifyGPUStack", "VerifyPersistenceAfterReboot"):
            with self.subTest(step=name):
                result = self.run_step(name, "healthy")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("nerdctl:run --rm", result.stdout)

    def test_only_exact_healthy_snapshotter_is_accepted(self):
        for name in ("VerifyGPUStack", "VerifyPersistenceAfterReboot"):
            for mode in ("unhealthy", "wrong-id", "wrong-type"):
                with self.subTest(step=name, mode=mode):
                    result = self.run_step(name, mode, rows=0)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("nerdctl:pull", result.stdout)
                    self.assertNotIn("nerdctl:run", result.stdout)

    def test_matching_output_cannot_hide_producer_failure(self):
        for name in ("VerifyGPUStack", "VerifyPersistenceAfterReboot"):
            with self.subTest(step=name):
                result = self.run_step(name, "producer-error")
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertNotIn("nerdctl:run", result.stdout)


class ResidueComponentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dirextalk-residue-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.roots = (
            "/root", "/home/ubuntu", "/tmp", "/var/tmp",
            "/var/lib/apt/lists", "/var/cache/apt/archives",
        )
        for path in self.roots:
            self.path(path).mkdir(parents=True)

    def path(self, path):
        return self.root / path.lstrip("/")

    def create_file(self, path, content=""):
        target = self.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def run_step(self, environment_mode="clean", find_failure=""):
        script = re.sub(
            "|".join(re.escape(path) for path in self.roots),
            lambda match: str(self.path(match.group())),
            shell_step("VerifyNoBuildResidue"),
        )
        stubs = r"""
pi() { printf '0.84.4\n'; }
uv() { printf 'uv 0.12.9\n'; }
env() {
  awk -v mode="$ENVIRONMENT_MODE" 'BEGIN {
    if (mode == "secret") print "AWS_SESSION_TOKEN=redacted-fixture-value"
    for (i = 0; i < 100000; i++) print "SAFE_FIXTURE_VAR=value"
    if (mode == "producer-error") exit 42
  }'
}
find() {
  case "$FIND_FAILURE:$1" in
    sensitive:*/root|apt:*/var/lib/apt/lists|temporary:*/tmp) return 42 ;;
  esac
  command find "$@"
}
"""
        return subprocess.run(
            ["bash", "-c", stubs + script],
            env={**os.environ, "ENVIRONMENT_MODE": environment_mode, "FIND_FAILURE": find_failure},
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_empty_authorized_keys_and_runtime_files_are_not_baked_secrets(self):
        self.create_file("/root/.ssh/authorized_keys")
        self.create_file("/home/ubuntu/.ssh/authorized_keys")
        self.create_file("/tmp/systemd-private-boot-caddy.service/tmp/runtime.log", "runtime")
        self.create_file("/var/tmp/cloud-init/runtime.log", "runtime")
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonempty_authorized_keys_are_rejected(self):
        for home in ("/root", "/home/ubuntu"):
            with self.subTest(home=home):
                key = self.create_file(home + "/.ssh/authorized_keys", "not-an-actual-key")
                result = self.run_step()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("not-an-actual-key", result.stdout + result.stderr)
                key.unlink()

    def test_sensitive_artifacts_are_rejected_even_if_empty(self):
        for path in (
            "/root/.bash_history", "/home/ubuntu/.git-credentials", "/tmp/.npmrc",
            "/var/tmp/build/.aws/credentials", "/root/.config/gh/hosts.yml",
            "/root/.ssh/id_rsa", "/home/ubuntu/.ssh/id_ed25519",
            "/tmp/build/private.pem", "/var/tmp/private.key",
        ):
            with self.subTest(path=path):
                artifact = self.create_file(path)
                self.assertNotEqual(self.run_step().returncode, 0)
                artifact.unlink()

    def test_sensitive_symlinks_are_rejected(self):
        target = self.create_file("/tmp/empty-target")
        for path in ("/root/.ssh/authorized_keys", "/home/ubuntu/.ssh", "/root/.aws"):
            with self.subTest(path=path):
                link = self.path(path)
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target)
                self.assertNotEqual(self.run_step().returncode, 0)
                link.unlink()

    def test_build_test_and_apt_leftovers_are_rejected(self):
        for path in (
            "/tmp/dirextalk-image-test.ABCDEF", "/var/tmp/tmp.ABCDEFGHIJ",
            "/var/lib/apt/lists/package-index", "/var/cache/apt/archives/package.deb",
        ):
            with self.subTest(path=path):
                artifact = self.create_file(path)
                self.assertNotEqual(self.run_step().returncode, 0)
                artifact.unlink()

    def test_all_find_failures_fail_closed(self):
        for scan in ("sensitive", "apt", "temporary"):
            with self.subTest(scan=scan):
                result = self.run_step(find_failure=scan)
                self.assertEqual(result.returncode, 42, result.stderr)

    def test_environment_secret_and_producer_failure_are_distinct(self):
        for mode, status in (("clean", 0), ("secret", 1), ("producer-error", 42)):
            with self.subTest(mode=mode):
                result = self.run_step(environment_mode=mode)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertNotIn("redacted-fixture-value", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
