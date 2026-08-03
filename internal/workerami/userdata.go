package workerami

import (
	"fmt"
	"strings"
)

// fixedUserData is intentionally a closed program. The only substitutions are
// a strictly parsed regional S3 URL and two lowercase SHA-256 values plus an
// integer size. No path, command, package, service name, or provider response
// is interpolated into the root script.
func fixedUserData(presignedURL string, object ArtifactObjectV1, expectedWorkerDigest string) (string, error) {
	if err := validatePresignedURL(presignedURL, object.Bucket, regionFromKMSARN(object.KMSKeyARN)); err != nil ||
		!digestPattern.MatchString(object.Digest) || !digestPattern.MatchString(expectedWorkerDigest) || object.Size <= 0 || object.Size > maxRootFSBytes {
		return "", ErrInvalidInput
	}
	digest := strings.TrimPrefix(object.Digest, "sha256:")
	workerDigest := strings.TrimPrefix(expectedWorkerDigest, "sha256:")
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
set +x
umask 077
readonly archive=/run/dirextalk-worker-rootfs.tar
readonly artifact_url='%s'
readonly rootfs_sha256='%s'
readonly rootfs_size='%d'
readonly expected_worker_sha256='%s'
build_step='bootstrap'

report_builder_failure() {
  builder_exit_status="$?"
  trap - EXIT
  if test "${builder_exit_status}" -ne 0; then
    printf 'dirextalk_worker_ami_builder_step=%%s status=%%s\n' "${build_step}" "${builder_exit_status}" >&2
  fi
  exit "${builder_exit_status}"
}
trap report_builder_failure EXIT

build_step='download'
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "${archive}" "${artifact_url}"
build_step='archive_integrity'
test "$(stat -c '%%s' "${archive}")" = "${rootfs_size}"
printf '%%s  %%s\n' "${rootfs_sha256}" "${archive}" | sha256sum --check --strict -
tar --extract --file "${archive}" --directory / --numeric-owner --same-owner --same-permissions
rm -f "${archive}"

build_step='worker_integrity'
readonly worker_digest_file=/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256
readonly worker_binary=/usr/local/bin/dirextalk-cloud-worker
test "$(cat "${worker_digest_file}")" = "${expected_worker_sha256}"
printf '%%s  %%s\n' "${expected_worker_sha256}" "${worker_binary}" | sha256sum --check --strict -

build_step='runtime_executables'
readonly pi_binary=/opt/dirextalk-worker/runtimes/pi/bin/pi
for required_runtime_executable in /lib64/ld-linux-x86-64.so.2 /bin/bash /usr/bin/git "${pi_binary}"; do
  test -x "${required_runtime_executable}" || exit 77
done
build_step='runtime_assets'
for required_pi_asset in \
  /opt/dirextalk-worker/runtimes/pi/bin/package.json \
  /opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm \
  /opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json \
  /opt/dirextalk-worker/runtimes/pi/bin/theme/light.json \
  /opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json \
  /opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts \
  /etc/dirextalk-worker/runtime-installation.json; do
  test -r "${required_pi_asset}" || exit 77
done
build_step='runtime_version'
test "$("${pi_binary}" --version)" = "0.83.0" || exit 77

build_step='systemd_install'
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers /usr/lib/sysusers.d/dirextalk-worker.conf
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles /usr/lib/tmpfiles.d/dirextalk-worker.conf
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles /usr/lib/tmpfiles.d/dirextalk-installer.conf
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service /etc/systemd/system/dirextalk-cloud-worker.service
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service /etc/systemd/system/dirextalk-worker-installer.service
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer-bootstrap.service /etc/systemd/system/dirextalk-worker-installer-bootstrap.service
install -o root -g root -m 0644 /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket /etc/systemd/system/dirextalk-worker-installer.socket
systemd-sysusers /usr/lib/sysusers.d/dirextalk-worker.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/dirextalk-worker.conf /usr/lib/tmpfiles.d/dirextalk-installer.conf
systemctl daemon-reload
systemctl disable dirextalk-worker-installer.socket
systemctl enable dirextalk-worker-installer-bootstrap.service
systemctl enable dirextalk-cloud-worker.service

build_step='filesystem_tools'
for required_filesystem_tool in /usr/bin/lsblk /usr/sbin/blkid /usr/bin/findmnt /usr/sbin/mkfs.ext4 /usr/bin/mount; do
  test -x "${required_filesystem_tool}" || exit 76
done

build_step='package_cleanup'
rm -rf /var/tmp/* /tmp/* /root/.cache /root/.bash_history
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get purge -y curl
  DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
  apt-get clean
  rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
  dnf remove -y curl curl-minimal
  dnf clean all
elif command -v yum >/dev/null 2>&1; then
  yum remove -y curl curl-minimal
  yum clean all
else
  exit 72
fi

# The approved Worker rootfs is deliberately not a container-in-container
# boundary. Refuse to publish an AMI when the selected base image contributes
# a cloud CLI, JavaScript runtime, or container runtime that was not part of
# the attested rootfs archive. This is a fail-closed release check rather than
# a best-effort uninstall whose dependency graph could drift between bases.
build_step='forbidden_runtime'
for forbidden_runtime in aws node npm docker dockerd containerd ctr nerdctl runc crun podman; do
  if command -v "${forbidden_runtime}" >/dev/null 2>&1; then
    exit 73
  fi
done
for forbidden_unit in docker.service docker.socket containerd.service podman.service podman.socket; do
  if systemctl list-unit-files "${forbidden_unit}" --no-legend --no-pager 2>/dev/null | grep -q "^${forbidden_unit}"; then
    exit 74
  fi
done
for forbidden_socket in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock; do
  test ! -e "${forbidden_socket}" || exit 75
done

build_step='cloud_init_cleanup'
cloud-init clean --logs --machine-id --seed || true
rm -rf /var/lib/cloud/instances/* /var/lib/cloud/instance /var/log/cloud-init.log /var/log/cloud-init-output.log
build_step='complete'
trap - EXIT
printf 'dirextalk_worker_ami_builder_step=%%s status=0\n' "${build_step}" >&2
sync
systemctl poweroff
`, presignedURL, digest, object.Size, workerDigest), nil
}

func regionFromKMSARN(value string) string {
	match := kmsARNPattern.FindStringSubmatch(value)
	if len(match) != 5 {
		return ""
	}
	return match[2]
}
