#!/bin/sh
set -eu

usage() {
    echo "usage: $0 --rootfs-tar ABSOLUTE_FILE --rootfs-sha256 HEX --output-tar ABSOLUTE_FILE --output-sha256 ABSOLUTE_FILE" >&2
    exit 64
}

rootfs_tar=
rootfs_sha256=
output_tar=
output_sha256=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rootfs-tar) [ "$#" -ge 2 ] || usage; rootfs_tar=$2; shift 2 ;;
        --rootfs-sha256) [ "$#" -ge 2 ] || usage; rootfs_sha256=$2; shift 2 ;;
        --output-tar) [ "$#" -ge 2 ] || usage; output_tar=$2; shift 2 ;;
        --output-sha256) [ "$#" -ge 2 ] || usage; output_sha256=$2; shift 2 ;;
        *) usage ;;
    esac
done

case "$rootfs_tar:$output_tar:$output_sha256" in /*:/*:/*) ;; *) usage ;; esac
printf '%s' "$rootfs_sha256" | grep -Eq '^[a-f0-9]{64}$' || usage
[ -f "$rootfs_tar" ] && [ ! -L "$rootfs_tar" ] || { echo "rootfs tar is missing or a symlink" >&2; exit 66; }
rootfs_tar=$(readlink -e -- "$rootfs_tar")
[ "$(stat -Lc '%h' -- "$rootfs_tar")" = 1 ] || { echo "rootfs tar must not be hard-linked" >&2; exit 66; }
[ "$(sha256sum "$rootfs_tar" | awk '{print $1}')" = "$rootfs_sha256" ] || { echo "rootfs tar digest mismatch" >&2; exit 66; }
[ "$output_tar" != "$output_sha256" ] || usage
[ ! -e "$output_tar" ] && [ ! -L "$output_tar" ] || { echo "output tar already exists" >&2; exit 73; }
[ ! -e "$output_sha256" ] && [ ! -L "$output_sha256" ] || { echo "output digest already exists" >&2; exit 73; }

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
for name in build-worker-ami.sh worker-ami.pkr.hcl install-rootfs.sh rootfs-files.allowlist; do
    [ -f "$script_dir/$name" ] && [ ! -L "$script_dir/$name" ] || {
        echo "required AMI build input is missing or a symlink: $name" >&2
        exit 69
    }
done

output_dir=$(dirname -- "$output_tar")
digest_dir=$(dirname -- "$output_sha256")
[ -d "$output_dir" ] && [ -d "$digest_dir" ] || { echo "output directory is missing" >&2; exit 73; }
output_dir=$(readlink -e -- "$output_dir")
digest_dir=$(readlink -e -- "$digest_dir")
output_tar=$output_dir/$(basename -- "$output_tar")
output_sha256=$digest_dir/$(basename -- "$output_sha256")

stage=$(mktemp -d)
temporary_tar=$output_dir/.dirextalk-worker-ami-context.$$.tar
temporary_digest=$digest_dir/.dirextalk-worker-ami-context.$$.sha256
cleanup() {
    rm -rf -- "$stage"
    rm -f -- "$temporary_tar" "$temporary_digest"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0755 "$stage/deploy/cloud-worker"
install -m 0555 "$script_dir/build-worker-ami.sh" "$stage/deploy/cloud-worker/build-worker-ami.sh"
install -m 0444 "$script_dir/worker-ami.pkr.hcl" "$stage/deploy/cloud-worker/worker-ami.pkr.hcl"
install -m 0555 "$script_dir/install-rootfs.sh" "$stage/deploy/cloud-worker/install-rootfs.sh"
install -m 0444 "$script_dir/rootfs-files.allowlist" "$stage/deploy/cloud-worker/rootfs-files.allowlist"
install -m 0444 "$rootfs_tar" "$stage/deploy/cloud-worker/rootfs.tar"

(
    cd "$stage"
    sha256sum \
        deploy/cloud-worker/build-worker-ami.sh \
        deploy/cloud-worker/install-rootfs.sh \
        deploy/cloud-worker/rootfs-files.allowlist \
        deploy/cloud-worker/rootfs.tar \
        deploy/cloud-worker/worker-ami.pkr.hcl > deploy/cloud-worker/context.sha256
)

tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --format=posix --pax-option=delete=atime,delete=ctime \
    -C "$stage" -cf "$temporary_tar" deploy
context_digest=$(sha256sum "$temporary_tar" | awk '{print $1}')
printf '%s  %s\n' "$context_digest" "$(basename -- "$output_tar")" > "$temporary_digest"
chmod 0444 "$temporary_tar" "$temporary_digest"
mv -- "$temporary_tar" "$output_tar"
mv -- "$temporary_digest" "$output_sha256"
trap - EXIT HUP INT TERM
rm -rf -- "$stage"
printf 'cloud-worker AMI build context: %s\n' "$context_digest"
