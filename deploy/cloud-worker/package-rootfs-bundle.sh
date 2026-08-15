#!/bin/sh
set -eu
umask 022

usage() {
    echo "usage: $0 --source-root ABSOLUTE_DIR --output-tar ABSOLUTE_FILE --output-sha256 ABSOLUTE_FILE" >&2
    exit 64
}

source_root=
output_tar=
output_sha256=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-root) [ "$#" -ge 2 ] || usage; source_root=$2; shift 2 ;;
        --output-tar) [ "$#" -ge 2 ] || usage; output_tar=$2; shift 2 ;;
        --output-sha256) [ "$#" -ge 2 ] || usage; output_sha256=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$source_root" ] && [ -n "$output_tar" ] && [ -n "$output_sha256" ] || usage

case "$source_root:$output_tar:$output_sha256" in
    /*:/*:/*) ;;
    *) usage ;;
esac
[ ! -L "$source_root" ] && [ -d "$source_root" ] || { echo "source root must be a real directory" >&2; exit 65; }
source_root=$(readlink -e -- "$source_root")
[ "$source_root" != / ] || { echo "refusing to package the host root" >&2; exit 65; }
[ ! -e "$output_tar" ] && [ ! -L "$output_tar" ] || { echo "output tar already exists" >&2; exit 65; }
[ ! -e "$output_sha256" ] && [ ! -L "$output_sha256" ] || { echo "output SHA file already exists" >&2; exit 65; }
[ -d "$(dirname -- "$output_tar")" ] && [ -d "$(dirname -- "$output_sha256")" ] || {
    echo "output parent directory is missing" >&2
    exit 65
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
allowlist=$script_dir/rootfs-files.allowlist
[ -f "$allowlist" ] && [ ! -L "$allowlist" ] || { echo "rootfs allowlist is missing" >&2; exit 66; }

work_dir=$(mktemp -d)
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT HUP INT TERM
expected=$work_dir/expected
expected_unsorted=$work_dir/expected.unsorted
actual=$work_dir/actual
bundle_root=$work_dir/rootfs
mkdir -p "$bundle_root"

awk '
    /^[[:space:]]*(#|$)/ { next }
    NF != 4 || $1 !~ /^0[0-7][0-7][0-7]$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ ||
        $4 ~ /^\// || $4 ~ /(^|\/)\.\.?(\/|$)/ { exit 1 }
    seen[$4]++ { exit 1 }
    { print $4 }
' "$allowlist" > "$expected_unsorted" || { echo "invalid rootfs allowlist" >&2; exit 66; }
LC_ALL=C sort "$expected_unsorted" > "$expected"
[ -s "$expected" ] || { echo "empty rootfs allowlist" >&2; exit 66; }

if find "$source_root" -mindepth 1 ! -type d ! -type f -print -quit | grep -q .; then
    echo "source root contains a symlink or special file" >&2
    exit 66
fi
if find "$source_root" -type f -links +1 -print -quit | grep -q .; then
    echo "source root contains a hard-linked file" >&2
    exit 66
fi
find "$source_root" -type f -printf '%P\n' | LC_ALL=C sort > "$actual"
cmp -s "$expected" "$actual" || { echo "source root does not exactly match the reviewed allowlist" >&2; exit 66; }

source_identity=$(stat -Lc '%d:%i:%u:%g' -- "$source_root")
while read -r mode _uid _gid path; do
    case "$mode" in \#*) continue ;; esac
    [ -n "$path" ] || continue
    [ "$(stat -Lc '%d:%i:%u:%g' -- "$source_root")" = "$source_identity" ] || {
        echo "source root identity changed" >&2
        exit 66
    }
    source_file=$source_root/$path
    [ -f "$source_file" ] && [ ! -L "$source_file" ] || { echo "allowlisted source is not a regular file" >&2; exit 66; }
    source_before="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$source_file"):$(sha256sum "$source_file" | awk '{print $1}')"
    install -D -m "$mode" -- "$source_file" "$bundle_root/$path"
    source_after="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$source_file"):$(sha256sum "$source_file" | awk '{print $1}')"
    [ "$source_before" = "$source_after" ] || { echo "allowlisted source changed while packaging" >&2; exit 66; }
done < "$allowlist"

tar --create --file "$work_dir/rootfs.tar" --directory "$bundle_root" \
    --format=ustar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner .
bundle_digest=$(sha256sum "$work_dir/rootfs.tar" | awk '{print $1}')
install -m 0444 -- "$work_dir/rootfs.tar" "$output_tar"
printf '%s  %s\n' "$bundle_digest" "$(basename -- "$output_tar")" > "$work_dir/rootfs.sha256"
install -m 0444 -- "$work_dir/rootfs.sha256" "$output_sha256"
printf '%s\n' "$bundle_digest"
