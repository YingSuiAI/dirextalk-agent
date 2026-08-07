#!/bin/sh
set -eu

usage() {
    echo "usage: $0 --target-root ABSOLUTE_DIR --payload-tar ABSOLUTE_FILE --payload-sha256 HEX --allowlist ABSOLUTE_FILE --nftables-nevra EXACT_NEVRA" >&2
    exit 64
}

target_root=
payload_tar=
payload_sha256=
allowlist=
nftables_nevra=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target-root) [ "$#" -ge 2 ] || usage; target_root=$2; shift 2 ;;
        --payload-tar) [ "$#" -ge 2 ] || usage; payload_tar=$2; shift 2 ;;
        --payload-sha256) [ "$#" -ge 2 ] || usage; payload_sha256=$2; shift 2 ;;
        --allowlist) [ "$#" -ge 2 ] || usage; allowlist=$2; shift 2 ;;
        --nftables-nevra) [ "$#" -ge 2 ] || usage; nftables_nevra=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$target_root" ] && [ -n "$payload_tar" ] && [ -n "$payload_sha256" ] && \
    [ -n "$allowlist" ] && [ -n "$nftables_nevra" ] || usage

[ "$(id -u)" -eq 0 ] || { echo "rootfs installation requires root" >&2; exit 77; }
case "$target_root:$payload_tar:$allowlist" in
    /*:/*:/*) ;;
    *) usage ;;
esac
printf '%s' "$payload_sha256" | grep -Eq '^[a-f0-9]{64}$' || { echo "invalid payload SHA-256" >&2; exit 65; }
printf '%s' "$nftables_nevra" | grep -Eq '^nftables-[0-9][A-Za-z0-9._+~:]*-[A-Za-z0-9][A-Za-z0-9._+~]*\.x86_64$' || {
    echo "nftables must be an exact x86_64 NEVRA" >&2
    exit 65
}
[ ! -L "$target_root" ] && [ -d "$target_root" ] || { echo "target root must be a real directory" >&2; exit 65; }
[ -f "$payload_tar" ] && [ ! -L "$payload_tar" ] || { echo "payload tar is missing" >&2; exit 65; }
[ -f "$allowlist" ] && [ ! -L "$allowlist" ] || { echo "allowlist is missing" >&2; exit 65; }
target_root=$(readlink -e -- "$target_root")
payload_tar=$(readlink -e -- "$payload_tar")
allowlist=$(readlink -e -- "$allowlist")
[ "$(stat -Lc '%u' -- "$target_root")" = 0 ] || { echo "target root is not root-owned" >&2; exit 65; }
allowlist_mode=$(stat -Lc '%a' -- "$allowlist")
[ "$(stat -Lc '%u:%h' -- "$allowlist")" = 0:1 ] && [ $((0$allowlist_mode & 022)) -eq 0 ] && [ "$allowlist_mode" = 444 ] || {
    echo "allowlist must be root-owned mode 0444 and not writable by group/other" >&2
    exit 65
}
payload_identity="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$payload_tar"):$(sha256sum "$payload_tar" | awk '{print $1}')"
[ "$(stat -Lc '%h' -- "$payload_tar")" = 1 ] || { echo "payload tar must not be hard-linked" >&2; exit 65; }
allowlist_identity="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$allowlist"):$(sha256sum "$allowlist" | awk '{print $1}')"
assert_payload_inputs() {
    [ -f "$payload_tar" ] && [ ! -L "$payload_tar" ] && \
        [ "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$payload_tar"):$(sha256sum "$payload_tar" | awk '{print $1}')" = "$payload_identity" ] || {
        echo "payload tar identity changed" >&2
        exit 70
    }
    [ -f "$allowlist" ] && [ ! -L "$allowlist" ] && \
        [ "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$allowlist"):$(sha256sum "$allowlist" | awk '{print $1}')" = "$allowlist_identity" ] || {
        echo "allowlist identity changed" >&2
        exit 70
    }
}

target_identity=$(stat -Lc '%d:%i:%u:%g' -- "$target_root")
assert_target() {
    [ "$(stat -Lc '%d:%i:%u:%g' -- "$target_root")" = "$target_identity" ] || {
        echo "target root identity changed" >&2
        exit 70
    }
}
target_path() {
    printf '%s/%s\n' "${target_root%/}" "$1"
}
assert_target_path() {
    relative=$1
    current=${target_root%/}
    remaining=$relative
    while [ -n "$remaining" ]; do
        component=${remaining%%/*}
        current=$current/$component
        [ ! -L "$current" ] || { echo "target path crosses a symlink: $relative" >&2; exit 70; }
        case "$remaining" in */*) remaining=${remaining#*/} ;; *) remaining= ;; esac
    done
}

actual_sha256=$(sha256sum "$payload_tar" | awk '{print $1}')
[ "$actual_sha256" = "$payload_sha256" ] || { echo "rootfs bundle digest mismatch" >&2; exit 66; }

work_dir=$(mktemp -d)
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT HUP INT TERM
expected=$work_dir/expected
actual=$work_dir/actual
staging=$work_dir/rootfs
mkdir -p "$staging"

assert_payload_inputs
awk '
    /^[[:space:]]*(#|$)/ { next }
    NF != 4 || $1 !~ /^0[0-7]{3}$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ ||
        $4 ~ /^\// || $4 ~ /(^|\/)\.\.?(\/|$)/ { exit 1 }
    seen[$4]++ { exit 1 }
    { print $4 }
' "$allowlist" | LC_ALL=C sort > "$expected" || { echo "invalid rootfs allowlist" >&2; exit 66; }
[ -s "$expected" ] || { echo "empty rootfs allowlist" >&2; exit 66; }

assert_payload_inputs
tar -tf "$payload_tar" | while IFS= read -r entry; do
    case "$entry" in /*|..|../*|*/../*|*/..) echo "unsafe payload path" >&2; exit 66 ;; esac
done
assert_payload_inputs
tar -tvf "$payload_tar" | awk '$1 !~ /^[d-]/ { exit 1 }' || {
    echo "payload archive contains a link or special entry" >&2
    exit 66
}
assert_payload_inputs
tar --extract --file "$payload_tar" --directory "$staging" --no-same-owner --no-same-permissions
assert_payload_inputs
if find "$staging" -mindepth 1 ! -type d ! -type f -print -quit | grep -q .; then
    echo "payload contains a symlink or special file" >&2
    exit 66
fi
if find "$staging" -type f -links +1 -print -quit | grep -q .; then
    echo "payload contains a hard-linked file" >&2
    exit 66
fi
find "$staging" -type f -printf '%P\n' | LC_ALL=C sort > "$actual"
cmp -s "$expected" "$actual" || { echo "payload does not exactly match the reviewed allowlist" >&2; exit 66; }
cmp -s "$allowlist" "$staging/usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist" || {
    echo "payload does not bind the reviewed allowlist" >&2
    exit 66
}

for reserved in \
    usr/local/bin/dirextalk-cloud-worker \
    usr/local/bin/dirextalk-cloud-worker-exec-gate \
    usr/local/lib/dirextalk-cloud-worker \
    usr/local/sbin/dirextalk-cloud-worker-qualify \
    usr/local/share/dirextalk-cloud-worker \
    usr/local/lib/systemd/system/dirextalk-cloud-worker.service \
    usr/local/lib/systemd/system/dirextalk-cloud-worker-exec-gate.service \
    usr/local/lib/systemd/system/dirextalk-cloud-worker-network.service \
    usr/lib/sysusers.d/dirextalk-cloud-worker.conf
do
    destination=$(target_path "$reserved")
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || {
        echo "target is not a fresh cloud-worker rootfs: $reserved" >&2
        exit 66
    }
done

assert_target
installed_nevra=$(rpm --root "$target_root" --query nftables)
[ "$installed_nevra" = "$nftables_nevra" ] || { echo "pinned source AMI nftables NEVRA drifted" >&2; exit 69; }

while read -r mode uid gid path; do
    case "$mode" in \#*) continue ;; esac
    [ -n "$path" ] || continue
    assert_target
    assert_target_path "$path"
    source_file=$staging/$path
    destination=$(target_path "$path")
    [ -f "$source_file" ] && [ ! -L "$source_file" ] || { echo "allowlisted source is not regular: $path" >&2; exit 70; }
    source_before="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$source_file"):$(sha256sum "$source_file" | awk '{print $1}')"
    install -D -m "$mode" -o "$uid" -g "$gid" -- "$source_file" "$destination"
    source_after="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$source_file"):$(sha256sum "$source_file" | awk '{print $1}')"
    [ "$source_before" = "$source_after" ] || { echo "allowlisted source changed during copy: $path" >&2; exit 70; }
    [ -f "$destination" ] && [ ! -L "$destination" ] && [ "$(stat -Lc '%a:%u:%g:%h' -- "$destination")" = "${mode#0}:$uid:$gid:1" ] && \
        [ "$(sha256sum "$destination" | awk '{print $1}')" = "$(sha256sum "$source_file" | awk '{print $1}')" ] || {
        echo "installed file postcondition failed: $path" >&2
        exit 70
    }
done < "$allowlist"

assert_target
systemd-sysusers --root="$target_root" "$(target_path usr/lib/sysusers.d/dirextalk-cloud-worker.conf)"
for identity in 'dirextalk-cloud-worker:65531:65531' 'dirextalk-pi:65532:65532'; do
    name=${identity%%:*}; remainder=${identity#*:}; uid=${remainder%%:*}; gid=${remainder#*:}
    awk -F: -v name="$name" -v uid="$uid" -v gid="$gid" \
        '$1 == name { count++; if ($3 != uid || $4 != gid) exit 1 } END { exit count == 1 ? 0 : 1 }' \
        "$(target_path etc/passwd)" || { echo "sysusers user identity mismatch" >&2; exit 69; }
    awk -F: -v name="$name" -v gid="$gid" \
        '$1 == name { count++; if ($3 != gid) exit 1 } END { exit count == 1 ? 0 : 1 }' \
        "$(target_path etc/group)" || { echo "sysusers group identity mismatch" >&2; exit 69; }
done

assert_target
systemctl --root="$target_root" enable \
    dirextalk-cloud-worker-network.service \
    dirextalk-cloud-worker-exec-gate.service \
    dirextalk-cloud-worker.service
systemctl --root="$target_root" mask \
    sshd.service sshd.socket ssh.service ssh.socket \
    amazon-ssm-agent.service amazon-ssm-agent.socket \
    cockpit.service cockpit.socket httpd.service nginx.service

printf '%s\n' "$payload_sha256" > "$work_dir/rootfs-bundle.sha256"
printf '%s\n' "$nftables_nevra" > "$work_dir/nftables.nevra"
assert_target
install -m 0444 -o 0 -g 0 -- "$work_dir/rootfs-bundle.sha256" \
    "$(target_path usr/local/share/dirextalk-cloud-worker/rootfs-bundle.sha256)"
assert_target
install -m 0444 -o 0 -g 0 -- "$work_dir/nftables.nevra" \
    "$(target_path usr/local/share/dirextalk-cloud-worker/nftables.nevra)"
