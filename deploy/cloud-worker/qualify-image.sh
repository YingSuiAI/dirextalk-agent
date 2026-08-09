#!/bin/sh
set -eu

usage() {
    echo "usage: $0 --phase offline|boot --target-root ABSOLUTE_DIR (--ami-digest HEX|--ami-digest-file FILE) (--rootfs-sha256 HEX|--rootfs-sha256-file FILE) (--nftables-nevra EXACT_NEVRA|--nftables-nevra-file FILE)" >&2
    exit 64
}

phase=
target_root=
ami_digest=
rootfs_sha256=
nftables_nevra=
ami_digest_file=
rootfs_sha256_file=
nftables_nevra_file=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --phase) [ "$#" -ge 2 ] || usage; phase=$2; shift 2 ;;
        --target-root) [ "$#" -ge 2 ] || usage; target_root=$2; shift 2 ;;
        --ami-digest) [ "$#" -ge 2 ] || usage; ami_digest=$2; shift 2 ;;
        --ami-digest-file) [ "$#" -ge 2 ] || usage; ami_digest_file=$2; shift 2 ;;
        --rootfs-sha256) [ "$#" -ge 2 ] || usage; rootfs_sha256=$2; shift 2 ;;
        --rootfs-sha256-file) [ "$#" -ge 2 ] || usage; rootfs_sha256_file=$2; shift 2 ;;
        --nftables-nevra) [ "$#" -ge 2 ] || usage; nftables_nevra=$2; shift 2 ;;
        --nftables-nevra-file) [ "$#" -ge 2 ] || usage; nftables_nevra_file=$2; shift 2 ;;
        *) usage ;;
    esac
done
case "$phase" in offline|boot) ;; *) usage ;; esac
[ -z "$ami_digest" ] || [ -z "$ami_digest_file" ] || usage
[ -z "$rootfs_sha256" ] || [ -z "$rootfs_sha256_file" ] || usage
[ -z "$nftables_nevra" ] || [ -z "$nftables_nevra_file" ] || usage
if [ -n "$ami_digest_file" ]; then
    [ -f "$ami_digest_file" ] && [ ! -L "$ami_digest_file" ] || usage
    ami_digest=$(sed -n 's/^{"schema_version":"dirextalk.agent.cloud-worker-installation\/v1","ami_digest":"\([a-f0-9]\{64\}\)",.*$/\1/p' "$ami_digest_file")
fi
if [ -n "$rootfs_sha256_file" ]; then
    [ -f "$rootfs_sha256_file" ] && [ ! -L "$rootfs_sha256_file" ] || usage
    rootfs_sha256=$(cat "$rootfs_sha256_file")
fi
if [ -n "$nftables_nevra_file" ]; then
    [ -f "$nftables_nevra_file" ] && [ ! -L "$nftables_nevra_file" ] || usage
    nftables_nevra=$(cat "$nftables_nevra_file")
fi
[ -n "$target_root" ] && [ -n "$ami_digest" ] && [ -n "$rootfs_sha256" ] && [ -n "$nftables_nevra" ] || usage
case "$target_root" in /*) ;; *) usage ;; esac
printf '%s' "$ami_digest" | grep -Eq '^[a-f0-9]{64}$' || { echo "invalid semantic AMI digest" >&2; exit 65; }
printf '%s' "$rootfs_sha256" | grep -Eq '^[a-f0-9]{64}$' || { echo "invalid rootfs SHA-256" >&2; exit 65; }
printf '%s' "$nftables_nevra" | grep -Eq '^nftables-[0-9][A-Za-z0-9._+~:]*-[A-Za-z0-9][A-Za-z0-9._+~]*\.x86_64$' || {
    echo "invalid nftables NEVRA" >&2
    exit 65
}
[ ! -L "$target_root" ] && [ -d "$target_root" ] || { echo "target root must be a real directory" >&2; exit 65; }
target_root=$(readlink -e -- "$target_root")
[ "$(stat -Lc '%u' -- "$target_root")" = 0 ] || { echo "target root is not root-owned" >&2; exit 65; }
[ "$phase" != boot ] || [ "$target_root" = / ] || { echo "boot qualification must observe the running root" >&2; exit 65; }
target_identity=$(stat -Lc '%d:%i:%u:%g' -- "$target_root")
assert_target() {
    [ "$(stat -Lc '%d:%i:%u:%g' -- "$target_root")" = "$target_identity" ] || {
        echo "target root identity changed" >&2
        exit 70
    }
}
target_path() { printf '%s/%s\n' "${target_root%/}" "$1"; }

for command in rpm systemctl systemd-analyze readelf getcap nft ss awk grep sed cat stat sha256sum setpriv mkfifo readlink; do
    command -v "$command" >/dev/null 2>&1 || { echo "qualification dependency is missing: $command" >&2; exit 69; }
done

allowlist=$(target_path usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist)
[ -f "$allowlist" ] && [ ! -L "$allowlist" ] && [ "$(stat -Lc '%a:%u:%g:%h' -- "$allowlist")" = 444:0:0:1 ] || {
    echo "installed allowlist boundary mismatch" >&2
    exit 66
}
installation=$(target_path usr/local/share/dirextalk-cloud-worker/installation.json)
manifest_ami_digest=$(sed -n 's/^{"schema_version":"dirextalk.agent.cloud-worker-installation\/v1","ami_digest":"\([a-f0-9]\{64\}\)",.*$/\1/p' "$installation")
[ "$manifest_ami_digest" = "$ami_digest" ] || { echo "canonical installation AMI digest mismatch" >&2; exit 66; }
rootfs_stamp=$(target_path usr/local/share/dirextalk-cloud-worker/rootfs-bundle.sha256)
nftables_stamp=$(target_path usr/local/share/dirextalk-cloud-worker/nftables.nevra)
for stamp in "$rootfs_stamp" "$nftables_stamp"; do
    [ -f "$stamp" ] && [ ! -L "$stamp" ] && [ "$(stat -Lc '%a:%u:%g:%h' -- "$stamp")" = 444:0:0:1 ] || {
        echo "qualification stamp boundary mismatch: $stamp" >&2
        exit 66
    }
done
[ "$(cat "$rootfs_stamp")" = "$rootfs_sha256" ] || {
    echo "installed rootfs bundle digest mismatch" >&2
    exit 66
}
[ "$(cat "$nftables_stamp")" = "$nftables_nevra" ] || {
    echo "installed nftables stamp mismatch" >&2
    exit 66
}
[ "$(rpm --root "$target_root" --query nftables)" = "$nftables_nevra" ] || {
    echo "installed nftables package drifted" >&2
    exit 69
}

while read -r mode uid gid path; do
    case "$mode" in \#*) continue ;; esac
    [ -n "$path" ] || continue
    assert_target
    file=$(target_path "$path")
    [ -f "$file" ] && [ ! -L "$file" ] || { echo "missing allowlisted file: $path" >&2; exit 66; }
    [ "$(stat -Lc '%a:%u:%g' -- "$file")" = "${mode#0}:$uid:$gid" ] || {
        echo "mode or owner mismatch: $path" >&2
        exit 66
    }
    [ "$(stat -Lc '%h' -- "$file")" = 1 ] || { echo "hard-linked allowlisted file: $path" >&2; exit 66; }
done < "$allowlist"

for binary in \
    usr/local/bin/dirextalk-cloud-worker \
    usr/local/bin/dirextalk-cloud-worker-exec-gate \
    usr/local/lib/dirextalk-cloud-worker/pi/pi
do
    file=$(target_path "$binary")
    readelf -h "$file" | grep -Eq 'Class:[[:space:]]+ELF64' || { echo "not an ELF64 binary: $binary" >&2; exit 66; }
    readelf -h "$file" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' || {
        echo "wrong executable architecture: $binary" >&2
        exit 66
    }
    [ -z "$(getcap "$file")" ] || { echo "file capability is forbidden: $binary" >&2; exit 66; }
done

for identity in 'dirextalk-cloud-worker:65531:65531' 'dirextalk-pi:65532:65532'; do
    name=${identity%%:*}; remainder=${identity#*:}; uid=${remainder%%:*}; gid=${remainder#*:}
    awk -F: -v name="$name" -v uid="$uid" -v gid="$gid" \
        '$1 == name { count++; if ($3 != uid || $4 != gid) exit 1 } END { exit count == 1 ? 0 : 1 }' \
        "$(target_path etc/passwd)" || { echo "user identity mismatch" >&2; exit 69; }
    awk -F: -v name="$name" -v gid="$gid" \
        '$1 == name { count++; if ($3 != gid) exit 1 } END { exit count == 1 ? 0 : 1 }' \
        "$(target_path etc/group)" || { echo "group identity mismatch" >&2; exit 69; }
done

for unit in \
    dirextalk-cloud-worker-network.service \
    dirextalk-cloud-worker-exec-gate.service \
    dirextalk-cloud-worker-boot-qualification.service \
    dirextalk-cloud-worker.service
do
    if unit_state=$(systemctl --root="$target_root" is-enabled "$unit"); then
        [ "$unit_state" = enabled ] || { echo "unit is not enabled: $unit" >&2; exit 69; }
    else
        status=$?
        echo "unit enable-state read failed for $unit with status $status" >&2
        exit 69
    fi
done
for unit in \
    sshd.service sshd.socket ssh.service ssh.socket \
    amazon-ssm-agent.service amazon-ssm-agent.socket \
    cockpit.service cockpit.socket httpd.service nginx.service
do
    if unit_state=$(systemctl --root="$target_root" is-enabled "$unit"); then
        status=0
    else
        status=$?
    fi
    [ "$status" -eq 1 ] && [ "$unit_state" = masked ] || {
        echo "inbound unit is not masked: $unit (status $status)" >&2
        exit 69
    }
done

systemd-analyze --root="$target_root" --man=no --generators=no verify \
    dirextalk-cloud-worker-network.service \
    dirextalk-cloud-worker-exec-gate.service \
    dirextalk-cloud-worker-boot-qualification.service \
    dirextalk-cloud-worker.service

qualify_pi_execution_boundary() (
    set -eu
    pi_file=$(target_path usr/local/lib/dirextalk-cloud-worker/pi/pi)
    expected_pi_sha256=c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a
    [ "$(stat -Lc '%a:%u:%g:%h' -- "$pi_file")" = 551:0:65531:1 ] || {
        echo "Pi execute-only loader boundary mismatch" >&2
        exit 66
    }
    if [ "$(sha256sum "$pi_file" | awk '{print $1}')" != "$expected_pi_sha256" ] ||
        ! grep -Fq '"pi_version":"0.83.0"' "$installation" ||
        ! grep -Fq '"pi_executable_sha256":"c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a"' "$installation"; then
        echo "pinned Pi 0.83.0 identity drifted" >&2
        exit 66
    fi
    setpriv --reuid=65531 --regid=65532 --groups=65531 test -r "$pi_file" || {
        echo "Worker cannot read the pinned Pi executable" >&2
        exit 66
    }
    if setpriv --reuid=65532 --regid=65532 --clear-groups test -r "$pi_file"; then
        echo "Pi identity can read its executable as loader input" >&2
        exit 66
    fi

    pi_interpreter=$(LC_ALL=C readelf -l "$pi_file" |
        sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
    [ "$pi_interpreter" = /lib64/ld-linux-x86-64.so.2 ] && [ -x "$pi_interpreter" ] || {
        echo "pinned Pi PT_INTERP drifted" >&2
        exit 66
    }
    if pi_version=$(setpriv --reuid=65532 --regid=65532 --clear-groups \
        env -i PATH=/usr/local/bin:/usr/bin:/bin PI_OFFLINE=1 \
        "$pi_file" --version 2>&1); then
        [ "$pi_version" = 0.83.0 ] || { echo "pinned Pi version probe drifted" >&2; exit 66; }
    else
        status=$?
        echo "direct execute-only Pi probe failed with status $status" >&2
        exit 66
    fi
    if loader_output=$(setpriv --reuid=65532 --regid=65532 --clear-groups \
        env -i PATH=/usr/local/bin:/usr/bin:/bin LC_ALL=C \
        "$pi_interpreter" "$pi_file" --version 2>&1); then
        echo "explicit PT_INTERP bypass executed the pinned Pi" >&2
        exit 66
    else
        status=$?
    fi
    if [ "$status" -ne 127 ] || ! printf '%s\n' "$loader_output" | grep -Fq 'Permission denied'; then
        echo "explicit PT_INTERP probe failed for an unexpected reason" >&2
        exit 66
    fi

    probe_root=$(mktemp -d)
    probe_pid=
    cleanup_probe() {
        if [ -n "$probe_pid" ]; then
            kill "$probe_pid" 2>/dev/null || true
            wait "$probe_pid" 2>/dev/null || true
        fi
        rm -rf -- "$probe_root"
    }
    trap cleanup_probe EXIT HUP INT TERM
    chown 65532:65532 "$probe_root"
    chmod 0700 "$probe_root"
    mkfifo "$probe_root/input"
    chown 65532:65532 "$probe_root/input"
    : > "$probe_root/stdout"
    : > "$probe_root/stderr"
    exec 9<> "$probe_root/input"
    (
        cd "$probe_root"
        exec setpriv --reuid=65532 --regid=65532 --clear-groups \
            env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$probe_root" \
            PI_OFFLINE=1 PI_TELEMETRY=0 \
            "$pi_file" --mode rpc --offline --no-session --no-tools \
            --no-extensions --no-skills --no-prompt-templates --no-themes \
            --no-context-files < input > stdout 2> stderr
    ) &
    probe_pid=$!
    attempts=0
    while [ "$attempts" -lt 50 ] && [ ! -r "/proc/$probe_pid/status" ]; do
        kill -0 "$probe_pid" 2>/dev/null || { echo "Pi runtime probe exited during startup" >&2; exit 66; }
        attempts=$((attempts + 1))
        sleep 0.1
    done
    [ -r "/proc/$probe_pid/status" ] || { echo "Pi runtime probe did not start" >&2; exit 66; }
    probe_start=$(sed 's/^.*) //' "/proc/$probe_pid/stat" | awk '{print $20}')
    assert_probe_identity() {
        current_start=$(sed 's/^.*) //' "/proc/$probe_pid/stat" | awk '{print $20}')
        [ -n "$probe_start" ] && [ "$current_start" = "$probe_start" ] || {
            echo "Pi runtime probe identity changed" >&2
            exit 70
        }
    }
    assert_probe_identity
    awk '
        $1 == "Uid:" { uid = ($2 == 65532 && $3 == 65532 && $4 == 65532 && $5 == 65532) }
        $1 == "Gid:" { gid = ($2 == 65532 && $3 == 65532 && $4 == 65532 && $5 == 65532) }
        $1 == "Groups:" { groups = (NF == 1) }
        $1 == "CapInh:" { cap_inh = ($2 == "0000000000000000") }
        $1 == "CapPrm:" { cap_prm = ($2 == "0000000000000000") }
        $1 == "CapEff:" { cap_eff = ($2 == "0000000000000000") }
        $1 == "CapAmb:" { cap_amb = ($2 == "0000000000000000") }
        END { exit uid && gid && groups && cap_inh && cap_prm && cap_eff && cap_amb ? 0 : 1 }
    ' "/proc/$probe_pid/status" || { echo "Pi runtime identity or capability boundary mismatch" >&2; exit 66; }
    assert_probe_identity
    for descriptor in "/proc/$probe_pid/fd/"*; do
        if descriptor_target=$(readlink "$descriptor" 2>/dev/null); then
            [ "$descriptor_target" != "$pi_file" ] || {
                echo "Pi runtime inherited a readable executable descriptor" >&2
                exit 66
            }
        elif [ -L "$descriptor" ]; then
            echo "Pi runtime descriptor could not be inspected" >&2
            exit 69
        fi
    done
    assert_probe_identity
    kill "$probe_pid"
    wait "$probe_pid" 2>/dev/null || true
    probe_pid=
    exec 9>&-
    cleanup_probe
)

if [ "$phase" = offline ]; then
    [ "$target_root" = / ] || { echo "offline nft syntax qualification requires the mounted build root" >&2; exit 65; }
    qualify_pi_execution_boundary
    nft --check --file "$(target_path usr/local/share/dirextalk-cloud-worker/pi-egress.nft)"
    echo "cloud-worker image offline qualification: PASS"
    exit 0
fi

for unit in \
    dirextalk-cloud-worker-network.service \
    dirextalk-cloud-worker-exec-gate.service
do
    if unit_state=$(systemctl is-active "$unit"); then
        [ "$unit_state" = active ] || { echo "unit is not active: $unit" >&2; exit 69; }
    else
        status=$?
        echo "unit active-state read failed for $unit with status $status" >&2
        exit 69
    fi
done
network_started=$(systemctl show --property=ActiveEnterTimestampMonotonic --value dirextalk-cloud-worker-network.service)
gate_started=$(systemctl show --property=ActiveEnterTimestampMonotonic --value dirextalk-cloud-worker-exec-gate.service)
case "$network_started:$gate_started" in *[!0-9:]*) echo "invalid systemd activation timestamp" >&2; exit 69 ;; esac
[ "$network_started" -gt 0 ] && [ "$gate_started" -gt 0 ] || {
    echo "network or execution Gate has no activation timestamp" >&2
    exit 69
}

check_process_capabilities() {
    unit=$1
    expected=$2
    pid=$(systemctl show --property=MainPID --value "$unit")
    case "$pid" in ''|0|*[!0-9]*) echo "missing main PID: $unit" >&2; exit 69 ;; esac
    for field in CapInh CapPrm CapEff CapBnd CapAmb; do
        value=$(awk -v field="$field:" '$1 == field { print $2 }' "/proc/$pid/status")
        [ "$value" = "$expected" ] || { echo "unexpected $field for $unit" >&2; exit 69; }
    done
}
check_process_capabilities dirextalk-cloud-worker-exec-gate.service 0000000000200020

[ "$(stat -Lc '%a:%u:%g' /run/dirextalk-cloud-worker-exec-gate)" = 750:0:65531 ] || {
    echo "execution Gate runtime directory boundary mismatch" >&2
    exit 69
}
[ "$(stat -Lc '%a:%u:%g' /run/dirextalk-cloud-worker-exec-gate/control.sock)" = 660:0:65531 ] || {
    echo "execution Gate socket boundary mismatch" >&2
    exit 69
}

rules=$(mktemp)
cleanup_rules() { rm -f -- "$rules"; }
trap cleanup_rules EXIT HUP INT TERM
nft --handle list chain inet dirextalk_cloud_worker pi_output > "$rules"
grep -Eq 'hook output priority filter -20; policy drop;' "$rules" || { echo "Pi nft chain is not default-drop" >&2; exit 69; }
[ "$(grep -c '^[[:space:]]*meta .*# handle' "$rules")" -eq 7 ] || { echo "Pi nft rule count drifted" >&2; exit 69; }
grep -Eq 'meta skuid 65532 ip daddr 127\.0\.0\.1 ip protocol tcp tcp dport 38081 accept' "$rules" || {
    echo "Pi loopback bridge rule is missing" >&2
    exit 69
}
grep -Eq 'meta skuid 65532 reject' "$rules" || { echo "Pi terminal reject rule is missing" >&2; exit 69; }

ss -H -lntu | while read -r netid _state _recvq _sendq local_address _peer_address; do
    case "$local_address" in 127.*:*|\[::1\]:*) ;;
        *) echo "non-loopback inbound listener: $netid $local_address" >&2; exit 69 ;;
    esac
done
echo "cloud-worker candidate boot prequalification: PASS"
