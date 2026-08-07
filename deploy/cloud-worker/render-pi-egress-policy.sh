#!/bin/sh
set -eu

# The immutable AMI release owns this policy. Runtime user data cannot alter
# it. The Pi UID can reach only the Worker-owned fixed loopback CONNECT bridge;
# the Worker itself reaches the plan-bound TLS proxy under the Security Group.
if [ "$#" -ne 1 ]; then
    exit 64
fi

output_path=$1

umask 077
printf '%s\n' \
    'table inet dirextalk_cloud_worker {' \
    '    chain pi_output {' \
    '        type filter hook output priority -20; policy drop;' \
    '' \
    '        meta skuid != 65532 accept' \
    '' \
    '        meta skuid 65532 ip daddr 127.0.0.1 ip protocol tcp tcp dport 38081 accept' \
    '        meta skuid 65532 ip daddr 127.0.0.0/8 reject' \
    '        meta skuid 65532 ip6 daddr ::1/128 reject' \
    '        meta skuid 65532 ip daddr 169.254.0.0/16 reject' \
    '        meta skuid 65532 ip6 daddr fe80::/10 reject' \
    '' \
    '        meta skuid 65532 reject' \
    '    }' \
    '}' > "$output_path"
chmod 0444 "$output_path"
