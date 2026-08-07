#!/bin/sh
set -eu

usage() {
    echo "usage: $0 --target-account-id ID --region REGION --source-ami-id AMI --source-ami-owner ID --vpc-id VPC --subnet-id SUBNET --security-group-id SG --packer-source-security-group-id SG --kms-key-arn ARN --instance-type TYPE --ssh-username USER --root-device-name DEVICE --rootfs-tar-path ABSOLUTE_FILE --rootfs-sha256 HEX --ami-digest HEX --nftables-nevra NEVRA" >&2
    exit 64
}

target_account_id=
region=
source_ami_id=
source_ami_owner=
vpc_id=
subnet_id=
security_group_id=
packer_source_security_group_id=
kms_key_arn=
instance_type=
ssh_username=
root_device_name=
rootfs_tar_path=
rootfs_sha256=
ami_digest=
nftables_nevra=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target-account-id) [ "$#" -ge 2 ] || usage; target_account_id=$2; shift 2 ;;
        --region) [ "$#" -ge 2 ] || usage; region=$2; shift 2 ;;
        --source-ami-id) [ "$#" -ge 2 ] || usage; source_ami_id=$2; shift 2 ;;
        --source-ami-owner) [ "$#" -ge 2 ] || usage; source_ami_owner=$2; shift 2 ;;
        --vpc-id) [ "$#" -ge 2 ] || usage; vpc_id=$2; shift 2 ;;
        --subnet-id) [ "$#" -ge 2 ] || usage; subnet_id=$2; shift 2 ;;
        --security-group-id) [ "$#" -ge 2 ] || usage; security_group_id=$2; shift 2 ;;
        --packer-source-security-group-id) [ "$#" -ge 2 ] || usage; packer_source_security_group_id=$2; shift 2 ;;
        --kms-key-arn) [ "$#" -ge 2 ] || usage; kms_key_arn=$2; shift 2 ;;
        --instance-type) [ "$#" -ge 2 ] || usage; instance_type=$2; shift 2 ;;
        --ssh-username) [ "$#" -ge 2 ] || usage; ssh_username=$2; shift 2 ;;
        --root-device-name) [ "$#" -ge 2 ] || usage; root_device_name=$2; shift 2 ;;
        --rootfs-tar-path) [ "$#" -ge 2 ] || usage; rootfs_tar_path=$2; shift 2 ;;
        --rootfs-sha256) [ "$#" -ge 2 ] || usage; rootfs_sha256=$2; shift 2 ;;
        --ami-digest) [ "$#" -ge 2 ] || usage; ami_digest=$2; shift 2 ;;
        --nftables-nevra) [ "$#" -ge 2 ] || usage; nftables_nevra=$2; shift 2 ;;
        *) usage ;;
    esac
done
for value in "$target_account_id" "$region" "$source_ami_id" "$source_ami_owner" "$vpc_id" "$subnet_id" \
    "$security_group_id" "$packer_source_security_group_id" "$kms_key_arn" "$instance_type" "$ssh_username" "$root_device_name" \
    "$rootfs_tar_path" "$rootfs_sha256" "$ami_digest" "$nftables_nevra"
do
    [ -n "$value" ] || usage
done

printf '%s' "$target_account_id:$source_ami_owner" | grep -Eq '^[0-9]{12}:[0-9]{12}$' || usage
printf '%s' "$region" | grep -Eq '^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$' || usage
printf '%s' "$source_ami_id:$vpc_id:$subnet_id:$security_group_id:$packer_source_security_group_id" | \
    grep -Eq '^ami-[0-9a-f]{17}:vpc-[0-9a-f]{17}:subnet-[0-9a-f]{17}:sg-[0-9a-f]{17}:sg-[0-9a-f]{17}$' || usage
[ "$security_group_id" != "$packer_source_security_group_id" ] || { echo "build and Packer source Security Groups must be distinct" >&2; exit 78; }
printf '%s' "$rootfs_sha256:$ami_digest" | grep -Eq '^[a-f0-9]{64}:[a-f0-9]{64}$' || usage
printf '%s' "$nftables_nevra" | grep -Eq '^nftables-[0-9][A-Za-z0-9._+~:]*-[A-Za-z0-9][A-Za-z0-9._+~]*\.x86_64$' || usage
case "$rootfs_tar_path:$root_device_name" in /*:/dev/*) ;; *) usage ;; esac
printf '%s' "$kms_key_arn" | grep -Eq '^arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$' || usage
kms_region=$(printf '%s' "$kms_key_arn" | cut -d: -f4)
kms_account=$(printf '%s' "$kms_key_arn" | cut -d: -f5)
[ "$kms_region:$kms_account" = "$region:$target_account_id" ] || {
    echo "KMS ARN is outside the target account or Region" >&2
    exit 78
}
[ -f "$rootfs_tar_path" ] && [ ! -L "$rootfs_tar_path" ] || { echo "rootfs tar is missing or a symlink" >&2; exit 66; }
rootfs_tar_path=$(readlink -e -- "$rootfs_tar_path")
[ "$(stat -Lc '%h' -- "$rootfs_tar_path")" = 1 ] || { echo "rootfs tar must not be hard-linked" >&2; exit 66; }
rootfs_identity="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$rootfs_tar_path"):$(sha256sum "$rootfs_tar_path" | awk '{print $1}')"
[ "${rootfs_identity##*:}" = "$rootfs_sha256" ] || { echo "rootfs tar digest mismatch" >&2; exit 66; }
if archive_index=$(tar -tf "$rootfs_tar_path"); then :; else status=$?; echo "rootfs tar index failed with status $status" >&2; exit 66; fi
[ "$(printf '%s\n' "$archive_index" | grep -c '^\./usr/local/share/dirextalk-cloud-worker/installation\.json$')" -eq 1 ] || {
    echo "rootfs tar must contain exactly one canonical installation manifest" >&2
    exit 66
}
if installation=$(tar -xOf "$rootfs_tar_path" ./usr/local/share/dirextalk-cloud-worker/installation.json); then :; else status=$?; echo "rootfs installation manifest read failed with status $status" >&2; exit 66; fi
bundle_ami_digest=$(printf '%s\n' "$installation" | sed -n 's/^{"schema_version":"dirextalk.agent.cloud-worker-installation\/v1","ami_digest":"\([a-f0-9]\{64\}\)",.*$/\1/p')
[ "$bundle_ami_digest" = "$ami_digest" ] || { echo "rootfs semantic AMI digest mismatch" >&2; exit 66; }

aws_cli=$(command -v aws) || { echo "aws CLI is missing" >&2; exit 69; }
packer=$(command -v packer) || { echo "Packer is missing" >&2; exit 69; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
template=$script_dir/worker-ami.pkr.hcl
[ -f "$template" ] && [ ! -L "$template" ] || { echo "pinned Packer template is missing" >&2; exit 69; }

verify_caller() {
    if caller_account=$("$aws_cli" sts get-caller-identity --query Account --output text); then
        :
    else
        status=$?
        echo "STS caller identity read failed with status $status" >&2
        return 75
    fi
    [ "$caller_account" = "$target_account_id" ] || {
        echo "AWS caller account does not match target_account_id" >&2
        return 77
    }
}

aws_read() {
    if verify_caller; then :; else status=$?; return "$status"; fi
    if read_result=$("$aws_cli" "$@"); then
        [ -n "$read_result" ] || { echo "AWS read returned no object" >&2; return 78; }
        case "$read_result" in
            *"
"*) echo "AWS read returned multiple records" >&2; return 78 ;;
        esac
        printf '%s\n' "$read_result"
    else
        status=$?
        echo "AWS read failed with status $status" >&2
        return 75
    fi
}

if image=$(aws_read ec2 describe-images --region "$region" --image-ids "$source_ami_id" \
    --query 'Images[0].[ImageId,OwnerId,State,Architecture,RootDeviceType,RootDeviceName]' --output text); then :; else status=$?; exit "$status"; fi
IFS="$(printf '\t')" read -r image_id image_owner image_state image_arch image_root_type image_root_device image_extra <<EOF
$image
EOF
[ -z "$image_extra" ] && [ "$image_id:$image_owner:$image_state:$image_arch:$image_root_type:$image_root_device" = "$source_ami_id:$source_ami_owner:available:x86_64:ebs:$root_device_name" ] || {
    echo "source AMI immutable owner or shape readback mismatch" >&2
    exit 78
}

if key=$(aws_read kms describe-key --region "$region" --key-id "$kms_key_arn" \
    --query 'KeyMetadata.[Arn,Enabled,KeyState,KeyManager]' --output text); then :; else status=$?; exit "$status"; fi
IFS="$(printf '\t')" read -r key_arn key_enabled key_state key_manager key_extra <<EOF
$key
EOF
[ -z "$key_extra" ] && [ "$key_arn:$key_enabled:$key_state:$key_manager" = "$kms_key_arn:True:Enabled:CUSTOMER" ] || {
    echo "KMS key readback mismatch" >&2
    exit 78
}

if vpc=$(aws_read ec2 describe-vpcs --region "$region" --vpc-ids "$vpc_id" \
    --query 'Vpcs[0].[VpcId,OwnerId,State]' --output text); then :; else status=$?; exit "$status"; fi
IFS="$(printf '\t')" read -r read_vpc_id vpc_owner vpc_state vpc_extra <<EOF
$vpc
EOF
[ -z "$vpc_extra" ] && [ "$read_vpc_id:$vpc_owner:$vpc_state" = "$vpc_id:$target_account_id:available" ] || {
    echo "VPC owner or state readback mismatch" >&2
    exit 78
}

if subnet=$(aws_read ec2 describe-subnets --region "$region" --subnet-ids "$subnet_id" \
    --query 'Subnets[0].[SubnetId,OwnerId,VpcId,State,MapPublicIpOnLaunch]' --output text); then :; else status=$?; exit "$status"; fi
IFS="$(printf '\t')" read -r read_subnet_id subnet_owner subnet_vpc subnet_state subnet_public subnet_extra <<EOF
$subnet
EOF
[ -z "$subnet_extra" ] && [ "$read_subnet_id:$subnet_owner:$subnet_vpc:$subnet_state:$subnet_public" = "$subnet_id:$target_account_id:$vpc_id:available:False" ] || {
    echo "private subnet owner, VPC, or state readback mismatch" >&2
    exit 78
}

read_security_group_snapshot() {
    if group_shape=$(aws_read ec2 describe-security-groups --region "$region" --group-ids "$security_group_id" \
        --query 'SecurityGroups[0].[GroupId,OwnerId,VpcId,length(IpPermissions),length(IpPermissionsEgress)]' --output text); then :; else status=$?; return "$status"; fi
    IFS="$(printf '\t')" read -r read_group_id group_owner group_vpc ingress_count egress_count group_extra <<EOF
$group_shape
EOF
    [ -z "$group_extra" ] && [ "$read_group_id:$group_owner:$group_vpc:$ingress_count:$egress_count" = "$security_group_id:$target_account_id:$vpc_id:1:0" ] || {
        echo "build Security Group owner, VPC, ingress count, or egress shape mismatch" >&2
        return 78
    }
    if ingress=$(aws_read ec2 describe-security-groups --region "$region" --group-ids "$security_group_id" \
        --query 'SecurityGroups[0].IpPermissions[0].[IpProtocol,FromPort,ToPort,length(IpRanges),length(Ipv6Ranges),length(PrefixListIds),length(UserIdGroupPairs),UserIdGroupPairs[0].UserId,UserIdGroupPairs[0].GroupId]' --output text); then :; else status=$?; return "$status"; fi
    IFS="$(printf '\t')" read -r ingress_protocol ingress_from ingress_to ingress_ipv4 ingress_ipv6 ingress_prefix ingress_groups ingress_owner ingress_source ingress_extra <<EOF
$ingress
EOF
    [ -z "$ingress_extra" ] && [ "$ingress_protocol:$ingress_from:$ingress_to:$ingress_ipv4:$ingress_ipv6:$ingress_prefix:$ingress_groups:$ingress_owner:$ingress_source" = "tcp:22:22:0:0:0:1:$target_account_id:$packer_source_security_group_id" ] || {
        echo "build Security Group must have only controlled source-SG TCP/22 ingress" >&2
        return 78
    }
    if source_group=$(aws_read ec2 describe-security-groups --region "$region" --group-ids "$packer_source_security_group_id" \
        --query 'SecurityGroups[0].[GroupId,OwnerId,VpcId]' --output text); then :; else status=$?; return "$status"; fi
    IFS="$(printf '\t')" read -r read_source_group source_owner source_vpc source_extra <<EOF
$source_group
EOF
    [ -z "$source_extra" ] && [ "$read_source_group:$source_owner:$source_vpc" = "$packer_source_security_group_id:$target_account_id:$vpc_id" ] || {
        echo "Packer source Security Group owner or VPC readback mismatch" >&2
        return 78
    }
    printf '%s|%s|%s\n' "$group_shape" "$ingress" "$source_group"
}

if security_group_snapshot=$(read_security_group_snapshot); then :; else status=$?; exit "$status"; fi

current_rootfs_identity="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "$rootfs_tar_path"):$(sha256sum "$rootfs_tar_path" | awk '{print $1}')"
[ "$current_rootfs_identity" = "$rootfs_identity" ] || { echo "rootfs tar identity changed before Packer" >&2; exit 70; }
if current_security_group_snapshot=$(read_security_group_snapshot); then :; else status=$?; exit "$status"; fi
[ "$current_security_group_snapshot" = "$security_group_snapshot" ] || { echo "build Security Group identity or rules changed before Packer" >&2; exit 70; }
if verify_caller; then :; else status=$?; exit "$status"; fi

if "$packer" build \
    -var "target_account_id=$target_account_id" \
    -var "region=$region" \
    -var "source_ami_id=$source_ami_id" \
    -var "source_ami_owner=$source_ami_owner" \
    -var "vpc_id=$vpc_id" \
    -var "subnet_id=$subnet_id" \
    -var "security_group_id=$security_group_id" \
    -var "packer_source_security_group_id=$packer_source_security_group_id" \
    -var "kms_key_arn=$kms_key_arn" \
    -var "instance_type=$instance_type" \
    -var "ssh_username=$ssh_username" \
    -var "root_device_name=$root_device_name" \
    -var "rootfs_tar_path=$rootfs_tar_path" \
    -var "rootfs_sha256=$rootfs_sha256" \
    -var "ami_digest=$ami_digest" \
    -var "nftables_nevra=$nftables_nevra" \
    "$template"
then
    exit 0
else
    status=$?
    echo "Packer build failed with status $status" >&2
    exit "$status"
fi
