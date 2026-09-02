#!/usr/bin/env bash
set -euo pipefail
umask 077

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cloud_dir=$(cd -- "$test_dir/.." && pwd -P)
for script in "$cloud_dir"/scripts/*.sh "$cloud_dir"/tests/*.sh; do bash -n "$script"; done

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin"
cat >"$work/bin/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_AWS_LOG:?}"
service=${1:-}; operation=${2:-}; shift 2
case "$service:$operation" in
  sts:get-caller-identity) printf '123456789012\n' ;;
  ssm:get-parameter)
    case " $* " in *deeplearning*) ami=ami-22222222222222222 ;; *) ami=ami-11111111111111111 ;; esac
    printf '{"Parameter":{"Value":"%s"}}\n' "$ami"
    ;;
  ec2:describe-images)
    case " $* " in
      *ami-22222222222222222*) printf '{"Images":[{"ImageId":"ami-22222222222222222","OwnerId":"898082745236","ImageOwnerAlias":"amazon","Description":"Supported EC2 instances: G4dn, G5, G6, Gr6, G6e, G7, G7e, P4d, P4de, P5, P5e, P5en, P6-B200, P6-B300. Release notes: https://aws.amazon.com/releasenotes/aws-deep-learning-base-gpu-ami-ubuntu-24-04/","State":"available","Architecture":"x86_64","RootDeviceType":"ebs","VirtualizationType":"hvm","RootDeviceName":"/dev/sda1","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"SnapshotId":"snap-22222222222222222","VolumeSize":32}}]}]}\n' ;;
      *) printf '{"Images":[{"ImageId":"ami-11111111111111111","OwnerId":"099720109477","State":"available","Architecture":"x86_64","RootDeviceType":"ebs","VirtualizationType":"hvm","RootDeviceName":"/dev/sda1","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"SnapshotId":"snap-11111111111111111","VolumeSize":32}}]}]}\n' ;;
    esac
    ;;
  ec2:describe-snapshots)
    case " $* " in *snap-22222222222222222*) owner=898082745236 ;; *) owner=099720109477 ;; esac
    printf '{"Snapshots":[{"SnapshotId":"snap-11111111111111111","OwnerId":"%s","VolumeSize":32}]}\n' "$owner"
    ;;
  ec2:describe-subnets) printf '{"Subnets":[{"SubnetId":"subnet-0123456789abcdef0","OwnerId":"123456789012","VpcId":"vpc-0123456789abcdef0","State":"available","MapPublicIpOnLaunch":false}]}\n' ;;
  ec2:describe-security-groups) printf '{"SecurityGroups":[{"GroupId":"sg-0123456789abcdef0","OwnerId":"123456789012","VpcId":"vpc-0123456789abcdef0","IpPermissions":[],"IpPermissionsEgress":[]}]}\n' ;;
  ec2:describe-instance-type-offerings) printf '{"InstanceTypeOfferings":[{"InstanceType":"g4dn.xlarge","LocationType":"region","Location":"us-east-1"}]}\n' ;;
  ec2:describe-instance-types)
    case " $* " in *g4dn.xlarge*) gpu='{"Gpus":[{"Name":"T4","Count":1}]}' ;; *) gpu=null ;; esac
    printf '{"InstanceTypes":[{"ProcessorInfo":{"SupportedArchitectures":["x86_64"]},"GpuInfo":%s}]}\n' "$gpu"
    ;;
  iam:get-instance-profile) printf '{"InstanceProfile":{"Arn":"arn:aws:iam::123456789012:instance-profile/DirextalkWorkerImageBuilder"}}\n' ;;
  kms:describe-key)
    region=us-east-1
    case " $* " in *--region\ us-west-2*) region=us-west-2 ;; esac
    printf '{"KeyMetadata":{"AWSAccountId":"123456789012","Arn":"arn:aws:kms:%s:123456789012:key/11111111-1111-4111-8111-111111111111","Enabled":true,"KeyUsage":"ENCRYPT_DECRYPT","KeyState":"Enabled"}}\n' "$region"
    ;;
  *) echo "unexpected fake AWS call: $service $operation $*" >&2; exit 99 ;;
esac
AWS
chmod 0700 "$work/bin/aws"
export FAKE_AWS_LOG=$work/aws.log
export PATH=$work/bin:$PATH

for flavor in cpu gpu; do
  : >"$FAKE_AWS_LOG"
  "$cloud_dir/scripts/render-release.sh" \
    --account-id 123456789012 --region us-east-1 --flavor "$flavor" \
    --distribution-regions us-west-2,us-east-1,us-west-2 \
    --instance-profile DirextalkWorkerImageBuilder \
    --subnet-id subnet-0123456789abcdef0 --security-group-id sg-0123456789abcdef0 \
    --output-dir "$work/$flavor" >/dev/null
  (cd "$work/$flavor" && sha256sum -c SHA256SUMS >/dev/null)
  [[ $(jq -r .flavor "$work/$flavor/render.json") == "$flavor" ]]
  [[ $(jq -r .parent_root_min_gib "$work/$flavor/render.json") == 32 ]]
  [[ $(jq -r '.blockDeviceMappings[0].ebs.volumeSize // "inherited"' "$work/$flavor/recipe.json") == inherited ]]
  [[ $(jq -r '.blockDeviceMappings[0].ebs.encrypted' "$work/$flavor/recipe.json") == false ]]
  [[ $(jq -r '.distribution_regions|join(",")' "$work/$flavor/render.json") == us-east-1,us-west-2 ]]
  [[ $(jq -r '.visibility+":"+(.snapshot_encrypted|tostring)' "$work/$flavor/render.json") == public:false ]]
  [[ $(jq -r '.distributions | length' "$work/$flavor/distribution.json") == 2 ]]
  [[ $(jq -r '[.distributions[].region]|join(",")' "$work/$flavor/distribution.json") == us-east-1,us-west-2 ]]
  [[ $(jq -r '[.distributions[].amiDistributionConfiguration.launchPermission.userGroups[]]|unique|join(",")' "$work/$flavor/distribution.json") == all ]]
  [[ $(jq -r '[.distributions[].amiDistributionConfiguration.kmsKeyId // "absent"]|unique|join(",")' "$work/$flavor/distribution.json") == absent ]]
  [[ $(jq -r '[.distributions[].ssmParameterConfigurations[0].parameterName]|unique|join(",")' "$work/$flavor/distribution.json") == "/dirextalk/worker-images/v1/$flavor/candidate" ]]
  [[ $(jq -r '[.distributions[].ssmParameterConfigurations[0].dataType]|unique|join(",")' "$work/$flavor/distribution.json") == aws:ec2:image ]]
  [[ $(jq -r '.components | length' "$work/$flavor/recipe.json") == 3 ]]
  for component in build plugin test; do
    (( $(jq -r .data "$work/$flavor/$component-component.json" | wc -c) <= 16000 ))
  done
  jq -e --arg flavor "$flavor" '.distributions[0].amiDistributionConfiguration.amiTags.DirextalkWorkerImageSchema == "1" and .distributions[0].amiDistributionConfiguration.amiTags.DirextalkWorkerImageFlavor == $flavor and .distributions[0].amiDistributionConfiguration.amiTags.DirextalkWorkerImageVersion == "1.1.0" and .distributions[0].amiDistributionConfiguration.amiTags.DirextalkPiVersion == "0.84.4" and .distributions[0].amiDistributionConfiguration.amiTags.DirextalkImageTested == "true"' "$work/$flavor/distribution.json" >/dev/null
  if [[ $flavor == gpu ]]; then
    families=g4dn,g5,g6,g6e,g7,g7e,gr6,p4d,p4de,p5,p5e,p5en,p6-b200,p6-b300
    [[ $(jq -r .gpu_supported_families "$work/$flavor/render.json") == "$families" ]]
    [[ $(jq -r '.distributions[0].amiDistributionConfiguration.amiTags.DirextalkGPUSupportedFamilies' "$work/$flavor/distribution.json") == "$families" ]]
    [[ $(jq -r '.tags.DirextalkGPUSupportedFamilies // "absent"' "$work/$flavor/build-component.json") == absent ]]
  else
    [[ $(jq -r '.distributions[0].amiDistributionConfiguration.amiTags.DirextalkGPUSupportedFamilies // "absent"' "$work/$flavor/distribution.json") == absent ]]
  fi
  grep -q 'action: Reboot' "$work/$flavor/test.yaml"
  grep -q 'git clone --no-local' "$work/$flavor/test.yaml"
  grep -q 'SOCI executable is missing' "$work/$flavor/test.yaml"
  grep -q 'sha256:e711c99333fdfe8ae1e677b4972be6c5021f0128a1d31f775c7e58d88921b6a9' "$work/$flavor/test.yaml"
  grep -q 'd81c6e66123fbaeeb585c02f757db8966022aa8649a6c75461bd7a82623f4552' "$work/$flavor/plugin.yaml"
  grep -q '/opt/dirextalk-worker/bin/pi' "$work/$flavor/install.yaml"
  grep -q '/opt/dirextalk-worker/bin/uvx' "$work/$flavor/install.yaml"
  grep -q 'c2f3c3e6a1850bd87654cc3ca8811013272397c3d042a4e2a64c43ee1b423972' "$work/$flavor/install.yaml"
  grep -q 'ec7a99cd05e0cd7f80243f135ce1361c76835cb0ee60055d14d20eba8eba1460' "$work/$flavor/install.yaml"
  grep -q '/opt/dirextalk-worker/manifest.json' "$work/$flavor/install.yaml"
  grep -q 'build-essential caddy ca-certificates' "$work/$flavor/install.yaml"
  grep -q 'pandoc poppler-utils python3-bs4 python3-httpx python3-lxml qpdf' "$work/$flavor/install.yaml"
  grep -q 'VerifyOfflinePythonWebAndPDFWorkflow' "$work/$flavor/test.yaml"
done

: >"$FAKE_AWS_LOG"
output=$("$cloud_dir/scripts/manage-release.sh" create --bundle "$work/cpu" --execute)
grep -q '^dry_run=true$' <<<"$output"
grep -q '^distribution_regions=us-east-1,us-west-2$' <<<"$output"
[[ ! -s $FAKE_AWS_LOG ]]
output=$("$cloud_dir/scripts/manage-release.sh" rollback --bundle "$work/cpu" --execute)
grep -q '^dry_run=true$' <<<"$output"
grep -q '^would_swap=verified-region-local-current-and-previous$' <<<"$output"
[[ ! -s $FAKE_AWS_LOG ]]

if "$cloud_dir/scripts/render-release.sh" --offline --account-id 123456789012 --region us-east-1 --flavor cpu \
  --distribution-regions us-west-2 --instance-profile DirextalkWorkerImageBuilder \
  --subnet-id subnet-REPLACE --security-group-id sg-REPLACE --output-dir "$work/reject" >/dev/null 2>&1; then
  echo 'renderer accepted a distribution allowlist without its source Region' >&2
  exit 1
fi

grep -q 'list-images --owner Self' "$cloud_dir/scripts/manage-release.sh"
grep -q 'DirextalkWorkerImageFlavor' "$cloud_dir/scripts/manage-release.sh"
grep -q 'delete-image --image-build-version-arn' "$cloud_dir/scripts/manage-release.sh"
grep -q 'delete-snapshot --snapshot-id' "$cloud_dir/scripts/manage-release.sh"
grep -q 'wait_candidate' "$cloud_dir/scripts/manage-release.sh"
grep -q 'aws_json_region' "$cloud_dir/scripts/manage-release.sh"
grep -q 'describe-image-attribute --image-id' "$cloud_dir/scripts/manage-release.sh"
grep -q 'describe-snapshot-attribute --snapshot-id' "$cloud_dir/scripts/manage-release.sh"
grep -Fq '($t.DirextalkPiVersion=="0.84.4" or $t.DirextalkPiVersion=="0.84.1")' "$cloud_dir/scripts/manage-release.sh"
printf 'cloud-worker image assets: PASS\n'
