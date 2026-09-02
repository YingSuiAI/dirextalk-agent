#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: render-release.sh [--offline] --account-id ID --region REGION --flavor cpu|gpu
       --instance-profile NAME --subnet-id ID --security-group-id ID --output-dir DIR
       --distribution-regions REGION[,REGION...] --distribution-kms-keys REGION=KEY_ARN[,REGION=KEY_ARN...]
       [--build-instance-type TYPE]
EOF
  exit 64
}

offline=false
account_id=''
region=''
flavor=''
instance_profile=''
subnet_id=''
security_group_id=''
output_dir=''
build_type=''
distribution_regions=''
distribution_kms_keys=''
while (($#)); do
  case "$1" in
    --offline) offline=true; shift ;;
    --account-id) account_id=${2:-}; shift 2 ;;
    --region) region=${2:-}; shift 2 ;;
    --flavor) flavor=${2:-}; shift 2 ;;
    --instance-profile) instance_profile=${2:-}; shift 2 ;;
    --subnet-id) subnet_id=${2:-}; shift 2 ;;
    --security-group-id) security_group_id=${2:-}; shift 2 ;;
    --output-dir) output_dir=${2:-}; shift 2 ;;
    --build-instance-type) build_type=${2:-}; shift 2 ;;
    --distribution-regions) distribution_regions=${2:-}; shift 2 ;;
    --distribution-kms-keys) distribution_kms_keys=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ $account_id =~ ^[0-9]{12}$ ]] || usage
[[ $region =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || usage
[[ $flavor == cpu || $flavor == gpu ]] || usage
[[ $instance_profile =~ ^[A-Za-z0-9+=,.@_-]{1,128}$ ]] || usage
[[ -n $subnet_id && -n $security_group_id && -n $output_dir ]] || usage
if [[ -z $build_type ]]; then
  [[ $flavor == cpu ]] && build_type=t3.small || build_type=g4dn.xlarge
fi
[[ $build_type =~ ^[a-z][a-z0-9]*[0-9][a-z0-9.]*$ ]] || usage
distribution_regions=${distribution_regions:-$region}
IFS=, read -r -a requested_regions <<<"$distribution_regions"
((${#requested_regions[@]} > 0)) || usage
for requested_region in "${requested_regions[@]}"; do
  [[ $requested_region =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || { echo "invalid distribution Region: $requested_region" >&2; exit 64; }
done
mapfile -t distribution_region_list < <(printf '%s\n' "${requested_regions[@]}" | sort -u)
printf '%s\n' "${distribution_region_list[@]}" | grep -qxF "$region" || {
  echo 'distribution Region allowlist must include the source Region' >&2; exit 64;
}
distribution_regions=$(IFS=,; printf '%s' "${distribution_region_list[*]}")
distribution_regions_json=$(printf '%s\n' "${distribution_region_list[@]}" | jq -R . | jq -s .)
declare -A kms_key_by_region=()
IFS=, read -r -a kms_pairs <<<"$distribution_kms_keys"
for pair in "${kms_pairs[@]}"; do
  kms_region=${pair%%=*}; kms_key=${pair#*=}
  [[ $pair == *=* && -n $kms_region && -n $kms_key && -z ${kms_key_by_region[$kms_region]:-} ]] || usage
  [[ $kms_key =~ ^arn:(aws|aws-us-gov|aws-cn):kms:$kms_region:$account_id:key/[A-Za-z0-9-]{16,}$ ]] || {
    echo "invalid same-account KMS key ARN for $kms_region" >&2; exit 64;
  }
  kms_key_by_region[$kms_region]=$kms_key
done
kms_keys_json='{}'
for requested_region in "${distribution_region_list[@]}"; do
  [[ -n ${kms_key_by_region[$requested_region]:-} ]] || { echo "missing KMS key for $requested_region" >&2; exit 64; }
  kms_keys_json=$(jq -c --arg region "$requested_region" --arg key "${kms_key_by_region[$requested_region]}" '. + {($region):$key}' <<<"$kms_keys_json")
done
((${#kms_key_by_region[@]} == ${#distribution_region_list[@]})) || { echo 'KMS key map contains a Region outside the distribution allowlist' >&2; exit 64; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cloud_dir=$(cd -- "$script_dir/.." && pwd -P)
repo_dir=$(cd -- "$cloud_dir/../.." && pwd -P)
release_file=$cloud_dir/release.json
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 69; }
command -v base64 >/dev/null || { echo 'base64 is required' >&2; exit 69; }
[[ -f $release_file && ! -L $release_file ]] || { echo 'release.json is missing or unsafe' >&2; exit 66; }
[[ $(jq -r .schema "$release_file") == dirextalk.worker-image-release/v1 ]]
[[ $(jq -r .image_version "$release_file") == 1.0.0 ]]
[[ $(jq -r .pi.version "$release_file") == 0.84.1 ]]

plugin_extension=$(jq -r '.plugins[0].extension_source' "$release_file")
plugin_agent=$(jq -r '.plugins[0].agent_source' "$release_file")
plugin_extension=$repo_dir/$plugin_extension
plugin_agent=$repo_dir/$plugin_agent
[[ -f $plugin_extension && ! -L $plugin_extension && -f $plugin_agent && ! -L $plugin_agent ]] || {
  echo 'reviewed plugin source is missing or unsafe' >&2; exit 66;
}
[[ $(sha256sum "$plugin_extension" | awk '{print $1}') == d81c6e66123fbaeeb585c02f757db8966022aa8649a6c75461bd7a82623f4552 ]]
[[ $(sha256sum "$plugin_agent" | awk '{print $1}') == 562434d598f2709150b042c50009ac224557769f0430d5093621530ce27cc7b5 ]]

aws_cli=$(command -v aws || true)
verify_identity() {
  [[ -n $aws_cli ]] || { echo 'AWS CLI is required for live rendering' >&2; return 69; }
  local observed
  observed=$($aws_cli sts get-caller-identity --region "$region" --query Account --output text) || return $?
  [[ $observed == "$account_id" ]] || { echo "AWS account changed: expected $account_id, observed $observed" >&2; return 77; }
  [[ ${AWS_REGION:-$region} == "$region" && ${AWS_DEFAULT_REGION:-$region} == "$region" ]] || {
    echo 'AWS region environment conflicts with the explicit region' >&2; return 77;
  }
}
verify_identity_region() {
  local call_region=$1 observed
  [[ -n $aws_cli ]] || { echo 'AWS CLI is required for live rendering' >&2; return 69; }
  observed=$($aws_cli sts get-caller-identity --region "$call_region" --query Account --output text) || return $?
  [[ $observed == "$account_id" ]] || { echo "AWS account changed in $call_region: expected $account_id, observed $observed" >&2; return 77; }
}
aws_read_json() {
  verify_identity
  $aws_cli "$@" --region "$region" --output json
}
aws_read_json_region() {
  local call_region=$1
  shift
  verify_identity_region "$call_region"
  $aws_cli "$@" --region "$call_region" --output json
}

parent_parameter=$(jq -r --arg flavor "$flavor" '.parents[$flavor]' "$release_file")
if $offline; then
  parent_ami=REPLACE_PARENT_AMI
  parent_owner=REPLACE_PARENT_OWNER
  parent_description=REPLACE_PARENT_AMI_DESCRIPTION
  [[ $flavor == gpu ]] && gpu_families=REPLACE_PARSED_GPU_FAMILIES || gpu_families=''
  root_device=/dev/sda1
  root_snapshot=REPLACE_PARENT_ROOT_SNAPSHOT
  root_min_gib=REPLACE_DISCOVERED_PARENT_MIN_GIB
else
  verify_identity
  parent_ami=$(aws_read_json ssm get-parameter --name "$parent_parameter" | jq -er '.Parameter.Value')
  [[ $parent_ami =~ ^ami-[0-9a-f]{8,17}$ ]] || { echo 'parent SSM value is not an AMI ID' >&2; exit 78; }
  image=$(aws_read_json ec2 describe-images --image-ids "$parent_ami")
  [[ $(jq '.Images | length' <<<"$image") == 1 ]] || { echo 'parent AMI did not resolve uniquely' >&2; exit 78; }
  [[ $(jq -r '.Images[0].State' <<<"$image") == available ]]
  [[ $(jq -r '.Images[0].Architecture' <<<"$image") == x86_64 ]]
  [[ $(jq -r '.Images[0].RootDeviceType+":"+.Images[0].VirtualizationType' <<<"$image") == ebs:hvm ]]
  parent_owner=$(jq -r '.Images[0].OwnerId' <<<"$image")
  parent_description=$(jq -r '.Images[0].Description // ""' <<<"$image")
  if [[ $flavor == cpu ]]; then
    [[ $parent_owner == 099720109477 ]] || { echo 'CPU parent is not owned by Canonical' >&2; exit 78; }
  else
    [[ $(jq -r '.Images[0].ImageOwnerAlias // ""' <<<"$image") == amazon ]] || {
      echo 'GPU parent is not published under the AWS amazon owner alias' >&2; exit 78;
    }
    description_prefix='Supported EC2 instances: '
    description_suffix='. Release notes:'
    [[ $parent_description == "$description_prefix"*"$description_suffix"* ]] || {
      echo 'GPU parent Description does not contain the canonical supported-instance clause' >&2; exit 78;
    }
    family_clause=${parent_description#"$description_prefix"}
    family_clause=${family_clause%%"$description_suffix"*}
    IFS=, read -r -a parsed_gpu_families <<<"$family_clause"
    ((${#parsed_gpu_families[@]} > 0)) || { echo 'GPU parent Description contains no supported GPU family list' >&2; exit 78; }
    strict_gpu_families=()
    for family in "${parsed_gpu_families[@]}"; do
      family=${family#"${family%%[![:space:]]*}"}
      family=${family%"${family##*[![:space:]]}"}
      family=$(printf '%s' "$family" | tr '[:upper:]' '[:lower:]')
      [[ $family =~ ^(g(r)?[3-9][a-z0-9-]*|p[2-9][a-z0-9-]*)$ ]] || {
        echo "GPU parent Description contains malformed family: $family" >&2; exit 78;
      }
      strict_gpu_families+=("$family")
    done
    mapfile -t canonical_gpu_families < <(printf '%s\n' "${strict_gpu_families[@]}" | sort -u)
    gpu_families=$(IFS=,; printf '%s' "${canonical_gpu_families[*]}")
    build_family=$(printf '%s' "${build_type%%.*}" | tr '[:upper:]' '[:lower:]')
    [[ ,$gpu_families, == *",$build_family,"* ]] || {
      echo "GPU build instance family $build_family is absent from the exact parent Description" >&2; exit 78;
    }
  fi
  [[ $flavor == gpu ]] || gpu_families=''
  root_device=$(jq -er '.Images[0].RootDeviceName' <<<"$image")
  root_snapshot=$(jq -er --arg root "$root_device" '.Images[0].BlockDeviceMappings[] | select(.DeviceName == $root) | .Ebs.SnapshotId' <<<"$image")
  [[ $root_snapshot =~ ^snap-[0-9a-f]{8,17}$ ]] || { echo 'parent root snapshot is missing' >&2; exit 78; }
  snapshot=$(aws_read_json ec2 describe-snapshots --snapshot-ids "$root_snapshot")
  [[ $(jq '.Snapshots | length' <<<"$snapshot") == 1 ]]
  [[ $(jq -r '.Snapshots[0].OwnerId' <<<"$snapshot") == "$parent_owner" ]] || {
    echo 'parent root snapshot owner does not match the exact parent AMI owner' >&2; exit 78;
  }
  root_min_gib=$(jq -er '.Snapshots[0].VolumeSize' <<<"$snapshot")
  [[ $root_min_gib =~ ^[1-9][0-9]*$ ]] || { echo 'parent snapshot minimum is invalid' >&2; exit 78; }

  subnet=$(aws_read_json ec2 describe-subnets --subnet-ids "$subnet_id")
  [[ $(jq -r '.Subnets[0] | [.OwnerId,.State,(.MapPublicIpOnLaunch|tostring)] | join(":")' <<<"$subnet") == "$account_id:available:false" ]] || {
    echo 'subnet must be same-account, available, and private without public-IP mapping' >&2; exit 78;
  }
  subnet_vpc=$(jq -r '.Subnets[0].VpcId' <<<"$subnet")
  group=$(aws_read_json ec2 describe-security-groups --group-ids "$security_group_id")
  [[ $(jq -r '.SecurityGroups[0] | [.OwnerId,.VpcId,(.IpPermissions|length)] | join(":")' <<<"$group") == "$account_id:$subnet_vpc:0" ]] || {
    echo 'build security group must be same-account, same-VPC, and have zero ingress' >&2; exit 78;
  }
  offering=$(aws_read_json ec2 describe-instance-type-offerings --location-type region --filters "Name=instance-type,Values=$build_type")
  [[ $(jq '.InstanceTypeOfferings | length' <<<"$offering") -gt 0 ]] || { echo 'build instance type is unavailable in this Region' >&2; exit 78; }
  type_info=$(aws_read_json ec2 describe-instance-types --instance-types "$build_type")
  [[ $(jq -r '.InstanceTypes[0].ProcessorInfo.SupportedArchitectures | index("x86_64") != null' <<<"$type_info") == true ]]
  if [[ $flavor == gpu ]]; then
    [[ $(jq -r '(.InstanceTypes[0].GpuInfo.Gpus // []) | map(.Count) | add // 0' <<<"$type_info") -gt 0 ]] || {
      echo 'GPU image tests require a GPU build instance type' >&2; exit 78;
    }
  fi
  verify_identity
  profile=$($aws_cli iam get-instance-profile --instance-profile-name "$instance_profile" --output json)
  verify_identity
  [[ $(jq -r '.InstanceProfile.Arn' <<<"$profile") == arn:aws*:iam::${account_id}:instance-profile/* ]] || {
    echo 'instance profile account mismatch' >&2; exit 78;
  }
  for requested_region in "${distribution_region_list[@]}"; do
    key_metadata=$(aws_read_json_region "$requested_region" kms describe-key --key-id "${kms_key_by_region[$requested_region]}")
    [[ $(jq -r '.KeyMetadata | [.AWSAccountId,.Arn,.Enabled,(.KeyUsage=="ENCRYPT_DECRYPT"),(.KeyState=="Enabled")] | map(tostring) | join(":")' <<<"$key_metadata") == "$account_id:${kms_key_by_region[$requested_region]}:true:true:true" ]] || {
      echo "KMS key is not an enabled same-account encryption key in $requested_region" >&2; exit 78;
    }
  done
fi

mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
extension_b64=$(base64 -w0 "$plugin_extension")
agent_b64=$(base64 -w0 "$plugin_agent")
for kind in install test; do
  sed -e "s/__FLAVOR__/$flavor/g" \
      -e "s/__GPU_FAMILIES__/$gpu_families/g" \
      -e "s|__SUBAGENT_EXTENSION_B64__|$extension_b64|g" \
      -e "s|__SUBAGENT_AGENT_B64__|$agent_b64|g" \
      "$cloud_dir/components/$kind.yaml.in" >"$output_dir/$kind.yaml"
done

name=dirextalk-worker-$flavor-1-0-0
tags=$(jq -n --arg flavor "$flavor" --arg gpu_families "$gpu_families" '{DirextalkWorkerImageSchema:"1",DirextalkWorkerImageFlavor:$flavor,DirextalkWorkerImageVersion:"1.0.0",DirextalkPiVersion:"0.84.1",DirextalkImageTested:"true"} + if $flavor == "gpu" then {DirextalkGPUSupportedFamilies:$gpu_families} else {} end')
jq -n --arg name "$name-install" --rawfile data "$output_dir/install.yaml" \
  --argjson tags "$tags" '{name:$name,semanticVersion:"1.0.0",description:"Dirextalk Worker install component 1.0.0",platform:"Linux",data:$data,tags:$tags}' \
  >"$output_dir/build-component.json"
jq -n --arg name "$name-test" --rawfile data "$output_dir/test.yaml" \
  --argjson tags "$tags" '{name:$name,semanticVersion:"1.0.0",description:"Dirextalk Worker test component 1.0.0",platform:"Linux",data:$data,tags:$tags}' \
  >"$output_dir/test-component.json"
jq -n --arg name "$name-infrastructure" --arg profile "$instance_profile" --arg type "$build_type" \
  --arg subnet "$subnet_id" --arg sg "$security_group_id" --argjson tags "$tags" \
  '{name:$name,description:"Dirextalk Worker Image Builder infrastructure 1.0.0",instanceProfileName:$profile,instanceTypes:[$type],subnetId:$subnet,securityGroupIds:[$sg],terminateInstanceOnFailure:true,instanceMetadataOptions:{httpTokens:"required",httpPutResponseHopLimit:1},tags:$tags}' \
  >"$output_dir/infrastructure.json"
jq -n --arg name "$name-distribution" --arg account "$account_id" --arg flavor "$flavor" --argjson regions "$distribution_regions_json" --argjson kms "$kms_keys_json" --argjson tags "$tags" \
  '{name:$name,description:"Dirextalk Worker allowlisted multi-Region distribution 1.0.0",distributions:[$regions[] as $region|{region:$region,amiDistributionConfiguration:{name:("dirextalk-worker-"+$flavor+"-1.0.0-"+$region+"-{{ imagebuilder:buildDate }}"),description:"Dirextalk Worker AMI 1.0.0",kmsKeyId:$kms[$region],amiTags:$tags},ssmParameterConfigurations:[{amiAccountId:$account,parameterName:("/dirextalk/worker-images/v1/"+$flavor+"/candidate"),dataType:"aws:ec2:image"}]}],tags:$tags}' \
  >"$output_dir/distribution.json"
jq -n --arg name "$name" --arg parent "$parent_ami" --arg root "$root_device" --arg snapshot "$root_snapshot" \
  --arg min "$root_min_gib" --argjson tags "$tags" \
  '{name:$name,semanticVersion:"1.0.0",description:"Dirextalk Worker image recipe 1.0.0",parentImage:$parent,components:[{componentArn:"REPLACE_BUILD_COMPONENT_ARN"},{componentArn:"REPLACE_TEST_COMPONENT_ARN"}],blockDeviceMappings:[{deviceName:$root,ebs:{deleteOnTermination:true,encrypted:true,volumeType:"gp3"}}],workingDirectory:"/tmp",additionalInstanceConfiguration:{systemsManagerAgent:{uninstallAfterBuild:false}},tags:($tags+{DirextalkParentSnapshot:$snapshot,DirextalkParentRootMinGiB:$min})}' \
  >"$output_dir/recipe.json"
jq -n --arg name "$name-pipeline" --argjson tags "$tags" \
  '{name:$name,description:"On-demand Dirextalk Worker image pipeline 1.0.0",status:"DISABLED",imageRecipeArn:"REPLACE_RECIPE_ARN",infrastructureConfigurationArn:"REPLACE_INFRASTRUCTURE_ARN",distributionConfigurationArn:"REPLACE_DISTRIBUTION_ARN",imageTestsConfiguration:{imageTestsEnabled:true,timeoutMinutes:90},enhancedImageMetadataEnabled:true,tags:$tags}' \
  >"$output_dir/pipeline.json"
jq -n --arg schema dirextalk.worker-image-render/v1 --arg account "$account_id" --arg region "$region" --arg flavor "$flavor" \
  --arg parent_parameter "$parent_parameter" --arg parent_ami "$parent_ami" --arg parent_owner "$parent_owner" \
  --arg parent_description "$parent_description" --arg gpu_families "$gpu_families" \
  --arg root_device "$root_device" --arg root_snapshot "$root_snapshot" --arg root_min "$root_min_gib" \
  --arg build_type "$build_type" --arg profile "$instance_profile" --arg subnet "$subnet_id" --arg sg "$security_group_id" \
  --argjson distribution_regions "$distribution_regions_json" --argjson distribution_kms_keys "$kms_keys_json" \
  '{schema:$schema,image_schema:"1",image_version:"1.0.0",pi_version:"0.84.1",account_id:$account,region:$region,distribution_regions:$distribution_regions,distribution_kms_keys:$distribution_kms_keys,flavor:$flavor,parent_parameter:$parent_parameter,parent_ami_id:$parent_ami,parent_owner_id:$parent_owner,parent_description:$parent_description,gpu_supported_families:$gpu_families,parent_root_device:$root_device,parent_root_snapshot_id:$root_snapshot,parent_root_min_gib:$root_min,build_instance_type:$build_type,instance_profile:$profile,subnet_id:$subnet,security_group_id:$sg,ssm:{candidate:("/dirextalk/worker-images/v1/"+$flavor+"/candidate"),current:("/dirextalk/worker-images/v1/"+$flavor+"/current"),previous:("/dirextalk/worker-images/v1/"+$flavor+"/previous")}}' \
  >"$output_dir/render.json"

cat >"$output_dir/manual-commands.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
# Auditable outline only. Prefer manage-release.sh, which identity-fences every call.
aws imagebuilder create-component --region '$region' --cli-input-json file://'$output_dir/build-component.json'
aws imagebuilder create-component --region '$region' --cli-input-json file://'$output_dir/test-component.json'
aws imagebuilder create-infrastructure-configuration --region '$region' --cli-input-json file://'$output_dir/infrastructure.json'
aws imagebuilder create-distribution-configuration --region '$region' --cli-input-json file://'$output_dir/distribution.json'
# Replace component ARNs in recipe.json, create the recipe, replace its/config ARNs in pipeline.json, then create the disabled pipeline.
# Start exactly one build with: aws imagebuilder start-image-pipeline-execution --region '$region' --image-pipeline-arn REPLACE_PIPELINE_ARN
# Distribution allowlist: $distribution_regions
# Distribution KMS keys: $distribution_kms_keys
# Image Builder writes the Region-local candidate parameter. Promote only through manage-release.sh publish after every output is AVAILABLE and exact tag read-back succeeds.
EOF
chmod 0700 "$output_dir/manual-commands.sh"
(
  cd -- "$output_dir"
  sha256sum build-component.json distribution.json infrastructure.json install.yaml manual-commands.sh pipeline.json recipe.json render.json test-component.json test.yaml >SHA256SUMS
)
printf 'rendered=%s\naccount=%s\nregion=%s\ndistribution_regions=%s\nflavor=%s\nparent=%s\nroot_snapshot=%s\nroot_min_gib=%s\n' \
  "$output_dir" "$account_id" "$region" "$distribution_regions" "$flavor" "$parent_ami" "$root_snapshot" "$root_min_gib"
