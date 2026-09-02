#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: manage-release.sh create|build|publish|rollback|cleanup --bundle DIR
       [--image-build-version-arn ARN] [--execute --confirm-costs]
Without both mutation flags the command prints its exact plan and exits without writes.
EOF
  exit 64
}

action=${1:-}; (($#)) && shift || true
bundle=''
image_build_arn=''
execute=false
confirm_costs=false
while (($#)); do
  case "$1" in
    --bundle) bundle=${2:-}; shift 2 ;;
    --image-build-version-arn) image_build_arn=${2:-}; shift 2 ;;
    --execute) execute=true; shift ;;
    --confirm-costs) confirm_costs=true; shift ;;
    *) usage ;;
  esac
done
case "$action" in create|build|publish|rollback|cleanup) ;; *) usage ;; esac
[[ -d $bundle && ! -L $bundle ]] || usage
bundle=$(cd -- "$bundle" && pwd -P)
for file in SHA256SUMS render.json; do
  [[ -f $bundle/$file && ! -L $bundle/$file ]] || { echo "unsafe or missing bundle file: $file" >&2; exit 66; }
done
(cd -- "$bundle" && sha256sum -c SHA256SUMS >/dev/null)

command -v aws >/dev/null || { echo 'AWS CLI is required' >&2; exit 69; }
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 69; }
account_id=$(jq -er .account_id "$bundle/render.json")
region=$(jq -er .region "$bundle/render.json")
flavor=$(jq -er .flavor "$bundle/render.json")
mapfile -t distribution_regions < <(jq -er '.distribution_regions[]' "$bundle/render.json")
parent_ami=$(jq -er .parent_ami_id "$bundle/render.json")
root_snapshot=$(jq -er .parent_root_snapshot_id "$bundle/render.json")
root_min=$(jq -er .parent_root_min_gib "$bundle/render.json")
[[ $account_id =~ ^[0-9]{12}$ && $region =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]
[[ $flavor == cpu || $flavor == gpu ]]
(( ${#distribution_regions[@]} > 0 )) || { echo 'distribution Region allowlist is empty' >&2; exit 78; }
for distribution_region in "${distribution_regions[@]}"; do
  [[ $distribution_region =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || { echo 'distribution Region is malformed' >&2; exit 78; }
done
[[ $(jq -r '.visibility+":"+(.snapshot_encrypted|tostring)' "$bundle/render.json") == public:false ]] || {
  echo 'release bundle is not the public unencrypted image contract' >&2; exit 78;
}
[[ $(printf '%s\n' "${distribution_regions[@]}" | sort -u | paste -sd, -) == $(printf '%s\n' "${distribution_regions[@]}" | paste -sd, -) ]] || {
  echo 'distribution Region allowlist is not sorted and unique' >&2; exit 78;
}
printf '%s\n' "${distribution_regions[@]}" | grep -qxF "$region" || { echo 'source Region is absent from distribution allowlist' >&2; exit 78; }
[[ $parent_ami =~ ^ami-[0-9a-f]{8,17}$ && $root_snapshot =~ ^snap-[0-9a-f]{8,17}$ && $root_min =~ ^[1-9][0-9]*$ ]] || {
  echo 'offline placeholder bundle cannot execute; rerender with live AWS reads' >&2; exit 78;
}

aws_cli=$(command -v aws)
verify_identity() {
  local call_region=${1:-$region} observed allowed=false listed
  for listed in "${distribution_regions[@]}"; do [[ $listed == "$call_region" ]] && allowed=true; done
  $allowed || { echo "AWS call Region is outside rendered allowlist: $call_region" >&2; return 77; }
  observed=$($aws_cli sts get-caller-identity --region "$call_region" --query Account --output text) || return $?
  [[ $observed == "$account_id" ]] || { echo "AWS account changed: expected $account_id, observed $observed" >&2; return 77; }
}
aws_json() {
  verify_identity
  $aws_cli "$@" --region "$region" --output json
}
aws_json_region() {
  local call_region=$1
  shift
  verify_identity "$call_region"
  $aws_cli "$@" --region "$call_region" --output json
}
require_mutation_gate() {
  if ! $execute || ! $confirm_costs; then
    printf 'dry_run=true\naction=%s\naccount=%s\nsource_region=%s\ndistribution_regions=%s\nflavor=%s\n' \
      "$action" "$account_id" "$region" "$(IFS=,; printf '%s' "${distribution_regions[*]}")" "$flavor"
    case "$action" in
      create) printf 'would_create=components,recipe,infrastructure,distribution,disabled-pipeline\n' ;;
      build) printf 'would_start=one-on-demand-image-pipeline-execution\n' ;;
      publish) printf 'would_promote=%s\n' "$image_build_arn" ;;
      rollback) printf 'would_swap=verified-region-local-current-and-previous\n' ;;
      cleanup) printf 'would_retain=exact-current-plus-previous-and-remove-older-tagged-images\n' ;;
    esac
    exit 0
  fi
  verify_identity
}
validate_arn() {
  local arn=$1 service=$2
  [[ $arn == arn:aws*:"$service":"$region":"$account_id":* ]] || {
    echo "resource ARN is outside rendered account/Region: $arn" >&2; exit 78;
  }
}
verify_parent_again() {
  local image observed_root observed_snapshot observed_size
  image=$(aws_json ec2 describe-images --image-ids "$parent_ami")
  [[ $(jq -r '.Images[0].ImageId+":"+.Images[0].State+":"+.Images[0].Architecture' <<<"$image") == "$parent_ami:available:x86_64" ]]
  observed_root=$(jq -er '.Images[0].RootDeviceName' <<<"$image")
  observed_snapshot=$(jq -er --arg root "$observed_root" '.Images[0].BlockDeviceMappings[]|select(.DeviceName==$root)|.Ebs.SnapshotId' <<<"$image")
  [[ $observed_snapshot == "$root_snapshot" ]] || { echo 'parent root snapshot changed after render' >&2; exit 78; }
  observed_size=$(jq -er --arg root "$observed_root" '.Images[0].BlockDeviceMappings[]|select(.DeviceName==$root)|.Ebs.VolumeSize' <<<"$image")
  [[ $observed_size == "$root_min" ]] || { echo 'parent AMI root minimum changed after render' >&2; exit 78; }
  [[ $(jq -r --arg root "$observed_root" '.blockDeviceMappings[]|select(.deviceName==$root)|.ebs.volumeSize // "inherited"' "$bundle/recipe.json") == inherited ]] || {
    echo 'recipe must inherit the parent root snapshot minimum' >&2; exit 78;
  }
}
resource_ids=$bundle/resource-ids.json
require_resource_ids() {
  [[ -f $resource_ids && ! -L $resource_ids ]] || { echo 'resource-ids.json is missing; run create first' >&2; exit 66; }
}

create_release() {
  require_mutation_gate
  verify_parent_again
  local build test infra dist recipe pipeline recipe_payload pipeline_payload
  local journal=$bundle/creation-journal.ndjson
  [[ ! -e $journal || -f $journal && ! -L $journal ]] || { echo 'unsafe creation journal' >&2; exit 66; }
  : >>"$journal"
  chmod 0600 "$journal"
  record_created() {
    local kind=$1 arn=$2
    jq -nc --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg kind "$kind" --arg arn "$arn" \
      '{created_at:$at,kind:$kind,arn:$arn}' >>"$journal"
  }
  build=$(aws_json imagebuilder create-component --cli-input-json "file://$bundle/build-component.json")
  build=$(jq -er .componentBuildVersionArn <<<"$build"); validate_arn "$build" imagebuilder
  record_created build_component "$build"
  test=$(aws_json imagebuilder create-component --cli-input-json "file://$bundle/test-component.json")
  test=$(jq -er .componentBuildVersionArn <<<"$test"); validate_arn "$test" imagebuilder
  record_created test_component "$test"
  infra=$(aws_json imagebuilder create-infrastructure-configuration --cli-input-json "file://$bundle/infrastructure.json")
  infra=$(jq -er .infrastructureConfigurationArn <<<"$infra"); validate_arn "$infra" imagebuilder
  record_created infrastructure "$infra"
  dist=$(aws_json imagebuilder create-distribution-configuration --cli-input-json "file://$bundle/distribution.json")
  dist=$(jq -er .distributionConfigurationArn <<<"$dist"); validate_arn "$dist" imagebuilder
  record_created distribution "$dist"
  recipe_payload=$(mktemp); pipeline_payload=$(mktemp)
  trap 'rm -f -- "$recipe_payload" "$pipeline_payload"' RETURN
  jq --arg build "$build" --arg test "$test" '(.components[0].componentArn=$build)|(.components[1].componentArn=$test)' "$bundle/recipe.json" >"$recipe_payload"
  recipe=$(aws_json imagebuilder create-image-recipe --cli-input-json "file://$recipe_payload")
  recipe=$(jq -er .imageRecipeArn <<<"$recipe"); validate_arn "$recipe" imagebuilder
  record_created recipe "$recipe"
  jq --arg recipe "$recipe" --arg infra "$infra" --arg dist "$dist" \
    '.imageRecipeArn=$recipe|.infrastructureConfigurationArn=$infra|.distributionConfigurationArn=$dist' \
    "$bundle/pipeline.json" >"$pipeline_payload"
  pipeline=$(aws_json imagebuilder create-image-pipeline --cli-input-json "file://$pipeline_payload")
  pipeline=$(jq -er .imagePipelineArn <<<"$pipeline"); validate_arn "$pipeline" imagebuilder
  record_created pipeline "$pipeline"
  jq -n --arg account "$account_id" --arg region "$region" --arg flavor "$flavor" \
    --arg build "$build" --arg test "$test" --arg infra "$infra" --arg dist "$dist" --arg recipe "$recipe" --arg pipeline "$pipeline" \
    '{schema:"dirextalk.worker-image-resources/v1",account_id:$account,region:$region,flavor:$flavor,build_component_arn:$build,test_component_arn:$test,infrastructure_arn:$infra,distribution_arn:$dist,recipe_arn:$recipe,pipeline_arn:$pipeline}' \
    >"$resource_ids"
  chmod 0600 "$resource_ids"
  printf 'created=true\npipeline_arn=%s\n' "$pipeline"
}

build_release() {
  require_mutation_gate
  require_resource_ids
  local pipeline observed started
  pipeline=$(jq -er .pipeline_arn "$resource_ids"); validate_arn "$pipeline" imagebuilder
  observed=$(aws_json imagebuilder get-image-pipeline --image-pipeline-arn "$pipeline")
  [[ $(jq -r '.imagePipeline.arn' <<<"$observed") == "$pipeline" ]]
  [[ $(jq -r '.imagePipeline.status' <<<"$observed") == DISABLED ]]
  verify_parent_again
  started=$(aws_json imagebuilder start-image-pipeline-execution --image-pipeline-arn "$pipeline")
  image_build_arn=$(jq -er .imageBuildVersionArn <<<"$started"); validate_arn "$image_build_arn" imagebuilder
  printf 'build_started=true\nimage_build_version_arn=%s\n' "$image_build_arn"
}

# shellcheck disable=SC2016 # jq variables are interpreted by jq.
expected_tag_query='(.Tags|map({key:.Key,value:.Value})|from_entries) as $t | $t.DirextalkWorkerImageSchema=="1" and $t.DirextalkWorkerImageFlavor==$flavor and $t.DirextalkWorkerImageVersion=="1.1.0" and $t.DirextalkPiVersion=="0.84.4" and $t.DirextalkImageTested=="true"'
verify_output_ami() {
  local call_region=$1 ami=$2 image permission
  [[ $ami =~ ^ami-[0-9a-f]{8,17}$ ]] || return 1
  image=$(aws_json_region "$call_region" ec2 describe-images --image-ids "$ami")
  [[ $(jq '.Images|length' <<<"$image") == 1 ]]
  [[ $(jq -r '.Images[0].OwnerId+":"+.Images[0].State' <<<"$image") == "$account_id:available" ]]
  jq -e --arg flavor "$flavor" ".Images[0] | $expected_tag_query" <<<"$image" >/dev/null
  permission=$(aws_json_region "$call_region" ec2 describe-image-attribute --image-id "$ami" --attribute launchPermission)
  jq -e '.LaunchPermissions | any(.Group=="all")' <<<"$permission" >/dev/null || {
    echo 'output AMI is not public' >&2; return 1;
  }
  if [[ $flavor == gpu ]]; then
    local expected_families
    expected_families=$(jq -er .gpu_supported_families "$bundle/render.json")
    [[ $expected_families =~ ^(g(r)?[3-9][a-z0-9-]*|p[2-9][a-z0-9-]*)(,(g(r)?[3-9][a-z0-9-]*|p[2-9][a-z0-9-]*))*$ ]]
    jq -e --arg families "$expected_families" '(.Images[0].Tags|map({key:.Key,value:.Value})|from_entries).DirextalkGPUSupportedFamilies == $families' <<<"$image" >/dev/null
  fi
  local device snapshot size
  device=$(jq -er '.Images[0].RootDeviceName' <<<"$image")
  snapshot=$(jq -er --arg root "$device" '.Images[0].BlockDeviceMappings[]|select(.DeviceName==$root)|.Ebs.SnapshotId' <<<"$image")
  local snapshot_detail snapshot_permission
  snapshot_detail=$(aws_json_region "$call_region" ec2 describe-snapshots --snapshot-ids "$snapshot")
  [[ $(jq -r '.Snapshots[0].OwnerId+":"+(.Snapshots[0].Encrypted|tostring)' <<<"$snapshot_detail") == "$account_id:false" ]] || { echo 'output AMI root snapshot is not owner-held and unencrypted' >&2; return 1; }
  snapshot_permission=$(aws_json_region "$call_region" ec2 describe-snapshot-attribute --snapshot-id "$snapshot" --attribute createVolumePermission)
  jq -e '.CreateVolumePermissions | any(.Group=="all")' <<<"$snapshot_permission" >/dev/null || {
    echo 'output AMI root snapshot is not public' >&2; return 1;
  }
  size=$(jq -er '.Snapshots[0].VolumeSize' <<<"$snapshot_detail")
  ((size >= root_min)) || { echo 'output AMI root snapshot is smaller than rendered parent minimum' >&2; return 1; }
}
verify_cleanup_ami() {
  local call_region=$1 ami=$2 image version device snapshot snapshot_detail snapshot_permission size families canonical permission
  [[ $ami =~ ^ami-[0-9a-f]{8,17}$ ]] || return 1
  image=$(aws_json_region "$call_region" ec2 describe-images --image-ids "$ami")
  [[ $(jq '.Images|length' <<<"$image") == 1 ]]
  [[ $(jq -r '.Images[0] | [.OwnerId,.State,.Architecture,.RootDeviceType,.VirtualizationType] | join(":")' <<<"$image") == "$account_id:available:x86_64:ebs:hvm" ]]
  permission=$(aws_json_region "$call_region" ec2 describe-image-attribute --image-id "$ami" --attribute launchPermission)
  jq -e '.LaunchPermissions | any(.Group=="all")' <<<"$permission" >/dev/null
  version=$(jq -er '.Images[0].Tags|map({key:.Key,value:.Value})|from_entries|.DirextalkWorkerImageVersion' <<<"$image")
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  jq -e --arg flavor "$flavor" '(.Images[0].Tags|map({key:.Key,value:.Value})|from_entries) as $t | $t.DirextalkWorkerImageSchema=="1" and $t.DirextalkWorkerImageFlavor==$flavor and ($t.DirextalkPiVersion=="0.84.4" or $t.DirextalkPiVersion=="0.84.1") and $t.DirextalkImageTested=="true"' <<<"$image" >/dev/null
  if [[ $flavor == gpu ]]; then
    families=$(jq -er '.Images[0].Tags|map({key:.Key,value:.Value})|from_entries|.DirextalkGPUSupportedFamilies' <<<"$image")
    [[ $families =~ ^(g(r)?[3-9][a-z0-9-]*|p[2-9][a-z0-9-]*)(,(g(r)?[3-9][a-z0-9-]*|p[2-9][a-z0-9-]*))*$ ]]
    canonical=$(tr ',' '\n' <<<"$families" | sort -u | paste -sd, -)
    [[ $families == "$canonical" ]]
  fi
  device=$(jq -er '.Images[0].RootDeviceName' <<<"$image")
  snapshot=$(jq -er --arg root "$device" '.Images[0].BlockDeviceMappings[]|select(.DeviceName==$root)|.Ebs.SnapshotId' <<<"$image")
  snapshot_detail=$(aws_json_region "$call_region" ec2 describe-snapshots --snapshot-ids "$snapshot")
  [[ $(jq -r '.Snapshots[0].OwnerId+":"+(.Snapshots[0].Encrypted|tostring)' <<<"$snapshot_detail") == "$account_id:false" ]]
  snapshot_permission=$(aws_json_region "$call_region" ec2 describe-snapshot-attribute --snapshot-id "$snapshot" --attribute createVolumePermission)
  jq -e '.CreateVolumePermissions | any(.Group=="all")' <<<"$snapshot_permission" >/dev/null
  size=$(jq -er '.Snapshots[0].VolumeSize' <<<"$snapshot_detail")
  ((size >= 8))
}
ssm_optional() {
  local call_region=$1 name=$2 output status error_file
  error_file=$(mktemp "$bundle/.ssm-error.XXXXXX")
  verify_identity "$call_region"
  if output=$($aws_cli ssm get-parameter --name "$name" --region "$call_region" --output json 2>"$error_file"); then
    rm -f "$error_file"
    [[ $(jq -r '.Parameter.DataType' <<<"$output") == aws:ec2:image ]] || { echo "SSM data type mismatch for $name in $call_region" >&2; return 78; }
    jq -er '.Parameter.Value' <<<"$output"
    return 0
  else
    status=$?
    if grep -q 'ParameterNotFound' "$error_file"; then rm -f "$error_file"; return 1; fi
    cat "$error_file" >&2; rm -f "$error_file"; return "$status"
  fi
}
put_ssm() {
  local call_region=$1 name=$2 value=$3
  aws_json_region "$call_region" ssm put-parameter --name "$name" --type String --data-type aws:ec2:image --value "$value" --overwrite >/dev/null
  wait_candidate "$call_region" "$name" "$value" || {
    echo "SSM read-back mismatch for $name in $call_region" >&2; exit 75;
  }
}
wait_candidate() {
  local call_region=$1 name=$2 expected=$3 observed='' status attempt
  for attempt in {1..12}; do
    if observed=$(ssm_optional "$call_region" "$name"); then
      [[ $observed == "$expected" ]] && return 0
    else
      status=$?
      [[ $status == 1 ]] || return "$status"
    fi
    ((attempt < 12)) && sleep 5
  done
  echo "Image Builder candidate did not converge to $expected in $call_region" >&2
  return 75
}

publish_release() {
  require_mutation_gate
  require_resource_ids
  [[ -n $image_build_arn ]] || usage
  validate_arn "$image_build_arn" imagebuilder
  local build recipe expected_recipe ami candidate_path current_path previous_path current call_region count
  declare -A output_amis=()
  build=$(aws_json imagebuilder get-image --image-build-version-arn "$image_build_arn")
  [[ $(jq -r '.image.state.status' <<<"$build") == AVAILABLE ]] || { echo 'Image Builder image is not AVAILABLE' >&2; exit 78; }
  expected_recipe=$(jq -er .recipe_arn "$resource_ids")
  recipe=$(jq -er '.image.imageRecipe.arn' <<<"$build")
  [[ $recipe == "$expected_recipe" ]] || { echo 'build recipe ARN does not match the rendered release' >&2; exit 78; }
  count=$(jq '.image.outputResources.amis|length' <<<"$build")
  ((count == ${#distribution_regions[@]})) || { echo 'build output count does not match the distribution allowlist' >&2; exit 78; }
  jq -e --arg account "$account_id" '[.image.outputResources.amis[].accountId == $account] | all' <<<"$build" >/dev/null || {
    echo 'build contains a cross-account output' >&2; exit 78;
  }
  candidate_path=$(jq -er .ssm.candidate "$bundle/render.json")
  current_path=$(jq -er .ssm.current "$bundle/render.json")
  previous_path=$(jq -er .ssm.previous "$bundle/render.json")
  # Phase one is read-only: validate every regional AMI and bounded-poll every
  # async aws:ec2:image candidate before changing current or previous anywhere.
  for call_region in "${distribution_regions[@]}"; do
    ami=$(jq -er --arg region "$call_region" --arg account "$account_id" '.image.outputResources.amis[]|select(.region==$region and .accountId==$account)|.image' <<<"$build")
    [[ $(wc -l <<<"$ami") == 1 ]] || { echo "build did not produce exactly one AMI in $call_region" >&2; exit 78; }
    verify_output_ami "$call_region" "$ami"
    wait_candidate "$call_region" "$candidate_path" "$ami"
    output_amis[$call_region]=$ami
  done
  # Phase two performs Region-local promotion only after every candidate passed.
  for call_region in "${distribution_regions[@]}"; do
    ami=${output_amis[$call_region]}
    if current=$(ssm_optional "$call_region" "$current_path"); then
      if [[ $current != "$ami" ]]; then
        verify_cleanup_ami "$call_region" "$current"
        put_ssm "$call_region" "$previous_path" "$current"
      fi
    else
      status=$?
      [[ $status == 1 ]] || exit "$status"
    fi
    put_ssm "$call_region" "$current_path" "$ami"
    printf 'region=%s candidate=%s current=%s previous=%s ami=%s\n' "$call_region" "$candidate_path" "$current_path" "$previous_path" "$ami"
  done
  printf 'published=true\n'
}

rollback_release() {
  require_mutation_gate
  local current_path previous_path call_region current previous journal
  declare -A current_amis=() previous_amis=()
  current_path=$(jq -er .ssm.current "$bundle/render.json")
  previous_path=$(jq -er .ssm.previous "$bundle/render.json")
  # Validate both sides in every Region before changing any pointer.
  for call_region in "${distribution_regions[@]}"; do
    current=$(ssm_optional "$call_region" "$current_path") || {
      echo "current AMI is missing in $call_region; rollback refuses to guess" >&2; exit 78;
    }
    previous=$(ssm_optional "$call_region" "$previous_path") || {
      echo "previous AMI is missing in $call_region; rollback refuses to guess" >&2; exit 78;
    }
    [[ $current != "$previous" ]] || { echo "current and previous are identical in $call_region" >&2; exit 78; }
    verify_cleanup_ami "$call_region" "$current"
    verify_cleanup_ami "$call_region" "$previous"
    current_amis[$call_region]=$current
    previous_amis[$call_region]=$previous
  done
  journal=$bundle/rollback-journal.ndjson
  [[ ! -e $journal || -f $journal && ! -L $journal ]] || { echo 'unsafe rollback journal' >&2; exit 66; }
  for call_region in "${distribution_regions[@]}"; do
    current=${current_amis[$call_region]}
    previous=${previous_amis[$call_region]}
    jq -nc --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg region "$call_region" \
      --arg old_current "$current" --arg old_previous "$previous" \
      '{started_at:$at,region:$region,old_current:$old_current,old_previous:$old_previous}' >>"$journal"
    chmod 0600 "$journal"
    put_ssm "$call_region" "$current_path" "$previous"
    put_ssm "$call_region" "$previous_path" "$current"
    printf 'region=%s current=%s previous=%s\n' "$call_region" "$previous" "$current"
  done
  printf 'rolled_back=true\n'
}

cleanup_release() {
  require_mutation_gate
  local current_path previous_path current previous image_list ami detail snapshots snapshot call_region read_file error_file
  declare -A protected_outputs=()
  current_path=$(jq -er .ssm.current "$bundle/render.json")
  previous_path=$(jq -er .ssm.previous "$bundle/render.json")
  for call_region in "${distribution_regions[@]}"; do
    current=''; previous=''
    if current=$(ssm_optional "$call_region" "$current_path"); then :; else status=$?; [[ $status == 1 ]] || exit "$status"; current=''; fi
    if previous=$(ssm_optional "$call_region" "$previous_path"); then :; else status=$?; [[ $status == 1 ]] || exit "$status"; previous=''; fi
    [[ $current =~ ^ami-[0-9a-f]{8,17}$ ]] || { echo "current AMI is missing in $call_region; cleanup refuses to guess" >&2; exit 78; }
    verify_cleanup_ami "$call_region" "$current"
    protected_outputs["$call_region:$current"]=1
    if [[ -n $previous ]]; then verify_cleanup_ami "$call_region" "$previous"; protected_outputs["$call_region:$previous"]=1; fi
    image_list=$(aws_json_region "$call_region" ec2 describe-images --owners self --filters \
      'Name=tag:DirextalkWorkerImageSchema,Values=1' "Name=tag:DirextalkWorkerImageFlavor,Values=$flavor" \
      'Name=tag:DirextalkImageTested,Values=true')
    while IFS= read -r ami; do
      [[ -n $ami ]] || continue
      [[ -n ${protected_outputs["$call_region:$ami"]:-} ]] && continue
      verify_cleanup_ami "$call_region" "$ami"
      detail=$(aws_json_region "$call_region" ec2 describe-images --image-ids "$ami")
      snapshots=$(jq -r '.Images[0].BlockDeviceMappings[].Ebs.SnapshotId // empty' <<<"$detail")
      aws_json_region "$call_region" ec2 deregister-image --image-id "$ami" >/dev/null
      read_file=$(mktemp "$bundle/.cleanup-read.XXXXXX"); error_file=$(mktemp "$bundle/.cleanup-error.XXXXXX")
      verify_identity "$call_region"
      if $aws_cli ec2 describe-images --image-ids "$ami" --region "$call_region" --output json >"$read_file" 2>"$error_file"; then
        [[ $(jq '.Images|length' "$read_file") == 0 ]] || { echo "AMI still exists after deregistration: $call_region/$ami" >&2; exit 75; }
      elif ! grep -q 'InvalidAMIID.NotFound' "$error_file"; then
        cat "$error_file" >&2; exit 75
      fi
      rm -f "$read_file" "$error_file"
      while IFS= read -r snapshot; do
        [[ -n $snapshot ]] || continue
        detail=$(aws_json_region "$call_region" ec2 describe-snapshots --snapshot-ids "$snapshot")
        [[ $(jq -r '.Snapshots[0].OwnerId' <<<"$detail") == "$account_id" ]] || { echo 'snapshot owner changed before cleanup' >&2; exit 77; }
        aws_json_region "$call_region" ec2 delete-snapshot --snapshot-id "$snapshot" >/dev/null
      done <<<"$snapshots"
    done < <(jq -r '.Images[].ImageId' <<<"$image_list")
    printf 'region=%s retained_current=%s retained_previous=%s\n' "$call_region" "$current" "$previous"
  done

  # Image Builder lifecycle COUNT is per recipe version, so enumerate every
  # Dirextalk flavor image resource across recipe versions in this Region.
  local resources version_arn builds resource outputs protect_resource output_region output_ami allowed_output
  resources=$(aws_json imagebuilder list-images --owner Self)
  while IFS= read -r version_arn; do
    [[ -n $version_arn ]] || continue
    validate_arn "$version_arn" imagebuilder
    builds=$(aws_json imagebuilder list-image-build-versions --image-version-arn "$version_arn")
    while IFS= read -r resource; do
      [[ -n $resource ]] || continue
      validate_arn "$resource" imagebuilder
      detail=$(aws_json imagebuilder get-image --image-build-version-arn "$resource")
      outputs=$(jq -r --arg account "$account_id" '.image.outputResources.amis[]?|select(.accountId==$account)|[.region,.image]|@tsv' <<<"$detail")
      [[ -n $outputs ]] || continue
      protect_resource=false
      while IFS=$'\t' read -r output_region output_ami; do
        allowed_output=false
        for call_region in "${distribution_regions[@]}"; do [[ $call_region == "$output_region" ]] && allowed_output=true; done
        if ! $allowed_output || [[ -n ${protected_outputs["$output_region:$output_ami"]:-} ]]; then protect_resource=true; break; fi
      done <<<"$outputs"
      $protect_resource && continue
      # EC2 outputs were identity-checked and removed above; delete only the
      # exact same-account, same-Region Image Builder build-version ARN now.
      aws_json imagebuilder delete-image --image-build-version-arn "$resource" >/dev/null
    done < <(jq -r '.imageSummaryList[]?.arn' <<<"$builds")
  done < <(jq -r --arg prefix "dirextalk-worker-$flavor-" '.imageVersionList[]?|select(.name|startswith($prefix))|.arn' <<<"$resources")
  printf 'cleanup_complete=true\n'
}

case "$action" in
  create) create_release ;;
  build) build_release ;;
  publish) publish_release ;;
  rollback) rollback_release ;;
  cleanup) cleanup_release ;;
esac
