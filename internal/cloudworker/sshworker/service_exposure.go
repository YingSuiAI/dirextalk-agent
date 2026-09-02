package sshworker

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
)

func (exposure ServiceExposure) valid() bool {
	return validID(exposure.WorkloadID) && remoteservice.ValidHostname(exposure.Hostname) &&
		exposure.Port != 0 && exposure.Port != 80 && exposure.Port != 443
}

// ReconcileServiceExposure applies one Agent-owned Caddy fragment over the
// Worker's pinned SSH connection. Inputs are validated before becoming remote
// argv, while the fixed script performs candidate validation and rollback.
func (source CommandStatusSource) ReconcileServiceExposure(ctx context.Context, worker WorkerRecord, exposure ServiceExposure) error {
	if source.Keys == nil || worker.Instance.PublicIP == "" || worker.SSHUser == "" || !exposure.valid() {
		return ErrInvalid
	}
	key, found, err := source.Keys.LookupPrivate(ctx, worker.WorkerID)
	if err != nil {
		return err
	}
	if !found {
		return ErrInvalid
	}
	sshPath := source.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	base, err := sshBaseArguments(key, worker.SSHUser, worker.Instance.PublicIP)
	if err != nil {
		return err
	}
	remote := fmt.Sprintf("bash -s -- %s %s %s", shellQuote(exposure.WorkloadID),
		shellQuote(remoteservice.CanonicalHostname(exposure.Hostname)), shellQuote(strconv.Itoa(int(exposure.Port))))
	return sshWithInput(ctx, sshPath, base, remote, strings.NewReader(reconcileServiceExposureScript))
}

const reconcileServiceExposureScript = `set -euo pipefail
umask 077

readonly workload_id="$1"
readonly hostname="$2"
readonly service_port="$3"
readonly caddy_main=/etc/caddy/Caddyfile
readonly caddy_dir=/etc/caddy/dirextalk
readonly target="$caddy_dir/$workload_id.caddy"

if ! command -v caddy >/dev/null 2>&1; then
  echo 'worker image is missing the required caddy baseline' >&2
  exit 1
fi
if [[ -f "$caddy_main" ]] && ! grep -qxF '# Managed by Dirextalk Agent' "$caddy_main"; then
  echo 'refusing to replace an unmanaged Caddyfile' >&2
  exit 1
fi

sudo install -d -m 0755 "$caddy_dir"
candidate="$(mktemp)"
main_candidate="$(mktemp)"
main_previous="$(mktemp)"
target_previous="$(mktemp)"
had_main=false
had_target=false
trap 'rm -f -- "$candidate" "$main_candidate" "$main_previous" "$target_previous"' EXIT
printf '%s {\n\ttls {\n\t\ton_demand\n\t}\n\treverse_proxy 127.0.0.1:%s\n}\n' "$hostname" "$service_port" > "$candidate"
printf '%s\n' '# Managed by Dirextalk Agent' 'import /etc/caddy/dirextalk/*.caddy' > "$main_candidate"
sudo caddy validate --config "$candidate" --adapter caddyfile >/dev/null
if [[ -f "$caddy_main" ]]; then
  sudo cp -- "$caddy_main" "$main_previous"
  had_main=true
fi
if [[ -f "$target" ]]; then
  sudo cp -- "$target" "$target_previous"
  had_target=true
fi

rollback() {
  set +e
  if [[ "$had_target" == true ]]; then
    sudo install -m 0644 "$target_previous" "$target"
  else
    sudo rm -f -- "$target"
  fi
  if [[ "$had_main" == true ]]; then
    sudo install -m 0644 "$main_previous" "$caddy_main"
  else
    sudo rm -f -- "$caddy_main"
  fi
  sudo systemctl reload caddy.service >/dev/null 2>&1 || true
}

sudo install -m 0644 "$main_candidate" "$caddy_main"
sudo install -m 0644 "$candidate" "$target"
if ! sudo caddy validate --config "$caddy_main" --adapter caddyfile >/dev/null ||
   ! sudo systemctl enable --now caddy.service >/dev/null ||
   ! sudo caddy reload --config "$caddy_main" --adapter caddyfile >/dev/null; then
  rollback
  exit 1
fi
`
