package sshworker

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/workerimage"
)

//go:embed vendor/pi-subagent/v0.84.1/extension.ts
var vendoredPiSubagentExtension string

//go:embed vendor/pi-subagent/v0.84.1/agents/worker.md
var vendoredPiSubagentWorkerAgent string

const (
	PiReleaseVersion = workerimage.PiVersion

	PiSubagentUpstreamCommit  = "53fa77ccd8a279eb87e92294ef3687b03ff80112"
	PiSubagentExtensionSHA256 = "d81c6e66123fbaeeb585c02f757db8966022aa8649a6c75461bd7a82623f4552"

	maxObjectiveBytes = 128 << 10
)

// RuntimeModel is the secret-bearing model snapshot used for exactly one
// remote execution. APIKey is returned only in RuntimeMaterial.SecretStdin;
// it is never rendered into the worker script or its files.
type RuntimeModel struct {
	Provider        string
	BaseURL         string
	Name            string
	APIKey          string
	MaxOutputTokens int
}

type RuntimeRequest struct {
	TaskID            string
	Objective         string
	Architecture      string
	Workload          WorkloadKind
	MaxRuntimeSeconds uint64
	Service           *RuntimeServiceSpec
	Model             RuntimeModel
	ImageFlavor       string
	EnableSubagent    bool
}

type RuntimeServiceSpec struct {
	WorkloadID string `json:"workload_id"`
	Port       uint16 `json:"port"`
	HealthPath string `json:"health_path"`
	Hostname   string `json:"hostname,omitempty"`
}

func (spec RuntimeServiceSpec) valid() bool {
	return validID(spec.WorkloadID) && spec.Port > 0 && strings.HasPrefix(spec.HealthPath, "/") &&
		len(spec.HealthPath) <= 2048 && !strings.HasPrefix(spec.HealthPath, "//") && !strings.ContainsAny(spec.HealthPath, " \t\r\n#") &&
		(spec.Hostname == "" || (remoteservice.ValidHostname(spec.Hostname) && spec.Port != 80 && spec.Port != 443))
}

// RuntimeMaterial is ready to pass to ExecuteRequest.WorkerScript. The SSH
// runner must connect SecretStdin to that script's standard input and must not
// log or persist it.
type RuntimeMaterial struct {
	TaskID             string
	WorkerScript       []byte
	WorkerScriptSHA256 string
	Protocol           RuntimeProtocol
}

// CompileRuntime builds the fixed bootstrap for a supported Ubuntu 24.04
// Worker host. The natural-language objective is encoded as data and fed to
// Pi on stdin; it is never evaluated by the shell.
func CompileRuntime(request RuntimeRequest) (RuntimeMaterial, error) {
	objective := strings.TrimSpace(request.Objective)
	if !validID(request.TaskID) || objective == "" || len(objective) > maxObjectiveBytes || !request.Workload.valid() ||
		request.MaxRuntimeSeconds == 0 || request.MaxRuntimeSeconds > 24*60*60 ||
		(request.Architecture != "x86_64" && request.Architecture != "amd64") ||
		(request.ImageFlavor != string(workerimage.FlavorCPU) && request.ImageFlavor != string(workerimage.FlavorGPU)) ||
		(request.Workload == WorkloadJob && request.Service != nil) ||
		(request.Workload == WorkloadService && (request.Service == nil || !request.Service.valid())) {
		return RuntimeMaterial{}, ErrInvalid
	}
	api, err := piModelAPI(request.Model.Provider)
	if err != nil || !validRuntimeModel(request.Model) {
		return RuntimeMaterial{}, ErrInvalid
	}
	modelDefinition := map[string]any{
		"id": request.Model.Name, "reasoning": true,
	}
	if request.Model.MaxOutputTokens > 0 {
		modelDefinition["maxTokens"] = request.Model.MaxOutputTokens
	}
	modelConfig, err := json.Marshal(map[string]any{
		"providers": map[string]any{
			"dirextalk-worker": map[string]any{
				"baseUrl": request.Model.BaseURL,
				"api":     api,
				"apiKey":  "$DIREXTALK_MODEL_API_KEY",
				"models":  []any{modelDefinition},
			},
		},
	})
	if err != nil {
		return RuntimeMaterial{}, ErrInvalid
	}
	spec, err := json.Marshal(remoteTaskSpec{
		TaskID: request.TaskID, Workload: request.Workload, Model: request.Model.Name,
		MaxRuntimeSeconds: request.MaxRuntimeSeconds, Service: request.Service, EnableSubagent: request.EnableSubagent,
	})
	if err != nil {
		return RuntimeMaterial{}, ErrInvalid
	}
	caddyPreflight := ""
	caddySetup := ""
	if request.Service != nil && request.Service.Hostname != "" {
		caddyPreflight = "command -v caddy >/dev/null\n"
		caddySetup = `if [[ -f /etc/caddy/Caddyfile ]] && ! grep -qxF '# Managed by Dirextalk Agent' /etc/caddy/Caddyfile; then
  echo 'refusing to replace an unmanaged Caddyfile' >&2
  exit 1
fi
sudo install -d -m 0755 /etc/caddy/dirextalk
caddy_main="$(mktemp)"
trap 'rm -f -- "$caddy_main"' EXIT
printf '%s\n' '# Managed by Dirextalk Agent' 'import /etc/caddy/dirextalk/*.caddy' > "$caddy_main"
sudo caddy validate --config "$caddy_main" --adapter caddyfile >/dev/null
sudo install -m 0644 "$caddy_main" /etc/caddy/Caddyfile
sudo systemctl enable --now caddy.service >/dev/null
sudo systemctl reload caddy.service
rm -f -- "$caddy_main"
trap - EXIT
`
	}
	subagentSetup := ""
	if request.EnableSubagent {
		subagentSetup = `readonly subagent_catalog=/opt/dirextalk-worker/pi-plugin-catalog/dirextalk-subagent
test -f "$subagent_catalog/extension.ts" && test ! -L "$subagent_catalog/extension.ts"
test -f "$subagent_catalog/agents/worker.md" && test ! -L "$subagent_catalog/agents/worker.md"
test "$(stat -c '%U:%G' "$subagent_catalog/extension.ts")" = root:root
test "$(stat -c '%U:%G' "$subagent_catalog/agents/worker.md")" = root:root
printf '%s  %s\n' 'd81c6e66123fbaeeb585c02f757db8966022aa8649a6c75461bd7a82623f4552' "$subagent_catalog/extension.ts" | sha256sum -c - >/dev/null
printf '%s  %s\n' '562434d598f2709150b042c50009ac224557769f0430d5093621530ce27cc7b5' "$subagent_catalog/agents/worker.md" | sha256sum -c - >/dev/null
mkdir -p -- "$config_root/extensions/dirextalk-subagent" "$config_root/agents"
install -m 0600 "$subagent_catalog/extension.ts" "$config_root/extensions/dirextalk-subagent/extension.ts"
install -m 0600 "$subagent_catalog/agents/worker.md" "$config_root/agents/worker.md"
`
	}
	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
umask 077

readonly worker_root=/var/lib/dirextalk-worker
readonly config_root="$worker_root/pi-config"
readonly artifact_root="$worker_root/artifacts"
readonly image_manifest=%s
readonly pi_bin=%s
readonly task_root="$worker_root/tasks/%s"

if [[ -L "$worker_root" ]]; then
  echo 'refusing symlinked Worker state root' >&2
  exit 1
fi
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 "$worker_root"
test -d "$worker_root" && test -O "$worker_root" && test ! -L "$worker_root"
mkdir -p -- "$config_root" "$artifact_root" "$task_root"
%s
test -f "$image_manifest" && test ! -L "$image_manifest"
test "$(stat -c '%%U:%%G:%%a' "$image_manifest")" = root:root:644
jq -e --arg flavor %s '
  .schema == 1 and
  (.image_version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and
  .flavor == $flavor and
  .pi_version == "%s" and
  .tool_baseline == "%s" and
  .tested == true
' "$image_manifest" >/dev/null
verify_coding_tools() {
  command -v python3 >/dev/null
  command -v python >/dev/null
  python3 -m pip --version >/dev/null
  python3 -m venv --help >/dev/null
  command -v node >/dev/null
  command -v npm >/dev/null
  command -v git >/dev/null
  command -v gh >/dev/null
  command -v go >/dev/null
  command -v curl >/dev/null
  command -v tar >/dev/null
  command -v gzip >/dev/null
  command -v cc >/dev/null
  command -v jq >/dev/null
  command -v rg >/dev/null
}
verify_coding_tools
%s
test -x "$pi_bin"
test ! -L "$pi_bin"
test "$(stat -c '%%U:%%G:%%a' "$pi_bin")" = root:root:755
test "$("$pi_bin" --version)" = %s

printf '%%s' %s | base64 --decode > "$config_root/models.json"
printf '%%s' %s | base64 --decode > "$task_root/objective.txt"
printf '%%s' %s | base64 --decode > "$task_root/spec.json"
printf '%%s' %s | base64 --decode > "$worker_root/runner.go"
chmod 600 "$config_root/models.json" "$task_root/objective.txt" "$task_root/spec.json" "$worker_root/runner.go"
%s
cd -- "$worker_root"
go build -trimpath -ldflags='-s -w' -o "$worker_root/dirextalk-worker-runner" "$worker_root/runner.go"
chmod 700 "$worker_root/dirextalk-worker-runner"
"$worker_root/dirextalk-worker-runner" server-status >/dev/null
`,
		shellQuote(workerimage.ManifestPath), shellQuote(workerimage.PiPath), request.TaskID,
		caddyPreflight, shellQuote(request.ImageFlavor), workerimage.PiVersion, workerimage.ToolBaseline,
		caddySetup, shellQuote(PiReleaseVersion),
		shellQuote(base64.StdEncoding.EncodeToString(modelConfig)),
		shellQuote(base64.StdEncoding.EncodeToString([]byte(objective))),
		shellQuote(base64.StdEncoding.EncodeToString(spec)),
		shellQuote(base64.StdEncoding.EncodeToString([]byte(remoteRunnerSource))),
		subagentSetup,
	)
	digest := sha256.Sum256([]byte(script))
	return RuntimeMaterial{
		TaskID:             request.TaskID,
		WorkerScript:       []byte(script),
		WorkerScriptSHA256: hex.EncodeToString(digest[:]),
		Protocol:           RuntimeProtocol{TaskID: request.TaskID, secretEnvelope: encodeRuntimeSecretEnvelope(request.Model.APIKey, "")},
	}, nil
}

type runtimeSecretEnvelope struct {
	Version     int    `json:"version"`
	ModelAPIKey string `json:"model_api_key"`
	GitHubPAT   string `json:"github_pat,omitempty"`
}

func encodeRuntimeSecretEnvelope(modelKey, githubPAT string) string {
	raw, _ := json.Marshal(runtimeSecretEnvelope{Version: 1, ModelAPIKey: modelKey, GitHubPAT: githubPAT})
	return base64.StdEncoding.EncodeToString(raw)
}

func encodeRuntimeSecretEnvelopeFromBase64(baseEnvelope, githubPAT string) string {
	raw, err := base64.StdEncoding.DecodeString(baseEnvelope)
	if err != nil {
		return ""
	}
	var envelope runtimeSecretEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != 1 || strings.TrimSpace(envelope.ModelAPIKey) == "" {
		return ""
	}
	envelope.GitHubPAT = githubPAT
	updated, err := json.Marshal(envelope)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(updated)
}

func piModelAPI(provider string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai", "openai_compatible", "deepseek", "openrouter":
		return "openai-completions", nil
	case "anthropic":
		return "anthropic-messages", nil
	case "gemini", "google":
		return "google-generative-ai", nil
	default:
		return "", ErrInvalid
	}
}

func validRuntimeModel(model RuntimeModel) bool {
	endpoint, err := url.Parse(strings.TrimSpace(model.BaseURL))
	return err == nil && endpoint.Scheme == "https" && endpoint.Host != "" &&
		strings.TrimSpace(model.Name) != "" && len(model.Name) <= 512 &&
		strings.TrimSpace(model.APIKey) != "" && !strings.ContainsAny(model.APIKey, "\r\n") &&
		model.MaxOutputTokens >= 0 && model.MaxOutputTokens <= 1<<20
}
