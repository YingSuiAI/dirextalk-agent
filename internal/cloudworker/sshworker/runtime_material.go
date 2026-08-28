package sshworker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
)

const (
	PiReleaseVersion = "0.84.1"

	piLinuxX64SHA256   = "5634d7ebd18274b63af3371e942f342d74bea012389575c1d1ff15ce6ca80c2f"
	piLinuxARM64SHA256 = "ab95c058a4651b5ff5d8c878e524edfb776263c7a444f325505f247c056eecfc"

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
	GitHubPAT       string
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

// CompileRuntime builds the fixed bootstrap for an official Ubuntu 24.04 LTS
// host. The natural-language objective is encoded as data and fed to Pi on
// stdin; it is never evaluated by the shell.
func CompileRuntime(request RuntimeRequest) (RuntimeMaterial, error) {
	objective := strings.TrimSpace(request.Objective)
	if !validID(request.TaskID) || objective == "" || len(objective) > maxObjectiveBytes || !request.Workload.valid() ||
		request.MaxRuntimeSeconds == 0 || request.MaxRuntimeSeconds > 24*60*60 ||
		(request.Workload == WorkloadJob && request.Service != nil) ||
		(request.Workload == WorkloadService && (request.Service == nil || !request.Service.valid())) {
		return RuntimeMaterial{}, ErrInvalid
	}
	archive, archiveSHA256, err := piArchive(request.Architecture)
	if err != nil {
		return RuntimeMaterial{}, err
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
		MaxRuntimeSeconds: request.MaxRuntimeSeconds, Service: request.Service,
	})
	if err != nil {
		return RuntimeMaterial{}, ErrInvalid
	}
	packages := "ca-certificates curl git gh golang-go gzip tar"
	caddyPreflight := ""
	caddySetup := ""
	if request.Service != nil && request.Service.Hostname != "" {
		packages += " caddy"
		caddyPreflight = `caddy_preexisting=false
if command -v caddy >/dev/null 2>&1; then caddy_preexisting=true; fi
`
		caddySetup = `if [[ "$caddy_preexisting" == true ]] && [[ -f /etc/caddy/Caddyfile ]] && ! grep -qxF '# Managed by Dirextalk Agent' /etc/caddy/Caddyfile; then
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
	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
umask 077

readonly worker_root=/tmp/dirextalk-worker
readonly runtime_root="$worker_root/runtime"
readonly config_root="$worker_root/pi-config"
readonly artifact_root="$worker_root/artifacts"
readonly archive="$worker_root/pi.tar.gz"
readonly pi_bin="$runtime_root/pi"
readonly task_root="$worker_root/tasks/%s"

mkdir -p -- "$runtime_root" "$config_root" "$artifact_root" "$task_root"
%s
sudo apt-get -qq update >/dev/null
sudo env DEBIAN_FRONTEND=noninteractive apt-get -qq -y install %s >/dev/null
%s
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "$archive" %s
printf '%%s  %%s\n' %s "$archive" | sha256sum -c - >/dev/null
tar -xzf "$archive" -C "$runtime_root" --strip-components=1
rm -f -- "$archive"
test "$("$pi_bin" --version)" = %s

printf '%%s' %s | base64 --decode > "$config_root/models.json"
printf '%%s' %s | base64 --decode > "$task_root/objective.txt"
printf '%%s' %s | base64 --decode > "$task_root/spec.json"
printf '%%s' %s | base64 --decode > "$worker_root/runner.go"
chmod 600 "$config_root/models.json" "$task_root/objective.txt" "$task_root/spec.json" "$worker_root/runner.go"
cd -- "$worker_root"
go build -trimpath -ldflags='-s -w' -o "$worker_root/dirextalk-worker-runner" "$worker_root/runner.go"
chmod 700 "$worker_root/dirextalk-worker-runner"
"$worker_root/dirextalk-worker-runner" server-status >/dev/null
`,
		request.TaskID,
		caddyPreflight, packages, caddySetup,
		shellQuote("https://github.com/earendil-works/pi/releases/download/v"+PiReleaseVersion+"/"+archive),
		shellQuote(archiveSHA256), shellQuote(PiReleaseVersion),
		shellQuote(base64.StdEncoding.EncodeToString(modelConfig)),
		shellQuote(base64.StdEncoding.EncodeToString([]byte(objective))),
		shellQuote(base64.StdEncoding.EncodeToString(spec)),
		shellQuote(base64.StdEncoding.EncodeToString([]byte(remoteRunnerSource))),
	)
	digest := sha256.Sum256([]byte(script))
	return RuntimeMaterial{
		TaskID:             request.TaskID,
		WorkerScript:       []byte(script),
		WorkerScriptSHA256: hex.EncodeToString(digest[:]),
		Protocol:           RuntimeProtocol{TaskID: request.TaskID, secretEnvelope: encodeRuntimeSecretEnvelope(request.Model.APIKey, request.Model.GitHubPAT)},
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

func piArchive(architecture string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(architecture)) {
	case "amd64", "x86_64":
		return "pi-linux-x64.tar.gz", piLinuxX64SHA256, nil
	case "arm64", "aarch64":
		return "pi-linux-arm64.tar.gz", piLinuxARM64SHA256, nil
	default:
		return "", "", ErrInvalid
	}
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
