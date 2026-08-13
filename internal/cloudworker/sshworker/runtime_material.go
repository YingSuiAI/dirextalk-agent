package sshworker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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
	MaxOutputTokens int
}

type RuntimeRequest struct {
	Objective    string
	Architecture string
	Model        RuntimeModel
}

// RuntimeMaterial is ready to pass to ExecuteRequest.WorkerScript. The SSH
// runner must connect SecretStdin to that script's standard input and must not
// log or persist it.
type RuntimeMaterial struct {
	WorkerScript       []byte
	WorkerScriptSHA256 string
	SecretStdin        []byte
}

// CompileRuntime builds the fixed bootstrap for an official Amazon Linux 2023
// host. The natural-language objective is encoded as data and fed to Pi on
// stdin; it is never evaluated by the shell.
func CompileRuntime(request RuntimeRequest) (RuntimeMaterial, error) {
	objective := strings.TrimSpace(request.Objective)
	if objective == "" || len(objective) > maxObjectiveBytes {
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
	modelConfig, err := json.Marshal(map[string]any{
		"providers": map[string]any{
			"dirextalk-worker": map[string]any{
				"baseUrl": request.Model.BaseURL,
				"api":     api,
				"apiKey":  "$DIREXTALK_MODEL_API_KEY",
				"models": []any{map[string]any{
					"id": request.Model.Name, "reasoning": true,
					"maxTokens": request.Model.MaxOutputTokens,
				}},
			},
		},
	})
	if err != nil {
		return RuntimeMaterial{}, ErrInvalid
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

mkdir -p -- "$runtime_root" "$config_root" "$artifact_root"
sudo dnf -q -y install ca-certificates curl git gzip tar >/dev/null
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "$archive" %s
printf '%%s  %%s\n' %s "$archive" | sha256sum -c - >/dev/null
tar -xzf "$archive" -C "$runtime_root" --strip-components=1
rm -f -- "$archive"
test "$("$pi_bin" --version)" = %s

printf '%%s' %s | base64 --decode > "$config_root/models.json"
printf '%%s' %s | base64 --decode > "$worker_root/objective.txt"
chmod 600 "$config_root/models.json" "$worker_root/objective.txt"

IFS= read -r encoded_model_key
model_key="$(printf '%%s' "$encoded_model_key" | base64 --decode)"
test -n "$model_key"

cd -- "$worker_root/workspace"
DIREXTALK_MODEL_API_KEY="$model_key" \
PI_CODING_AGENT_DIR="$config_root" \
PI_TELEMETRY=0 NO_COLOR=1 TERM=dumb \
  "$pi_bin" --mode text --print --no-session \
  --provider dirextalk-worker --model %s \
  --thinking medium --tools read,bash,edit,write,grep,find,ls \
  --no-extensions --no-skills --no-prompt-templates --no-themes \
  --no-context-files --no-approve \
  --system-prompt %s \
  < "$worker_root/objective.txt" | tee "$artifact_root/final-report.md"
model_key=
`,
		shellQuote("https://github.com/earendil-works/pi/releases/download/v"+PiReleaseVersion+"/"+archive),
		shellQuote(archiveSHA256), shellQuote(PiReleaseVersion),
		shellQuote(base64.StdEncoding.EncodeToString(modelConfig)),
		shellQuote(base64.StdEncoding.EncodeToString([]byte(objective))),
		shellQuote(request.Model.Name),
		shellQuote("Complete the supplied objective on this temporary remote host. Use the workspace and shell tools as needed. Write every user-facing deliverable under /tmp/dirextalk-worker/artifacts. Your final response must be a concise report of the work, deployment flow, verification, actual server load, and artifact paths. Never expose credentials or hidden configuration."),
	)
	digest := sha256.Sum256([]byte(script))
	secret := []byte(base64.StdEncoding.EncodeToString([]byte(request.Model.APIKey)) + "\n")
	return RuntimeMaterial{
		WorkerScript:       []byte(script),
		WorkerScriptSHA256: hex.EncodeToString(digest[:]),
		SecretStdin:        secret,
	}, nil
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
		model.MaxOutputTokens > 0 && model.MaxOutputTokens <= 262_144
}
