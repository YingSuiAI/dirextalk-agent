package workerruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	piQualificationBinaryEnvironment = "DIREXTALK_PI_QUALIFICATION_BINARY"
	pi083DarwinARM64ExecutableSHA256 = "c4e195fd511fd3eac2bfd91d5058b456248c62202871efe23f13e299d49dd642"
	pi083LinuxAMD64ExecutableSHA256  = "c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a"
	piResultExtensionSHA256          = "c7d74946490d70f2be2d3da55b34e95ca273b3a7c64aa348bf9b90d78eaa6cc0"
)

func TestPi083RealBinaryLoopbackQualification(t *testing.T) {
	binaryPath := strings.TrimSpace(os.Getenv(piQualificationBinaryEnvironment))
	if binaryPath == "" {
		t.Skip(piQualificationBinaryEnvironment + " is not configured")
	}
	expectedBinaryDigest, ok := pi083ExecutableDigest(runtime.GOOS, runtime.GOARCH)
	if !ok {
		t.Skipf("Pi 0.83.0 qualification is unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	requireFileDigest(t, binaryPath, expectedBinaryDigest)
	extensionPath, err := filepath.Abs(filepath.Join(
		"..", "..", "deploy", "container", "pi-worker", "dirextalk-result.ts",
	))
	if err != nil {
		t.Fatal(err)
	}
	requireFileDigest(t, extensionPath, piResultExtensionSHA256)

	provider := newPiLoopbackProvider(t)
	defer provider.Close()
	root := t.TempDir()
	configRoot := filepath.Join(root, "config")
	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	for _, directory := range []string{configRoot, home, workspace} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	models := map[string]any{"providers": map[string]any{
		"deepseek": map[string]any{
			"baseUrl": provider.URL + "/v1",
			"modelOverrides": map[string]any{
				"deepseek-v4-pro": map[string]any{
					"maxTokens": 512,
					"compat": map[string]any{
						"maxTokensField": "max_tokens",
					},
				},
			},
		},
	}}
	modelsJSON, err := json.Marshal(models)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configRoot, "models.json"), modelsJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	task := validPiTask()
	task.ModelProfileID = "deepseek-v4-pro"
	task.ModelProvider = "deepseek"
	task.Model = "deepseek-v4-pro"
	task.ModelInterface = ModelOpenAICompatible
	task.MaxOutputTokens = 512
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, piArguments(task, extensionPath)...)
	command.Dir = workspace
	command.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + home,
		"PI_CODING_AGENT_DIR=" + configRoot,
		"PI_OFFLINE=1",
		"PI_TELEMETRY=0",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TERM=dumb",
		"DEEPSEEK_API_KEY=loopback-credential-1234567890",
	}
	command.Stdin = bytes.NewReader([]byte(
		"Execute the loopback qualification. Call dirextalk_submit_result exactly once.",
	))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf(
			"Pi qualification process failed: %v stderr=%q",
			err,
			security.RedactText(stderr.String()),
		)
	}
	if provider.requests != 1 {
		t.Fatalf("loopback provider requests = %d", provider.requests)
	}
	usage, finalJSON, err := parsePiEvents(stdout.Bytes())
	if err != nil {
		t.Fatalf("parse real Pi events: %v", err)
	}
	defer clear(finalJSON)
	final, canonical, err := ParsePiFinalV1(finalJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	if final.Status != "completed" ||
		final.Summary != "Pi 0.83.0 loopback qualification passed." ||
		usage.InputTokens != 12 ||
		usage.OutputTokens != 8 {
		t.Fatalf("qualification final=%+v usage=%+v", final, usage)
	}
}

type piLoopbackProvider struct {
	*httptest.Server
	requests int
}

func newPiLoopbackProvider(t *testing.T) *piLoopbackProvider {
	t.Helper()
	provider := &piLoopbackProvider{}
	provider.Server = httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		provider.requests++
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" {
			http.Error(writer, "unexpected request", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil {
			t.Error(err)
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		defer clear(body)
		var payload struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			Tools     []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if json.Unmarshal(body, &payload) != nil ||
			payload.Model != "deepseek-v4-pro" ||
			payload.MaxTokens != 512 ||
			!containsPiResultTool(payload.Tools) {
			t.Errorf(
				"unexpected Pi provider payload model=%q max_tokens=%d tools=%d",
				payload.Model,
				payload.MaxTokens,
				len(payload.Tools),
			)
			http.Error(writer, "invalid payload", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		chunks := []string{
			`{"id":"loopback-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-loopback-1","type":"function","function":{"name":"dirextalk_submit_result","arguments":"{\"status\":\"completed\",\"summary\":\"Pi 0.83.0 loopback qualification passed.\",\"deliverables\":[],\"tests\":[\"real Pi binary\"],\"risks\":[],\"artifacts\":[]}"}}]},"finish_reason":null}]}`,
			`{"id":"loopback-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":0}}}`,
		}
		for _, chunk := range chunks {
			_, _ = fmt.Fprintf(writer, "data: %s\n\n", chunk)
		}
		_, _ = io.WriteString(writer, "data: [DONE]\n\n")
	}))
	return provider
}

func containsPiResultTool(tools []struct {
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}) bool {
	for _, tool := range tools {
		if tool.Function.Name == piResultToolName {
			return true
		}
	}
	return false
}

func pi083ExecutableDigest(goos, goarch string) (string, bool) {
	switch goos + "/" + goarch {
	case "darwin/arm64":
		return pi083DarwinARM64ExecutableSHA256, true
	case "linux/amd64":
		return pi083LinuxAMD64ExecutableSHA256, true
	default:
		return "", false
	}
}

func requireFileDigest(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	digest := sha256.Sum256(content)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		t.Fatalf("%s digest = %s, want %s", filepath.Base(path), actual, expected)
	}
}
