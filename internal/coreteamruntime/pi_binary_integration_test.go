package coreteamruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	piQualificationEnabledEnvironment   = "DIREXTALK_PI_QUALIFY"
	piQualificationBinaryEnvironment    = "DIREXTALK_PI_QUALIFICATION_BINARY"
	piQualificationExtensionEnvironment = "DIREXTALK_PI_QUALIFICATION_EXTENSION"
	piQualificationSandboxEnvironment   = "DIREXTALK_PI_QUALIFICATION_SANDBOX"
	pi083LinuxAMD64ExecutableSHA256     = "c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a"
	piResultExtensionSHA256             = "39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9"
)

func TestOfficialPiBinaryLoopback(t *testing.T) {
	if strings.TrimSpace(os.Getenv(piQualificationEnabledEnvironment)) != "1" {
		t.Skip(piQualificationEnabledEnvironment + " is not enabled")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("authoritative Pi qualification requires linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	binaryPath := strings.TrimSpace(os.Getenv(piQualificationBinaryEnvironment))
	if binaryPath == "" {
		binaryPath = "/opt/dirextalk-worker/runtimes/pi/bin/pi"
	}
	if verifyRegularFile(binaryPath, pi083LinuxAMD64ExecutableSHA256, true) != nil {
		t.Fatalf("Pi %s binary digest or mode is invalid", OfficialPiVersion)
	}
	extensionPath := strings.TrimSpace(os.Getenv(piQualificationExtensionEnvironment))
	if extensionPath == "" {
		var err error
		extensionPath, err = filepath.Abs(filepath.Join("..", "..", "deploy", "container", "pi-worker", "dirextalk-result.ts"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if verifyRegularFile(extensionPath, piResultExtensionSHA256, false) != nil {
		t.Fatal("Pi result extension digest or mode is invalid")
	}
	sandboxPath := strings.TrimSpace(os.Getenv(piQualificationSandboxEnvironment))
	if sandboxPath == "" || verifyExecutablePath(sandboxPath) != nil {
		t.Fatal("Pi sandbox launcher is required")
	}

	provider := newPiLoopbackProvider(t)
	defer provider.Close()
	root, err := os.MkdirTemp("", "dirextalk-pi-qualification-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := preparePiDirectory(root); err != nil {
		t.Fatal(err)
	}
	configRoot := filepath.Join(root, "config")
	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	temporaryRoot := filepath.Join(root, "tmp")
	for _, directory := range []string{configRoot, home, workspace, temporaryRoot} {
		if err := os.Mkdir(directory, piDirectoryMode); err != nil {
			t.Fatal(err)
		}
		if err := preparePiDirectory(directory); err != nil {
			t.Fatal(err)
		}
	}
	modelsJSON, err := json.Marshal(map[string]any{"providers": map[string]any{
		"deepseek": map[string]any{
			"baseUrl": provider.URL + "/v1",
			"modelOverrides": map[string]any{"deepseek-v4-pro": map[string]any{
				"maxTokens": 512,
				"compat":    map[string]any{"maxTokensField": "max_tokens"},
			}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(modelsJSON)
	modelsPath := filepath.Join(configRoot, "models.json")
	if err := os.WriteFile(modelsPath, modelsJSON, piConfigFileMode); err != nil {
		t.Fatal(err)
	}
	if err := preparePiFile(modelsPath); err != nil {
		t.Fatal(err)
	}
	assignment := validRuntimeAssignment()
	assignment.Model = ModelBinding{Provider: "deepseek", Name: "deepseek-v4-pro", Interface: "openai_compatible"}
	assignment.Worker.OutputTokens = 512
	paths := []SandboxPath{
		{Path: filepath.Dir(filepath.Dir(binaryPath)), Access: SandboxReadExecute},
		{Path: root, Access: SandboxReadWriteExecute},
	}
	for _, path := range []string{"/usr/bin", "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/share"} {
		paths = appendExistingSandboxPath(paths, path, SandboxReadExecute)
	}
	for _, path := range []string{
		"/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/proc/self",
	} {
		paths = appendExistingSandboxPath(paths, path, SandboxReadOnly)
	}
	for _, path := range []string{"/dev/null", "/dev/urandom"} {
		paths = appendExistingSandboxPath(paths, path, SandboxReadWrite)
	}
	output, processFailure, err := (OSProcessRunner{}).Run(context.Background(), ProcessSpec{
		Executable: binaryPath, Arguments: piArguments(assignment, extensionPath), Directory: workspace,
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin", "HOME": home, "PI_CODING_AGENT_DIR": configRoot, "TMPDIR": temporaryRoot,
			"PI_OFFLINE": "1", "PI_TELEMETRY": "0", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb",
		},
		SecretEnvironment: map[string][]byte{"DEEPSEEK_API_KEY": []byte("loopback-credential-1234567890")},
		Stdin:             []byte("Execute the loopback qualification. Call dirextalk_submit_result exactly once."),
		MaxStdoutBytes:    MaxProcessOutputBytes, MaxStderrBytes: 1 << 20, Timeout: 20 * time.Second,
		Sandbox: &SandboxPolicy{LauncherPath: sandboxPath, MinimumLandlockABI: 2, Paths: paths},
	})
	if err != nil || processFailure.Valid() {
		t.Fatalf("Pi qualification failed: err=%v failure=%s", err, security.RedactText(processFailure.Error()))
	}
	defer clear(output)
	if provider.requests != 1 {
		t.Fatalf("loopback provider requests = %d", provider.requests)
	}
	parsed, failure := parsePiEvents(output)
	if failure.Valid() {
		t.Fatalf("parse real Pi events: %s", failure.Error())
	}
	result, err := buildResult(parsed.final, parsed.usage)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.Summary != "Pi 0.83.0 loopback qualification passed." ||
		result.Usage.InputTokens != 12 || result.Usage.OutputTokens != 8 {
		t.Fatalf("qualification result = %+v", result)
	}
}

type piLoopbackProvider struct {
	*httptest.Server
	requests int
}

func newPiLoopbackProvider(t *testing.T) *piLoopbackProvider {
	t.Helper()
	provider := &piLoopbackProvider{}
	provider.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		if json.Unmarshal(body, &payload) != nil || payload.Model != "deepseek-v4-pro" || payload.MaxTokens != 512 || !containsPiResultTool(payload.Tools) {
			http.Error(writer, "invalid payload", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		chunks := []string{
			`{"id":"loopback-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-loopback-1","type":"function","function":{"name":"dirextalk_submit_result","arguments":"{\"status\":\"completed\",\"summary\":\"Pi 0.83.0 loopback qualification passed.\",\"deliverables\":[],\"tests\":[\"real Pi binary\"],\"risks\":[]}"}}]},"finish_reason":null}]}`,
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
