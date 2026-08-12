//go:build linux && cloud_worker_exec_gate_e2e

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

const (
	execGateE2EWorkerUID = 65531
	execGateE2EPiUID     = 65532
)

func TestRealExecGateServer(t *testing.T) {
	if os.Getenv("DIREXTALK_EXEC_GATE_E2E_SERVER") != "1" {
		t.Skip("exec-gate E2E server mode is disabled")
	}
	config := execgate.DefaultConfig()
	config.WorkerUID = execGateE2EWorkerUID
	config.SocketGID = execGateE2EWorkerUID
	config.WorkerExecutable = requiredE2EPath(t, "DIREXTALK_EXEC_GATE_E2E_WORKER")
	config.PiExecutable = requiredE2EPath(t, "DIREXTALK_EXEC_GATE_E2E_PI")
	_ = os.Remove(config.SocketPath)
	server, err := execgate.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRealPiBashLifecycleUnderExecGate(t *testing.T) {
	if os.Getenv("DIREXTALK_EXEC_GATE_E2E_WORKER_MODE") != "1" {
		t.Skip("exec-gate E2E Worker mode is disabled")
	}
	if os.Geteuid() != execGateE2EWorkerUID {
		t.Fatalf("effective uid=%d, want %d", os.Geteuid(), execGateE2EWorkerUID)
	}
	piPath := requiredE2EPath(t, "DIREXTALK_EXEC_GATE_E2E_PI")
	extensionPath := requiredE2EPath(t, "DIREXTALK_EXEC_GATE_E2E_EXTENSION")
	server := newPiToolLifecycleServer(t)
	defer server.Close()

	root, err := os.MkdirTemp("/tmp", "dirextalk-exec-gate-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	workspace := filepath.Join(root, "workspace")
	home := filepath.Join(root, "home")
	configRoot := filepath.Join(root, "config")
	for _, directory := range []string{root, workspace, home, configRoot} {
		if err := os.MkdirAll(directory, 0o777); err != nil || os.Chmod(directory, 0o777) != nil {
			t.Fatalf("prepare %s: %v", directory, err)
		}
	}
	writeE2EPiConfig(t, configRoot, server.URL+"/v1")
	probe := exec.CommandContext(t.Context(), piPath, "--version")
	probe.Dir = workspace
	probe.Env = []string{"HOME=" + home, "PATH=/usr/local/bin:/usr/bin:/bin"}
	if err := configureProcessCancellation(probe, execGateE2EPiUID, execGateE2EPiUID); err != nil {
		t.Fatal(err)
	}
	if err := startIsolatedProcess(probe, true); err != nil {
		t.Fatalf("setuid Pi probe start failed: %T %v", err, err)
	}
	if err := probe.Wait(); err != nil {
		t.Fatalf("setuid Pi probe wait failed: %T %v", err, err)
	}
	piSHA256, err := digestPath(piPath)
	if err != nil {
		t.Fatal(err)
	}

	runner, err := NewOSProcessRunner(execGateE2EPiUID, execGateE2EPiUID)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := runner.BindProcess(ProcessBinding{
		ExecutionID:       "11111111-1111-4111-8111-111111111111",
		TaskID:            "22222222-2222-4222-8222-222222222222",
		Attempt:           1,
		LeaseEpoch:        1,
		RuntimeTaskSHA256: strings.Repeat("1", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	output, err := bound.Run(ctx, ProcessSpec{
		Executable:               piPath,
		ExpectedExecutableSHA256: piSHA256,
		Arguments: []string{
			"--mode", "json", "--print", "--no-session", "--offline",
			"--provider", "deepseek", "--model", "deepseek-v4-pro",
			"--thinking", "medium", "--tools", "read,bash,edit,write,grep,find,ls,dirextalk_submit_result",
			"--extension", extensionPath,
			"--no-extensions", "--no-skills", "--no-prompt-templates",
			"--no-themes", "--no-context-files", "--no-approve",
			"--system-prompt", piSystemPrompt,
		},
		Directory: workspace,
		Environment: map[string]string{
			"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home,
			"PI_CODING_AGENT_DIR": configRoot, "PI_OFFLINE": "1", "PI_TELEMETRY": "0",
			"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1",
			"NO_PROXY": "127.0.0.1,localhost",
		},
		SecretEnvironment: map[string][]byte{"DEEPSEEK_API_KEY": []byte("e2e-placeholder-token")},
		Stdin:             []byte("Build Answer42, run its unit test, and submit the bounded result."),
		StdoutPolicy:      ProcessStdoutPiEventsV1,
		MaxStdoutBytes:    MaxProcessOutputBytes,
		MaxStderrBytes:    MaxFinalArtifactBytes,
	})
	if err != nil {
		t.Fatalf("guarded Pi lifecycle failed: %v", err)
	}
	if output.RuntimeTopology.ValidateTerminal() != nil {
		t.Fatalf("invalid terminal topology: %+v", output.RuntimeTopology)
	}
	if _, err := os.Stat(filepath.Join(workspace, "answer42.py")); err != nil {
		t.Fatalf("missing Answer42 deliverable: %v", err)
	}
}

func requiredE2EPath(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if !filepath.IsAbs(value) {
		t.Fatalf("%s must be an absolute path", name)
	}
	return value
}

func writeE2EPiConfig(t *testing.T, configRoot, baseURL string) {
	t.Helper()
	config := map[string]any{"providers": map[string]any{"deepseek": map[string]any{
		"baseUrl": baseURL, "api": "openai-completions", "apiKey": "$DEEPSEEK_API_KEY",
		"models": []any{map[string]any{
			"id": "deepseek-v4-pro", "reasoning": true, "maxTokens": 8192,
			"compat": map[string]any{
				"maxTokensField": "max_tokens", "supportsStore": false,
				"supportsDeveloperRole": false, "supportsReasoningEffort": true,
				"thinkingFormat": "deepseek", "requiresReasoningContentOnAssistantMessages": true,
			},
		}},
	}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"models.json":   raw,
		"auth.json":     []byte("{}"),
		"settings.json": []byte(`{"enableInstallTelemetry":false}`),
	} {
		if err := os.WriteFile(filepath.Join(configRoot, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newPiToolLifecycleServer(t *testing.T) *httptest.Server {
	t.Helper()
	var calls atomic.Uint32
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		step := calls.Add(1)
		response.Header().Set("Content-Type", "text/event-stream")
		response.Header().Set("Cache-Control", "no-cache")
		var name, arguments string
		switch step {
		case 1:
			name = "write"
			arguments = `{"path":"answer42.py","content":"def answer():\n    return 42\n\nif __name__ == '__main__':\n    print(answer())\n"}`
		case 2:
			name = "bash"
			arguments = `{"command":"sleep 2\ncat > test_answer42.py <<'PY'\nimport unittest\nimport answer42\n\nclass Answer42Test(unittest.TestCase):\n    def test_answer(self):\n        self.assertEqual(answer42.answer(), 42)\n\nif __name__ == '__main__':\n    unittest.main()\nPY\nprintf '# Answer42\\n\\nRun with: python3 answer42.py\\n' > README.md\npython3 -m unittest -v"}`
		case 3:
			name = PiResultToolName
			arguments = `{"status":"completed","summary":"Answer42 is implemented and tested.","deliverables":["answer42.py","test_answer42.py","README.md"],"tests":["python3 -m unittest -v"],"risks":[]}`
		default:
			http.Error(response, "unexpected request", http.StatusBadRequest)
			return
		}
		chunk := map[string]any{
			"id": fmt.Sprintf("chatcmpl-e2e-%d", step), "object": "chat.completion.chunk",
			"created": time.Now().Unix(), "model": "deepseek-v4-pro",
			"choices": []any{map[string]any{
				"index": 0,
				"delta": map[string]any{
					"role": "assistant", "reasoning_content": "Use the next authorized tool.",
					"tool_calls": []any{map[string]any{
						"index": 0, "id": fmt.Sprintf("call_e2e_%d", step), "type": "function",
						"function": map[string]any{"name": name, "arguments": arguments},
					}},
				},
				"finish_reason": nil,
			}},
		}
		terminal := map[string]any{
			"id": fmt.Sprintf("chatcmpl-e2e-%d", step), "object": "chat.completion.chunk",
			"created": time.Now().Unix(), "model": "deepseek-v4-pro",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "tool_calls"}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
		}
		for _, value := range []any{chunk, terminal} {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Error(err)
				return
			}
			fmt.Fprintf(response, "data: %s\n\n", raw)
		}
		fmt.Fprint(response, "data: [DONE]\n\n")
		if flusher, ok := response.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
}
