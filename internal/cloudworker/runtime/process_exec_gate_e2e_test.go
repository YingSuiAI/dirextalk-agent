//go:build linux && cloud_worker_exec_gate_e2e

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func TestRealUnlimitedPinnedPiProcessTreeUnderExecGate(t *testing.T) {
	if os.Getenv("DIREXTALK_EXEC_GATE_E2E_PROCESS_TREE") != "1" {
		t.Skip("exec-gate process-tree mode is disabled")
	}
	if os.Geteuid() != execGateE2EWorkerUID {
		t.Fatalf("effective uid=%d, want %d", os.Geteuid(), execGateE2EWorkerUID)
	}
	piPath := requiredE2EPath(t, "DIREXTALK_EXEC_GATE_E2E_PI")
	piSHA256, err := digestPath(piPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "dirextalk-exec-gate-tree-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o777); err != nil {
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
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	started := time.Now()
	output, err := bound.Run(ctx, ProcessSpec{
		Executable:               piPath,
		ExpectedExecutableSHA256: piSHA256,
		Arguments: []string{"-c", `
"$PINNED_PI" -c '"$PINNED_PI" -c "sleep 1.1" & sleep 0.9; wait' &
"$PINNED_PI" -c 'sleep 1.2' &
sleep 1.0 &
sleep 0.3
printf root-finished
`},
		Directory: root,
		Environment: map[string]string{
			"PATH": "/usr/local/bin:/usr/bin:/bin", "PINNED_PI": piPath,
		},
		StdoutPolicy:   ProcessStdoutRaw,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	})
	if err != nil {
		t.Fatalf("guarded nested Pi lifecycle failed: %v", err)
	}
	if string(output.Stdout) != "root-finished" || output.RuntimeTopology.ValidateTerminal() != nil {
		t.Fatalf("output=%q topology=%+v", output.Stdout, output.RuntimeTopology)
	}
	if output.RuntimeTopology.TotalAllowedPiExecs < 4 {
		t.Fatalf("authorized Pi exec audit=%d, want at least 4", output.RuntimeTopology.TotalAllowedPiExecs)
	}
	if elapsed := time.Since(started); elapsed < time.Second {
		t.Fatalf("terminal proof returned before child Agents drained: %s", elapsed)
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
			"id": "deepseek-v4-pro", "reasoning": true, "maxTokens": 4096, "contextWindow": 65536,
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
		"settings.json": []byte(`{"compaction":{"enabled":false},"enableInstallTelemetry":false}`),
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
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read Pi request: %v", err)
			return
		}
		if step >= 4 && len(body) > 100<<10 {
			t.Errorf("Pi request %d remained unbounded: %d bytes", step, len(body))
			return
		}
		if err := validateE2EToolPairing(body); err != nil {
			t.Errorf("Pi request %d tool pairing: %v", step, err)
			return
		}
		response.Header().Set("Content-Type", "text/event-stream")
		response.Header().Set("Cache-Control", "no-cache")
		var name, arguments string
		switch step {
		case 1:
			name = "write"
			arguments = `{"path":"answer42.py","content":"def answer():\n    return 42\n\nif __name__ == '__main__':\n    print(answer())\n"}`
		case 2:
			name = "bash"
			arguments = `{"command":"cat > test_answer42.py <<'PY'\nimport unittest\nimport answer42\n\nclass Answer42Test(unittest.TestCase):\n    def test_answer(self):\n        self.assertEqual(answer42.answer(), 42)\n\nif __name__ == '__main__':\n    unittest.main()\nPY\nprintf '# Answer42\\n\\nRun with: python3 answer42.py\\n' > README.md\npython3 -m unittest -v\npython3 -c \"print('x' * 50000)\""}`
		case 3, 4, 5, 6, 7, 8, 9:
			name = "bash"
			arguments = fmt.Sprintf(`{"command":"python3 -c \"print('x' * 50000)\" # context-round-%d"}`, step)
		case 10:
			name = PiResultToolName
			arguments = `{"status":"completed","summary":"Answer42 is implemented and tested through a bounded long-tool loop.","deliverables":["answer42.py","test_answer42.py","README.md"],"tests":["python3 -m unittest -v","eight 50 KiB tool-output rounds"],"risks":[]}`
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
			"usage":   map[string]any{"prompt_tokens": len(body) / 4, "completion_tokens": 20, "total_tokens": len(body)/4 + 20},
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

func validateE2EToolPairing(raw []byte) error {
	var request struct {
		Messages []struct {
			Role       string `json:"role"`
			ToolCallID string `json:"tool_call_id"`
			ToolCalls  []struct {
				ID       string `json:"id"`
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	calls := make(map[string]bool)
	results := make(map[string]bool)
	for _, message := range request.Messages {
		for _, call := range message.ToolCalls {
			if call.ID == "" || calls[call.ID] || call.Function.Arguments == "" {
				return fmt.Errorf("invalid or duplicate tool call %q", call.ID)
			}
			if strings.HasPrefix(call.ID, "call_e2e_") && strings.Contains(call.ID, "3") &&
				!strings.Contains(call.Function.Arguments, "context-round-3") {
				return fmt.Errorf("tool call %q arguments were rewritten", call.ID)
			}
			calls[call.ID] = true
		}
		if message.Role == "tool" {
			if message.ToolCallID == "" || results[message.ToolCallID] {
				return fmt.Errorf("invalid or duplicate tool result %q", message.ToolCallID)
			}
			results[message.ToolCallID] = true
		}
	}
	if len(calls) != len(results) {
		return fmt.Errorf("calls=%d results=%d", len(calls), len(results))
	}
	for id := range results {
		if !calls[id] {
			return fmt.Errorf("orphan tool result %q", id)
		}
	}
	return nil
}
