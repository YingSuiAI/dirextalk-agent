package sshworker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Exercise the real embedded start/run/report/log consumer, not a parser
// fixture. Only systemd and Pi are replaced by local deterministic commands.
func TestEmbeddedWorkerReportSeparatesFinalReplyAndDiagnostics(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "worker")
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(remoteRunnerSource, `const root = "/var/lib/dirextalk-worker"`, "const root = "+strconv.Quote(root), 1)
	pi := filepath.Join(bin, "pi")
	source = strings.Replace(source, `"/opt/dirextalk-worker/bin/pi"`, strconv.Quote(pi), 1)
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "runner.go"), source, 0600)
	runner := filepath.Join(dir, "runner")
	build := exec.Command("go", "build", "-o", runner, filepath.Join(dir, "runner.go"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	write(filepath.Join(bin, "systemd-run"), "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n case \"$1\" in */pi) exec \"$@\" ;; esac\n shift\ndone\nexit 64\n", 0700)
	eventScript := func(text string) string {
		body, _ := json.Marshal(map[string]any{"type": "message_end", "message": map[string]any{"role": "assistant", "stopReason": "stop", "content": []any{map[string]any{"type": "text", "text": text}}}})
		return "#!/bin/sh\nprintf '%s\\n' " + shellQuote(`{"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","delta":"PRIVATE-THOUGHT"}}`) + " " + shellQuote(`{"type":"tool_execution_start","toolName":"read","args":{"path":"PRIVATE-ARGUMENT"}}`) + " " + shellQuote(`{"type":"tool_execution_end","toolName":"read","result":{"content":"PRIVATE-OUTPUT"},"isError":false}`) + " " + shellQuote(string(body)) + "\nprintf 'PRIVATE-DIAGNOSTIC %s' \"$DIREXTALK_MODEL_API_KEY\" >&2\n"
	}
	env := append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, runner, args...)
		cmd.Env = env
		secret, _ := json.Marshal(map[string]any{"version": 1, "model_api_key": "private-model-key"})
		cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(secret) + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("runner %v: %v %s", args, err, out)
		}
		return out
	}
	for _, taskID := range []string{"ordinary", "bounded", "balance", "http2"} {
		t.Run(taskID, func(t *testing.T) {
			taskRoot := filepath.Join(root, "tasks", taskID)
			if err := os.MkdirAll(filepath.Join(taskRoot, "workspace"), 0700); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(taskRoot, "spec.json"), `{"task_id":"`+taskID+`","workload":"job","model":"test","max_runtime_seconds":5}`, 0600)
			write(filepath.Join(taskRoot, "objective.txt"), "make a website", 0600)
			text := "网站已经完成 OPENING private-model-key 末尾验证 CLOSING"
			if taskID == "bounded" {
				text = "OPENING" + strings.Repeat("中间", 7000) + "CLOSING"
			}
			write(pi, eventScript(text), 0700)
			if taskID == "balance" {
				write(pi, "#!/bin/sh\nprintf '%s\\n' "+shellQuote(`{"type":"message_end","message":{"role":"assistant","stopReason":"error","errorMessage":"402: Insufficient Balance","content":[]}}`)+"\n", 0700)
			}
			if taskID == "http2" {
				write(pi, "#!/bin/sh\nprintf '%s\\n' "+shellQuote(`{"type":"message_end","message":{"role":"assistant","stopReason":"error","errorMessage":"Upstream HTTP/2 stream failed","content":[]}}`)+"\n", 0700)
			}
			run("start", taskID)
			deadline := time.Now().Add(8 * time.Second)
			for {
				var status struct {
					Phase string `json:"phase"`
				}
				if err := json.Unmarshal(run("status", taskID), &status); err != nil {
					t.Fatal(err)
				}
				if status.Phase != "running" {
					if taskID != "balance" && taskID != "http2" && status.Phase != "completed" || (taskID == "balance" || taskID == "http2") && status.Phase != "failed" {
						t.Fatalf("phase=%s", status.Phase)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("runner did not finish")
				}
				time.Sleep(10 * time.Millisecond)
			}
			report := string(run("report", taskID))
			log := string(run("log", taskID, "0"))
			statusBody := run("status", taskID)
			for _, secret := range []string{"PRIVATE-THOUGHT", "PRIVATE-ARGUMENT", "PRIVATE-OUTPUT"} {
				if strings.Contains(report+log+string(statusBody), secret) {
					t.Fatalf("private event content persisted: %s", secret)
				}
			}
			if taskID == "balance" {
				var status struct {
					Code string `json:"failure_code"`
					HTTP int    `json:"http_status"`
				}
				if json.Unmarshal(statusBody, &status) != nil || status.Code != "provider_request_failed" || status.HTTP != 402 || report != "" {
					t.Fatalf("balance classification lost: %s", statusBody)
				}
				return
			}
			if taskID == "http2" {
				var status struct {
					Code string `json:"failure_code"`
					HTTP int    `json:"http_status"`
				}
				if json.Unmarshal(statusBody, &status) != nil || status.Code != "model_connection_failed" || status.HTTP != 0 || report != "" {
					t.Fatalf("HTTP/2 stream failure classification lost: %s", statusBody)
				}
				return
			}
			if !strings.Contains(string(statusBody), "worker_thinking") || !strings.Contains(string(statusBody), "worker_reading") || !strings.Contains(string(statusBody), "worker_tool_complete") {
				t.Fatalf("activity history lost: %s", statusBody)
			}
			if strings.Contains(report, "PRIVATE-DIAGNOSTIC") || strings.Contains(report+log, "private-model-key") || strings.Contains(log, "OPENING") {
				t.Fatalf("channels/secrets mixed: report=%q log=%q", report, log)
			}
			if !strings.Contains(report, "OPENING") || !strings.Contains(report, "CLOSING") || len(report) > MaxWorkerReportBytes || !utf8.ValidString(report) {
				t.Fatal("bounded final reply lost its ends")
			}
			if taskID == "ordinary" && (!strings.Contains(report, "[REDACTED]") || !strings.Contains(log, "PRIVATE-DIAGNOSTIC")) {
				t.Fatal("redaction/diagnostic evidence missing")
			}
			if taskID == "bounded" && !strings.Contains(report, "[Worker report truncated;") {
				t.Fatal("truncation was silent")
			}
			info, err := os.Stat(filepath.Join(taskRoot, "report.txt"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("report is not private")
			}
		})
	}
}
