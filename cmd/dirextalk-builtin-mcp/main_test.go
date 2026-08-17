package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestToolsAreReadOnlyAndReturnLiveValues(t *testing.T) {
	for _, kind := range []string{"server_time", "server_load"} {
		definition := tool(kind)
		if definition["name"] != kind {
			t.Fatalf("tool(%s)=%#v", kind, definition)
		}
		if kind == "server_load" && !strings.Contains(definition["description"].(string), "Agent node") {
			t.Fatalf("server_load target is ambiguous: %#v", definition)
		}
		result, err := call(kind, json.RawMessage(`{"name":"`+kind+`","arguments":{}}`))
		if err != nil || result["isError"] != false {
			t.Fatalf("call(%s)=%#v err=%v", kind, result, err)
		}
		payload := result["structuredContent"].(map[string]any)
		if kind == "server_time" {
			parsed, err := time.Parse(time.RFC3339Nano, payload["rfc3339"].(string))
			if err != nil || time.Since(parsed) > time.Minute || time.Until(parsed) > time.Minute {
				t.Fatalf("server time=%#v err=%v", payload, err)
			}
		} else if payload["uptime_seconds"].(int64) <= 0 || payload["total_memory_bytes"].(uint64) == 0 {
			t.Fatalf("server load=%#v", payload)
		}
	}
}

func TestToolCallRejectsArgumentsAndWrongName(t *testing.T) {
	for _, raw := range []string{`{"name":"server_time","arguments":{"zone":"local"}}`, `{"name":"other","arguments":{}}`} {
		if _, err := call("server_time", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestLocalSandboxToolReturnsBoundedShellResult(t *testing.T) {
	original := newLocalSandboxCommand
	originalPrepare := prepareLocalSandboxApplets
	t.Cleanup(func() {
		newLocalSandboxCommand = original
		prepareLocalSandboxApplets = originalPrepare
	})
	work := t.TempDir()
	prepareLocalSandboxApplets = func() error { return nil }
	newLocalSandboxCommand = func(script string) *exec.Cmd {
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Dir = work
		return cmd
	}
	definition := tool(localSandboxKind)
	if definition["name"] != localSandboxToolName {
		t.Fatalf("local sandbox definition=%#v", definition)
	}
	if description := definition["description"].(string); strings.Contains(description, "cloud_worker_propose") || !strings.Contains(description, "another suitable available tool") {
		t.Fatalf("local sandbox routing description=%q", description)
	}
	result, err := call(localSandboxKind, json.RawMessage(`{"name":"local_sandbox_run","arguments":{"script":"printf stdout; printf stderr >&2; printf artifact > result.txt","result_paths":["result.txt"]}}`))
	if err != nil || result["isError"] != false {
		t.Fatalf("local sandbox result=%#v err=%v", result, err)
	}
	payload := result["structuredContent"].(map[string]any)
	if payload["stdout"] != "stdout" || payload["stderr"] != "stderr" || payload["stdout_truncated"] != false || payload["stderr_truncated"] != false || payload["exit_code"] != 0 {
		t.Fatalf("local sandbox payload=%#v", payload)
	}
}

func TestLocalSandboxToolReportsOutputTruncation(t *testing.T) {
	original := newLocalSandboxCommand
	originalPrepare := prepareLocalSandboxApplets
	t.Cleanup(func() {
		newLocalSandboxCommand = original
		prepareLocalSandboxApplets = originalPrepare
	})
	prepareLocalSandboxApplets = func() error { return nil }
	newLocalSandboxCommand = func(string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestLocalSandboxOutputHelperProcess")
		cmd.Env = append(os.Environ(), "DIREXTALK_TEST_LOCAL_SANDBOX_OUTPUT=1")
		return cmd
	}

	result, err := call(localSandboxKind, json.RawMessage(`{"name":"local_sandbox_run","arguments":{"script":"ignored"}}`))
	if err != nil || result["isError"] != false {
		t.Fatalf("local sandbox result=%#v err=%v", result, err)
	}
	payload := result["structuredContent"].(map[string]any)
	stdout, stdoutOK := payload["stdout"].(string)
	stderr, stderrOK := payload["stderr"].(string)
	if !stdoutOK || !stderrOK || len(stdout) != localSandboxMaxOutputBytes || len(stderr) != localSandboxMaxOutputBytes {
		t.Fatalf("local sandbox output lengths stdout=%d stderr=%d", len(stdout), len(stderr))
	}
	if payload["stdout_truncated"] != true || payload["stderr_truncated"] != true {
		t.Fatalf("local sandbox truncation metadata=%#v", payload)
	}
}

func TestLocalSandboxOutputHelperProcess(t *testing.T) {
	if os.Getenv("DIREXTALK_TEST_LOCAL_SANDBOX_OUTPUT") != "1" {
		return
	}
	output := bytes.Repeat([]byte("x"), localSandboxMaxOutputBytes+1)
	_, _ = os.Stdout.Write(output)
	_, _ = os.Stderr.Write(output)
	os.Exit(0)
}

func TestLocalSandboxPreparesBusyBoxAppletsBeforeRunningScript(t *testing.T) {
	original := newLocalSandboxCommand
	originalPrepare := prepareLocalSandboxApplets
	t.Cleanup(func() {
		newLocalSandboxCommand = original
		prepareLocalSandboxApplets = originalPrepare
	})
	prepared := false
	work := t.TempDir()
	prepareLocalSandboxApplets = func() error {
		prepared = true
		return nil
	}
	newLocalSandboxCommand = func(string) *exec.Cmd {
		if !prepared {
			t.Fatal("shell command created before BusyBox applets")
		}
		cmd := exec.Command("/bin/sh", "-c", "printf artifact > result.txt; cat result.txt")
		cmd.Dir = work
		return cmd
	}
	result, err := call(localSandboxKind, json.RawMessage(`{"name":"local_sandbox_run","arguments":{"script":"ignored","result_paths":["result.txt"]}}`))
	if err != nil || result["isError"] != false || !prepared {
		t.Fatalf("local sandbox result=%#v prepared=%t err=%v", result, prepared, err)
	}
}

func TestLocalSandboxToolRejectsUnsafeResultPath(t *testing.T) {
	if _, err := call(localSandboxKind, json.RawMessage(`{"name":"local_sandbox_run","arguments":{"script":"true","result_paths":["../escape"]}}`)); err == nil {
		t.Fatal("unsafe result path accepted")
	}
}
