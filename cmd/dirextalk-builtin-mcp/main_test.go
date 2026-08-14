package main

import (
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

func TestToolsAreReadOnlyAndReturnLiveValues(t *testing.T) {
	for _, kind := range []string{"server_time", "server_load"} {
		definition := tool(kind)
		if definition["name"] != kind {
			t.Fatalf("tool(%s)=%#v", kind, definition)
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
	result, err := call(localSandboxKind, json.RawMessage(`{"name":"local_sandbox_run","arguments":{"script":"printf stdout; printf stderr >&2; printf artifact > result.txt","result_paths":["result.txt"]}}`))
	if err != nil || result["isError"] != false {
		t.Fatalf("local sandbox result=%#v err=%v", result, err)
	}
	payload := result["structuredContent"].(map[string]any)
	if payload["stdout"] != "stdout" || payload["stderr"] != "stderr" || payload["exit_code"] != 0 {
		t.Fatalf("local sandbox payload=%#v", payload)
	}
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
