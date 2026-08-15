package sshworker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type recordingResultSink struct {
	text      []byte
	artifacts map[string][]byte
}

func (sink *recordingResultSink) StoreText(_ context.Context, stdout, _ []byte, _ int) error {
	sink.text = bytes.Clone(stdout)
	return nil
}

func (sink *recordingResultSink) StoreArtifact(_ context.Context, name string, body io.Reader, _ int64) error {
	value, err := io.ReadAll(body)
	if err == nil {
		sink.artifacts[name] = value
	}
	return err
}

func TestCommandSSHExecutorResumesNotStartedRuntime(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*)
    count status >/dev/null
    if [[ -f "$state/started" ]]; then
      printf '%s\n' '{"phase":"completed","exit_code":0}'
    else
      printf '%s\n' '{"phase":"not_started","exit_code":0}'
    fi
    ;;
  *"'start'"*)
    count start >/dev/null
    cat >/dev/null
    touch "$state/started"
    ;;
  *"'log'"*) printf '%s\n' 'resumed successfully' ;;
  *"'artifact'"*) exit 0 ;;
  *) exit 64 ;;
esac
`)
	sink := &recordingResultSink{artifacts: make(map[string][]byte)}
	result, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), sshRequestFixture(t, sink))
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || string(sink.text) != "resumed successfully\n" || readCount(t, state, "status") != 2 || readCount(t, state, "start") != 1 {
		t.Fatalf("result=%+v text=%q status=%d start=%d", result, sink.text, readCount(t, state, "status"), readCount(t, state, "start"))
	}
}

func TestCommandSSHExecutorAppliesDeferredGuidanceBeforeRuntimeStart(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*)
    if [[ -f "$state/started" ]]; then
      printf '%s\n' '{"phase":"completed","exit_code":0}'
    else
      printf '%s\n' '{"phase":"not_started","exit_code":0}'
    fi
    ;;
  *"objective.txt"*) cat > "$state/guidance" ;;
  *"'start'"*) cat >/dev/null; touch "$state/started" ;;
  *"'log'"*) printf '%s\n' 'completed with RIVER-LANTERN-7392' ;;
  *"'artifact'"*) exit 0 ;;
  *) exit 64 ;;
esac
`)
	sink := &recordingResultSink{artifacts: make(map[string][]byte)}
	request := sshRequestFixture(t, sink)
	const steerID = "b5eb0214-91fa-40af-9a89-056ca78c9a61"
	request.ResolveGuidance = func(context.Context) (RuntimeGuidance, error) {
		return RuntimeGuidance{SteerIDs: []string{steerID}, Text: "Read the attached TXT and include RIVER-LANTERN-7392 in both reports."}, nil
	}
	result, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	guidance, err := os.ReadFile(filepath.Join(state, "guidance"))
	if err != nil || !bytes.Contains(guidance, []byte("RIVER-LANTERN-7392")) ||
		len(result.AppliedSteerIDs) != 1 || result.AppliedSteerIDs[0] != steerID {
		t.Fatalf("guidance=%q result=%+v err=%v", guidance, result, err)
	}
}

func TestCommandSSHExecutorRetriesTransientReads(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*)
    [[ "$(count status)" -gt 1 ]] || exit 255
    printf '%s\n' '{"phase":"completed","exit_code":0}'
    ;;
  *"'log'"*)
    [[ "$(count log)" -gt 1 ]] || exit 255
    printf '%s\n' 'completed after reconnect'
    ;;
  *"'artifact'"*"'report.txt'"*)
    [[ "$(count download)" -gt 1 ]] || exit 255
    printf 'data'
    ;;
  *"'artifact'"*)
    [[ "$(count list)" -gt 1 ]] || exit 255
    printf '%s\n' '{"name":"report.txt","size":4}'
    ;;
  *"'start'"*) count start >/dev/null ;;
  *) exit 64 ;;
esac
`)
	withoutRetryDelay(t)
	sink := &recordingResultSink{artifacts: make(map[string][]byte)}
	result, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), sshRequestFixture(t, sink))
	if err != nil {
		t.Fatal(err)
	}
	if result.ArtifactCount != 1 || string(sink.text) != "completed after reconnect\n" || string(sink.artifacts["report.txt"]) != "data" {
		t.Fatalf("result=%+v text=%q artifacts=%q", result, sink.text, sink.artifacts)
	}
	for _, name := range []string{"status", "log", "list", "download"} {
		if got := readCount(t, state, name); got != 2 {
			t.Fatalf("%s attempts=%d, want 2", name, got)
		}
	}
	if _, err = os.Stat(filepath.Join(state, "start.count")); !os.IsNotExist(err) {
		t.Fatalf("resume unexpectedly restarted an existing runtime: %v", err)
	}
}

func sshRequestFixture(t *testing.T, sink ResultSink) SSHRequest {
	t.Helper()
	return SSHRequest{
		ExecutionID: "execution-recovery", Host: "203.0.113.20", User: "ec2-user",
		PrivateKeyPath: filepath.Join(t.TempDir(), "key"), WorkerScript: []byte("bootstrap"), WorkerScriptSHA256: "unused",
		Runtime:           RuntimeProtocol{TaskID: "execution-recovery", encodedModelKey: "c2VjcmV0"},
		MaxWorkspaceBytes: 1 << 20, MaxResultBytes: 1 << 20, Sink: sink, Resume: true,
	}
}

func writeFakeSSH(t *testing.T, state, behavior string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
state=%s
remote="${!#}"
count() {
  local name="$1" file="$state/$1.count" value=0
  if [[ -f "$file" ]]; then read -r value < "$file"; fi
  value=$((value+1))
  printf '%%s\n' "$value" > "$file"
  printf '%%s\n' "$value"
}
%s`, strconv.Quote(state), behavior)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCount(t *testing.T, state, name string) int {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(state, name+".count"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(string(bytes.TrimSpace(body)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func withoutRetryDelay(t *testing.T) {
	t.Helper()
	previous := timeAfter
	timeAfter = func(int) <-chan time.Time {
		ready := make(chan time.Time, 1)
		ready <- time.Now()
		return ready
	}
	t.Cleanup(func() { timeAfter = previous })
}
