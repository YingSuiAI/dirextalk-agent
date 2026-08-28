package sshworker

import (
	"bytes"
	"context"
	"errors"
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

func TestCommandSSHExecutorNeverRestartsAfterRemoteCompletionReceipt(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) printf '%s\n' '{"phase":"not_started","exit_code":0}' ;;
  *"'start'"*) count start >/dev/null ;;
  *) exit 64 ;;
esac
`)
	request := sshRequestFixture(t, &recordingResultSink{artifacts: make(map[string][]byte)})
	request.CollectOnly = true
	_, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), request)
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("missing completed runtime error=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(state, "start.count")); !os.IsNotExist(statErr) {
		t.Fatalf("completed remote task restarted: %v", statErr)
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
	*"'artifact'"*"'empty.txt'"*) count empty-download >/dev/null ;;
  *"'artifact'"*)
    [[ "$(count list)" -gt 1 ]] || exit 255
	printf '%s\n' '{"name":"empty.txt","size":0}'
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
	if _, err = os.Stat(filepath.Join(state, "empty-download.count")); !os.IsNotExist(err) {
		t.Fatalf("zero-byte artifact was transferred: %v", err)
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

func TestCommandSSHExecutorSharesResultBudgetAcrossLogsAndArtifacts(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) printf '%s\n' '{"phase":"completed","exit_code":0}' ;;
  *"'log'"*) printf '12345' ;;
  *"'artifact'"*"'report.txt'"*) count download >/dev/null; printf 'data' ;;
  *"'artifact'"*) printf '%s\n' '{"name":"report.txt","size":4}' ;;
  *) exit 64 ;;
esac
`)
	sink := &recordingResultSink{artifacts: make(map[string][]byte)}
	request := sshRequestFixture(t, sink)
	request.MaxResultBytes = 8
	_, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), request)
	if !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("aggregate result budget error=%v", err)
	}
	if string(sink.text) != "12345" {
		t.Fatalf("stored log=%q", sink.text)
	}
	if _, statErr := os.Stat(filepath.Join(state, "download.count")); !os.IsNotExist(statErr) {
		t.Fatalf("artifact crossed remaining result budget: %v", statErr)
	}
}

func TestSSHConnectionsPinKnownHostBesideWorkerKeyUntilKeyDeletion(t *testing.T) {
	keys, err := NewLocalKeyMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _, err := keys.Ensure(context.Background(), "worker-pinned")
	if err != nil {
		t.Fatal(err)
	}
	arguments, err := sshBaseArguments(privateKey, "ubuntu", "203.0.113.20")
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := privateKey + ".known_hosts"
	info, err := os.Stat(knownHosts)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts info=%v err=%v", info, err)
	}
	if !containsString(arguments, "StrictHostKeyChecking=accept-new") || !containsString(arguments, "UserKnownHostsFile="+knownHosts) {
		t.Fatalf("SSH arguments=%q", arguments)
	}
	if err = os.WriteFile(knownHosts, []byte("pinned-host-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = sshBaseArguments(privateKey, "ubuntu", "203.0.113.20"); err != nil {
		t.Fatal(err)
	}
	if body, readErr := os.ReadFile(knownHosts); readErr != nil || string(body) != "pinned-host-key\n" {
		t.Fatalf("known_hosts=%q err=%v", body, readErr)
	}
	if err = keys.Delete(context.Background(), "worker-pinned"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(knownHosts); !os.IsNotExist(err) {
		t.Fatalf("known_hosts survived key deletion: %v", err)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestCommandSSHExecutorReportsProgressWhileRuntimeIsRunning(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*)
    current="$(count status)"
    if [[ "$current" -le 2 ]]; then printf '%s\n' '{"phase":"running","exit_code":0}'; else printf '%s\n' '{"phase":"completed","exit_code":0}'; fi
    ;;
  *"'log'"*) printf '%s\n' 'completed after progress' ;;
  *"'artifact'"*) exit 0 ;;
  *) exit 64 ;;
esac
`)
	withoutRetryDelay(t)
	previousInterval := runtimeProgressInterval
	runtimeProgressInterval = 0
	t.Cleanup(func() { runtimeProgressInterval = previousInterval })
	sink := &recordingResultSink{artifacts: make(map[string][]byte)}
	request := sshRequestFixture(t, sink)
	var phases []string
	request.ReportProgress = func(_ context.Context, phase, _ string) error {
		phases = append(phases, phase)
		return nil
	}
	if _, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	want := []string{"executing_remote_task", "executing_remote_task", "executing_remote_task", "collecting_result"}
	if fmt.Sprint(phases) != fmt.Sprint(want) {
		t.Fatalf("progress phases=%v want=%v", phases, want)
	}
}

func TestCommandSSHExecutorTreatsProgressFailureAfterStartAsAmbiguous(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) printf '%s\n' '{"phase":"running","exit_code":0}' ;;
  *) exit 64 ;;
esac
`)
	previousInterval := runtimeProgressInterval
	runtimeProgressInterval = 0
	t.Cleanup(func() { runtimeProgressInterval = previousInterval })
	sink := &recordingResultSink{artifacts: make(map[string][]byte)}
	request := sshRequestFixture(t, sink)
	calls := 0
	request.ReportProgress = func(context.Context, string, string) error {
		calls++
		if calls > 1 {
			return errors.New("progress unavailable")
		}
		return nil
	}
	_, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), request)
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("progress failure=%v", err)
	}
}

func TestCommandSSHExecutorStopsRemoteRuntimeWhenCanceled(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) printf '%s\n' '{"phase":"running","exit_code":0}' ;;
  *"'stop'"*) count stop >/dev/null ;;
  *) exit 64 ;;
esac
`)
	withoutRetryDelay(t)
	previousInterval := runtimeProgressInterval
	runtimeProgressInterval = 0
	t.Cleanup(func() { runtimeProgressInterval = previousInterval })
	request := sshRequestFixture(t, &recordingResultSink{artifacts: make(map[string][]byte)})
	progress := 0
	request.ReportProgress = func(context.Context, string, string) error {
		progress++
		if progress == 2 {
			return context.Canceled
		}
		return nil
	}
	_, err := (CommandSSHExecutor{SSHPath: ssh}).Execute(context.Background(), request)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAmbiguous) || readCount(t, state, "stop") != 1 {
		t.Fatalf("cancel result err=%v stop=%d", err, readCount(t, state, "stop"))
	}
}

func TestAmbiguousRuntimeStartAcceptsAuthoritativeRunningStatus(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) count status >/dev/null; printf '%s\n' '{"phase":"running"}' ;;
  *"'stop'"*) count stop >/dev/null ;;
  *) exit 64 ;;
esac`)
	protocol := RuntimeProtocol{TaskID: "execution-recovery", secretEnvelope: encodeRuntimeSecretEnvelope("secret", "")}
	if err := reconcileAmbiguousRuntimeStart(context.Background(), ssh, nil, protocol, errors.New("connection reset")); err != nil {
		t.Fatal(err)
	}
	if readCount(t, state, "status") != 1 {
		t.Fatal("missing exact status probe")
	}
	if _, err := os.Stat(filepath.Join(state, "stop.count")); !os.IsNotExist(err) {
		t.Fatal("running task was stopped")
	}
}

func TestAmbiguousRuntimeStartStopsDefiniteNonRunningTask(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) printf '%s\n' '{"phase":"not_started"}' ;;
  *"'stop'"*) count stop >/dev/null ;;
  *) exit 64 ;;
esac`)
	protocol := RuntimeProtocol{TaskID: "execution-recovery", secretEnvelope: encodeRuntimeSecretEnvelope("secret", "")}
	err := reconcileAmbiguousRuntimeStart(context.Background(), ssh, nil, protocol, errors.New("connection reset"))
	if !errors.Is(err, ErrAmbiguous) || !errors.Is(err, errRuntimeNotStarted) || readCount(t, state, "stop") != 1 {
		t.Fatalf("err=%v stop=%d", err, readCount(t, state, "stop"))
	}
}

func TestAmbiguousRuntimeStartStatusFailureRemainsUncertain(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `case "$remote" in *"'status'"*) exit 1 ;; *) exit 64 ;; esac`)
	withoutRetryDelay(t)
	protocol := RuntimeProtocol{TaskID: "execution-recovery", secretEnvelope: encodeRuntimeSecretEnvelope("secret", "")}
	err := reconcileAmbiguousRuntimeStart(context.Background(), ssh, nil, protocol, errors.New("connection reset"))
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "stop.count")); !os.IsNotExist(err) {
		t.Fatal("status failure triggered blind cleanup retry")
	}
}

func TestAmbiguousRuntimeStartReconcilesAfterCallerCancellation(t *testing.T) {
	state := t.TempDir()
	ssh := writeFakeSSH(t, state, `
case "$remote" in
  *"'status'"*) printf '%s\n' '{"phase":"failed"}' ;;
  *"'stop'"*) count stop >/dev/null ;;
  *) exit 64 ;;
esac`)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	protocol := RuntimeProtocol{TaskID: "execution-recovery", secretEnvelope: encodeRuntimeSecretEnvelope("secret", "")}
	err := reconcileAmbiguousRuntimeStart(ctx, ssh, nil, protocol, context.Canceled)
	if !errors.Is(err, ErrAmbiguous) || readCount(t, state, "stop") != 1 {
		t.Fatalf("err=%v stop=%d", err, readCount(t, state, "stop"))
	}
}

func sshRequestFixture(t *testing.T, sink ResultSink) SSHRequest {
	t.Helper()
	return SSHRequest{
		ExecutionID: "execution-recovery", Host: "203.0.113.20", User: "ec2-user",
		PrivateKeyPath: filepath.Join(t.TempDir(), "key"), WorkerScript: []byte("bootstrap"), WorkerScriptSHA256: "unused",
		Runtime:           RuntimeProtocol{TaskID: "execution-recovery", secretEnvelope: encodeRuntimeSecretEnvelope("secret", "")},
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
