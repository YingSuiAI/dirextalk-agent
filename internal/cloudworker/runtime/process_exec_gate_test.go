//go:build unix

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func TestProcessCancellationKillsCompleteProcessGroup(t *testing.T) {
	directory := t.TempDir()
	pidFile := filepath.Join(directory, "child.pid")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := (OSProcessRunner{}).Run(ctx, ProcessSpec{
			Executable: "/bin/sh", Arguments: []string{"-c", "sleep 30 & echo $! > child.pid; wait"},
			Directory: directory, Environment: map[string]string{"PATH": "/usr/bin:/bin"},
			MaxStdoutBytes: 1024, MaxStderrBytes: 1024,
		})
		done <- err
	}()
	var childPID int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(pidFile)
		if err == nil {
			childPID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
			clear(raw)
			if childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID < 1 {
		cancel()
		t.Fatal("shell child pid was not published")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	for attempt := 0; attempt < 100; attempt++ {
		err := syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process-group child %d survived cancellation", childPID)
}

func TestGuardedRunnerRequiresTerminalProofBeforeReturningOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only setuid/setgid Worker qualification")
	}
	directory := t.TempDir()
	if err := os.Chown(directory, 0, 65532); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	sha, err := digestPath("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	binding := ProcessBinding{
		ExecutionID: "11111111-1111-4111-8111-111111111111",
		TaskID:      "22222222-2222-4222-8222-222222222222",
		Attempt:     1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
	}
	gate := &fakeProcessExecGate{}
	runner := OSProcessRunner{uid: 65532, gid: 65532, gate: gate, state: &processRunnerState{}}
	bound, err := runner.BindProcess(binding)
	if err != nil {
		t.Fatal(err)
	}
	output, err := bound.Run(t.Context(), ProcessSpec{
		Executable: "/bin/sh", ExpectedExecutableSHA256: sha,
		Arguments: []string{"-c", "printf guarded"}, Directory: directory,
		Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
		MaxStdoutBytes: 1024, MaxStderrBytes: 1024,
	})
	if err != nil || string(output.Stdout) != "guarded" || output.RuntimeTopology.ValidateTerminal() != nil {
		t.Fatalf("output=%q topology=%+v err=%v", output.Stdout, output.RuntimeTopology, err)
	}
	if gate.registration.ExecutionID != binding.ExecutionID || gate.run.activatedPID < 1 || gate.run.terminalCalls != 1 {
		t.Fatalf("gate registration=%+v activated_pid=%d terminal_calls=%d", gate.registration, gate.run.activatedPID, gate.run.terminalCalls)
	}
}

func TestGuardedRunnerPreservesTopologyFailures(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only setuid/setgid Worker qualification")
	}
	for _, test := range []struct {
		name        string
		activateErr error
		terminalErr error
	}{
		{name: "activate", activateErr: execgate.ErrUnavailable},
		{name: "terminal", terminalErr: execgate.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chown(directory, 0, 65532); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o770); err != nil {
				t.Fatal(err)
			}
			sha, err := digestPath("/bin/sh")
			if err != nil {
				t.Fatal(err)
			}
			binding := ProcessBinding{
				ExecutionID: "11111111-1111-4111-8111-111111111111",
				TaskID:      "22222222-2222-4222-8222-222222222222",
				Attempt:     1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
			}
			gate := &fakeProcessExecGate{}
			gate.run.activateErr = test.activateErr
			gate.run.terminalErr = test.terminalErr
			runner := OSProcessRunner{uid: 65532, gid: 65532, gate: gate, state: &processRunnerState{}}
			bound, err := runner.BindProcess(binding)
			if err != nil {
				t.Fatal(err)
			}
			_, err = bound.Run(t.Context(), ProcessSpec{
				Executable: "/bin/sh", ExpectedExecutableSHA256: sha,
				Arguments: []string{"-c", "printf guarded"}, Directory: directory,
				Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
				MaxStdoutBytes: 1024, MaxStderrBytes: 1024,
			})
			failure, ok := FailureOf(err)
			if !ok || failure.Stage != FailureStageProcess ||
				failure.Code != FailureCodeProcessTopology {
				t.Fatalf("failure=%+v ok=%t err=%v", failure, ok, err)
			}
		})
	}
}

func TestGuardedRunnerPreservesStartFailureBeforeActivation(t *testing.T) {
	directory := t.TempDir()
	sha, err := digestPath("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	binding := ProcessBinding{
		ExecutionID: "11111111-1111-4111-8111-111111111111",
		TaskID:      "22222222-2222-4222-8222-222222222222",
		Attempt:     1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
	}
	gate := &fakeProcessExecGate{}
	runner := OSProcessRunner{uid: 65532, gid: 65532, gate: gate, state: &processRunnerState{}}
	bound, err := runner.BindProcess(binding)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bound.Run(t.Context(), ProcessSpec{
		Executable: "/bin/sh", ExpectedExecutableSHA256: sha,
		Arguments: []string{"-c", "printf guarded"}, Directory: directory,
		Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
		MaxStdoutBytes: 1024, MaxStderrBytes: 1024,
	})
	failure, ok := FailureOf(err)
	if !ok || failure.Stage != FailureStageProcess ||
		failure.Code != FailureCodeProcessStart {
		t.Fatalf("failure=%+v ok=%t err=%v", failure, ok, err)
	}
	if gate.run.activatedPID != 0 || gate.run.terminalCalls != 0 || gate.run.cancelCalls != 1 {
		t.Fatalf(
			"activated_pid=%d terminal_calls=%d cancel_calls=%d",
			gate.run.activatedPID, gate.run.terminalCalls, gate.run.cancelCalls,
		)
	}
}

type fakeProcessExecGate struct {
	registration execgate.Registration
	run          fakeProcessExecGateRun
}

func (gate *fakeProcessExecGate) Register(_ context.Context, value execgate.Registration) (processExecGateRun, error) {
	gate.registration = value
	gate.run.registration = value
	return &gate.run, nil
}

type fakeProcessExecGateRun struct {
	mu            sync.Mutex
	registration  execgate.Registration
	activatedPID  int
	terminalCalls int
	cancelCalls   int
	activateErr   error
	terminalErr   error
}

func (run *fakeProcessExecGateRun) Activate(_ context.Context, pid int) (execgate.Proof, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	run.activatedPID = pid
	if run.activateErr != nil {
		return execgate.Proof{}, run.activateErr
	}
	return execgate.Proof{}, nil
}

func (run *fakeProcessExecGateRun) Terminal(context.Context) (execgate.Proof, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	run.terminalCalls++
	if run.terminalErr != nil {
		return execgate.Proof{}, run.terminalErr
	}
	return execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV1, State: execgate.ProofTerminal,
		RunID:       "33333333-3333-4333-8333-333333333333",
		ExecutionID: run.registration.ExecutionID, TaskID: run.registration.TaskID,
		Attempt: run.registration.Attempt, LeaseEpoch: run.registration.LeaseEpoch,
		RuntimeTaskSHA256: run.registration.RuntimeTaskSHA256,
		BootID:            "44444444-4444-4444-8444-444444444444",
		CgroupSHA256:      strings.Repeat("2", 64), PolicySHA256: strings.Repeat("3", 64),
		Worker:             execgate.ProcessIdentity{PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("4", 64)},
		Pi:                 execgate.ProcessIdentity{PID: int32(run.activatedPID), StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: run.registration.PiSHA256},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1, ObservedAtUnixNano: time.Now().UTC().UnixNano(),
	}, nil
}

func (run *fakeProcessExecGateRun) Cancel(context.Context) error {
	run.mu.Lock()
	defer run.mu.Unlock()
	run.cancelCalls++
	return nil
}

func digestPath(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(digest[:]), nil
}
