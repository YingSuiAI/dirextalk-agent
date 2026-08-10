//go:build unix

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func TestWaitDelayReturnsPiEventsOnlyWithSuccessfulQuiescentRun(t *testing.T) {
	proof := processTerminalProof()
	if !acceptPiEventsAfterWaitDelay(
		exec.ErrWaitDelay, true, proof, ProcessStdoutPiEventsV1, false,
	) {
		t.Fatal("valid Pi wait-delay result was rejected")
	}
	stream := validPiEventStream()
	defer clear(stream)
	_, finalJSON, err := ParsePiEvents(stream)
	clear(finalJSON)
	if err != nil {
		t.Fatalf("retained Pi events were not parseable: %v", err)
	}

	invalidProof := proof
	invalidProof.ActiveDescendants = 1
	for _, test := range []struct {
		name           string
		err            error
		processSuccess bool
		proof          execgate.Proof
		policy         ProcessStdoutPolicy
		exceeded       bool
	}{
		{name: "different wait error", err: errors.New("wait failed"), processSuccess: true, proof: proof, policy: ProcessStdoutPiEventsV1},
		{name: "failed process", err: exec.ErrWaitDelay, proof: proof, policy: ProcessStdoutPiEventsV1},
		{name: "invalid terminal proof", err: exec.ErrWaitDelay, processSuccess: true, proof: invalidProof, policy: ProcessStdoutPiEventsV1},
		{name: "raw stdout", err: exec.ErrWaitDelay, processSuccess: true, proof: proof, policy: ProcessStdoutRaw},
		{name: "output exceeded", err: exec.ErrWaitDelay, processSuccess: true, proof: proof, policy: ProcessStdoutPiEventsV1, exceeded: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if acceptPiEventsAfterWaitDelay(
				test.err, test.processSuccess, test.proof, test.policy, test.exceeded,
			) {
				t.Fatal("unsafe wait-delay result was accepted")
			}
		})
	}
}

func TestOSProcessRunnerDoesNotClassifyWaitFailureAsStartFailure(t *testing.T) {
	directory := t.TempDir()
	pidPath := filepath.Join(directory, "child.pid")
	_, err := (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", "sleep 4 & echo $! > child.pid"},
		Directory:  directory,
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
		StdoutPolicy:   ProcessStdoutPiEventsV1,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	})
	rawPID, readErr := os.ReadFile(pidPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	childPID, parseErr := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	clear(rawPID)
	if parseErr != nil || childPID < 1 {
		t.Fatalf("child pid is invalid: %d err=%v", childPID, parseErr)
	}
	_ = syscall.Kill(childPID, syscall.SIGKILL)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if killErr := syscall.Kill(childPID, 0); errors.Is(killErr, syscall.ESRCH) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	failure, ok := FailureOf(err)
	if !ok || failure.Stage != FailureStageProcess ||
		failure.Code != FailureCodeProcessWait {
		t.Fatalf("failure=%+v ok=%t err=%v", failure, ok, err)
	}
}

func processTerminalProof() execgate.Proof {
	return execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV1, State: execgate.ProofTerminal,
		RunID:       "11111111-1111-4111-8111-111111111111",
		ExecutionID: "22222222-2222-4222-8222-222222222222",
		TaskID:      "33333333-3333-4333-8333-333333333333",
		Attempt:     1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
		BootID:       "44444444-4444-4444-8444-444444444444",
		CgroupSHA256: strings.Repeat("2", 64), PolicySHA256: strings.Repeat("3", 64),
		Worker: execgate.ProcessIdentity{
			PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("4", 64),
		},
		Pi: execgate.ProcessIdentity{
			PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: strings.Repeat("5", 64),
		},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1,
		ObservedAtUnixNano: time.Now().UTC().UnixNano(),
	}
}
