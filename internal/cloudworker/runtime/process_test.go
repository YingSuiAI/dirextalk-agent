//go:build unix

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func TestOSProcessRunnerWaitsForDescendantsWithoutLocalDeadline(t *testing.T) {
	directory := t.TempDir()
	started := time.Now()
	output, err := (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", "sleep 2.2 &"},
		Directory:  directory,
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
		StdoutPolicy:   ProcessStdoutPiEventsV1,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	})
	if err != nil || len(output.Stdout) != 0 {
		t.Fatalf("output=%q err=%v", output.Stdout, err)
	}
	if elapsed := time.Since(started); elapsed < 2*time.Second {
		t.Fatalf("Run returned before descendant exited: %s", elapsed)
	}
}

func processTerminalProof() execgate.Proof {
	return execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV2, State: execgate.ProofTerminal,
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
