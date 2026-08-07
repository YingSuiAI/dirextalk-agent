package execgate

import (
	"strings"
	"testing"
	"time"
)

func TestTerminalProofRequiresExactlyOneAllowedExecAndQuiescentCgroup(t *testing.T) {
	proof := testTerminalProof()
	if err := proof.ValidateTerminal(); err != nil {
		t.Fatalf("valid terminal proof rejected: %v", err)
	}
	firstDigest, err := proof.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Proof){
		"loader bypass left no observed Pi exec": func(value *Proof) { value.TotalAllowedPiExecs = 0 },
		"second Pi exec":                         func(value *Proof) { value.TotalAllowedPiExecs = 2 },
		"Pi still active":                        func(value *Proof) { value.ActivePiProcesses = 1 },
		"orphan child":                           func(value *Proof) { value.CgroupProcessCount, value.ActiveDescendants = 2, 1 },
		"second Worker":                          func(value *Proof) { value.WorkerProcessCount = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			mutate(&changed)
			if err := changed.ValidateTerminal(); err == nil {
				t.Fatal("invalid topology accepted")
			}
			if digest, err := changed.Digest(); err == nil && digest == firstDigest {
				t.Fatal("topology drift retained authorization digest")
			}
		})
	}
	changed := proof
	changed.Pi.SHA256 = strings.Repeat("9", 64)
	changedDigest, err := changed.Digest()
	if err != nil || changedDigest == firstDigest {
		t.Fatalf("identity drift digest=%q err=%v", changedDigest, err)
	}
}

func testTerminalProof() Proof {
	return Proof{
		SchemaVersion: ProofSchemaV1, State: ProofTerminal,
		RunID:       "11111111-1111-4111-8111-111111111111",
		ExecutionID: "22222222-2222-4222-8222-222222222222",
		TaskID:      "33333333-3333-4333-8333-333333333333",
		Attempt:     1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
		BootID:       "44444444-4444-4444-8444-444444444444",
		CgroupSHA256: strings.Repeat("2", 64), PolicySHA256: strings.Repeat("3", 64),
		Worker:             ProcessIdentity{PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("4", 64)},
		Pi:                 ProcessIdentity{PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: strings.Repeat("5", 64)},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1,
		ObservedAtUnixNano: time.Now().UTC().UnixNano(),
	}
}
