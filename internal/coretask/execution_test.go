package coretask

import (
	"strings"
	"testing"
)

func TestAgentExecutionPolicyValidation(t *testing.T) {
	policy := DefaultAgentExecutionPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("default policy: %v", err)
	}
	for _, invalid := range []AgentExecutionPolicy{
		{Version: AgentExecutionPolicyVersion + 1, NoProgressRepeatLimit: DefaultNoProgressRepeatLimit},
		{Version: AgentExecutionPolicyVersion, NoProgressRepeatLimit: 1},
		{Version: AgentExecutionPolicyVersion, NoProgressRepeatLimit: MaxNoProgressRepeatLimit + 1},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %+v", invalid)
		}
	}
}

func TestExecutionSnapshotPinsAgentPolicyWithoutChangingAbsentSnapshot(t *testing.T) {
	legacy := ExecutionSnapshot{}
	if err := legacy.Seal(); err != nil {
		t.Fatalf("seal absent policy: %v", err)
	}
	if legacy.AgentPolicy != nil || legacy.EffectiveAgentPolicy() != DefaultAgentExecutionPolicy() {
		t.Fatalf("absent policy was mutated or resolved incorrectly: %+v", legacy)
	}

	policy := DefaultAgentExecutionPolicy()
	pinned := ExecutionSnapshot{AgentPolicy: &policy}
	if err := pinned.Seal(); err != nil {
		t.Fatalf("seal pinned policy: %v", err)
	}
	if pinned.AgentPolicy == nil || pinned.EffectiveAgentPolicy() != policy || pinned.Digest == legacy.Digest {
		t.Fatalf("policy was not pinned into snapshot digest: pinned=%+v legacy=%+v", pinned, legacy)
	}
}

func TestDurableLedgersAllowProductiveRoundsBeyondEight(t *testing.T) {
	const taskID = "00000000-0000-4000-8000-000000000001"
	digest := strings.Repeat("a", 64)

	for _, round := range []uint32{8, MaxAgentLedgerRounds - 1} {
		model := ModelRoundLedger{TaskID: taskID, Attempt: 1, Round: round, LeaseEpoch: 1, TaskRevision: 1, InputDigest: digest, State: ModelRoundPrepared}
		if err := model.Validate(); err != nil {
			t.Fatalf("model round %d rejected: %v", round, err)
		}
		tool := ToolCallLedger{TaskID: taskID, Attempt: 1, Round: round, CallID: "call", LeaseEpoch: 1, TaskRevision: 1, ToolDigest: digest, ArgumentsDigest: digest, State: ToolCallPrepared}
		if err := tool.Validate(); err != nil {
			t.Fatalf("tool round %d rejected: %v", round, err)
		}
	}

	model := ModelRoundLedger{TaskID: taskID, Attempt: 1, Round: MaxAgentLedgerRounds, LeaseEpoch: 1, TaskRevision: 1, InputDigest: digest, State: ModelRoundPrepared}
	if err := model.Validate(); err == nil {
		t.Fatal("model ledger accepted the internal safety-fuse round")
	}
	tool := ToolCallLedger{TaskID: taskID, Attempt: 1, Round: MaxAgentLedgerRounds, CallID: "call", LeaseEpoch: 1, TaskRevision: 1, ToolDigest: digest, ArgumentsDigest: digest, State: ToolCallPrepared}
	if err := tool.Validate(); err == nil {
		t.Fatal("tool ledger accepted the internal safety-fuse round")
	}
}
