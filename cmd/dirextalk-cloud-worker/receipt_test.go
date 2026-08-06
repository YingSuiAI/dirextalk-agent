//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestReceiptPersistsLaunchAndExactPendingCompletionAcrossRestart(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := newReceiptJournal(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	key := testReceiptKey()
	locked, err := journal.lock(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, found, err := locked.load(); err != nil || found || receipt.State != "" {
		t.Fatalf("initial receipt=%+v found=%v err=%v", receipt, found, err)
	}
	recovery := testCompleteRequest()
	recoveryRaw, err := proto.MarshalOptions{Deterministic: true}.Marshal(recovery)
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.commitLaunch(recovery); err != nil {
		t.Fatal(err)
	}
	if err := locked.close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := journal.lock(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	receipt, found, err := restarted.load()
	if err != nil || !found || receipt.State != receiptLaunchCommitted || !bytes.Equal(receipt.CompletionRequest, recoveryRaw) {
		t.Fatalf("launch receipt=%+v found=%v err=%v", receipt, found, err)
	}
	request := testCompleteRequest()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.commitPending(request); err != nil {
		t.Fatal(err)
	}
	receipt, found, err = restarted.load()
	if err != nil || !found || receipt.State != receiptCompletionPending || !bytes.Equal(receipt.CompletionRequest, raw) {
		t.Fatalf("pending receipt=%+v found=%v err=%v", receipt, found, err)
	}
	if err := restarted.commitAcknowledged(); err != nil {
		t.Fatal(err)
	}
	receipt, found, err = restarted.load()
	if err != nil || !found || receipt.State != receiptCompletionAcknowledged || !bytes.Equal(receipt.CompletionRequest, raw) {
		t.Fatalf("acked receipt=%+v found=%v err=%v", receipt, found, err)
	}
}

func TestReceiptRejectsSkippedTransitionTamperAndUnsafeRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := newReceiptJournal(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	locked, err := journal.lock(context.Background(), testReceiptKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.commitPending(testCompleteRequest()); err == nil {
		t.Fatal("completion_pending skipped launch_committed")
	}
	if err := locked.commitLaunch(testCompleteRequest()); err != nil {
		t.Fatal(err)
	}
	if err := locked.commitLaunch(testCompleteRequest()); err == nil {
		t.Fatal("launch_committed was overwritten")
	}
	name := locked.receiptName
	if err := locked.close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	locked, err = journal.lock(context.Background(), testReceiptKey())
	if err != nil {
		t.Fatal(err)
	}
	defer locked.close()
	if _, _, err := locked.load(); err == nil {
		t.Fatal("world-readable receipt was accepted")
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newReceiptJournal(root, uint32(os.Geteuid())); err == nil {
		t.Fatal("world-accessible receipt root was accepted")
	}
}

func TestReceiptRejectsNonDeterministicCompletionID(t *testing.T) {
	request := testCompleteRequest()
	request.CompletionId = "88888888-8888-4888-8888-888888888888"
	if _, err := marshalCompleteRequest(request, testReceiptKey()); err == nil {
		t.Fatal("non-deterministic completion ID was accepted")
	}
}

func TestConcurrentReceiptLocksSerializeOneRoleAttempt(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := newReceiptJournal(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	first, err := journal.lock(context.Background(), testReceiptKey())
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan *lockedReceipt, 1)
	errors := make(chan error, 1)
	go func() {
		second, lockErr := journal.lock(context.Background(), testReceiptKey())
		if lockErr != nil {
			errors <- lockErr
			return
		}
		acquired <- second
	}()
	select {
	case second := <-acquired:
		second.close()
		t.Fatal("second process entered the same role attempt concurrently")
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.commitLaunch(testCompleteRequest()); err != nil {
		t.Fatal(err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-acquired:
		defer second.close()
		receipt, found, err := second.load()
		if err != nil || !found || receipt.State != receiptLaunchCommitted || len(receipt.CompletionRequest) == 0 {
			t.Fatalf("serialized receipt=%+v found=%v err=%v", receipt, found, err)
		}
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("second process did not acquire released receipt lock")
	}
}

func testReceiptKey() receiptKey {
	return receiptKey{
		ExecutionID: "22222222-2222-4222-8222-222222222222",
		RoleID:      "implementer",
		Attempt:     1,
	}
}

func testCompleteRequest() *agentv1.CoreTeamWorkerServiceCompleteRequest {
	return &agentv1.CoreTeamWorkerServiceCompleteRequest{
		Fence: &agentv1.CoreTeamWorkerLeaseFence{
			ExecutionId: "22222222-2222-4222-8222-222222222222", RoleId: "implementer",
			WorkerId: "11111111-1111-4111-8111-111111111111", Attempt: 1, LeaseEpoch: 1,
		},
		CompletionId: stableOperationID("22222222-2222-4222-8222-222222222222", "implementer", 1, "complete"),
		Outcome:      agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_FAILED,
		FailureCode:  agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_EXECUTION_UNCERTAIN,
	}
}
