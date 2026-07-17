package pairingworker

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
)

func TestDurableOperationExactCreateLeaseAndCompleteReplay(t *testing.T) {
	now := time.Date(2026, 7, 17, 1, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository()
	service, _ := NewService(repository, func() time.Time { return now })
	command := testOperationCommand(now)
	first, err := service.Ensure(context.Background(), command, "88888888-8888-8888-8888-888888888888")
	replay, replayErr := service.Ensure(context.Background(), command, "88888888-8888-8888-8888-888888888888")
	if err != nil || replayErr != nil || first.Revision != replay.Revision {
		t.Fatalf("create replay failed: %v %v", err, replayErr)
	}
	leased, err := service.AcquireNext(context.Background(), command.DeploymentID,
		"99999999-9999-9999-9999-999999999999", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", time.Minute)
	if err != nil || leased.LeaseEpoch != 1 || leased.ExecutionEpoch != 1 {
		t.Fatalf("acquire failed: %#v %v", leased, err)
	}
	if _, err := service.Complete(context.Background(), command.OperationID, leased.WorkerID, leased.LeaseEpoch,
		leased.Revision, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", nil, "root_helper_failed"); err != nil {
		t.Fatal(err)
	}
	completed, err := service.Complete(context.Background(), command.OperationID, leased.WorkerID, leased.LeaseEpoch,
		leased.Revision, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", nil, "root_helper_failed")
	if err != nil || completed.State != StateFailed {
		t.Fatalf("complete replay failed: %#v %v", completed, err)
	}
}

func TestExecutionEpochSurvivesExpiredLeaseReacquire(t *testing.T) {
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository()
	service, _ := NewService(repository, func() time.Time { return now })
	command := testOperationCommand(now)
	if _, err := service.Ensure(context.Background(), command, "88888888-8888-8888-8888-888888888888"); err != nil {
		t.Fatal(err)
	}
	first, err := service.AcquireNext(context.Background(), command.DeploymentID,
		"99999999-9999-9999-9999-999999999999", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 5*time.Second)
	if err != nil || first.LeaseEpoch != 1 || first.ExecutionEpoch != 1 {
		t.Fatalf("first lease=%#v err=%v", first, err)
	}
	now = now.Add(6 * time.Second)
	replayed, err := service.AcquireNext(context.Background(), command.DeploymentID,
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 5*time.Second)
	if err != nil || replayed.LeaseEpoch != 2 || replayed.ExecutionEpoch != first.ExecutionEpoch {
		t.Fatalf("re-lease changed immutable execution identity: %#v err=%v", replayed, err)
	}
	// The first root invocation may have journaled this receipt while its
	// Complete response was lost. The new transport lease can safely persist
	// that old receipt because the stable execution scope remains exact.
	receipt := &roothelper.PairingBeginReceiptV1{
		OperationID: command.OperationID, DeploymentID: command.DeploymentID, OwnerID: command.OwnerID,
		CommandID: command.CommandID, RecipientPublicKeyDigest: command.RecipientPublicKeyDigest,
		ExecutionEpoch: replayed.ExecutionEpoch, PairingExpiresAt: pairingExpiryText(command.PairingExpiresAt),
		WorkerLeaseEpoch: first.LeaseEpoch, AssociatedData: []byte{0xa1}, Signature: make([]byte, ed25519.SignatureSize),
	}
	completed, err := service.Complete(context.Background(), command.OperationID, replayed.WorkerID, replayed.LeaseEpoch,
		replayed.Revision, "cccccccc-cccc-cccc-cccc-cccccccccccc", &Result{Begin: receipt}, "")
	if err != nil || completed.State != StateSucceeded || completed.Result == nil || completed.Result.Begin.WorkerLeaseEpoch != first.LeaseEpoch {
		t.Fatalf("old root receipt did not complete re-lease safely: %#v err=%v", completed, err)
	}
}

func testOperationCommand(now time.Time) Command {
	return Command{
		OperationID: "77777777-7777-7777-7777-777777777777",
		SessionID:   "11111111-1111-1111-1111-111111111111", TaskID: "55555555-5555-5555-5555-555555555555",
		StepID: "66666666-6666-6666-6666-666666666666", DeploymentID: "22222222-2222-2222-2222-222222222222",
		DeploymentRevision: 7, OwnerID: "owner", RecipeID: "recipe",
		RecipeDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RecipeRevision: 1, PayloadScopeRevision: 1, CommandID: "pair.begin",
		ExecutionManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PairingExpiresAt:        now.Add(time.Hour), Action: ActionBegin, RecipientPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		RecipientPublicKeyDigest: recipientDigest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	}
}
