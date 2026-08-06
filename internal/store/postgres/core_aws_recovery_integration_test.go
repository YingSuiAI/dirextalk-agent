package postgres

import (
	"errors"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/google/uuid"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCoreAWSPostgresReclaimAfterDurableClaimBeforeProviderCall(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	now := time.Now().UTC()
	aws := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	credential := coreaws.RehydrateCredentials(credentialID, "claim-crash", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/claim-crash", []byte("AKIA"), []byte("secret"), nil, 1, 1, now, now)
	if _, err := aws.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	template, digest, err := coreaws.NormalizeTemplate([]byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan := coreaws.Plan{ID: uuid.NewString(), OwnerID: store.instanceID.String(), AccountGeneration: 1, CredentialID: credentialID, Region: "us-east-1", StackName: "claim-crash-" + uuid.NewString()[:8], Operation: coreaws.OperationCreate, Template: template, TemplateSHA256: digest, Parameters: map[string]string{}, Tags: map[string]string{}, Revision: 1, CreatedAt: now}
	if _, err = aws.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	coord := NewCoreAWSChangeCoordinator(store, time.Now)
	requested, err := coord.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString(), Scope: coreteam.Scope{OwnerID: store.instanceID.String(), AccountGeneration: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_ = confirmAWSRequest(t, ctx, store, requested)
	tasks := NewCoreTaskStore(store)
	firstTask, _, err := tasks.ClaimNextDue(ctx, "first", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coord.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{ChangeID: requested.Change.ID, ConfirmationID: requested.Confirmation.ConfirmationID, TaskID: requested.Task.ID, IdempotencyKey: uuid.NewString(), Attempt: firstTask.Attempt, LeaseEpoch: firstTask.LeaseEpoch, ExpectedChangeRevision: pre.Change.Revision, ExpectedTaskRevision: pre.Task.Revision, ExpectedConfirmationRevision: pre.Confirmation.Revision, Binding: pre.Confirmation.Binding}); err != nil {
		t.Fatal(err)
	}
	first, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := coord.ClaimProviderMutation(ctx, coreaws.ProviderMutationCommand{ChangeID: first.Change.ID, ConfirmationID: first.Change.ConfirmationID, TaskID: first.Task.ID, Attempt: first.Task.Attempt, LeaseEpoch: first.Task.LeaseEpoch, ExpectedChangeRevision: first.Change.Revision, ExpectedTaskRevision: first.Task.Revision, ExpectedConfirmationRevision: first.Confirmation.Revision, Kind: coreaws.ProviderMutationCreate})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately no SDK invocation: this is the crash boundary after durable claim.
	if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET lease_expires_at=$2 WHERE task_id=$1`, firstTask.ID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_confirmation_reservations SET acquired_lease_expires_at=$2 WHERE confirmation_id=$1`, requested.Confirmation.ConfirmationID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	reclaimedTask, _, err := tasks.ClaimNextDue(ctx, "reclaimed", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.Task.LeaseEpoch == first.Task.LeaseEpoch || reclaimed.Change.ProviderToken != claimed.Change.ProviderToken {
		t.Fatal("reclaim changed provider action token")
	}
	if _, err = coord.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{ChangeID: reclaimed.Change.ID, ConfirmationID: reclaimed.Change.ConfirmationID, TaskID: reclaimed.Task.ID, IdempotencyKey: uuid.NewString(), Attempt: reclaimed.Task.Attempt, LeaseEpoch: reclaimed.Task.LeaseEpoch, ExpectedChangeRevision: reclaimed.Change.Revision, ExpectedTaskRevision: reclaimed.Task.Revision, ExpectedConfirmationRevision: reclaimed.Confirmation.Revision, Binding: reclaimed.Confirmation.Binding}); err != nil {
		t.Fatalf("reclaimed lease could not take confirmation reservation: %v", err)
	}
	reclaimed, err = coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coord.ClaimProviderMutation(ctx, coreaws.ProviderMutationCommand{ChangeID: reclaimed.Change.ID, ConfirmationID: reclaimed.Change.ConfirmationID, TaskID: reclaimed.Task.ID, Attempt: reclaimed.Task.Attempt, LeaseEpoch: reclaimed.Task.LeaseEpoch, ExpectedChangeRevision: reclaimed.Change.Revision, ExpectedTaskRevision: reclaimed.Task.Revision, ExpectedConfirmationRevision: reclaimed.Confirmation.Revision, Kind: coreaws.ProviderMutationCreate}); err != nil {
		t.Fatalf("reclaim did not reissue provider action: %v", err)
	}
	provider := coreaws.NewFakeProvider()
	service := coreaws.NewServiceWithCoordinator(aws, coord, nil, nil, nil, provider, time.Now)
	if _, err = service.ExecuteChange(ctx, requested.Confirmation.ConfirmationID); err != nil {
		t.Fatal(err)
	}
	createCalls := 0
	for _, call := range provider.Calls {
		if call == "create_change_set" {
			createCalls++
		}
	}
	if createCalls != 1 || reclaimedTask.LeaseEpoch != reclaimed.Task.LeaseEpoch {
		t.Fatalf("provider calls=%v reclaimed=%+v", provider.Calls, reclaimedTask)
	}
	for _, changeSet := range provider.Changes {
		if changeSet.ClientToken != claimed.Change.ProviderToken {
			t.Fatalf("reissued create token=%q want=%q", changeSet.ClientToken, claimed.Change.ProviderToken)
		}
	}
}

// A user cancellation after the provider mutation has been durably claimed
// cannot claim that the external request stopped.  The late terminal worker
// must lose its stale fence and reconciliation remains the sole authority for
// recording the provider outcome and releasing the confirmation target.
func TestCoreAWSPostgresConsumedCancelVsCompleteReconcilesAndReleasesTarget(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	now := time.Now().UTC()
	aws := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	credential := coreaws.RehydrateCredentials(credentialID, "cancel-complete-race", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/cancel-complete-race", []byte("AKIA"), []byte("secret"), nil, 1, 1, now, now)
	if _, err := aws.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	template, digest, err := coreaws.NormalizeTemplate([]byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan := coreaws.Plan{ID: uuid.NewString(), OwnerID: store.instanceID.String(), AccountGeneration: 1, CredentialID: credentialID, Region: "us-east-1", StackName: "cancel-race-" + uuid.NewString()[:8], Operation: coreaws.OperationCreate, Template: template, TemplateSHA256: digest, Parameters: map[string]string{}, Tags: map[string]string{}, Revision: 1, CreatedAt: now}
	if _, err = aws.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	coord := NewCoreAWSChangeCoordinator(store, time.Now)
	requested, err := coord.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString(), Scope: coreteam.Scope{OwnerID: store.instanceID.String(), AccountGeneration: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_ = confirmAWSRequest(t, ctx, store, requested)
	tasks := NewCoreTaskStore(store)
	claimedTask, _, err := tasks.ClaimNextDue(ctx, "cancel-race", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coord.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{ChangeID: pre.Change.ID, ConfirmationID: pre.Confirmation.ConfirmationID, TaskID: pre.Task.ID, IdempotencyKey: uuid.NewString(), Attempt: claimedTask.Attempt, LeaseEpoch: claimedTask.LeaseEpoch, ExpectedChangeRevision: pre.Change.Revision, ExpectedTaskRevision: pre.Task.Revision, ExpectedConfirmationRevision: pre.Confirmation.Revision, Binding: pre.Confirmation.Binding}); err != nil {
		t.Fatal(err)
	}
	consumed, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	providerClaim, err := coord.ClaimProviderMutation(ctx, coreaws.ProviderMutationCommand{ChangeID: consumed.Change.ID, ConfirmationID: consumed.Confirmation.ConfirmationID, TaskID: consumed.Task.ID, Attempt: consumed.Task.Attempt, LeaseEpoch: consumed.Task.LeaseEpoch, ExpectedChangeRevision: consumed.Change.Revision, ExpectedTaskRevision: consumed.Task.Revision, ExpectedConfirmationRevision: consumed.Confirmation.Revision, Kind: coreaws.ProviderMutationCreate})
	if err != nil {
		t.Fatal(err)
	}
	providerCommitted, err := coord.CommitProviderMutation(ctx, coreaws.ProviderMutationResult{Command: coreaws.ProviderMutationCommand{ChangeID: providerClaim.Change.ID, ConfirmationID: providerClaim.Confirmation.ConfirmationID, TaskID: providerClaim.Task.ID, Attempt: providerClaim.Task.Attempt, LeaseEpoch: providerClaim.Task.LeaseEpoch, ExpectedChangeRevision: providerClaim.Change.Revision, ExpectedTaskRevision: providerClaim.Task.Revision, ExpectedConfirmationRevision: providerClaim.Confirmation.Revision, Kind: coreaws.ProviderMutationCreate}, Success: true, ProviderChangeSetID: "change-set-cancel-race"})
	if err != nil {
		t.Fatal(err)
	}
	providerToken := providerCommitted.ProviderToken
	reservation := providerClaim.Reservation

	start := make(chan struct{})
	completeReady := make(chan struct{})
	cancelDone := make(chan struct{})
	var wg sync.WaitGroup
	var cancelErr, completeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		cancelErr = func() error {
			_, err := tasks.CancelTask(ctx, coretask.CancelCommand{TaskID: providerClaim.Task.ID, Reason: "user_cancelled_after_provider_claim", At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64), ExpectedRevision: uint64(providerClaim.Task.Revision)}})
			return err
		}()
		close(cancelDone)
	}()
	go func() {
		defer wg.Done()
		<-start
		close(completeReady)
		<-cancelDone
		_, completeErr = coord.CompleteChange(ctx, coreaws.CompleteChangeCommand{ChangeID: providerClaim.Change.ID, ConfirmationID: providerClaim.Confirmation.ConfirmationID, TaskID: providerClaim.Task.ID, Attempt: providerClaim.Task.Attempt, LeaseEpoch: providerClaim.Task.LeaseEpoch, ExpectedChangeRevision: providerCommitted.Revision, ExpectedTaskRevision: providerClaim.Task.Revision, ExpectedConfirmationRevision: providerClaim.Confirmation.Revision, Status: coreaws.ChangeSucceeded})
	}()
	close(start)
	<-completeReady
	wg.Wait()
	if cancelErr != nil {
		t.Fatalf("cancel consumed work: %v", cancelErr)
	}
	if completeErr == nil {
		t.Fatal("stale completion committed after cancellation")
	}

	afterCancel, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if afterCancel.Change.ProviderToken != providerToken || afterCancel.Reservation.ConfirmationID != reservation.ConfirmationID || afterCancel.Reservation.TaskID != reservation.TaskID || afterCancel.Reservation.Attempt != reservation.Attempt || afterCancel.Reservation.LeaseEpoch != reservation.LeaseEpoch {
		t.Fatalf("cancel changed provider/reservation identity: before=%+v after=%+v", providerClaim, afterCancel)
	}
	if afterCancel.Change.Status != coreaws.ChangeRunning || afterCancel.Change.Stage != coreaws.StageReconciliationRequired || afterCancel.Confirmation.State != coreconfirmation.StateConsumed || !afterCancel.Reservation.Active {
		t.Fatalf("cancel falsely terminalized issued provider work: %+v", afterCancel)
	}

	reconcile := coreaws.ReconcileChangeCommand{ChangeID: afterCancel.Change.ID, ConfirmationID: afterCancel.Confirmation.ConfirmationID, TaskID: afterCancel.Task.ID, Attempt: reservation.Attempt, LeaseEpoch: reservation.LeaseEpoch, ExpectedChangeRevision: afterCancel.Change.Revision, ExpectedTaskRevision: afterCancel.Task.Revision, ExpectedConfirmationRevision: afterCancel.Confirmation.Revision, ProviderChangeSetID: providerCommitted.ChangeSetID, ProviderToken: providerToken, ProviderRequestDigest: providerCommitted.ProviderRequestDigest, Success: true}
	reconciled, err := coord.ReconcileChange(ctx, reconcile)
	if err != nil {
		t.Fatalf("authoritative reconciliation after cancellation: %v", err)
	}
	if reconciled.Status != coreaws.ChangeSucceeded {
		t.Fatalf("reconciled status=%s", reconciled.Status)
	}
	replayed, err := coord.ReconcileChange(ctx, reconcile)
	if err != nil || replayed.ID != reconciled.ID || replayed.Revision != reconciled.Revision {
		t.Fatalf("reconciliation replay=%+v err=%v", replayed, err)
	}
	mismatched := reconcile
	mismatched.ProviderRequestDigest = "mismatched-evidence"
	if _, err = coord.ReconcileChange(ctx, mismatched); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("mismatched reconciliation evidence err=%v", err)
	}
	final, err := coord.ExecutionFence(ctx, requested.Confirmation.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Reservation.Active {
		t.Fatalf("terminal reconciliation retained reservation: %+v", final.Reservation)
	}
	if _, err = coord.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString(), Scope: coreteam.Scope{OwnerID: store.instanceID.String(), AccountGeneration: 1}}); err != nil {
		t.Fatalf("same-target request remained blocked after reconciliation: %v", err)
	}
}
