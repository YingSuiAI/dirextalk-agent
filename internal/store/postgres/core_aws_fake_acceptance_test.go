package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/google/uuid"
)

type fakeAcceptanceSTS struct{}

func (fakeAcceptanceSTS) GetCallerIdentity(context.Context, coreaws.CredentialHandle) (coreaws.Identity, error) {
	return coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/fake-acceptance", PrincipalID: "fake-principal"}, nil
}

func acceptanceUUID() string { return uuid.NewString() }

func acceptanceTemplate(version string) []byte {
	return []byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Metadata":{"version":"` + version + `"}}}}`)
}

func TestCoreAWSPostgresFakeProviderAcceptanceRPC(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	awsStore := NewCoreAWSStore(store)
	coord := NewCoreAWSChangeCoordinator(store, time.Now)
	confirmDomain, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}
	confirmRPC, err := rpcapi.NewCoreConfirmationService(confirmDomain)
	if err != nil {
		t.Fatal(err)
	}
	provider := coreaws.NewFakeProvider()
	domain := coreaws.NewServiceWithCoordinator(awsStore, coord, confirmDomain, nil, fakeAcceptanceSTS{}, provider, time.Now)
	cloudRPC, err := rpcapi.NewCoreCloudControlService(domain)
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(store)
	handler, err := coreruntime.NewAWSChangeTaskHandler(domain, coord)
	if err != nil {
		t.Fatal(err)
	}

	credResp, err := cloudRPC.CreateCredential(ctx, &agentv1.CoreCloudControlServiceCreateCredentialRequest{
		IdempotencyKey: acceptanceUUID(), Name: "fake-acceptance", Region: "us-east-1", AccessKeyId: "AKIA-" + acceptanceUUID(), SecretAccessKey: acceptanceUUID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cred := credResp.GetCredential()
	if cred == nil || !cred.GetSecretAccessKeyConfigured() || !cred.GetAccessKeyConfigured() {
		// The public view deliberately reports only configuration, never the
		// stored secret value.
		t.Fatalf("credential secret exposure/configuration mismatch: %+v", cred)
	}
	if _, err := domain.TestCredential(ctx, cred.GetCredentialId()); err != nil {
		t.Fatal(err)
	}
	createPlan, err := cloudRPC.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{
		IdempotencyKey: acceptanceUUID(), CredentialId: cred.GetCredentialId(), StackName: "fake-acceptance-stack",
		Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE, Template: acceptanceTemplate("create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	updatePlan, err := cloudRPC.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{
		IdempotencyKey: acceptanceUUID(), CredentialId: cred.GetCredentialId(), StackName: "fake-acceptance-stack",
		Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_UPDATE, Template: acceptanceTemplate("update"),
	})
	if err != nil {
		t.Fatal(err)
	}
	deletePlan, err := cloudRPC.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{
		IdempotencyKey: acceptanceUUID(), CredentialId: cred.GetCredentialId(), StackName: "fake-acceptance-stack",
		Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_DELETE, Template: acceptanceTemplate("delete"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if createPlan.GetPlan().GetOperation() != agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE || updatePlan.GetPlan().GetOperation() != agentv1.CoreAWSOperation_CORE_AWS_OPERATION_UPDATE || deletePlan.GetPlan().GetOperation() != agentv1.CoreAWSOperation_CORE_AWS_OPERATION_DELETE {
		t.Fatal("create/update/delete plan operations were not retained")
	}

	// A rejected generic confirmation must never reach a provider mutation.
	rejected, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: acceptanceUUID(), PlanId: createPlan.GetPlan().GetPlanId()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmRPC.Reject(ctx, &agentv1.ConfirmationServiceRejectRequest{ConfirmationId: rejected.GetConfirmation().GetConfirmationId(), IdempotencyKey: acceptanceUUID(), ExpectedRevision: rejected.GetConfirmation().GetRevision(), Reason: "fake acceptance rejection"}); err != nil {
		t.Fatal(err)
	}
	if rejectedChange, execErr := domain.ExecuteChange(ctx, rejected.GetConfirmation().GetConfirmationId()); execErr != nil || rejectedChange.Status != coreaws.ChangeCanceled {
		t.Fatalf("rejected change execution change=%+v err=%v", rejectedChange, execErr)
	}
	if got := provider.UnconfirmedMutationCalls(); got != 0 {
		t.Fatalf("unconfirmed provider mutations=%d", got)
	}

	// Confirm the create through the RPC boundary, then run the durable Task
	// handler. Request replay must preserve the exact change/task/confirmation.
	createKey := acceptanceUUID()
	createReq, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: createKey, PlanId: createPlan.GetPlan().GetPlanId()})
	if err != nil {
		t.Fatal(err)
	}
	createReplay, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: createKey, PlanId: createPlan.GetPlan().GetPlanId()})
	if err != nil || createReplay.GetChange().GetChangeId() != createReq.GetChange().GetChangeId() || createReplay.GetTaskId() != createReq.GetTaskId() {
		t.Fatalf("request replay=%+v err=%v", createReplay, err)
	}
	confirmed, err := confirmRPC.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: createReq.GetConfirmation().GetConfirmationId(), IdempotencyKey: acceptanceUUID(), ExpectedRevision: createReq.GetConfirmation().GetRevision()})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.GetConfirmation().GetState() != agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_CONFIRMED {
		t.Fatalf("confirmation state=%v", confirmed.GetConfirmation().GetState())
	}
	claimed, _, err := tasks.ClaimNextDue(ctx, "fake-acceptance-create", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if out := handler(ctx, claimed); out.Err != nil || !out.TerminalOwned {
		t.Fatalf("create task outcome=%+v", out)
	}
	created, err := cloudRPC.GetChange(ctx, &agentv1.CoreCloudControlServiceGetChangeRequest{ChangeId: createReq.GetChange().GetChangeId()})
	if err != nil || created.GetChange().GetStatus() != string(coreaws.ChangeSucceeded) {
		t.Fatalf("created change=%+v err=%v", created, err)
	}
	if len(provider.Calls) == 0 {
		t.Fatal("fake provider did not receive create progress mutations")
	}
	progress, _, err := tasks.ListProgress(ctx, createReq.GetTaskId(), 0, 100)
	if err != nil || len(progress) < 3 {
		t.Fatalf("durable task progress=%d err=%v", len(progress), err)
	}

	// Response loss after a durable provider mutation is recovered by a new
	// worker lease and reconciliation; the provider token remains unchanged.
	provider.ResponseLossCreate = true
	updateReq, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: acceptanceUUID(), PlanId: updatePlan.GetPlan().GetPlanId()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmRPC.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: updateReq.GetConfirmation().GetConfirmationId(), IdempotencyKey: acceptanceUUID(), ExpectedRevision: updateReq.GetConfirmation().GetRevision()}); err != nil {
		t.Fatal(err)
	}
	first, _, err := tasks.ClaimNextDue(ctx, "fake-acceptance-update-1", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if out := handler(ctx, first); !errors.Is(out.Err, coreaws.ErrResponseUncertain) || !out.TerminalOwned {
		t.Fatalf("uncertain update outcome=%+v", out)
	}
	uncertainFence, err := coord.ExecutionFence(ctx, updateReq.GetConfirmation().GetConfirmationId())
	if err != nil {
		t.Fatal(err)
	}
	providerToken := uncertainFence.Change.ProviderToken
	if providerToken == "" || uncertainFence.Change.Stage != coreaws.StageReconciling {
		t.Fatalf("uncertain change fence=%+v", uncertainFence)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET lease_expires_at=$2 WHERE task_id=$1`, first.ID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_confirmation_reservations SET acquired_lease_expires_at=$2 WHERE confirmation_id=$1`, updateReq.GetConfirmation().GetConfirmationId(), time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	provider.ResponseLossCreate = false
	reclaimed, _, err := tasks.ClaimNextDue(ctx, "fake-acceptance-update-2", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.LeaseEpoch == first.LeaseEpoch {
		t.Fatalf("task lease was not reclaimed: first=%+v reclaimed=%+v", first, reclaimed)
	}
	if out := handler(ctx, reclaimed); out.Err != nil || !out.TerminalOwned {
		t.Fatalf("reclaimed update outcome=%+v", out)
	}
	updated, err := cloudRPC.GetChange(ctx, &agentv1.CoreCloudControlServiceGetChangeRequest{ChangeId: updateReq.GetChange().GetChangeId()})
	if err != nil || updated.GetChange().GetStatus() != string(coreaws.ChangeSucceeded) {
		t.Fatalf("reconciled update=%+v err=%v", updated, err)
	}
	fenceAfter, err := coord.ExecutionFence(ctx, updateReq.GetConfirmation().GetConfirmationId())
	if err != nil || fenceAfter.Change.ProviderToken != providerToken || fenceAfter.Reservation.Active {
		t.Fatalf("reconciled token/reservation fence=%+v err=%v", fenceAfter, err)
	}

	// A fresh same-target delete request is allowed after release, and its
	// destroy mutation is also confirmation-bound.
	deleteReq, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: acceptanceUUID(), PlanId: deletePlan.GetPlan().GetPlanId()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmRPC.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: deleteReq.GetConfirmation().GetConfirmationId(), IdempotencyKey: acceptanceUUID(), ExpectedRevision: deleteReq.GetConfirmation().GetRevision()}); err != nil {
		t.Fatal(err)
	}
	deleteTask, _, err := tasks.ClaimNextDue(ctx, "fake-acceptance-delete", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if out := handler(ctx, deleteTask); out.Err != nil || !out.TerminalOwned {
		t.Fatalf("delete outcome=%+v", out)
	}
	deleted, err := cloudRPC.GetChange(ctx, &agentv1.CoreCloudControlServiceGetChangeRequest{ChangeId: deleteReq.GetChange().GetChangeId()})
	if err != nil || deleted.GetChange().GetStatus() != string(coreaws.ChangeSucceeded) {
		t.Fatalf("deleted change=%+v err=%v", deleted, err)
	}
	if _, err = provider.DescribeStack(ctx, coreaws.CredentialHandle{Region: "us-east-1"}, "us-east-1", "fake-acceptance-stack"); err == nil {
		t.Fatal("fake provider retained deleted stack")
	}

	// The durable Task terminal state is visible after a fresh domain/RPC
	// service instance, proving restart reads do not reconstruct volatile state.
	restarted := coreaws.NewServiceWithCoordinator(awsStore, coord, confirmDomain, nil, fakeAcceptanceSTS{}, provider, time.Now)
	restartedRPC, err := rpcapi.NewCoreCloudControlService(restarted)
	if err != nil {
		t.Fatal(err)
	}
	final, err := restartedRPC.GetChange(ctx, &agentv1.CoreCloudControlServiceGetChangeRequest{ChangeId: deleteReq.GetChange().GetChangeId()})
	if err != nil || final.GetChange().GetStatus() != string(coreaws.ChangeSucceeded) {
		t.Fatalf("restart change=%+v err=%v", final, err)
	}
	finalTask, err := tasks.GetTask(ctx, deleteReq.GetTaskId())
	if err != nil || finalTask.Status != coretask.StatusSucceeded {
		t.Fatalf("restart task=%+v err=%v", finalTask, err)
	}
}
