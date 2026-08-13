package postgres

import (
	"context"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func confirmAWSRequest(t *testing.T, ctx context.Context, store *Store, request coreaws.ChangeRequestResult) coreconfirmation.Confirmation {
	t.Helper()
	service, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := service.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: request.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: request.Confirmation.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return confirmed
}

func TestCoreAWSPostgresGenericTaskHandlerClaimExecuteTerminal(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	now := time.Now().UTC()
	credID := uuid.NewString()
	cred := coreaws.RehydrateCredentials(credID, "generic", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/generic", []byte("AKIA"), []byte("secret"), nil, 1, 1, now, now)
	if _, err := NewCoreAWSStore(store).CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	template, digest, err := coreaws.NormalizeTemplate([]byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan := coreaws.Plan{ID: uuid.NewString(), CredentialID: credID, Region: "us-east-1", StackName: "generic-" + uuid.NewString()[:8], Operation: coreaws.OperationCreate, Template: template, TemplateSHA256: digest, Parameters: map[string]string{}, Tags: map[string]string{}, Revision: 1, CreatedAt: now}
	if _, err = NewCoreAWSStore(store).CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	coord := NewCoreAWSChangeCoordinator(store, time.Now)
	req, err := coord.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	_ = confirmAWSRequest(t, ctx, store, req)
	provider := coreaws.NewFakeProvider()
	service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), coord, nil, nil, nil, provider, time.Now)
	handler, err := coreruntime.NewAWSChangeTaskHandler(service, coord)
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(store)
	claimed, _, err := tasks.ClaimNextDue(ctx, uuid.NewString(), time.Now().UTC().Add(time.Minute), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	preFence, ferr := coord.ExecutionFence(ctx, req.Confirmation.ConfirmationID)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if preFence.Task.Revision != int64(claimed.Revision) {
		t.Fatalf("claim fence task revision=%d claimed=%d", preFence.Task.Revision, claimed.Revision)
	}
	if _, err = coord.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{ChangeID: req.Change.ID, ConfirmationID: req.Confirmation.ConfirmationID, TaskID: claimed.ID, IdempotencyKey: uuid.NewString(), Attempt: claimed.Attempt, LeaseEpoch: claimed.LeaseEpoch, ExpectedChangeRevision: preFence.Change.Revision, ExpectedConfirmationRevision: preFence.Confirmation.Revision, ExpectedTaskRevision: int64(claimed.Revision), Binding: preFence.Confirmation.Binding}); err != nil {
		t.Fatal(err)
	}
	out := handler(ctx, claimed)
	if out.Err != nil || !out.TerminalOwned {
		t.Fatalf("outcome=%+v", out)
	}
	done, err := NewCoreAWSStore(store).GetChange(ctx, req.Change.ID)
	if err != nil || done.Status != coreaws.ChangeSucceeded {
		t.Fatalf("change=%+v err=%v", done, err)
	}
	finalTask, err := tasks.GetTask(ctx, req.Task.ID)
	if err != nil || finalTask.Status != "succeeded" {
		t.Fatalf("task=%+v err=%v", finalTask, err)
	}
	if len(provider.Calls) == 0 {
		t.Fatal("provider was not called")
	}
}

func TestCoreAWSPostgresGenericTaskHandlerReclaimsUncertainProviderMutation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response func(*coreaws.FakeProvider)
	}{
		{name: "create_response_loss", response: func(p *coreaws.FakeProvider) { p.ResponseLossCreate = true }},
		{name: "execute_response_loss", response: func(p *coreaws.FakeProvider) { p.ResponseLossExecute = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, store, _, cleanup := corePG18Fixture(t)
			defer cleanup()
			now := time.Now().UTC()
			credID := uuid.NewString()
			cred := coreaws.RehydrateCredentials(credID, "reclaim", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/reclaim", []byte("AKIA"), []byte("secret"), nil, 1, 1, now, now)
			if _, err := NewCoreAWSStore(store).CreateCredential(ctx, cred); err != nil {
				t.Fatal(err)
			}
			template, digest, err := coreaws.NormalizeTemplate([]byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`))
			if err != nil {
				t.Fatal(err)
			}
			plan := coreaws.Plan{ID: uuid.NewString(), CredentialID: credID, Region: "us-east-1", StackName: "reclaim-" + uuid.NewString()[:8], Operation: coreaws.OperationCreate, Template: template, TemplateSHA256: digest, Parameters: map[string]string{}, Tags: map[string]string{}, Revision: 1, CreatedAt: now}
			if _, err = NewCoreAWSStore(store).CreatePlan(ctx, plan); err != nil {
				t.Fatal(err)
			}
			coord := NewCoreAWSChangeCoordinator(store, time.Now)
			req, err := coord.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString()})
			if err != nil {
				t.Fatal(err)
			}
			_ = confirmAWSRequest(t, ctx, store, req)
			provider := coreaws.NewFakeProvider()
			tc.response(provider)
			service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), coord, nil, nil, nil, provider, time.Now)
			handler, err := coreruntime.NewAWSChangeTaskHandler(service, coord)
			if err != nil {
				t.Fatal(err)
			}
			tasks := NewCoreTaskStore(store)
			first, _, err := tasks.ClaimNextDue(ctx, "worker-first", time.Now().UTC(), time.Minute, 1)
			if err != nil {
				t.Fatal(err)
			}
			if out := handler(ctx, first); out.Err != coreaws.ErrResponseUncertain || !out.TerminalOwned {
				t.Fatalf("first outcome=%+v", out)
			}
			if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET lease_expires_at=$2 WHERE task_id=$1`, first.ID, time.Now().UTC().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = store.pool.Exec(ctx, `UPDATE core_confirmation_reservations SET acquired_lease_expires_at=$2 WHERE confirmation_id=$1`, req.Confirmation.ConfirmationID, time.Now().UTC().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			reclaimed, _, err := tasks.ClaimNextDue(ctx, "worker-reclaimed", time.Now().UTC(), time.Minute, 1)
			if err != nil {
				t.Fatal(err)
			}
			if reclaimed.LeaseEpoch == first.LeaseEpoch || reclaimed.Revision <= first.Revision {
				t.Fatalf("reclaim did not advance task fence: first=%+v reclaimed=%+v", first, reclaimed)
			}
			if out := handler(ctx, reclaimed); out.Err != nil || !out.TerminalOwned {
				t.Fatalf("reclaimed outcome=%+v", out)
			}
			done, err := NewCoreAWSStore(store).GetChange(ctx, req.Change.ID)
			if err != nil || done.Status != coreaws.ChangeSucceeded {
				t.Fatalf("change=%+v err=%v", done, err)
			}
			finalTask, err := tasks.GetTask(ctx, req.Task.ID)
			if err != nil || finalTask.Status != coretask.StatusSucceeded {
				t.Fatalf("task=%+v err=%v", finalTask, err)
			}
			var creates, executes int
			for _, call := range provider.Calls {
				if call == "create_change_set" {
					creates++
				}
				if call == "execute_change_set" {
					executes++
				}
			}
			if creates != 1 || executes != 1 {
				t.Fatalf("provider mutation replayed: calls=%v", provider.Calls)
			}
		})
	}
}

func TestCoreAWSPostgresRequestConfirmConsumeClaimCommitLifecycle(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	var e error
	credID := uuid.NewString()
	now := time.Now().UTC()
	cred := coreaws.RehydrateCredentials(credID, "integration", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/integration", []byte("AKIA"), []byte("secret"), nil, 1, 1, now, now)
	if _, e = NewCoreAWSStore(store).CreateCredential(ctx, cred); e != nil {
		t.Fatal(e)
	}
	template := []byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`)
	norm, digest, e := coreaws.NormalizeTemplate(template)
	if e != nil {
		t.Fatal(e)
	}
	plan := coreaws.Plan{ID: uuid.NewString(), CredentialID: credID, Region: "us-east-1", StackName: "it-" + strings.ToLower(uuid.NewString()[:8]), Operation: coreaws.OperationCreate, Template: norm, TemplateSHA256: digest, Parameters: map[string]string{}, Tags: map[string]string{}, Capabilities: []string{}, Revision: 1, CreatedAt: now}
	if _, e = NewCoreAWSStore(store).CreatePlan(ctx, plan); e != nil {
		t.Fatal(e)
	}
	coord := NewCoreAWSChangeCoordinator(store, time.Now)
	reqInput := coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString()}
	req, e := coord.RequestChange(ctx, reqInput)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := coord.RequestChange(ctx, reqInput)
	if e != nil || replay.Change.ID != req.Change.ID {
		t.Fatalf("request replay=%+v err=%v", replay, e)
	}
	confirmedConfirmation := confirmAWSRequest(t, ctx, store, req)
	confirmedChange, e := NewCoreAWSStore(store).GetChange(ctx, req.Change.ID)
	if e != nil {
		t.Fatal(e)
	}
	confirmedTask := req.Task
	if e = store.pool.QueryRow(ctx, `SELECT status,revision FROM core_tasks WHERE task_id=$1`, req.Task.ID).Scan(&confirmedTask.Status, &confirmedTask.Revision); e != nil {
		t.Fatal(e)
	}
	confirmed := coreaws.ChangeRequestResult{Change: confirmedChange, Task: confirmedTask, Confirmation: confirmedConfirmation}
	// A current-1 lease epoch is never a valid provider/confirmation fence.
	if _, e = coord.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{ChangeID: confirmed.Change.ID, ConfirmationID: confirmed.Confirmation.ConfirmationID, TaskID: confirmed.Task.ID, IdempotencyKey: uuid.NewString(), Attempt: 1, LeaseEpoch: 2, ExpectedChangeRevision: confirmed.Change.Revision, ExpectedConfirmationRevision: confirmed.Confirmation.Revision, ExpectedTaskRevision: confirmed.Task.Revision - 1, Binding: confirmed.Confirmation.Binding}); e == nil {
		t.Fatal("wrong lease fence was accepted")
	}
	consumed, e := coord.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{ChangeID: confirmed.Change.ID, ConfirmationID: confirmed.Confirmation.ConfirmationID, TaskID: confirmed.Task.ID, IdempotencyKey: uuid.NewString(), Attempt: 1, LeaseEpoch: 1, ExpectedChangeRevision: confirmed.Change.Revision, ExpectedConfirmationRevision: confirmed.Confirmation.Revision, ExpectedTaskRevision: confirmed.Task.Revision, Binding: confirmed.Confirmation.Binding})
	if e != nil {
		t.Fatal(e)
	}
	fence, e := coord.ClaimProviderMutation(ctx, coreaws.ProviderMutationCommand{ChangeID: confirmed.Change.ID, ConfirmationID: confirmed.Confirmation.ConfirmationID, TaskID: confirmed.Task.ID, Attempt: 1, LeaseEpoch: 1, ExpectedChangeRevision: confirmed.Change.Revision + 1, ExpectedConfirmationRevision: confirmed.Confirmation.Revision + 1, ExpectedTaskRevision: consumed.TaskRevision, Kind: coreaws.ProviderMutationCreate})
	if e != nil {
		t.Fatal(e)
	}
	done, e := coord.CommitProviderMutation(ctx, coreaws.ProviderMutationResult{Command: coreaws.ProviderMutationCommand{ChangeID: fence.Change.ID, ConfirmationID: fence.Confirmation.ConfirmationID, TaskID: fence.Task.ID, Attempt: 1, LeaseEpoch: 1, ExpectedChangeRevision: fence.Change.Revision, ExpectedConfirmationRevision: fence.Confirmation.Revision, ExpectedTaskRevision: fence.Task.Revision, Kind: coreaws.ProviderMutationCreate}, Success: true, ProviderChangeSetID: "change-set-evidence"})
	if e != nil {
		t.Fatal(e)
	}
	if done.Status != coreaws.ChangeRunning {
		t.Fatalf("provider evidence status=%s", done.Status)
	}
	terminalFence, e := coord.ExecutionFence(ctx, done.ConfirmationID)
	if e != nil {
		t.Fatal(e)
	}
	done, e = coord.CompleteChange(ctx, coreaws.CompleteChangeCommand{ChangeID: terminalFence.Change.ID, ConfirmationID: terminalFence.Confirmation.ConfirmationID, TaskID: terminalFence.Task.ID, Attempt: terminalFence.Task.Attempt, LeaseEpoch: terminalFence.Task.LeaseEpoch, ExpectedChangeRevision: terminalFence.Change.Revision, ExpectedTaskRevision: terminalFence.Task.Revision, ExpectedConfirmationRevision: terminalFence.Confirmation.Revision, Status: coreaws.ChangeSucceeded})
	if e != nil {
		t.Fatal(e)
	}
	if done.Status != coreaws.ChangeSucceeded {
		t.Fatalf("status=%s", done.Status)
	}
	var awsEvents, taskEvents int
	if e = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_aws_events WHERE change_id=$1`, done.ID).Scan(&awsEvents); e != nil || awsEvents < 5 {
		t.Fatalf("aws events=%d err=%v", awsEvents, e)
	}
	if e = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_task_events WHERE task_id=$1`, done.TaskID).Scan(&taskEvents); e != nil || taskEvents < 5 {
		t.Fatalf("task events=%d err=%v", taskEvents, e)
	}
	if _, e = NewCoreAWSStore(store).GetChange(ctx, done.ID); e != nil {
		t.Fatal(e)
	}
	if r, e := NewCoreAWSStore(store).GetChangeByConfirmation(ctx, done.ConfirmationID); e != nil || r.Status != coreaws.ChangeSucceeded {
		t.Fatalf("change=%+v err=%v", r, e)
	}
	_ = consumed
}

func TestCoreAWSPostgresCredentialReplaceCASAndPagination(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	aws := NewCoreAWSStore(store)
	now := time.Now().UTC()
	credentialID := uuid.NewString()
	credential := coreaws.RehydrateCredentials(credentialID, "credential", "us-east-1", "", "", []byte("AKIA-old"), []byte("secret-old"), []byte("session-old"), 0, 1, now, now)
	if _, err := aws.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	old, err := aws.GetCredential(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	replaced := coreaws.RehydrateCredentials(old.ID, old.Name, old.Region, "", "", []byte("AKIA-new"), []byte("secret-new"), []byte("session-new"), 0, old.Revision+1, old.CreatedAt, now)
	got, err := aws.UpdateCredential(ctx, replaced, old.Revision)
	if err != nil {
		t.Fatal(err)
	}
	a, secret, session := got.StoredSecretBytes()
	if string(a) != "AKIA-new" || string(secret) != "secret-new" || string(session) != "session-new" {
		t.Fatal("replacement did not reload all secret columns")
	}
	if _, err = aws.UpdateCredential(ctx, replaced, old.Revision); err != coreaws.ErrRevisionConflict {
		t.Fatalf("stale update err=%v", err)
	}
	seen := map[string]bool{}
	for token := ""; ; {
		page, err := aws.ListCredentials(ctx, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatalf("duplicate credential %s", item.ID)
			}
			seen[item.ID] = true
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}
	if len(seen) != 1 {
		t.Fatalf("credential pagination lost rows: %v", seen)
	}
	for i := 0; i < 3; i++ {
		template, digest, err := coreaws.NormalizeTemplate([]byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = aws.CreatePlan(ctx, coreaws.Plan{ID: uuid.NewString(), CredentialID: credentialID, Region: "us-east-1", StackName: "page-" + uuid.NewString()[:8], Operation: coreaws.OperationCreate, Template: template, TemplateSHA256: digest, Parameters: map[string]string{}, Tags: map[string]string{}, Revision: 1, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	plans := map[string]bool{}
	for token := ""; ; {
		page, err := aws.ListPlans(ctx, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if plans[item.ID] {
				t.Fatalf("duplicate plan %s", item.ID)
			}
			plans[item.ID] = true
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}
	if len(plans) != 3 {
		t.Fatalf("plan pagination lost rows: %v", plans)
	}
}
