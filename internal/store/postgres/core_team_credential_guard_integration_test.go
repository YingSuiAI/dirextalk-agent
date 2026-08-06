package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/google/uuid"
)

func createTeamCredential(t *testing.T, ctx context.Context, service *coreaws.Service, id string) coreaws.CredentialView {
	t.Helper()
	created, err := service.SaveCredential(ctx, coreaws.CredentialInput{
		ID: id, Name: "team-credential", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-" + uuid.NewString(), SecretAccessKey: uuid.NewString(), IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func bindTeamCommandToCredential(t *testing.T, command coreteam.CreatePlanCommand, credential coreaws.CredentialView) coreteam.CreatePlanCommand {
	t.Helper()
	command.Plan.CredentialID = credential.ID
	command.Plan.CredentialRevision = uint64(credential.Revision)
	digest, err := command.Plan.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	command.Plan.Digest = digest
	command.ConfirmationBinding, err = coreteam.ConfirmationBinding(command.Plan)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func teamCreatePlanCommandForScope(t *testing.T, ctx context.Context, store *Store, now time.Time, scope coreteam.Scope) coreteam.CreatePlanCommand {
	t.Helper()
	plan := teamTestPlan(t, now)
	plan.OwnerID = scope.OwnerID
	plan.AccountGeneration = scope.AccountGeneration
	plan.PlanID = uuid.NewString()
	plan.TaskID = uuid.NewString()
	plan.ConversationID = uuid.NewString()
	plan.CredentialID = uuid.NewString()
	plan.ConfirmationID = uuid.NewString()
	credential := coreaws.RehydrateCredentials(
		plan.CredentialID, "scoped-team-plan", plan.Quote.Region, "", "",
		[]byte("AKIA-SCOPED-TEAM"), []byte("scoped-team-secret"), nil,
		0, int64(plan.CredentialRevision), now, now,
	)
	if _, err := NewCoreAWSStore(store).CreateCredentialGuarded(ctx, scope, credential); err != nil {
		t.Fatal(err)
	}
	var err error
	plan.Digest, err = plan.SemanticDigest()
	if err != nil || plan.ValidateAt(now) != nil {
		t.Fatalf("scoped plan: %#v err=%v", plan, err)
	}
	return coreteam.CreatePlanCommand{
		Scope: scope, Plan: plan, InitialExecutionID: uuid.NewString(), ConfirmationBinding: teamTestBinding(t, plan),
		IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("d", 64), CreatedAt: now,
	}
}

func scopedTaskContext(t *testing.T, ctx context.Context, scope coreteam.Scope) context.Context {
	t.Helper()
	scoped, err := coretask.WithOwnerScope(ctx, coretask.OwnerScope{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration})
	if err != nil {
		t.Fatal(err)
	}
	return scoped
}

func terminalizeTeamForCredentialMutation(t *testing.T, store *Store, command coreteam.CreatePlanCommand, at time.Time) {
	t.Helper()
	repository := NewCoreTeamStore(store)
	execution, err := repository.GetExecution(t.Context(), command.Scope, command.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionRunning
	execution.UpdatedAt = at.Add(-2 * time.Second)
	execution, err = repository.CompareAndSwapExecution(t.Context(), command.Scope, execution, execution.Revision)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionCleaningUp
	execution.UpdatedAt = at.Add(-time.Second)
	execution, err = repository.CompareAndSwapExecution(t.Context(), command.Scope, execution, execution.Revision)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionCompleted
	execution.CleanupVerifiedAt = at
	execution.UpdatedAt = at
	if _, err = repository.CompareAndSwapExecution(t.Context(), command.Scope, execution, execution.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `UPDATE core_team_role_runs SET status='completed',revision=revision+1,updated_at=$2 WHERE execution_id=$1`, command.InitialExecutionID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `UPDATE core_tasks SET status='succeeded',attempt=1,result_json='{}'::jsonb,revision=revision+1,updated_at=$2 WHERE task_id=$1`, command.Plan.TaskID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), `UPDATE core_confirmations SET state='consumed',consumed_released=true,revision=revision+1,updated_at=$2 WHERE confirmation_id=$1`, command.Plan.ConfirmationID, at); err != nil {
		t.Fatal(err)
	}
}

func TestTeamCredentialMutationsBlockOnlyActiveOwnerGeneration(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
	if err != nil {
		t.Fatal(err)
	}
	awsService := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)
	storedCredential, err := NewCoreAWSStore(store).GetCredential(ctx, command.Plan.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	credential := storedCredential.View()
	command = bindTeamCommandToCredential(t, command, credential)
	deletableCredential := createTeamCredential(t, scopeCtx, awsService, uuid.NewString())
	if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
		t.Fatalf("create active Team Plan replayed=%v err=%v", replayed, err)
	}

	newCredentialID := uuid.NewString()
	if _, err := awsService.SaveCredential(scopeCtx, coreaws.CredentialInput{
		ID: newCredentialID, Name: "blocked", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-BLOCKED", SecretAccessKey: "blocked-secret", IdempotencyKey: uuid.NewString(),
	}); !errors.Is(err, coreteam.ErrExecutionActive) || err.Error() != coreteam.ErrorCodeTeamExecutionActive {
		t.Fatalf("active create err=%v", err)
	}
	if _, err := awsService.ReplaceCredential(scopeCtx, coreaws.CredentialInput{
		ID: credential.ID, Name: credential.Name, Region: credential.Region,
		AccessKeyID: "AKIA-BLOCKED-REPLACE", SecretAccessKey: "blocked-replace",
	}, credential.Revision, uuid.NewString()); !errors.Is(err, coreteam.ErrExecutionActive) {
		t.Fatalf("active replace err=%v", err)
	}
	if err := awsService.DeleteCredential(scopeCtx, deletableCredential.ID, deletableCredential.Revision, uuid.NewString()); !errors.Is(err, coreteam.ErrExecutionActive) {
		t.Fatalf("active delete err=%v", err)
	}
	if _, err := NewCoreAWSStore(store).GetCredential(ctx, newCredentialID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("blocked create left a row: %v", err)
	}
	unchanged, err := awsService.GetCredential(scopeCtx, credential.ID)
	if err != nil || unchanged.Revision != credential.Revision {
		t.Fatalf("blocked mutation changed credential=%#v err=%v", unchanged, err)
	}

	otherScope := coreteam.Scope{OwnerID: command.Scope.OwnerID, AccountGeneration: command.Scope.AccountGeneration + 1}
	otherCtx, err := coreaws.WithCredentialMutationScope(ctx, otherScope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = awsService.ReplaceCredential(otherCtx, coreaws.CredentialInput{
		ID: credential.ID, Name: credential.Name, Region: credential.Region,
		AccessKeyID: "AKIA-WRONG-OWNER", SecretAccessKey: "wrong-owner",
	}, credential.Revision, uuid.NewString()); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("other generation replaced foreign credential: %v", err)
	}
	if err = awsService.DeleteCredential(otherCtx, credential.ID, credential.Revision, uuid.NewString()); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("other generation deleted foreign credential: %v", err)
	}
	wrongScopeCommand := command
	wrongScopeCommand.Scope = otherScope
	wrongScopeCommand.Plan.OwnerID = otherScope.OwnerID
	wrongScopeCommand.Plan.AccountGeneration = otherScope.AccountGeneration
	wrongScopeCommand = bindTeamCommandToCredential(t, wrongScopeCommand, credential)
	if _, _, err = teamStore.CreatePlan(ctx, wrongScopeCommand); !errors.Is(err, coreteam.ErrConflict) {
		t.Fatalf("other generation bound foreign credential to Team Plan: %v", err)
	}
	otherCredentialID := uuid.NewString()
	createTeamCredential(t, otherCtx, awsService, otherCredentialID)
	var storedOwner string
	var storedGeneration int64
	if err = store.pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_aws_credentials WHERE credential_id=$1`, otherCredentialID).Scan(&storedOwner, &storedGeneration); err != nil {
		t.Fatal(err)
	}
	if storedOwner != otherScope.OwnerID || storedGeneration != otherScope.AccountGeneration {
		t.Fatalf("credential scope=(%q,%d), want (%q,%d)", storedOwner, storedGeneration, otherScope.OwnerID, otherScope.AccountGeneration)
	}

	terminalizeTeamForCredentialMutation(t, store, command, now.Add(time.Minute))
	replaced, err := awsService.ReplaceCredential(scopeCtx, coreaws.CredentialInput{
		ID: credential.ID, Name: credential.Name, Region: credential.Region,
		AccessKeyID: "AKIA-AFTER-CLEANUP", SecretAccessKey: "after-cleanup",
	}, credential.Revision, uuid.NewString())
	if err != nil || replaced.Revision != credential.Revision+1 {
		t.Fatalf("replace after cleanup=%#v err=%v", replaced, err)
	}
	if err = awsService.DeleteCredential(scopeCtx, deletableCredential.ID, deletableCredential.Revision, uuid.NewString()); err != nil {
		t.Fatalf("delete after cleanup: %v", err)
	}
	createTeamCredential(t, scopeCtx, awsService, uuid.NewString())
}

func TestUnlaunchedTeamConfirmationTerminalStateReleasesCredentialGuard(t *testing.T) {
	for _, test := range []struct {
		name          string
		wantExecution coreteam.ExecutionStatus
		terminalize   func(*testing.T, *coreconfirmation.Service, coreteam.CreatePlanCommand, time.Time)
	}{
		{
			name:          "rejected",
			wantExecution: coreteam.ExecutionCanceled,
			terminalize: func(t *testing.T, service *coreconfirmation.Service, command coreteam.CreatePlanCommand, at time.Time) {
				t.Helper()
				if _, err := service.Reject(t.Context(), coreconfirmation.RejectCommand{
					ConfirmationID:   command.Plan.ConfirmationID,
					IdempotencyKey:   uuid.NewString(),
					ExpectedRevision: 1,
					Reason:           "user changed credentials",
					At:               at,
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:          "expired",
			wantExecution: coreteam.ExecutionTimedOut,
			terminalize: func(t *testing.T, service *coreconfirmation.Service, command coreteam.CreatePlanCommand, at time.Time) {
				t.Helper()
				if _, err := service.Expire(t.Context(), coreconfirmation.ExpireCommand{
					ConfirmationID:   command.Plan.ConfirmationID,
					IdempotencyKey:   uuid.NewString(),
					ExpectedRevision: 1,
					Reason:           coreconfirmation.ReasonExpired,
					At:               at,
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, store, teamStore, cleanup := teamStoreFixture(t)
			defer cleanup()
			now := time.Now().UTC().Truncate(time.Microsecond)
			command := teamCreatePlanCommand(t, ctx, store, now)
			if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
				t.Fatalf("create Team Plan replayed=%v err=%v", replayed, err)
			}
			confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
			if err != nil {
				t.Fatal(err)
			}

			terminalAt := now.Add(time.Minute)
			test.terminalize(t, confirmationService, command, terminalAt)

			execution, err := teamStore.GetExecution(ctx, command.Scope, command.InitialExecutionID)
			if err != nil {
				t.Fatal(err)
			}
			if execution.Status != test.wantExecution || !execution.CleanupVerifiedAt.Equal(terminalAt) {
				t.Fatalf("execution=%#v want status=%s cleanup=%s", execution, test.wantExecution, terminalAt)
			}
			var nonterminalRuns int
			if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_team_role_runs WHERE execution_id=$1 AND status<>$2`, command.InitialExecutionID, string(test.wantExecution)).Scan(&nonterminalRuns); err != nil {
				t.Fatal(err)
			}
			if nonterminalRuns != 0 {
				t.Fatalf("%d role runs were not terminalized", nonterminalRuns)
			}

			scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
			if err != nil {
				t.Fatal(err)
			}
			awsService := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)
			if _, err = awsService.SaveCredential(scopeCtx, coreaws.CredentialInput{
				ID: uuid.NewString(), Name: "after-terminal", Region: "ap-northeast-3",
				AccessKeyID: "AKIA-AFTER-TERMINAL", SecretAccessKey: "after-terminal-secret", IdempotencyKey: uuid.NewString(),
			}); err != nil {
				t.Fatalf("credential mutation remained blocked: %v", err)
			}
		})
	}
}

func TestStartedTeamConfirmationExpiryCannotFabricateCleanup(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
		t.Fatalf("create Team Plan replayed=%v err=%v", replayed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=1,lease_epoch=1,lease_holder='worker-1',lease_expires_at=$2,revision=revision+1,updated_at=$3 WHERE task_id=$1`, command.Plan.TaskID, now.Add(time.Hour), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	execution, err := teamStore.GetExecution(ctx, command.Scope, command.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionRunning
	execution.UpdatedAt = now.Add(time.Second)
	if _, err = teamStore.CompareAndSwapExecution(ctx, command.Scope, execution, execution.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_team_role_runs SET status='running',revision=revision+1,updated_at=$2 WHERE execution_id=$1 AND role_id='research'`, command.InitialExecutionID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Expire(ctx, coreconfirmation.ExpireCommand{
		ConfirmationID:   command.Plan.ConfirmationID,
		IdempotencyKey:   uuid.NewString(),
		ExpectedRevision: 1,
		Reason:           coreconfirmation.ReasonExpired,
		At:               now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	execution, err = teamStore.GetExecution(ctx, command.Scope, command.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Status != coreteam.ExecutionRunning || !execution.CleanupVerifiedAt.IsZero() {
		t.Fatalf("started execution was falsely cleaned: %#v", execution)
	}
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
	if err != nil {
		t.Fatal(err)
	}
	awsService := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)
	if _, err = awsService.SaveCredential(scopeCtx, coreaws.CredentialInput{
		ID: uuid.NewString(), Name: "must-stay-blocked", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-MUST-STAY-BLOCKED", SecretAccessKey: "must-stay-blocked", IdempotencyKey: uuid.NewString(),
	}); !errors.Is(err, coreteam.ErrExecutionActive) {
		t.Fatalf("started execution released credential guard: %v", err)
	}
}

func TestTeamCredentialLaunchRotationRaceHasSingleWinner(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	awsService := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)

	for iteration := 1; iteration <= 8; iteration++ {
		now := time.Now().UTC().Truncate(time.Microsecond)
		command := teamCreatePlanCommand(t, ctx, store, now)
		command.Scope.OwnerID = fmt.Sprintf("@team-race-%d:example.test", iteration)
		command.Plan.OwnerID = command.Scope.OwnerID
		command.Scope.AccountGeneration = int64(iteration)
		command.Plan.AccountGeneration = int64(iteration)
		scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
		if err != nil {
			t.Fatal(err)
		}
		credential := createTeamCredential(t, scopeCtx, awsService, uuid.NewString())
		command = bindTeamCommandToCredential(t, command, credential)

		start := make(chan struct{})
		var wait sync.WaitGroup
		var planErr, mutationErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, _, planErr = teamStore.CreatePlan(ctx, command)
		}()
		go func() {
			defer wait.Done()
			<-start
			_, mutationErr = awsService.ReplaceCredential(scopeCtx, coreaws.CredentialInput{
				ID: credential.ID, Name: credential.Name, Region: credential.Region,
				AccessKeyID: "AKIA-RACE", SecretAccessKey: "race-secret",
			}, credential.Revision, uuid.NewString())
		}()
		close(start)
		wait.Wait()

		switch {
		case planErr == nil && errors.Is(mutationErr, coreteam.ErrExecutionActive):
			terminalizeTeamForCredentialMutation(t, store, command, now.Add(time.Minute))
		case mutationErr == nil && errors.Is(planErr, coreteam.ErrConflict):
		default:
			t.Fatalf("iteration %d planErr=%v mutationErr=%v", iteration, planErr, mutationErr)
		}
	}
}

func TestPostgresCredentialMutationsReplayDurablyAcrossActiveTeamExecution(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
	if err != nil {
		t.Fatal(err)
	}
	service := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)

	createKey := uuid.NewString()
	createInput := coreaws.CredentialInput{
		ID: uuid.NewString(), Name: "durable-create", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-DURABLE-CREATE", SecretAccessKey: "durable-create-secret", IdempotencyKey: createKey,
	}
	created, err := service.SaveCredential(scopeCtx, createInput)
	if err != nil {
		t.Fatal(err)
	}
	createdReplay, err := service.SaveCredential(scopeCtx, createInput)
	if err != nil || createdReplay != created {
		t.Fatalf("create replay=%#v want=%#v err=%v", createdReplay, created, err)
	}
	changedCreate := createInput
	changedCreate.Name = "changed-create"
	if _, err = service.SaveCredential(scopeCtx, changedCreate); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("changed create replay err=%v", err)
	}

	concurrentKey := uuid.NewString()
	concurrentInput := coreaws.CredentialInput{
		ID: uuid.NewString(), Name: "concurrent", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-CONCURRENT", SecretAccessKey: "concurrent-secret", IdempotencyKey: concurrentKey,
	}
	start := make(chan struct{})
	results := make(chan coreaws.CredentialView, 8)
	errorsSeen := make(chan error, 8)
	var wait sync.WaitGroup
	for attempt := 0; attempt < 8; attempt++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, saveErr := service.SaveCredential(scopeCtx, concurrentInput)
			results <- result
			errorsSeen <- saveErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsSeen)
	for saveErr := range errorsSeen {
		if saveErr != nil {
			t.Fatalf("concurrent replay err=%v", saveErr)
		}
	}
	for result := range results {
		if result.ID != concurrentInput.ID || result.Revision != 1 {
			t.Fatalf("concurrent result=%#v", result)
		}
	}
	var rowCount int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_aws_credentials WHERE credential_id=$1`, concurrentInput.ID).Scan(&rowCount); err != nil || rowCount != 1 {
		t.Fatalf("concurrent credential rows=%d err=%v", rowCount, err)
	}

	replaceKey := uuid.NewString()
	replaceInput := coreaws.CredentialInput{
		ID: created.ID, Name: "durable-replaced", Region: created.Region,
		AccessKeyID: "AKIA-DURABLE-REPLACED", SecretAccessKey: "durable-replaced-secret",
	}
	replaced, err := service.ReplaceCredential(scopeCtx, replaceInput, created.Revision, replaceKey)
	if err != nil {
		t.Fatal(err)
	}
	replacedReplay, err := service.ReplaceCredential(scopeCtx, replaceInput, created.Revision, replaceKey)
	if err != nil || replacedReplay != replaced {
		t.Fatalf("replace replay=%#v want=%#v err=%v", replacedReplay, replaced, err)
	}

	deletable := createTeamCredential(t, scopeCtx, service, uuid.NewString())
	deleteKey := uuid.NewString()
	if err = service.DeleteCredential(scopeCtx, deletable.ID, deletable.Revision, deleteKey); err != nil {
		t.Fatal(err)
	}
	if err = service.DeleteCredential(scopeCtx, deletable.ID, deletable.Revision, deleteKey); err != nil {
		t.Fatalf("delete replay after row removal: %v", err)
	}

	if _, replayed, createErr := teamStore.CreatePlan(ctx, command); createErr != nil || replayed {
		t.Fatalf("create active Team Plan replayed=%v err=%v", replayed, createErr)
	}
	if replay, replayErr := service.SaveCredential(scopeCtx, createInput); replayErr != nil || replay != created {
		t.Fatalf("create replay while active=%#v err=%v", replay, replayErr)
	}
	if replay, replayErr := service.ReplaceCredential(scopeCtx, replaceInput, created.Revision, replaceKey); replayErr != nil || replay != replaced {
		t.Fatalf("replace replay while active=%#v err=%v", replay, replayErr)
	}
	if replayErr := service.DeleteCredential(scopeCtx, deletable.ID, deletable.Revision, deleteKey); replayErr != nil {
		t.Fatalf("delete replay while active: %v", replayErr)
	}
	changedReplace := replaceInput
	changedReplace.Name = "changed-replace"
	if _, err = service.ReplaceCredential(scopeCtx, changedReplace, created.Revision, replaceKey); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("changed replace replay err=%v", err)
	}
	if _, err = service.SaveCredential(scopeCtx, coreaws.CredentialInput{
		ID: uuid.NewString(), Name: "fresh-blocked", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-FRESH-BLOCKED", SecretAccessKey: "fresh-blocked", IdempotencyKey: uuid.NewString(),
	}); !errors.Is(err, coreteam.ErrExecutionActive) {
		t.Fatalf("fresh mutation while active err=%v", err)
	}
}

func TestTeamCredentialGuardRequiresVerifiedCleanup(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
	if err != nil {
		t.Fatal(err)
	}
	service := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)
	deletable := createTeamCredential(t, scopeCtx, service, uuid.NewString())
	if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
		t.Fatalf("create Team Plan replayed=%v err=%v", replayed, err)
	}
	execution, err := teamStore.GetExecution(ctx, command.Scope, command.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionRunning
	execution.UpdatedAt = now.Add(time.Second)
	execution, err = teamStore.CompareAndSwapExecution(ctx, command.Scope, execution, execution.Revision)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionCleaningUp
	execution.UpdatedAt = now.Add(2 * time.Second)
	execution, err = teamStore.CompareAndSwapExecution(ctx, command.Scope, execution, execution.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_team_executions SET status='completed',revision=revision+1,updated_at=$2 WHERE execution_id=$1`, execution.ExecutionID, now.Add(3*time.Second)); err == nil {
		t.Fatal("database accepted terminal Team execution without cleanup verification")
	}
	invalidTerminal := execution
	invalidTerminal.Status = coreteam.ExecutionCompleted
	invalidTerminal.UpdatedAt = now.Add(3 * time.Second)
	if _, err = teamStore.CompareAndSwapExecution(ctx, command.Scope, invalidTerminal, execution.Revision); !errors.Is(err, coreteam.ErrInvalid) {
		t.Fatalf("domain accepted terminal execution without cleanup verification: %v", err)
	}
	if err = service.DeleteCredential(scopeCtx, deletable.ID, deletable.Revision, uuid.NewString()); !errors.Is(err, coreteam.ErrExecutionActive) {
		t.Fatalf("cleaning-up execution released key fence: %v", err)
	}
	verifiedTerminal := execution
	verifiedTerminal.Status = coreteam.ExecutionCompleted
	verifiedTerminal.UpdatedAt = now.Add(4 * time.Second)
	verifiedTerminal.CleanupVerifiedAt = verifiedTerminal.UpdatedAt
	if _, err = teamStore.CompareAndSwapExecution(ctx, command.Scope, verifiedTerminal, execution.Revision); err != nil {
		t.Fatalf("verified cleanup terminalization: %v", err)
	}
	if err = service.DeleteCredential(scopeCtx, deletable.ID, deletable.Revision, uuid.NewString()); err != nil {
		t.Fatalf("verified cleanup did not release key fence: %v", err)
	}
}

func TestCoreAWSPostgresUserSurfaceScopesEveryOwnerGeneration(t *testing.T) {
	ctx, store, _, cleanup := teamStoreFixture(t)
	defer cleanup()
	owner := coreteam.Scope{OwnerID: "@postgres-aws-owner:example.test", AccountGeneration: 3}
	foreign := coreteam.Scope{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration + 1}
	ownerContext, err := coreaws.WithCredentialMutationScope(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	foreignContext, err := coreaws.WithCredentialMutationScope(ctx, foreign)
	if err != nil {
		t.Fatal(err)
	}
	sts := &coreaws.FakeSTSProvider{Identity: coreaws.Identity{
		AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/postgres-owner", PrincipalID: "AIDAPOSTGRESOWNER",
	}}
	repository := NewCoreAWSStore(store)
	service := coreaws.NewServiceWithCoordinator(repository, NewCoreAWSChangeCoordinator(store, time.Now), nil, nil, sts, coreaws.NewFakeProvider(), time.Now)
	credential := createTeamCredential(t, ownerContext, service, uuid.NewString())

	if _, err = service.GetCredential(foreignContext, credential.ID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign credential read err=%v", err)
	}
	if page, listErr := service.ListCredentials(foreignContext, 20, ""); listErr != nil || len(page.Items) != 0 {
		t.Fatalf("foreign credential list=%#v err=%v", page, listErr)
	}
	if _, err = service.TestCredential(foreignContext, credential.ID); !errors.Is(err, coreaws.ErrNotFound) || sts.Calls != 0 {
		t.Fatalf("foreign STS test err=%v calls=%d", err, sts.Calls)
	}
	if _, err = service.ReplaceCredential(foreignContext, coreaws.CredentialInput{
		ID: credential.ID, Name: "foreign", Region: credential.Region,
		AccessKeyID: "AKIA-FOREIGN", SecretAccessKey: "foreign-secret",
	}, credential.Revision, uuid.NewString()); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign credential replace err=%v", err)
	}
	if err = service.DeleteCredential(foreignContext, credential.ID, credential.Revision, uuid.NewString()); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign credential delete err=%v", err)
	}
	if _, err = service.CreatePlan(foreignContext, coreaws.PlanInput{
		CredentialID: credential.ID, StackName: "foreign", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: uuid.NewString(),
	}); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign Plan creation err=%v", err)
	}
	if _, err = service.TestCredential(ownerContext, credential.ID); err != nil {
		t.Fatalf("owner credential verification: %v", err)
	}
	plan, err := service.CreatePlan(ownerContext, coreaws.PlanInput{
		CredentialID: credential.ID, StackName: "owner", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetPlan(foreignContext, plan.ID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign Plan read err=%v", err)
	}
	if plans, listErr := service.ListPlans(foreignContext, 20, ""); listErr != nil || len(plans.Items) != 0 {
		t.Fatalf("foreign Plan list=%#v err=%v", plans, listErr)
	}
	if _, err = service.Quote(foreignContext, plan.ID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign quote err=%v", err)
	}
	requested, err := service.RequestChange(ownerContext, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetChange(foreignContext, requested.Change.ID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign Change read err=%v", err)
	}
	if changes, listErr := service.ListChanges(foreignContext, 20, plan.ID, ""); listErr != nil || len(changes.Items) != 0 {
		t.Fatalf("foreign Change list=%#v err=%v", changes, listErr)
	}
	if _, err = service.RequestChange(foreignContext, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: uuid.NewString()}); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("foreign Change request err=%v", err)
	}
}

func TestCoreAWSPostgresRequestChangeReplayIsOwnerGenerationScoped(t *testing.T) {
	ctx, store, _, cleanup := teamStoreFixture(t)
	defer cleanup()
	sts := &coreaws.FakeSTSProvider{Identity: coreaws.Identity{
		AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/scoped-replay", PrincipalID: "AIDASCOPEDREPLAY",
	}}
	service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), NewCoreAWSChangeCoordinator(store, time.Now), nil, nil, sts, coreaws.NewFakeProvider(), time.Now)
	sharedKey := uuid.NewString()

	var firstChangeIDs []string
	for index, scope := range []coreteam.Scope{
		{OwnerID: "@request-owner-a:example.test", AccountGeneration: 1},
		{OwnerID: "@request-owner-b:example.test", AccountGeneration: 8},
	} {
		scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		credential := createTeamCredential(t, scopeCtx, service, uuid.NewString())
		if _, err = service.TestCredential(scopeCtx, credential.ID); err != nil {
			t.Fatal(err)
		}
		plan, err := service.CreatePlan(scopeCtx, coreaws.PlanInput{
			CredentialID:   credential.ID,
			StackName:      fmt.Sprintf("scoped-replay-%d", index),
			Operation:      coreaws.OperationCreate,
			Template:       []byte(`{"Resources":{}}`),
			IdempotencyKey: uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		requested, err := service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: sharedKey})
		if err != nil {
			t.Fatalf("scope %d request: %v", index, err)
		}
		replayed, err := service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: sharedKey})
		if err != nil || replayed.Change.ID != requested.Change.ID {
			t.Fatalf("scope %d replay=%#v err=%v", index, replayed, err)
		}
		firstChangeIDs = append(firstChangeIDs, requested.Change.ID)
	}
	if firstChangeIDs[0] == firstChangeIDs[1] {
		t.Fatalf("cross-owner requests shared one Change: %v", firstChangeIDs)
	}
}

func TestCoreAWSPostgresCreatePlanReplaySurvivesRestartAndConcurrency(t *testing.T) {
	ctx, store, _, cleanup := teamStoreFixture(t)
	defer cleanup()
	scope := coreteam.Scope{OwnerID: "@plan-replay:example.test", AccountGeneration: 4}
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	newService := func() *coreaws.Service {
		return coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), NewCoreAWSChangeCoordinator(store, time.Now), nil, nil, &coreaws.FakeSTSProvider{}, coreaws.NewFakeProvider(), time.Now)
	}
	credential := createTeamCredential(t, scopeCtx, newService(), uuid.NewString())
	key := uuid.NewString()
	input := coreaws.PlanInput{
		CredentialID: credential.ID, StackName: "durable-plan-replay", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: key,
	}
	first, err := newService().CreatePlan(scopeCtx, input)
	if err != nil {
		t.Fatal(err)
	}

	const callers = 8
	start := make(chan struct{})
	results := make([]coreaws.PlanView, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for index := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index], errs[index] = newService().CreatePlan(scopeCtx, input)
		}(index)
	}
	close(start)
	wg.Wait()
	for index := range results {
		if errs[index] != nil || results[index].ID != first.ID {
			t.Fatalf("replay %d Plan=%#v err=%v want id=%s", index, results[index], errs[index], first.ID)
		}
	}

	changed := input
	changed.StackName = "changed-plan-replay"
	if _, err = newService().CreatePlan(scopeCtx, changed); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("changed replay err=%v", err)
	}
	var planCount int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_aws_plans WHERE owner_id=$1 AND account_generation=$2 AND credential_id=$3`, scope.OwnerID, scope.AccountGeneration, credential.ID).Scan(&planCount); err != nil || planCount != 1 {
		t.Fatalf("durable Plan count=%d err=%v", planCount, err)
	}
}

func TestPublicTaskAndConfirmationStoresEnforceOwnerGeneration(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scopeA := coreteam.Scope{OwnerID: "@task-owner-a:example.test", AccountGeneration: 2}
	scopeB := coreteam.Scope{OwnerID: "@task-owner-b:example.test", AccountGeneration: 7}
	commandA := teamCreatePlanCommandForScope(t, ctx, store, now, scopeA)
	commandB := teamCreatePlanCommandForScope(t, ctx, store, now, scopeB)
	for _, command := range []coreteam.CreatePlanCommand{commandA, commandB} {
		if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
			t.Fatalf("create scoped Team Plan replayed=%v err=%v", replayed, err)
		}
	}
	ctxA := scopedTaskContext(t, ctx, scopeA)
	ctxB := scopedTaskContext(t, ctx, scopeB)
	tasks := NewCoreTaskStore(store)
	confirmations, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = tasks.GetTask(ctxA, commandA.Plan.TaskID); err != nil {
		t.Fatalf("owner task read: %v", err)
	}
	if _, err = tasks.GetTask(ctxB, commandA.Plan.TaskID); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("foreign task read err=%v", err)
	}
	if items, _, listErr := tasks.ListTasks(ctxA, coretask.TaskListQuery{Limit: 20}); listErr != nil || len(items) != 1 || items[0].ID != commandA.Plan.TaskID {
		t.Fatalf("owner task list=%#v err=%v", items, listErr)
	}
	if events, _, listErr := tasks.ListProgress(ctxB, commandA.Plan.TaskID, 0, 20); !errors.Is(listErr, coretask.ErrNotFound) || len(events) != 0 {
		t.Fatalf("foreign task progress=%#v err=%v", events, listErr)
	}

	cancelKey := uuid.NewString()
	cancelDigest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "cancel", "task_id": commandA.Plan.TaskID})
	if _, err = tasks.CancelTask(ctxB, coretask.CancelCommand{
		TaskID: commandA.Plan.TaskID, At: now.Add(time.Second),
		Mutation: coretask.MutationCommand{IdempotencyKey: cancelKey, RequestDigest: cancelDigest, ExpectedRevision: 1},
	}); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("foreign task cancellation err=%v", err)
	}
	retryDigest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "retry", "task_id": commandA.Plan.TaskID})
	if _, err = tasks.RetryTask(ctxB, coretask.RetryCommand{
		TaskID: commandA.Plan.TaskID, At: now.Add(time.Second),
		Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: retryDigest, ExpectedRevision: 1},
	}); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("foreign task retry err=%v", err)
	}

	if _, err = confirmations.Get(ctxB, commandA.Plan.ConfirmationID); !errors.Is(err, coreconfirmation.ErrNotFound) {
		t.Fatalf("foreign confirmation read err=%v", err)
	}
	if page, listErr := confirmations.List(ctxA, coreconfirmation.ListQuery{PageSize: 20}); listErr != nil || len(page.Confirmations) != 1 || page.Confirmations[0].ConfirmationID != commandA.Plan.ConfirmationID {
		t.Fatalf("owner confirmation list=%#v err=%v", page, listErr)
	}
	if _, err = confirmations.Reject(ctxB, coreconfirmation.RejectCommand{
		ConfirmationID: commandA.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Reason: "foreign reject", At: now.Add(2 * time.Second),
	}); !errors.Is(err, coreconfirmation.ErrNotFound) {
		t.Fatalf("foreign confirmation rejection err=%v", err)
	}
	if _, err = confirmations.Confirm(ctxB, coreconfirmation.ConfirmCommand{
		ConfirmationID: commandA.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: now.Add(2 * time.Second),
	}); !errors.Is(err, coreconfirmation.ErrNotFound) {
		t.Fatalf("foreign confirmation approval err=%v", err)
	}
	confirmed, err := confirmations.Confirm(ctxA, coreconfirmation.ConfirmCommand{
		ConfirmationID: commandA.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: now.Add(3 * time.Second),
	})
	if err != nil || confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("owner confirmation=%#v err=%v", confirmed, err)
	}
}

func TestConfirmedUnlaunchedTeamExecutionCleanupOnExpiryAndTaskCancellation(t *testing.T) {
	for _, test := range []struct {
		name        string
		terminalize func(context.Context, *Store, *coreconfirmation.Service, coreteam.CreatePlanCommand, time.Time) error
	}{
		{
			name: "confirmation expiry",
			terminalize: func(ctx context.Context, _ *Store, confirmations *coreconfirmation.Service, command coreteam.CreatePlanCommand, at time.Time) error {
				_, err := confirmations.Expire(ctx, coreconfirmation.ExpireCommand{ConfirmationID: command.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 2, Reason: coreconfirmation.ReasonExpired, At: at})
				return err
			},
		},
		{
			name: "generic task cancellation",
			terminalize: func(ctx context.Context, store *Store, _ *coreconfirmation.Service, command coreteam.CreatePlanCommand, at time.Time) error {
				digest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "cancel", "task_id": command.Plan.TaskID, "revision": uint64(2)})
				_, err := NewCoreTaskStore(store).CancelTask(ctx, coretask.CancelCommand{
					TaskID: command.Plan.TaskID, Reason: "owner canceled", At: at,
					Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: digest, ExpectedRevision: 2},
				})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, store, teamStore, cleanup := teamStoreFixture(t)
			defer cleanup()
			now := time.Now().UTC().Truncate(time.Microsecond)
			command := teamCreatePlanCommand(t, ctx, store, now)
			if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
				t.Fatalf("create Team Plan replayed=%v err=%v", replayed, err)
			}
			confirmations, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
			if err != nil {
				t.Fatal(err)
			}
			ownerContext := scopedTaskContext(t, ctx, command.Scope)
			if _, err = confirmations.Confirm(ownerContext, coreconfirmation.ConfirmCommand{
				ConfirmationID: command.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: now.Add(time.Second),
			}); err != nil {
				t.Fatalf("confirm Team Plan: %v", err)
			}
			terminalAt := now.Add(2 * time.Second)
			if err = test.terminalize(ownerContext, store, confirmations, command, terminalAt); err != nil {
				t.Fatalf("terminalize confirmed Team Plan: %v", err)
			}
			execution, err := teamStore.GetExecution(ctx, command.Scope, command.InitialExecutionID)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus := coreteam.ExecutionTimedOut
			if test.name == "generic task cancellation" {
				wantStatus = coreteam.ExecutionCanceled
			}
			if execution.Status != wantStatus || !execution.CleanupVerifiedAt.Equal(terminalAt) {
				t.Fatalf("execution=%#v want status=%s cleanup=%s", execution, wantStatus, terminalAt)
			}
			scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, command.Scope)
			if err != nil {
				t.Fatal(err)
			}
			service := coreaws.NewService(NewCoreAWSStore(store), nil, nil, nil, nil, time.Now)
			if _, err = service.SaveCredential(scopeCtx, coreaws.CredentialInput{
				ID: uuid.NewString(), Name: "after-confirmed-terminal", Region: command.Plan.Quote.Region,
				AccessKeyID: "AKIA-AFTER-CONFIRMED", SecretAccessKey: "after-confirmed-secret", IdempotencyKey: uuid.NewString(),
			}); err != nil {
				t.Fatalf("credential mutation remained blocked: %v", err)
			}
		})
	}
}

func TestTeamExecutionCreationAndRejectionDoNotDeadlock(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
		t.Fatalf("create Team Plan replayed=%v err=%v", replayed, err)
	}
	confirmations, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}
	ownerContext := scopedTaskContext(t, ctx, command.Scope)
	nextAt := now.Add(2 * time.Second)
	next := coreteam.Execution{
		ExecutionID: uuid.NewString(), PlanID: command.Plan.PlanID, TaskID: uuid.NewString(), ConfirmationID: uuid.NewString(),
		OwnerID: command.Scope.OwnerID, AccountGeneration: command.Scope.AccountGeneration,
		Status: coreteam.ExecutionQueued, Revision: 1, CreatedAt: nextAt, UpdatedAt: nextAt,
	}
	createCommand := coreteam.CreateExecutionCommand{
		Scope: command.Scope, Execution: next, ConfirmationBinding: command.ConfirmationBinding,
		IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64), CreatedAt: nextAt,
	}
	start := make(chan struct{})
	rejectDone := make(chan error, 1)
	createDone := make(chan error, 1)
	go func() {
		<-start
		_, rejectErr := confirmations.Reject(ownerContext, coreconfirmation.RejectCommand{
			ConfirmationID: command.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1,
			Reason: "replace queued execution", At: now.Add(time.Second),
		})
		rejectDone <- rejectErr
	}()
	go func() {
		<-start
		_, _, createErr := teamStore.CreateExecution(ctx, createCommand)
		createDone <- createErr
	}()
	close(start)
	select {
	case err = <-rejectDone:
		if err != nil {
			t.Fatalf("concurrent rejection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent rejection deadlocked")
	}
	select {
	case err = <-createDone:
		if err != nil && !errors.Is(err, coreteam.ErrConflict) {
			t.Fatalf("concurrent execution creation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent execution creation deadlocked")
	}
}

func TestTeamTaskTimeoutAndCancellationDoNotDeadlock(t *testing.T) {
	ctx, store, teamStore, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, replayed, err := teamStore.CreatePlan(ctx, command); err != nil || replayed {
		t.Fatalf("create Team Plan replayed=%v err=%v", replayed, err)
	}
	confirmations, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}
	ownerContext := scopedTaskContext(t, ctx, command.Scope)
	if _, err = confirmations.Confirm(ownerContext, coreconfirmation.ConfirmCommand{
		ConfirmationID: command.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(store)
	claimed, lease, err := tasks.ClaimNextDue(ctx, "team-timeout-worker", now.Add(2*time.Second), time.Hour, 3)
	if err != nil || claimed.ID != command.Plan.TaskID {
		t.Fatalf("claim Team Task=%#v err=%v", claimed, err)
	}
	start := make(chan struct{})
	timeoutDone := make(chan error, 1)
	cancelDone := make(chan error, 1)
	go func() {
		<-start
		timeoutDone <- tasks.TimeoutTask(ctx, coretask.TimeoutCommand{
			Fence: coretask.Fence{TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: claimed.Revision},
			At:    now.Add(3 * time.Second),
		})
	}()
	go func() {
		<-start
		digest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "cancel", "task_id": claimed.ID, "revision": claimed.Revision})
		_, cancelErr := tasks.CancelTask(ownerContext, coretask.CancelCommand{
			TaskID: claimed.ID, Reason: "concurrent owner cancellation", At: now.Add(3 * time.Second),
			Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: digest, ExpectedRevision: claimed.Revision},
		})
		cancelDone <- cancelErr
	}()
	close(start)
	var timeoutErr, cancelErr error
	select {
	case timeoutErr = <-timeoutDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Team timeout deadlocked")
	}
	select {
	case cancelErr = <-cancelDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Team cancellation deadlocked")
	}
	if timeoutErr != nil && cancelErr != nil {
		if !errors.Is(timeoutErr, coretask.ErrLeaseConflict) || (!errors.Is(cancelErr, coretask.ErrTerminal) && !errors.Is(cancelErr, coretask.ErrRevisionConflict)) {
			t.Fatalf("timeout err=%v cancel err=%v", timeoutErr, cancelErr)
		}
	}
}

func TestConcurrentCoreAWSRequestChangeProducesOneDurableGraph(t *testing.T) {
	ctx, store, _, cleanup := teamStoreFixture(t)
	defer cleanup()
	scope := coreteam.Scope{OwnerID: "@request-concurrency:example.test", AccountGeneration: 5}
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	sts := &coreaws.FakeSTSProvider{Identity: coreaws.Identity{
		AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/request-concurrency", PrincipalID: "AIDAREQUESTCONCURRENCY",
	}}
	service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), NewCoreAWSChangeCoordinator(store, time.Now), nil, nil, sts, coreaws.NewFakeProvider(), time.Now)
	credential := createTeamCredential(t, scopeCtx, service, uuid.NewString())
	if _, err = service.TestCredential(scopeCtx, credential.ID); err != nil {
		t.Fatal(err)
	}
	plan, err := service.CreatePlan(scopeCtx, coreaws.PlanInput{
		CredentialID: credential.ID, StackName: "request-concurrency", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	key := uuid.NewString()
	start := make(chan struct{})
	results := make([]coreaws.ChangeRequestResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for index := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index], errs[index] = service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: key})
		}(index)
	}
	close(start)
	wg.Wait()
	wantID := results[0].Change.ID
	if wantID == "" {
		t.Fatalf("first concurrent request=%#v err=%v", results[0], errs[0])
	}
	for index := range results {
		if errs[index] != nil || results[index].Change.ID != wantID || results[index].Task.ID != results[0].Task.ID || results[index].Confirmation.ConfirmationID != results[0].Confirmation.ConfirmationID {
			t.Fatalf("request %d result=%#v err=%v want change=%s", index, results[index], errs[index], wantID)
		}
	}
	var graphCount int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_aws_changes WHERE plan_id=$1`, plan.ID).Scan(&graphCount); err != nil || graphCount != 1 {
		t.Fatalf("durable Change graphs=%d err=%v", graphCount, err)
	}
}

func TestLegacyCoreAWSRequestReplayRejectsMalformedDurableRelationships(t *testing.T) {
	ctx, store, _, cleanup := teamStoreFixture(t)
	defer cleanup()
	scope := coreteam.Scope{OwnerID: "@legacy-malformed:example.test", AccountGeneration: 3}
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	sts := &coreaws.FakeSTSProvider{Identity: coreaws.Identity{
		AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/legacy-malformed", PrincipalID: "AIDALEGACYMALFORMED",
	}}
	service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), NewCoreAWSChangeCoordinator(store, time.Now), nil, nil, sts, coreaws.NewFakeProvider(), time.Now)
	credential := createTeamCredential(t, scopeCtx, service, uuid.NewString())
	if _, err = service.TestCredential(scopeCtx, credential.ID); err != nil {
		t.Fatal(err)
	}
	plan, err := service.CreatePlan(scopeCtx, coreaws.PlanInput{
		CredentialID: credential.ID, StackName: "legacy-malformed", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	requested, err := service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := sha256.Sum256([]byte(plan.ID + ":" + key + ":" + requested.Confirmation.Binding.TargetID + ":" + strconv.FormatInt(requested.Confirmation.Binding.TargetRevision, 10)))
	if _, err = store.pool.Exec(ctx, `UPDATE core_aws_change_request_replays SET request_hash=$4,hash_version=1 WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, key, fmt.Sprintf("%x", legacyHash)); err != nil {
		t.Fatal(err)
	}
	dummyTaskID := uuid.NewString()
	now := time.Now().UTC()
	if _, err = store.pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'malformed replay target',NULL,$2,'aws_change',$3,'waiting_user',1,$4,$4,$4)`, dummyTaskID, uuid.NewString(), []byte(`{"aws_change":{"change_id":"`+requested.Change.ID+`"}}`), now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_confirmations SET task_id=$2 WHERE confirmation_id=$1`, requested.Confirmation.ConfirmationID, dummyTaskID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: key}); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("malformed legacy replay accepted: %v", err)
	}
	var version int
	if err = store.pool.QueryRow(ctx, `SELECT hash_version FROM core_aws_change_request_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, key).Scan(&version); err != nil || version != 1 {
		t.Fatalf("malformed replay version=%d err=%v", version, err)
	}
}

func TestConcurrentLegacyCoreAWSRequestReplayUpgrade(t *testing.T) {
	ctx, store, _, cleanup := teamStoreFixture(t)
	defer cleanup()
	scope := coreteam.Scope{OwnerID: "@legacy-concurrency:example.test", AccountGeneration: 6}
	scopeCtx, err := coreaws.WithCredentialMutationScope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	sts := &coreaws.FakeSTSProvider{Identity: coreaws.Identity{
		AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/legacy-concurrency", PrincipalID: "AIDALEGACYCONCURRENCY",
	}}
	service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), NewCoreAWSChangeCoordinator(store, time.Now), nil, nil, sts, coreaws.NewFakeProvider(), time.Now)
	credential := createTeamCredential(t, scopeCtx, service, uuid.NewString())
	if _, err = service.TestCredential(scopeCtx, credential.ID); err != nil {
		t.Fatal(err)
	}
	plan, err := service.CreatePlan(scopeCtx, coreaws.PlanInput{
		CredentialID: credential.ID, StackName: "legacy-concurrency", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	requested, err := service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := sha256.Sum256([]byte(plan.ID + ":" + key + ":" + requested.Confirmation.Binding.TargetID + ":" + strconv.FormatInt(requested.Confirmation.Binding.TargetRevision, 10)))
	if _, err = store.pool.Exec(ctx, `UPDATE core_aws_change_request_replays SET request_hash=$4,hash_version=1 WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, key, fmt.Sprintf("%x", legacyHash)); err != nil {
		t.Fatal(err)
	}
	const callers = 8
	start := make(chan struct{})
	results := make([]coreaws.ChangeRequestResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for index := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index], errs[index] = service.RequestChange(scopeCtx, coreaws.RequestChangeInput{PlanID: plan.ID, IdempotencyKey: key})
		}(index)
	}
	close(start)
	wg.Wait()
	for index := range results {
		if errs[index] != nil || results[index].Change.ID != requested.Change.ID {
			t.Fatalf("legacy upgrade %d result=%#v err=%v", index, results[index], errs[index])
		}
	}
	var version int
	if err = store.pool.QueryRow(ctx, `SELECT hash_version FROM core_aws_change_request_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, key).Scan(&version); err != nil || version != 2 {
		t.Fatalf("legacy replay version=%d err=%v", version, err)
	}
}
