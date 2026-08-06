package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const teamTestOwner = "@team-store:example.test"

func teamStoreFixture(t *testing.T) (context.Context, *Store, *CoreTeamStore, func()) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for Core Team PostgreSQL 18 integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	schema := "dtx_agent_team_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	instanceID := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, store, NewCoreTeamStore(store), func() {
		pool.Close()
		cancel()
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		admin.Close()
	}
}

func teamTestPlan(t *testing.T, now time.Time) coreteam.Plan {
	t.Helper()
	plan := coreteam.Plan{
		PlanID:             uuid.NewString(),
		OwnerID:            teamTestOwner,
		AccountGeneration:  7,
		TaskID:             uuid.NewString(),
		ConversationID:     uuid.NewString(),
		CredentialID:       uuid.NewString(),
		ConfirmationID:     uuid.NewString(),
		Revision:           1,
		CredentialRevision: 3,
		Goal:               "research and independently verify",
		Runtime: coreteam.RuntimeBinding{
			RuntimeID: "official-pi-0.83.0", Adapter: "pi-v1",
			ImageDigest: "sha256:" + strings.Repeat("a", 64), AMIID: "ami-0123456789abcdef0", OutputTokens: 32_768,
		},
		Quote: coreteam.QuoteBinding{
			Region: "ap-northeast-3", AvailabilityZone: "ap-northeast-3a", InstanceType: "t3.small",
			Currency: "USD", Amount: "0.0256", HardBudget: "1.00", ExpiresAt: now.Add(time.Hour),
		},
		Roles: []coreteam.Role{
			{RoleID: "research", Goal: "collect primary evidence", Capabilities: []coreteam.Capability{coreteam.CapabilityWebResearch}},
			{RoleID: "review", Goal: "independently review evidence", DependsOn: []string{"research"}, Capabilities: []coreteam.Capability{coreteam.CapabilityCodeReview}},
		},
		Status: coreteam.PlanWaitingUser,
	}
	var err error
	plan.Digest, err = plan.SemanticDigest()
	if err != nil || plan.ValidateAt(now) != nil {
		t.Fatalf("valid plan: %#v err=%v", plan, err)
	}
	return plan
}

func teamTestBinding(t *testing.T, plan coreteam.Plan) coreconfirmation.Binding {
	t.Helper()
	binding, err := coreteam.ConfirmationBinding(plan)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func teamCreatePlanCommand(t *testing.T, ctx context.Context, store *Store, now time.Time) coreteam.CreatePlanCommand {
	t.Helper()
	plan := teamTestPlan(t, now)
	credential := coreaws.RehydrateCredentials(
		plan.CredentialID, "team-plan", plan.Quote.Region, "", "",
		[]byte("AKIA-TEAM-PLAN"), []byte("team-plan-secret"), nil,
		0, int64(plan.CredentialRevision), now, now,
	)
	scope := coreteam.Scope{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration}
	if _, err := NewCoreAWSStore(store).CreateCredentialGuarded(ctx, scope, credential); err != nil {
		t.Fatal(err)
	}
	return coreteam.CreatePlanCommand{
		Scope: scope,
		Plan:  plan, InitialExecutionID: uuid.NewString(), ConfirmationBinding: teamTestBinding(t, plan),
		IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("e", 64), CreatedAt: now,
	}
}

func TestCoreTeamStoreCreatesAtomicPlanGraphAndExactReplay(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, err := validateTeamPlanCommand(command); err != nil {
		t.Fatalf("command preflight: %v", err)
	}
	initial := coreteam.Execution{
		ExecutionID: command.InitialExecutionID, PlanID: command.Plan.PlanID,
		TaskID: command.Plan.TaskID, ConfirmationID: command.Plan.ConfirmationID,
		OwnerID: command.Scope.OwnerID, AccountGeneration: command.Scope.AccountGeneration,
		Status: coreteam.ExecutionQueued, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := initial.Validate(); err != nil {
		t.Fatalf("initial execution preflight: %v", err)
	}

	created, replayed, err := repo.CreatePlan(ctx, command)
	if err != nil || replayed || created.Plan.TaskID == "" || !created.CreatedAt.Equal(now) {
		t.Fatalf("created=%#v replayed=%v err=%v", created, replayed, err)
	}
	command.CreatedAt = now.Add(time.Minute)
	same, replayed, err := repo.CreatePlan(ctx, command)
	if err != nil || !replayed || !reflect.DeepEqual(same, created) {
		t.Fatalf("same=%#v replayed=%v err=%v", same, replayed, err)
	}

	for table, want := range map[string]int64{
		"core_tasks": 1, "core_task_events": 1, "core_confirmations": 1,
		"core_team_plans": 1, "core_team_roles": 2, "core_team_executions": 1,
		"core_team_role_runs": 2, "core_team_replays": 1,
	} {
		var got int64
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
		}
	}

	var kind, taskStatus string
	var payloadRaw []byte
	if err := store.pool.QueryRow(ctx, `SELECT task_kind,status,payload_json FROM core_tasks WHERE task_id=$1`, command.Plan.TaskID).Scan(&kind, &taskStatus, &payloadRaw); err != nil {
		t.Fatal(err)
	}
	var payload coretask.TaskPayload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil || payload.TeamExecution == nil {
		t.Fatalf("payload=%s err=%v", payloadRaw, err)
	}
	if kind != string(coretask.TaskKindTeamExecution) || taskStatus != string(coretask.StatusWaitingUser) ||
		payload.TeamExecution.PlanID != command.Plan.PlanID || payload.TeamExecution.ExecutionID != command.InitialExecutionID ||
		payload.TeamExecution.ConfirmationID != command.Plan.ConfirmationID {
		t.Fatalf("kind=%s status=%s payload=%#v", kind, taskStatus, payload.TeamExecution)
	}

	confirmation, err := NewCoreConfirmationStore(store).Get(ctx, command.Plan.ConfirmationID)
	if err != nil || !confirmation.Binding.Equal(command.ConfirmationBinding) || confirmation.TaskID != command.Plan.TaskID ||
		confirmation.State != coreconfirmation.StatePending || !confirmation.ExpiresAt.Equal(command.Plan.Quote.ExpiresAt) {
		t.Fatalf("confirmation=%#v err=%v", confirmation, err)
	}
	execution, err := repo.GetExecution(ctx, command.Scope, command.InitialExecutionID)
	if err != nil || execution.TaskID != command.Plan.TaskID || execution.ConfirmationID != command.Plan.ConfirmationID || execution.Status != coreteam.ExecutionQueued || execution.Revision != 1 {
		t.Fatalf("execution=%#v err=%v", execution, err)
	}
	runnable, err := repo.ListRunnableRoles(ctx, command.Scope, command.InitialExecutionID, 3)
	if err != nil || len(runnable) != 0 {
		t.Fatalf("roles became runnable before confirmation: %#v err=%v", runnable, err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET status='queued',updated_at=$2,revision=revision+1 WHERE task_id=$1 AND status='waiting_user'`, command.Plan.TaskID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	runnable, err = repo.ListRunnableRoles(ctx, command.Scope, command.InitialExecutionID, 3)
	if err != nil || len(runnable) != 1 || runnable[0].RoleID != "research" {
		t.Fatalf("runnable=%#v err=%v", runnable, err)
	}
}

func TestCoreTeamStoreRejectsReplayConflictAndScopesEveryRead(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	created, _, err := repo.CreatePlan(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	conflict := command
	conflict.RequestDigest = strings.Repeat("f", 64)
	if _, _, err := repo.CreatePlan(ctx, conflict); !errors.Is(err, coreteam.ErrConflict) {
		t.Fatalf("conflicting replay err=%v", err)
	}
	for _, scope := range []coreteam.Scope{
		{OwnerID: "@other:example.test", AccountGeneration: command.Scope.AccountGeneration},
		{OwnerID: command.Scope.OwnerID, AccountGeneration: command.Scope.AccountGeneration + 1},
	} {
		if _, err := repo.GetPlan(ctx, scope, created.Plan.PlanID); !errors.Is(err, coreteam.ErrNotFound) {
			t.Fatalf("scope=%#v plan err=%v", scope, err)
		}
		if _, err := repo.GetExecution(ctx, scope, command.InitialExecutionID); !errors.Is(err, coreteam.ErrNotFound) {
			t.Fatalf("scope=%#v execution err=%v", scope, err)
		}
	}
	if _, err := repo.GetPlan(ctx, coreteam.Scope{OwnerID: command.Scope.OwnerID}, created.Plan.PlanID); !errors.Is(err, coreteam.ErrInvalid) {
		t.Fatalf("invalid scope err=%v", err)
	}
}

func TestCoreTeamStoreRejectsInitialExecutionIdentityCollision(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	command := teamCreatePlanCommand(t, ctx, store, time.Now().UTC().Truncate(time.Microsecond))
	command.InitialExecutionID = command.Plan.CredentialID
	if _, _, err := repo.CreatePlan(ctx, command); !errors.Is(err, coreteam.ErrInvalid) {
		t.Fatalf("identity collision err=%v", err)
	}
	for _, table := range []string{"core_tasks", "core_confirmations", "core_team_plans", "core_team_executions", "core_team_replays"} {
		var count int64
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
}

func TestCoreTeamStoreSurvivesRestartAndRejectsPlanMutation(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	created, _, err := repo.CreatePlan(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewCoreTeamStore(store)
	restored, err := restarted.GetPlan(ctx, command.Scope, command.Plan.PlanID)
	if err != nil || !reflect.DeepEqual(restored, created) {
		t.Fatalf("restored=%#v err=%v", restored, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_team_plans SET goal='tampered' WHERE plan_id=$1`, command.Plan.PlanID); err == nil {
		t.Fatal("immutable Plan update succeeded")
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_team_roles SET goal='tampered' WHERE plan_id=$1 AND role_id='research'`, command.Plan.PlanID); err == nil {
		t.Fatal("immutable role update succeeded")
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM core_team_plans WHERE plan_id=$1`, command.Plan.PlanID); err == nil {
		t.Fatal("immutable Plan delete succeeded")
	}
}

func TestCoreTeamStoreExecutionCASListAndSchemaSafety(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, _, err := repo.CreatePlan(ctx, command); err != nil {
		t.Fatal(err)
	}
	execution, err := repo.GetExecution(ctx, command.Scope, command.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	execution.Status = coreteam.ExecutionRunning
	execution.UpdatedAt = now.Add(time.Minute)
	updated, err := repo.CompareAndSwapExecution(ctx, command.Scope, execution, 1)
	if err != nil || updated.Revision != 2 || updated.Status != coreteam.ExecutionRunning {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	if _, err := repo.CompareAndSwapExecution(ctx, command.Scope, execution, 1); !errors.Is(err, coreteam.ErrRevisionConflict) {
		t.Fatalf("stale CAS err=%v", err)
	}
	page, err := repo.ListExecutions(ctx, coreteam.ListQuery{Scope: command.Scope, Limit: 20, Statuses: []coreteam.ExecutionStatus{coreteam.ExecutionRunning}})
	if err != nil || len(page.Executions) != 1 || page.Executions[0].ExecutionID != execution.ExecutionID {
		t.Fatalf("page=%#v err=%v", page, err)
	}

	rows, err := store.pool.Query(ctx, `SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name LIKE 'core_team_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(column)
		if strings.Contains(lower, "access_key") || strings.Contains(lower, "secret_key") || strings.Contains(lower, "session_token") || strings.Contains(lower, "credential_value") || strings.Contains(lower, "provider_error") {
			t.Fatalf("secret-shaped column %s.%s", table, column)
		}
	}
}

func TestCoreTeamStoreCreatesRetryOnlyAfterPriorExecutionAndConfirmationAreTerminal(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	planCommand := teamCreatePlanCommand(t, ctx, store, now)
	if _, _, err := repo.CreatePlan(ctx, planCommand); err != nil {
		t.Fatal(err)
	}
	initial, err := repo.GetExecution(ctx, planCommand.Scope, planCommand.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	initial.Status = coreteam.ExecutionCanceled
	initial.UpdatedAt = now.Add(time.Minute)
	initial.CleanupVerifiedAt = initial.UpdatedAt
	if _, err = repo.CompareAndSwapExecution(ctx, planCommand.Scope, initial, 1); err != nil {
		t.Fatal(err)
	}
	if runnable, err := repo.ListRunnableRoles(ctx, planCommand.Scope, initial.ExecutionID, 3); err != nil || len(runnable) != 0 {
		t.Fatalf("terminal execution remained runnable: %#v err=%v", runnable, err)
	}

	retryAt := now.Add(2 * time.Minute)
	retry := coreteam.Execution{
		ExecutionID: uuid.NewString(), PlanID: planCommand.Plan.PlanID,
		TaskID: uuid.NewString(), ConfirmationID: uuid.NewString(),
		OwnerID: planCommand.Scope.OwnerID, AccountGeneration: planCommand.Scope.AccountGeneration,
		Status: coreteam.ExecutionQueued, Revision: 1, CreatedAt: retryAt, UpdatedAt: retryAt,
	}
	retryCommand := coreteam.CreateExecutionCommand{
		Scope: planCommand.Scope, Execution: retry, ConfirmationBinding: teamTestBinding(t, planCommand.Plan),
		IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("9", 64), CreatedAt: retryAt,
	}
	if _, _, err := repo.CreateExecution(ctx, retryCommand); !errors.Is(err, coreteam.ErrConflict) {
		t.Fatalf("retry created while prior confirmation was active: %v", err)
	}
	if _, err = NewCoreConfirmationStore(store).Reject(ctx, coreconfirmation.RejectCommand{
		ConfirmationID: planCommand.Plan.ConfirmationID, IdempotencyKey: uuid.NewString(),
		RequestDigest: coreconfirmation.Digest(strings.Repeat("8", 64)), ExpectedRevision: 1,
		Reason: "retry after cancellation", At: now.Add(90 * time.Second),
	}); err != nil {
		t.Fatalf("reject prior confirmation: %v", err)
	}
	mismatchedTime := retryCommand
	mismatchedTime.CreatedAt = retryAt.Add(time.Second)
	if _, _, err := repo.CreateExecution(ctx, mismatchedTime); !errors.Is(err, coreteam.ErrInvalid) {
		t.Fatalf("mismatched execution/command time err=%v", err)
	}
	created, replayed, err := repo.CreateExecution(ctx, retryCommand)
	if err != nil || replayed || !reflect.DeepEqual(created, retry) {
		t.Fatalf("created=%#v replayed=%v err=%v", created, replayed, err)
	}
	same, replayed, err := repo.CreateExecution(ctx, retryCommand)
	if err != nil || !replayed || !reflect.DeepEqual(same, retry) {
		t.Fatalf("same=%#v replayed=%v err=%v", same, replayed, err)
	}
	for table, want := range map[string]int64{"core_tasks": 2, "core_confirmations": 2, "core_team_plans": 1, "core_team_executions": 2, "core_team_role_runs": 4, "core_team_replays": 2} {
		var got int64
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
		}
	}
}

func TestCoreTeamStoreRetryRequiresPriorCoreTaskToBeTerminal(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	planCommand := teamCreatePlanCommand(t, ctx, store, now)
	if _, _, err := repo.CreatePlan(ctx, planCommand); err != nil {
		t.Fatal(err)
	}
	initial, err := repo.GetExecution(ctx, planCommand.Scope, planCommand.InitialExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	initial.Status = coreteam.ExecutionCanceled
	initial.UpdatedAt = now.Add(time.Minute)
	initial.CleanupVerifiedAt = initial.UpdatedAt
	if _, err = repo.CompareAndSwapExecution(ctx, planCommand.Scope, initial, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_confirmations SET state='rejected',revision=revision+1,updated_at=$2,terminal_code='user_rejected',terminal_reason='user_rejected' WHERE confirmation_id=$1`, planCommand.Plan.ConfirmationID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	retryAt := now.Add(2 * time.Minute)
	retry := coreteam.Execution{
		ExecutionID: uuid.NewString(), PlanID: planCommand.Plan.PlanID,
		TaskID: uuid.NewString(), ConfirmationID: uuid.NewString(),
		OwnerID: planCommand.Scope.OwnerID, AccountGeneration: planCommand.Scope.AccountGeneration,
		Status: coreteam.ExecutionQueued, Revision: 1, CreatedAt: retryAt, UpdatedAt: retryAt,
	}
	_, _, err = repo.CreateExecution(ctx, coreteam.CreateExecutionCommand{
		Scope: planCommand.Scope, Execution: retry, ConfirmationBinding: teamTestBinding(t, planCommand.Plan),
		IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("7", 64), CreatedAt: retryAt,
	})
	if !errors.Is(err, coreteam.ErrConflict) {
		t.Fatalf("retry created while prior Core Task was waiting_user: %v", err)
	}
}

func TestCoreTeamStoreConcurrentDuplicateCreatesExactlyOnce(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	command := teamCreatePlanCommand(t, ctx, store, time.Now().UTC().Truncate(time.Microsecond))
	const callers = 8
	type result struct {
		record   coreteam.PlanRecord
		replayed bool
		err      error
	}
	results := make(chan result, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		go func() {
			ready.Done()
			<-start
			record, replayed, err := repo.CreatePlan(ctx, command)
			results <- result{record: record, replayed: replayed, err: err}
		}()
	}
	ready.Wait()
	close(start)
	var created int
	var first coreteam.PlanRecord
	for i := 0; i < callers; i++ {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.replayed {
			created++
		}
		if i == 0 {
			first = got.record
		} else if !reflect.DeepEqual(first, got.record) {
			t.Fatalf("non-exact concurrent replay: %#v != %#v", first, got.record)
		}
	}
	if created != 1 {
		t.Fatalf("created=%d want=1", created)
	}
	var plans, executions int64
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_team_plans`).Scan(&plans); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_team_executions`).Scan(&executions); err != nil {
		t.Fatal(err)
	}
	if plans != 1 || executions != 1 {
		t.Fatalf("plans=%d executions=%d", plans, executions)
	}
}

func TestCoreTeamStoreAccountGenerationFenceLeavesNoPartialGraph(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	command := teamCreatePlanCommand(t, ctx, store, time.Now().UTC().Truncate(time.Microsecond))
	if _, err := store.pool.Exec(ctx, `INSERT INTO agent_account_deprovisions(owner_id,account_generation,idempotency_key,request_digest,state) VALUES($1,$2,$3,$4,'running')`, command.Scope.OwnerID, command.Scope.AccountGeneration, uuid.New(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.CreatePlan(ctx, command); !errors.Is(err, coreteam.ErrConflict) {
		t.Fatalf("deprovisioned generation admitted: %v", err)
	}
	for _, table := range []string{"core_tasks", "core_confirmations", "core_team_plans", "core_team_executions", "core_team_replays"} {
		var count int64
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
}

func TestCoreTeamStoreSerializesWithUncommittedAccountDeprovision(t *testing.T) {
	ctx, store, repo, cleanup := teamStoreFixture(t)
	defer cleanup()
	command := teamCreatePlanCommand(t, ctx, store, time.Now().UTC().Truncate(time.Microsecond))
	deprovisionTx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deprovisionOpen := true
	defer func() {
		if deprovisionOpen {
			_ = deprovisionTx.Rollback(context.Background())
		}
	}()
	if _, err = deprovisionTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		t.Fatal(err)
	}
	if _, err = deprovisionTx.Exec(ctx, `INSERT INTO agent_account_deprovisions(owner_id,account_generation,idempotency_key,request_digest,state) VALUES($1,$2,$3,$4,'running')`, command.Scope.OwnerID, command.Scope.AccountGeneration, uuid.New(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, createErr := repo.CreatePlan(ctx, command)
		result <- createErr
	}()
	select {
	case createErr := <-result:
		t.Fatalf("Team create escaped uncommitted deprovision fence: %v", createErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err = deprovisionTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	deprovisionOpen = false
	select {
	case createErr := <-result:
		if !errors.Is(createErr, coreteam.ErrConflict) {
			t.Fatalf("create after deprovision commit err=%v", createErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Team create remained blocked after deprovision commit")
	}
	for _, table := range []string{"core_tasks", "core_confirmations", "core_team_plans", "core_team_executions", "core_team_replays"} {
		var count int64
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
}
