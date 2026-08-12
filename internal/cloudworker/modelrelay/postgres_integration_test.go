package modelrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const modelRelayPostgresDSN = "postgres://postgres:dtx_corev1_test_only@127.0.0.1:46509/postgres?sslmode=disable"

func TestPostgresStorePersistsReservationAcrossRestartAndConcurrentClamp(t *testing.T) {
	fixture := newPostgresRelayFixture(t)
	store, err := NewPostgresStore(fixture.pool)
	if err != nil || store.Ready(fixture.ctx) != nil {
		t.Fatalf("relay store readiness: store=%v err=%v", store, err)
	}
	token := []byte("cwmg1_postgres-integration-bearer-not-persisted")
	tokenDigest := sha256.Sum256(token)
	grant := fixture.activate(t, store, tokenDigest, 100)
	first, invocation, err := store.BeginInvocation(fixture.ctx, BeginMutation{
		InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
		Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("request-1"),
		RequestedTokens: 40, At: fixture.now.Add(time.Second),
	})
	if err != nil || invocation.ReservedTokens != 40 || first.ReservedTokens != 40 {
		t.Fatalf("first reservation grant=%+v invocation=%+v err=%v", first, invocation, err)
	}

	restarted, err := NewPostgresStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := restarted.GetGrant(fixture.ctx, grant.GrantID)
	if err != nil || persisted.Profile != fixture.profile ||
		persisted.ReservedTokens != 40 || persisted.SettledTokens != 0 {
		t.Fatalf("restart grant=%+v err=%v", persisted, err)
	}

	const contenders = 8
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, _, err := restarted.BeginInvocation(context.Background(), BeginMutation{
				InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
				Path:            PathChatCompletions,
				RequestDigest:   relayIntegrationDigest(fmt.Sprintf("request-%d", index+2)),
				RequestedTokens: 80, At: fixture.now.Add(2 * time.Second),
			})
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded := 0
	for result := range results {
		switch {
		case result == nil:
			succeeded++
		case errorsIsAny(result, ErrBudgetExhausted, ErrConflict):
		default:
			t.Fatalf("concurrent reservation error = %v", result)
		}
	}
	final, err := restarted.GetGrant(fixture.ctx, grant.GrantID)
	if err != nil || succeeded == 0 || final.ReservedTokens != 100 ||
		final.SettledTokens != 0 || final.AvailableTokens() != 0 {
		t.Fatalf("final grant=%+v successes=%d err=%v", final, succeeded, err)
	}
	var reservedTotal int64
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT COALESCE(sum(reserved_tokens),0)
FROM core_cloud_worker_model_invocations WHERE grant_id=$1 AND state='reserved'`, grant.GrantID).Scan(&reservedTotal); err != nil || reservedTotal != 100 {
		t.Fatalf("reserved total=%d err=%v", reservedTotal, err)
	}
	var stored string
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT row_to_json(g)::text
FROM core_cloud_worker_model_grants g WHERE grant_id=$1`, grant.GrantID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, string(token)) || strings.Contains(stored, "provider-secret") {
		t.Fatal("plaintext relay or provider credential persisted")
	}
	clear(token)
}

func TestPostgresExecutionBudgetSurvivesDuplicateClaimLeaseReclaimAndRestart(t *testing.T) {
	fixture := newPostgresRelayFixture(t)
	store, err := NewPostgresStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := sha256.Sum256([]byte("cwmg1_execution-budget-first-claim"))
	fixture.activate(t, store, firstToken, 100)
	_, firstInvocation, err := store.BeginInvocation(fixture.ctx, BeginMutation{
		InvocationID: uuid.NewString(), TokenDigest: firstToken,
		Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("first-claim-request"),
		RequestedTokens: 40, At: fixture.now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Settle(fixture.ctx, SettleMutation{
		InvocationID: firstInvocation.InvocationID, ActualTokens: 25, At: fixture.now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	_, oldPendingInvocation, err := store.BeginInvocation(fixture.ctx, BeginMutation{
		InvocationID: uuid.NewString(), TokenDigest: firstToken,
		Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("old-pending-request"),
		RequestedTokens: 10, At: fixture.now.Add(2500 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A fresh store is the Agent restart boundary. Activating another bearer
	// for the same Worker session models a retried/fresh Claim response.
	restarted, err := NewPostgresStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	fixture = fixture.replaceSession(t, fixture.now.Add(3*time.Second))
	duplicateToken := sha256.Sum256([]byte("cwmg1_execution-budget-duplicate-claim"))
	duplicate := fixture.activate(t, restarted, duplicateToken, 100)
	_, duplicateInvocation, err := restarted.BeginInvocation(fixture.ctx, BeginMutation{
		InvocationID: uuid.NewString(), TokenDigest: duplicateToken,
		Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("duplicate-claim-request"),
		RequestedTokens: 100, At: fixture.now.Add(time.Second),
	})
	if err != nil || duplicateInvocation.ReservedTokens != 65 {
		t.Fatalf("duplicate claim grant=%+v invocation=%+v err=%v", duplicate, duplicateInvocation, err)
	}
	if _, _, err = restarted.Settle(fixture.ctx, SettleMutation{
		InvocationID: duplicateInvocation.InvocationID, ActualTokens: 15, At: fixture.now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = restarted.Settle(fixture.ctx, SettleMutation{
		InvocationID: oldPendingInvocation.InvocationID, ActualTokens: 10,
		At: fixture.now.Add(2500 * time.Millisecond),
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("settling old fenced grant error=%v, want %v", err, ErrFenced)
	}

	reclaimed := fixture.reclaimLease(t, fixture.now.Add(3*time.Second))
	reclaimToken := sha256.Sum256([]byte("cwmg1_execution-budget-reclaimed-lease"))
	reclaimedGrant := reclaimed.activate(t, restarted, reclaimToken, 100)
	_, reclaimedInvocation, err := restarted.BeginInvocation(fixture.ctx, BeginMutation{
		InvocationID: uuid.NewString(), TokenDigest: reclaimToken,
		Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("reclaimed-lease-request"),
		RequestedTokens: 100, At: reclaimed.now.Add(time.Second),
	})
	if err != nil || reclaimedInvocation.ReservedTokens != 50 {
		t.Fatalf("reclaimed grant=%+v invocation=%+v err=%v", reclaimedGrant, reclaimedInvocation, err)
	}
	if _, _, err = restarted.Settle(fixture.ctx, SettleMutation{
		InvocationID: reclaimedInvocation.InvocationID, ActualTokens: 50, At: reclaimed.now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	var maxTokens, reservedTokens, settledTokens, revision int64
	if err = fixture.pool.QueryRow(fixture.ctx, `SELECT max_tokens,reserved_tokens,settled_tokens,revision
FROM core_cloud_worker_model_budgets WHERE execution_id=$1`, fixture.fence.ExecutionID).Scan(
		&maxTokens, &reservedTokens, &settledTokens, &revision); err != nil ||
		maxTokens != 100 || reservedTokens != 0 || settledTokens != 100 || revision < 6 {
		t.Fatalf("execution budget max=%d reserved=%d settled=%d revision=%d err=%v",
			maxTokens, reservedTokens, settledTokens, revision, err)
	}
	if _, err = restarted.Activate(fixture.ctx, ActivationMutation{
		Grant: Grant{
			GrantID: uuid.NewString(), Fence: reclaimed.fence, Profile: reclaimed.profile,
			AudienceDigest: relayIntegrationDigest("audience"), LimitDigest: relayIntegrationDigest("limit"),
			RelayURL: "https://relay.example.test/v1", RelayBindingDigest: relayIntegrationDigest("relay-binding"),
			MaxTokens: 100, State: GrantActive, ExpiresAt: reclaimed.now.Add(time.Hour),
			ActivatedAt: reclaimed.now, UpdatedAt: reclaimed.now, Revision: 1,
		},
		TokenDigest: sha256.Sum256([]byte("cwmg1_execution-budget-exhausted-claim")),
	}); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("exhausted claim activation error=%v, want %v", err, ErrBudgetExhausted)
	}
}

func TestPostgresStoreFencesSessionLossCancelAndTerminal(t *testing.T) {
	t.Run("expired task lease before reclaim", func(t *testing.T) {
		fixture := newPostgresRelayFixture(t)
		store, err := NewPostgresStore(fixture.pool)
		if err != nil {
			t.Fatal(err)
		}
		tokenDigest := sha256.Sum256([]byte("cwmg1_expired-task-lease-integration-token"))
		grant := fixture.activate(t, store, tokenDigest, 100)
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_tasks
SET lease_expires_at=clock_timestamp()-interval '1 second'
WHERE task_id=$1 AND status='running' AND attempt=1 AND lease_epoch=1`, fixture.fence.TaskID); err != nil {
			t.Fatal(err)
		}
		_, _, err = store.BeginInvocation(fixture.ctx, BeginMutation{
			InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
			Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("expired-before-reclaim"),
			RequestedTokens: 10, At: fixture.now.Add(2 * time.Second),
		})
		if !errorsIsAny(err, ErrStaleFence) {
			t.Fatalf("expired lease error = %v", err)
		}
		stored, err := store.GetGrant(fixture.ctx, grant.GrantID)
		if err != nil || stored.State != GrantFenced || stored.ReasonCode != "stale_fence" || stored.ReservedTokens != 0 {
			t.Fatalf("expired-lease grant=%+v err=%v", stored, err)
		}
	})

	t.Run("reclaimed task epoch", func(t *testing.T) {
		fixture := newPostgresRelayFixture(t)
		store, err := NewPostgresStore(fixture.pool)
		if err != nil {
			t.Fatal(err)
		}
		tokenDigest := sha256.Sum256([]byte("cwmg1_reclaimed-task-lease-integration-token"))
		grant := fixture.activate(t, store, tokenDigest, 100)
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_tasks
SET lease_expires_at=clock_timestamp()-interval '1 second'
WHERE task_id=$1 AND status='running' AND attempt=1 AND lease_epoch=1`, fixture.fence.TaskID); err != nil {
			t.Fatal(err)
		}
		// This is the durable CoreTask reclaim transition: attempt is preserved,
		// the lease epoch advances, and a new holder gets a fresh lease.
		result, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_tasks
SET lease_epoch=lease_epoch+1,lease_holder='relay-reclaim-test',
    lease_expires_at=clock_timestamp()+interval '1 hour',revision=revision+1,
    updated_at=clock_timestamp()
WHERE task_id=$1 AND status='running' AND attempt=1 AND lease_epoch=1
  AND lease_expires_at<=clock_timestamp()`, fixture.fence.TaskID)
		if err != nil || result.RowsAffected() != 1 {
			t.Fatalf("reclaim row affected=%d err=%v", result.RowsAffected(), err)
		}
		_, _, err = store.BeginInvocation(fixture.ctx, BeginMutation{
			InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
			Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("after-reclaim"),
			RequestedTokens: 10, At: fixture.now.Add(2 * time.Second),
		})
		if !errorsIsAny(err, ErrStaleFence) {
			t.Fatalf("reclaimed lease error = %v", err)
		}
		stored, err := store.GetGrant(fixture.ctx, grant.GrantID)
		if err != nil || stored.State != GrantFenced || stored.ReservedTokens != 0 {
			t.Fatalf("reclaimed-lease grant=%+v err=%v", stored, err)
		}
	})

	t.Run("session fence", func(t *testing.T) {
		fixture := newPostgresRelayFixture(t)
		store, err := NewPostgresStore(fixture.pool)
		if err != nil {
			t.Fatal(err)
		}
		tokenDigest := sha256.Sum256([]byte("cwmg1_session-fence-integration-token"))
		grant := fixture.activate(t, store, tokenDigest, 100)
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_cloud_worker_sessions
SET state='failed',failure_code='session_fenced',failure_summary='fenced',finished_at=$2
WHERE session_id=$1`, fixture.sessionID, fixture.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		_, _, err = store.BeginInvocation(fixture.ctx, BeginMutation{
			InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
			Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("stale-session"),
			RequestedTokens: 10, At: fixture.now.Add(2 * time.Second),
		})
		if !errorsIsAny(err, ErrStaleFence) {
			t.Fatalf("session fence error = %v", err)
		}
		stored, err := store.GetGrant(fixture.ctx, grant.GrantID)
		if err != nil || stored.State != GrantFenced || stored.ReasonCode != "stale_fence" {
			t.Fatalf("fenced grant=%+v err=%v", stored, err)
		}
	})

	t.Run("cancel and terminal", func(t *testing.T) {
		fixture := newPostgresRelayFixture(t)
		store, err := NewPostgresStore(fixture.pool)
		if err != nil {
			t.Fatal(err)
		}
		tokenDigest := sha256.Sum256([]byte("cwmg1_cancel-integration-token"))
		grant := fixture.activate(t, store, tokenDigest, 100)
		_, invocation, err := store.BeginInvocation(fixture.ctx, BeginMutation{
			InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
			Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("in-flight"),
			RequestedTokens: 30, At: fixture.now.Add(time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.FenceExecution(fixture.ctx, FenceMutation{
			Fence: fixture.fence, ReasonCode: "user_canceled", At: fixture.now.Add(2 * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		_, _, err = store.BeginInvocation(fixture.ctx, BeginMutation{
			InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
			Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("after-cancel"),
			RequestedTokens: 10, At: fixture.now.Add(3 * time.Second),
		})
		if !errorsIsAny(err, ErrFenced) {
			t.Fatalf("cancel error = %v", err)
		}
		settled, finished, err := store.Settle(fixture.ctx, SettleMutation{
			InvocationID: invocation.InvocationID, ActualTokens: 30,
			At: fixture.now.Add(4 * time.Second),
		})
		if !errorsIsAny(err, ErrFenced) || settled.ReservedTokens != 0 ||
			settled.SettledTokens != 30 || finished.State != InvocationSettled {
			t.Fatalf("post-cancel settlement grant=%+v invocation=%+v err=%v", settled, finished, err)
		}
		if err := store.FenceExecution(fixture.ctx, FenceMutation{
			Fence: fixture.fence, ReasonCode: "cleanup_complete", Terminal: true,
			At: fixture.now.Add(5 * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		terminal, err := store.GetGrant(fixture.ctx, grant.GrantID)
		if err != nil || terminal.State != GrantTerminal || terminal.TerminalAt.IsZero() {
			t.Fatalf("terminal grant=%+v err=%v", terminal, err)
		}
		_, _, err = store.BeginInvocation(fixture.ctx, BeginMutation{
			InvocationID: uuid.NewString(), TokenDigest: tokenDigest,
			Path: PathChatCompletions, RequestDigest: relayIntegrationDigest("after-terminal"),
			RequestedTokens: 10, At: fixture.now.Add(6 * time.Second),
		})
		if !errorsIsAny(err, ErrTerminal) {
			t.Fatalf("terminal error = %v", err)
		}
	})
}

type postgresRelayFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	now       time.Time
	fence     Fence
	profile   ProfileReference
	sessionID string
}

func newPostgresRelayFixture(t *testing.T) postgresRelayFixture {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	strict := dsn != ""
	if dsn == "" {
		dsn = modelRelayPostgresDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		cancel()
		if strict {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err == nil {
		err = admin.Ping(ctx)
	}
	if err != nil {
		if admin != nil {
			admin.Close()
		}
		cancel()
		if strict {
			t.Fatal(err)
		}
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	schema := "dtx_model_relay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-model-relay-integration"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
	})
	for _, migration := range migrations.Ordered() {
		if _, err := pool.Exec(ctx, string(migration.Script)); err != nil {
			if !strict && strings.Contains(err.Error(), `extension "vector" is not available`) {
				t.Skipf("pgvector unavailable: %v", err)
			}
			t.Fatalf("apply migration %s: %v", migration.Name, err)
		}
	}
	fixture := postgresRelayFixture{
		ctx: ctx, pool: pool, now: time.Now().UTC().Truncate(time.Second),
		sessionID: uuid.NewString(),
	}
	fixture.fence = Fence{
		OwnerID: "@model-relay-owner:example.test", AccountGeneration: 7,
		ExecutionID: uuid.NewString(), TaskID: uuid.NewString(), Attempt: 1, LeaseEpoch: 1,
		SessionID: fixture.sessionID,
	}
	fixture.profile = ProfileReference{
		OwnerID: fixture.fence.OwnerID, AccountGeneration: fixture.fence.AccountGeneration,
		ProfileID: uuid.NewString(), ProfileRevision: 1, CredentialVersion: 1,
		Provider: ProviderOpenAICompatible, Interface: InterfaceOpenAICompatible,
		Model:                   "relay-integration-model",
		MaximumOutputTokens:     4096,
		CredentialBindingDigest: relayIntegrationDigest("credential-binding"),
		ModelBindingDigest:      relayIntegrationDigest("model-binding"),
	}
	fixture.seed(t)
	return fixture
}

func (fixture postgresRelayFixture) activate(
	t *testing.T,
	store *PostgresStore,
	tokenDigest [sha256.Size]byte,
	maxTokens uint64,
) Grant {
	t.Helper()
	grant := Grant{
		GrantID: uuid.NewString(), Fence: fixture.fence, Profile: fixture.profile,
		AudienceDigest:     relayIntegrationDigest("audience"),
		LimitDigest:        relayIntegrationDigest("limit"),
		RelayURL:           "https://relay.example.test/v1",
		RelayBindingDigest: relayIntegrationDigest("relay-binding"),
		MaxTokens:          maxTokens, State: GrantActive,
		ExpiresAt: fixture.now.Add(time.Hour), ActivatedAt: fixture.now,
		UpdatedAt: fixture.now, Revision: 1,
	}
	stored, err := store.Activate(fixture.ctx, ActivationMutation{Grant: grant, TokenDigest: tokenDigest})
	if err != nil || stored.Validate() != nil {
		t.Fatalf("activate grant=%+v err=%v", stored, err)
	}
	return stored
}

func (fixture postgresRelayFixture) replaceSession(t *testing.T, at time.Time) postgresRelayFixture {
	t.Helper()
	at = at.UTC()
	newSessionID, challengeID := uuid.NewString(), uuid.NewString()
	if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_cloud_worker_sessions
SET state='failed',failure_code='session_superseded',failure_summary='fresh identity claim',
    finished_at=$2,revision=revision+1 WHERE execution_id=$1 AND state='active'`,
		fixture.fence.ExecutionID, at); err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO core_cloud_worker_identity_challenges
(challenge_id,nonce_digest,execution_id,task_id,task_attempt,lease_epoch,
 account_generation,expectation_json,expires_at,consumed_at,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,'{}',$8,$9,$9)`, []any{
			challengeID, bytes.Repeat([]byte{10}, 32), fixture.fence.ExecutionID,
			fixture.fence.TaskID, fixture.fence.Attempt, fixture.fence.LeaseEpoch,
			fixture.fence.AccountGeneration, at.Add(time.Hour), at,
		}},
		{`INSERT INTO core_cloud_worker_sessions
(session_id,challenge_id,execution_id,task_id,task_attempt,lease_epoch,token_digest,
 expectation_json,identity_json,state,revision,claimed_at,heartbeat_at)
VALUES($1,$2,$3,$4,$5,$6,$7,'{}','{}','active',1,$8,$8)`, []any{
			newSessionID, challengeID, fixture.fence.ExecutionID, fixture.fence.TaskID,
			fixture.fence.Attempt, fixture.fence.LeaseEpoch, bytes.Repeat([]byte{11}, 32), at,
		}},
	}
	for _, statement := range statements {
		if _, err := fixture.pool.Exec(fixture.ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("replace relay session: %v\n%s", err, statement.query)
		}
	}
	fixture.now = at
	fixture.sessionID = newSessionID
	fixture.fence.SessionID = newSessionID
	return fixture
}

func (fixture postgresRelayFixture) reclaimLease(t *testing.T, at time.Time) postgresRelayFixture {
	t.Helper()
	at = at.UTC()
	newSessionID, challengeID := uuid.NewString(), uuid.NewString()
	if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_tasks
SET lease_epoch=lease_epoch+1,lease_holder='relay-budget-reclaim',lease_expires_at=$2,
    revision=revision+1,updated_at=$3
WHERE task_id=$1 AND status='running' AND attempt=$4 AND lease_epoch=$5`, fixture.fence.TaskID,
		at.Add(time.Hour), at, fixture.fence.Attempt, fixture.fence.LeaseEpoch); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_cloud_worker_launch_expectations
SET current=false,superseded_at=$2 WHERE execution_id=$1 AND current=true`,
		fixture.fence.ExecutionID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE core_cloud_worker_sessions
SET state='failed',failure_code='session_superseded',failure_summary='lease reclaimed',
    finished_at=$2,revision=revision+1 WHERE execution_id=$1 AND state='active'`,
		fixture.fence.ExecutionID, at); err != nil {
		t.Fatal(err)
	}
	newEpoch := fixture.fence.LeaseEpoch + 1
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO core_cloud_worker_launch_expectations
(execution_id,task_id,task_attempt,lease_epoch,owner_id,account_generation,account_id,
 region,instance_id,launch_identity,role_arn,role_id,instance_profile_id,required_tags_json,
 runtime_task_sha256,input_manifest_sha256,artifact_bucket,artifact_prefix,maximum_artifact_bytes,created_at)
VALUES($1,$2,$3,$4,$5,$6,'123456789012','us-east-1','i-0123456789abcdef0',$7,
 'arn:aws:iam::123456789012:role/relay-integration','AROA1234567890ABCDEFG',
 'AIPA1234567890ABCDEFG','{}',$7,$7,'dirextalk-relay-integration','execution/artifacts/',8388608,$8)`, []any{
			fixture.fence.ExecutionID, fixture.fence.TaskID, fixture.fence.Attempt, newEpoch,
			fixture.fence.OwnerID, fixture.fence.AccountGeneration, relayIntegrationDigest("seed"), at,
		}},
		{`INSERT INTO core_cloud_worker_identity_challenges
(challenge_id,nonce_digest,execution_id,task_id,task_attempt,lease_epoch,
 account_generation,expectation_json,expires_at,consumed_at,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,'{}',$8,$9,$9)`, []any{
			challengeID, bytes.Repeat([]byte{5}, 32), fixture.fence.ExecutionID,
			fixture.fence.TaskID, fixture.fence.Attempt, newEpoch, fixture.fence.AccountGeneration,
			at.Add(time.Hour), at,
		}},
		{`INSERT INTO core_cloud_worker_sessions
(session_id,challenge_id,execution_id,task_id,task_attempt,lease_epoch,token_digest,
 expectation_json,identity_json,state,revision,claimed_at,heartbeat_at)
VALUES($1,$2,$3,$4,$5,$6,$7,'{}','{}','active',1,$8,$8)`, []any{
			newSessionID, challengeID, fixture.fence.ExecutionID, fixture.fence.TaskID,
			fixture.fence.Attempt, newEpoch, bytes.Repeat([]byte{6}, 32), at,
		}},
	}
	for _, statement := range statements {
		if _, err := fixture.pool.Exec(fixture.ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("reclaim relay PostgreSQL: %v\n%s", err, statement.query)
		}
	}
	fixture.now = at
	fixture.sessionID = newSessionID
	fixture.fence.LeaseEpoch = newEpoch
	fixture.fence.SessionID = newSessionID
	return fixture
}

func (fixture postgresRelayFixture) seed(t *testing.T) {
	t.Helper()
	conversationID, turnID := uuid.NewString(), uuid.NewString()
	confirmationID, planID := uuid.NewString(), uuid.NewString()
	credentialID := uuid.NewString()
	challengeID := uuid.NewString()
	digest := relayIntegrationDigest("seed")
	tx, err := fixture.pool.Begin(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(fixture.ctx)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO core_aws_credentials
(credential_id,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,
 secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,
 session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at)
VALUES($1,'relay integration','us-east-1',1,$2,$3,$2,$3,$2,$3,false,
 '123456789012','arn:aws:iam::123456789012:user/relay-integration',1,1,$4,$4,$4)`, []any{
			credentialID, bytes.Repeat([]byte{8}, 12), bytes.Repeat([]byte{9}, 16), fixture.now,
		}},
		{`INSERT INTO core_aws_credential_revisions
(credential_id,revision,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,
 secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,
 session_token_configured,created_at)
VALUES($1,1,'us-east-1',1,$2,$3,$2,$3,$2,$3,false,$4)`, []any{
			credentialID, bytes.Repeat([]byte{8}, 12), bytes.Repeat([]byte{9}, 16), fixture.now,
		}},
		{`INSERT INTO core_model_profiles
(profile_id,display_name,provider,base_url,model_name,credential_version,revision)
VALUES($1,'relay integration','openai_compatible','https://provider.example.test/v1',$2,1,1)`, []any{fixture.profile.ProfileID, fixture.profile.Model}},
		{`INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at)
VALUES($1,'relay integration',1,$2,$2)`, []any{conversationID, fixture.now}},
		{`INSERT INTO core_conversation_turns
(turn_id,request_id,request_fingerprint,conversation_id,prompt,profile_id,profile_snapshot_json,
 profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,
 profile_snapshot_api_key_ciphertext,state,revision,created_at,updated_at,owner_id,account_generation)
VALUES($1,$2,$3,$4,'cloud worker relay integration',$5,'{}',$3,1,$6,$7,
 'waiting_confirmation',1,$8,$8,$9,$10)`, []any{
			turnID, uuid.NewString(), digest, conversationID, fixture.profile.ProfileID,
			bytes.Repeat([]byte{1}, 12), bytes.Repeat([]byte{2}, 16), fixture.now,
			fixture.fence.OwnerID, fixture.fence.AccountGeneration,
		}},
		{`INSERT INTO core_tasks
(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,status,attempt,
 lease_epoch,lease_holder,lease_expires_at,revision,created_at,updated_at,task_kind,payload_json)
VALUES($1,'cloud worker relay integration',$2,$3,$4,'running',1,1,'relay-integration',$5,
 1,$6,$6,'cloud_worker','{}')`, []any{
			fixture.fence.TaskID, conversationID, fixture.profile.ProfileID, uuid.NewString(),
			fixture.now.Add(time.Hour), fixture.now,
		}},
		{`INSERT INTO core_confirmations
(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,
 revision,created_at,updated_at,expires_at)
VALUES($1,'cloud_worker',$2,1,'{}',$3,'confirmed',1,$4,$4,$5)`, []any{
			confirmationID, fixture.fence.ExecutionID, fixture.fence.TaskID,
			fixture.now, fixture.now.Add(time.Hour),
		}},
		{`SET CONSTRAINTS ALL DEFERRED`, nil},
		{`INSERT INTO core_cloud_worker_plans
(plan_id,owner_id,account_generation,revision,digest,execution_digest,
 authorization_basis_digest,quote_digest,input_manifest_digest,model_binding_digest,
 credential_id,credential_revision,execution_id,task_id,confirmation_id,conversation_id,turn_id,recipe_id,adapter,
 workspace_mode,status,quote_expires_at,plan_json,private_json,created_at,updated_at)
VALUES($1,$2,$3,1,$4,$4,$4,$4,$4,$5,$6,1,$7,$8,$9,$10,$11,
 'ephemeral-pi-task','pi_json_task_v1','none','waiting_user',$12,
 '{"limits":{"max_tokens":100}}','{}',$13,$13)`, []any{
			planID, fixture.fence.OwnerID, fixture.fence.AccountGeneration, digest,
			fixture.profile.ModelBindingDigest, credentialID, fixture.fence.ExecutionID, fixture.fence.TaskID,
			confirmationID, conversationID, turnID, fixture.now.Add(time.Hour), fixture.now,
		}},
		{`INSERT INTO core_cloud_worker_executions
(execution_id,owner_id,account_generation,plan_id,plan_revision,plan_digest,task_id,
 confirmation_id,conversation_id,turn_id,state,revision,digest,quote_digest,
 execution_digest,execution_json,created_at,updated_at)
VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,'running',1,$5,$5,$5,'{}',$10,$10)`, []any{
			fixture.fence.ExecutionID, fixture.fence.OwnerID, fixture.fence.AccountGeneration,
			planID, digest, fixture.fence.TaskID, confirmationID, conversationID, turnID, fixture.now,
		}},
		{`INSERT INTO core_cloud_worker_launch_expectations
(execution_id,task_id,task_attempt,lease_epoch,owner_id,account_generation,account_id,
 region,instance_id,launch_identity,role_arn,role_id,instance_profile_id,required_tags_json,runtime_task_sha256,
 input_manifest_sha256,artifact_bucket,artifact_prefix,maximum_artifact_bytes,created_at)
VALUES($1,$2,1,1,$3,$4,'123456789012','us-east-1','i-0123456789abcdef0',$5,
 'arn:aws:iam::123456789012:role/relay-integration','AROA1234567890ABCDEFG',
 'AIPA1234567890ABCDEFG','{}',$5,$5,
 'dirextalk-relay-integration','execution/artifacts/',8388608,$6)`, []any{
			fixture.fence.ExecutionID, fixture.fence.TaskID, fixture.fence.OwnerID,
			fixture.fence.AccountGeneration, digest, fixture.now,
		}},
		{`INSERT INTO core_cloud_worker_identity_challenges
(challenge_id,nonce_digest,execution_id,task_id,task_attempt,lease_epoch,
 account_generation,expectation_json,expires_at,consumed_at,created_at)
VALUES($1,$2,$3,$4,1,1,$5,'{}',$6,$7,$7)`, []any{
			challengeID, bytes.Repeat([]byte{3}, 32), fixture.fence.ExecutionID,
			fixture.fence.TaskID, fixture.fence.AccountGeneration,
			fixture.now.Add(time.Hour), fixture.now,
		}},
		{`INSERT INTO core_cloud_worker_sessions
(session_id,challenge_id,execution_id,task_id,task_attempt,lease_epoch,token_digest,
 expectation_json,identity_json,state,revision,claimed_at,heartbeat_at)
VALUES($1,$2,$3,$4,1,1,$5,'{}','{}','active',1,$6,$6)`, []any{
			fixture.sessionID, challengeID, fixture.fence.ExecutionID, fixture.fence.TaskID,
			bytes.Repeat([]byte{4}, 32), fixture.now,
		}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(fixture.ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed relay PostgreSQL: %v\n%s", err, statement.query)
		}
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatal(err)
	}
}

func relayIntegrationDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest[:])
}

func errorsIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
