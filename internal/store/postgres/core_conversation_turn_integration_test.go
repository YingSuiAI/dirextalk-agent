package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type turnDBHarness struct {
	pool   *pgxpool.Pool
	admin  *pgxpool.Pool
	schema string
	store  *CoreConversationStore
}

func openTurnDB(t *testing.T) *turnDBHarness {
	t.Helper()
	dsn := os.Getenv("AGENT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for durable turn PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminCfg, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		t.Fatalf("invalid AGENT_TEST_POSTGRES_DSN: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dtx_turn_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	instance := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instance); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	base, err := New(pool, instance, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCoreConversationStore(base)
	if err != nil {
		t.Fatal(err)
	}
	h := &turnDBHarness{pool: pool, admin: admin, schema: quoted, store: store}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
	})
	return h
}

func turnCommand() core.TurnStartCommand {
	s := coremodel.ExecutionSnapshot{ProfileID: uuid.NewString(), Revision: 1, CredentialVersion: 1, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.invalid", Model: "test", APIKey: "integration-secret"}
	return core.TurnStartCommand{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: s.ProfileID, ExpectedProfileRevision: s.Revision, ExpectedCredentialVersion: s.CredentialVersion, ProfileSnapshot: s}
}

func TestCoreConversationTurnConcurrentStartIdempotencyPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	results := make([]core.Turn, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], errs[i] = h.store.StartTurn(context.Background(), cmd) }(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if results[0].ID != results[1].ID {
		t.Fatalf("concurrent identities differ: %s %s", results[0].ID, results[1].ID)
	}
	changed := cmd
	changed.Prompt = "different"
	if _, err := h.store.StartTurn(context.Background(), changed); err != core.ErrConflict {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestCoreConversationTurnConcurrentDifferentPayloadConflictPostgres(t *testing.T) {
	h := openTurnDB(t)
	base := turnCommand()
	first := base
	second := base
	second.Prompt = "different"
	start := make(chan struct{})
	results := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, results[0] = h.store.StartTurn(context.Background(), first)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, results[1] = h.store.StartTurn(context.Background(), second)
	}()
	close(start)
	wg.Wait()
	var successes, conflicts int
	for _, err := range results {
		switch err {
		case nil:
			successes++
		case core.ErrConflict:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent start error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent different payload results: successes=%d conflicts=%d errors=%v", successes, conflicts, results)
	}
}

func TestCoreConversationTurnCancelCompletionFencePostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	turn, err := h.store.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cancel := core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID, ExpectedRevision: turn.Revision}
	start := make(chan struct{})
	cancelErrs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range cancelErrs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, cancelErrs[i] = h.store.RequestTurnCancel(context.Background(), cancel)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, cancelErr := range cancelErrs {
		if cancelErr != nil {
			t.Fatalf("identical concurrent cancel[%d]: %v", i, cancelErr)
		}
	}
	changedCancel := cancel
	changedCancel.ExpectedRevision++
	if _, err = h.store.RequestTurnCancel(context.Background(), changedCancel); err != core.ErrConflict {
		t.Fatalf("changed cancel replay err=%v", err)
	}
	response := core.ChatResponse{RequestID: cmd.RequestID, ConversationID: turn.ConversationID, Revision: 2, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "done", ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC()}}
	if _, err = h.store.CommitTurn(context.Background(), lease, response); err == nil {
		t.Fatal("stale completion won cancellation")
	}
	if _, err = h.store.MarkTurnCanceledRequested(context.Background(), turn.ID); err != nil {
		t.Fatal(err)
	}
	got, err := h.store.GetTurn(context.Background(), turn.ID)
	if err != nil || got.State != core.TurnCanceled {
		t.Fatalf("turn=%+v err=%v", got, err)
	}
}

func TestCoreConversationTurnDispatchRecoveryPostgres(t *testing.T) {
	h := openTurnDB(t)
	turn, err := h.store.StartTurn(context.Background(), turnCommand())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.PrepareTurnModel(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err = h.store.MarkTurnModelUncertain(context.Background(), lease, "provider_uncertain", "unknown"); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.FailTurnUncertain(context.Background(), turn.ID, "provider_uncertain", "unknown"); err != nil {
		t.Fatal(err)
	}
	got, err := h.store.GetTurn(context.Background(), turn.ID)
	if err != nil || got.State != core.TurnFailed {
		t.Fatalf("turn=%+v err=%v", got, err)
	}
}

func TestCoreConversationTurnMigrationConstraintsPostgres(t *testing.T) {
	h := openTurnDB(t)
	if _, err := h.pool.Exec(context.Background(), `INSERT INTO core_conversation_turns(turn_id,request_id,request_fingerprint,prompt,profile_id,profile_snapshot_json,profile_snapshot_digest,state) VALUES($1,$2,$3,'x',$4,'{}',$5,'completed')`, uuid.New(), uuid.New(), strings.Repeat("a", 64), uuid.New(), strings.Repeat("b", 64)); err == nil {
		t.Fatal("completed turn without result accepted")
	}
}

func TestCoreConversationTurnHistoryAndEventsAtomicPostgres(t *testing.T) {
	h := openTurnDB(t)
	turn, err := h.store.StartTurn(context.Background(), turnCommand())
	if err != nil {
		t.Fatal(err)
	}
	createTestProfile(context.Background(), t, h.store.Store, turn.ProfileID, "test", "integration-secret")
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response := core.ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: 2, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "done", ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC()}}
	if _, err = h.store.CommitTurn(context.Background(), lease, response); err != nil {
		t.Fatal(err)
	}
	conversation, err := h.store.LoadConversation(context.Background(), turn.ConversationID)
	if err != nil || len(conversation.Messages) != 2 {
		t.Fatalf("conversation=%+v err=%v", conversation, err)
	}
	if err := conversation.ValidateForPersistence(); err != nil {
		t.Fatalf("persisted turn conversation is invalid: %v", err)
	}
	userAt, assistantAt := conversation.Messages[0].CreatedAt, conversation.Messages[1].CreatedAt
	if userAt.Location() != time.UTC || assistantAt.Location() != time.UTC || userAt.Nanosecond()%int(time.Microsecond) != 0 || assistantAt.Nanosecond()%int(time.Microsecond) != 0 || assistantAt.Sub(userAt) != time.Microsecond {
		t.Fatalf("turn timestamps are not persistably ordered: user=%s assistant=%s", userAt.Format(time.RFC3339Nano), assistantAt.Format(time.RFC3339Nano))
	}
	events, err := h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 10)
	if err != nil || len(events) < 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
}
