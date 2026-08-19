package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
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
	s := coremodel.ExecutionSnapshot{ProfileID: uuid.NewString(), Revision: 1, CredentialVersion: 1, Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, BaseURL: "https://example.invalid", Model: "test", APIKey: "integration-secret"}
	return core.TurnStartCommand{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: s.ProfileID, ExpectedProfileRevision: s.Revision, ExpectedCredentialVersion: s.CredentialVersion, ProfileSnapshot: s}
}

func TestCoreConversationFirstTurnPersistsProvisionalTitleAtAcceptancePostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	cmd.Prompt = "  请帮我部署服务。后续要求  "
	turn, err := h.store.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := h.store.LoadConversation(context.Background(), turn.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if conversation.Title != "请帮我部署服务" || conversation.Revision != 1 || len(conversation.Messages) != 0 {
		t.Fatalf("accepted conversation=%+v", conversation)
	}

	existingID := uuid.NewString()
	if err = h.store.CreateConversation(context.Background(), core.Conversation{ID: existingID, Revision: 1}, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	cmd = turnCommand()
	cmd.ConversationID = existingID
	cmd.Prompt = "existing empty conversation"
	revision := uint64(1)
	cmd.ExpectedRevision = &revision
	if _, err = h.store.StartTurn(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	conversation, err = h.store.LoadConversation(context.Background(), existingID)
	if err != nil || conversation.Title != "existing empty conversation" || conversation.Revision != revision {
		t.Fatalf("existing accepted conversation=%+v err=%v", conversation, err)
	}
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

func TestCoreConversationTurnPreservesPublicTurnIdentityInListPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	cmd.TurnID = uuid.NewString()
	turn, err := h.store.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if turn.ID != cmd.TurnID {
		t.Fatalf("turn id=%q want capability operation id=%q", turn.ID, cmd.TurnID)
	}
	turns, next, err := h.store.ListTurns(context.Background(), cmd.ConversationID, "", 10)
	if err != nil || next != "" || len(turns) != 1 || turns[0].ID != cmd.TurnID || turns[0].RequestID != cmd.RequestID {
		t.Fatalf("turns=%+v next=%q err=%v", turns, next, err)
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
	if _, err = h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET revision=revision+1 WHERE turn_id=$1`, turn.ID); err != nil {
		t.Fatal(err)
	}
	cancel := core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID}
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
	if replay, replayErr := h.store.RequestTurnCancel(context.Background(), cancel); replayErr != nil || replay.State != core.TurnCanceled {
		t.Fatalf("terminal cancel replay=%+v err=%v", replay, replayErr)
	}
}

func TestCoreConversationCompletionReplacesStoppedFirstTurnProvisionalTitlePostgres(t *testing.T) {
	h := openTurnDB(t)
	firstCommand := turnCommand()
	firstCommand.Prompt = "请帮我部署一个服务"
	first, err := h.store.StartTurn(context.Background(), firstCommand)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.RequestTurnCancel(context.Background(), core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: first.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.MarkTurnCanceledRequested(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}

	secondCommand := turnCommand()
	secondCommand.ConversationID = first.ConversationID
	secondCommand.Prompt = "继续完成"
	revision := uint64(1)
	secondCommand.ExpectedRevision = &revision
	second, err := h.store.StartTurn(context.Background(), secondCommand)
	if err != nil {
		t.Fatal(err)
	}
	createTestProfile(context.Background(), t, h.store.Store, second.ProfileID, "test", "integration-secret")
	lease, err := h.store.ClaimTurn(context.Background(), second.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response := core.ChatResponse{
		RequestID: second.RequestID, ConversationID: second.ConversationID, Revision: 2,
		Message:           core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "done", ModelProfileID: second.ProfileID, CreatedAt: time.Now().UTC()},
		ConversationTitle: "服务部署进度", ConversationTitleSource: first.Prompt,
	}
	if _, err = h.store.CommitTurn(context.Background(), lease, response); err != nil {
		t.Fatal(err)
	}
	conversation, err := h.store.LoadConversation(context.Background(), second.ConversationID)
	if err != nil || conversation.Title != "服务部署进度" {
		t.Fatalf("conversation=%+v err=%v", conversation, err)
	}
}

func TestCoreConversationContinuesWithNewProfileAfterOldProfileTombstonePostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()

	firstCommand := turnCommand()
	createTestProfile(ctx, t, h.store.Store, firstCommand.ProfileID, "old-model", "old-secret")
	first, err := h.store.StartTurn(ctx, firstCommand)
	if err != nil {
		t.Fatal(err)
	}
	firstLease, err := h.store.ClaimTurn(ctx, first.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.CommitTurn(ctx, firstLease, core.ChatResponse{
		RequestID: first.RequestID, ConversationID: first.ConversationID, Revision: 2,
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "old answer", ModelProfileID: first.ProfileID, CreatedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatal(err)
	}
	if deleted, deleteErr := h.store.Store.DeleteProfile(ctx, first.ProfileID, uuid.NewString(), strings.Repeat("a", 64), 1); deleteErr != nil || !deleted.Deleted {
		t.Fatalf("tombstone old profile=%#v err=%v", deleted, deleteErr)
	}

	secondCommand := turnCommand()
	secondCommand.ConversationID = first.ConversationID
	secondCommand.Prompt = "continue with the replacement model"
	expectedRevision := uint64(2)
	secondCommand.ExpectedRevision = &expectedRevision
	createTestProfile(ctx, t, h.store.Store, secondCommand.ProfileID, "new-model", "new-secret")
	second, err := h.store.StartTurn(ctx, secondCommand)
	if err != nil {
		t.Fatal(err)
	}
	secondLease, err := h.store.ClaimTurn(ctx, second.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.CommitTurn(ctx, secondLease, core.ChatResponse{
		RequestID: second.RequestID, ConversationID: second.ConversationID, Revision: 3,
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "new answer", ModelProfileID: second.ProfileID, CreatedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatal(err)
	}

	conversation, err := h.store.LoadConversation(ctx, first.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(conversation.Messages) != 4 {
		t.Fatalf("messages=%+v", conversation.Messages)
	}
	for i, wantProfileID := range []string{first.ProfileID, first.ProfileID, second.ProfileID, second.ProfileID} {
		if conversation.Messages[i].ModelProfileID != wantProfileID {
			t.Fatalf("message[%d].profile_id=%q want %q", i, conversation.Messages[i].ModelProfileID, wantProfileID)
		}
	}
}

func TestCoreConversationTurnSteerInvalidatesProviderLeaseAndCommitsGuidancePostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	turn, err := h.store.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	createTestProfile(context.Background(), t, h.store.Store, turn.ProfileID, "test", "integration-secret")
	staleLease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.PrepareTurnModel(context.Background(), staleLease); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	steer := core.TurnSteerCommand{
		RequestID: uuid.NewString(), TurnID: turn.ID,
		ExpectedRevision: turn.Revision, Instruction: "focus on the concise answer",
	}
	steered, applied, err := h.store.RequestTurnSteer(context.Background(), steer)
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("first steer was not applied")
	}
	if steered.ID != turn.ID || steered.State != core.TurnAccepted || steered.Revision != turn.Revision+1 || steered.LastSequence != turn.LastSequence+1 {
		t.Fatalf("steered turn=%+v", steered)
	}
	if steered.ModelDispatchCount != 1 || steered.ModelActiveDuration <= 0 || !steered.ModelDispatchStartedAt.IsZero() {
		t.Fatalf("steered model budget=%+v", steered)
	}
	if err = h.store.RecordTurnModelResult(context.Background(), staleLease, core.ModelRunResult{}); err != core.ErrConflict {
		t.Fatalf("stale provider result err=%v", err)
	}
	replayed, applied, err := h.store.RequestTurnSteer(context.Background(), steer)
	if err != nil || replayed.Revision != steered.Revision {
		t.Fatalf("steer replay=%+v err=%v", replayed, err)
	}
	if applied {
		t.Fatal("idempotent steer replay was applied twice")
	}
	changed := steer
	changed.Instruction = "different guidance"
	if _, _, err = h.store.RequestTurnSteer(context.Background(), changed); err != core.ErrConflict {
		t.Fatalf("changed steer replay err=%v", err)
	}
	steers, err := h.store.ListTurnSteers(context.Background(), turn.ID)
	if err != nil || len(steers) != 1 || steers[0].RequestID != steer.RequestID || steers[0].Instruction != steer.Instruction {
		t.Fatalf("steers=%+v err=%v", steers, err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response := core.ChatResponse{RequestID: cmd.RequestID, ConversationID: turn.ConversationID, Revision: 2, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "concise answer", ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC()}}
	if _, err = h.store.CommitTurn(context.Background(), lease, response); err != nil {
		t.Fatal(err)
	}
	conversation, err := h.store.LoadConversation(context.Background(), turn.ConversationID)
	if err != nil || len(conversation.Messages) != 3 {
		t.Fatalf("conversation=%+v err=%v", conversation, err)
	}
	if conversation.Messages[0].Content != cmd.Prompt || conversation.Messages[1].Content != steer.Instruction || conversation.Messages[2].Content != "concise answer" {
		t.Fatalf("same-turn transcript=%+v", conversation.Messages)
	}
}

func TestCoreConversationTurnDispatchRecoveryPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	turn, err := h.store.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := h.store.PrepareTurnModel(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ModelDispatchCount != 1 || prepared.ModelDispatchStartedAt.IsZero() || prepared.ModelActiveDuration != 0 {
		t.Fatalf("prepared model budget=%+v", prepared)
	}
	time.Sleep(2 * time.Millisecond)
	if err = h.store.MarkTurnModelUncertain(context.Background(), lease, "provider_uncertain", "unknown"); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.FailTurnUncertain(context.Background(), turn.ID, "provider_uncertain", "unknown"); err != nil {
		t.Fatal(err)
	}
	got, err := h.store.GetTurn(context.Background(), turn.ID)
	if err != nil || got.State != core.TurnFailed || got.ModelDispatchCount != 1 || got.ModelActiveDuration <= 0 || !got.ModelDispatchStartedAt.IsZero() {
		t.Fatalf("turn=%+v err=%v", got, err)
	}
}

func TestCoreConversationPhysicalModelAttemptsAreFencedAndDurablePostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	cmd := turnCommand()
	cmd.ProfileSnapshot.RequestDialect = coremodel.DialectOpenAICompatibleChatV1
	candidate, err := h.store.PrepareTurnRuntimeAdmission(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := core.NewTurnRuntimeSnapshot("frozen system prompt", cmd.ProfileSnapshot, nil, candidate.ExtensionSnapshotDigest, candidate.AttachmentSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.StartTurnWithRuntime(ctx, cmd, runtime)
	if err != nil {
		t.Fatal(err)
	}
	changedRuntime, err := core.NewTurnRuntimeSnapshot("changed system prompt", cmd.ProfileSnapshot, nil, candidate.ExtensionSnapshotDigest, candidate.AttachmentSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.StartTurnWithRuntime(ctx, cmd, changedRuntime); !errors.Is(err, core.ErrTurnRuntimeIncompatible) {
		t.Fatalf("changed admitted runtime replay err=%v", err)
	}
	lease, err := h.store.ClaimTurn(ctx, turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.store.ValidateTurnRuntime(ctx, lease, runtime); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.PrepareTurnModel(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err = h.store.BindTurnModelRuntime(ctx, lease, runtime); err != nil {
		t.Fatal(err)
	}
	renewed, err := h.store.RenewTurn(ctx, turn.ID, lease.LeaseID, lease.Epoch, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	failure := core.ModelAttemptFailure{Code: "provider_rate_limited", Summary: "rate limited", RateLimited: true, RetryAfterMS: 30_000}
	if err = h.store.MarkTurnModelRetryable(ctx, lease, failure); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("stale lease retryable err=%v", err)
	}
	if err = h.store.MarkTurnModelRetryable(ctx, renewed, failure); err != nil {
		t.Fatal(err)
	}
	prepared, err := h.store.PrepareTurnModelRetry(ctx, renewed)
	if err != nil || prepared.ModelDispatchCount != 2 {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if err = h.store.BindTurnModelRuntime(ctx, renewed, runtime); err != nil {
		t.Fatal(err)
	}
	if err = h.store.MarkTurnModelAttemptUncertain(ctx, renewed, core.ModelAttemptFailure{Code: "provider_uncertain", Summary: "unknown"}); err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, `SELECT attempt_sequence,state,rate_limited,retry_after_ms,runtime_snapshot_digest FROM core_conversation_model_attempts WHERE turn_id=$1 ORDER BY attempt_sequence`, turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type attempt struct {
		sequence    int
		state       string
		rateLimited bool
		retryAfter  int64
		digest      string
	}
	var attempts []attempt
	for rows.Next() {
		var value attempt
		if err = rows.Scan(&value.sequence, &value.state, &value.rateLimited, &value.retryAfter, &value.digest); err != nil {
			t.Fatal(err)
		}
		attempts = append(attempts, value)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || attempts[0].state != "retryable" || !attempts[0].rateLimited || attempts[0].retryAfter != 30_000 || attempts[1].state != "uncertain" || attempts[0].digest != runtime.Digest() || attempts[1].digest != runtime.Digest() {
		t.Fatalf("attempts=%+v", attempts)
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
	started, err := h.store.AppendTurnEvent(context.Background(), turn.ID, core.TurnEvent{Kind: core.TurnEventStarted})
	if err != nil || started.Sequence != 2 || started.Revision != turn.Revision {
		t.Fatalf("started event=%+v err=%v", started, err)
	}
	delta, err := h.store.AppendTurnEvent(context.Background(), turn.ID, core.TurnEvent{Kind: core.TurnEventDelta, Text: "visible progress"})
	if err != nil || delta.Sequence != 3 || delta.Revision != turn.Revision || delta.Text != "visible progress" {
		t.Fatalf("delta event=%+v err=%v", delta, err)
	}
	response := core.ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: 2, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "done", ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC()}, ConversationTitle: "Generated title"}
	if _, err = h.store.CommitTurn(context.Background(), lease, response); err != nil {
		t.Fatal(err)
	}
	conversation, err := h.store.LoadConversation(context.Background(), turn.ConversationID)
	if err != nil || conversation.Title != "Generated title" || len(conversation.Messages) != 2 {
		t.Fatalf("conversation=%+v err=%v", conversation, err)
	}
	if err := conversation.ValidateForPersistence(); err != nil {
		t.Fatalf("persisted turn conversation is invalid: %v", err)
	}
	if conversation.Messages[0].TurnID != turn.ID || conversation.Messages[1].TurnID != turn.ID {
		t.Fatalf("persisted transcript lost turn identity: %+v", conversation.Messages)
	}
	userAt, assistantAt := conversation.Messages[0].CreatedAt, conversation.Messages[1].CreatedAt
	if userAt.Location() != time.UTC || assistantAt.Location() != time.UTC || userAt.Nanosecond()%int(time.Microsecond) != 0 || assistantAt.Nanosecond()%int(time.Microsecond) != 0 || assistantAt.Sub(userAt) != time.Microsecond {
		t.Fatalf("turn timestamps are not persistably ordered: user=%s assistant=%s", userAt.Format(time.RFC3339Nano), assistantAt.Format(time.RFC3339Nano))
	}
	events, err := h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 10)
	if err != nil || len(events) != 4 || events[0].Sequence != 1 || events[0].Revision != 1 ||
		events[1].Sequence != 2 || events[1].Revision != 1 || events[1].Kind != core.TurnEventStarted ||
		events[2].Sequence != 3 || events[2].Revision != 1 || events[2].Kind != core.TurnEventDelta || events[2].Text != "visible progress" ||
		events[3].Sequence != 4 || events[3].Revision != 2 || events[3].Kind != core.TurnEventDone {
		t.Fatalf("delayed replay events=%+v err=%v", events, err)
	}
}

func TestCoreConversationFailedTurnPersistsPartialTranscriptOncePostgres(t *testing.T) {
	for _, test := range []struct {
		name                 string
		userAlreadyCommitted bool
		deltas               []string
		wantContent          string
	}{
		{name: "new user with partial output", deltas: []string{"partial one", "partial two"}, wantContent: "partial onepartial two\n\nError (intrinsic_failed): Core intrinsic operation failed"},
		{name: "precommitted user without partial output", userAlreadyCommitted: true, wantContent: "Error (intrinsic_failed): Core intrinsic operation failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := openTurnDB(t)
			turn, err := h.store.StartTurn(context.Background(), turnCommand())
			if err != nil {
				t.Fatal(err)
			}
			createTestProfile(context.Background(), t, h.store.Store, turn.ProfileID, "test", "integration-secret")
			initialRevision := uint64(1)
			if test.userAlreadyCommitted {
				message := core.Message{ID: core.TurnUserMessageID(turn.RequestID), Role: core.RoleUser, Content: turn.Prompt,
					ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)}
				tx, txErr := h.pool.Begin(context.Background())
				if txErr != nil {
					t.Fatal(txErr)
				}
				defer tx.Rollback(context.Background())
				if err = insertCloudWorkerMessageTx(context.Background(), tx, turn.ConversationID, 1, message); err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(context.Background(), `UPDATE core_conversations SET revision=revision+1 WHERE conversation_id=$1`, turn.ConversationID); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(context.Background()); err != nil {
					t.Fatal(err)
				}
				initialRevision++
			}
			lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.store.AppendTurnEvent(context.Background(), turn.ID, core.TurnEvent{Kind: core.TurnEventStarted}); err != nil {
				t.Fatal(err)
			}
			for _, text := range test.deltas {
				if _, err = h.store.AppendTurnEvent(context.Background(), turn.ID, core.TurnEvent{Kind: core.TurnEventDelta, Text: text}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = h.store.FailTurn(context.Background(), lease, "intrinsic_failed", "Core intrinsic operation failed"); err != nil {
				t.Fatal(err)
			}

			conversation, err := h.store.LoadConversation(context.Background(), turn.ConversationID)
			if err != nil || conversation.Revision != initialRevision+1 || len(conversation.Messages) != 2 {
				t.Fatalf("conversation=%+v err=%v", conversation, err)
			}
			if conversation.Messages[0].ID != core.TurnUserMessageID(turn.RequestID) || conversation.Messages[0].Content != turn.Prompt {
				t.Fatalf("failed user transcript=%+v", conversation.Messages[0])
			}
			if conversation.Messages[0].TurnID != turn.ID || conversation.Messages[1].TurnID != turn.ID {
				t.Fatalf("failed transcript lost turn identity: %+v", conversation.Messages)
			}
			assistant := conversation.Messages[1]
			if assistant.Status != "failed" || assistant.Role != core.RoleAssistant ||
				assistant.Content != test.wantContent {
				t.Fatalf("failed assistant transcript=%+v", assistant)
			}
			if _, err = h.store.FailTurn(context.Background(), lease, "intrinsic_failed", "Core intrinsic operation failed"); !errors.Is(err, core.ErrConflict) {
				t.Fatalf("failed turn replay err=%v", err)
			}
			replayed, err := h.store.LoadConversation(context.Background(), turn.ConversationID)
			if err != nil || replayed.Revision != conversation.Revision || len(replayed.Messages) != 2 {
				t.Fatalf("replayed conversation=%+v err=%v", replayed, err)
			}
		})
	}
}

func TestCoreConversationTurnEventsRejectZeroRevisionPayloadPostgres(t *testing.T) {
	h := openTurnDB(t)
	turn, err := h.store.StartTurn(context.Background(), turnCommand())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `UPDATE core_conversation_turn_events
		SET payload_json=jsonb_set(payload_json,'{Revision}','0'::jsonb) WHERE turn_id=$1 AND sequence=1`, turn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 10); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("zero-revision event payload err=%v", err)
	}
}

type conversationToolPrepareFixture struct {
	h         *turnDBHarness
	snapshot  core.ExtensionExecutionSnapshot
	turn      core.Turn
	lease     core.TurnLease
	arguments []byte
	call      core.ToolCall
	prepare   core.PrepareToolCommand
}

func newConversationToolPrepareFixture(t *testing.T, callID string) *conversationToolPrepareFixture {
	return newConversationToolPrepareFixtureForTool(t, callID, "write_html")
}

func newConversationToolPrepareFixtureForTool(t *testing.T, callID, toolName string) *conversationToolPrepareFixture {
	t.Helper()
	h := openTurnDB(t)
	installationID, versionID := uuid.NewString(), uuid.NewString()
	contentDigest := strings.Repeat("a", 64)
	artifactDigest := strings.Repeat("b", 64)
	versionRaw, err := json.Marshal(coreextension.VersionRecord{
		VersionID: versionID, ContentDigest: contentDigest, ArtifactDigest: artifactDigest,
		Execution: coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "entry", Digest: artifactDigest, Argv: []string{"entry"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err = h.pool.Exec(context.Background(), `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,active_version_id,network_grants_json,secret_grants_json,created_at,updated_at) VALUES($1,'{}'::jsonb,'mcp','github','fixture','fixture','', 'stdio_static',4,'installed',true,$2,'[]'::jsonb,'[]'::jsonb,$3,$3)`, installationID, versionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, installationID, versionRaw, now); err != nil {
		t.Fatal(err)
	}
	snapshot := core.ExtensionExecutionSnapshot{
		Selection: core.ExtensionSelection{
			Kind: core.ExtensionMCP, ID: installationID, Version: versionID,
			Digest: contentDigest, AllowedTools: []string{toolName},
		},
		InstallationID: installationID, VersionID: versionID, InstallationRevision: 4,
		Source: "github", ContentDigest: contentDigest, ArtifactDigest: artifactDigest,
		ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64),
		SecretBindingDigest: strings.Repeat("e", 64), ToolNames: []string{toolName}, RequiresConfirmation: true,
	}
	cmd := turnCommand()
	cmd.OwnerID = "@conversation-tool:test"
	cmd.AccountGeneration = 1
	cmd.Extensions = []core.ExtensionSelection{snapshot.Selection}
	cmd.ExtensionSnapshots = []core.ExtensionExecutionSnapshot{snapshot}
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	candidate, err := h.store.PrepareTurnRuntimeAdmission(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := core.NewTurnRuntimeSnapshot("fixture system prompt", cmd.ProfileSnapshot, nil, candidate.ExtensionSnapshotDigest, candidate.AttachmentSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.StartTurnWithRuntime(context.Background(), cmd, runtime)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	arguments, err := json.Marshal(map[string]any{"content": "<h1>Hello from Dirextalk</h1>"})
	if err != nil {
		t.Fatal(err)
	}
	call := core.ToolCall{ID: callID, Name: toolName, Arguments: string(arguments)}
	prepare := core.PrepareToolCommand{
		Lease: lease, Round: 0, Call: call, Snapshot: snapshot,
		CanonicalArguments: arguments, ArgumentsDigest: conversationArgsDigest(arguments),
		SafeSummary: "conversation tool call " + toolName, IdempotencyKey: uuid.NewString(),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	return &conversationToolPrepareFixture{
		h: h, snapshot: snapshot, turn: turn, lease: lease,
		arguments: arguments, call: call, prepare: prepare,
	}
}

func TestCoreConversationToolPrepareWaitingEventFailureRollsBackPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, "call_waiting_event_rollback")
	if _, err := fixture.h.pool.Exec(context.Background(), `CREATE FUNCTION reject_conversation_tool_waiting_event() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced waiting event failure'; END $$;
		CREATE TRIGGER reject_conversation_tool_waiting_event BEFORE INSERT ON core_conversation_turn_events
		FOR EACH ROW WHEN (NEW.kind = 'waiting_confirmation') EXECUTE FUNCTION reject_conversation_tool_waiting_event()`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.h.store.PrepareConversationTool(context.Background(), fixture.prepare); err == nil {
		t.Fatal("forced waiting event failure unexpectedly committed preparation")
	}

	var state, leaseID string
	var revision uint64
	var lastSequence int64
	var tasks, attempts, confirmations, targetBindings, currentBindings, taskEvents, waitingEvents int
	if err := fixture.h.pool.QueryRow(context.Background(), `SELECT state,revision,last_sequence,lease_id::text,
		(SELECT count(*) FROM core_tasks WHERE task_kind='conversation_tool'),
		(SELECT count(*) FROM core_conversation_tool_attempts),
		(SELECT count(*) FROM core_confirmations WHERE operation_domain='conversation_tool'),
		(SELECT count(*) FROM core_confirmation_target_bindings),
		(SELECT count(*) FROM core_confirmation_current_bindings WHERE operation_domain='conversation_tool'),
		(SELECT count(*) FROM core_task_events),
		(SELECT count(*) FROM core_conversation_turn_events WHERE kind='waiting_confirmation')
		FROM core_conversation_turns WHERE turn_id=$1`, fixture.turn.ID).Scan(
		&state, &revision, &lastSequence, &leaseID, &tasks, &attempts, &confirmations,
		&targetBindings, &currentBindings, &taskEvents, &waitingEvents); err != nil {
		t.Fatal(err)
	}
	if state != string(core.TurnRunning) || revision != fixture.turn.Revision || lastSequence != fixture.turn.LastSequence ||
		leaseID != fixture.lease.LeaseID || tasks+attempts+confirmations+targetBindings+currentBindings+taskEvents+waitingEvents != 0 {
		t.Fatalf("prepare rollback state=%s revision=%d sequence=%d lease=%q rows=%d/%d/%d/%d/%d/%d/%d",
			state, revision, lastSequence, leaseID, tasks, attempts, confirmations, targetBindings, currentBindings, taskEvents, waitingEvents)
	}
}

func TestCoreConversationToolCurrentStatesRejectPreparedAndTerminalizeFailsClosedPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, "call_current_tool_states")
	attempt, task, confirmation, err := fixture.h.store.PrepareConversationTool(context.Background(), fixture.prepare)
	if err != nil {
		t.Fatal(err)
	}
	if task.Spec.Payload.ConversationTool == nil || task.Spec.Payload.ConversationTool.ExecutionTarget != coretask.ExtensionExecutionTargetLocalSandbox {
		t.Fatalf("sealed conversation tool target=%+v", task.Spec.Payload.ConversationTool)
	}
	if _, err = fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_tool_attempts SET state='prepared' WHERE attempt_id=$1`, attempt.ID); err == nil {
		t.Fatal("current schema accepted removed conversation tool prepared state")
	}
	if _, err = fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET dispatch_state='prepared' WHERE turn_id=$1`, fixture.turn.ID); err == nil {
		t.Fatal("current schema accepted removed conversation turn prepared dispatch state")
	}
	if _, err = fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_tool_attempts SET state='dispatched' WHERE attempt_id=$1`, attempt.ID); err != nil {
		t.Fatal(err)
	}
	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(fixture.h.store.Store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Reject(context.Background(), coreconfirmation.RejectCommand{
		ConfirmationID:   confirmation.ConfirmationID,
		IdempotencyKey:   uuid.NewString(),
		ExpectedRevision: confirmation.Revision,
		Reason:           "owner rejected",
		At:               time.Now().UTC(),
	}); !errors.Is(err, coreconfirmation.ErrConflict) {
		t.Fatalf("mismatched attempt terminalization err=%v", err)
	}
	var attemptState, taskState, confirmationState, turnState string
	if err = fixture.h.pool.QueryRow(context.Background(), `SELECT a.state,t.status,c.state,ct.state
		FROM core_conversation_tool_attempts a
		JOIN core_tasks t ON t.task_id=a.task_id
		JOIN core_confirmations c ON c.confirmation_id=a.confirmation_id
		JOIN core_conversation_turns ct ON ct.turn_id=a.turn_id
		WHERE a.attempt_id=$1 AND t.task_id=$2`, attempt.ID, task.ID).Scan(
		&attemptState, &taskState, &confirmationState, &turnState); err != nil {
		t.Fatal(err)
	}
	if attemptState != "dispatched" || taskState != "waiting_user" || confirmationState != "pending" || turnState != "waiting_confirmation" {
		t.Fatalf("failed-close rollback attempt/task/confirmation/turn=%q/%q/%q/%q",
			attemptState, taskState, confirmationState, turnState)
	}
}

func TestCoreConversationToolFailedResourceSummarySurvivesRestartPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, "call_resource_summary_restart")
	attempt, task, confirmation, err := fixture.h.store.PrepareConversationTool(context.Background(), fixture.prepare)
	if err != nil {
		t.Fatal(err)
	}
	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(fixture.h.store.Store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(context.Background(), coreconfirmation.ConfirmCommand{
		ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: confirmation.Revision, At: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(fixture.h.store.Store)
	claimed, _, err := tasks.ClaimNextDue(context.Background(), "resource-summary-test", time.Now().UTC(), time.Minute, 2)
	if err != nil || claimed.ID != task.ID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err = fixture.h.store.BeginConversationTool(context.Background(), claimed); err != nil {
		t.Fatal(err)
	}
	if err = fixture.h.store.FinishConversationTool(
		context.Background(), claimed, "failed", nil,
		execution.LocalResourceBusyCode, execution.LocalResourceBusySummary,
	); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewCoreConversationStore(fixture.h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := restarted.ObserveConversationTool(context.Background(), fixture.turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	var recovered coretask.Result
	if observed.ID != attempt.ID || observed.State != "denied" || json.Unmarshal(observed.Result, &recovered) != nil ||
		recovered.Validate() != nil || recovered.Summary != execution.LocalResourceBusySummary ||
		strings.Contains(string(observed.Result), "protected detail") {
		t.Fatalf("restarted attempt=%+v recovered=%+v", observed, recovered)
	}
	terminal, err := tasks.GetTask(context.Background(), task.ID)
	if err != nil || terminal.Status != coretask.StatusFailed || terminal.FailureCode != execution.LocalResourceBusyCode ||
		terminal.FailureSummary != execution.LocalResourceBusySummary || terminal.Result != nil {
		t.Fatalf("terminal task=%+v err=%v", terminal, err)
	}
}

func TestCoreConversationToolPrepareCreatesAtomicTaskAndConfirmationPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, "call_deepseek_non_uuid_1")
	h, snapshot, turn, lease := fixture.h, fixture.snapshot, fixture.turn, fixture.lease
	arguments, call, prepare := fixture.arguments, fixture.call, fixture.prepare
	var err error
	attempt, task, confirmation, err := h.store.PrepareConversationTool(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != "waiting_confirmation" || attempt.CallID != call.ID || attempt.TaskID != task.ID || attempt.ConfirmationID != confirmation.ConfirmationID || task.Spec.Kind != "conversation_tool" || confirmation.State != "pending" {
		t.Fatalf("attempt=%+v task=%+v confirmation=%+v", attempt, task, confirmation)
	}
	var storedSummary, storedState, storedCallID, payloadCallID string
	var createdAt, updatedAt time.Time
	if err = h.pool.QueryRow(context.Background(), `SELECT a.safe_summary,a.state,a.call_id::text,t.payload_json#>>'{conversation_tool,call_id}',a.created_at,a.updated_at FROM core_conversation_tool_attempts a JOIN core_tasks t ON t.task_id=a.task_id WHERE a.attempt_id=$1`, attempt.ID).Scan(&storedSummary, &storedState, &storedCallID, &payloadCallID, &createdAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	if storedSummary != "conversation tool call write_html" || storedState != "waiting_confirmation" || storedCallID != attempt.ID || payloadCallID != call.ID || createdAt.IsZero() || !createdAt.Equal(updatedAt) {
		t.Fatalf("summary=%q state=%q stored_call_id=%q payload_call_id=%q created_at=%s updated_at=%s", storedSummary, storedState, storedCallID, payloadCallID, createdAt, updatedAt)
	}
	observed, err := h.store.ObserveConversationTool(context.Background(), turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ID != attempt.ID || observed.CallID != call.ID {
		t.Fatalf("observed attempt=%+v", observed)
	}
	storedTurn, err := h.store.GetTurn(context.Background(), turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedTurn.State != core.TurnWaitingConfirmation || storedTurn.Revision != lease.Turn.Revision+1 {
		t.Fatalf("turn=%+v", storedTurn)
	}
	preparedEvents, err := h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 10)
	if err != nil || len(preparedEvents) != 2 || preparedEvents[0].Kind != core.TurnEventAccepted ||
		preparedEvents[0].Sequence != 1 || preparedEvents[0].Revision != turn.Revision ||
		preparedEvents[1].Kind != core.TurnEventWaitingConfirmation || preparedEvents[1].Sequence != 2 ||
		preparedEvents[1].Revision != storedTurn.Revision || preparedEvents[1].ConfirmationID != attempt.ConfirmationID ||
		preparedEvents[1].ExecutionID != attempt.ExecutionID || preparedEvents[1].ValidateWaitingConfirmationAuthority() != nil {
		t.Fatalf("atomic prepare events=%+v err=%v", preparedEvents, err)
	}
	originalWaitingRevision := preparedEvents[1].Revision
	var leaseReleased bool
	if err = h.pool.QueryRow(context.Background(), `SELECT lease_id IS NULL AND lease_expires_at IS NULL FROM core_conversation_turns WHERE turn_id=$1`, turn.ID).Scan(&leaseReleased); err != nil {
		t.Fatal(err)
	}
	if !leaseReleased {
		t.Fatal("waiting confirmation retained its running lease")
	}
	restarted, err := NewCoreConversationStore(h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	replayedAttempt, replayedTask, replayedConfirmation, err := restarted.PrepareConversationTool(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	if replayedAttempt.ID != attempt.ID || replayedAttempt.CallID != call.ID || replayedTask.ID != task.ID || replayedTask.Spec.ConversationID != turn.ConversationID || replayedConfirmation.ConfirmationID != confirmation.ConfirmationID {
		t.Fatalf("replayed attempt=%+v task=%+v confirmation=%+v", replayedAttempt, replayedTask, replayedConfirmation)
	}
	replayedEvents, err := restarted.LoadTurnEvents(context.Background(), turn.ID, 0, 10)
	if err != nil || len(replayedEvents) != 2 || replayedEvents[1].Kind != core.TurnEventWaitingConfirmation ||
		replayedEvents[1].Revision != originalWaitingRevision || replayedEvents[1].Sequence != preparedEvents[1].Sequence {
		t.Fatalf("restart replay duplicated or rewrote waiting event: before=%+v after=%+v err=%v", preparedEvents, replayedEvents, err)
	}
	var taskCount, attemptCount, confirmationCount int
	if err = h.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM core_tasks WHERE task_id=$1),(SELECT count(*) FROM core_conversation_tool_attempts WHERE attempt_id=$2),(SELECT count(*) FROM core_confirmations WHERE confirmation_id=$3)`, task.ID, attempt.ID, confirmation.ConfirmationID).Scan(&taskCount, &attemptCount, &confirmationCount); err != nil {
		t.Fatal(err)
	}
	if taskCount != 1 || attemptCount != 1 || confirmationCount != 1 {
		t.Fatalf("replay duplicated rows: task=%d attempt=%d confirmation=%d", taskCount, attemptCount, confirmationCount)
	}

	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(h.store.Store))
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := confirmationService.Confirm(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmation.Revision, At: time.Now().UTC()})
	if err != nil || confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("confirmed=%+v err=%v", confirmed, err)
	}
	tasks := NewCoreTaskStore(h.store.Store)
	claimed, _, err := tasks.ClaimNextDue(context.Background(), "conversation-tool-test", time.Now().UTC(), time.Minute, 2)
	if err != nil || claimed.ID != task.ID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err = tasks.CancelTask(context.Background(), coretask.CancelCommand{TaskID: claimed.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64), ExpectedRevision: claimed.Revision}, At: time.Now().UTC()}); !errors.Is(err, coretask.ErrDispatchStarted) {
		t.Fatalf("running conversation tool cancel err=%v", err)
	}
	if err = h.store.FinishConversationTool(context.Background(), claimed, "uncertain", nil, "tool_uncertain", "tool dispatch outcome is unknown"); !errors.Is(err, coretask.ErrLeaseConflict) {
		t.Fatalf("pre-dispatch finish err=%v", err)
	}
	unchanged, err := tasks.GetTask(context.Background(), claimed.ID)
	if err != nil || unchanged.Status != coretask.StatusRunning || unchanged.Revision != claimed.Revision {
		t.Fatalf("pre-dispatch finish mutated task=%+v err=%v", unchanged, err)
	}
	var unchangedAttempt, unchangedConfirmation string
	if err = h.pool.QueryRow(context.Background(), `SELECT a.state,c.state FROM core_conversation_tool_attempts a JOIN core_confirmations c ON c.confirmation_id=a.confirmation_id WHERE a.attempt_id=$1`, attempt.ID).Scan(&unchangedAttempt, &unchangedConfirmation); err != nil || unchangedAttempt != "waiting_confirmation" || unchangedConfirmation != "confirmed" {
		t.Fatalf("pre-dispatch state attempt=%q confirmation=%q err=%v", unchangedAttempt, unchangedConfirmation, err)
	}
	if _, err = h.store.BeginConversationTool(context.Background(), claimed); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewValidatedPostgresExtensionExecutionCoordinator(h.store.Store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := coordinator.ResolveConversationInvocation(context.Background(), claimed)
	if err != nil || invocation.Local == nil {
		t.Fatalf("invocation=%+v err=%v", invocation, err)
	}
	if string(invocation.Local.Input) != string(arguments) || conversationArgsDigest(invocation.Local.Input) != prepare.ArgumentsDigest {
		t.Fatalf("non-canonical stored input digest=%s want=%s", conversationArgsDigest(invocation.Local.Input), prepare.ArgumentsDigest)
	}
	if _, err = h.pool.Exec(context.Background(), `UPDATE core_conversation_tool_attempts SET arguments_json='{"content":"tampered"}'::jsonb WHERE attempt_id=$1`, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.ResolveConversationInvocation(context.Background(), claimed); !errors.Is(err, coretask.ErrConflict) {
		t.Fatalf("tampered stored arguments err=%v", err)
	}
	if _, err = h.pool.Exec(context.Background(), `UPDATE core_conversation_tool_attempts SET arguments_json=$2 WHERE attempt_id=$1`, attempt.ID, arguments); err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `UPDATE core_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, _, err := tasks.ClaimNextDue(context.Background(), "conversation-tool-recovery", time.Now().UTC(), time.Minute, 2)
	if err != nil || reclaimed.ID != task.ID || reclaimed.LeaseEpoch <= claimed.LeaseEpoch {
		t.Fatalf("reclaimed=%+v err=%v", reclaimed, err)
	}
	if _, err = h.store.BeginConversationTool(context.Background(), reclaimed); !errors.Is(err, core.ErrToolDispatchStarted) {
		t.Fatalf("reclaimed begin err=%v", err)
	}
	if err = h.store.FinishConversationTool(context.Background(), reclaimed, "uncertain", nil, "tool_uncertain", "tool dispatch outcome is unknown"); err != nil {
		t.Fatal(err)
	}
	terminal, err := tasks.GetTask(context.Background(), task.ID)
	if err != nil || terminal.Status != coretask.StatusFailed || terminal.FailureCode != "tool_uncertain" {
		t.Fatalf("terminal=%+v err=%v", terminal, err)
	}
	var terminalAttempt string
	if err = h.pool.QueryRow(context.Background(), `SELECT state FROM core_conversation_tool_attempts WHERE attempt_id=$1`, attempt.ID).Scan(&terminalAttempt); err != nil || terminalAttempt != "uncertain" {
		t.Fatalf("attempt_state=%q err=%v", terminalAttempt, err)
	}
	terminalTurn, err := h.store.GetTurn(context.Background(), turn.ID)
	if err != nil || terminalTurn.State != core.TurnFailed || terminalTurn.TerminalCode != "tool_uncertain" || terminalTurn.TerminalSummary != "tool dispatch outcome is unknown" {
		t.Fatalf("terminal_turn=%+v err=%v", terminalTurn, err)
	}
	events, err := h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 100)
	if err != nil || len(events) == 0 || events[len(events)-1].Kind != core.TurnEventError || events[len(events)-1].ErrorCode != "tool_uncertain" {
		t.Fatalf("terminal events=%+v err=%v", events, err)
	}

	cancelCmd := turnCommand()
	cancelCmd.Extensions = []core.ExtensionSelection{snapshot.Selection}
	cancelCmd.ExtensionSnapshots = []core.ExtensionExecutionSnapshot{snapshot}
	cancelTurn, err := h.store.StartTurn(context.Background(), cancelCmd)
	if err != nil {
		t.Fatal(err)
	}
	cancelLease, err := h.store.ClaimTurn(context.Background(), cancelTurn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cancelCall := core.ToolCall{ID: "call_deepseek_cancel_non_uuid_1", Name: "write_html", Arguments: string(arguments)}
	cancelAttempt, cancelTask, cancelConfirmation, err := h.store.PrepareConversationTool(context.Background(), core.PrepareToolCommand{
		Lease: cancelLease, Round: 101, Call: cancelCall, Snapshot: snapshot,
		CanonicalArguments: arguments, ArgumentsDigest: conversationArgsDigest(arguments),
		SafeSummary: "conversation tool call write_html", IdempotencyKey: uuid.NewString(),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	waitingTurn, err := h.store.GetTurn(context.Background(), cancelTurn.ID)
	if err != nil || waitingTurn.State != core.TurnWaitingConfirmation {
		t.Fatalf("waiting cancel turn=%+v err=%v", waitingTurn, err)
	}
	canceledTurn, err := h.store.RequestTurnCancel(context.Background(), core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: waitingTurn.ID})
	if err != nil || canceledTurn.State != core.TurnCanceled || canceledTurn.Revision != waitingTurn.Revision+1 {
		t.Fatalf("canceled turn=%+v err=%v", canceledTurn, err)
	}
	var canceledTaskState, canceledAttemptState, canceledConfirmationState string
	if err = h.pool.QueryRow(context.Background(), `SELECT t.status,a.state,c.state FROM core_tasks t JOIN core_conversation_tool_attempts a ON a.task_id=t.task_id JOIN core_confirmations c ON c.confirmation_id=a.confirmation_id WHERE t.task_id=$1 AND a.attempt_id=$2 AND c.confirmation_id=$3`, cancelTask.ID, cancelAttempt.ID, cancelConfirmation.ConfirmationID).Scan(&canceledTaskState, &canceledAttemptState, &canceledConfirmationState); err != nil {
		t.Fatal(err)
	}
	if canceledTaskState != "canceled" || canceledAttemptState != "canceled" || canceledConfirmationState != "expired" {
		t.Fatalf("canceled tool state task=%q attempt=%q confirmation=%q", canceledTaskState, canceledAttemptState, canceledConfirmationState)
	}
	cancelEvents, err := h.store.LoadTurnEvents(context.Background(), cancelTurn.ID, 0, 100)
	if err != nil || len(cancelEvents) == 0 || cancelEvents[len(cancelEvents)-1].Kind != core.TurnEventCanceled {
		t.Fatalf("cancel events=%+v err=%v", cancelEvents, err)
	}
}

func TestCoreConversationToolServerOwnedSandboxQueuesWithoutConfirmationPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, "call_local_sandbox_no_confirmation")
	fixture.snapshot.RequiresConfirmation = false
	fixture.prepare.Snapshot = fixture.snapshot
	snapshots, err := json.Marshal([]core.ExtensionExecutionSnapshot{fixture.snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET extension_snapshot_json=$2 WHERE turn_id=$1`, fixture.turn.ID, snapshots); err != nil {
		t.Fatal(err)
	}
	attempt, task, confirmation, err := fixture.h.store.PrepareConversationTool(context.Background(), fixture.prepare)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != coretask.StatusQueued || task.Spec.Payload.ConversationTool == nil || task.Spec.Payload.ConversationTool.ConfirmationID != "" || attempt.ConfirmationID != "" || confirmation.ConfirmationID != "" {
		t.Fatalf("attempt=%+v task=%+v confirmation=%+v", attempt, task, confirmation)
	}
	events, err := fixture.h.store.LoadTurnEvents(context.Background(), fixture.turn.ID, 0, 10)
	if err != nil || len(events) != 1 || events[0].Kind != core.TurnEventAccepted {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	claimed, _, err := NewCoreTaskStore(fixture.h.store.Store).ClaimNextDue(context.Background(), "local-sandbox-test", time.Now().UTC(), time.Minute, 4)
	if err != nil || claimed.ID != task.ID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err = fixture.h.store.BeginConversationTool(context.Background(), claimed); err != nil {
		t.Fatal(err)
	}
	coordinator := NewPostgresExtensionExecutionCoordinator(fixture.h.store.Store)
	coordinator.WorkspaceRoot = t.TempDir()
	invocation, err := coordinator.ResolveConversationInvocation(context.Background(), claimed)
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Local == nil || invocation.Local.Timeout != execution.LocalSandboxWallTimeout {
		t.Fatalf("local conversation timeout=%v want=%v", invocation.Local, execution.LocalSandboxWallTimeout)
	}
}
