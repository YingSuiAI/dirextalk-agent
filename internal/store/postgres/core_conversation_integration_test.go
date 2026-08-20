package postgres

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationModelClient struct{}

func (integrationModelClient) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: "ok"}}, nil
}
func (integrationModelClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return integrationModelStream{}, nil
}

type integrationModelStream struct{}

func (integrationModelStream) Recv() (coremodel.Delta, error) { return coremodel.Delta{}, io.EOF }
func (integrationModelStream) Close() error                   { return nil }

type integrationConversationRunner struct{}

func (integrationConversationRunner) Run(_ context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	createdAt := request.Conversation.Messages[len(request.Conversation.Messages)-1].CreatedAt.Add(time.Nanosecond)
	return core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "ok", ReasoningContent: "integration reasoning", CreatedAt: createdAt}}, nil
}

func (runner integrationConversationRunner) Stream(ctx context.Context, request core.ModelRunRequest, emit func(core.ModelDelta) error) (core.ModelRunResult, error) {
	result, err := runner.Run(ctx, request)
	if err == nil && emit != nil {
		err = emit(core.ModelDelta{Text: result.Message.Content, ReasoningContent: result.Message.ReasoningContent})
	}
	return result, err
}

type integrationSnapshotResolver struct{ snapshot coremodel.ExecutionSnapshot }

func (r integrationSnapshotResolver) ResolveProfileSnapshot(context.Context, string) (coremodel.ExecutionSnapshot, error) {
	return r.snapshot, nil
}

func TestCoreConversationPostgresIntegrationOptIn(t *testing.T) {
	dsn := os.Getenv("AGENT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for PG18 integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, e := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if e != nil {
		t.Fatal(e)
	}
	adminPool, e := pgxpool.NewWithConfig(ctx, adminConfig)
	if e != nil {
		t.Fatal(e)
	}
	schema := "dtx_agent_conversation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, e = adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); e != nil {
		adminPool.Close()
		t.Fatal(e)
	}
	config, e := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if e != nil {
		adminPool.Close()
		t.Fatal(e)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-core-conversation-integration"
	pool, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE")
		adminPool.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		adminPool.Close()
	})
	sid := uuid.NewString()
	if e = ApplyMigrations(ctx, pool, sid); e != nil {
		t.Fatal(e)
	}
	keyring, e := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x5a}, secretbox.MasterKeySize))
	if e != nil {
		t.Fatal(e)
	}
	s, e := New(pool, sid, keyring)
	if e != nil {
		t.Fatal(e)
	}
	cs, e := NewCoreConversationStore(s)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	c := core.Conversation{ID: uuid.NewString(), Title: "integration", Revision: 1, CreatedAt: now, UpdatedAt: now}
	key := uuid.NewString()
	cmd := core.CreateConversationCommand{RequestID: key, Conversation: c, Fingerprint: digestConversationPG(c)}
	first, e := cs.CreateConversationMutation(ctx, cmd)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := cs.CreateConversationMutation(ctx, cmd)
	if e != nil || replay.Conversation.ID != first.Conversation.ID {
		t.Fatalf("replay=%+v err=%v", replay, e)
	}
	changed := c
	changed.Title = "changed"
	cmd.Conversation = changed
	cmd.Fingerprint = digestConversationPG(changed)
	if _, e = cs.CreateConversationMutation(ctx, cmd); !errors.Is(e, core.ErrConflict) {
		t.Fatalf("digest conflict=%v", e)
	}
	loadedInitial, e := cs.LoadConversation(ctx, c.ID)
	if e != nil || loadedInitial.Title != c.Title {
		t.Fatalf("title persistence=%+v err=%v", loadedInitial, e)
	}
	if loadedInitial.CreatedAt.Location() != time.UTC || loadedInitial.UpdatedAt.Location() != time.UTC || loadedInitial.ValidateForPersistence() != nil {
		t.Fatalf("loaded conversation timestamps were not normalized to UTC: created=%v updated=%v", loadedInitial.CreatedAt.Location(), loadedInitial.UpdatedAt.Location())
	}
	mutationConversation := core.Conversation{ID: uuid.NewString(), Title: "mutation timestamps", Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, e = cs.CreateConversationMutation(ctx, core.CreateConversationCommand{RequestID: uuid.NewString(), Conversation: mutationConversation, Fingerprint: digestConversationPG(mutationConversation)}); e != nil {
		t.Fatal(e)
	}
	renamed, e := cs.RenameConversationMutation(ctx, mutationConversation.ID, "renamed", 1, uuid.NewString())
	if e != nil || renamed.Conversation.CreatedAt.Location() != time.UTC || renamed.Conversation.UpdatedAt.Location() != time.UTC {
		t.Fatalf("rename response timestamps were not normalized to UTC: response=%+v err=%v", renamed, e)
	}
	deleted, e := cs.DeleteConversationMutation(ctx, core.DeleteConversationCommand{RequestID: uuid.NewString(), ConversationID: mutationConversation.ID, ExpectedRevision: 2, Fingerprint: digestDeletePG(mutationConversation.ID, 2)})
	if e != nil || deleted.Conversation.CreatedAt.Location() != time.UTC || deleted.Conversation.UpdatedAt.Location() != time.UTC || deleted.Conversation.DeletedAt == nil || deleted.Conversation.DeletedAt.Location() != time.UTC {
		t.Fatalf("delete response timestamps were not normalized to UTC: response=%+v err=%v", deleted, e)
	}
	rid := uuid.NewString()
	lease, e := cs.ClaimChat(ctx, rid, c.ID, sha256hexPG([]byte("chat")), uuid.NewString(), nil, now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = cs.ReleaseChat(ctx, rid, lease.LeaseID, lease.Epoch); e != nil {
		t.Fatalf("release chat lease: %v", e)
	}
	lease, e = cs.ClaimChat(ctx, rid, c.ID, sha256hexPG([]byte("chat")), lease.ProfileID, nil, now, time.Minute)
	if e != nil || lease.Status != core.ClaimReclaimed || lease.Epoch <= 1 {
		t.Fatalf("released lease was not reclaimable: lease=%+v err=%v", lease, e)
	}
	profileID := lease.ProfileID
	nowProfile := time.Now().UTC().Truncate(time.Microsecond)
	temperatureProfile, topPProfile := 0.25, 0.75
	if _, e = s.CreateProfile(ctx, coremodel.Profile{ID: profileID, DisplayName: "snapshot", Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.invalid/v1", Model: "original-model", SystemPrompt: "original prompt", APIKey: "original-secret", Temperature: &temperatureProfile, TopP: &topPProfile, MaxOutputTokens: 321, ContextWindow: 8192, ReasoningEffort: "high", Revision: 1, CreatedAt: nowProfile, UpdatedAt: nowProfile}, uuid.NewString(), sha256hexPG([]byte("profile-create"))); e != nil {
		t.Fatal(e)
	}
	temperature, topP := 0.25, 0.75
	snapshot := coremodel.ExecutionSnapshot{ProfileID: profileID, Revision: 1, CredentialVersion: 1, Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, BaseURL: "https://example.invalid/v1", Model: "original-model", APIKey: "original-secret", SystemPrompt: "original prompt", Temperature: &temperature, TopP: &topP, MaxOutputTokens: 321, ContextWindow: 8192, ReasoningEffort: "high"}
	bound, e := cs.BindChatProfileSnapshot(ctx, rid, lease.LeaseID, lease.Epoch, sha256hexPG([]byte("chat")), snapshot)
	if e != nil || bound.ProfileSnapshotDigest != snapshot.Digest() {
		t.Fatalf("bind snapshot=%+v err=%v", bound, e)
	}
	if strings.Contains(bound.String(), snapshot.APIKey) || strings.Contains(bound.GoString(), snapshot.APIKey) {
		t.Fatal("snapshot secret leaked from lease string")
	}
	if _, e = pool.Exec(ctx, `UPDATE core_model_profiles SET model_name='mutated-model',system_prompt='mutated prompt',temperature=1.5,top_p=0.1 WHERE profile_id=$1`, profileID); e != nil {
		t.Fatal(e)
	}
	// Delete through the profile repository so immutable secret-revision
	// retention and task-snapshot foreign keys are enforced by the supported
	// API. A direct SQL delete would violate the retention FK by design.
	if _, e = s.DeleteProfile(ctx, profileID, uuid.NewString(), sha256hexPG([]byte("integration-delete-profile")), 1); e != nil {
		t.Fatal(e)
	}
	if e = cs.ReleaseChat(ctx, rid, bound.LeaseID, bound.Epoch); e != nil {
		t.Fatalf("release snapshot-bound chat lease: %v", e)
	}
	reclaimed, e := cs.ClaimChat(ctx, rid, c.ID, sha256hexPG([]byte("chat")), profileID, nil, now, time.Minute)
	if e != nil || reclaimed.Status != core.ClaimReclaimed || reclaimed.ProfileSnapshotDigest != snapshot.Digest() {
		t.Fatalf("reclaimed=%+v err=%v", reclaimed, e)
	}
	renewed, e := cs.RenewChat(ctx, rid, reclaimed.LeaseID, reclaimed.Epoch, now.Add(2*time.Minute), time.Minute)
	if e != nil || renewed.ProfileSnapshotDigest != snapshot.Digest() || !reflect.DeepEqual(renewed.ProfileSnapshot, snapshot) {
		t.Fatalf("renewed snapshot=%+v err=%v", renewed, e)
	}
	if renewed.ProfileSnapshot.RequestDialect != coremodel.DialectOpenAICompatibleChatV1 {
		t.Fatalf("renewed request dialect=%q", renewed.ProfileSnapshot.RequestDialect)
	}
	var built coremodel.Profile
	runner, e := coreruntime.NewModelRunner(func(p coremodel.Profile) (coremodel.Client, error) { built = p; return integrationModelClient{}, nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runner.Run(ctx, core.ModelRunRequest{
		Snapshot: renewed.ProfileSnapshot,
		Conversation: core.Conversation{Messages: []core.Message{{
			Role: core.RoleUser, Content: "integration snapshot check",
		}}},
	}); e != nil {
		t.Fatal(e)
	}
	if built.Model != snapshot.Model || built.APIKey != snapshot.APIKey || built.SystemPrompt != snapshot.SystemPrompt || built.Provider != snapshot.Provider || built.BaseURL != snapshot.BaseURL || built.MaxOutputTokens != snapshot.MaxOutputTokens || built.ContextWindow != snapshot.ContextWindow || built.ReasoningEffort != snapshot.ReasoningEffort || built.Temperature == nil || *built.Temperature != *snapshot.Temperature || built.TopP == nil || *built.TopP != *snapshot.TopP {
		t.Fatalf("model runner used mutated profile: %+v", built)
	}
	lease = renewed
	_, e = cs.RenewChat(ctx, rid, lease.LeaseID, lease.Epoch, now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cs.RenewChat(ctx, rid, lease.LeaseID, lease.Epoch, now, time.Minute); !errors.Is(e, core.ErrConflict) {
		t.Fatalf("stale epoch=%v", e)
	}
	modelResult := core.ModelRunResult{Done: true, RelatedTaskIDs: []string{uuid.NewString()}, ToolSummaries: []string{"model complete"}}
	if e = cs.RecordModelStep(ctx, rid, lease.LeaseID, sha256hexPG([]byte("chat")), lease.Epoch+1, lease.ProfileID, 0, modelResult); e != nil {
		t.Fatal(e)
	}
	loaded, ok, e := cs.LoadModelStep(ctx, rid, lease.LeaseID, sha256hexPG([]byte("chat")), lease.Epoch+1, lease.ProfileID, 0)
	if e != nil || !ok || !loaded.Done {
		t.Fatalf("model replay loaded=%+v ok=%v err=%v", loaded, ok, e)
	}
	toolCallID := "tool-call-1"
	tool, e := cs.ClaimToolExecution(ctx, rid, toolCallID, sha256hexPG([]byte(`{"a":1}`)), sha256hexPG([]byte("ext")), now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = cs.MarkToolDispatched(ctx, rid, toolCallID, tool.LeaseID, tool.Epoch); e != nil {
		t.Fatal(e)
	}
	heartbeatCallID := "tool-heartbeat"
	heartbeatArgs := sha256hexPG([]byte(`{"heartbeat":true}`))
	heartbeatExt := sha256hexPG([]byte("ext"))
	heartbeatTool, e := cs.ClaimToolExecution(ctx, rid, heartbeatCallID, heartbeatArgs, heartbeatExt, now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = cs.MarkToolDispatched(ctx, rid, heartbeatCallID, heartbeatTool.LeaseID, heartbeatTool.Epoch); e != nil {
		t.Fatal(e)
	}
	renewedTool, e := cs.RenewToolExecution(ctx, rid, heartbeatCallID, heartbeatTool.LeaseID, heartbeatTool.Epoch, now.Add(45*time.Second), time.Minute)
	if e != nil || renewedTool.Status != core.ToolClaimDispatched {
		t.Fatalf("renewed dispatched tool=%+v err=%v", renewedTool, e)
	}
	if _, e = cs.CompleteToolExecution(ctx, core.ToolCompletion{RequestID: rid, ToolCallID: heartbeatCallID, LeaseID: renewedTool.LeaseID, Epoch: renewedTool.Epoch, ArgsDigest: heartbeatArgs, ExtensionDigest: heartbeatExt, Result: core.ToolResult{CallID: heartbeatCallID, Content: "heartbeat complete"}}); e != nil {
		t.Fatalf("complete renewed dispatched tool=%v", e)
	}
	expiredDispatched, e := cs.ClaimToolExecution(ctx, rid, toolCallID, sha256hexPG([]byte(`{"a":1}`)), sha256hexPG([]byte("ext")), now.Add(2*time.Minute), time.Minute)
	if e != nil || expiredDispatched.Status != core.ToolClaimDispatched {
		t.Fatalf("expired dispatched claim=%+v err=%v", expiredDispatched, e)
	}
	if e = cs.TerminalizeToolUncertain(ctx, rid, toolCallID, tool.LeaseID, tool.Epoch, lease.LeaseID, lease.Epoch+1, "runner_lost", "runner lost"); e != nil {
		t.Fatal(e)
	}
	retryTool, e := cs.ClaimToolExecution(ctx, rid, toolCallID, sha256hexPG([]byte(`{"a":1}`)), sha256hexPG([]byte("ext")), now.Add(2*time.Minute), time.Minute)
	if e != nil || retryTool.Status != core.ToolClaimUncertain {
		t.Fatalf("uncertain retry=%+v err=%v", retryTool, e)
	}

	commitReq := uuid.NewString()
	commitConv := core.Conversation{ID: uuid.NewString(), Revision: 1, CreatedAt: now, UpdatedAt: now}
	commitProfile := uuid.NewString()
	if _, e = s.CreateProfile(ctx, coremodel.Profile{ID: commitProfile, DisplayName: "integration", Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.invalid", Model: "test-model", APIKey: "commit-secret", Revision: 1, CreatedAt: nowProfile, UpdatedAt: nowProfile}, uuid.NewString(), sha256hexPG([]byte("commit-profile-create"))); e != nil {
		t.Fatal(e)
	}
	chatSnapshot := coremodel.ExecutionSnapshot{ProfileID: commitProfile, Revision: 1, CredentialVersion: 1, Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, BaseURL: "https://example.invalid", Model: "test-model", APIKey: "commit-secret"}
	chatService, e := core.NewService(cs, integrationConversationRunner{}, nil, integrationSnapshotResolver{snapshot: chatSnapshot})
	if e != nil {
		t.Fatal(e)
	}
	chatConversation := core.Conversation{ID: uuid.NewString(), Title: "round trip", Revision: 1, CreatedAt: nowProfile, UpdatedAt: nowProfile}
	if _, e = cs.CreateConversationMutation(ctx, core.CreateConversationCommand{RequestID: uuid.NewString(), Conversation: chatConversation, Fingerprint: digestConversationPG(chatConversation)}); e != nil {
		t.Fatal(e)
	}
	firstChat, e := chatService.Chat(ctx, core.ChatCommand{RequestID: uuid.NewString(), ConversationID: chatConversation.ID, Prompt: "first", ProfileID: commitProfile, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1})
	if e != nil {
		t.Fatalf("first round-trip chat: %v", e)
	}
	expectedRevision := firstChat.Revision
	if _, e = chatService.Chat(ctx, core.ChatCommand{RequestID: uuid.NewString(), ConversationID: chatConversation.ID, Prompt: "second", ProfileID: commitProfile, ExpectedRevision: &expectedRevision, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1}); e != nil {
		t.Fatalf("second round-trip chat: %v", e)
	}
	loadedChat, e := cs.LoadConversation(ctx, chatConversation.ID)
	if e != nil || len(loadedChat.Messages) != 4 || loadedChat.ValidateForPersistence() != nil {
		t.Fatalf("round-trip conversation=%+v err=%v", loadedChat, e)
	}
	if loadedChat.Messages[1].ReasoningContent != "integration reasoning" || loadedChat.Messages[3].ReasoningContent != "integration reasoning" {
		t.Fatalf("reasoning was not restored from message payload: %+v", loadedChat.Messages)
	}
	for i := 1; i < len(loadedChat.Messages); i++ {
		previous, current := loadedChat.Messages[i-1].CreatedAt, loadedChat.Messages[i].CreatedAt
		if !current.After(previous) || current.Sub(previous) < time.Microsecond || current.Nanosecond()%int(time.Microsecond) != 0 {
			t.Fatalf("message timestamps are not persistably ordered: previous=%s current=%s", previous.Format(time.RFC3339Nano), current.Format(time.RFC3339Nano))
		}
	}
	commitLease, e := cs.ClaimChat(ctx, commitReq, commitConv.ID, sha256hexPG([]byte("commit")), commitProfile, nil, now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	commitSnapshot := coremodel.ExecutionSnapshot{ProfileID: commitProfile, Revision: 1, CredentialVersion: 1, Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, BaseURL: "https://example.invalid", Model: "test-model", APIKey: "commit-secret"}
	commitLease, e = cs.BindChatProfileSnapshot(ctx, commitReq, commitLease.LeaseID, commitLease.Epoch, sha256hexPG([]byte("commit")), commitSnapshot)
	if e != nil {
		t.Fatal(e)
	}
	msg := core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "answer", ReasoningContent: "persisted reasoning", CreatedAt: now, ModelProfileID: commitProfile, ToolCalls: []core.ToolCall{{ID: toolCallID, Name: "demo", Arguments: `{"a":1}`}}, ToolResults: []core.ToolResult{{CallID: toolCallID, Content: "ok", Summary: "done"}}}
	commitConv.Messages = []core.Message{msg}
	resp := core.ChatResponse{RequestID: commitReq, ConversationID: commitConv.ID, Revision: 1, Message: msg, Done: true, ModelProfileID: commitProfile}
	if _, e = cs.CommitChatCompletion(ctx, core.AtomicCompletion{RequestID: commitReq, LeaseID: commitLease.LeaseID, Fingerprint: sha256hexPG([]byte("commit")), ExpectedRevision: 1, Conversation: commitConv, Response: resp, Epoch: commitLease.Epoch}); e != nil {
		t.Fatal(e)
	}
	loadedConv, e := cs.LoadConversation(ctx, commitConv.ID)
	if e != nil || len(loadedConv.Messages) != 1 || loadedConv.Messages[0].ReasoningContent != "persisted reasoning" || len(loadedConv.Messages[0].ToolCalls) != 1 || len(loadedConv.Messages[0].ToolResults) != 1 {
		t.Fatalf("committed conversation=%+v err=%v", loadedConv, e)
	}

	badReq := uuid.NewString()
	badConv := core.Conversation{ID: uuid.NewString(), Revision: 1, CreatedAt: now, UpdatedAt: now}
	badLease, e := cs.ClaimChat(ctx, badReq, badConv.ID, sha256hexPG([]byte("bad")), commitProfile, nil, now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	badMsg := core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "bad", CreatedAt: now, ModelProfileID: commitProfile, ToolCalls: []core.ToolCall{{ID: "bad", Name: "bad", Arguments: "not-json"}}}
	badConv.Messages = []core.Message{badMsg}
	badResp := core.ChatResponse{RequestID: badReq, ConversationID: badConv.ID, Revision: 1, Message: badMsg, Done: true, ModelProfileID: commitProfile}
	if _, e = cs.CommitChatCompletion(ctx, core.AtomicCompletion{RequestID: badReq, LeaseID: badLease.LeaseID, Fingerprint: sha256hexPG([]byte("bad")), ExpectedRevision: 1, Conversation: badConv, Response: badResp, Epoch: badLease.Epoch}); e == nil {
		t.Fatal("expected invalid child rollback")
	}
	if _, e = cs.LoadConversation(ctx, badConv.ID); e == nil {
		t.Fatal("invalid child commit persisted conversation")
	}
}

// A model result may be committed before the worker dies during the final
// conversation transaction.  Reclaiming the request must rebind that durable
// step to the new lease epoch so the next service instance replays it, while
// the old lease remains fenced.
func TestCoreConversationModelStepReplayAfterReclaim(t *testing.T) {
	dsn := os.Getenv("AGENT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for PG18 integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		t.Fatal(err)
	}
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dtx_agent_model_replay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
		t.Fatal(err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-core-model-replay-test"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
	})
	instanceID := uuid.NewString()
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	conversationStore, err := NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	requestID, conversationID, profileID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	fingerprint := sha256hexPG([]byte("model-replay"))
	now := time.Now().UTC()
	old, err := conversationStore.ClaimChat(ctx, requestID, conversationID, fingerprint, profileID, nil, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result := core.ModelRunResult{Done: true, Message: core.Message{Role: core.RoleAssistant, Content: "once"}}
	if err := conversationStore.RecordModelStep(ctx, requestID, old.LeaseID, fingerprint, old.Epoch, profileID, 0, result); err != nil {
		t.Fatal(err)
	}
	// Simulate a worker crash after model-step persistence.  The lease is
	// expired but the step row is intentionally left completed.
	if _, err = pool.Exec(ctx, `UPDATE core_chat_request_leases SET lease_expires_at=clock_timestamp() WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3`, requestID, old.LeaseID, old.Epoch); err != nil {
		t.Fatal(err)
	}
	fresh, err := conversationStore.ClaimChat(ctx, requestID, conversationID, fingerprint, profileID, nil, now, time.Minute)
	if err != nil || fresh.Status != core.ClaimReclaimed || fresh.Epoch <= old.Epoch {
		t.Fatalf("fresh lease=%+v err=%v", fresh, err)
	}
	replayed, ok, err := conversationStore.LoadModelStep(ctx, requestID, fresh.LeaseID, fingerprint, fresh.Epoch, profileID, 0)
	if err != nil || !ok || replayed.Message.Content != "once" {
		t.Fatalf("replay=%+v ok=%v err=%v", replayed, ok, err)
	}
	if _, ok, err := conversationStore.LoadModelStep(ctx, requestID, old.LeaseID, fingerprint, old.Epoch, profileID, 0); err != nil || ok {
		t.Fatalf("stale epoch read err=%v ok=%v", err, ok)
	}
	if err := conversationStore.RecordModelStep(ctx, requestID, old.LeaseID, fingerprint, old.Epoch, profileID, 0, core.ModelRunResult{Done: true}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("stale epoch write err=%v", err)
	}
}
