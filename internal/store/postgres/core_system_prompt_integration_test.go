package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

func TestGlobalSystemPromptMigrationPreservesDefault(t *testing.T) {
	h := openTurnDBAtVersion(t, 32)
	ctx := context.Background()
	for _, entry := range []struct{ id, prompt string }{{"default", "Use Chinese\nKeep it concise."}, {"other", "Other model override"}} {
		_, err := h.pool.Exec(ctx, `INSERT INTO core_model_profiles(profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,request_dialect) VALUES($1,$2,$2,'openai_compatible','https://example.invalid','test',$3,'openai_compatible_chat_v1')`, uuid.NewString(), entry.id, entry.prompt)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO core_model_profile_defaults(singleton,default_conversation_client_profile_id) VALUES(true,'default')`); err != nil {
		t.Fatal(err)
	}
	var instance string
	if err := h.pool.QueryRow(ctx, `SELECT agent_instance_id::text FROM agent_instance_metadata`).Scan(&instance); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, h.pool, instance); err != nil {
		t.Fatal(err)
	}
	got, err := NewCoreAgentConfigStore(h.store.Store).GetSystemPrompt(ctx)
	if err != nil || got.Prompt != "Use Chinese\nKeep it concise." || got.Revision != 1 {
		t.Fatalf("global migration: %+v %v", got, err)
	}
	var exists bool
	if err = h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='core_model_profiles' AND column_name='system_prompt')`).Scan(&exists); err != nil || exists {
		t.Fatalf("model prompt column retained: %v %v", exists, err)
	}
}

func TestGlobalSystemPromptCapabilityPersistenceAndSnapshots(t *testing.T) {
	ctx, store, firstID, cleanup := coreTaskScheduleFixture(t)
	defer cleanup()
	secondID := uuid.NewString()
	createTestProfile(ctx, t, store, secondID, "second-model", "test")
	config := NewCoreAgentConfigStore(store)
	cap := agentcapability.NewConfigCapability(config)
	authorized := capabilityclient.WithCallContext(ctx, &capv1.CallContext{ChainId: uuid.NewString(), RootOperationId: uuid.NewString(), Route: "ms→agent"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner-1", AccountGeneration: 1})
	if _, err := cap.HandleOperation(ctx, "get_system_prompt", []byte(`{}`)); err == nil {
		t.Fatal("anonymous config read accepted")
	}
	update := coreconfig.SystemPromptUpdate{IdempotencyKey: uuid.NewString(), Prompt: "GLOBAL-PROMPT-ONE\n用中文回答"}
	raw, _ := json.Marshal(update)
	response, err := cap.HandleOperation(authorized, "update_system_prompt", raw)
	if err != nil {
		t.Fatal(err)
	}
	var saved coreconfig.SystemPrompt
	if err = json.Unmarshal(response, &saved); err != nil || saved.Revision != 1 || saved.Prompt != update.Prompt {
		t.Fatalf("save: %+v %v", saved, err)
	}
	for _, id := range []string{firstID, secondID} {
		p, err := store.ResolveProfile(ctx, id)
		if err != nil || p.SystemPrompt != update.Prompt {
			t.Fatalf("model %s missed global prompt: %v", id, err)
		}
		public, _ := json.Marshal(p.Public())
		if strings.Contains(string(public), "system_prompt") {
			t.Fatal("model profile exposes a prompt")
		}
	}
	conversations, err := NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	runner := &finalizationConversationModel{result: core.ModelRunResult{Message: core.Message{Role: core.RoleAssistant, Content: "Hello."}, Done: true}}
	service, err := core.NewService(conversations, runner, nil, core.AdaptProfileResolver(store))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	start := core.TurnStartCommand{RequestID: uuid.NewString(), ProfileID: firstID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1, Prompt: "hello"}
	turn, err := service.StartTurn(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	waitConversationTurnState(t, conversations, turn.ID, core.TurnCompleted, 5*time.Second)
	requests := runner.snapshotRequests()
	if len(requests) != 1 || !strings.Contains(requests[0].Profile.SystemPrompt, "GLOBAL-PROMPT-ONE") {
		t.Fatal("consumer omitted saved global prompt")
	}
	tasks := NewCoreTaskStore(store)
	spec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "queued task", ModelProfileID: secondID, IdempotencyKey: uuid.NewString(), AvailableAt: time.Now().UTC()}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	task, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: spec.IdempotencyKey, RequestDigest: digest}})
	if err != nil || task.Snapshot == nil || task.Snapshot.Model.SystemPrompt != update.Prompt {
		t.Fatalf("task admission omitted global prompt: %v", err)
	}
	changed, err := config.UpdateSystemPrompt(ctx, "owner-1", coreconfig.SystemPromptUpdate{IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Prompt: "GLOBAL-PROMPT-TWO"})
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewCoreAgentConfigStore(store)
	got, err := restarted.GetSystemPrompt(ctx)
	if err != nil || got != changed {
		t.Fatalf("restart lost config: %+v %v", got, err)
	}
	replay, err := restarted.UpdateSystemPrompt(ctx, "owner-1", update)
	if err != nil || replay != saved {
		t.Fatalf("old idempotency replay drifted: %+v %v", replay, err)
	}
	conflicting := update
	conflicting.Prompt = "different"
	if _, err = restarted.UpdateSystemPrompt(ctx, "owner-1", conflicting); !errors.Is(err, coreconfig.ErrConflict) {
		t.Fatalf("key collision accepted: %v", err)
	}
	if _, err = restarted.UpdateSystemPrompt(ctx, "other-owner", update); !errors.Is(err, coreconfig.ErrConflict) {
		t.Fatalf("owner-bound replay crossed owner: %v", err)
	}
	replayTurn, err := service.StartTurn(ctx, start)
	if err != nil || replayTurn.ProfileSnapshot.SystemPrompt != saved.Prompt || replayTurn.RuntimeSnapshot.CompiledSystemPrompt != turn.RuntimeSnapshot.CompiledSystemPrompt {
		t.Fatalf("replayed turn prompt changed: %v", err)
	}
	profile, err := store.ResolveExecutionProfile(ctx, task.Snapshot.Model)
	if err != nil || profile.SystemPrompt != saved.Prompt {
		t.Fatalf("queued task changed after config update: %v", err)
	}
	nextStart := start
	nextStart.RequestID = uuid.NewString()
	nextStart.ProfileID = secondID
	next, err := service.StartTurn(ctx, nextStart)
	if err != nil {
		t.Fatal(err)
	}
	waitConversationTurnState(t, conversations, next.ID, core.TurnCompleted, 5*time.Second)
	requests = runner.snapshotRequests()
	if len(requests) != 2 || !strings.Contains(requests[1].Profile.SystemPrompt, changed.Prompt) || strings.Contains(requests[1].Profile.SystemPrompt, "GLOBAL-PROMPT-ONE") {
		t.Fatal("new model turn did not use updated global value")
	}
	cleared, err := restarted.UpdateSystemPrompt(ctx, "owner-1", coreconfig.SystemPromptUpdate{IdempotencyKey: uuid.NewString(), ExpectedRevision: 2, Prompt: ""})
	if err != nil || cleared.Prompt != "" || cleared.Revision != 3 {
		t.Fatalf("clear: %+v %v", cleared, err)
	}
	for _, id := range []string{firstID, secondID} {
		p, err := store.ResolveProfile(ctx, id)
		if err != nil || p.SystemPrompt != "" {
			t.Fatal("clearing global prompt restored a model override")
		}
	}
	stale := coreconfig.SystemPromptUpdate{IdempotencyKey: uuid.NewString(), ExpectedRevision: 0, Prompt: "stale"}
	if _, err = restarted.UpdateSystemPrompt(ctx, "owner-1", stale); !errors.Is(err, coreconfig.ErrConflict) {
		t.Fatalf("revision zero overwrote existing setting: %v", err)
	}
}

func TestGlobalSystemPromptConcurrentFirstSave(t *testing.T) {
	ctx, store, _, cleanup := coreTaskScheduleFixture(t)
	defer cleanup()
	config := NewCoreAgentConfigStore(store)
	var wg sync.WaitGroup
	errorsFound := make(chan error, 2)
	for _, prompt := range []string{"first", "second"} {
		wg.Add(1)
		go func(prompt string) {
			defer wg.Done()
			_, err := config.UpdateSystemPrompt(ctx, "owner", coreconfig.SystemPromptUpdate{IdempotencyKey: uuid.NewString(), Prompt: prompt})
			errorsFound <- err
		}(prompt)
	}
	wg.Wait()
	close(errorsFound)
	successes, conflicts := 0, 0
	for err := range errorsFound {
		if err == nil {
			successes++
		} else if errors.Is(err, coreconfig.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("first save race successes=%d conflicts=%d", successes, conflicts)
	}
}
