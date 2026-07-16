package p0_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestRuntimeStorePersistsConfigConversationAndFencesRevision(t *testing.T) {
	database := newMigratedDatabase(t)
	scope := runtimeMutationScope("runtime-config")
	configCommand := runtimeConfigCommand("owner-runtime", uuid.NewString())

	created, err := database.store.SaveRuntimeConfig(context.Background(), scope, configCommand)
	if err != nil {
		t.Fatalf("save runtime config failed (%T)", err)
	}
	if created.Revision != 1 || !reflect.DeepEqual(created.EnabledTools, []string{"knowledge.query", "task.create"}) {
		t.Fatalf("runtime config was not normalized and revisioned: revision=%d tools=%v", created.Revision, created.EnabledTools)
	}
	replayedConfig, err := database.store.SaveRuntimeConfig(context.Background(), scope, configCommand)
	if err != nil || !reflect.DeepEqual(created, replayedConfig) {
		t.Fatalf("same-caller runtime config replay was not exact: err=%T", err)
	}

	restarted, err := postgres.New(database.pool, database.instanceID)
	if err != nil {
		t.Fatalf("reopen runtime store failed (%T)", err)
	}
	loadedConfig, err := restarted.LoadRuntimeConfig(context.Background(), "owner-runtime")
	if err != nil || !reflect.DeepEqual(created, loadedConfig) {
		t.Fatalf("runtime config did not survive store restart: err=%T", err)
	}

	conversation := pairedRuntimeConversation("owner-runtime", "conversation-runtime")
	saved, err := database.store.SaveConversation(context.Background(), conversation, 0)
	if err != nil {
		t.Fatalf("save paired runtime conversation failed (%T)", err)
	}
	if saved.Revision != 1 || saved.UpdatedAt.IsZero() {
		t.Fatalf("saved conversation revision/time invalid: revision=%d", saved.Revision)
	}
	loaded, found, err := restarted.LoadConversation(context.Background(), conversation.OwnerID, conversation.ConversationID)
	if err != nil || !found || loaded.Revision != 1 || !reflect.DeepEqual(conversation.Messages, loaded.Messages) || loaded.Summary != conversation.Summary {
		t.Fatalf("paired conversation did not survive restart: found=%t revision=%d err=%T", found, loaded.Revision, err)
	}

	firstUpdate := loaded
	firstUpdate.Summary = "first concurrent update"
	secondUpdate := loaded
	secondUpdate.Summary = "second concurrent update"
	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	var writers sync.WaitGroup
	for _, update := range []runtimeapi.Conversation{firstUpdate, secondUpdate} {
		update := update
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			_, saveErr := database.store.SaveConversation(context.Background(), update, 1)
			errorsByWriter <- saveErr
		}()
	}
	close(start)
	writers.Wait()
	close(errorsByWriter)
	var successes, conflicts int
	for saveErr := range errorsByWriter {
		switch {
		case saveErr == nil:
			successes++
		case errors.Is(saveErr, runtimeapi.ErrRuntimeRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent conversation save failed unexpectedly (%T)", saveErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("conversation revision fencing = %d success/%d conflict, want 1/1", successes, conflicts)
	}
}

func TestRuntimeRequestCallerReplayRecoveryAndToolDeduplication(t *testing.T) {
	database := newMigratedDatabase(t)
	scopeA := runtimeMutationScope("runtime-a")
	scopeB := runtimeMutationScope("runtime-b")
	request := runtimeapi.RuntimeRequestCommand{
		Request: runtimeapi.ChatRequest{
			RequestID: uuid.NewString(), OwnerID: "owner-request", ConversationID: "conversation-request",
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "Plan a safe deployment."}},
		},
		LeaseDuration: time.Second,
	}

	claimA, err := database.store.BeginRuntimeRequest(context.Background(), scopeA, request)
	if err != nil || claimA.Completed || claimA.LeaseEpoch != 1 {
		t.Fatalf("begin caller A runtime request failed: completed=%t epoch=%d err=%T", claimA.Completed, claimA.LeaseEpoch, err)
	}
	claimB, err := database.store.BeginRuntimeRequest(context.Background(), scopeB, request)
	if err != nil || claimB.Completed || claimB.LeaseEpoch != 1 {
		t.Fatalf("same request UUID was not isolated for caller B: completed=%t epoch=%d err=%T", claimB.Completed, claimB.LeaseEpoch, err)
	}
	if _, err := database.store.BeginRuntimeRequest(context.Background(), scopeA, request); !errors.Is(err, runtimeapi.ErrRuntimeRequestInFlight) {
		t.Fatalf("active same-caller replay error = %T, want in-flight", err)
	}
	if _, err := database.store.BindRuntimeRequestMemoryMode(context.Background(), scopeA, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: request.Request.RequestID, LeaseEpoch: claimA.LeaseEpoch,
	}); err != nil {
		t.Fatalf("bind caller A memory mode failed (%T)", err)
	}

	conversation := runtimeapi.Conversation{
		OwnerID: request.Request.OwnerID, ConversationID: request.Request.ConversationID,
		Messages: []modelapi.Message{
			{Role: modelapi.RoleUser, Content: "Plan a safe deployment."},
			{Role: modelapi.RoleAssistant, Content: "I prepared a typed draft."},
		},
	}
	completed, err := database.store.CompleteRuntimeRequest(context.Background(), scopeA, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: request.Request.RequestID, LeaseEpoch: claimA.LeaseEpoch, Conversation: conversation,
		ExpectedConversationRevision: 0,
		Result: runtimeapi.ChatResult{
			Message:        modelapi.Message{Role: modelapi.RoleAssistant, Content: "I prepared a typed draft."},
			RelatedTaskIDs: []string{"99a88e43-ab03-48cb-a917-334f126a303e"},
		},
	})
	if err != nil || completed.SchemaVersion != runtimeapi.RuntimeResponseSnapshotSchemaV1 || completed.Result.ConversationRevision != 1 {
		t.Fatalf("complete runtime request failed: schema=%d revision=%d err=%T", completed.SchemaVersion, completed.Result.ConversationRevision, err)
	}
	replayed, err := database.store.BeginRuntimeRequest(context.Background(), scopeA, request)
	if err != nil || !replayed.Completed || !reflect.DeepEqual(completed, replayed.Response) {
		t.Fatalf("completed same-caller request did not replay exact versioned snapshot: completed=%t err=%T", replayed.Completed, err)
	}
	restarted, err := postgres.New(database.pool, database.instanceID)
	if err != nil {
		t.Fatalf("reopen runtime store failed (%T)", err)
	}
	restartedReplay, err := restarted.BeginRuntimeRequest(context.Background(), scopeA, request)
	if err != nil || !reflect.DeepEqual(replayed, restartedReplay) {
		t.Fatalf("runtime response snapshot did not survive restart: err=%T", err)
	}
	conflicting := request
	conflicting.Request.Messages = []modelapi.Message{{Role: modelapi.RoleUser, Content: "A different payload."}}
	if _, err := restarted.BeginRuntimeRequest(context.Background(), scopeA, conflicting); !errors.Is(err, runtimeapi.ErrRuntimeIdempotency) {
		t.Fatalf("same caller reused request UUID with different payload: err=%T", err)
	}

	recoverable := runtimeapi.RuntimeRequestCommand{
		Request:       runtimeapi.ChatRequest{RequestID: uuid.NewString(), OwnerID: "owner-request", Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "Recover me."}}},
		LeaseDuration: 30 * time.Millisecond,
	}
	firstLease, err := database.store.BeginRuntimeRequest(context.Background(), scopeA, recoverable)
	if err != nil {
		t.Fatalf("begin recoverable request failed (%T)", err)
	}
	time.Sleep(50 * time.Millisecond)
	secondLease, err := restarted.BeginRuntimeRequest(context.Background(), scopeA, recoverable)
	if err != nil || secondLease.LeaseEpoch != firstLease.LeaseEpoch+1 {
		t.Fatalf("expired request lease was not recovered after restart: first=%d second=%d err=%T", firstLease.LeaseEpoch, secondLease.LeaseEpoch, err)
	}
	if _, err := restarted.CompleteRuntimeRequest(context.Background(), scopeA, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: recoverable.Request.RequestID, LeaseEpoch: firstLease.LeaseEpoch,
		Result: runtimeapi.ChatResult{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "A late result."}},
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old runtime request lease completion error = %T, want stale lease", err)
	}
	if _, err := restarted.RenewRuntimeRequest(context.Background(), scopeA, runtimeapi.RenewRuntimeRequestCommand{
		RequestID: recoverable.Request.RequestID, LeaseEpoch: firstLease.LeaseEpoch, LeaseDuration: time.Second,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old runtime request renewal error = %T, want stale lease", err)
	}
	if err := restarted.ReleaseRuntimeRequest(context.Background(), scopeA, runtimeapi.ReleaseRuntimeRequestCommand{
		RequestID: recoverable.Request.RequestID, LeaseEpoch: firstLease.LeaseEpoch,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old runtime request release error = %T, want stale lease", err)
	}
	if _, err := restarted.RenewRuntimeRequest(context.Background(), scopeA, runtimeapi.RenewRuntimeRequestCommand{
		RequestID: recoverable.Request.RequestID, LeaseEpoch: secondLease.LeaseEpoch, LeaseDuration: time.Second,
	}); err != nil {
		t.Fatalf("current runtime request renewal failed (%T)", err)
	}
	boundStateless, err := restarted.BindRuntimeRequestMemoryMode(context.Background(), scopeA, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: recoverable.Request.RequestID, LeaseEpoch: secondLease.LeaseEpoch,
	})
	if err != nil || !boundStateless {
		t.Fatalf("bind recovered stateless memory mode: disabled=%t err=%T", boundStateless, err)
	}

	toolCommand := runtimeapi.ToolExecutionCommand{
		RequestID: recoverable.Request.RequestID, ParentLeaseEpoch: secondLease.LeaseEpoch, OwnerID: recoverable.Request.OwnerID,
		ToolCallID: "call-1", Name: "knowledge.query", Arguments: []byte(`{"query":"safe"}`), LeaseDuration: time.Second,
	}
	toolClaim, err := restarted.BeginToolExecution(context.Background(), scopeA, toolCommand)
	if err != nil || toolClaim.Completed || toolClaim.LeaseEpoch != 1 {
		t.Fatalf("begin tool execution failed: completed=%t epoch=%d err=%T", toolClaim.Completed, toolClaim.LeaseEpoch, err)
	}
	execution := runtimeapi.ToolExecution{
		ToolCallID: "call-1", Name: "knowledge.query", Content: `{"matches":1}`,
		RelatedTaskIDs: []string{"99a88e43-ab03-48cb-a917-334f126a303e"},
	}
	storedExecution, err := restarted.CompleteToolExecution(context.Background(), scopeA, runtimeapi.CompleteToolExecutionCommand{
		RequestID: recoverable.Request.RequestID, ToolCallID: "call-1", ParentLeaseEpoch: secondLease.LeaseEpoch, LeaseEpoch: toolClaim.LeaseEpoch, Execution: execution,
	})
	if err != nil || !reflect.DeepEqual(execution, storedExecution) {
		t.Fatalf("complete tool execution failed (%T)", err)
	}
	toolReplay, err := database.store.BeginToolExecution(context.Background(), scopeA, toolCommand)
	if err != nil || !toolReplay.Completed || !reflect.DeepEqual(execution, toolReplay.Execution) {
		t.Fatalf("tool execution was not deduplicated after restart: completed=%t err=%T", toolReplay.Completed, err)
	}
	toolConflict := toolCommand
	toolConflict.Arguments = []byte(`{"query":"different"}`)
	if _, err := database.store.BeginToolExecution(context.Background(), scopeA, toolConflict); !errors.Is(err, runtimeapi.ErrRuntimeIdempotency) {
		t.Fatalf("tool call reused with different arguments: err=%T", err)
	}
	recoverableTool := toolCommand
	recoverableTool.ToolCallID = "call-recover"
	recoverableTool.LeaseDuration = 30 * time.Millisecond
	firstToolLease, err := restarted.BeginToolExecution(context.Background(), scopeA, recoverableTool)
	if err != nil {
		t.Fatalf("begin recoverable tool execution failed (%T)", err)
	}
	time.Sleep(50 * time.Millisecond)
	secondToolLease, err := database.store.BeginToolExecution(context.Background(), scopeA, recoverableTool)
	if err != nil || secondToolLease.LeaseEpoch != firstToolLease.LeaseEpoch+1 {
		t.Fatalf("expired tool lease was not reclaimed: first=%d second=%d err=%T", firstToolLease.LeaseEpoch, secondToolLease.LeaseEpoch, err)
	}
	recoveredExecution := runtimeapi.ToolExecution{ToolCallID: "call-recover", Name: recoverableTool.Name, Content: `{"matches":2}`}
	if _, err := database.store.CompleteToolExecution(context.Background(), scopeA, runtimeapi.CompleteToolExecutionCommand{
		RequestID: recoverableTool.RequestID, ToolCallID: recoverableTool.ToolCallID,
		ParentLeaseEpoch: secondLease.LeaseEpoch, LeaseEpoch: firstToolLease.LeaseEpoch, Execution: recoveredExecution,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old tool lease completion error = %T, want stale lease", err)
	}
	if _, err := database.store.CompleteToolExecution(context.Background(), scopeA, runtimeapi.CompleteToolExecutionCommand{
		RequestID: recoverableTool.RequestID, ToolCallID: recoverableTool.ToolCallID,
		ParentLeaseEpoch: secondLease.LeaseEpoch, LeaseEpoch: secondToolLease.LeaseEpoch, Execution: recoveredExecution,
	}); err != nil {
		t.Fatalf("reclaimed tool lease could not complete (%T)", err)
	}
	releasedTool := toolCommand
	releasedTool.ToolCallID = "call-release"
	releasedTool.LeaseDuration = time.Second
	firstReleasedTool, err := database.store.BeginToolExecution(context.Background(), scopeA, releasedTool)
	if err != nil {
		t.Fatalf("begin releasable tool execution failed (%T)", err)
	}
	if err := database.store.ReleaseToolExecution(context.Background(), scopeA, runtimeapi.ReleaseToolExecutionCommand{
		RequestID: releasedTool.RequestID, ToolCallID: releasedTool.ToolCallID,
		ParentLeaseEpoch: secondLease.LeaseEpoch, LeaseEpoch: firstReleasedTool.LeaseEpoch,
	}); err != nil {
		t.Fatalf("release tool execution failed (%T)", err)
	}
	secondReleasedTool, err := database.store.BeginToolExecution(context.Background(), scopeA, releasedTool)
	if err != nil || secondReleasedTool.LeaseEpoch != firstReleasedTool.LeaseEpoch+1 {
		t.Fatalf("released tool was not reclaimed immediately: first=%d second=%d err=%T", firstReleasedTool.LeaseEpoch, secondReleasedTool.LeaseEpoch, err)
	}
	if _, err := database.store.RenewToolExecution(context.Background(), scopeA, runtimeapi.RenewToolExecutionCommand{
		RequestID: releasedTool.RequestID, ToolCallID: releasedTool.ToolCallID,
		ParentLeaseEpoch: secondLease.LeaseEpoch, LeaseEpoch: firstReleasedTool.LeaseEpoch, LeaseDuration: time.Second,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old tool renewal error = %T, want stale lease", err)
	}
	if err := database.store.ReleaseToolExecution(context.Background(), scopeA, runtimeapi.ReleaseToolExecutionCommand{
		RequestID: releasedTool.RequestID, ToolCallID: releasedTool.ToolCallID,
		ParentLeaseEpoch: secondLease.LeaseEpoch, LeaseEpoch: firstReleasedTool.LeaseEpoch,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old tool release error = %T, want stale lease", err)
	}

	releasableRequest := runtimeapi.RuntimeRequestCommand{
		Request: runtimeapi.ChatRequest{
			RequestID: uuid.NewString(), OwnerID: "owner-release",
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "Release and retry."}},
		},
		LeaseDuration: time.Second,
	}
	firstReleasedRequest, err := database.store.BeginRuntimeRequest(context.Background(), scopeA, releasableRequest)
	if err != nil {
		t.Fatalf("begin releasable runtime request failed (%T)", err)
	}
	if disabled, err := database.store.BindRuntimeRequestMemoryMode(context.Background(), scopeA, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: releasableRequest.Request.RequestID, LeaseEpoch: firstReleasedRequest.LeaseEpoch,
	}); err != nil || !disabled {
		t.Fatalf("bind first releasable request memory mode: disabled=%t err=%T", disabled, err)
	}
	childBeforeRelease := runtimeapi.ToolExecutionCommand{
		RequestID: releasableRequest.Request.RequestID, ParentLeaseEpoch: firstReleasedRequest.LeaseEpoch,
		OwnerID: releasableRequest.Request.OwnerID, ToolCallID: "call-child-release", Name: "knowledge.query",
		Arguments: []byte(`{"query":"release"}`), LeaseDuration: time.Second,
	}
	firstChild, err := database.store.BeginToolExecution(context.Background(), scopeA, childBeforeRelease)
	if err != nil {
		t.Fatalf("begin child tool before request release failed (%T)", err)
	}
	if err := database.store.ReleaseRuntimeRequest(context.Background(), scopeA, runtimeapi.ReleaseRuntimeRequestCommand{
		RequestID: releasableRequest.Request.RequestID, LeaseEpoch: firstReleasedRequest.LeaseEpoch,
	}); err != nil {
		t.Fatalf("release runtime request failed (%T)", err)
	}
	secondReleasedRequest, err := database.store.BeginRuntimeRequest(context.Background(), scopeA, releasableRequest)
	if err != nil || secondReleasedRequest.LeaseEpoch != firstReleasedRequest.LeaseEpoch+1 {
		t.Fatalf("released runtime request was not reclaimed immediately: first=%d second=%d err=%T", firstReleasedRequest.LeaseEpoch, secondReleasedRequest.LeaseEpoch, err)
	}
	boundReleasedStateless, err := database.store.BindRuntimeRequestMemoryMode(context.Background(), scopeA, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: releasableRequest.Request.RequestID, LeaseEpoch: secondReleasedRequest.LeaseEpoch,
	})
	if err != nil || !boundReleasedStateless {
		t.Fatalf("bind released stateless memory mode: disabled=%t err=%T", boundReleasedStateless, err)
	}
	if _, err := database.store.RenewRuntimeRequest(context.Background(), scopeA, runtimeapi.RenewRuntimeRequestCommand{
		RequestID: releasableRequest.Request.RequestID, LeaseEpoch: firstReleasedRequest.LeaseEpoch, LeaseDuration: time.Second,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("released runtime epoch renewal error = %T, want stale lease", err)
	}
	if err := database.store.ReleaseRuntimeRequest(context.Background(), scopeA, runtimeapi.ReleaseRuntimeRequestCommand{
		RequestID: releasableRequest.Request.RequestID, LeaseEpoch: firstReleasedRequest.LeaseEpoch,
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("released runtime epoch second release error = %T, want stale lease", err)
	}
	childAfterRelease := childBeforeRelease
	childAfterRelease.ParentLeaseEpoch = secondReleasedRequest.LeaseEpoch
	secondChild, err := database.store.BeginToolExecution(context.Background(), scopeA, childAfterRelease)
	if err != nil || secondChild.LeaseEpoch != firstChild.LeaseEpoch+1 {
		t.Fatalf("child tool was not reclaimed with parent request: first=%d second=%d err=%T", firstChild.LeaseEpoch, secondChild.LeaseEpoch, err)
	}
	if _, err := database.store.CompleteToolExecution(context.Background(), scopeA, runtimeapi.CompleteToolExecutionCommand{
		RequestID: childBeforeRelease.RequestID, ToolCallID: childBeforeRelease.ToolCallID,
		ParentLeaseEpoch: firstReleasedRequest.LeaseEpoch, LeaseEpoch: firstChild.LeaseEpoch,
		Execution: runtimeapi.ToolExecution{ToolCallID: childBeforeRelease.ToolCallID, Name: childBeforeRelease.Name, Content: `{}`},
	}); !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("old parent/tool epoch completion error = %T, want stale lease", err)
	}
	if err := database.store.ReleaseToolExecution(context.Background(), scopeA, runtimeapi.ReleaseToolExecutionCommand{
		RequestID: childAfterRelease.RequestID, ToolCallID: childAfterRelease.ToolCallID,
		ParentLeaseEpoch: secondReleasedRequest.LeaseEpoch, LeaseEpoch: secondChild.LeaseEpoch,
	}); err != nil {
		t.Fatalf("release current child tool failed (%T)", err)
	}
	if _, err := database.store.CompleteRuntimeRequest(context.Background(), scopeA, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: releasableRequest.Request.RequestID, LeaseEpoch: secondReleasedRequest.LeaseEpoch,
		Result: runtimeapi.ChatResult{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "Recovered without an active child."}},
	}); err != nil {
		t.Fatalf("expired child blocked recovered runtime completion (%T)", err)
	}

	var schemaVersion int
	if err := database.pool.QueryRow(context.Background(), `SELECT response_schema_version FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3`, scopeA.ClientID, scopeA.CredentialID, request.Request.RequestID).Scan(&schemaVersion); err != nil || schemaVersion != runtimeapi.RuntimeResponseSnapshotSchemaV1 {
		t.Fatalf("runtime response snapshot version was not persisted: version=%d err=%T", schemaVersion, err)
	}
}

func TestRuntimeRequestPersistsEffectiveStatelessModeWithoutConversation(t *testing.T) {
	database := newMigratedDatabase(t)
	scope := runtimeMutationScope("runtime-stateless")
	request := runtimeapi.RuntimeRequestCommand{
		Request: runtimeapi.ChatRequest{
			RequestID: uuid.NewString(), OwnerID: "owner-stateless", ConversationID: "conversation-must-not-persist",
			MemoryDisabled: true,
			Messages:       []modelapi.Message{{Role: modelapi.RoleUser, Content: "Answer without memory."}},
		},
		LeaseDuration: time.Second,
	}
	claim, err := database.store.BeginRuntimeRequest(context.Background(), scope, request)
	if err != nil {
		t.Fatalf("begin stateless runtime request failed (%T)", err)
	}
	disabled, err := database.store.BindRuntimeRequestMemoryMode(context.Background(), scope, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: request.Request.RequestID, LeaseEpoch: claim.LeaseEpoch, MemoryDisabled: true,
	})
	if err != nil || !disabled {
		t.Fatalf("bind stateless mode: disabled=%t err=%T", disabled, err)
	}
	completed, err := database.store.CompleteRuntimeRequest(context.Background(), scope, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: request.Request.RequestID, LeaseEpoch: claim.LeaseEpoch,
		Result: runtimeapi.ChatResult{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "Stateless answer."}},
	})
	if err != nil || completed.Result.ConversationRevision != 0 {
		t.Fatalf("complete stateless runtime request: revision=%d err=%T", completed.Result.ConversationRevision, err)
	}
	replayed, err := database.store.BeginRuntimeRequest(context.Background(), scope, request)
	if err != nil || !replayed.Completed || !reflect.DeepEqual(completed, replayed.Response) {
		t.Fatalf("stateless response did not replay exactly: completed=%t err=%T", replayed.Completed, err)
	}
	var conversationCount int
	if err := database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM runtime_conversations
		WHERE owner_id=$1 AND conversation_id=$2`, request.Request.OwnerID, request.Request.ConversationID,
	).Scan(&conversationCount); err != nil || conversationCount != 0 {
		t.Fatalf("stateless request persisted a conversation: count=%d err=%T", conversationCount, err)
	}
}

func TestRuntimeStoreRejectsSecretCanariesBeforePersistence(t *testing.T) {
	database := newMigratedDatabase(t)
	scope := runtimeMutationScope("runtime-secret")
	canaries := []string{
		"sk-" + strings.Repeat("Q", 40),
		"AKIA" + strings.Repeat("R", 16),
		"ghp_" + strings.Repeat("s", 32),
		"password=" + strings.Repeat("p", 16),
	}
	for index, canary := range canaries {
		config := runtimeConfigCommand("owner-secret-"+uuid.NewString(), uuid.NewString())
		config.Config.ProjectProfile = "policy " + canary
		if _, err := database.store.SaveRuntimeConfig(context.Background(), scope, config); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
			t.Fatalf("runtime config secret canary %d error = %T", index, err)
		}
		conversation := runtimeapi.Conversation{
			OwnerID: "owner-secret", ConversationID: "conversation-" + uuid.NewString(),
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "message " + canary}},
		}
		if _, err := database.store.SaveConversation(context.Background(), conversation, 0); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
			t.Fatalf("runtime message secret canary %d error = %T", index, err)
		}
		request := runtimeapi.RuntimeRequestCommand{
			Request:       runtimeapi.ChatRequest{RequestID: uuid.NewString(), OwnerID: "owner-secret", Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "request " + canary}}},
			LeaseDuration: time.Second,
		}
		if _, err := database.store.BeginRuntimeRequest(context.Background(), scope, request); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
			t.Fatalf("runtime request secret canary %d error = %T", index, err)
		}
	}
	escapedSecretJSON := `"s\u006b-` + strings.Repeat("E", 40) + `"`
	if _, err := database.store.SaveConversation(context.Background(), runtimeapi.Conversation{
		OwnerID: "owner-secret", ConversationID: "conversation-escaped-secret",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: escapedSecretJSON}},
	}, 0); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
		t.Fatalf("JSON-escaped runtime secret error = %T", err)
	}

	cleanRequest := runtimeapi.RuntimeRequestCommand{
		Request:       runtimeapi.ChatRequest{RequestID: uuid.NewString(), OwnerID: "owner-secret", Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "clean request"}}},
		LeaseDuration: time.Second,
	}
	claim, err := database.store.BeginRuntimeRequest(context.Background(), scope, cleanRequest)
	if err != nil {
		t.Fatalf("begin clean request failed (%T)", err)
	}
	if disabled, err := database.store.BindRuntimeRequestMemoryMode(context.Background(), scope, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: cleanRequest.Request.RequestID, LeaseEpoch: claim.LeaseEpoch,
	}); err != nil || !disabled {
		t.Fatalf("bind clean stateless request memory mode: disabled=%t err=%T", disabled, err)
	}
	canary := "sk-" + strings.Repeat("Z", 40)
	if _, err := database.store.CompleteRuntimeRequest(context.Background(), scope, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: cleanRequest.Request.RequestID, LeaseEpoch: claim.LeaseEpoch,
		Result: runtimeapi.ChatResult{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: canary}},
	}); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
		t.Fatalf("runtime response secret canary error = %T", err)
	}
	if _, err := database.store.BeginToolExecution(context.Background(), scope, runtimeapi.ToolExecutionCommand{
		RequestID: cleanRequest.Request.RequestID, ParentLeaseEpoch: claim.LeaseEpoch, OwnerID: cleanRequest.Request.OwnerID,
		ToolCallID: "call-secret", Name: "knowledge.query", Arguments: []byte(`{"api_key":"` + canary + `"}`), LeaseDuration: time.Second,
	}); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
		t.Fatalf("tool arguments secret canary error = %T", err)
	}
	cleanTool, err := database.store.BeginToolExecution(context.Background(), scope, runtimeapi.ToolExecutionCommand{
		RequestID: cleanRequest.Request.RequestID, ParentLeaseEpoch: claim.LeaseEpoch, OwnerID: cleanRequest.Request.OwnerID,
		ToolCallID: "call-result-secret", Name: "knowledge.query", Arguments: []byte(`{"query":"clean"}`), LeaseDuration: time.Second,
	})
	if err != nil {
		t.Fatalf("begin clean tool execution failed (%T)", err)
	}
	if _, err := database.store.CompleteToolExecution(context.Background(), scope, runtimeapi.CompleteToolExecutionCommand{
		RequestID: cleanRequest.Request.RequestID, ToolCallID: "call-result-secret", ParentLeaseEpoch: claim.LeaseEpoch, LeaseEpoch: cleanTool.LeaseEpoch,
		Execution: runtimeapi.ToolExecution{ToolCallID: "call-result-secret", Name: "knowledge.query", Content: canary},
	}); !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
		t.Fatalf("tool result secret canary error = %T", err)
	}
	reasoningConversation := runtimeapi.Conversation{
		OwnerID: "owner-secret", ConversationID: "conversation-reasoning",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "clean", ReasoningContent: "private chain of thought"}},
	}
	if _, err := database.store.SaveConversation(context.Background(), reasoningConversation, 0); !errors.Is(err, runtimeapi.ErrRuntimePersistence) {
		t.Fatalf("raw reasoning persistence error = %T", err)
	}
	var reasoningColumnExists bool
	if err := database.pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='runtime_messages' AND column_name='reasoning_content'
	)`).Scan(&reasoningColumnExists); err != nil || reasoningColumnExists {
		t.Fatalf("runtime_messages reasoning column exists=%t err=%T", reasoningColumnExists, err)
	}

	queries := []string{
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM runtime_configs AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM runtime_conversations AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM runtime_messages AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM runtime_requests AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM runtime_tool_executions AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM idempotency_records AS item`,
	}
	var snapshot strings.Builder
	for _, query := range queries {
		var relation string
		if err := database.pool.QueryRow(context.Background(), query).Scan(&relation); err != nil {
			t.Fatalf("scan runtime persistence failed (%T)", err)
		}
		snapshot.WriteString(relation)
	}
	for index, value := range append(canaries, canary) {
		if strings.Contains(snapshot.String(), value) {
			t.Fatalf("runtime secret canary %d reached PostgreSQL", index)
		}
	}
}

func runtimeMutationScope(alias string) runtimeapi.MutationScope {
	return runtimeapi.MutationScope{ClientID: "p1-" + alias, CredentialID: uuid.NewString()}
}

func runtimeConfigCommand(ownerID, idempotencyKey string) runtimeapi.SaveRuntimeConfigCommand {
	temperature := 0.2
	return runtimeapi.SaveRuntimeConfigCommand{
		IdempotencyKey: idempotencyKey, OwnerID: ownerID,
		Config: runtimeapi.RuntimeConfig{
			ModelProfile: modelapi.Profile{
				ProfileID: "deepseek-v4", Provider: modelapi.ProviderDeepSeek, Model: "deepseekv4-pro", BaseURL: "https://api.example.invalid/v1",
				SecretRef: "secret:model-primary", Temperature: &temperature, MaxOutputTokens: 4096, ContextWindow: 65536,
			},
			ProjectProfile: "Follow the project policy.", ContextMessageLimit: 64, MemoryMessageLimit: 16, MaxSteps: 24,
			EnabledTools:  []string{"task.create", "knowledge.query", "task.create"},
			KnowledgeRefs: []string{"knowledge:primary"}, MCPServerIDs: []string{"mcp:project"}, RecipeIDs: []string{"recipe:private"},
		},
	}
}

func pairedRuntimeConversation(ownerID, conversationID string) runtimeapi.Conversation {
	return runtimeapi.Conversation{
		OwnerID: ownerID, ConversationID: conversationID, Summary: "Earlier deployment planning context.",
		Messages: []modelapi.Message{
			{Role: modelapi.RoleUser, Content: "Compare the current state."},
			{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{
				{Index: 0, ID: "call-status", Type: "function", Function: modelapi.FunctionCall{Name: "task.status", Arguments: `{}`}},
				{Index: 1, ID: "call-knowledge", Type: "function", Function: modelapi.FunctionCall{Name: "knowledge.query", Arguments: `{"query":"state"}`}},
			}},
			{Role: modelapi.RoleTool, ToolCallID: "call-status", Name: "task.status", Content: `{"status":"planning"}`},
			{Role: modelapi.RoleTool, ToolCallID: "call-knowledge", Name: "knowledge.query", Content: `{"matches":1}`},
			{Role: modelapi.RoleAssistant, Content: "The planning task is active."},
		},
	}
}
