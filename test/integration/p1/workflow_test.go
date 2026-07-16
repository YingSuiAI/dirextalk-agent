package p1_test

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestRuntimeServiceEinoPlanningWorkflowPersistsAndRecoversOnPostgreSQL18(t *testing.T) {
	database := newSiblingDatabase(t)
	credential := createRuntimeCredential(t, database.store)
	requestID := uuid.NewString()
	planArguments := validPlanDraftArguments(t)
	model := &scriptedClient{
		completions: []modelapi.Completion{
			{Message: toolCallMessage("research-call", cloudskill.ToolResearch, `{"goal":"Research an official knowledge node and prepare a provider-neutral deployment plan."}`)},
			{Message: toolCallMessage("official-source-call", publicweb.ToolName, `{"url":"`+offlineOfficialSourceURL+`"}`)},
			{Message: toolCallMessage("plan-draft-call", cloudskill.ToolSubmitPlanDraft, planArguments)},
			{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "The experimental plan draft is ready and waiting for an AWS connection before quoting."}},
		},
		streams: []*scriptedStream{
			{deltas: []modelapi.Delta{{ToolCalls: []modelapi.ToolCall{{
				Index: 0, ID: "status-call", Type: "function", Function: modelapi.FunctionCall{Name: cloudskill.ToolStatus, Arguments: `{}`},
			}}}}},
			{deltas: []modelapi.Delta{{Content: "The durable planning status remains ready."}}},
		},
	}
	official := &offlineOfficialProvider{}
	coordinator, factory := newRuntimeCoordinator(t, database.store, model, official)
	firstServer := startTLSServer(t, database.store, coordinator, credential.pepper)

	putRuntimeConfig(t, firstServer.runtime, credential.serviceKey)
	chatRequest := &agentv1.ChatRequest{
		IdempotencyKey: requestID, OwnerId: testOwnerID, ConversationId: testConversationID,
		Message: "Prepare a safe deployment plan for an official knowledge node.", ExpectedConversationRevision: 0,
	}
	firstResponse := chat(t, firstServer.runtime, credential.serviceKey, chatRequest)
	if firstResponse.GetConversationRevision() != 1 || firstResponse.GetMessage().GetContent() == "" {
		t.Fatalf("first Chat returned an incomplete durable response: %#v", firstResponse)
	}
	if factory.calls.Load() != 1 || len(model.Requests()) != 4 {
		t.Fatalf("first Chat model construction/calls = %d/%d, want 1/4", factory.calls.Load(), len(model.Requests()))
	}
	assertToolAvailable(t, model.Requests()[0], publicweb.ToolName)
	assertToolAvailable(t, model.Requests()[0], cloudskill.ToolStatus)
	assertToolAvailable(t, model.Requests()[0], cloudskill.ToolRecipeDraft)
	if official.calls.Load() != 1 {
		t.Fatalf("offline official-source evidence calls = %d, want 1", official.calls.Load())
	}

	replayed := chat(t, firstServer.runtime, credential.serviceKey, chatRequest)
	if !proto.Equal(firstResponse, replayed) || factory.calls.Load() != 1 || len(model.Requests()) != 4 {
		t.Fatalf("same-caller completed replay was not exact or re-executed model: equal=%t factory=%d calls=%d", proto.Equal(firstResponse, replayed), factory.calls.Load(), len(model.Requests()))
	}

	tampered := proto.Clone(chatRequest).(*agentv1.ChatRequest)
	tampered.Message = "Reuse the idempotency key with different input."
	assertChatCode(t, firstServer.runtime, credential.serviceKey, tampered, codes.AlreadyExists)
	stale := proto.Clone(chatRequest).(*agentv1.ChatRequest)
	stale.IdempotencyKey = uuid.NewString()
	stale.Message = "This request intentionally carries a stale revision."
	assertChatCode(t, firstServer.runtime, credential.serviceKey, stale, codes.Aborted)
	secretCanary := "sk-test-p1-canary-0123456789abcdefghijklmnopqrstuvwxyz"
	secretRequest := proto.Clone(chatRequest).(*agentv1.ChatRequest)
	secretRequest.IdempotencyKey = uuid.NewString()
	secretRequest.Message = "Reject this synthetic credential: " + secretCanary
	assertChatCode(t, firstServer.runtime, credential.serviceKey, secretRequest, codes.InvalidArgument)
	if factory.calls.Load() != 1 || len(model.Requests()) != 4 {
		t.Fatal("replay/conflict/revision/secret failures reached the model")
	}

	taskID := assertPlanningProjection(t, database, credential, requestID)
	if len(firstResponse.GetRelatedTaskIds()) != 1 || firstResponse.GetRelatedTaskIds()[0] != taskID || len(firstResponse.GetRelatedPlanIds()) != 0 {
		t.Fatalf("Chat did not return the durable planning Task reference: tasks=%v plans=%v", firstResponse.GetRelatedTaskIds(), firstResponse.GetRelatedPlanIds())
	}
	events := mustEvents(t, database.store, 0)
	if len(events) < 7 {
		t.Fatalf("planning workflow emitted %d events, want task creation plus three running/finished steps", len(events))
	}
	assertMonotonicTaskEvents(t, events, taskID)

	streamRequest := &agentv1.StreamChatRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: testOwnerID, ConversationId: testConversationID,
		Message: "Summarize the current durable planning state.", ExpectedConversationRevision: 1,
	}
	streamDone := streamAndAssertCommittedDone(t, database, firstServer.runtime, credential.serviceKey, streamRequest)
	if streamDone.GetResponse().GetConversationRevision() != 2 {
		t.Fatalf("stream completion conversation revision = %d, want 2", streamDone.GetResponse().GetConversationRevision())
	}
	if len(streamDone.GetResponse().GetRelatedTaskIds()) != 1 || streamDone.GetResponse().GetRelatedTaskIds()[0] != taskID {
		t.Fatalf("Stream Done did not return the bound planning Task: %v", streamDone.GetResponse().GetRelatedTaskIds())
	}
	if factory.calls.Load() != 2 || len(model.Requests()) != 6 {
		t.Fatalf("fresh StreamChat model construction/calls = %d/%d, want 2/6", factory.calls.Load(), len(model.Requests()))
	}

	firstServer.Close()
	restartedStore, err := postgres.New(database.pool, database.instance)
	if err != nil {
		t.Fatalf("reopen PostgreSQL Store failed (%T)", err)
	}
	restartModel := &scriptedClient{}
	restartOfficial := &offlineOfficialProvider{}
	restartedCoordinator, restartedFactory := newRuntimeCoordinator(t, restartedStore, restartModel, restartOfficial)
	restartedServer := startTLSServer(t, restartedStore, restartedCoordinator, credential.pepper)

	restartedReplay := chat(t, restartedServer.runtime, credential.serviceKey, chatRequest)
	if !proto.Equal(firstResponse, restartedReplay) {
		t.Fatal("completed Chat response snapshot changed after Store/coordinator restart")
	}
	replayedStream := receiveStream(t, restartedServer.runtime, credential.serviceKey, streamRequest)
	if len(replayedStream) != 1 || replayedStream[0].GetDone() == nil || !proto.Equal(streamDone.GetResponse(), replayedStream[0].GetDone().GetResponse()) {
		t.Fatalf("completed StreamChat restart replay was not one exact Done event: %#v", replayedStream)
	}
	if restartedFactory.calls.Load() != 0 || len(restartModel.Requests()) != 0 || restartOfficial.calls.Load() != 0 {
		t.Fatal("completed restart replay re-executed model or tools")
	}

	cursor := events[0].Seq
	restartedTail, err := restartedStore.EventsAfter(context.Background(), cursor, 1000)
	if err != nil {
		t.Fatalf("resume durable event cursor after restart failed (%T)", err)
	}
	if len(restartedTail) != len(events)-1 || (len(restartedTail) > 0 && restartedTail[0].Seq != events[1].Seq) {
		t.Fatalf("event cursor restart result count/first = %d/%d, want %d/%d", len(restartedTail), firstEventSeq(restartedTail), len(events)-1, events[1].Seq)
	}
	assertSecretAbsentFromEveryAgentTable(t, database, secretCanary)

	restartedServer.Close()
	database.Close() // Includes independent 0 database / 0 role read-back.
}

func putRuntimeConfig(t *testing.T, client agentv1.RuntimeServiceClient, serviceKey string) {
	t.Helper()
	ctx, cancel := rpcContext(serviceKey, 10*time.Second)
	defer cancel()
	response, err := client.PutRuntimeConfig(ctx, &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: testOwnerID, ExpectedRevision: 0,
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile: &agentv1.ModelProfile{
				ProfileId: "scripted-p1", MaxOutputTokens: 4096,
			},
			ProjectProfile:      "Use typed, secret-free tools and never approve or provision resources.",
			ContextMessageLimit: 96, MemoryMessageLimit: 64, MaxSteps: 12,
			EnabledTools: []string{
				cloudskill.ToolResearch, cloudskill.ToolSubmitPlanDraft, cloudskill.ToolStatus,
				cloudskill.ToolRecipeDraft, publicweb.ToolName,
			},
		},
	})
	if err != nil {
		t.Fatalf("PutRuntimeConfig failed: %s", status.Code(err))
	}
	if response.GetConfig().GetRevision() != 1 {
		t.Fatalf("runtime config revision = %d, want 1", response.GetConfig().GetRevision())
	}
}

func chat(t *testing.T, client agentv1.RuntimeServiceClient, serviceKey string, request *agentv1.ChatRequest) *agentv1.ChatResponse {
	t.Helper()
	ctx, cancel := rpcContext(serviceKey, 20*time.Second)
	defer cancel()
	response, err := client.Chat(ctx, request)
	if err != nil {
		t.Fatalf("Chat failed: %s", status.Code(err))
	}
	return response
}

func assertChatCode(t *testing.T, client agentv1.RuntimeServiceClient, serviceKey string, request *agentv1.ChatRequest, expected codes.Code) {
	t.Helper()
	ctx, cancel := rpcContext(serviceKey, 10*time.Second)
	defer cancel()
	response, err := client.Chat(ctx, request)
	if status.Code(err) != expected || response != nil {
		t.Fatalf("Chat failure code/response = %s/%t, want %s/false", status.Code(err), response != nil, expected)
	}
}

func assertPlanningProjection(t *testing.T, database *siblingDatabase, credential testCredential, requestID string) string {
	t.Helper()
	listed, err := database.store.List(context.Background(), task.ListQuery{OwnerID: testOwnerID, PageSize: 10})
	if err != nil || len(listed.Tasks) != 1 {
		t.Fatalf("list durable planning Task failed: count=%d err=%T", len(listed.Tasks), err)
	}
	item := listed.Tasks[0]
	if item.ExecutionStatus != task.ExecutionFinished || item.OutcomeStatus != task.OutcomeSucceeded || item.RetentionPolicy != task.RetentionEphemeralAutoDestroy {
		t.Fatalf("planning Task terminal state = %s/%s/%s", item.ExecutionStatus, item.OutcomeStatus, item.RetentionPolicy)
	}
	steps, err := database.store.ListSteps(context.Background(), item.TaskID)
	if err != nil || len(steps) != 3 {
		t.Fatalf("list planning Task steps failed: count=%d err=%T", len(steps), err)
	}
	wantNames := []string{cloudskill.StepResearchOfficialSources, cloudskill.StepDraftRecipe, cloudskill.StepPrepareResourceCandidates}
	for index, step := range steps {
		if step.Name != wantNames[index] || step.ExecutionStatus != task.ExecutionFinished || step.OutcomeStatus != task.OutcomeSucceeded || step.ExecutorKind != task.ExecutorControlPlane {
			t.Fatalf("planning step %d = %s/%s/%s/%s", index, step.Name, step.ExecutionStatus, step.OutcomeStatus, step.ExecutorKind)
		}
	}
	if !strings.HasPrefix(steps[0].ResultRef, "planning://official-source-evidence/sha256:") {
		t.Fatalf("research step result_ref is not durable evidence: %q", steps[0].ResultRef)
	}
	var evidenceCount int
	if err := database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM planning_official_source_evidence
		WHERE task_id=$1 AND caller_client_id=$2 AND request_id=$3`, item.TaskID, testClientID, requestID).Scan(&evidenceCount); err != nil || evidenceCount != 1 {
		t.Fatalf("durable official evidence rows=%d err=%T", evidenceCount, err)
	}
	scope := planningScope(credential.credential)
	binding := planningBinding(requestID)
	draft, found, err := database.store.GetRecipeDraft(context.Background(), scope, binding)
	if err != nil || !found {
		t.Fatalf("load persisted RecipeDraft failed: found=%t err=%T", found, err)
	}
	digest, err := draft.Recipe.Digest()
	if err != nil || draft.Digest != digest || draft.Recipe.Maturity != recipe.MaturityExperimental || draft.Revision != 1 {
		t.Fatalf("persisted RecipeDraft digest/maturity/revision invalid: digest_match=%t maturity=%s revision=%d err=%T", draft.Digest == digest, draft.Recipe.Maturity, draft.Revision, err)
	}
	session, err := database.store.GetResearch(context.Background(), scope, binding)
	if err != nil {
		t.Fatalf("load planning research projection failed (%T)", err)
	}
	if session.TaskID != item.TaskID || session.QuoteState != planning.QuoteAwaitingConnection || session.CandidateRevision != 1 || len(session.Candidates) != 3 {
		t.Fatalf("planning projection = task:%s quote:%s revision:%d candidates:%d", session.TaskID, session.QuoteState, session.CandidateRevision, len(session.Candidates))
	}
	tiers := make([]planning.CandidateTier, 0, len(session.Candidates))
	for _, candidate := range session.Candidates {
		tiers = append(tiers, candidate.Tier)
	}
	sort.Slice(tiers, func(left, right int) bool { return tiers[left] < tiers[right] })
	if !reflect.DeepEqual(tiers, []planning.CandidateTier{planning.TierEconomy, planning.TierPerformance, planning.TierRecommended}) {
		t.Fatalf("persisted candidate tiers = %v", tiers)
	}
	return item.TaskID
}

func streamAndAssertCommittedDone(t *testing.T, database *siblingDatabase, client agentv1.RuntimeServiceClient, serviceKey string, request *agentv1.StreamChatRequest) *agentv1.ChatDone {
	t.Helper()
	events := receiveStream(t, client, serviceKey, request)
	var done *agentv1.ChatDone
	for _, event := range events {
		if event.GetDone() == nil {
			continue
		}
		done = event.GetDone()
		var state string
		var requestRevision, conversationRevision int64
		err := database.pool.QueryRow(context.Background(), `SELECT state, conversation_revision FROM runtime_requests WHERE request_id=$1`, request.GetIdempotencyKey()).Scan(&state, &requestRevision)
		if err != nil {
			t.Fatalf("read StreamChat request commit failed (%T)", err)
		}
		err = database.pool.QueryRow(context.Background(), `SELECT revision FROM runtime_conversations WHERE owner_id=$1 AND conversation_id=$2`, testOwnerID, testConversationID).Scan(&conversationRevision)
		if err != nil || state != "completed" || requestRevision != 2 || conversationRevision != 2 {
			t.Fatalf("Done observed before durable commit: state=%s request_revision=%d conversation_revision=%d err=%T", state, requestRevision, conversationRevision, err)
		}
	}
	if done == nil || events[len(events)-1].GetDone() == nil {
		t.Fatalf("StreamChat did not end with Done: %#v", events)
	}
	return done
}

func receiveStream(t *testing.T, client agentv1.RuntimeServiceClient, serviceKey string, request *agentv1.StreamChatRequest) []*agentv1.StreamChatResponse {
	t.Helper()
	ctx, cancel := rpcContext(serviceKey, 20*time.Second)
	defer cancel()
	stream, err := client.StreamChat(ctx, request)
	if err != nil {
		t.Fatalf("open StreamChat failed: %s", status.Code(err))
	}
	var events []*agentv1.StreamChatResponse
	for {
		event, receiveErr := stream.Recv()
		if receiveErr == io.EOF {
			break
		}
		if receiveErr != nil {
			t.Fatalf("receive StreamChat failed: %s", status.Code(receiveErr))
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("StreamChat returned no events")
	}
	return events
}

func mustEvents(t *testing.T, store *postgres.Store, after int64) []task.Event {
	t.Helper()
	events, err := store.EventsAfter(context.Background(), after, 1000)
	if err != nil {
		t.Fatalf("read durable events failed (%T)", err)
	}
	return events
}

func assertMonotonicTaskEvents(t *testing.T, events []task.Event, taskID string) {
	t.Helper()
	seenTask := false
	for index, event := range events {
		if event.Seq <= 0 || (index > 0 && event.Seq <= events[index-1].Seq) {
			t.Fatalf("event sequence is not strictly monotonic at %d: %d", index, event.Seq)
		}
		if event.AggregateID == taskID {
			seenTask = true
		}
	}
	if !seenTask {
		t.Fatal("planning Task event is missing from the durable cursor")
	}
}

func firstEventSeq(events []task.Event) int64 {
	if len(events) == 0 {
		return 0
	}
	return events[0].Seq
}

func assertSecretAbsentFromEveryAgentTable(t *testing.T, database *siblingDatabase, canary string) {
	t.Helper()
	rows, err := database.pool.Query(context.Background(), `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=current_schema() ORDER BY tablename`)
	if err != nil {
		t.Fatalf("list Agent tables for secret canary failed (%T)", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			t.Fatalf("scan Agent table name failed (%T)", err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate Agent table names failed (%T)", err)
	}
	for _, table := range tables {
		query := `SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM ` + pgx.Identifier{table}.Sanitize() + ` AS item`
		var snapshot string
		if err := database.pool.QueryRow(context.Background(), query).Scan(&snapshot); err != nil {
			t.Fatalf("scan Agent table %s for secret canary failed (%T)", table, err)
		}
		if strings.Contains(snapshot, canary) {
			t.Fatalf("synthetic secret canary reached Agent table %s", table)
		}
	}
}

func toolCallMessage(id, name, arguments string) modelapi.Message {
	return modelapi.Message{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{{
		ID: id, Type: "function", Function: modelapi.FunctionCall{Name: name, Arguments: arguments},
	}}}
}

func assertToolAvailable(t *testing.T, request modelapi.CompletionRequest, name string) {
	t.Helper()
	for _, tool := range request.Tools {
		if tool.Name == name {
			return
		}
	}
	t.Fatalf("model request did not include enabled tool %q", name)
}

func validPlanDraftArguments(t *testing.T) string {
	t.Helper()
	retrievedAt := offlineOfficialRetrievedAt()
	recipeInput := struct {
		Name         string                        `json:"name"`
		Sources      []recipe.SourceV1             `json:"sources"`
		Requirements recipe.ResourceRequirementsV1 `json:"requirements"`
		Install      recipe.InstallContractV1      `json:"install"`
		Health       recipe.HealthContractV1       `json:"health"`
		Lifecycle    recipe.LifecycleContractV1    `json:"lifecycle"`
	}{
		Name: "Official knowledge node",
		Sources: []recipe.SourceV1{{
			URL: offlineOfficialSourceURL, Version: "v1.0.0",
			Commit: strings.Repeat("a", 40), ArtifactDigest: "sha256:" + strings.Repeat("b", 64),
			ContentDigest: offlineOfficialContentDigest(), License: "Apache-2.0", RetrievedAt: retrievedAt, Official: true,
		}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install: recipe.InstallContractV1{
			TimeoutSeconds: 1800, CheckpointNames: []string{"installed"},
			Steps: []recipe.InstallStepV1{{ID: "install", Summary: "Install the digest-pinned artifact", TimeoutSeconds: 1200}},
		},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live"},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready"},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check"},
		},
		Lifecycle: recipe.LifecycleContractV1{
			Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback",
			Backup: "backup", Restore: "restore", Destroy: "destroy",
		},
	}
	type candidate struct {
		Architecture recipe.Architecture `json:"architecture"`
		VCPU         uint32              `json:"vcpu"`
		MemoryMiB    uint64              `json:"memory_mib"`
		DiskGiB      uint64              `json:"disk_gib"`
		Rationale    string              `json:"rationale"`
	}
	input := struct {
		Recipe      any       `json:"recipe"`
		Economy     candidate `json:"economy"`
		Recommended candidate `json:"recommended"`
		Performance candidate `json:"performance"`
	}{
		Recipe:      recipeInput,
		Economy:     candidate{Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40, Rationale: "meets the official minimum requirements"},
		Recommended: candidate{Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80, Rationale: "adds headroom for normal indexing work"},
		Performance: candidate{Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160, Rationale: "adds headroom for larger knowledge imports"},
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("encode scripted plan draft failed (%T)", err)
	}
	return string(encoded)
}
