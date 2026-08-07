package coreruntime

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type memoryTestClient struct {
	content string
	calls   int
}

func (c *memoryTestClient) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	c.calls++
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: c.content}}, nil
}
func (*memoryTestClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, io.EOF
}

type memoryTestProfiles struct{}

func (memoryTestProfiles) ResolveExecutionProfile(context.Context, coretask.ModelProfileSnapshot) (coremodel.Profile, error) {
	return coremodel.Profile{ID: uuid.NewString(), Provider: coremodel.ProviderOpenAICompatible, Model: "test"}, nil
}

type memoryTestTurns struct {
	turn     coreconversation.Turn
	hasTools bool
}

func (r memoryTestTurns) GetTurn(context.Context, string) (coreconversation.Turn, error) {
	return r.turn, nil
}
func (r memoryTestTurns) HasTurnToolAttempts(context.Context, string) (bool, error) {
	return r.hasTools, nil
}

type memoryTestKnowledge struct {
	sources map[string]coreknowledge.Source
	values  map[string]coreknowledge.Memory
	creates int
}

func newMemoryTestKnowledge() *memoryTestKnowledge {
	return &memoryTestKnowledge{sources: map[string]coreknowledge.Source{}, values: map[string]coreknowledge.Memory{}}
}

func (k *memoryTestKnowledge) CreateMemory(_ context.Context, command coreknowledge.MemoryCommand) (coreknowledge.Source, error) {
	if source, ok := k.sources[command.SourceID]; ok {
		return source, nil
	}
	k.creates++
	now := time.Now().UTC()
	source := coreknowledge.Source{ID: command.SourceID, Kind: coreknowledge.SourceKindMemory, Status: coreknowledge.SourceStatusReady, Title: command.Title, Digest: memoryDigest(command.Content), Revision: 1, CreatedAt: now, UpdatedAt: now}
	k.sources[source.ID] = source
	k.values[source.ID] = coreknowledge.Memory{ID: source.ID, Title: source.Title, Content: command.Content, Tags: command.Tags, Revision: source.Revision, CreatedAt: now, UpdatedAt: now}
	return source, nil
}
func (k *memoryTestKnowledge) GetMemory(_ context.Context, id string) (coreknowledge.Memory, error) {
	value, ok := k.values[id]
	if !ok {
		return coreknowledge.Memory{}, coreknowledge.ErrNotFound
	}
	return value, nil
}

type memoryTestRepository struct {
	slots   map[corememory.SlotKey]corememory.Slot
	applies int
}

func newMemoryTestRepository() *memoryTestRepository {
	return &memoryTestRepository{slots: map[corememory.SlotKey]corememory.Slot{}}
}

func (r *memoryTestRepository) Get(_ context.Context, key corememory.SlotKey) (corememory.Slot, error) {
	value, ok := r.slots[key.Normalize()]
	if !ok {
		return corememory.Slot{}, corememory.ErrNotFound
	}
	return value, nil
}
func (r *memoryTestRepository) List(_ context.Context, scope corememory.Scope, conversationID string, includeDeleted bool, limit int) ([]corememory.Slot, error) {
	out := make([]corememory.Slot, 0, limit)
	for _, value := range r.slots {
		if value.Scope == scope && value.ConversationID == conversationID && (includeDeleted || !value.Deleted) && len(out) < limit {
			out = append(out, value)
		}
	}
	return out, nil
}
func (r *memoryTestRepository) Apply(_ context.Context, command corememory.ApplyCommand) (corememory.Slot, error) {
	key := command.Slot.Normalize()
	current, exists := r.slots[key]
	if command.Action == corememory.ChangeCreate && exists {
		return corememory.Slot{}, corememory.ErrRevisionConflict
	}
	if command.Action != corememory.ChangeCreate && (!exists || current.Revision != command.ExpectedRevision) {
		return corememory.Slot{}, corememory.ErrRevisionConflict
	}
	r.applies++
	revision := int64(1)
	createdAt := time.Now().UTC()
	if exists {
		revision, createdAt = current.Revision+1, current.CreatedAt
	}
	value := corememory.Slot{ID: memoryUUID("slot", string(key.Scope), key.CanonicalKey), SlotKey: key, Type: command.Type, Sensitivity: command.Sensitivity, CurrentSourceID: command.SourceID, CurrentSourceRevision: command.SourceRevision, CurrentTextDigest: command.TextDigest, Revision: revision, Deleted: command.Action == corememory.ChangeDelete, Confidence: command.Confidence, Importance: command.Importance, CandidateSchemaVersion: command.CandidateSchemaVersion, PolicyVersion: command.PolicyVersion, SourceConversationID: command.SourceConversationID, SourceTurnID: command.SourceTurnID, CreatedAt: createdAt, UpdatedAt: time.Now().UTC()}
	if value.Deleted {
		value.CurrentSourceID, value.CurrentSourceRevision, value.CurrentTextDigest = "", 0, ""
	}
	r.slots[key] = value
	return value, nil
}

type memoryTestLedger struct {
	latest coretask.ModelRoundLedger
}

func (l *memoryTestLedger) LatestModelRound(context.Context, string, uint32) (coretask.ModelRoundLedger, error) {
	if l.latest.State == "" {
		return coretask.ModelRoundLedger{}, coretask.ErrNotFound
	}
	return l.latest, nil
}
func (l *memoryTestLedger) PrepareModelRound(_ context.Context, command coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	l.latest = coretask.ModelRoundLedger{TaskID: command.TaskID, Attempt: command.Attempt, Round: command.Round, LeaseEpoch: command.LeaseEpoch, TaskRevision: command.ExpectedRevision, InputDigest: command.InputDigest, State: coretask.ModelRoundPrepared}
	return l.latest, nil
}
func (l *memoryTestLedger) MarkModelDispatched(_ context.Context, command coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	l.latest.State, l.latest.TaskRevision = coretask.ModelRoundDispatched, command.ExpectedRevision
	return l.latest, nil
}
func (l *memoryTestLedger) CompleteModelRound(_ context.Context, command coretask.ModelResponseCommand) (coretask.ModelRoundLedger, error) {
	l.latest.State, l.latest.TaskRevision, l.latest.Response = coretask.ModelRoundCompleted, command.ExpectedRevision, append([]byte(nil), command.Response...)
	return l.latest, nil
}
func (l *memoryTestLedger) MarkModelUncertain(_ context.Context, command coretask.ModelUncertainCommand) (coretask.ModelRoundLedger, error) {
	l.latest.State, l.latest.TaskRevision = coretask.ModelRoundUncertain, command.ExpectedRevision
	return l.latest, nil
}

func memoryTestTaskAndTurn() (coretask.Task, coreconversation.Turn) {
	profileID, turnID, conversationID, taskID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	response := coreconversation.ChatResponse{ConversationID: conversationID, Message: coreconversation.Message{Role: coreconversation.RoleAssistant, Content: "Understood."}}
	turn := coreconversation.Turn{ID: turnID, ConversationID: conversationID, Prompt: "I prefer concise replies", ProfileID: profileID, State: coreconversation.TurnCompleted, Response: &response}
	snapshot := coretask.ExecutionSnapshot{Model: coretask.ModelProfileSnapshot{ProfileID: profileID, Revision: 1, Provider: string(coremodel.ProviderOpenAICompatible), Model: "test"}}
	now := time.Now().UTC()
	task := coretask.Task{ID: taskID, Spec: coretask.TaskSpec{Kind: coretask.TaskKindMemoryReconcile, ModelProfileID: profileID, Payload: coretask.TaskPayload{MemoryReconcile: &coretask.MemoryReconcileTaskPayload{TurnID: turnID, CandidateSchemaVersion: 1, PolicyVersion: 1}}}, Snapshot: &snapshot, Status: coretask.StatusRunning, Attempt: 1, LeaseEpoch: 1, Revision: 1, Lease: &coretask.Lease{TaskID: taskID, Attempt: 1, Epoch: 1, Holder: "test", ExpiresAt: now.Add(time.Minute)}}
	return task, turn
}

func TestMemoryReconcileHandlerCreatesAndReplaysCanonicalMemory(t *testing.T) {
	task, turn := memoryTestTaskAndTurn()
	client := &memoryTestClient{content: `{"schema_version":1,"candidates":[{"operation":"create","key":"preference.response.length","text":"User prefers concise replies","type":"preference","scope":"owner","confidence":0.98,"importance":0.9,"sensitivity":"low","evidence":"I prefer concise replies","reason":"durable response preference"}]}`}
	memory, knowledge, ledger := newMemoryTestRepository(), newMemoryTestKnowledge(), &memoryTestLedger{}
	handler, err := NewMemoryReconcileHandler(memoryTestProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return client, nil }, memoryTestTurns{turn: turn}, memory, knowledge, ledger)
	if err != nil {
		t.Fatal(err)
	}
	first := handler(context.Background(), task)
	if first.Err != nil || memory.applies != 1 || knowledge.creates != 1 || client.calls != 1 {
		t.Fatalf("first=%+v applies=%d creates=%d calls=%d", first, memory.applies, knowledge.creates, client.calls)
	}
	second := handler(context.Background(), task)
	if second.Err != nil || memory.applies != 1 || knowledge.creates != 1 || client.calls != 1 {
		t.Fatalf("replay=%+v applies=%d creates=%d calls=%d", second, memory.applies, knowledge.creates, client.calls)
	}
}

func TestMemoryReconcileHandlerNeverPersistsSecretCandidate(t *testing.T) {
	task, turn := memoryTestTaskAndTurn()
	turn.Prompt = "remember api_key=sk-supersecret"
	client := &memoryTestClient{content: `{"schema_version":1,"candidates":[{"operation":"create","key":"profile.api.key","text":"sk-supersecret","type":"fact","scope":"owner","confidence":1,"importance":1,"sensitivity":"secret","evidence":"api_key=sk-supersecret","reason":"explicit"}]}`}
	memory, knowledge, ledger := newMemoryTestRepository(), newMemoryTestKnowledge(), &memoryTestLedger{}
	handler, _ := NewMemoryReconcileHandler(memoryTestProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return client, nil }, memoryTestTurns{turn: turn}, memory, knowledge, ledger)
	outcome := handler(context.Background(), task)
	if outcome.Err != nil || memory.applies != 0 || knowledge.creates != 0 {
		t.Fatalf("outcome=%+v applies=%d creates=%d", outcome, memory.applies, knowledge.creates)
	}
	if strings.Contains(string(ledger.latest.Response), "sk-supersecret") {
		t.Fatal("secret candidate was persisted in the durable model receipt")
	}
	var result map[string]any
	if json.Unmarshal(outcome.Result.JSON, &result) != nil || result["created"] != float64(0) {
		t.Fatalf("result=%s", outcome.Result.JSON)
	}
}

func TestMemoryReconcileHandlerSkipsToolDerivedTurn(t *testing.T) {
	task, turn := memoryTestTaskAndTurn()
	client := &memoryTestClient{content: `{}`}
	memory, knowledge, ledger := newMemoryTestRepository(), newMemoryTestKnowledge(), &memoryTestLedger{}
	handler, _ := NewMemoryReconcileHandler(memoryTestProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return client, nil }, memoryTestTurns{turn: turn, hasTools: true}, memory, knowledge, ledger)
	outcome := handler(context.Background(), task)
	if outcome.Err != nil || client.calls != 0 || memory.applies != 0 || knowledge.creates != 0 || !strings.Contains(string(outcome.Result.JSON), "skipped_tool_derived_turn") {
		t.Fatalf("outcome=%+v calls=%d", outcome, client.calls)
	}
}

var _ corememory.Repository = (*memoryTestRepository)(nil)
var _ MemoryKnowledgePort = (*memoryTestKnowledge)(nil)
var _ MemoryModelLedger = (*memoryTestLedger)(nil)
