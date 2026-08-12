package agentcapability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
)

type memoryCapabilityStore struct {
	config corememory.Config
	status corememory.Status
}

func (s *memoryCapabilityStore) GetConfig(context.Context) (corememory.Config, error) {
	return s.config, nil
}
func (s *memoryCapabilityStore) UpdateConfig(_ context.Context, mutation corememory.ConfigMutation) (corememory.Config, error) {
	s.config.Enabled = mutation.Enabled
	s.config.Revision++
	return s.config, nil
}
func (s *memoryCapabilityStore) UpdateFact(_ context.Context, mutation corememory.FactMutation) (corememory.Fact, error) {
	return corememory.Fact{ID: "33333333-3333-4333-8333-333333333333", Subject: "user", Predicate: "city", Value: mutation.Value, Kind: "fact", Confidence: 1, ValidFrom: mutation.Now, LastConfirmedAt: mutation.Now}, nil
}
func (s *memoryCapabilityStore) DeleteFact(_ context.Context, mutation corememory.FactMutation) (corememory.FactDeletion, error) {
	return corememory.FactDeletion{FactID: mutation.FactID, Deleted: true}, nil
}
func (s *memoryCapabilityStore) Status(context.Context, int, int) (corememory.Status, error) {
	return s.status, nil
}
func (*memoryCapabilityStore) ClaimObservation(context.Context, time.Time, time.Duration) (corememory.ObservationLease, bool, error) {
	return corememory.ObservationLease{}, false, nil
}
func (*memoryCapabilityStore) ListActiveFacts(context.Context, int) ([]corememory.Fact, error) {
	return nil, nil
}
func (*memoryCapabilityStore) ApplyObservation(context.Context, corememory.ObservationLease, []corememory.Candidate, time.Time) error {
	return nil
}
func (*memoryCapabilityStore) RetryObservation(context.Context, corememory.ObservationLease, string, time.Time) error {
	return nil
}
func (*memoryCapabilityStore) Recall(context.Context, int, int) (corememory.Snapshot, error) {
	return corememory.Snapshot{}, nil
}

func TestMemoryCapabilityPublishesClosedOwnerOperations(t *testing.T) {
	store := &memoryCapabilityStore{
		config: corememory.Config{EmbeddingConfigured: true, EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", EmbeddingModel: "embed"},
		status: corememory.Status{Config: corememory.Config{Enabled: false}, Facts: []corememory.Fact{}, Timeline: []corememory.TimelineEvent{}},
	}
	service, err := corememory.NewService(store, memoryExtractorStub{})
	if err != nil {
		t.Fatal(err)
	}
	capability := NewCoreMemoryCapability(service)
	descriptor := capability.Descriptor()
	if descriptor.CapabilityId != "agent.memory.v1" || len(descriptor.Operations) != 5 {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	operations := make(map[string]bool, len(descriptor.Operations))
	for _, operation := range descriptor.Operations {
		operations[operation.OperationId] = true
	}
	for _, operationID := range []string{"get_config", "update_config", "status", "update_fact", "delete_fact"} {
		if !operations[operationID] {
			t.Fatalf("missing operation %q", operationID)
		}
	}
	ctx := capabilityTestContext()
	if _, err = capability.HandleOperation(ctx, "get_config", []byte(`{"unexpected":true}`)); err == nil {
		t.Fatal("get_config accepted unknown input")
	}
	raw, err := capability.HandleOperation(ctx, "update_config", []byte(`{"idempotency_key":"22222222-2222-4222-8222-222222222222","expected_revision":0,"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var config corememory.Config
	if json.Unmarshal(raw, &config) != nil || !config.Enabled || config.Revision != 1 {
		t.Fatalf("config=%s", raw)
	}
	if _, err = capability.HandleOperation(ctx, "update_fact", []byte(`{"fact_id":"11111111-1111-4111-8111-111111111111","idempotency_key":"44444444-4444-4444-8444-444444444444","value":"Beijing"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = capability.HandleOperation(ctx, "delete_fact", []byte(`{"fact_id":"33333333-3333-4333-8333-333333333333","idempotency_key":"55555555-5555-4555-8555-555555555555"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = capability.HandleOperation(context.Background(), "status", []byte(`{}`)); err == nil {
		t.Fatal("status accepted unauthenticated context")
	}
}

type memoryExtractorStub struct{}

func (memoryExtractorStub) Extract(context.Context, corememory.Observation, []corememory.Fact) ([]corememory.Candidate, error) {
	return nil, nil
}
