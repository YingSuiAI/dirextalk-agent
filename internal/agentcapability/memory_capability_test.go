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
	if descriptor.CapabilityId != "agent.memory.v1" || len(descriptor.Operations) != 3 {
		t.Fatalf("descriptor=%+v", descriptor)
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
	if _, err = capability.HandleOperation(context.Background(), "status", []byte(`{}`)); err == nil {
		t.Fatal("status accepted unauthenticated context")
	}
}

type memoryExtractorStub struct{}

func (memoryExtractorStub) Extract(context.Context, corememory.Observation, []corememory.Fact) ([]corememory.Candidate, error) {
	return nil, nil
}
