package agentcapability

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type systemPromptStoreStub struct {
	configStoreStub
	calls int
	owner string
	value coreconfig.SystemPrompt
}

func (s *systemPromptStoreStub) GetSystemPrompt(context.Context) (coreconfig.SystemPrompt, error) {
	return s.value, nil
}
func (s *systemPromptStoreStub) UpdateSystemPrompt(_ context.Context, owner string, update coreconfig.SystemPromptUpdate) (coreconfig.SystemPrompt, error) {
	s.calls++
	s.owner = owner
	s.value = coreconfig.SystemPrompt{Prompt: update.Prompt, Revision: update.ExpectedRevision + 1}
	return s.value, nil
}

func TestGlobalSystemPromptCapabilityValidatesAuthorityAndShape(t *testing.T) {
	store := &systemPromptStoreStub{}
	cap := NewConfigCapability(store)
	if len(cap.Descriptor().GetOperations()) != 4 {
		t.Fatal("global prompt operations not published")
	}
	for _, operation := range []string{"get_system_prompt", "update_system_prompt"} {
		if _, err := cap.HandleOperation(context.Background(), operation, []byte(`{}`)); err == nil {
			t.Fatal("anonymous setting access accepted")
		}
	}
	for _, raw := range []string{
		`{}`, `{"idempotency_key":"` + uuid.NewString() + `","system_prompt":"text"}`,
		`{"idempotency_key":"` + uuid.NewString() + `","expected_revision":0}`,
		`{"idempotency_key":"` + uuid.NewString() + `","expected_revision":0,"system_prompt":null}`,
		`{"idempotency_key":"` + uuid.NewString() + `","expected_revision":-1,"system_prompt":""}`,
		`{"idempotency_key":"` + uuid.NewString() + `","expected_revision":0,"system_prompt":"","owner_id":"attacker"}`,
	} {
		if _, err := cap.HandleOperation(capabilityTestContext(), "update_system_prompt", []byte(raw)); !errors.Is(err, coreconfig.ErrInvalid) {
			t.Fatalf("invalid update accepted: %v", err)
		}
	}
	update := coreconfig.SystemPromptUpdate{IdempotencyKey: uuid.NewString(), Prompt: strings.Repeat("你", coreconfig.MaxSystemPromptBytes/3+1)}
	raw, _ := json.Marshal(update)
	if _, err := cap.HandleOperation(capabilityTestContext(), "update_system_prompt", raw); !errors.Is(err, coreconfig.ErrInvalid) {
		t.Fatal("UTF-8 byte limit not enforced")
	}
	if store.calls != 0 {
		t.Fatal("invalid inputs reached storage")
	}
	update.Prompt = ""
	raw, _ = json.Marshal(update)
	if _, err := cap.HandleOperation(capabilityTestContext(), "update_system_prompt", raw); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.owner != "owner-1" || store.value.Revision != 1 || store.value.Prompt != "" {
		t.Fatal("owner-bound empty update lost")
	}
	if _, err := cap.HandleOperation(capabilityTestContext(), "get_system_prompt", []byte(`{"model_profile_id":"different"}`)); err == nil {
		t.Fatal("global read accepted model binding")
	}
}

func TestModelSyncRejectsRetiredSystemPromptField(t *testing.T) {
	service, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cap := &coreModelCapability{service: service}
	raw := `{"idempotency_key":"` + uuid.NewString() + `","entries":[{"client_profile_id":"chat","provider":"openai","request_dialect":"openai_compatible_chat_v1","model":"test","api_key":"test","system_prompt":"must not become a model override"}]}`
	if _, err = cap.HandleOperation(capabilityTestContext(), "sync_models", []byte(raw)); !errors.Is(err, coremodel.ErrInvalidProfile) {
		t.Fatalf("retired field accepted: %v", err)
	}
}
