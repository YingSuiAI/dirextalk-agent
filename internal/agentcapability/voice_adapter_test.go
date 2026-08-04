package agentcapability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type adapterVoiceProfiles struct{}

func (adapterVoiceProfiles) Resolve(context.Context, string, corevoice.CreateRequest) (corevoice.ProfileBinding, error) {
	return corevoice.ProfileBinding{ConversationProfileID: "conversation", SpeechProfileID: "speech", ClientTranscriptEnabled: true}, nil
}

type adapterVoiceProvider struct{}

func (adapterVoiceProvider) Create(_ context.Context, _ string, s corevoice.Session, _ corevoice.ProfileBinding) (corevoice.ProviderSession, error) {
	return corevoice.ProviderSession{Token: "token", AppID: "app", VoiceChatAppID: "voice-app", RoomID: "room", UserID: "user", AIUserID: "ai", ProviderHandle: "handle", ExpiresAt: s.ExpiresAt}, nil
}
func (adapterVoiceProvider) Start(context.Context, string, corevoice.Session, corevoice.ProfileBinding) error {
	return nil
}
func (adapterVoiceProvider) Interrupt(context.Context, string, corevoice.Session, corevoice.ProfileBinding) error {
	return nil
}
func (adapterVoiceProvider) End(context.Context, string, corevoice.Session, corevoice.ProfileBinding) error {
	return nil
}

type adapterVoiceRunner struct{}

func (adapterVoiceRunner) Run(context.Context, string, corevoice.Session, corevoice.Turn, func(corevoice.StreamEvent) error) error {
	return nil
}
func (adapterVoiceRunner) Cancel(context.Context, string, string) error { return nil }

func TestCoreVoiceCapabilityDescriptorAndContextOwner(t *testing.T) {
	service, err := corevoice.NewService(corevoice.NewMemoryStore(), adapterVoiceProfiles{}, adapterVoiceProvider{}, adapterVoiceRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	capability := NewCoreVoiceCapability(service, func(context.Context, string, []byte) error { return nil })
	desc := capability.Descriptor()
	if desc.GetCapabilityId() != "agent.voice.v1" || len(desc.GetOperations()) != 6 {
		t.Fatalf("descriptor=%+v", desc)
	}
	for _, op := range desc.GetOperations() {
		if op.GetInputSchemaJson() == "" || len(op.GetRequiredScopes()) != 1 || op.GetRequiredScopes()[0] != "agent:voice:write" {
			t.Fatalf("operation descriptor=%+v", op)
		}
	}
	call := &capv1.CallContext{ChainId: "chain", RootOperationId: "op-create", Route: "ms→agent", Hop: 1, DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli()}
	permission := &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 4, GrantedScopes: []string{"agent:voice:write"}}
	ctx := capabilityclient.WithCallContext(context.Background(), call, permission)
	raw, err := capability.HandleOperation(ctx, "create_session", []byte(`{"conversation_id":"conversation"}`))
	if err != nil {
		t.Fatal(err)
	}
	var response corevoice.CreateResponse
	if err := json.Unmarshal(raw, &response); err != nil || response.SessionID == "" || response.Token == "" {
		t.Fatalf("response=%s err=%v", raw, err)
	}
	if _, err := capability.HandleOperation(ctx, "start_session", []byte(`{"session_id":"`+response.SessionID+`"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCoreVoiceCapabilityRejectsMissingPermission(t *testing.T) {
	service, err := corevoice.NewService(corevoice.NewMemoryStore(), adapterVoiceProfiles{}, adapterVoiceProvider{}, adapterVoiceRunner{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	capability := NewCoreVoiceCapability(service, nil)
	if _, err := capability.HandleOperation(context.Background(), "create_session", []byte(`{"conversation_id":"conversation"}`)); err == nil {
		t.Fatal("missing permission accepted")
	}
}
