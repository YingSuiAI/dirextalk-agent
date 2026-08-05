package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
	"github.com/google/uuid"
)

func TestCoreVoiceProfileResolverReadsMountedSecretsWithoutPersistingThem(t *testing.T) {
	const conversationID = "11111111-1111-4111-8111-111111111111"
	const speechID = "22222222-2222-4222-8222-222222222222"
	repo := coremodel.NewMemoryProfileRepository()
	profiles, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "openrouter-key"
	if _, err := profiles.Create(context.Background(), coremodel.CreateProfileCommand{IdempotencyKey: "33333333-3333-4333-8333-333333333333", Spec: coremodel.ProfileSpec{ID: conversationID, DisplayName: "voice conversation", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://openrouter.ai/api/v1", Model: "openai/gpt-4o-mini", APIKey: &key}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	secretFile := func(name, value string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg := config.Config{CoreVoiceProvider: "volc_voice", CoreVoiceAppID: "123456789012345678901234", CoreVoiceConversationProfileID: conversationID, CoreVoiceSpeechProfileID: speechID, CoreVoiceWebhookURL: "https://message.example.test/_p2p/agent/voice/webhook", CoreVoiceCustomLLMURL: "https://message.example.test/_p2p/agent/voice/volc/custom-llm", CoreVoiceAccessKeyIDFile: secretFile("access", "access-key"), CoreVoiceSecretAccessKeyFile: secretFile("secret", "secret-key"), CoreVoiceRTCAppKeyFile: secretFile("rtc", "rtc-key"), CoreVoiceWebhookSecretFile: secretFile("webhook", "callback-secret")}
	binding, err := (coreVoiceProfileResolver{profiles: profiles, config: cfg}).Resolve(context.Background(), "owner", corevoice.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if binding.ConversationProfileID != conversationID || binding.SpeechProfileID != speechID || binding.AccessKeyID != "access-key" || binding.SecretAccessKey != "secret-key" || binding.RTCAppKey != "rtc-key" {
		t.Fatalf("binding=%+v", binding)
	}
	if binding.WebhookSecret == "" {
		t.Fatal("callback secret missing")
	}
}

func TestCoreConversationVoiceRunnerReplaysPinnedTurnAfterProfileRotation(t *testing.T) {
	const profileID = "33333333-3333-4333-8333-333333333333"
	repo := coremodel.NewMemoryProfileRepository()
	profiles, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := "old-conversation-key"
	if _, err := profiles.Create(context.Background(), coremodel.CreateProfileCommand{
		IdempotencyKey: "44444444-4444-4444-8444-444444444444",
		Spec:           coremodel.ProfileSpec{ID: profileID, DisplayName: "voice conversation", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.invalid", Model: "voice-model", APIKey: &oldKey},
	}); err != nil {
		t.Fatal(err)
	}
	conversation := &voiceConversationStub{events: []coreconversation.TurnEvent{{Kind: coreconversation.TurnEventDone}}}
	runner := coreConversationVoiceRunner{conversation: conversation, profiles: profiles}
	session := corevoice.Session{ConversationID: "voice-room", ConversationProfileID: profileID}
	voiceTurn := corevoice.Turn{ID: uuid.NewString(), Transcript: "hello"}
	var emitted int
	emit := func(event corevoice.StreamEvent) error {
		if event.Event == "done" {
			emitted++
		}
		return nil
	}
	if err := runner.Run(context.Background(), "owner", session, voiceTurn, emit); err != nil {
		t.Fatal(err)
	}
	if len(conversation.starts) != 1 || conversation.existing == nil || conversation.existing.ProfileSnapshot.APIKey != oldKey || conversation.existing.ProfileSnapshot.CredentialVersion != 1 {
		t.Fatalf("initial turn binding=%+v starts=%d", conversation.existing, len(conversation.starts))
	}
	newKey := "rotated-conversation-key"
	if _, err := profiles.Update(context.Background(), coremodel.UpdateProfileCommand{
		ID:               profileID,
		IdempotencyKey:   "55555555-5555-4555-8555-555555555555",
		ExpectedRevision: 1,
		Spec:             coremodel.ProfileSpec{ID: profileID, Patch: true, DisplayName: "voice conversation", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.invalid", Model: "voice-model", APIKey: &newKey},
	}); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), "owner", session, voiceTurn, emit); err != nil {
		t.Fatalf("replay after profile rotation: %v", err)
	}
	if len(conversation.starts) != 1 {
		t.Fatalf("replay started a second turn after profile rotation: %d", len(conversation.starts))
	}
	if conversation.existing.ProfileSnapshot.APIKey != oldKey || conversation.existing.ProfileSnapshot.CredentialVersion != 1 {
		t.Fatalf("replay changed pinned snapshot: %+v", conversation.existing.ProfileSnapshot)
	}
	if emitted != 2 {
		t.Fatalf("done events=%d, want initial and replay", emitted)
	}
}

type voiceConversationStub struct {
	existing *coreconversation.Turn
	starts   []coreconversation.TurnStartCommand
	events   []coreconversation.TurnEvent
}

func (s *voiceConversationStub) GetTurnByRequestID(_ context.Context, _ string) (coreconversation.Turn, error) {
	if s.existing == nil {
		return coreconversation.Turn{}, coreconversation.ErrConflict
	}
	return *s.existing, nil
}

func (s *voiceConversationStub) StartTurn(_ context.Context, cmd coreconversation.TurnStartCommand) (coreconversation.Turn, error) {
	s.starts = append(s.starts, cmd)
	if s.existing != nil {
		return *s.existing, nil
	}
	s.existing = &coreconversation.Turn{ID: uuid.NewString(), RequestID: cmd.RequestID, ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, ProfileSnapshot: cmd.ProfileSnapshot, State: coreconversation.TurnAccepted, Revision: 1}
	return *s.existing, nil
}

func (s *voiceConversationStub) WatchTurnEvents(_ context.Context, _ string, _ int64, _ int) (<-chan coreconversation.TurnEvent, error) {
	if s.existing == nil {
		return nil, errors.New("turn not started")
	}
	out := make(chan coreconversation.TurnEvent, len(s.events))
	for _, event := range s.events {
		out <- event
	}
	close(out)
	return out, nil
}

func (s *voiceConversationStub) CancelTurn(_ context.Context, _ coreconversation.TurnCancelCommand) (coreconversation.Turn, error) {
	if s.existing == nil {
		return coreconversation.Turn{}, coreconversation.ErrConflict
	}
	return *s.existing, nil
}
