package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
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
