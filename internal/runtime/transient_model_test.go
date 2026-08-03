package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	transientmodelsdk "github.com/YingSuiAI/dirextalk-agent/sdk/transientmodel"
)

func TestTransientModelCredentialIsBoundConsumedAndCleared(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	manager, err := secretbootstrap.NewManager(
		secretbootstrap.NewMemoryStore(), secretbootstrap.NewMemoryKeyStore(), rand.Reader,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("client-model-key-canary-that-must-not-persist")
	digest := sha256.Sum256(credential)
	profile := modelapi.Profile{
		ProfileID: "openai:gpt-4.1-mini", Provider: modelapi.ProviderOpenAICompatible,
		Model: "gpt-4.1-mini", BaseURL: "https://api.openai.com/v1",
		MaxOutputTokens: 4096, ContextWindow: 64 * 1024,
	}
	bindingProfile := transientmodelsdk.Profile{
		ProfileID: profile.ProfileID, Provider: string(profile.Provider), Model: profile.Model, BaseURL: profile.BaseURL,
		MaxOutputTokens: int32(profile.MaxOutputTokens), ContextWindow: int32(profile.ContextWindow),
	}
	targetID, err := transientmodelsdk.TargetID("owner-1", "request-1", bindingProfile, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.Create(context.Background(), "message-server-client", secretbootstrap.BindingV1{
		AgentInstanceID: "11111111-2222-4333-8444-555555555555", OwnerID: "owner-1",
		Purpose: transientmodelsdk.CredentialPurpose, TargetID: targetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretbootstrap.Seal(created.Session, credential, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Upload(context.Background(), "message-server-client", created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope); err != nil {
		t.Fatal(err)
	}
	request := ChatRequest{
		RequestID: "request-1", OwnerID: "owner-1", MemoryDisabled: true,
		Messages:          []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
		BootstrapClientID: "message-server-client",
		TransientModel: &TransientModelInvocation{
			Profile: profile, CredentialSessionID: created.Session.SessionID,
			CredentialSessionRevision: 2, CredentialSHA256: digest,
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, credential) || bytes.Contains(encoded, []byte("message-server-client")) {
		t.Fatalf("durable request JSON exposed transient material: %s", encoded)
	}

	var requestResolver *transientSecretResolver
	transientFactory := ModelFactoryFunc(func(ctx context.Context, gotProfile modelapi.Profile, resolver SecretResolver) (modelapi.Client, error) {
		if gotProfile.ProfileID != profile.ProfileID || gotProfile.SecretRef != "transient:"+created.Session.SessionID {
			t.Fatalf("transient profile = %#v", gotProfile)
		}
		resolved, resolveErr := resolver.ResolveSecret(ctx, gotProfile.SecretRef)
		if resolveErr != nil || !bytes.Equal(resolved, credential) {
			t.Fatalf("resolved credential mismatch: %v", resolveErr)
		}
		clear(resolved)
		requestResolver, _ = resolver.(*transientSecretResolver)
		return inertModelClient{}, nil
	})
	runtime := mustTestRuntime(t, Dependencies{
		Engine: &scriptedEngine{generate: func(context.Context, EngineRequest) (EngineResult, error) {
			return finalEngineResult("ok"), nil
		}},
		Models: &recordingModelFactory{client: inertModelClient{}}, TransientModels: transientFactory,
		Tools:   ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) { return nil, nil }),
		Configs: staticConfigRepository{config: validTestConfig()}, Conversations: &recordingConversationRepository{},
		Secrets: inertSecretResolver{}, TransientCredentials: manager, Clock: func() time.Time { return now },
	})
	result, err := runtime.Chat(context.Background(), request)
	if err != nil || result.Message.Content != "ok" {
		t.Fatalf("transient chat result=%#v err=%v", result, err)
	}
	session, err := manager.Get(context.Background(), "message-server-client", created.Session.SessionID)
	if err != nil || session.Status != secretbootstrap.StatusConsumed || session.Revision != 3 {
		t.Fatalf("consumed session=%#v err=%v", session, err)
	}
	if requestResolver == nil {
		t.Fatal("transient resolver was not used")
	}
	for _, value := range requestResolver.credential {
		if value != 0 {
			t.Fatal("request-local credential was not cleared after chat")
		}
	}
}

func TestTransientModelRejectsUnsafeEndpointBeforeModelCall(t *testing.T) {
	t.Parallel()
	request := ChatRequest{
		RequestID: "request-2", OwnerID: "owner-1", MemoryDisabled: true,
		Messages:          []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
		BootstrapClientID: "message-server-client",
		TransientModel: &TransientModelInvocation{
			Profile: modelapi.Profile{
				ProfileID: "client-profile", Provider: modelapi.ProviderOpenAICompatible,
				Model: "gpt-4.1-mini", BaseURL: "http://127.0.0.1/v1",
				MaxOutputTokens: 1024, ContextWindow: 4096,
			},
			CredentialSessionID:       "27b65194-c9c3-4dc6-bca7-79c9a32ed4dc",
			CredentialSessionRevision: 2,
		},
	}
	if _, err := (RuntimeRequestCommand{Request: request, LeaseDuration: time.Minute}).Validated(); err == nil {
		t.Fatal("unsafe transient endpoint passed durable request validation")
	}
}

func TestTransientModelRejectsMalformedDeepSeekCredentialShape(t *testing.T) {
	t.Parallel()
	if !validTransientProviderCredential(
		modelapi.ProviderDeepSeek,
		[]byte("sk-valid-deepseek-key_123456"),
	) {
		t.Fatal("valid DeepSeek credential shape was rejected")
	}
	if validTransientProviderCredential(
		modelapi.ProviderDeepSeek,
		[]byte("sk-valid-deepseek-key_123456`x"),
	) {
		t.Fatal("malformed DeepSeek credential shape was accepted")
	}
	if !validTransientProviderCredential(
		modelapi.ProviderOpenAICompatible,
		[]byte("custom-provider:key"),
	) {
		t.Fatal("custom OpenAI-compatible credential was over-restricted")
	}
}

func TestTransientModelDiscoveryConsumesAndClearsCredential(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	manager, err := secretbootstrap.NewManager(
		secretbootstrap.NewMemoryStore(), secretbootstrap.NewMemoryKeyStore(), rand.Reader,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("client-discovery-key-canary-123456")
	digest := sha256.Sum256(credential)
	profile := modelapi.Profile{
		ProfileID: "model-discovery", Provider: modelapi.ProviderOpenAICompatible,
		Model: "model-discovery", BaseURL: "https://api.openai.com/v1",
		MaxOutputTokens: 4096, ContextWindow: 64 * 1024,
	}
	binding := transientmodelsdk.Profile{
		ProfileID: profile.ProfileID, Provider: string(profile.Provider), Model: profile.Model,
		BaseURL: profile.BaseURL, MaxOutputTokens: 4096, ContextWindow: 64 * 1024,
	}
	targetID, err := transientmodelsdk.TargetID("owner-1", "request-model-list", binding, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.Create(context.Background(), "message-server-client", secretbootstrap.BindingV1{
		AgentInstanceID: "11111111-2222-4333-8444-555555555555", OwnerID: "owner-1",
		Purpose: transientmodelsdk.CredentialPurpose, TargetID: targetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretbootstrap.Seal(created.Session, credential, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Upload(context.Background(), "message-server-client", created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope); err != nil {
		t.Fatal(err)
	}

	var requestResolver *transientSecretResolver
	runtime := mustTestRuntime(t, Dependencies{
		Engine: &scriptedEngine{}, Models: &recordingModelFactory{client: inertModelClient{}},
		ModelDiscovery: ModelDiscoveryFunc(func(ctx context.Context, got modelapi.Profile, resolver SecretResolver) ([]modelapi.Descriptor, error) {
			if got.SecretRef != "transient:"+created.Session.SessionID {
				t.Fatalf("profile = %#v", got)
			}
			resolved, resolveErr := resolver.ResolveSecret(ctx, got.SecretRef)
			if resolveErr != nil || !bytes.Equal(resolved, credential) {
				t.Fatalf("credential mismatch: %v", resolveErr)
			}
			clear(resolved)
			requestResolver, _ = resolver.(*transientSecretResolver)
			return []modelapi.Descriptor{{ID: "gpt-test", Name: "GPT Test"}}, nil
		}),
		Tools:   ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) { return nil, nil }),
		Configs: staticConfigRepository{config: validTestConfig()}, Conversations: &recordingConversationRepository{},
		Secrets: inertSecretResolver{}, TransientCredentials: manager, Clock: func() time.Time { return now },
	})
	models, err := runtime.ListModels(context.Background(), ModelListRequest{
		RequestID: "request-model-list", OwnerID: "owner-1", BootstrapClientID: "message-server-client",
		TransientModel: &TransientModelInvocation{
			Profile: profile, CredentialSessionID: created.Session.SessionID,
			CredentialSessionRevision: 2, CredentialSHA256: digest,
		},
	})
	if err != nil || len(models) != 1 || models[0].ID != "gpt-test" {
		t.Fatalf("models=%#v err=%v", models, err)
	}
	session, err := manager.Get(context.Background(), "message-server-client", created.Session.SessionID)
	if err != nil || session.Status != secretbootstrap.StatusConsumed || session.Revision != 3 {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	if requestResolver == nil {
		t.Fatal("request-local resolver was not used")
	}
	for _, value := range requestResolver.credential {
		if value != 0 {
			t.Fatal("request-local discovery credential was not cleared")
		}
	}
}
