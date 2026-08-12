package main

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type titleProfileResolver struct {
	profile coremodel.Profile
	calls   int
}

func (r *titleProfileResolver) ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error) {
	r.calls++
	return r.profile, nil
}

type titleModelClient struct {
	request coremodel.CompletionRequest
}

func (c *titleModelClient) Generate(_ context.Context, request coremodel.CompletionRequest) (coremodel.Completion, error) {
	c.request = request
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: "AWS 服务部署"}}, nil
}

func (*titleModelClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, coremodel.ErrInvalidCompletionRequest
}

func TestConversationTitleGeneratorUsesExplicitToolProfile(t *testing.T) {
	profile := coremodel.Profile{
		ID: uuid.NewString(), DisplayName: "tool", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://example.invalid", Model: "tool-model", APIKey: "tool-secret",
		SystemPrompt: "unrelated configured prompt", MaxOutputTokens: 4096,
	}
	resolver := &titleProfileResolver{profile: profile}
	client := &titleModelClient{}
	var factoryProfile coremodel.Profile
	generator := coreConversationTitleGenerator{
		profiles: resolver,
		clientFactory: func(got coremodel.Profile) (coremodel.Client, error) {
			factoryProfile = got
			return client, nil
		},
	}
	title, err := generator.GenerateConversationTitle(context.Background(), "请帮我部署服务", "我会先分析项目")
	if err != nil {
		t.Fatal(err)
	}
	if title != "AWS 服务部署" || resolver.calls != 1 {
		t.Fatalf("title=%q resolver_calls=%d", title, resolver.calls)
	}
	if factoryProfile.ID != profile.ID || factoryProfile.Model != profile.Model || factoryProfile.APIKey != profile.APIKey {
		t.Fatalf("factory profile=%+v", factoryProfile.Public())
	}
	if factoryProfile.SystemPrompt != "" || factoryProfile.MaxOutputTokens != 64 {
		t.Fatalf("title profile system_prompt=%q max_output_tokens=%d", factoryProfile.SystemPrompt, factoryProfile.MaxOutputTokens)
	}
	if len(client.request.Messages) != 2 || client.request.Messages[0].Role != coremodel.RoleSystem || client.request.Messages[1].Role != coremodel.RoleUser {
		t.Fatalf("request messages=%+v", client.request.Messages)
	}
}
