package main

import (
	"context"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const conversationTitleGenerationLimit = 8 * time.Second

type coreConversationTitleGenerator struct {
	profiles interface {
		ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error)
	}
	clientFactory func(coremodel.Profile) (coremodel.Client, error)
}

func (g coreConversationTitleGenerator) GenerateConversationTitle(ctx context.Context, userText, assistantText string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, conversationTitleGenerationLimit)
	defer cancel()
	profile, err := g.profiles.ResolveDefaultToolProfile(ctx)
	if err != nil {
		return "", err
	}
	profile.SystemPrompt = ""
	profile.MaxOutputTokens = 64
	factory := g.clientFactory
	if factory == nil {
		factory = func(profile coremodel.Profile) (coremodel.Client, error) {
			return coremodel.NewClient(profile, coremodel.WithTimeout(conversationTitleGenerationLimit))
		}
	}
	client, err := factory(profile)
	if err != nil {
		return "", err
	}
	prompt := "User:\n" + userText
	if assistantText = strings.TrimSpace(assistantText); assistantText != "" {
		prompt += "\n\nAssistant:\n" + assistantText
	}
	completion, err := client.Generate(ctx, coremodel.CompletionRequest{Messages: []coremodel.Message{
		{Role: coremodel.RoleSystem, Content: "Generate one concise title for this conversation in the user's language. Return only the title, without quotes, markdown, punctuation suffixes, or explanation. Use at most 16 Chinese/Japanese characters or 8 English words."},
		{Role: coremodel.RoleUser, Content: prompt},
	}})
	if err != nil {
		return "", err
	}
	return completion.Message.Content, nil
}
