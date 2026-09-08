package agentcapability

import (
	"context"
	"encoding/json"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
)

const systemPromptResultSchema = `{"type":"object","additionalProperties":false,"properties":{"revision":{"type":"integer","minimum":0},"system_prompt":{"type":"string","maxLength":131072}},"required":["revision","system_prompt"]}`
const systemPromptUpdateSchema = `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":0},"system_prompt":{"type":"string","maxLength":131072}},"required":["idempotency_key","expected_revision","system_prompt"]}`

func (c *configCapability) handleSystemPrompt(ctx context.Context, operation string, raw []byte) ([]byte, error) {
	if c == nil {
		return nil, coreconfig.ErrInvalid
	}
	store, ok := c.store.(coreconfig.SystemPromptStore)
	if !ok {
		return nil, coreconfig.ErrInvalid
	}
	if operation == "get_system_prompt" {
		if requireEmptyObject(raw) != nil {
			return nil, coreconfig.ErrInvalid
		}
		value, err := store.GetSystemPrompt(ctx)
		return marshalResult(value, err)
	}
	var input struct {
		IdempotencyKey   string  `json:"idempotency_key"`
		ExpectedRevision *int64  `json:"expected_revision"`
		Prompt           *string `json:"system_prompt"`
	}
	if decodeStrictObject(raw, &input) != nil || input.ExpectedRevision == nil || input.Prompt == nil {
		return nil, coreconfig.ErrInvalid
	}
	update := coreconfig.SystemPromptUpdate{IdempotencyKey: input.IdempotencyKey, ExpectedRevision: *input.ExpectedRevision, Prompt: *input.Prompt}
	if err := update.Validate(); err != nil {
		return nil, err
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil {
		return nil, coreconfig.ErrInvalid
	}
	value, err := store.UpdateSystemPrompt(ctx, permission.GetAuthenticatedOwnerId(), update)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
