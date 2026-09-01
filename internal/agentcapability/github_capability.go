package agentcapability

import (
	"context"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	githubConfigSchema     = `{"additionalProperties":false,"properties":{"github_token_configured":{"type":"boolean"},"github_token_hint":{"type":"string"},"enabled":{"type":"boolean"},"provider":{"enum":["github"],"type":"string"},"revision":{"minimum":0,"type":"integer"},"tested_at":{"format":"date-time","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["enabled","provider","github_token_configured","revision"],"type":"object"}`
	githubUpdateSchema     = `{"additionalProperties":false,"properties":{"github_token":{"maxLength":4096,"minLength":1,"type":"string","writeOnly":true},"github_token_clear":{"type":"boolean"},"enabled":{"type":"boolean"},"expected_revision":{"minimum":0,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"provider":{"enum":["github"],"type":"string"}},"required":["idempotency_key","expected_revision"],"type":"object"}`
	githubTestResultSchema = `{"additionalProperties":false,"properties":{"github_token_configured":{"type":"boolean"},"enabled":{"type":"boolean"},"ok":{"type":"boolean"},"provider":{"enum":["github"],"type":"string"},"result_count":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"tested_at":{"format":"date-time","type":"string"}},"required":["ok","provider","result_count","tested_at","enabled","github_token_configured","revision"],"type":"object"}`
)

type coreGitHubCapability struct {
	service *coregithub.Service
}

func NewCoreGitHubCapability(service *coregithub.Service) Capability {
	return &coreGitHubCapability{service: service}
}

func (c *coreGitHubCapability) Descriptor() *capv1.CapabilityDescriptor {
	return capabilityDescriptor("agent.github.v1", "GitHub", "Agent-owned encrypted GitHub PAT configuration and identity connectivity", []capabilityOperation{
		{ID: "get_config", DisplayName: "Get GitHub config", Description: "Read the non-secret GitHub configuration.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:mcp:read", InputSchema: emptyObjectSchema, ResultSchema: githubConfigSchema},
		{ID: "update_config", DisplayName: "Update GitHub config", Description: "Update GitHub configuration and its write-only PAT; enabling validates the exact proposed PAT before commit.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:mcp:write", InputSchema: githubUpdateSchema, ResultSchema: githubConfigSchema},
		{ID: "test", DisplayName: "Test GitHub", Description: "Test the stored GitHub PAT against the GitHub identity API.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:mcp:write", InputSchema: emptyObjectSchema, ResultSchema: githubTestResultSchema},
	})
}

func (c *coreGitHubCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coregithub.ErrRepository
	}
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	permission, _ := capabilityclient.PermissionFromContext(ctx)
	ownerID := strings.TrimSpace(permission.GetAuthenticatedOwnerId())
	accountGeneration := permission.GetAccountGeneration()
	switch operationID {
	case "get_config":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		value, err := c.service.Get(ctx, ownerID, accountGeneration)
		return marshalResult(value, err)
	case "update_config":
		var request struct {
			IdempotencyKey   string  `json:"idempotency_key"`
			ExpectedRevision int64   `json:"expected_revision"`
			Enabled          *bool   `json:"enabled,omitempty"`
			Provider         *string `json:"provider,omitempty"`
			GitHubToken      *string `json:"github_token,omitempty"`
			GitHubTokenClear bool    `json:"github_token_clear,omitempty"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		var provider *coregithub.Provider
		if request.Provider != nil {
			value := coregithub.Provider(strings.ToLower(strings.TrimSpace(*request.Provider)))
			provider = &value
		}
		value, err := c.service.Update(ctx, coregithub.UpdateCommand{
			OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: request.IdempotencyKey, ExpectedRevision: request.ExpectedRevision,
			Enabled: request.Enabled, Provider: provider, GitHubToken: request.GitHubToken, GitHubTokenClear: request.GitHubTokenClear,
		})
		return marshalResult(value, err)
	case "test":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		value, err := c.service.Test(ctx, ownerID, accountGeneration)
		return marshalResult(value, err)
	default:
		return nil, fmt.Errorf("unknown GitHub operation %q", operationID)
	}
}
