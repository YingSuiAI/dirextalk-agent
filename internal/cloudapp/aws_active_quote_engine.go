package cloudapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

// SourceCredentialOpener is the narrow read boundary used after a Foundation
// has replaced the uploaded administrator credential with the source IAM key.
// The returned value is always wiped by AWSActiveQuoteEngine.
type SourceCredentialOpener interface {
	Open(context.Context, awsfoundation.SourceCredentialBinding) (awsprovider.SourceCredentials, error)
}

// ActivePricingFactory constructs the read-only pricing provider from a
// short-lived Control Role session. It is intentionally not an arbitrary AWS
// client factory and is never exposed to RuntimeService, Eino, MCP, or Skills.
type ActivePricingFactory interface {
	NewPricingPort(string, *awsprovider.SourceCredentials, string, string) (cloudquote.PricingPort, error)
}

type SDKActivePricingFactory struct{}

func (SDKActivePricingFactory) NewPricingPort(region string, source *awsprovider.SourceCredentials, controlRoleARN, roleSessionName string) (cloudquote.PricingPort, error) {
	config, err := awsprovider.AssumedControlAWSConfig(region, source, controlRoleARN, roleSessionName)
	if err != nil {
		return nil, err
	}
	return awsprovider.NewPricingProviderFromConfig(config)
}

// AWSActiveQuoteEngine performs provider pricing through an already active,
// owner-bound Connection. Unlike AWSBootstrapQuoteEngine, it never reopens or
// depends on the one-time uploaded administrator credential.
type AWSActiveQuoteEngine struct {
	agentInstanceID string
	credentials     SourceCredentialOpener
	releases        WorkerReleaseResolver
	factory         ActivePricingFactory
	now             func() time.Time
}

func NewAWSActiveQuoteEngine(agentInstanceID string, credentials SourceCredentialOpener, releases WorkerReleaseResolver, factory ActivePricingFactory, now func() time.Time) (*AWSActiveQuoteEngine, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || credentials == nil || releases == nil || factory == nil || now == nil {
		return nil, ErrInvalid
	}
	return &AWSActiveQuoteEngine{agentInstanceID: agentInstanceID, credentials: credentials, releases: releases, factory: factory, now: now}, nil
}

func (engine *AWSActiveQuoteEngine) Quote(ctx context.Context, connection Connection, request cloudquote.RequestV1, boundRecipe recipe.RecipeV1) (cloudquote.QuoteV1, error) {
	if engine == nil || ctx == nil || validateActiveQuoteBinding(engine.agentInstanceID, connection, request) != nil || boundRecipe.Validate() != nil {
		return cloudquote.QuoteV1{}, ErrInvalid
	}
	bound, err := bindWorkerReleaseForQuote(ctx, engine.agentInstanceID, engine.releases, request, connection.AccountID)
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	bound, err = bindVolumeScopesForQuote(engine.agentInstanceID, bound, boundRecipe)
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	if err := bound.Validate(); err != nil {
		return cloudquote.QuoteV1{}, ErrInvalid
	}
	credentials, err := engine.credentials.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: engine.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return cloudquote.QuoteV1{}, ErrUnavailable
	}
	defer credentials.Wipe()
	pricing, err := engine.factory.NewPricingPort(connection.Region, &credentials, connection.ControlRoleARN, activeQuoteRoleSession(request.QuoteID))
	if err != nil {
		return cloudquote.QuoteV1{}, ErrUnavailable
	}
	service, err := cloudquote.NewService(pricing, engine.now)
	if err != nil {
		return cloudquote.QuoteV1{}, ErrUnavailable
	}
	quoted, err := service.Quote(ctx, bound, boundRecipe)
	if err != nil {
		return cloudquote.QuoteV1{}, ErrUnavailable
	}
	return quoted, nil
}

func validateActiveQuoteBinding(agentInstanceID string, connection Connection, request cloudquote.RequestV1) error {
	connectionID, connectionErr := uuid.Parse(strings.TrimSpace(connection.ConnectionID))
	role, roleErr := arn.Parse(strings.TrimSpace(connection.ControlRoleARN))
	if connectionErr != nil || connectionID == uuid.Nil || connectionID.String() != connection.ConnectionID ||
		connection.OwnerID == "" || connection.AccountID == "" || connection.Region == "" || connection.FoundationStack == "" ||
		connection.Status != "active" || connection.Revision < 1 || roleErr != nil || role.Service != "iam" || role.AccountID != connection.AccountID || len(request.Scopes) != 3 {
		return ErrInvalid
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: agentInstanceID, Partition: role.Partition, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil || role.Resource != "role/"+spec.ControlRoleName {
		return ErrInvalid
	}
	for _, scope := range request.Scopes {
		if scope.AgentInstanceID != agentInstanceID || scope.OwnerID != connection.OwnerID || scope.ConnectionID != connection.ConnectionID || scope.Resource.Region != connection.Region {
			return ErrInvalid
		}
	}
	return nil
}

func activeQuoteRoleSession(quoteID string) string {
	digest := sha256.Sum256([]byte(quoteID))
	return "dtx-quote-" + hex.EncodeToString(digest[:])[:20]
}
