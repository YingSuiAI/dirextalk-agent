package cloudapp

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

type BootstrapPricingFactory interface {
	NewPricingPort(string, *awsprovider.Credentials) (cloudquote.PricingPort, error)
}

type SDKBootstrapPricingFactory struct{}

func (SDKBootstrapPricingFactory) NewPricingPort(region string, credentials *awsprovider.Credentials) (cloudquote.PricingPort, error) {
	config, err := awsprovider.StaticAWSConfig(region, credentials)
	if err != nil {
		return nil, err
	}
	return awsprovider.NewPricingProviderFromConfig(config)
}

type WorkerReleaseResolver interface {
	ResolveActiveWorkerRelease(context.Context, string, string, string, recipe.Architecture) (workerrelease.ReleaseV1, error)
}

// AWSBootstrapQuoteEngine uses an uploaded admin credential only for typed,
// read-only pricing and quota calls. The credential remains inside the
// bootstrap decryption callback and is never attached to a Recipe or Quote.
type AWSBootstrapQuoteEngine struct {
	agentInstanceID string
	secrets         SecretBootstrapInspector
	identities      AWSIdentityRepository
	releases        WorkerReleaseResolver
	factory         BootstrapPricingFactory
	now             func() time.Time
}

func NewAWSBootstrapQuoteEngine(agentInstanceID string, secrets SecretBootstrapInspector, identities AWSIdentityRepository, releases WorkerReleaseResolver, factory BootstrapPricingFactory, now func() time.Time) (*AWSBootstrapQuoteEngine, error) {
	if agentInstanceID == "" || secrets == nil || identities == nil || releases == nil || factory == nil || now == nil {
		return nil, ErrInvalid
	}
	return &AWSBootstrapQuoteEngine{agentInstanceID: agentInstanceID, secrets: secrets, identities: identities, releases: releases, factory: factory, now: now}, nil
}

func (engine *AWSBootstrapQuoteEngine) Quote(ctx context.Context, request QuoteExecutionRequest, boundRecipe recipe.RecipeV1) (cloudquote.QuoteV1, error) {
	if engine == nil || ctx == nil || secretbootstrap.ValidateClientID(request.CallerClientID) != nil || request.BootstrapSessionID == "" || request.ExpectedSessionRevision == 0 || len(request.Pricing.Scopes) == 0 {
		return cloudquote.QuoteV1{}, ErrInvalid
	}
	first := request.Pricing.Scopes[0]
	descriptor, err := engine.secrets.Get(ctx, request.CallerClientID, request.BootstrapSessionID)
	if err != nil {
		return cloudquote.QuoteV1{}, mapBootstrapError(err)
	}
	now := engine.now().UTC()
	if descriptor.AgentInstanceID != engine.agentInstanceID || descriptor.OwnerID != first.OwnerID ||
		descriptor.TargetID != first.ConnectionID || descriptor.Purpose != "aws_connection" ||
		descriptor.Status != secretbootstrap.StatusUploaded || descriptor.Revision != request.ExpectedSessionRevision ||
		!now.Before(descriptor.ExpiresAt) {
		return cloudquote.QuoteV1{}, ErrRevisionConflict
	}
	evidence, err := engine.identities.GetAWSIdentityEvidence(ctx, request.BootstrapSessionID, request.ExpectedSessionRevision)
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	if evidence.AgentInstanceID != engine.agentInstanceID || evidence.OwnerID != first.OwnerID || evidence.TargetID != first.ConnectionID ||
		evidence.Identity.Region != first.Resource.Region || !now.Before(evidence.ExpiresAt) {
		return cloudquote.QuoteV1{}, ErrApprovalRequired
	}
	pricingRequest, err := engine.bindWorkerRelease(ctx, request.Pricing, evidence.Identity.AccountID)
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	var result cloudquote.QuoteV1
	_, err = engine.secrets.Inspect(ctx, request.CallerClientID, request.BootstrapSessionID, request.ExpectedSessionRevision, func(payload []byte) error {
		return awsprovider.ConsumeBootstrapCredentials(payload, func(credentials *awsprovider.Credentials) error {
			pricing, pricingErr := engine.factory.NewPricingPort(first.Resource.Region, credentials)
			if pricingErr != nil {
				return pricingErr
			}
			service, pricingErr := cloudquote.NewService(pricing, engine.now)
			if pricingErr != nil {
				return pricingErr
			}
			result, pricingErr = service.Quote(ctx, pricingRequest, boundRecipe)
			return pricingErr
		})
	})
	if err != nil {
		return cloudquote.QuoteV1{}, mapBootstrapError(err)
	}
	return result, nil
}

func (engine *AWSBootstrapQuoteEngine) bindWorkerRelease(ctx context.Context, request cloudquote.RequestV1, accountID string) (cloudquote.RequestV1, error) {
	if engine == nil || engine.releases == nil || ctx == nil || accountID == "" || len(request.Scopes) == 0 {
		return cloudquote.RequestV1{}, ErrInvalid
	}
	bound := request
	bound.Scopes = append([]cloudquote.ScopeV1(nil), request.Scopes...)
	cache := make(map[string]workerrelease.ReleaseV1)
	for index := range bound.Scopes {
		resource := &bound.Scopes[index].Resource
		key := resource.Region + "\x00" + string(resource.Architecture)
		release, ok := cache[key]
		if !ok {
			var err error
			release, err = engine.releases.ResolveActiveWorkerRelease(ctx, engine.agentInstanceID, accountID, resource.Region, resource.Architecture)
			if err != nil {
				return cloudquote.RequestV1{}, ErrUnavailable
			}
			if release.AgentInstanceID != engine.agentInstanceID || release.AccountID != accountID || release.Region != resource.Region || release.Architecture != resource.Architecture {
				return cloudquote.RequestV1{}, ErrUnavailable
			}
			cache[key] = release
		}
		resource.WorkerImageID = release.ImageID
		resource.WorkerImageDigest = release.ImageDigest
	}
	return bound, nil
}
