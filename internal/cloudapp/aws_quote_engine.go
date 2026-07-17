package cloudapp

import (
	"context"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
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
	pricingRequest, err = bindVolumeScopesForQuote(engine.agentInstanceID, pricingRequest, boundRecipe)
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
	if engine == nil {
		return cloudquote.RequestV1{}, ErrInvalid
	}
	return bindWorkerReleaseForQuote(ctx, engine.agentInstanceID, engine.releases, request, accountID)
}

func bindWorkerReleaseForQuote(ctx context.Context, agentInstanceID string, releases WorkerReleaseResolver, request cloudquote.RequestV1, accountID string) (cloudquote.RequestV1, error) {
	if releases == nil || ctx == nil || agentInstanceID == "" || accountID == "" || len(request.Scopes) == 0 {
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
			release, err = releases.ResolveActiveWorkerRelease(ctx, agentInstanceID, accountID, resource.Region, resource.Architecture)
			if err != nil {
				return cloudquote.RequestV1{}, ErrUnavailable
			}
			if release.AgentInstanceID != agentInstanceID || release.AccountID != accountID || release.Region != resource.Region || release.Architecture != resource.Architecture {
				return cloudquote.RequestV1{}, ErrUnavailable
			}
			cache[key] = release
		}
		resource.WorkerImageID = release.ImageID
		resource.WorkerImageDigest = release.ImageDigest
	}
	return bound, nil
}

var quoteVolumeDevices = []string{
	"/dev/sdf", "/dev/sdg", "/dev/sdh", "/dev/sdi", "/dev/sdj", "/dev/sdk",
	"/dev/sdl", "/dev/sdm", "/dev/sdn", "/dev/sdo", "/dev/sdp",
}

// bindVolumeScopesForQuote fills only server-owned defaults. A caller may
// choose size/performance/device values, but it cannot redirect an approved
// data volume to a KMS key outside the deterministic Foundation boundary.
func bindVolumeScopesForQuote(agentInstanceID string, request cloudquote.RequestV1, boundRecipe recipe.RecipeV1) (cloudquote.RequestV1, error) {
	if len(request.Scopes) == 0 || len(boundRecipe.VolumeSlots) > len(quoteVolumeDevices) {
		return cloudquote.RequestV1{}, ErrInvalid
	}
	kmsAlias, err := awsfoundation.KMSAliasForAgent(agentInstanceID)
	if err != nil {
		return cloudquote.RequestV1{}, ErrInvalid
	}
	bound := request
	bound.Scopes = append([]cloudquote.ScopeV1(nil), request.Scopes...)
	provided := 0
	for _, scope := range bound.Scopes {
		if len(scope.Resource.VolumeScopes) != 0 {
			provided++
		}
	}
	if len(boundRecipe.VolumeSlots) == 0 {
		if provided != 0 {
			return cloudquote.RequestV1{}, ErrInvalid
		}
		return bound, nil
	}
	if provided != 0 && provided != len(bound.Scopes) {
		return cloudquote.RequestV1{}, ErrInvalid
	}
	slots := append([]recipe.VolumeSlotRequirementV1(nil), boundRecipe.VolumeSlots...)
	sort.Slice(slots, func(i, j int) bool { return slots[i].SlotID < slots[j].SlotID })
	for index := range bound.Scopes {
		resource := &bound.Scopes[index].Resource
		if provided == 0 {
			for slotIndex, slot := range slots {
				if slot.MountPath == "" {
					return cloudquote.RequestV1{}, ErrInvalid
				}
				sizeGiB := resource.DiskGiB
				if sizeGiB < 8 {
					sizeGiB = 8
				}
				if sizeGiB > 65_536 {
					return cloudquote.RequestV1{}, ErrInvalid
				}
				disposition := cloudquote.VolumeDeleteWithDeployment
				if bound.Scopes[index].Retention.Class == cloudquote.RetentionManaged {
					disposition = cloudquote.VolumeRetainWithManagedService
				}
				resource.VolumeScopes = append(resource.VolumeScopes, cloudquote.VolumeScopeV1{
					SlotID: slot.SlotID, SizeGiB: uint32(sizeGiB), VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
					Encrypted: true, KMSKeyID: kmsAlias, DeviceName: quoteVolumeDevices[slotIndex], MountPath: slot.MountPath,
					ReadOnly: slot.ReadOnly, Persistent: slot.Persistent, Disposition: disposition,
				})
			}
		} else {
			resource.VolumeScopes = append([]cloudquote.VolumeScopeV1(nil), resource.VolumeScopes...)
			for _, volume := range resource.VolumeScopes {
				if volume.KMSKeyID != kmsAlias {
					return cloudquote.RequestV1{}, ErrInvalid
				}
			}
		}
		if err := cloudquote.ValidateVolumeScopesForRecipe(resource.VolumeScopes, boundRecipe, bound.Scopes[index].Retention); err != nil {
			return cloudquote.RequestV1{}, ErrInvalid
		}
	}
	return bound, nil
}
