package cloudworker

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
)

// ModelAuthorizationFromSnapshot is the single Pi model-adapter boundary used
// by both proposal compilation and pre-mutation authority revalidation. The
// returned value contains only immutable identifiers and digests, never the
// profile credential itself.
func ModelAuthorizationFromSnapshot(snapshot coremodel.ExecutionSnapshot) (ModelAuthorization, error) {
	if snapshot.Validate() != nil || snapshot.Revision <= 0 || snapshot.CredentialVersion <= 0 {
		return ModelAuthorization{}, ErrInvalid
	}
	modelInterface := ""
	switch snapshot.Provider {
	case coremodel.ProviderOpenAICompatible:
		modelInterface = "openai_compatible"
	case coremodel.ProviderAnthropic:
		modelInterface = "anthropic-messages"
	case coremodel.ProviderGemini:
		modelInterface = "google-generative-ai"
	default:
		return ModelAuthorization{}, ErrInvalid
	}
	authorization := ModelAuthorization{
		ModelProfileID: snapshot.ProfileID, ModelProfileRevision: uint64(snapshot.Revision),
		Provider: string(snapshot.Provider), Model: snapshot.Model, Interface: modelInterface,
		MaximumOutputTokens: uint64(snapshot.MaxOutputTokens),
		CredentialVersion:   uint64(snapshot.CredentialVersion), CredentialBindingDigest: snapshot.Digest(),
	}
	if err := authorization.Seal(); err != nil {
		return ModelAuthorization{}, err
	}
	return authorization, nil
}

// effectivePlanLimits derives the output-token cost and authorization ceiling
// signed by the Plan and priced by the quote. A zero profile limit means the
// profile did not narrow the server-owned default. The Pi runtime derives its
// concrete request cap separately from the immutable model snapshot; this
// pricing limit must not be reused as model configuration.
func effectivePlanLimits(defaults Limits, authorization ModelAuthorization) (Limits, error) {
	copy := authorization
	if validateLimits(defaults) != nil || copy.Seal() != nil {
		return Limits{}, ErrInvalid
	}
	maximum := defaults.MaxTokens
	if copy.MaximumOutputTokens > 0 && copy.MaximumOutputTokens < maximum {
		maximum = copy.MaximumOutputTokens
	}
	if copy.Provider == "openai_compatible" && copy.Interface == "openai_compatible" {
		if maximum > runtimebounds.OpenAICompatibleMaximumAuthorizedOutputTokens {
			maximum = runtimebounds.OpenAICompatibleMaximumAuthorizedOutputTokens
		}
		if maximum < runtimebounds.OpenAICompatibleMinimumAuthorizedOutputTokens {
			return Limits{}, ErrInvalid
		}
	}
	defaults.MaxTokens = maximum
	if validateLimits(defaults) != nil {
		return Limits{}, ErrInvalid
	}
	return defaults, nil
}

// ModelAuthorizationResolver re-reads the current secret-bearing model
// profile selected by an existing plan. Implementations must not resolve a
// default or "latest compatible" profile in its place.
type ModelAuthorizationResolver interface {
	ResolveCurrentModelAuthorization(context.Context, ModelAuthorization) (ModelAuthorization, error)
}

type ModelAuthorizationResolverFunc func(context.Context, ModelAuthorization) (ModelAuthorization, error)

func (resolve ModelAuthorizationResolverFunc) ResolveCurrentModelAuthorization(ctx context.Context, previous ModelAuthorization) (ModelAuthorization, error) {
	if resolve == nil {
		return ModelAuthorization{}, ErrInvalid
	}
	return resolve(ctx, previous)
}
