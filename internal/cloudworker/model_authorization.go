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

// effectivePlanLimits derives the one output-token limit signed by the Plan,
// priced by the quote, granted by Model Relay, and sent by Pi. A zero profile
// limit means the profile did not narrow the server-owned default.
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
		if maximum > runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens {
			maximum = runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens
		}
		if maximum < runtimebounds.PiOpenAICompatibleMinimumOutputTokens {
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
