package cloudworker

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
)

const MinimumPiContextWindow uint64 = 16 * 1024

// ModelAuthorizationFromSnapshot is the single Pi model-adapter boundary used
// by both proposal compilation and pre-mutation authority revalidation. The
// returned value contains only immutable identifiers and digests, never the
// profile credential itself.
func ModelAuthorizationFromSnapshot(snapshot coremodel.ExecutionSnapshot) (ModelAuthorization, error) {
	if snapshot.Validate() != nil || snapshot.Revision <= 0 || snapshot.CredentialVersion <= 0 ||
		uint64(snapshot.ContextWindow) < MinimumPiContextWindow {
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
		MaximumOutputTokens: uint64(snapshot.MaxOutputTokens), ContextWindow: uint64(snapshot.ContextWindow),
		CredentialVersion: uint64(snapshot.CredentialVersion), CredentialBindingDigest: snapshot.Digest(),
	}
	if err := authorization.Seal(); err != nil {
		return ModelAuthorization{}, err
	}
	return authorization, nil
}

// effectivePlanLimits validates the model's per-request output limit while
// preserving the server-owned cumulative token budget signed and priced by
// the Plan. Pi may make several model calls during one execution.
func effectivePlanLimits(defaults Limits, authorization ModelAuthorization) (Limits, error) {
	copy := authorization
	if validateLimits(defaults) != nil || copy.Seal() != nil {
		return Limits{}, ErrInvalid
	}
	if copy.ContextWindow < MinimumPiContextWindow {
		return Limits{}, ErrInvalid
	}
	if _, err := effectiveModelOutputTokens(copy); err != nil {
		return Limits{}, err
	}
	return defaults, nil
}

// effectiveModelOutputTokens returns the model-qualified ceiling for one Pi
// request. It is separate from the execution-wide budget in Plan.Limits.
func effectiveModelOutputTokens(authorization ModelAuthorization) (uint64, error) {
	copy := authorization
	if copy.Seal() != nil {
		return 0, ErrInvalid
	}
	maximum := copy.MaximumOutputTokens
	if copy.Provider == "openai_compatible" && copy.Interface == "openai_compatible" {
		if maximum == 0 {
			maximum = copy.ContextWindow / 4
		}
		if maximum > runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens {
			maximum = runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens
		}
		if maximum < runtimebounds.PiOpenAICompatibleMinimumOutputTokens {
			return 0, ErrInvalid
		}
	}
	if maximum == 0 || maximum >= copy.ContextWindow ||
		maximum > runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens {
		return 0, ErrInvalid
	}
	return maximum, nil
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
