package production

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/modelrelay"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type exactProfileReader interface {
	ResolveProfile(context.Context, string) (coremodel.Profile, error)
}

// ExactModelResolver binds the model relay to the same immutable Core model
// snapshot used to quote the plan. It resolves no "latest compatible" alias:
// revision, credential version, provider, model and both digests must match.
type ExactModelResolver struct {
	profiles exactProfileReader
}

func NewExactModelResolver(profiles exactProfileReader) (*ExactModelResolver, error) {
	if profiles == nil {
		return nil, modelrelay.ErrInvalid
	}
	return &ExactModelResolver{profiles: profiles}, nil
}

func (resolver *ExactModelResolver) ResolveExactProfileBinding(ctx context.Context, reference modelrelay.ProfileReference) (modelrelay.ProfileBinding, error) {
	profile, err := resolver.resolve(ctx, reference)
	if err != nil {
		return modelrelay.ProfileBinding{}, err
	}
	binding := modelrelay.ProfileBinding{Reference: reference, BaseURL: profile.BaseURL}
	if binding.Validate() != nil {
		return modelrelay.ProfileBinding{}, modelrelay.ErrProfileDrift
	}
	return binding, nil
}

func (resolver *ExactModelResolver) ResolveExactCredential(ctx context.Context, binding modelrelay.ProfileBinding) (modelrelay.ResolvedCredential, error) {
	if binding.Validate() != nil {
		return modelrelay.ResolvedCredential{}, modelrelay.ErrInvalid
	}
	profile, err := resolver.resolve(ctx, binding.Reference)
	if err != nil {
		return modelrelay.ResolvedCredential{}, err
	}
	credential := modelrelay.ResolvedCredential{
		Value:                   []byte(profile.APIKey),
		CredentialBindingDigest: binding.Reference.CredentialBindingDigest,
	}
	if credential.ValidateFor(binding.Reference) != nil {
		credential.Destroy()
		return modelrelay.ResolvedCredential{}, modelrelay.ErrCredentialUnavailable
	}
	return credential, nil
}

// ResolveCurrentModelAuthorization returns the current immutable
// authorization for the exact profile already selected by previous. It never
// returns credential plaintext and never switches to a default profile.
func (resolver *ExactModelResolver) ResolveCurrentModelAuthorization(ctx context.Context, previous cloudworker.ModelAuthorization) (cloudworker.ModelAuthorization, error) {
	previousDigest := previous.BindingDigest
	if resolver == nil || resolver.profiles == nil || ctx == nil || previous.Seal() != nil || previous.BindingDigest != previousDigest {
		return cloudworker.ModelAuthorization{}, cloudworker.ErrInvalid
	}
	_, current, err := resolver.current(ctx, previous.ModelProfileID)
	if err != nil {
		return cloudworker.ModelAuthorization{}, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	if current.ModelProfileID != previous.ModelProfileID {
		return cloudworker.ModelAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	return current, nil
}

func (resolver *ExactModelResolver) resolve(ctx context.Context, reference modelrelay.ProfileReference) (coremodel.Profile, error) {
	if resolver == nil || resolver.profiles == nil || ctx == nil || reference.Validate() != nil {
		return coremodel.Profile{}, modelrelay.ErrInvalid
	}
	expected := cloudworker.ModelAuthorization{
		ModelProfileID: reference.ProfileID, ModelProfileRevision: reference.ProfileRevision,
		Provider: reference.Provider, Model: reference.Model, Interface: reference.Interface,
		CredentialVersion: reference.CredentialVersion, CredentialBindingDigest: reference.CredentialBindingDigest,
	}
	if expected.Seal() != nil || expected.BindingDigest != reference.ModelBindingDigest {
		return coremodel.Profile{}, modelrelay.ErrProfileDrift
	}
	profile, current, err := resolver.current(ctx, reference.ProfileID)
	if err != nil || current != expected {
		return coremodel.Profile{}, errors.Join(modelrelay.ErrProfileDrift, err)
	}
	return profile, nil
}

func (resolver *ExactModelResolver) current(ctx context.Context, profileID string) (coremodel.Profile, cloudworker.ModelAuthorization, error) {
	if resolver == nil || resolver.profiles == nil || ctx == nil || profileID == "" {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, modelrelay.ErrInvalid
	}
	profile, err := resolver.profiles.ResolveProfile(ctx, profileID)
	if err != nil {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, err
	}
	if profile.ID != profileID {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, modelrelay.ErrProfileDrift
	}
	authorization, err := cloudworker.ModelAuthorizationFromSnapshot(coremodel.SnapshotFromProfile(profile))
	if err != nil {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, errors.Join(modelrelay.ErrProfileDrift, err)
	}
	return profile, authorization, nil
}

var _ modelrelay.ProfileBindingReader = (*ExactModelResolver)(nil)
var _ modelrelay.ExactCredentialResolver = (*ExactModelResolver)(nil)
var _ cloudworker.ModelAuthorizationResolver = (*ExactModelResolver)(nil)
