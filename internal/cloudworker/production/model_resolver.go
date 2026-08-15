package production

import (
	"bytes"
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// ResolveWorkerCredential returns the exact provider key selected by an
// already-sealed model authorization. The caller must clear the returned
// bytes after constructing one verified Worker Claim response.
func (resolver *ExactModelResolver) ResolveWorkerCredential(
	ctx context.Context,
	authorization cloudworker.ModelAuthorization,
) ([]byte, error) {
	if resolver == nil || ctx == nil || authorization.Seal() != nil {
		return nil, cloudworker.ErrInvalid
	}
	profile, current, err := resolver.current(ctx, authorization.ModelProfileID)
	if err != nil || current.BindingDigest != authorization.BindingDigest ||
		current.CredentialBindingDigest != authorization.CredentialBindingDigest ||
		current.ModelProfileRevision != authorization.ModelProfileRevision ||
		current.CredentialVersion != authorization.CredentialVersion ||
		profile.APIKey == "" {
		return nil, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return bytes.Clone([]byte(profile.APIKey)), nil
}

type exactProfileReader interface {
	ResolveProfile(context.Context, string) (coremodel.Profile, error)
}

// ExactModelResolver binds a Worker to the same immutable Core model snapshot
// used to quote the plan. It resolves no "latest compatible" alias:
// revision, credential version, provider, model and both digests must match.
type ExactModelResolver struct {
	profiles exactProfileReader
}

func NewExactModelResolver(profiles exactProfileReader) (*ExactModelResolver, error) {
	if profiles == nil {
		return nil, cloudworker.ErrInvalid
	}
	return &ExactModelResolver{profiles: profiles}, nil
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

func (resolver *ExactModelResolver) current(ctx context.Context, profileID string) (coremodel.Profile, cloudworker.ModelAuthorization, error) {
	if resolver == nil || resolver.profiles == nil || ctx == nil || profileID == "" {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, cloudworker.ErrInvalid
	}
	profile, err := resolver.profiles.ResolveProfile(ctx, profileID)
	if err != nil {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, err
	}
	if profile.ID != profileID {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	authorization, err := cloudworker.ModelAuthorizationFromSnapshot(coremodel.SnapshotFromProfile(profile))
	if err != nil {
		return coremodel.Profile{}, cloudworker.ModelAuthorization{}, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return profile, authorization, nil
}

var _ cloudworker.ModelAuthorizationResolver = (*ExactModelResolver)(nil)
