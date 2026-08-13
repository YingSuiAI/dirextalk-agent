package production

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/modelrelay"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type exactProfileReaderFunc func(context.Context, string) (coremodel.Profile, error)

func (resolve exactProfileReaderFunc) ResolveProfile(ctx context.Context, id string) (coremodel.Profile, error) {
	return resolve(ctx, id)
}

func TestExactModelResolverRequiresCompleteSnapshotAndReturnsDestroyableCredential(t *testing.T) {
	profile := coremodel.Profile{
		ID: uuid.NewString(), DisplayName: "Cloud model", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://openrouter.ai/api/v1", Model: "gpt-test", APIKey: "provider-key-value",
		MaxOutputTokens: 4096, ContextWindow: 65536, Revision: 7, CredentialVersion: 3,
	}
	snapshot := coremodel.SnapshotFromProfile(profile)
	authorization := cloudworker.ModelAuthorization{
		ModelProfileID: profile.ID, ModelProfileRevision: uint64(profile.Revision),
		Provider: string(profile.Provider), Interface: modelrelay.InterfaceOpenAICompatible,
		Model: profile.Model, MaximumOutputTokens: uint64(profile.MaxOutputTokens), ContextWindow: uint64(profile.ContextWindow), CredentialVersion: uint64(profile.CredentialVersion),
		CredentialBindingDigest: snapshot.Digest(),
	}
	if err := authorization.Seal(); err != nil {
		t.Fatal(err)
	}
	reference := modelrelay.ProfileReference{
		OwnerID: "@owner:example.test", AccountGeneration: 9,
		ProfileID: profile.ID, ProfileRevision: uint64(profile.Revision),
		CredentialVersion: uint64(profile.CredentialVersion), Provider: string(profile.Provider),
		Interface: modelrelay.InterfaceOpenAICompatible, Model: profile.Model, MaximumOutputTokens: uint64(profile.MaxOutputTokens),
		CredentialBindingDigest: authorization.CredentialBindingDigest,
		ModelBindingDigest:      authorization.BindingDigest,
	}
	resolver, err := NewExactModelResolver(exactProfileReaderFunc(func(context.Context, string) (coremodel.Profile, error) {
		return profile, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := resolver.ResolveExactProfileBinding(context.Background(), reference)
	if err != nil || binding.Reference != reference || binding.BaseURL != profile.BaseURL {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	credential, err := resolver.ResolveExactCredential(context.Background(), binding)
	if err != nil || string(credential.Value) != profile.APIKey || credential.CredentialBindingDigest != reference.CredentialBindingDigest {
		t.Fatalf("credential=%s err=%v", credential.Value, err)
	}
	credential.Destroy()
	if len(credential.Value) != 0 {
		t.Fatal("credential plaintext was not destroyed")
	}
}

func TestExactModelResolverRejectsRevisionCredentialAndEndpointDrift(t *testing.T) {
	profile := coremodel.Profile{
		ID: uuid.NewString(), DisplayName: "Cloud model", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://model.example.test/v1", Model: "gpt-test", APIKey: "provider-key-value",
		MaxOutputTokens: 4096, ContextWindow: 65536, Revision: 7, CredentialVersion: 3,
	}
	snapshot := coremodel.SnapshotFromProfile(profile)
	authorization := cloudworker.ModelAuthorization{
		ModelProfileID: profile.ID, ModelProfileRevision: 7, Provider: string(profile.Provider),
		Interface: modelrelay.InterfaceOpenAICompatible, Model: profile.Model, MaximumOutputTokens: uint64(profile.MaxOutputTokens), ContextWindow: uint64(profile.ContextWindow), CredentialVersion: 3,
		CredentialBindingDigest: snapshot.Digest(),
	}
	if err := authorization.Seal(); err != nil {
		t.Fatal(err)
	}
	reference := modelrelay.ProfileReference{
		OwnerID: "@owner:example.test", AccountGeneration: 9, ProfileID: profile.ID,
		ProfileRevision: 7, CredentialVersion: 3, Provider: string(profile.Provider),
		Interface: modelrelay.InterfaceOpenAICompatible, Model: profile.Model, MaximumOutputTokens: uint64(profile.MaxOutputTokens),
		CredentialBindingDigest: authorization.CredentialBindingDigest, ModelBindingDigest: authorization.BindingDigest,
	}
	current := profile
	resolver, _ := NewExactModelResolver(exactProfileReaderFunc(func(context.Context, string) (coremodel.Profile, error) {
		return current, nil
	}))
	for name, mutate := range map[string]func(){
		"revision":               func() { current.Revision++ },
		"credential":             func() { current.APIKey = "rotated-provider-key"; current.CredentialVersion++ },
		"provider endpoint path": func() { current.BaseURL = "https://model.example.test/api/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			current = profile
			mutate()
			_, err := resolver.ResolveExactProfileBinding(context.Background(), reference)
			if !errors.Is(err, modelrelay.ErrProfileDrift) {
				t.Fatalf("err=%v, want profile drift", err)
			}
		})
	}
}

func TestExactModelResolverRebuildsCurrentAuthorizationAfterRotation(t *testing.T) {
	profile := coremodel.Profile{
		ID: uuid.NewString(), DisplayName: "Cloud model", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://model.example.test/v1", Model: "gpt-test", APIKey: "provider-key-value",
		MaxOutputTokens: 4096, ContextWindow: 65536, Revision: 7, CredentialVersion: 3,
	}
	previous, err := cloudworker.ModelAuthorizationFromSnapshot(coremodel.SnapshotFromProfile(profile))
	if err != nil {
		t.Fatal(err)
	}
	current := profile
	resolver, err := NewExactModelResolver(exactProfileReaderFunc(func(_ context.Context, id string) (coremodel.Profile, error) {
		if id != profile.ID {
			return coremodel.Profile{}, errors.New("profile not found")
		}
		return current, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := resolver.ResolveCurrentModelAuthorization(context.Background(), previous)
	if err != nil || unchanged != previous {
		t.Fatalf("unchanged=%+v err=%v", unchanged, err)
	}
	current.Revision++
	current.CredentialVersion++
	current.APIKey = "rotated-provider-key"
	rotated, err := resolver.ResolveCurrentModelAuthorization(context.Background(), previous)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ModelProfileID != previous.ModelProfileID || rotated.ModelProfileRevision != uint64(current.Revision) ||
		rotated.CredentialVersion != uint64(current.CredentialVersion) || rotated.CredentialBindingDigest == previous.CredentialBindingDigest ||
		rotated.BindingDigest == previous.BindingDigest {
		t.Fatalf("rotation was not rebound: previous=%+v rotated=%+v", previous, rotated)
	}
}

func TestExactModelResolverCurrentAuthorizationFailsClosed(t *testing.T) {
	profile := coremodel.Profile{
		ID: uuid.NewString(), DisplayName: "Cloud model", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://model.example.test/v1", Model: "gpt-test", APIKey: "provider-key-value",
		MaxOutputTokens: 4096, ContextWindow: 65536, Revision: 7, CredentialVersion: 3,
	}
	previous, err := cloudworker.ModelAuthorizationFromSnapshot(coremodel.SnapshotFromProfile(profile))
	if err != nil {
		t.Fatal(err)
	}
	for name, reader := range map[string]exactProfileReaderFunc{
		"deleted": func(context.Context, string) (coremodel.Profile, error) {
			return coremodel.Profile{}, errors.New("profile not found")
		},
		"unsupported_provider": func(context.Context, string) (coremodel.Profile, error) {
			unsupported := profile
			unsupported.Provider = coremodel.ProviderAnthropic
			return unsupported, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			resolver, resolveErr := NewExactModelResolver(reader)
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if _, resolveErr = resolver.ResolveCurrentModelAuthorization(context.Background(), previous); !errors.Is(resolveErr, cloudworker.ErrStaleAuthorization) {
				t.Fatalf("err=%v, want stale authorization", resolveErr)
			}
		})
	}
}
