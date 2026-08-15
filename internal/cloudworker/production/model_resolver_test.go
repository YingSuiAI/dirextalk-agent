package production

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
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
		Provider: string(profile.Provider), Interface: "openai_compatible",
		Model: profile.Model, BaseURL: profile.BaseURL, MaximumOutputTokens: uint64(profile.MaxOutputTokens), ContextWindow: uint64(profile.ContextWindow), CredentialVersion: uint64(profile.CredentialVersion),
		CredentialBindingDigest: snapshot.Digest(),
	}
	if err := authorization.Seal(); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewExactModelResolver(exactProfileReaderFunc(func(context.Context, string) (coremodel.Profile, error) {
		return profile, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	workerCredential, err := resolver.ResolveWorkerCredential(context.Background(), authorization)
	if err != nil || string(workerCredential) != profile.APIKey {
		t.Fatalf("worker credential=%q err=%v", workerCredential, err)
	}
	clear(workerCredential)
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
		Interface: "openai_compatible", Model: profile.Model, BaseURL: profile.BaseURL, MaximumOutputTokens: uint64(profile.MaxOutputTokens), ContextWindow: uint64(profile.ContextWindow), CredentialVersion: 3,
		CredentialBindingDigest: snapshot.Digest(),
	}
	if err := authorization.Seal(); err != nil {
		t.Fatal(err)
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
			_, err := resolver.ResolveWorkerCredential(context.Background(), authorization)
			if !errors.Is(err, cloudworker.ErrStaleAuthorization) {
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
