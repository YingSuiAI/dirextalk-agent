package coremodel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	serviceProfileID = "11111111-1111-4111-8111-111111111111"
	serviceKey1      = "service-secret-one"
)

func serviceSpec(id, name string, key *string) ProfileSpec {
	return ProfileSpec{ID: id, DisplayName: name, Provider: ProviderOpenAICompatible, Model: "test-model", APIKey: key}
}

func TestServiceCRUDReplayRevisionAndSecretBoundary(t *testing.T) {
	repo := NewMemoryProfileRepository()
	svc, err := NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	idem := "22222222-2222-4222-8222-222222222222"
	pub, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: idem, Spec: serviceSpec(serviceProfileID, "Primary", strPtr(serviceKey1))})
	if err != nil {
		t.Fatal(err)
	}
	if !pub.APIKeyConfigured || strings.Contains(mustJSON(pub), serviceKey1) {
		t.Fatalf("secret leaked: %#v", pub)
	}
	if strings.Contains(mustJSON(Profile{APIKey: serviceKey1}), serviceKey1) {
		t.Fatal("Profile JSON leaked API key")
	}
	if strings.Contains(Profile{APIKey: serviceKey1}.String(), serviceKey1) {
		t.Fatal("Profile String leaked API key")
	}
	replay, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: idem, Spec: serviceSpec(serviceProfileID, "Primary", strPtr(serviceKey1))})
	if err != nil {
		t.Fatal(err)
	}
	if replay.DisplayName != "Primary" {
		t.Fatalf("replay mutated: %#v", replay)
	}
	if _, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: idem, Spec: serviceSpec(serviceProfileID, "Changed", strPtr("different"))}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed digest err=%v", err)
	}
	updated, err := svc.Update(context.Background(), UpdateProfileCommand{ID: serviceProfileID, IdempotencyKey: "33333333-3333-4333-8333-333333333333", ExpectedRevision: 1, Spec: ProfileSpec{ID: serviceProfileID, DisplayName: "Updated", Provider: ProviderAnthropic, Model: "claude", APIKeyClear: true}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.APIKeyConfigured || updated.Revision != 2 {
		t.Fatalf("clear patch failed: %#v", updated)
	}
	if _, err := svc.Update(context.Background(), UpdateProfileCommand{ID: serviceProfileID, IdempotencyKey: "44444444-4444-4444-8444-444444444444", ExpectedRevision: 1, Spec: serviceSpec(serviceProfileID, "Stale", nil)}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision err=%v", err)
	}
	if _, err := svc.ResolveProfile(context.Background(), serviceProfileID); !errors.Is(err, ErrAPIKeyUnavailable) {
		t.Fatalf("cleared key resolve err=%v", err)
	}
}

func TestServiceReferencesPaginationAndDeleteTombstone(t *testing.T) {
	repo := NewMemoryProfileRepository()
	svc, _ := NewService(repo, nil)
	for i, id := range []string{"55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"} {
		key := "k"
		_, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: uuidForTest(i + 5), Spec: serviceSpec(id, "p", &key)})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := svc.List(context.Background(), ListProfileCommand{Limit: 1})
	if err != nil || len(page.Profiles) != 1 || page.NextCursor == "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	page2, err := svc.List(context.Background(), ListProfileCommand{Cursor: page.NextCursor, Limit: 1})
	if err != nil || len(page2.Profiles) != 1 {
		t.Fatalf("page2=%#v err=%v", page2, err)
	}
	if _, err := svc.List(context.Background(), ListProfileCommand{Cursor: "bad", Limit: 1}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cursor err=%v", err)
	}
	repo.SetActiveReferences(page.Profiles[0].ID, 1)
	if _, err := svc.Delete(context.Background(), DeleteProfileCommand{ID: page.Profiles[0].ID, IdempotencyKey: "77777777-7777-4777-8777-777777777777", ExpectedRevision: 1}); !errors.Is(err, ErrProfileInUse) {
		t.Fatalf("refs err=%v", err)
	}
	repo.SetActiveReferences(page.Profiles[0].ID, 0)
	tomb, err := svc.Delete(context.Background(), DeleteProfileCommand{ID: page.Profiles[0].ID, IdempotencyKey: "88888888-8888-4888-8888-888888888888", ExpectedRevision: 1})
	if err != nil || tomb.APIKeyConfigured == false {
		t.Fatalf("tomb=%#v err=%v", tomb, err)
	}
	if _, err := svc.Get(context.Background(), page.Profiles[0].ID); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("deleted get err=%v", err)
	}
}

func TestPreserveReplayDoesNotAliasExplicitEmptySet(t *testing.T) {
	repo := NewMemoryProfileRepository()
	svc, _ := NewService(repo, nil)
	_, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Spec: serviceSpec(serviceProfileID, "Primary", strPtr(serviceKey1))})
	if err != nil {
		t.Fatal(err)
	}
	cmd := UpdateProfileCommand{ID: serviceProfileID, IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ExpectedRevision: 1, Spec: ProfileSpec{ID: serviceProfileID, DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "test-model"}}
	if _, err := svc.Update(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	cmd.Spec.APIKey = strPtr("")
	if _, err := svc.Update(context.Background(), cmd); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("explicit empty set aliased preserve: %v", err)
	}
}

func TestClearReplayDoesNotAliasClearAndSet(t *testing.T) {
	repo := NewMemoryProfileRepository()
	svc, _ := NewService(repo, nil)
	key := "k"
	_, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Spec: serviceSpec(serviceProfileID, "Primary", &key)})
	if err != nil {
		t.Fatal(err)
	}
	cmd := UpdateProfileCommand{ID: serviceProfileID, IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", ExpectedRevision: 1, Spec: ProfileSpec{ID: serviceProfileID, DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "test-model", APIKeyClear: true}}
	if _, err := svc.Update(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	cmd.Spec.APIKey = strPtr("new-key")
	if _, err := svc.Update(context.Background(), cmd); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("clear+set aliased clear: %v", err)
	}
}

func TestProviderSecretRotationChangesCreateAndUpdateDigest(t *testing.T) {
	repo := NewMemoryProfileRepository()
	svc, _ := NewService(repo, nil)
	create := CreateProfileCommand{IdempotencyKey: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Spec: serviceSpec(serviceProfileID, "Primary", strPtr(serviceKey1))}
	create.Spec.ProviderSecrets = map[string]string{"credential": "first-value"}
	if _, err := svc.Create(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	create.Spec.ProviderSecrets["credential"] = "rotated-value"
	if _, err := svc.Create(context.Background(), create); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("provider secret rotation aliased create replay: %v", err)
	}

	update := UpdateProfileCommand{ID: serviceProfileID, IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ExpectedRevision: 1, Spec: ProfileSpec{ID: serviceProfileID, Patch: true, ProviderSecrets: map[string]string{"credential": "second-value"}}}
	if _, err := svc.Update(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	update.Spec.ProviderSecrets["credential"] = "another-value"
	if _, err := svc.Update(context.Background(), update); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("provider secret rotation aliased update replay: %v", err)
	}
}

func TestSamplingPatchOperationsStrict(t *testing.T) {
	key := "k"
	base := validProfile(ProviderOpenAICompatible, "https://example.com", key)
	base.ID = serviceProfileID
	base.DisplayName = "p"
	cases := []ProfileSpec{
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TemperatureSet: true},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TemperatureClear: true, Temperature: ptrFloat(0.2)},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TemperatureSet: true, TemperatureClear: true, Temperature: ptrFloat(0.2)},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, Temperature: ptrFloat(0.2)},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TopPSet: true},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TopPClear: true, TopP: ptrFloat(0.2)},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TopPSet: true, TopPClear: true, TopP: ptrFloat(0.2)},
		{ID: base.ID, DisplayName: "p", Provider: base.Provider, Model: base.Model, TopP: ptrFloat(0.2)},
	}
	for i, spec := range cases {
		if _, err := UpdateProfile(base, spec); err == nil {
			t.Fatalf("sampling case %d accepted", i)
		}
	}
}

func TestServiceConnectionTestingIsReadOnlyAndSafe(t *testing.T) {
	repo := NewMemoryProfileRepository()
	tester := ConnectionTesterFunc(func(_ context.Context, p Profile) error {
		if p.APIKey != serviceKey1 {
			t.Fatal("tester did not receive secret internally")
		}
		return errors.New("provider body contains " + serviceKey1)
	})
	svc, _ := NewService(repo, tester)
	_, err := svc.Create(context.Background(), CreateProfileCommand{IdempotencyKey: "99999999-9999-4999-8999-999999999999", Spec: serviceSpec(serviceProfileID, "Primary", strPtr(serviceKey1))})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.TestConnection(context.Background(), serviceProfileID)
	if err != nil || result.OK || result.ErrorCode != "provider_unavailable" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, err := svc.Get(context.Background(), serviceProfileID); err != nil {
		t.Fatal("connection test mutated profile")
	}
}

func strPtr(v string) *string { return &v }
func uuidForTest(n int) string {
	return []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}[n-5]
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
