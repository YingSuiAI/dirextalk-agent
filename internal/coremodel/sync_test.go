package coremodel

import (
	"context"
	"errors"
	"testing"
)

func TestSyncProfilesIsAtomicAndBatchIdempotent(t *testing.T) {
	repo := NewMemoryProfileRepository()
	service, err := NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "a0000000-0000-4000-8000-000000000001"
	first, err := service.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: key, DefaultClientProfileID: "primary", Entries: []SyncProfileEntry{{ClientProfileID: "primary", DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("secret")}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Profiles) != 1 || first.Profiles[0].APIKeyConfigured != true || first.Profiles[0].ClientProfileID != "primary" {
		t.Fatalf("result=%+v", first)
	}
	replay, err := service.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: key, DefaultClientProfileID: "primary", Entries: []SyncProfileEntry{{ClientProfileID: "primary", DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("secret")}}})
	if err != nil || !replay.Replay || replay.Profiles[0].Revision != first.Profiles[0].Revision {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	_, err = service.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000002", DefaultClientProfileID: "primary", Entries: []SyncProfileEntry{{ClientProfileID: "primary", ExpectedRevision: int64Ptr(1), DisplayName: "Changed", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("rotated")}, {ClientProfileID: "bad", DisplayName: "", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("key")}}})
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("invalid batch err=%v", err)
	}
	got, err := service.Get(context.Background(), first.Profiles[0].ID)
	if err != nil || got.DisplayName != "Primary" || got.Revision != 1 {
		t.Fatalf("atomic state=%+v err=%v", got, err)
	}
}

func TestSyncProfilesPreservesMissingProfilesAndRotatesWriteOnlyKey(t *testing.T) {
	svc := newSyncTestService(t)
	first := mustSync(t, svc, "a0000000-0000-4000-8000-000000000010", "primary", syncEntry("primary", "Primary", "first"), syncEntry("secondary", "Secondary", "second"))
	if len(first.Profiles) != 2 || first.Profiles[0].ClientProfileID != "primary" || first.Profiles[1].ClientProfileID != "secondary" {
		t.Fatalf("response order=%+v", first.Profiles)
	}
	updated := mustSync(t, svc, "a0000000-0000-4000-8000-000000000011", "secondary", SyncProfileEntry{ClientProfileID: "secondary", ExpectedRevision: int64Ptr(1), DisplayName: "Secondary v2", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil})
	if len(updated.Profiles) != 1 || updated.Profiles[0].ClientProfileID != "secondary" {
		t.Fatalf("update response=%+v", updated.Profiles)
	}
	secondary, err := svc.ResolveProfile(context.Background(), updated.Profiles[0].ID)
	if err != nil || secondary.APIKey != "second" {
		t.Fatalf("preserved key=%q err=%v", secondary.APIKey, err)
	}
	rotated := mustSync(t, svc, "a0000000-0000-4000-8000-000000000012", "secondary", SyncProfileEntry{ClientProfileID: "secondary", ExpectedRevision: int64Ptr(2), DisplayName: "Secondary v3", Provider: ProviderOpenAICompatible, Model: "model", APIKey: stringPtr("rotated")})
	resolved, err := svc.ResolveProfile(context.Background(), rotated.Profiles[0].ID)
	if err != nil || resolved.APIKey != "rotated" || resolved.Revision != 3 {
		t.Fatalf("rotated profile=%+v err=%v", resolved, err)
	}
	page, err := svc.List(context.Background(), ListProfileCommand{Limit: 10})
	if err != nil || len(page.Profiles) != 2 {
		t.Fatalf("missing profile was deleted: page=%+v err=%v", page, err)
	}
}

func TestSyncProfilesStaleAndDefaultFailuresRollBackBatch(t *testing.T) {
	svc := newSyncTestService(t)
	created := mustSync(t, svc, "a0000000-0000-4000-8000-000000000020", "one", syncEntry("one", "One", "one-key"), syncEntry("two", "Two", "two-key"))
	_, err := svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000021", DefaultClientProfileID: "one", Entries: []SyncProfileEntry{
		{ClientProfileID: "one", ExpectedRevision: int64Ptr(1), DisplayName: "One changed", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil},
		{ClientProfileID: "two", ExpectedRevision: int64Ptr(99), DisplayName: "Two changed", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil},
	}})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale batch err=%v", err)
	}
	one, _ := svc.Get(context.Background(), created.Profiles[0].ID)
	two, _ := svc.Get(context.Background(), created.Profiles[1].ID)
	if one.DisplayName != "One" || two.DisplayName != "Two" || one.Revision != 1 || two.Revision != 1 {
		t.Fatalf("stale batch partially applied: one=%+v two=%+v", one, two)
	}
	_, err = svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000022", DefaultClientProfileID: "missing", Entries: []SyncProfileEntry{{ClientProfileID: "one", ExpectedRevision: int64Ptr(1), DisplayName: "One changed", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil}}})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("default batch err=%v", err)
	}
	one, _ = svc.Get(context.Background(), created.Profiles[0].ID)
	if one.DisplayName != "One" || one.Revision != 1 {
		t.Fatalf("default failure partially applied: %+v", one)
	}
}

func TestSyncProfilesDigestConflictAndOverlappingRevisionFence(t *testing.T) {
	svc := newSyncTestService(t)
	created := mustSync(t, svc, "a0000000-0000-4000-8000-000000000030", "one", syncEntry("one", "One", "key"))
	request := SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000031", DefaultClientProfileID: "one", Entries: []SyncProfileEntry{{ClientProfileID: "one", ExpectedRevision: int64Ptr(1), DisplayName: "One v2", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil}}}
	first, err := svc.Sync(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.Sync(context.Background(), request)
	if err != nil || !replay.Replay || replay.Profiles[0].Revision != first.Profiles[0].Revision || replay.Profiles[0].APIKeyConfigured != first.Profiles[0].APIKeyConfigured {
		t.Fatalf("sanitized replay=%+v err=%v", replay, err)
	}
	request.Entries[0].DisplayName = "different"
	if _, err := svc.Sync(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest conflict err=%v", err)
	}
	base := int64(2)
	left, right := request, request
	left.Entries = append([]SyncProfileEntry(nil), request.Entries...)
	right.Entries = append([]SyncProfileEntry(nil), request.Entries...)
	left.IdempotencyKey = "a0000000-0000-4000-8000-000000000032"
	right.IdempotencyKey = "a0000000-0000-4000-8000-000000000033"
	left.Entries[0].ExpectedRevision, right.Entries[0].ExpectedRevision = &base, &base
	left.Entries[0].DisplayName, right.Entries[0].DisplayName = "left", "right"
	results := make(chan error, 2)
	go func() { _, e := svc.Sync(context.Background(), left); results <- e }()
	go func() { _, e := svc.Sync(context.Background(), right); results <- e }()
	var successes, conflicts int
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("overlap successes=%d conflicts=%d", successes, conflicts)
	}
	_ = created
}

func TestSyncProviderSecretRotationChangesDigest(t *testing.T) {
	svc := newSyncTestService(t)
	request := SyncProfileCommand{
		IdempotencyKey:         "a0000000-0000-4000-8000-000000000040",
		DefaultSpeechProfileID: "speech",
		Entries: []SyncProfileEntry{{
			ClientProfileID: "speech", DisplayName: "Speech", Provider: ProviderVolcVoice,
			ModelKind: ModelKindSpeech, ProviderSecrets: map[string]string{"rtc_app_key": "first-value"},
		}},
	}
	if _, err := svc.Sync(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Entries[0].ProviderSecrets["rtc_app_key"] = "rotated-value"
	if _, err := svc.Sync(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("provider secret rotation aliased sync replay: %v", err)
	}
}

func newSyncTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func syncEntry(id, name, key string) SyncProfileEntry {
	return SyncProfileEntry{ClientProfileID: id, DisplayName: name, Provider: ProviderOpenAICompatible, Model: "model", APIKey: stringPtr(key)}
}

func mustSync(t *testing.T, svc *Service, key, defaultID string, entries ...SyncProfileEntry) SyncProfileResult {
	t.Helper()
	result, err := svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: key, DefaultClientProfileID: defaultID, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func stringPtr(v string) *string { return &v }
func int64Ptr(v int64) *int64    { return &v }
