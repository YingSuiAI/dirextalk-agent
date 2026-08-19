package coremodel

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSyncProfilesIsAtomicAndBatchIdempotent(t *testing.T) {
	repo := NewMemoryProfileRepository()
	service, err := NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "a0000000-0000-4000-8000-000000000001"
	first, err := service.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: key, DefaultConversationProfileID: "primary", Entries: []SyncProfileEntry{{ClientProfileID: "primary", DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("secret")}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Profiles) != 1 || first.Profiles[0].APIKeyConfigured != true || first.Profiles[0].ClientProfileID != "primary" {
		t.Fatalf("result=%+v", first)
	}
	replay, err := service.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: key, DefaultConversationProfileID: "primary", Entries: []SyncProfileEntry{{ClientProfileID: "primary", DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("secret")}}})
	if err != nil || !replay.Replay || replay.Profiles[0].Revision != first.Profiles[0].Revision {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	_, err = service.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000002", DefaultConversationProfileID: "primary", Entries: []SyncProfileEntry{{ClientProfileID: "primary", ExpectedRevision: int64Ptr(1), DisplayName: "Changed", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("rotated")}, {ClientProfileID: "bad", DisplayName: "", Provider: ProviderOpenAICompatible, Model: "gpt", APIKey: stringPtr("key")}}})
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("invalid batch err=%v", err)
	}
	got, err := service.Get(context.Background(), first.Profiles[0].ID)
	if err != nil || got.DisplayName != "Primary" || got.Revision != 1 {
		t.Fatalf("atomic state=%+v err=%v", got, err)
	}
}

func TestSyncProfilesNoOpPreservesRevision(t *testing.T) {
	svc := newSyncTestService(t)
	created := mustSync(t, svc, "a0000000-0000-4000-8000-000000000003", "primary", syncEntry("primary", "Primary", "secret"))
	first := created.Profiles[0]

	unchanged := mustSync(t, svc, "a0000000-0000-4000-8000-000000000004", "primary", SyncProfileEntry{
		ClientProfileID: "primary", ExpectedRevision: int64Ptr(1), DisplayName: "Primary",
		Provider: ProviderOpenAICompatible, Model: "model",
	})
	if got := unchanged.Profiles[0]; got.Revision != 1 || got.CredentialVersion != 1 || !got.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("no-op sync changed profile: before=%+v after=%+v", first, got)
	}

	if _, err := svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000005", Entries: []SyncProfileEntry{{
		ClientProfileID: "primary", ExpectedRevision: int64Ptr(2), DisplayName: "Primary",
		Provider: ProviderOpenAICompatible, Model: "model",
	}}}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale no-op sync err=%v", err)
	}

	changed := mustSync(t, svc, "a0000000-0000-4000-8000-000000000006", "primary", SyncProfileEntry{
		ClientProfileID: "primary", ExpectedRevision: int64Ptr(1), DisplayName: "Primary v2",
		Provider: ProviderOpenAICompatible, Model: "model",
	})
	if got := changed.Profiles[0]; got.Revision != 2 || got.CredentialVersion != 1 {
		t.Fatalf("real change was not revisioned: %+v", got)
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
	if err != nil || resolved.APIKey != "rotated" || resolved.Revision != 3 || resolved.CredentialVersion != 2 {
		t.Fatalf("rotated profile=%+v err=%v", resolved, err)
	}
	page, err := svc.List(context.Background(), ListProfileCommand{Limit: 10})
	if err != nil || len(page.Profiles) != 2 {
		t.Fatalf("missing profile was deleted: page=%+v err=%v", page, err)
	}
}

func TestSyncProfilesPersistsIndependentConversationKindToolDefault(t *testing.T) {
	repo := NewMemoryProfileRepository()
	svc, err := NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Sync(context.Background(), SyncProfileCommand{
		IdempotencyKey:               "a0000000-0000-4000-8000-000000000060",
		DefaultConversationProfileID: "chat",
		Entries:                      []SyncProfileEntry{syncEntry("chat", "Chat", "chat-key")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.DefaultConversationProfileID != "chat" || first.DefaultToolProfileID != "chat" {
		t.Fatalf("unique configured conversation profile did not converge both independent roles: %+v", first)
	}
	bound, err := svc.Sync(context.Background(), SyncProfileCommand{
		IdempotencyKey:       "a0000000-0000-4000-8000-000000000061",
		DefaultToolProfileID: "tool",
		Entries:              []SyncProfileEntry{syncEntry("tool", "Tool", "tool-key")},
	})
	if err != nil || bound.DefaultToolProfileID != "tool" {
		t.Fatalf("tool default=%+v err=%v", bound, err)
	}
	page, err := svc.List(context.Background(), ListProfileCommand{Limit: 10})
	if err != nil || page.Defaults.ToolClientProfileID != "tool" || page.Defaults.ConversationClientProfileID != "chat" {
		t.Fatalf("durable defaults=%+v err=%v", page.Defaults, err)
	}

	for index, entry := range []SyncProfileEntry{
		{ClientProfileID: "embed", DisplayName: "Embed", Provider: ProviderOpenAICompatible, ModelKind: ModelKindEmbedding, Model: "embed", APIKey: stringPtr("embed-key")},
		{ClientProfileID: "speech", DisplayName: "Speech", Provider: ProviderVolcVoice, ModelKind: ModelKindSpeech},
	} {
		_, err = svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: []string{"a0000000-0000-4000-8000-000000000062", "a0000000-0000-4000-8000-000000000063"}[index], DefaultToolProfileID: entry.ClientProfileID, Entries: []SyncProfileEntry{entry}})
		if !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("tool default accepted %s profile: %v", entry.ModelKind, err)
		}
	}
	if _, err = svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000064", DefaultEmbeddingProfileID: "embed", Entries: []SyncProfileEntry{{ClientProfileID: "embed", DisplayName: "Embed", Provider: ProviderOpenAICompatible, ModelKind: ModelKindEmbedding, Model: "embed", APIKey: stringPtr("embed-key")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.SyncProfiles(context.Background(), "a0000000-0000-4000-8000-000000000065", "memory-store-tool-kind", SyncProfileCommand{DefaultToolProfileID: "embed"}); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("memory repository accepted embedding tool default: %v", err)
	}
}

func TestConfiguredModelDefaultsConvergeByRole(t *testing.T) {
	valid := func(clientID, kind string) Profile {
		createdAt := time.Unix(1, 0).UTC()
		switch clientID {
		case "chat-two", "tool-two", "embed-two":
			createdAt = time.Unix(2, 0).UTC()
		case "chat-three", "tool-three", "embed-three":
			createdAt = time.Unix(3, 0).UTC()
		}
		return Profile{ID: SyncProfileID(clientID), ClientProfileID: clientID, Provider: ProviderOpenAICompatible,
			RequestDialect: DialectOpenAICompatibleChatV1, ModelKind: kind, APIKey: "configured", Revision: 1, CredentialVersion: 1, CreatedAt: createdAt}
	}
	tests := []struct {
		name     string
		role     string
		current  string
		profiles []Profile
		want     string
	}{
		{name: "conversation zero", role: ModelKindConversation},
		{name: "conversation unique", role: ModelKindConversation, profiles: []Profile{valid("chat-one", ModelKindConversation)}, want: "chat-one"},
		{name: "conversation multiple selects first", role: ModelKindConversation, profiles: []Profile{valid("chat-two", ModelKindConversation), valid("chat-one", ModelKindConversation)}, want: "chat-one"},
		{name: "conversation preserves explicit among multiple", role: ModelKindConversation, current: "chat-two", profiles: []Profile{valid("chat-one", ModelKindConversation), valid("chat-two", ModelKindConversation)}, want: "chat-two"},
		{name: "conversation invalid default converges unique", role: ModelKindConversation, current: "removed", profiles: []Profile{valid("chat-one", ModelKindConversation)}, want: "chat-one"},
		{name: "conversation invalid default selects next", role: ModelKindConversation, current: "chat-one", profiles: []Profile{func() Profile { p := valid("chat-one", ModelKindConversation); p.APIKey = ""; return p }(), valid("chat-two", ModelKindConversation), valid("chat-three", ModelKindConversation)}, want: "chat-two"},
		{name: "conversation invalid last wraps first", role: ModelKindConversation, current: "chat-three", profiles: []Profile{valid("chat-one", ModelKindConversation), valid("chat-two", ModelKindConversation), func() Profile { p := valid("chat-three", ModelKindConversation); p.APIKey = ""; return p }()}, want: "chat-one"},
		{name: "tool zero", role: "tool"},
		{name: "tool unique", role: "tool", profiles: []Profile{valid("tool-one", ModelKindConversation)}, want: "tool-one"},
		{name: "tool multiple selects first", role: "tool", profiles: []Profile{valid("tool-two", ModelKindConversation), valid("tool-one", ModelKindConversation)}, want: "tool-one"},
		{name: "tool preserves explicit among multiple", role: "tool", current: "tool-two", profiles: []Profile{valid("tool-one", ModelKindConversation), valid("tool-two", ModelKindConversation)}, want: "tool-two"},
		{name: "tool invalid default converges unique", role: "tool", current: "removed", profiles: []Profile{valid("tool-one", ModelKindConversation)}, want: "tool-one"},
		{name: "tool invalid default selects next", role: "tool", current: "tool-one", profiles: []Profile{func() Profile { p := valid("tool-one", ModelKindConversation); p.APIKey = ""; return p }(), valid("tool-two", ModelKindConversation)}, want: "tool-two"},
		{name: "embedding zero", role: ModelKindEmbedding},
		{name: "embedding unique", role: ModelKindEmbedding, profiles: []Profile{valid("embed-one", ModelKindEmbedding)}, want: "embed-one"},
		{name: "embedding multiple selects first", role: ModelKindEmbedding, profiles: []Profile{valid("embed-two", ModelKindEmbedding), valid("embed-one", ModelKindEmbedding)}, want: "embed-one"},
		{name: "embedding preserves explicit among multiple", role: ModelKindEmbedding, current: "embed-two", profiles: []Profile{valid("embed-one", ModelKindEmbedding), valid("embed-two", ModelKindEmbedding)}, want: "embed-two"},
		{name: "embedding invalid default converges unique", role: ModelKindEmbedding, current: "removed", profiles: []Profile{valid("embed-one", ModelKindEmbedding)}, want: "embed-one"},
		{name: "embedding invalid last wraps first", role: ModelKindEmbedding, current: "embed-two", profiles: []Profile{valid("embed-one", ModelKindEmbedding), func() Profile { p := valid("embed-two", ModelKindEmbedding); p.APIKey = ""; return p }()}, want: "embed-one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profiles := make(map[string]Profile, len(test.profiles))
			for _, profile := range test.profiles {
				profiles[profile.ID] = profile
			}
			defaults := ProfileDefaults{}
			switch test.role {
			case ModelKindConversation:
				defaults.ConversationClientProfileID = test.current
			case "tool":
				defaults.ToolClientProfileID = test.current
			case ModelKindEmbedding:
				defaults.EmbeddingClientProfileID = test.current
			}
			got := convergeMemoryProfileDefaults(defaults, profiles)
			var selected string
			switch test.role {
			case ModelKindConversation:
				selected = got.ConversationClientProfileID
			case "tool":
				selected = got.ToolClientProfileID
			case ModelKindEmbedding:
				selected = got.EmbeddingClientProfileID
			}
			if selected != test.want {
				t.Fatalf("selected=%q want=%q defaults=%+v", selected, test.want, got)
			}
		})
	}
}

func TestSyncProfilesPreservesAndReplacesProviderSecrets(t *testing.T) {
	svc := newSyncTestService(t)
	first := mustSync(t, svc, "a0000000-0000-4000-8000-000000000050", "primary", SyncProfileEntry{
		ClientProfileID: "primary", DisplayName: "Primary", Provider: ProviderOpenAICompatible, Model: "model", APIKey: stringPtr("api-key"), ProviderSecrets: map[string]string{"rtc_app_key": "first"},
	})
	if first.Profiles[0].CredentialVersion != 1 {
		t.Fatalf("initial credential version=%d, want 1", first.Profiles[0].CredentialVersion)
	}
	profileID := first.Profiles[0].ID
	preserved := mustSync(t, svc, "a0000000-0000-4000-8000-000000000051", "primary", SyncProfileEntry{
		ClientProfileID: "primary", ExpectedRevision: int64Ptr(1), DisplayName: "Primary preserved", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil, ProviderSecrets: nil,
	})
	resolved, err := svc.ResolveProfile(context.Background(), profileID)
	if err != nil || resolved.ProviderSecrets["rtc_app_key"] != "first" || preserved.Profiles[0].CredentialVersion != 1 {
		t.Fatalf("nil provider secrets did not preserve material: profile=%+v result=%+v err=%v", resolved, preserved, err)
	}
	replaced := mustSync(t, svc, "a0000000-0000-4000-8000-000000000052", "primary", SyncProfileEntry{
		ClientProfileID: "primary", ExpectedRevision: int64Ptr(2), DisplayName: "Primary replaced", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil, ProviderSecrets: map[string]string{"rtc_app_key": "second"},
	})
	resolved, err = svc.ResolveProfile(context.Background(), profileID)
	if err != nil || resolved.ProviderSecrets["rtc_app_key"] != "second" || replaced.Profiles[0].CredentialVersion != 2 {
		t.Fatalf("provider secret replacement did not rotate: profile=%+v result=%+v err=%v", resolved, replaced, err)
	}
	cleared := mustSync(t, svc, "a0000000-0000-4000-8000-000000000053", "primary", SyncProfileEntry{
		ClientProfileID: "primary", ExpectedRevision: int64Ptr(3), DisplayName: "Primary cleared", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil, ProviderSecrets: map[string]string{},
	})
	resolved, err = svc.ResolveProfile(context.Background(), profileID)
	if err != nil || len(resolved.ProviderSecrets) != 0 || cleared.Profiles[0].CredentialVersion != 3 {
		t.Fatalf("explicit provider secret clear did not rotate: profile=%+v result=%+v err=%v", resolved, cleared, err)
	}
}

func TestSyncProfilesStaleAndDefaultFailuresRollBackBatch(t *testing.T) {
	svc := newSyncTestService(t)
	created := mustSync(t, svc, "a0000000-0000-4000-8000-000000000020", "one", syncEntry("one", "One", "one-key"), syncEntry("two", "Two", "two-key"))
	_, err := svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000021", DefaultConversationProfileID: "one", Entries: []SyncProfileEntry{
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
	_, err = svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000022", DefaultConversationProfileID: "missing", Entries: []SyncProfileEntry{{ClientProfileID: "one", ExpectedRevision: int64Ptr(1), DisplayName: "One changed", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil}}})
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
	request := SyncProfileCommand{IdempotencyKey: "a0000000-0000-4000-8000-000000000031", DefaultConversationProfileID: "one", Entries: []SyncProfileEntry{{ClientProfileID: "one", ExpectedRevision: int64Ptr(1), DisplayName: "One v2", Provider: ProviderOpenAICompatible, Model: "model", APIKey: nil}}}
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
	result, err := svc.Sync(context.Background(), SyncProfileCommand{IdempotencyKey: key, DefaultConversationProfileID: defaultID, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func stringPtr(v string) *string { return &v }
func int64Ptr(v int64) *int64    { return &v }
