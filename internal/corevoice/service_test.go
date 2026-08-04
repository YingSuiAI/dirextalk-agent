package corevoice

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testProfiles struct{ enabled bool }

func (p testProfiles) Resolve(context.Context, string, CreateRequest) (ProfileBinding, error) {
	return ProfileBinding{ConversationProfileID: "conv-profile", SpeechProfileID: "speech-profile", ClientTranscriptEnabled: p.enabled, WebhookSecret: "callback-secret"}, nil
}

type testProvider struct {
	mu          sync.Mutex
	created     int
	started     int
	interrupted int
	ended       int
}

func (p *testProvider) Create(_ context.Context, _ string, s Session, _ ProfileBinding) (ProviderSession, error) {
	p.mu.Lock()
	p.created++
	p.mu.Unlock()
	return ProviderSession{AppID: "app", VoiceChatAppID: "voice-app", AIUserID: "ai", RoomID: "room", UserID: "user", Token: "token-" + s.ID, ProviderHandle: "handle-" + s.ID, ExpiresAt: s.ExpiresAt}, nil
}
func (p *testProvider) Start(context.Context, string, Session, ProfileBinding) error {
	p.mu.Lock()
	p.started++
	p.mu.Unlock()
	return nil
}
func (p *testProvider) Interrupt(context.Context, string, Session, ProfileBinding) error {
	p.mu.Lock()
	p.interrupted++
	p.mu.Unlock()
	return nil
}
func (p *testProvider) End(context.Context, string, Session, ProfileBinding) error {
	p.mu.Lock()
	p.ended++
	p.mu.Unlock()
	return nil
}

type testRunner struct{}

func (testRunner) Run(_ context.Context, _ string, _ Session, _ Turn, emit func(StreamEvent) error) error {
	if err := emit(StreamEvent{Event: "delta", Text: "hello"}); err != nil {
		return err
	}
	return nil
}
func (testRunner) Cancel(context.Context, string, string) error { return nil }

func newVoiceTestService(t *testing.T, enabled bool) (*Service, *MemoryStore, *testProvider) {
	t.Helper()
	store := NewMemoryStore()
	provider := &testProvider{}
	service, err := NewService(store, testProfiles{enabled: enabled}, provider, testRunner{})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, provider
}

func TestVoiceLifecycleIdempotencyAndOwnerGenerationFence(t *testing.T) {
	service, store, provider := newVoiceTestService(t, true)
	defer service.Close()
	ctx := context.Background()
	created, err := service.Create(ctx, "owner-a", 7, CreateRequest{ConversationID: "conversation-a"}, "create-1")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.Create(ctx, "owner-a", 7, CreateRequest{ConversationID: "conversation-a"}, "create-1")
	if err != nil || replayed.SessionID != created.SessionID || replayed.Token != created.Token {
		t.Fatalf("create replay = %+v, err=%v", replayed, err)
	}
	if provider.created != 1 {
		t.Fatalf("provider create count=%d", provider.created)
	}
	if _, err := service.Start(ctx, "owner-b", 7, created.SessionID, "start-b"); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign owner start err=%v", err)
	}
	if _, err := service.Start(ctx, "owner-a", 8, created.SessionID, "start-new-generation"); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrForbidden) {
		t.Fatalf("stale generation start err=%v", err)
	}
	started, err := service.Start(ctx, "owner-a", 7, created.SessionID, "start-1")
	if err != nil || started["started"] != true {
		t.Fatalf("start=%v err=%v", started, err)
	}
	startedReplay, err := service.Start(ctx, "owner-a", 7, created.SessionID, "start-1")
	if err != nil || startedReplay["started"] != true {
		t.Fatalf("start replay=%v err=%v", startedReplay, err)
	}
	if provider.started != 1 {
		t.Fatalf("provider start count=%d", provider.started)
	}
	accepted, err := service.Transcript(ctx, "owner-a", 7, created.SessionID, "hello", "turn-1")
	if err != nil || accepted["accepted"] != true {
		t.Fatalf("transcript=%v err=%v", accepted, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		turn, getErr := store.GetTurn(ctx, "owner-a", created.SessionID, created.SessionID+"_turn_"+shortDigest("turn-1"), 7)
		if getErr == nil && turn.State == TurnCompleted && turn.Answer == "hello" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	turn, err := store.GetTurn(ctx, "owner-a", created.SessionID, created.SessionID+"_turn_"+shortDigest("turn-1"), 7)
	if err != nil || turn.State != TurnCompleted || turn.Answer != "hello" {
		t.Fatalf("turn=%+v err=%v", turn, err)
	}
	ended, err := service.End(ctx, "owner-a", 7, created.SessionID, "end-1")
	if err != nil || ended["ended"] != true {
		t.Fatalf("end=%v err=%v", ended, err)
	}
	endedReplay, err := service.End(ctx, "owner-a", 7, created.SessionID, "end-1")
	if err != nil || endedReplay["ended"] != true {
		t.Fatalf("end replay=%v err=%v", endedReplay, err)
	}
	if provider.ended != 1 {
		t.Fatalf("provider end count=%d", provider.ended)
	}
	replay, ok, err := store.Replay(ctx, "owner-a", 7, "create", "create-1", digestValue(CreateRequest{ConversationID: "conversation-a"}))
	if err != nil || !ok || len(replay) == 0 {
		t.Fatalf("atomic create replay receipt ok=%v err=%v len=%d", ok, err, len(replay))
	}
	saved, err := store.FindSession(ctx, created.SessionID)
	if err != nil || saved.ProviderTaskID != created.SessionID {
		t.Fatalf("deterministic provider task id session=%+v err=%v", saved, err)
	}
}

func TestVoiceTranscriptDisabledAndStreamEvents(t *testing.T) {
	service, _, _ := newVoiceTestService(t, false)
	defer service.Close()
	ctx := context.Background()
	created, err := service.Create(ctx, "owner-a", 1, CreateRequest{ConversationID: "conversation"}, "create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(ctx, "owner-a", 1, created.SessionID, "start"); err != nil {
		t.Fatal(err)
	}
	response, err := service.Transcript(ctx, "owner-a", 1, created.SessionID, "hello", "transcript")
	if err != nil || response["accepted"] != false {
		t.Fatalf("disabled transcript=%v err=%v", response, err)
	}

	service2, store, _ := newVoiceTestService(t, true)
	defer service2.Close()
	created, err = service2.Create(ctx, "owner-a", 1, CreateRequest{ConversationID: "conversation"}, "create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service2.Start(ctx, "owner-a", 1, created.SessionID, "start"); err != nil {
		t.Fatal(err)
	}
	streamCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	events := make(chan Event, 8)
	go func() {
		_ = service2.Stream(streamCtx, "owner-a", 1, created.SessionID, 0, func(event Event) error { events <- event; return nil })
	}()
	if _, err := service2.Transcript(ctx, "owner-a", 1, created.SessionID, "hello", "turn"); err != nil {
		t.Fatal(err)
	}
	seenDone := false
	deadline := time.After(time.Second)
	for !seenDone {
		select {
		case event := <-events:
			if event.Event == "turn.done" {
				seenDone = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for durable voice events")
		}
	}
	if _, err := store.GetSession(ctx, "owner-a", created.SessionID, 2); !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("generation fence after stream err=%v", err)
	}
}

func TestVoiceRestartMarksInFlightUncertainAndKeepsTombstone(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().UTC()
	session := Session{ID: "voice-restart", OwnerID: "owner", AccountGeneration: 3, ConversationID: "conv", ConversationProfileID: "conv-profile", SpeechProfileID: "speech-profile", ExpiresAt: now.Add(time.Hour), State: SessionStarted, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	turn := Turn{ID: "turn-restart", SessionID: session.ID, OwnerID: session.OwnerID, AccountGeneration: session.AccountGeneration, Transcript: "pending", State: TurnRunning, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTurn(context.Background(), turn); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewService(store, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetTurn(context.Background(), session.OwnerID, session.ID, turn.ID, session.AccountGeneration)
	if err != nil || recovered.State != TurnUncertain {
		t.Fatalf("recovered turn=%+v err=%v", recovered, err)
	}
	if err := store.SaveSession(context.Background(), session, 1); err != nil {
		t.Fatal(err)
	}
	// Expiry recovery produces an ended tombstone and a terminal event.
	session.ExpiresAt = now.Add(-time.Minute)
	session.Revision = 2
	session.UpdatedAt = now
	if err := store.SaveSession(context.Background(), session, 1); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	ended, err := store.GetSession(context.Background(), session.OwnerID, session.ID, session.AccountGeneration)
	if err != nil || ended.State != SessionEnded || ended.TombstoneExpiresAt == nil {
		t.Fatalf("ended tombstone=%+v err=%v", ended, err)
	}
}

func TestVoiceRecoverRetriesPendingProviderStop(t *testing.T) {
	store := NewMemoryStore()
	provider := &testProvider{}
	service, err := NewService(store, testProfiles{enabled: true}, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	now := time.Now().UTC()
	session := Session{
		ID:                    "voice-pending-stop",
		OwnerID:               "owner",
		AccountGeneration:     4,
		ConversationID:        "conv",
		ConversationProfileID: "conv-profile",
		SpeechProfileID:       "speech-profile",
		ProviderHandle:        "opaque-handle",
		ExpiresAt:             now.Add(time.Hour),
		State:                 SessionStopping,
		Revision:              3,
		ProviderStopPending:   true,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetSession(context.Background(), session.OwnerID, session.ID, session.AccountGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ProviderStopPending || !recovered.ProviderStopped || provider.ended != 1 {
		t.Fatalf("pending provider stop recovery session=%+v provider ended=%d", recovered, provider.ended)
	}
}

func TestVoiceRecoverReconcilesProviderIntentsAfterCrashWindow(t *testing.T) {
	store := NewMemoryStore()
	provider := &testProvider{}
	service, err := NewService(store, testProfiles{enabled: true}, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	now := time.Now().UTC()
	start := Session{ID: "voice-crash-start", OwnerID: "owner", AccountGeneration: 11, ConversationID: "conv", ConversationProfileID: "conv-profile", SpeechProfileID: "speech-profile", ProviderTaskID: "stable-provider-task", ExpiresAt: now.Add(time.Hour), State: SessionCreated, Revision: 1, ProviderIntent: ProviderIntentStart, ProviderUncertain: true, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateSession(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetSession(context.Background(), start.OwnerID, start.ID, start.AccountGeneration)
	if err != nil || recovered.State != SessionStarted || recovered.ProviderIntent != ProviderIntentNone || recovered.ProviderUncertain || recovered.ProviderTaskID != start.ProviderTaskID {
		t.Fatalf("start intent recovery session=%+v err=%v", recovered, err)
	}
	end := Session{ID: "voice-crash-end", OwnerID: "owner", AccountGeneration: 11, ConversationID: "conv", ConversationProfileID: "conv-profile", SpeechProfileID: "speech-profile", ProviderTaskID: "stable-end-task", ExpiresAt: now.Add(time.Hour), State: SessionStopping, Revision: 1, ProviderIntent: ProviderIntentEnd, ProviderUncertain: true, ProviderStopPending: true, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateSession(context.Background(), end); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	ended, err := store.GetSession(context.Background(), end.OwnerID, end.ID, end.AccountGeneration)
	if err != nil || ended.State != SessionEnded || ended.ProviderIntent != ProviderIntentNone || ended.ProviderUncertain || ended.ProviderStopPending || !ended.ProviderStopped || ended.TombstoneExpiresAt == nil {
		t.Fatalf("end intent recovery session=%+v err=%v", ended, err)
	}
	if provider.started != 1 || provider.ended != 1 {
		t.Fatalf("provider reconciliation counts start=%d end=%d", provider.started, provider.ended)
	}
	expired := Session{ID: "voice-crash-expired-start", OwnerID: "owner", AccountGeneration: 11, ConversationID: "conv", ConversationProfileID: "conv-profile", SpeechProfileID: "speech-profile", ProviderTaskID: "expired-task", ExpiresAt: now.Add(-time.Minute), State: SessionCreated, Revision: 1, ProviderIntent: ProviderIntentStart, ProviderUncertain: true, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)}
	if err := store.CreateSession(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	expiredRecovered, err := store.GetSession(context.Background(), expired.OwnerID, expired.ID, expired.AccountGeneration)
	if err != nil || expiredRecovered.State != SessionEnded || expiredRecovered.ProviderIntent != ProviderIntentNone {
		t.Fatalf("expired start intent recovery session=%+v err=%v", expiredRecovered, err)
	}
	if provider.started != 1 {
		t.Fatalf("expired start was incorrectly retried: starts=%d", provider.started)
	}
}

func TestVoiceCallbackSignatureAndGenerationFence(t *testing.T) {
	service, _, _ := newVoiceTestService(t, true)
	defer service.Close()
	ctx := context.Background()
	created, err := service.Create(ctx, "owner-a", 9, CreateRequest{ConversationID: "conversation"}, "create")
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.AuthorizeCallback(ctx, created.SessionID, callbackHMAC("callback-secret", created.SessionID, timeFromRFC3339(t, created.ExpiresAt)), 9)
	if err != nil || session.ID != created.SessionID {
		t.Fatalf("valid callback rejected session=%+v err=%v", session, err)
	}
	if _, err := service.AuthorizeCallback(ctx, created.SessionID, "forged", 9); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forged callback err=%v", err)
	}
	if _, err := service.AuthorizeCallback(ctx, created.SessionID, callbackHMAC("callback-secret", created.SessionID, timeFromRFC3339(t, created.ExpiresAt)), 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("generation callback err=%v", err)
	}
}

func TestVoiceCallbackCustomLLMUsesProviderPayloadFence(t *testing.T) {
	service, _, _ := newVoiceTestService(t, true)
	defer service.Close()
	ctx := context.Background()
	created, err := service.Create(ctx, "owner-a", 9, CreateRequest{ConversationID: "conversation"}, "create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(ctx, "owner-a", 9, created.SessionID, "start"); err != nil {
		t.Fatal(err)
	}
	token := callbackHMAC("callback-secret", created.SessionID, timeFromRFC3339(t, created.ExpiresAt))
	if err := service.ValidateProviderPayload(ctx, created.SessionID, token, map[string]any{"session_id": created.SessionID, "RoomId": "room"}, 9); err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateProviderPayload(ctx, created.SessionID, token, map[string]any{"session_id": created.SessionID, "RoomId": "wrong"}, 9); !errors.Is(err, ErrForbidden) {
		t.Fatalf("identity mismatch err=%v", err)
	}
	if err := service.ValidateProviderPayload(ctx, created.SessionID, token, map[string]any{"session_id": created.SessionID}, 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stale generation err=%v", err)
	}
	var answer string
	if err := service.RunCallback(ctx, created.SessionID, token, "hello", "provider-request-1", func(event StreamEvent) error {
		if event.Event == "delta" {
			answer += event.Text
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if answer != "hello" {
		t.Fatalf("callback answer=%q", answer)
	}
	var replay string
	if err := service.RunCallback(ctx, created.SessionID, token, "hello", "provider-request-1", func(event StreamEvent) error {
		if event.Event == "delta" {
			replay += event.Text
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if replay != "hello" {
		t.Fatalf("callback replay=%q", replay)
	}
}

func timeFromRFC3339(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
