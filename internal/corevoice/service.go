package corevoice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	store    Store
	profiles ProfileResolver
	provider Provider
	runner   TranscriptRunner
	now      func() time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	workers  sync.WaitGroup
	mu       sync.Mutex
}

func NewService(store Store, profiles ProfileResolver, provider Provider, runner TranscriptRunner) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{store: store, profiles: profiles, provider: provider, runner: runner, now: func() time.Time { return time.Now().UTC() }, ctx: ctx, cancel: cancel}, nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	s.workers.Wait()
	return nil
}

// Recover is called by the Agent composition after migrations and before the
// capability server advertises readiness. Running/running transcript turns
// are made explicitly uncertain; they are never silently replayed.
func (s *Service) Recover(ctx context.Context) error {
	if s == nil || s.store == nil {
		return ErrInvalid
	}
	if err := s.store.Recover(ctx, s.clock()); err != nil {
		return err
	}
	if s.provider == nil {
		return nil
	}
	intents, err := s.store.ListProviderIntents(ctx)
	if err != nil {
		return err
	}
	for _, session := range intents {
		if err := s.reconcileProviderIntent(ctx, session); err != nil {
			// A provider outage or a temporarily unavailable profile must not
			// erase the intent. The next restart/recovery pass retries it.
			continue
		}
	}
	pending, err := s.store.ListPendingStops(ctx)
	if err != nil {
		return err
	}
	for _, session := range pending {
		binding, resolveErr := s.binding(ctx, session.OwnerID, session)
		if resolveErr != nil {
			continue
		}
		if session.ProviderIntent != ProviderIntentNone || session.ProviderUncertain {
			// End intents were handled above. Keep this pass for legacy pending
			// rows written before intent columns existed.
			continue
		}
		if providerErr := s.provider.End(ctx, session.OwnerID, session, binding); providerErr != nil {
			continue
		}
		current, getErr := s.store.GetSession(ctx, session.OwnerID, session.ID, session.AccountGeneration)
		if getErr != nil || !current.ProviderStopPending {
			continue
		}
		current.ProviderStopPending, current.ProviderStopped, current.UpdatedAt, current.Revision = false, true, s.clock(), current.Revision+1
		_ = s.store.SaveSession(ctx, current, current.Revision-1)
	}
	return nil
}

func (s *Service) reconcileProviderIntent(ctx context.Context, session Session) error {
	if session.ProviderIntent == ProviderIntentNone {
		return nil
	}
	// Recovery must never resurrect an expired/ended session whose process
	// died after recording a Start or Interrupt intent.  If a provider handle
	// exists, converge by stopping it; otherwise only the local tombstone is
	// needed.
	if (session.State == SessionEnded || !s.clock().Before(session.ExpiresAt)) && session.ProviderIntent != ProviderIntentEnd {
		if strings.TrimSpace(session.ProviderHandle) != "" {
			binding, err := s.binding(ctx, session.OwnerID, session)
			if err != nil {
				return err
			}
			if providerErr := s.provider.End(ctx, session.OwnerID, session, binding); providerErr != nil {
				s.rememberProviderError(ctx, session, providerErr)
				return fmtProvider(providerErr)
			}
		}
		current, err := s.store.GetSession(ctx, session.OwnerID, session.ID, session.AccountGeneration)
		if err != nil || current.ProviderIntent != session.ProviderIntent {
			return err
		}
		now := s.clock()
		current.State = SessionEnded
		if current.EndedAt == nil {
			current.EndedAt = &now
		}
		if current.TombstoneExpiresAt == nil {
			current.TombstoneExpiresAt = ptrTime(now.Add(TombstoneTTL))
		}
		current.ActiveTurnID, current.ProviderStopped, current.ProviderStopPending = "", true, false
		current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentNone, false, ""
		current.ProviderTaskID = providerTaskID(current)
		current.UpdatedAt, current.Revision = now, current.Revision+1
		return s.store.SaveSession(ctx, current, current.Revision-1)
	}
	binding, err := s.binding(ctx, session.OwnerID, session)
	if err != nil {
		return err
	}
	var providerErr error
	switch session.ProviderIntent {
	case ProviderIntentStart:
		providerErr = s.provider.Start(ctx, session.OwnerID, session, binding)
	case ProviderIntentInterrupt:
		providerErr = s.provider.Interrupt(ctx, session.OwnerID, session, binding)
	case ProviderIntentEnd:
		providerErr = s.provider.End(ctx, session.OwnerID, session, binding)
	case ProviderIntentCreate:
		// Create is intentionally not persisted before the provider call (the
		// provider returns the opaque handle/token needed for the row). If a
		// future adapter records this intent, an existing handle is enough to
		// safely converge by stopping the remote task.
		if strings.TrimSpace(session.ProviderHandle) != "" {
			providerErr = s.provider.End(ctx, session.OwnerID, session, binding)
		}
	default:
		return ErrInvalid
	}
	if providerErr != nil {
		s.rememberProviderError(ctx, session, providerErr)
		return fmtProvider(providerErr)
	}
	current, err := s.store.GetSession(ctx, session.OwnerID, session.ID, session.AccountGeneration)
	if err != nil {
		return err
	}
	if current.ProviderIntent != session.ProviderIntent {
		return nil
	}
	now := s.clock()
	switch session.ProviderIntent {
	case ProviderIntentStart:
		current.State = SessionStarted
		if current.StartedAt == nil {
			current.StartedAt = &now
		}
		current.ProviderStopped, current.ProviderStopPending = false, false
	case ProviderIntentEnd, ProviderIntentCreate:
		current.State = SessionEnded
		if current.EndedAt == nil {
			current.EndedAt = &now
		}
		if current.TombstoneExpiresAt == nil {
			current.TombstoneExpiresAt = ptrTime(now.Add(TombstoneTTL))
		}
		current.ActiveTurnID, current.ProviderStopped, current.ProviderStopPending = "", true, false
	case ProviderIntentInterrupt:
		// Interrupt leaves the session in its existing state; only the
		// provider intent needs acknowledgement.
	}
	current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentNone, false, ""
	current.ProviderTaskID = providerTaskID(current)
	current.UpdatedAt, current.Revision = now, current.Revision+1
	return s.store.SaveSession(ctx, current, current.Revision-1)
}

func (s *Service) rememberProviderError(ctx context.Context, session Session, providerErr error) {
	current, err := s.store.GetSession(ctx, session.OwnerID, session.ID, session.AccountGeneration)
	if err != nil || current.ProviderIntent != session.ProviderIntent {
		return
	}
	current.ProviderLastError = providerErrorMessage(providerErr)
	current.ProviderUncertain = true
	current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
	_ = s.store.SaveSession(context.Background(), current, current.Revision-1)
}

// AuthorizeCallback authenticates the opaque provider callback token and
// returns the owner-fenced session. It intentionally does not expose owner or
// profile data to the caller before the HMAC comparison succeeds.
func (s *Service) AuthorizeCallback(ctx context.Context, sessionID, token string, expectedGeneration ...int64) (Session, error) {
	if s == nil || s.store == nil || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(token) == "" {
		return Session{}, ErrForbidden
	}
	session, err := s.store.FindSession(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	if len(expectedGeneration) > 0 && expectedGeneration[0] > 0 && session.AccountGeneration != expectedGeneration[0] {
		return Session{}, ErrForbidden
	}
	if session.State == SessionEnded || !s.clock().Before(session.ExpiresAt) {
		return Session{}, ErrExpired
	}
	binding, err := s.binding(ctx, session.OwnerID, session)
	if err != nil || strings.TrimSpace(binding.WebhookSecret) == "" {
		return Session{}, ErrForbidden
	}
	want := callbackHMAC(binding.WebhookSecret, session.ID, session.ExpiresAt)
	if subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(token))) != 1 {
		return Session{}, ErrForbidden
	}
	return session, nil
}

// RunCallback executes a provider custom-LLM callback for an already-created
// session.  The callback token is the only authentication material accepted;
// owner and account generation are recovered from the fenced session and are
// never trusted from the HTTP request.  Callback turns share the durable turn
// and event store with client transcript turns, but intentionally do not honor
// ClientTranscriptEnabled (that flag controls only client-originated text).
func (s *Service) RunCallback(ctx context.Context, sessionID, token, transcript, requestID string, emit func(StreamEvent) error, expectedGeneration ...int64) error {
	if s == nil || s.store == nil || s.runner == nil || emit == nil {
		return ErrUnavailable
	}
	session, err := s.AuthorizeCallback(ctx, sessionID, token, expectedGeneration...)
	if err != nil {
		return err
	}
	if session.State != SessionStarted || !s.active(session) {
		return ErrExpired
	}
	transcript = strings.TrimSpace(transcript)
	if len(transcript) == 0 || len(transcript) > MaxTranscriptBytes {
		return ErrInvalid
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = shortDigest(transcript)
	}
	if len(requestID) > 512 {
		return ErrInvalid
	}
	digest := digestValue(struct {
		SessionID string `json:"session_id"`
		Text      string `json:"text"`
	}{session.ID, transcript})
	if raw, ok, replayErr := s.store.Replay(ctx, session.OwnerID, session.AccountGeneration, "callback", requestID, digest); replayErr != nil {
		return replayErr
	} else if ok {
		var replay struct {
			Answer string `json:"answer"`
		}
		if json.Unmarshal(raw, &replay) != nil {
			return ErrConflict
		}
		if replay.Answer != "" {
			if err := emit(StreamEvent{Event: "delta", Text: replay.Answer}); err != nil {
				return err
			}
		}
		return nil
	}
	if session.ActiveTurnID != "" {
		return ErrBusy
	}
	turn := Turn{ID: session.ID + "_callback_" + shortDigest(requestID), SessionID: session.ID, OwnerID: session.OwnerID, AccountGeneration: session.AccountGeneration, Transcript: transcript, State: TurnPending, Revision: 1, CreatedAt: s.clock(), UpdatedAt: s.clock()}
	if err := s.store.CreateTurn(ctx, turn); err != nil {
		if errors.Is(err, ErrConflict) {
			if existing, getErr := s.store.GetTurn(ctx, session.OwnerID, session.ID, turn.ID, session.AccountGeneration); getErr == nil && existing.State == TurnCompleted {
				if existing.Answer != "" {
					return emit(StreamEvent{Event: "delta", Text: existing.Answer})
				}
				return nil
			}
		}
		return err
	}
	session.ActiveTurnID, session.TurnSequence, session.Revision = turn.ID, session.TurnSequence+1, session.Revision+1
	session.UpdatedAt = s.clock()
	if err := s.store.SaveSession(ctx, session, session.Revision-1); err != nil {
		return err
	}
	turn.State, turn.Revision, turn.UpdatedAt = TurnRunning, turn.Revision+1, s.clock()
	if err := s.store.SaveTurn(ctx, turn, turn.Revision-1); err != nil {
		return err
	}
	var answer strings.Builder
	runErr := s.runner.Run(ctx, session.OwnerID, session, turn, func(event StreamEvent) error {
		if event.Event == "delta" && event.Text != "" {
			answer.WriteString(event.Text)
			if answer.Len() > MaxAnswerBytes {
				return ErrInvalid
			}
		}
		if err := emit(event); err != nil {
			return err
		}
		return event.Error
	})
	if runErr != nil {
		state, code := TurnFailed, "VOICE_PROVIDER_FAILED"
		if errors.Is(runErr, context.Canceled) {
			state, code = TurnUncertain, "UNCERTAIN"
		}
		_ = s.finishTurn(context.Background(), session, turn, state, code, runErr.Error())
		return runErr
	}
	turn.Answer = answer.String()
	if err := s.finishTurn(context.Background(), session, turn, TurnCompleted, "", ""); err != nil {
		return err
	}
	replay, _ := json.Marshal(struct {
		Answer string `json:"answer"`
	}{turn.Answer})
	return s.store.SaveReplay(ctx, session.OwnerID, session.AccountGeneration, "callback", requestID, digest, replay)
}

// ValidateProviderPayload binds provider identity markers to the same
// callback-authenticated session.  Volc has emitted both title-case and
// snake-case forms across API revisions, so the accepted aliases are kept
// deliberately narrow and every supplied marker must match.
func (s *Service) ValidateProviderPayload(ctx context.Context, sessionID, token string, payload map[string]any, expectedGeneration ...int64) error {
	session, err := s.AuthorizeCallback(ctx, sessionID, token, expectedGeneration...)
	if err != nil {
		return err
	}
	if payload == nil {
		return ErrInvalid
	}
	for _, field := range []struct {
		keys []string
		want string
	}{{[]string{"TaskId", "task_id"}, providerTaskID(session)}, {[]string{"RoomId", "room_id"}, session.RoomID}, {[]string{"UserId", "user_id"}, session.UserID}} {
		for _, key := range field.keys {
			if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" && strings.TrimSpace(value) != field.want {
				return ErrForbidden
			}
		}
	}
	marked := false
	if value, ok := payload["session_id"].(string); ok && strings.TrimSpace(value) != "" {
		if strings.TrimSpace(value) != session.ID {
			return ErrForbidden
		}
		marked = true
	}
	for _, key := range []string{"custom", "Custom"} {
		switch value := payload[key].(type) {
		case map[string]any:
			if marker, ok := value["session_id"].(string); ok && strings.TrimSpace(marker) != "" {
				if strings.TrimSpace(marker) != session.ID {
					return ErrForbidden
				}
				marked = true
			}
		case string:
			if strings.TrimSpace(value) == "" {
				continue
			}
			var nested map[string]any
			if json.Unmarshal([]byte(value), &nested) != nil {
				return ErrForbidden
			}
			marker, ok := nested["session_id"].(string)
			if !ok || strings.TrimSpace(marker) != session.ID {
				return ErrForbidden
			}
			marked = true
		}
	}
	if !marked {
		return ErrForbidden
	}
	return nil
}

func (s *Service) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func (s *Service) Create(ctx context.Context, owner string, generation int64, req CreateRequest, idempotencyKey string) (CreateResponse, error) {
	if err := validateIdentity(owner, generation); err != nil {
		return CreateResponse{}, err
	}
	if strings.TrimSpace(req.ConversationID) == "" || len(req.ConversationID) > MaxConversationID {
		return CreateResponse{}, ErrInvalid
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return CreateResponse{}, ErrInvalid
	}
	digest := digestValue(req)
	if raw, ok, err := s.store.Replay(ctx, owner, generation, "create", idempotencyKey, digest); err != nil {
		return CreateResponse{}, err
	} else if ok {
		var out CreateResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return CreateResponse{}, ErrConflict
		}
		return out, nil
	}
	if s.profiles == nil || s.provider == nil {
		return CreateResponse{}, ErrUnavailable
	}
	binding, err := s.profiles.Resolve(ctx, owner, req)
	if err != nil {
		return CreateResponse{}, err
	}
	if strings.TrimSpace(binding.ConversationProfileID) == "" || strings.TrimSpace(binding.SpeechProfileID) == "" {
		return CreateResponse{}, ErrInvalid
	}
	now := s.clock()
	session := Session{ID: "voice_" + uuid.NewString(), OwnerID: owner, AccountGeneration: generation, ConversationID: req.ConversationID, ConversationProfileID: binding.ConversationProfileID, SpeechProfileID: binding.SpeechProfileID, ExpiresAt: now.Add(SessionTTL), State: SessionCreated, Revision: 1, CreatedAt: now, UpdatedAt: now, ClientTranscriptEnabled: binding.ClientTranscriptEnabled}
	// The provider task id is deterministic and survives a process restart;
	// the provider adapter must use it for every Start/Interrupt/End retry.
	session.ProviderTaskID = session.ID
	providerSession, err := s.provider.Create(ctx, owner, session, binding)
	if err != nil {
		return CreateResponse{}, fmtProvider(err)
	}
	if providerSession.ExpiresAt.IsZero() || !providerSession.ExpiresAt.After(now) {
		providerSession.ExpiresAt = session.ExpiresAt
	}
	session.AppID = strings.TrimSpace(providerSession.AppID)
	session.VoiceChatAppID = strings.TrimSpace(providerSession.VoiceChatAppID)
	session.AIUserID = strings.TrimSpace(providerSession.AIUserID)
	session.RoomID = strings.TrimSpace(providerSession.RoomID)
	session.UserID = strings.TrimSpace(providerSession.UserID)
	session.ProviderHandle = strings.TrimSpace(providerSession.ProviderHandle)
	session.ExpiresAt = providerSession.ExpiresAt.UTC()
	if err := validateSession(session); err != nil {
		return CreateResponse{}, err
	}
	out := CreateResponse{OK: true, SessionID: session.ID, ConversationID: session.ConversationID, Token: providerSession.Token, AppID: session.AppID, VoiceChatAppID: session.VoiceChatAppID, RoomID: session.RoomID, UserID: session.UserID, AIUserID: session.AIUserID, ExpiresAt: session.ExpiresAt.Format(time.RFC3339), ConversationProfileID: session.ConversationProfileID, SpeechProfileID: session.SpeechProfileID, ClientTranscriptEnabled: session.ClientTranscriptEnabled}
	raw, _ := json.Marshal(out)
	if atomic, ok := s.store.(AtomicCreateStore); ok {
		if err := atomic.CreateSessionWithReplay(ctx, session, owner, generation, "create", idempotencyKey, digest, raw); err != nil {
			if errors.Is(err, ErrConflict) {
				if existing, ok, replayErr := s.store.Replay(ctx, owner, generation, "create", idempotencyKey, digest); replayErr == nil && ok {
					var replayed CreateResponse
					if json.Unmarshal(existing, &replayed) == nil {
						return replayed, nil
					}
				}
			}
			return CreateResponse{}, err
		}
		return out, nil
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		if errors.Is(err, ErrConflict) {
			if raw, ok, replayErr := s.store.Replay(ctx, owner, generation, "create", idempotencyKey, digest); replayErr == nil && ok {
				var out CreateResponse
				if json.Unmarshal(raw, &out) == nil {
					return out, nil
				}
			}
		}
		return CreateResponse{}, err
	}
	if err := s.store.SaveReplay(ctx, owner, generation, "create", idempotencyKey, digest, raw); err != nil {
		return CreateResponse{}, err
	}
	return out, nil
}

func (s *Service) Start(ctx context.Context, owner string, generation int64, sessionID, idempotencyKey string) (map[string]any, error) {
	return s.mutation(ctx, owner, generation, "start", sessionID, idempotencyKey, func(ctx context.Context, current Session) (map[string]any, error) {
		if current.State == SessionEnded || current.State == SessionStopping {
			return nil, ErrTerminal
		}
		if !s.active(current) {
			return nil, ErrExpired
		}
		if current.State == SessionStarted {
			if current.ProviderIntent != ProviderIntentNone || current.ProviderUncertain || current.ProviderLastError != "" {
				// The provider call and the started state were already committed;
				// only the final intent acknowledgement was interrupted.
				current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentNone, false, ""
				current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
				if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
					return nil, err
				}
			}
			return map[string]any{"ok": true, "session_id": current.ID, "started": true, "already_started": true}, nil
		}
		if s.provider == nil {
			return nil, ErrUnavailable
		}
		binding, err := s.binding(ctx, owner, current)
		if err != nil {
			return nil, err
		}
		current.ProviderTaskID = providerTaskID(current)
		current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentStart, true, ""
		current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
		if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
			return nil, err
		}
		if err := s.provider.Start(ctx, owner, current, binding); err != nil {
			current.ProviderLastError = providerErrorMessage(err)
			current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
			_ = s.store.SaveSession(context.Background(), current, current.Revision-1)
			return nil, fmtProvider(err)
		}
		now := s.clock()
		current.State, current.StartedAt, current.UpdatedAt, current.ProviderStopped, current.ProviderStopPending = SessionStarted, &now, now, false, false
		current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError, current.Revision = ProviderIntentNone, false, "", current.Revision+1
		if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
			// Leave the start intent durable. Recovery will retry/acknowledge
			// the deterministic provider task instead of guessing its state.
			return nil, err
		}
		_ = s.emit(ctx, current.ID, "session.started", map[string]any{"status": "started"})
		return map[string]any{"ok": true, "session_id": current.ID, "started": true}, nil
	})
}

func (s *Service) Transcript(ctx context.Context, owner string, generation int64, sessionID, transcript, idempotencyKey string) (map[string]any, error) {
	if err := validateIdentity(owner, generation); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sessionID) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return nil, ErrInvalid
	}
	if len(transcript) == 0 || len(transcript) > MaxTranscriptBytes {
		return nil, ErrInvalid
	}
	session, err := s.store.GetSession(ctx, owner, sessionID, generation)
	if err != nil {
		return nil, err
	}
	if !s.active(session) {
		return nil, ErrExpired
	}
	if session.State != SessionStarted {
		return nil, ErrConflict
	}
	if !session.ClientTranscriptEnabled {
		return map[string]any{"ok": true, "session_id": sessionID, "accepted": false, "reason": ErrTranscriptDisabled.Error()}, nil
	}
	digest := digestValue(struct{ SessionID, Transcript string }{sessionID, transcript})
	if raw, ok, e := s.store.Replay(ctx, owner, generation, "transcript", idempotencyKey, digest); e != nil {
		return nil, e
	} else if ok {
		var out map[string]any
		if json.Unmarshal(raw, &out) != nil {
			return nil, ErrConflict
		}
		return out, nil
	}
	if session.ActiveTurnID != "" {
		return nil, ErrBusy
	}
	turnID := session.ID + "_turn_" + shortDigest(idempotencyKey)
	turn := Turn{ID: turnID, SessionID: session.ID, OwnerID: owner, AccountGeneration: generation, Transcript: transcript, State: TurnPending, Revision: 1, CreatedAt: s.clock(), UpdatedAt: s.clock()}
	if err := s.store.CreateTurn(ctx, turn); err != nil {
		if errors.Is(err, ErrConflict) {
			if existing, getErr := s.store.GetTurn(ctx, owner, session.ID, turnID, generation); getErr == nil {
				return map[string]any{"ok": true, "session_id": session.ID, "accepted": existing.State == TurnPending || existing.State == TurnRunning, "turn_id": existing.ID}, nil
			}
		}
		return nil, err
	}
	session.ActiveTurnID, session.TurnSequence, session.Revision = turn.ID, session.TurnSequence+1, session.Revision+1
	session.UpdatedAt = s.clock()
	if err := s.store.SaveSession(ctx, session, session.Revision-1); err != nil {
		return nil, err
	}
	accepted := map[string]any{"ok": true, "session_id": session.ID, "accepted": true, "turn_id": turn.ID}
	raw, _ := json.Marshal(accepted)
	if err := s.store.SaveReplay(ctx, owner, generation, "transcript", idempotencyKey, digest, raw); err != nil {
		return nil, err
	}
	_ = s.emit(ctx, session.ID, "transcript.accepted", map[string]any{"status": "accepted", "turn_id": turn.ID})
	s.startTurn(turn, session)
	return accepted, nil
}

func (s *Service) Interrupt(ctx context.Context, owner string, generation int64, sessionID, idempotencyKey string) (map[string]any, error) {
	return s.mutation(ctx, owner, generation, "interrupt", sessionID, idempotencyKey, func(ctx context.Context, current Session) (map[string]any, error) {
		if current.State == SessionEnded {
			return nil, ErrTerminal
		}
		if s.provider != nil {
			current.ProviderTaskID = providerTaskID(current)
			current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentInterrupt, true, ""
			current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
			if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
				return nil, err
			}
		}
		if current.ActiveTurnID != "" && s.runner != nil {
			if err := s.runner.Cancel(ctx, owner, current.ActiveTurnID); err != nil {
				current.ProviderLastError = providerErrorMessage(err)
				current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
				_ = s.store.SaveSession(context.Background(), current, current.Revision-1)
				return nil, fmtProvider(err)
			}
			if turn, err := s.store.GetTurn(ctx, owner, current.ID, current.ActiveTurnID, generation); err == nil && !stateTerminal(turn.State) {
				turn.State, turn.ErrorCode, turn.ErrorMessage, turn.Revision, turn.UpdatedAt = TurnInterrupted, "INTERRUPTED", "voice session interrupted", turn.Revision+1, s.clock()
				_ = s.store.SaveTurn(ctx, turn, turn.Revision-1)
			}
			current.ActiveTurnID = ""
		}
		if s.provider != nil {
			binding, err := s.binding(ctx, owner, current)
			if err != nil {
				return nil, err
			}
			if err := s.provider.Interrupt(ctx, owner, current, binding); err != nil {
				current.ProviderLastError = providerErrorMessage(err)
				current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
				_ = s.store.SaveSession(context.Background(), current, current.Revision-1)
				return nil, fmtProvider(err)
			}
			current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentNone, false, ""
		}
		current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
		if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
			return nil, err
		}
		_ = s.emit(ctx, current.ID, "session.interrupted", map[string]any{"status": "listening", "interrupted": true})
		return map[string]any{"ok": true, "session_id": current.ID, "interrupted": true}, nil
	})
}

func (s *Service) End(ctx context.Context, owner string, generation int64, sessionID, idempotencyKey string) (map[string]any, error) {
	return s.mutation(ctx, owner, generation, "end", sessionID, idempotencyKey, func(ctx context.Context, current Session) (map[string]any, error) {
		if current.State == SessionEnded && !current.ProviderStopPending {
			return map[string]any{"ok": true, "session_id": current.ID, "ended": true, "already_ended": true}, nil
		}
		if s.provider == nil {
			return nil, ErrUnavailable
		}
		binding, err := s.binding(ctx, owner, current)
		if err != nil {
			return nil, err
		}
		current.ProviderTaskID = providerTaskID(current)
		current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError = ProviderIntentEnd, true, ""
		if current.State != SessionEnded {
			current.State = SessionStopping
		}
		current.ProviderStopPending, current.ProviderStopped = true, false
		current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
		if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
			return nil, err
		}
		if err := s.provider.End(ctx, owner, current, binding); err != nil {
			current.ProviderLastError = providerErrorMessage(err)
			current.UpdatedAt, current.Revision = s.clock(), current.Revision+1
			_ = s.store.SaveSession(context.Background(), current, current.Revision-1)
			return nil, fmtProvider(err)
		}
		now := s.clock()
		current.State, current.EndedAt, current.TombstoneExpiresAt = SessionEnded, &now, ptrTime(now.Add(TombstoneTTL))
		current.ActiveTurnID, current.ProviderStopped, current.ProviderStopPending, current.UpdatedAt = "", true, false, now
		current.ProviderIntent, current.ProviderUncertain, current.ProviderLastError, current.Revision = ProviderIntentNone, false, "", current.Revision+1
		if err := s.store.SaveSession(ctx, current, current.Revision-1); err != nil {
			return nil, err
		}
		_ = s.emit(ctx, current.ID, "session.done", map[string]any{"status": "done", "session_ended": true})
		return map[string]any{"ok": true, "session_id": current.ID, "ended": true}, nil
	})
}

func (s *Service) Stream(ctx context.Context, owner string, generation int64, sessionID string, afterSequence int64, emit func(Event) error) error {
	if err := validateIdentity(owner, generation); err != nil {
		return err
	}
	if strings.TrimSpace(sessionID) == "" || emit == nil || afterSequence < 0 {
		return ErrInvalid
	}
	if _, err := s.store.GetSession(ctx, owner, sessionID, generation); err != nil {
		return err
	}
	ticker := time.NewTicker(75 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := s.store.ListEvents(ctx, owner, sessionID, generation, afterSequence, 128)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := emit(event); err != nil {
				return err
			}
			afterSequence = event.Sequence
			if event.Event == "session.done" {
				return nil
			}
		}
		current, err := s.store.GetSession(ctx, owner, sessionID, generation)
		if err != nil {
			return err
		}
		if current.State == SessionEnded && len(events) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) mutation(ctx context.Context, owner string, generation int64, operation, sessionID, idempotencyKey string, fn func(context.Context, Session) (map[string]any, error)) (map[string]any, error) {
	if err := validateIdentity(owner, generation); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sessionID) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return nil, ErrInvalid
	}
	digest := digestValue(struct{ SessionID string }{sessionID})
	if raw, ok, err := s.store.Replay(ctx, owner, generation, operation, idempotencyKey, digest); err != nil {
		return nil, err
	} else if ok {
		var out map[string]any
		if json.Unmarshal(raw, &out) != nil {
			return nil, ErrConflict
		}
		return out, nil
	}
	current, err := s.store.GetSession(ctx, owner, sessionID, generation)
	if err != nil {
		return nil, err
	}
	out, err := fn(ctx, current)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(out)
	if err := s.store.SaveReplay(ctx, owner, generation, operation, idempotencyKey, digest, raw); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) startTurn(turn Turn, session Session) {
	if s.runner == nil {
		_ = s.finishTurn(context.Background(), session, turn, TurnFailed, "VOICE_PROVIDER_UNAVAILABLE", ErrUnavailable.Error())
		return
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		turn.State, turn.Revision, turn.UpdatedAt = TurnRunning, turn.Revision+1, s.clock()
		if err := s.store.SaveTurn(s.ctx, turn, turn.Revision-1); err != nil {
			return
		}
		err := s.runner.Run(s.ctx, session.OwnerID, session, turn, func(event StreamEvent) error {
			if event.Event == "delta" && event.Text != "" {
				turn.Answer += event.Text
				if len(turn.Answer) > MaxAnswerBytes {
					return ErrInvalid
				}
				if err := s.emit(s.ctx, session.ID, "answer", map[string]any{"status": "speaking", "answer_delta": event.Text, "turn_id": turn.ID}); err != nil {
					return err
				}
			}
			return event.Error
		})
		if err != nil {
			state, code := TurnFailed, "VOICE_PROVIDER_FAILED"
			if errors.Is(err, context.Canceled) {
				state, code = TurnUncertain, "UNCERTAIN"
			}
			_ = s.finishTurn(context.Background(), session, turn, state, code, err.Error())
			return
		}
		_ = s.finishTurn(context.Background(), session, turn, TurnCompleted, "", "")
	}()
}

func (s *Service) finishTurn(ctx context.Context, session Session, turn Turn, state TurnState, code, message string) error {
	turn.State, turn.ErrorCode, turn.ErrorMessage, turn.Revision, turn.UpdatedAt = state, code, message, turn.Revision+1, s.clock()
	if err := s.store.SaveTurn(ctx, turn, turn.Revision-1); err != nil {
		return err
	}
	current, err := s.store.GetSession(ctx, session.OwnerID, session.ID, session.AccountGeneration)
	if err == nil && current.ActiveTurnID == turn.ID {
		current.ActiveTurnID, current.UpdatedAt, current.Revision = "", s.clock(), current.Revision+1
		_ = s.store.SaveSession(ctx, current, current.Revision-1)
	}
	if state == TurnCompleted {
		return s.emit(ctx, session.ID, "turn.done", map[string]any{"status": "done", "turn_id": turn.ID, "answer": turn.Answer})
	}
	return s.emit(ctx, session.ID, "turn."+string(state), map[string]any{"status": string(state), "turn_id": turn.ID, "error": message})
}

func (s *Service) emit(ctx context.Context, sessionID, name string, data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if len(raw) > MaxEventBytes {
		return ErrInvalid
	}
	_, err = s.store.AppendEvent(ctx, Event{SessionID: sessionID, Event: name, Data: raw, CreatedAt: s.clock()})
	return err
}

func (s *Service) active(session Session) bool {
	return session.State != SessionEnded && session.State != SessionStopping && s.clock().Before(session.ExpiresAt)
}

func (s *Service) binding(ctx context.Context, owner string, session Session) (ProfileBinding, error) {
	if s.profiles == nil {
		return ProfileBinding{}, ErrUnavailable
	}
	return s.profiles.Resolve(ctx, owner, CreateRequest{ConversationID: session.ConversationID, ConversationProfileID: session.ConversationProfileID, SpeechProfileID: session.SpeechProfileID})
}

func digestValue(value any) string {
	raw, _ := json.Marshal(value)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func shortDigest(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:8])
}

func providerTaskID(session Session) string {
	if value := strings.TrimSpace(session.ProviderTaskID); value != "" {
		return value
	}
	// Rows created before the explicit task-id column was introduced retain
	// the original deterministic convention and remain safely retryable.
	return session.ID
}

func providerErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > MaxProviderError {
		return value[:MaxProviderError]
	}
	return value
}

func ptrTime(value time.Time) *time.Time { return &value }
