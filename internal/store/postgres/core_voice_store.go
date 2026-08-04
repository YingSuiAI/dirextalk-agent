package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CoreVoiceStore is the durable Agent-owned voice session/turn/event store.
// Credentials and RTC bearer tokens are intentionally absent from the session
// row; only the provider's opaque cleanup handle is retained.
type CoreVoiceStore struct{ store *Store }

func NewCoreVoiceStore(store *Store) *CoreVoiceStore {
	if store == nil {
		return nil
	}
	return &CoreVoiceStore{store: store}
}

func (s *CoreVoiceStore) CreateSession(ctx context.Context, value corevoice.Session) error {
	if s == nil || s.store == nil || validateSessionForStore(value) != nil {
		return corevoice.ErrInvalid
	}
	_, err := s.store.pool.Exec(ctx, `INSERT INTO core_voice_sessions(session_id,owner_id,account_generation,conversation_id,conversation_profile_id,speech_profile_id,app_id,voice_chat_app_id,ai_user_id,room_id,user_id,provider_handle,provider_task_id,provider_intent,provider_uncertain,provider_last_error,expires_at,state,started_at,ended_at,tombstone_expires_at,active_turn_id,turn_sequence,revision,provider_stopped,provider_stop_pending,client_transcript_enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NULLIF($21,''),$22,$23,$24,$25,$26,$27,$28,$29)`, value.ID, value.OwnerID, value.AccountGeneration, value.ConversationID, value.ConversationProfileID, value.SpeechProfileID, value.AppID, value.VoiceChatAppID, value.AIUserID, value.RoomID, value.UserID, value.ProviderHandle, value.ProviderTaskID, string(value.ProviderIntent), value.ProviderUncertain, value.ProviderLastError, value.ExpiresAt.UTC(), string(value.State), nullableVoiceTime(value.StartedAt), nullableVoiceTime(value.EndedAt), nullableVoiceTime(value.TombstoneExpiresAt), value.ActiveTurnID, value.TurnSequence, value.Revision, value.ProviderStopped, value.ProviderStopPending, value.ClientTranscriptEnabled, value.CreatedAt.UTC(), value.UpdatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return corevoice.ErrConflict
		}
		return err
	}
	return nil
}

func (s *CoreVoiceStore) CreateSessionWithReplay(ctx context.Context, value corevoice.Session, owner string, generation int64, operation, key, digest string, response []byte) error {
	if s == nil || s.store == nil || validateSessionForStore(value) != nil || strings.TrimSpace(owner) == "" || generation <= 0 || value.OwnerID != owner || value.AccountGeneration != generation || operation == "" || key == "" || digest == "" || len(response) == 0 || !json.Valid(response) {
		return corevoice.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO core_voice_sessions(session_id,owner_id,account_generation,conversation_id,conversation_profile_id,speech_profile_id,app_id,voice_chat_app_id,ai_user_id,room_id,user_id,provider_handle,provider_task_id,provider_intent,provider_uncertain,provider_last_error,expires_at,state,started_at,ended_at,tombstone_expires_at,active_turn_id,turn_sequence,revision,provider_stopped,provider_stop_pending,client_transcript_enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NULLIF($21,''),$22,$23,$24,$25,$26,$27,$28,$29)`, value.ID, value.OwnerID, value.AccountGeneration, value.ConversationID, value.ConversationProfileID, value.SpeechProfileID, value.AppID, value.VoiceChatAppID, value.AIUserID, value.RoomID, value.UserID, value.ProviderHandle, value.ProviderTaskID, string(value.ProviderIntent), value.ProviderUncertain, value.ProviderLastError, value.ExpiresAt.UTC(), string(value.State), nullableVoiceTime(value.StartedAt), nullableVoiceTime(value.EndedAt), nullableVoiceTime(value.TombstoneExpiresAt), value.ActiveTurnID, value.TurnSequence, value.Revision, value.ProviderStopped, value.ProviderStopPending, value.ClientTranscriptEnabled, value.CreatedAt.UTC(), value.UpdatedAt.UTC()); err != nil {
		if isUniqueViolation(err) {
			return corevoice.ErrConflict
		}
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_voice_replays(owner_id,account_generation,operation,idempotency_key,request_hash,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, owner, generation, operation, key, digest, response, time.Now().UTC()); err != nil {
		if isUniqueViolation(err) {
			return corevoice.ErrConflict
		}
		return err
	}
	return tx.Commit(ctx)
}

func (s *CoreVoiceStore) GetSession(ctx context.Context, owner, id string, generation int64) (corevoice.Session, error) {
	if s == nil || s.store == nil || owner == "" || id == "" || generation <= 0 {
		return corevoice.Session{}, corevoice.ErrForbidden
	}
	var out corevoice.Session
	var state string
	var started, ended, tombstone *time.Time
	var providerIntent string
	err := s.store.pool.QueryRow(ctx, `SELECT session_id,owner_id,account_generation,conversation_id,conversation_profile_id,speech_profile_id,app_id,voice_chat_app_id,ai_user_id,room_id,user_id,provider_handle,provider_task_id,provider_intent,provider_uncertain,provider_last_error,expires_at,state,started_at,ended_at,tombstone_expires_at,active_turn_id,turn_sequence,revision,provider_stopped,provider_stop_pending,client_transcript_enabled,created_at,updated_at FROM core_voice_sessions WHERE session_id=$1 AND owner_id=$2 AND account_generation=$3 AND (tombstone_expires_at IS NULL OR tombstone_expires_at>$4)`, id, owner, generation, time.Now().UTC()).Scan(&out.ID, &out.OwnerID, &out.AccountGeneration, &out.ConversationID, &out.ConversationProfileID, &out.SpeechProfileID, &out.AppID, &out.VoiceChatAppID, &out.AIUserID, &out.RoomID, &out.UserID, &out.ProviderHandle, &out.ProviderTaskID, &providerIntent, &out.ProviderUncertain, &out.ProviderLastError, &out.ExpiresAt, &state, &started, &ended, &tombstone, &out.ActiveTurnID, &out.TurnSequence, &out.Revision, &out.ProviderStopped, &out.ProviderStopPending, &out.ClientTranscriptEnabled, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// Deliberately do not reveal whether the id belongs to another owner.
		return corevoice.Session{}, corevoice.ErrNotFound
	}
	if err != nil {
		return corevoice.Session{}, err
	}
	out.State, out.ProviderIntent, out.StartedAt, out.EndedAt, out.TombstoneExpiresAt = corevoice.SessionState(state), corevoice.ProviderIntent(providerIntent), started, ended, tombstone
	return out, nil
}

func (s *CoreVoiceStore) FindSession(ctx context.Context, id string) (corevoice.Session, error) {
	if s == nil || s.store == nil || id == "" {
		return corevoice.Session{}, corevoice.ErrInvalid
	}
	var out corevoice.Session
	var state string
	var started, ended, tombstone *time.Time
	var providerIntent string
	err := s.store.pool.QueryRow(ctx, `SELECT session_id,owner_id,account_generation,conversation_id,conversation_profile_id,speech_profile_id,app_id,voice_chat_app_id,ai_user_id,room_id,user_id,provider_handle,provider_task_id,provider_intent,provider_uncertain,provider_last_error,expires_at,state,started_at,ended_at,tombstone_expires_at,active_turn_id,turn_sequence,revision,provider_stopped,provider_stop_pending,client_transcript_enabled,created_at,updated_at FROM core_voice_sessions WHERE session_id=$1`, id).Scan(&out.ID, &out.OwnerID, &out.AccountGeneration, &out.ConversationID, &out.ConversationProfileID, &out.SpeechProfileID, &out.AppID, &out.VoiceChatAppID, &out.AIUserID, &out.RoomID, &out.UserID, &out.ProviderHandle, &out.ProviderTaskID, &providerIntent, &out.ProviderUncertain, &out.ProviderLastError, &out.ExpiresAt, &state, &started, &ended, &tombstone, &out.ActiveTurnID, &out.TurnSequence, &out.Revision, &out.ProviderStopped, &out.ProviderStopPending, &out.ClientTranscriptEnabled, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return corevoice.Session{}, corevoice.ErrNotFound
	}
	if err != nil {
		return corevoice.Session{}, err
	}
	out.State, out.ProviderIntent, out.StartedAt, out.EndedAt, out.TombstoneExpiresAt = corevoice.SessionState(state), corevoice.ProviderIntent(providerIntent), started, ended, tombstone
	return out, nil
}

func (s *CoreVoiceStore) SaveSession(ctx context.Context, value corevoice.Session, expectedRevision int64) error {
	if s == nil || s.store == nil || validateSessionForStore(value) != nil || expectedRevision <= 0 {
		return corevoice.ErrInvalid
	}
	result, err := s.store.pool.Exec(ctx, `UPDATE core_voice_sessions SET conversation_profile_id=$4,speech_profile_id=$5,app_id=$6,voice_chat_app_id=$7,ai_user_id=$8,room_id=$9,user_id=$10,provider_handle=$11,provider_task_id=$12,provider_intent=$13,provider_uncertain=$14,provider_last_error=$15,expires_at=$16,state=$17,started_at=$18,ended_at=$19,tombstone_expires_at=$20,active_turn_id=NULLIF($21,''),turn_sequence=$22,revision=$23,provider_stopped=$24,provider_stop_pending=$25,client_transcript_enabled=$26,updated_at=$27 WHERE session_id=$1 AND owner_id=$2 AND account_generation=$3 AND revision=$28 AND (state<>'ended' OR $17='ended')`, value.ID, value.OwnerID, value.AccountGeneration, value.ConversationProfileID, value.SpeechProfileID, value.AppID, value.VoiceChatAppID, value.AIUserID, value.RoomID, value.UserID, value.ProviderHandle, value.ProviderTaskID, string(value.ProviderIntent), value.ProviderUncertain, value.ProviderLastError, value.ExpiresAt.UTC(), string(value.State), nullableVoiceTime(value.StartedAt), nullableVoiceTime(value.EndedAt), nullableVoiceTime(value.TombstoneExpiresAt), value.ActiveTurnID, value.TurnSequence, value.Revision, value.ProviderStopped, value.ProviderStopPending, value.ClientTranscriptEnabled, value.UpdatedAt.UTC(), expectedRevision)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return corevoice.ErrConflict
	}
	return nil
}

func (s *CoreVoiceStore) CreateTurn(ctx context.Context, value corevoice.Turn) error {
	if s == nil || s.store == nil || validateTurnForStore(value) != nil {
		return corevoice.ErrInvalid
	}
	_, err := s.store.pool.Exec(ctx, `INSERT INTO core_voice_turns(turn_id,session_id,owner_id,account_generation,transcript,answer,state,error_code,error_message,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`, value.ID, value.SessionID, value.OwnerID, value.AccountGeneration, value.Transcript, value.Answer, string(value.State), value.ErrorCode, value.ErrorMessage, value.Revision, value.CreatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return corevoice.ErrConflict
		}
		return err
	}
	return nil
}

func (s *CoreVoiceStore) GetTurn(ctx context.Context, owner, sessionID, turnID string, generation int64) (corevoice.Turn, error) {
	if s == nil || s.store == nil || owner == "" || sessionID == "" || turnID == "" || generation <= 0 {
		return corevoice.Turn{}, corevoice.ErrForbidden
	}
	var out corevoice.Turn
	var state string
	err := s.store.pool.QueryRow(ctx, `SELECT turn_id,session_id,owner_id,account_generation,transcript,answer,state,error_code,error_message,revision,created_at,updated_at FROM core_voice_turns WHERE turn_id=$1 AND session_id=$2 AND owner_id=$3 AND account_generation=$4`, turnID, sessionID, owner, generation).Scan(&out.ID, &out.SessionID, &out.OwnerID, &out.AccountGeneration, &out.Transcript, &out.Answer, &state, &out.ErrorCode, &out.ErrorMessage, &out.Revision, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return corevoice.Turn{}, corevoice.ErrNotFound
	}
	if err != nil {
		return corevoice.Turn{}, err
	}
	out.State = corevoice.TurnState(state)
	return out, nil
}

func (s *CoreVoiceStore) SaveTurn(ctx context.Context, value corevoice.Turn, expectedRevision int64) error {
	if s == nil || s.store == nil || validateTurnForStore(value) != nil || expectedRevision <= 0 {
		return corevoice.ErrInvalid
	}
	result, err := s.store.pool.Exec(ctx, `UPDATE core_voice_turns SET transcript=$4,answer=$5,state=$6,error_code=$7,error_message=$8,revision=$9,updated_at=$10 WHERE turn_id=$1 AND owner_id=$2 AND account_generation=$3 AND revision=$11 AND (state NOT IN ('completed','interrupted','failed','uncertain') OR $6=state)`, value.ID, value.OwnerID, value.AccountGeneration, value.Transcript, value.Answer, string(value.State), value.ErrorCode, value.ErrorMessage, value.Revision, value.UpdatedAt.UTC(), expectedRevision)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return corevoice.ErrConflict
	}
	return nil
}

func (s *CoreVoiceStore) AppendEvent(ctx context.Context, event corevoice.Event) (corevoice.Event, error) {
	if s == nil || s.store == nil || len(event.Data) == 0 || event.SessionID == "" || event.Event == "" {
		return corevoice.Event{}, corevoice.ErrInvalid
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	err := s.store.pool.QueryRow(ctx, `INSERT INTO core_voice_events(session_id,event,event_json,created_at) VALUES($1,$2,$3,$4) RETURNING sequence`, event.SessionID, event.Event, event.Data, event.CreatedAt.UTC()).Scan(&event.Sequence)
	if err != nil {
		return corevoice.Event{}, err
	}
	return event, nil
}

func (s *CoreVoiceStore) ListEvents(ctx context.Context, owner, sessionID string, generation, after int64, limit int) ([]corevoice.Event, error) {
	if s == nil || s.store == nil || owner == "" || sessionID == "" || generation <= 0 || after < 0 || limit <= 0 || limit > 256 {
		return nil, corevoice.ErrInvalid
	}
	if _, err := s.GetSession(ctx, owner, sessionID, generation); err != nil {
		return nil, err
	}
	rows, err := s.store.pool.Query(ctx, `SELECT sequence,session_id,event,event_json,created_at FROM core_voice_events WHERE session_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3`, sessionID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]corevoice.Event, 0, limit)
	for rows.Next() {
		var value corevoice.Event
		if err := rows.Scan(&value.Sequence, &value.SessionID, &value.Event, &value.Data, &value.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *CoreVoiceStore) Replay(ctx context.Context, owner string, generation int64, operation, key, digest string) ([]byte, bool, error) {
	if s == nil || s.store == nil || owner == "" || generation <= 0 || operation == "" || key == "" || digest == "" {
		return nil, false, corevoice.ErrInvalid
	}
	var storedDigest string
	var value []byte
	err := s.store.pool.QueryRow(ctx, `SELECT request_hash,response_json FROM core_voice_replays WHERE owner_id=$1 AND account_generation=$2 AND operation=$3 AND idempotency_key=$4`, owner, generation, operation, key).Scan(&storedDigest, &value)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if storedDigest != digest {
		return nil, false, corevoice.ErrConflict
	}
	return append([]byte(nil), value...), true, nil
}

func (s *CoreVoiceStore) SaveReplay(ctx context.Context, owner string, generation int64, operation, key, digest string, value []byte) error {
	if s == nil || s.store == nil || owner == "" || generation <= 0 || operation == "" || key == "" || digest == "" || len(value) == 0 || !json.Valid(value) {
		return corevoice.ErrInvalid
	}
	_, err := s.store.pool.Exec(ctx, `INSERT INTO core_voice_replays(owner_id,account_generation,operation,idempotency_key,request_hash,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(owner_id,account_generation,operation,idempotency_key) DO NOTHING`, owner, generation, operation, key, digest, value, time.Now().UTC())
	return err
}

func (s *CoreVoiceStore) Recover(ctx context.Context, now time.Time) error {
	if s == nil || s.store == nil {
		return corevoice.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE core_voice_turns SET state='uncertain',error_code='UNCERTAIN',error_message='turn interrupted by Agent restart',revision=revision+1,updated_at=$1 WHERE state IN ('pending','running')`, now.UTC()); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT session_id FROM core_voice_sessions WHERE state<>'ended' AND expires_at<=$1`, now.UTC())
	if err != nil {
		return err
	}
	var expired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, id)
	}
	rows.Close()
	for _, id := range expired {
		if _, err := tx.Exec(ctx, `UPDATE core_voice_sessions SET state='ended',provider_stop_pending=true,active_turn_id='',ended_at=$2,tombstone_expires_at=$3,revision=revision+1,updated_at=$2 WHERE session_id=$1 AND state<>'ended'`, id, now.UTC(), now.UTC().Add(corevoice.TombstoneTTL)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO core_voice_events(session_id,event,event_json,created_at) VALUES($1,'session.done','{"status":"done","session_ended":true}'::jsonb,$2)`, id, now.UTC()); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core_voice_sessions WHERE state='ended' AND tombstone_expires_at IS NOT NULL AND tombstone_expires_at<=$1`, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *CoreVoiceStore) ListPendingStops(ctx context.Context) ([]corevoice.Session, error) {
	if s == nil || s.store == nil {
		return nil, corevoice.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT session_id,owner_id,account_generation,conversation_id,conversation_profile_id,speech_profile_id,app_id,voice_chat_app_id,ai_user_id,room_id,user_id,provider_handle,provider_task_id,provider_intent,provider_uncertain,provider_last_error,expires_at,state,started_at,ended_at,tombstone_expires_at,active_turn_id,turn_sequence,revision,provider_stopped,provider_stop_pending,client_transcript_enabled,created_at,updated_at FROM core_voice_sessions WHERE provider_stop_pending=true ORDER BY updated_at,session_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]corevoice.Session, 0)
	for rows.Next() {
		var value corevoice.Session
		var state, providerIntent string
		var started, ended, tombstone *time.Time
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.AccountGeneration, &value.ConversationID, &value.ConversationProfileID, &value.SpeechProfileID, &value.AppID, &value.VoiceChatAppID, &value.AIUserID, &value.RoomID, &value.UserID, &value.ProviderHandle, &value.ProviderTaskID, &providerIntent, &value.ProviderUncertain, &value.ProviderLastError, &value.ExpiresAt, &state, &started, &ended, &tombstone, &value.ActiveTurnID, &value.TurnSequence, &value.Revision, &value.ProviderStopped, &value.ProviderStopPending, &value.ClientTranscriptEnabled, &value.CreatedAt, &value.UpdatedAt); err != nil {
			return nil, err
		}
		value.State, value.ProviderIntent, value.StartedAt, value.EndedAt, value.TombstoneExpiresAt = corevoice.SessionState(state), corevoice.ProviderIntent(providerIntent), started, ended, tombstone
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *CoreVoiceStore) ListProviderIntents(ctx context.Context) ([]corevoice.Session, error) {
	if s == nil || s.store == nil {
		return nil, corevoice.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT session_id,owner_id,account_generation,conversation_id,conversation_profile_id,speech_profile_id,app_id,voice_chat_app_id,ai_user_id,room_id,user_id,provider_handle,provider_task_id,provider_intent,provider_uncertain,provider_last_error,expires_at,state,started_at,ended_at,tombstone_expires_at,active_turn_id,turn_sequence,revision,provider_stopped,provider_stop_pending,client_transcript_enabled,created_at,updated_at FROM core_voice_sessions WHERE provider_uncertain=true OR provider_intent<>'' ORDER BY updated_at,session_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]corevoice.Session, 0)
	for rows.Next() {
		var value corevoice.Session
		var state, providerIntent string
		var started, ended, tombstone *time.Time
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.AccountGeneration, &value.ConversationID, &value.ConversationProfileID, &value.SpeechProfileID, &value.AppID, &value.VoiceChatAppID, &value.AIUserID, &value.RoomID, &value.UserID, &value.ProviderHandle, &value.ProviderTaskID, &providerIntent, &value.ProviderUncertain, &value.ProviderLastError, &value.ExpiresAt, &state, &started, &ended, &tombstone, &value.ActiveTurnID, &value.TurnSequence, &value.Revision, &value.ProviderStopped, &value.ProviderStopPending, &value.ClientTranscriptEnabled, &value.CreatedAt, &value.UpdatedAt); err != nil {
			return nil, err
		}
		value.State, value.ProviderIntent, value.StartedAt, value.EndedAt, value.TombstoneExpiresAt = corevoice.SessionState(state), corevoice.ProviderIntent(providerIntent), started, ended, tombstone
		result = append(result, value)
	}
	return result, rows.Err()
}

func nullableVoiceTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func validateSessionForStore(value corevoice.Session) error {
	if strings.TrimSpace(value.ID) == "" || strings.TrimSpace(value.OwnerID) == "" || value.AccountGeneration <= 0 || strings.TrimSpace(value.ConversationID) == "" || strings.TrimSpace(value.ConversationProfileID) == "" || strings.TrimSpace(value.SpeechProfileID) == "" || value.ExpiresAt.IsZero() || value.Revision <= 0 || value.State == "" || len(value.ProviderTaskID) > corevoice.MaxProviderTaskID || len(value.ProviderLastError) > corevoice.MaxProviderError {
		return corevoice.ErrInvalid
	}
	switch value.ProviderIntent {
	case corevoice.ProviderIntentNone, corevoice.ProviderIntentCreate, corevoice.ProviderIntentStart, corevoice.ProviderIntentInterrupt, corevoice.ProviderIntentEnd:
	default:
		return corevoice.ErrInvalid
	}
	return nil
}

func validateTurnForStore(value corevoice.Turn) error {
	if strings.TrimSpace(value.ID) == "" || strings.TrimSpace(value.SessionID) == "" || strings.TrimSpace(value.OwnerID) == "" || value.AccountGeneration <= 0 || value.Transcript == "" || len(value.Transcript) > corevoice.MaxTranscriptBytes || value.Revision <= 0 || value.State == "" {
		return corevoice.ErrInvalid
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

var _ corevoice.Store = (*CoreVoiceStore)(nil)
var _ corevoice.AtomicCreateStore = (*CoreVoiceStore)(nil)
