package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreMemoryStore struct{ *Store }

const memoryConfigLockKey = "dirextalk-agent/core-memory-config/v1"

func NewCoreMemoryStore(store *Store) (*CoreMemoryStore, error) {
	if store == nil || store.pool == nil {
		return nil, errors.New("postgres store is required")
	}
	return &CoreMemoryStore{Store: store}, nil
}

func lockMemoryConfig(ctx context.Context, tx pgx.Tx, shared bool) error {
	function := "pg_advisory_xact_lock"
	if shared {
		function += "_shared"
	}
	_, err := tx.Exec(ctx, `SELECT `+function+`(hashtextextended($1,0))`, memoryConfigLockKey)
	return err
}

func memoryConfigTx(ctx context.Context, tx pgx.Tx) (corememory.Config, error) {
	var value corememory.Config
	var updatedAt time.Time
	err := tx.QueryRow(ctx, `SELECT enabled,revision,updated_at FROM core_memory_configs WHERE singleton=true`).Scan(&value.Enabled, &value.Revision, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		value = corememory.DefaultConfig()
	} else if err != nil {
		return corememory.Config{}, corememory.ErrRepository
	} else {
		updatedAt = updatedAt.UTC()
		value.UpdatedAt = &updatedAt
	}
	var profileID, model string
	err = tx.QueryRow(ctx, `SELECT p.profile_id::text,p.model_name FROM core_knowledge_embedding_config k JOIN core_model_profiles p ON p.profile_id=k.embedding_profile_id WHERE k.singleton=true AND k.embedding_profile_id<>$1::uuid AND p.deleted_at IS NULL AND p.model_kind='embedding' AND p.api_key_configured=true`, uuid.Nil.String()).Scan(&profileID, &model)
	if err == nil {
		value.EmbeddingConfigured = true
		value.EmbeddingProfileID = profileID
		value.EmbeddingModel = model
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return corememory.Config{}, corememory.ErrRepository
	}
	return value, nil
}

func (s *CoreMemoryStore) GetConfig(ctx context.Context) (corememory.Config, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockMemoryConfig(ctx, tx, true); err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	value, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return corememory.Config{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	return value, nil
}

func (s *CoreMemoryStore) UpdateConfig(ctx context.Context, mutation corememory.ConfigMutation) (corememory.Config, error) {
	if uuid.Validate(mutation.IdempotencyKey) != nil || len(mutation.RequestDigest) != 64 || mutation.ExpectedRevision < 0 || mutation.Now.IsZero() {
		return corememory.Config{}, corememory.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockMemoryConfig(ctx, tx, false); err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	var storedDigest string
	var storedResponse []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_memory_config_replays WHERE idempotency_key=$1`, mutation.IdempotencyKey).Scan(&storedDigest, &storedResponse)
	if err == nil {
		if storedDigest != mutation.RequestDigest {
			return corememory.Config{}, corememory.ErrIdempotencyConflict
		}
		var replay corememory.Config
		if json.Unmarshal(storedResponse, &replay) != nil {
			return corememory.Config{}, corememory.ErrRepository
		}
		if err = tx.Commit(ctx); err != nil {
			return corememory.Config{}, corememory.ErrRepository
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return corememory.Config{}, corememory.ErrRepository
	}
	current, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return corememory.Config{}, err
	}
	if current.Revision != mutation.ExpectedRevision {
		return corememory.Config{}, corememory.ErrRevisionConflict
	}
	if mutation.Enabled && !current.EmbeddingConfigured {
		return corememory.Config{}, corememory.ErrEmbeddingNotConfigured
	}
	now := mutation.Now.UTC().Truncate(time.Microsecond)
	next := current
	next.Enabled, next.Revision, next.UpdatedAt = mutation.Enabled, current.Revision+1, &now
	result, err := tx.Exec(ctx, `INSERT INTO core_memory_configs(singleton,enabled,revision,created_at,updated_at) VALUES(true,$1,$2,$3,$3) ON CONFLICT(singleton) DO UPDATE SET enabled=EXCLUDED.enabled,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at WHERE core_memory_configs.revision=$4`, next.Enabled, next.Revision, now, current.Revision)
	if err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	if result.RowsAffected() != 1 {
		return corememory.Config{}, corememory.ErrRevisionConflict
	}
	response, _ := json.Marshal(next)
	if _, err = tx.Exec(ctx, `INSERT INTO core_memory_config_replays(idempotency_key,request_digest,response_json,created_at) VALUES($1,$2,$3,$4)`, mutation.IdempotencyKey, mutation.RequestDigest, response, now); err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	if err = tx.Commit(ctx); err != nil {
		return corememory.Config{}, corememory.ErrRepository
	}
	return next, nil
}

func (s *CoreConversationStore) enqueueMemoryObservationTx(ctx context.Context, tx pgx.Tx, observationID, conversationID, profileID, userText, assistantText string, observedAt time.Time) error {
	if s == nil || !s.memoryCapture.Load() {
		return nil
	}
	userText = strings.TrimSpace(userText)
	assistantText = strings.TrimSpace(assistantText)
	if uuid.Validate(observationID) != nil || uuid.Validate(conversationID) != nil || uuid.Validate(profileID) != nil || userText == "" || len(userText) > 1<<20 || len(assistantText) > 1<<20 {
		return corememory.ErrInvalid
	}
	if err := lockMemoryConfig(ctx, tx, true); err != nil {
		return corememory.ErrRepository
	}
	config, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return err
	}
	if !config.Enabled {
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_memory_observations(observation_id,conversation_id,profile_id,user_text,assistant_text,observed_at,next_attempt_at)
		VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(observation_id) DO NOTHING`, observationID, conversationID, profileID, userText, assistantText, observedAt)
	return err
}

func (s *CoreMemoryStore) ClaimObservation(ctx context.Context, now time.Time, ttl time.Duration) (corememory.ObservationLease, bool, error) {
	if ctx == nil || ttl <= 0 {
		return corememory.ObservationLease{}, false, corememory.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return corememory.ObservationLease{}, false, corememory.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockMemoryConfig(ctx, tx, true); err != nil {
		return corememory.ObservationLease{}, false, corememory.ErrRepository
	}
	config, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return corememory.ObservationLease{}, false, err
	}
	if !config.Enabled {
		return corememory.ObservationLease{}, false, tx.Commit(ctx)
	}
	leaseID := uuid.NewString()
	if _, err := tx.Exec(ctx, `UPDATE core_memory_observations SET state='dead',lease_id=NULL,lease_expires_at=NULL,last_error='memory_consolidation_abandoned',updated_at=$1 WHERE state='processing' AND attempt>=5 AND lease_expires_at<=$1`, now); err != nil {
		return corememory.ObservationLease{}, false, err
	}
	row := tx.QueryRow(ctx, `WITH candidate AS (
		SELECT observation_id FROM core_memory_observations
		WHERE attempt<5 AND ((state='pending' AND next_attempt_at<=$1) OR (state='processing' AND lease_expires_at<=$1))
		ORDER BY observed_at,observation_id FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE core_memory_observations o SET state='processing',attempt=attempt+1,lease_id=$2,lease_expires_at=$3,updated_at=$1
	FROM candidate c WHERE o.observation_id=c.observation_id
	RETURNING o.observation_id::text,o.conversation_id::text,o.profile_id::text,o.user_text,o.assistant_text,o.observed_at,o.attempt`, now, leaseID, now.Add(ttl))
	var lease corememory.ObservationLease
	if err := row.Scan(&lease.ID, &lease.ConversationID, &lease.ProfileID, &lease.UserText, &lease.AssistantText, &lease.ObservedAt, &lease.Attempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return corememory.ObservationLease{}, false, tx.Commit(ctx)
		}
		return corememory.ObservationLease{}, false, err
	}
	lease.LeaseID = leaseID
	if err = tx.Commit(ctx); err != nil {
		return corememory.ObservationLease{}, false, corememory.ErrRepository
	}
	return lease, true, nil
}

func (s *CoreMemoryStore) ListActiveFacts(ctx context.Context, limit int) ([]corememory.Fact, error) {
	if ctx == nil || limit <= 0 || limit > corememory.MaxActiveFacts {
		return nil, corememory.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT fact_id::text,subject,predicate,value,kind,confidence,valid_from,last_confirmed_at
		FROM core_memory_facts WHERE state='active' ORDER BY last_confirmed_at DESC,fact_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := make([]corememory.Fact, 0, limit)
	for rows.Next() {
		var fact corememory.Fact
		if err = rows.Scan(&fact.ID, &fact.Subject, &fact.Predicate, &fact.Value, &fact.Kind, &fact.Confidence, &fact.ValidFrom, &fact.LastConfirmedAt); err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	return facts, rows.Err()
}

func (s *CoreMemoryStore) ApplyObservation(ctx context.Context, lease corememory.ObservationLease, candidates []corememory.Candidate, now time.Time) error {
	if ctx == nil || uuid.Validate(lease.ID) != nil || uuid.Validate(lease.LeaseID) != nil || len(candidates) > corememory.MaxCandidates {
		return corememory.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockMemoryConfig(ctx, tx, true); err != nil {
		return corememory.ErrRepository
	}
	config, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return err
	}
	if !config.Enabled {
		_, err = tx.Exec(ctx, `UPDATE core_memory_observations SET state='pending',lease_id=NULL,lease_expires_at=NULL,updated_at=$3 WHERE observation_id=$1 AND lease_id=$2 AND state='processing'`, lease.ID, lease.LeaseID, now)
		if err != nil {
			return corememory.ErrRepository
		}
		return tx.Commit(ctx)
	}
	var state string
	if err = tx.QueryRow(ctx, `SELECT state FROM core_memory_observations WHERE observation_id=$1 AND lease_id=$2 AND state='processing' AND lease_expires_at>$3 FOR UPDATE`, lease.ID, lease.LeaseID, now).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return corememory.ErrInvalid
		}
		return err
	}
	for _, candidate := range candidates {
		if err = applyMemoryCandidate(ctx, tx, lease.ID, candidate, now); err != nil {
			return err
		}
	}
	result, err := tx.Exec(ctx, `UPDATE core_memory_observations SET state='completed',lease_id=NULL,lease_expires_at=NULL,last_error='',updated_at=$3 WHERE observation_id=$1 AND lease_id=$2 AND state='processing'`, lease.ID, lease.LeaseID, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return corememory.ErrInvalid
	}
	return tx.Commit(ctx)
}

func applyMemoryCandidate(ctx context.Context, tx pgx.Tx, observationID string, candidate corememory.Candidate, now time.Time) error {
	if err := candidate.Normalize(); err != nil {
		return err
	}
	effectiveAt := candidate.EffectiveTime(now)
	if effectiveAt.After(now.Add(5 * time.Minute)) {
		return corememory.ErrInvalid
	}
	var current corememory.Fact
	err := tx.QueryRow(ctx, `SELECT fact_id::text,subject,predicate,value,kind,confidence,valid_from,last_confirmed_at FROM core_memory_facts WHERE subject=$1 AND predicate=$2 AND state='active' FOR UPDATE`, candidate.Subject, candidate.Predicate).
		Scan(&current.ID, &current.Subject, &current.Predicate, &current.Value, &current.Kind, &current.Confidence, &current.ValidFrom, &current.LastConfirmedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if candidate.Operation == "retract" {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		validTo := effectiveAt
		if validTo.Before(current.ValidFrom) {
			validTo = current.ValidFrom
		}
		if _, err = tx.Exec(ctx, `UPDATE core_memory_facts SET state='retracted',valid_to=$2,last_confirmed_at=$3 WHERE fact_id=$1 AND state='active'`, current.ID, validTo, now); err != nil {
			return err
		}
		return insertMemoryTimeline(ctx, tx, observationID, "retracted", current.ID, "", memorySummary(current.Subject, current.Predicate, current.Value), effectiveAt, now)
	}
	if err == nil && current.Value == candidate.Value {
		if _, err = tx.Exec(ctx, `UPDATE core_memory_facts SET confidence=GREATEST(confidence,$2),last_confirmed_at=$3 WHERE fact_id=$1 AND state='active'`, current.ID, candidate.Confidence, now); err != nil {
			return err
		}
		return insertMemoryTimeline(ctx, tx, observationID, "confirmed", current.ID, "", memorySummary(candidate.Subject, candidate.Predicate, candidate.Value), effectiveAt, now)
	}
	newID := uuid.NewString()
	previousID := ""
	eventKind := "added"
	if err == nil {
		previousID, eventKind = current.ID, "replaced"
		validTo := effectiveAt
		if validTo.Before(current.ValidFrom) {
			validTo = current.ValidFrom
		}
		if _, err = tx.Exec(ctx, `UPDATE core_memory_facts SET state='superseded',valid_to=$2 WHERE fact_id=$1 AND state='active'`, current.ID, validTo); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_memory_facts(fact_id,subject,predicate,value,kind,confidence,state,valid_from,last_confirmed_at,source_observation_id,supersedes_fact_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10,$8)`, newID, candidate.Subject, candidate.Predicate, candidate.Value, candidate.Kind, candidate.Confidence, effectiveAt, now, observationID, nullableUUIDPG(previousID)); err != nil {
		return err
	}
	return insertMemoryTimeline(ctx, tx, observationID, eventKind, newID, previousID, memorySummary(candidate.Subject, candidate.Predicate, candidate.Value), effectiveAt, now)
}

func insertMemoryTimeline(ctx context.Context, tx pgx.Tx, observationID, kind, factID, previousID, summary string, effectiveAt, observedAt time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO core_memory_timeline(event_id,observation_id,event_kind,fact_id,previous_fact_id,summary,effective_at,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.NewString(), observationID, kind, factID, nullableUUIDPG(previousID), summary, effectiveAt, observedAt)
	return err
}

func memorySummary(subject, predicate, value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 2048 {
		value = value[:2048]
	}
	return fmt.Sprintf("%s.%s = %s", subject, predicate, value)
}

func (s *CoreMemoryStore) RetryObservation(ctx context.Context, lease corememory.ObservationLease, code string, now time.Time) error {
	if ctx == nil || uuid.Validate(lease.ID) != nil || uuid.Validate(lease.LeaseID) != nil || code == "" || len(code) > 128 {
		return corememory.ErrInvalid
	}
	delayMinutes := lease.Attempt
	if delayMinutes < 1 {
		delayMinutes = 1
	}
	if delayMinutes > 30 {
		delayMinutes = 30
	}
	result, err := s.pool.Exec(ctx, `UPDATE core_memory_observations SET state=CASE WHEN attempt>=5 THEN 'dead' ELSE 'pending' END,next_attempt_at=$3,lease_id=NULL,lease_expires_at=NULL,last_error=$4,updated_at=$5 WHERE observation_id=$1 AND lease_id=$2 AND state='processing'`, lease.ID, lease.LeaseID, now.Add(time.Duration(delayMinutes)*time.Minute), code, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return corememory.ErrInvalid
	}
	return nil
}

func (s *CoreMemoryStore) Recall(ctx context.Context, factLimit, eventLimit int) (corememory.Snapshot, error) {
	if ctx == nil || factLimit <= 0 || factLimit > corememory.MaxActiveFacts || eventLimit <= 0 || eventLimit > 64 {
		return corememory.Snapshot{}, corememory.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return corememory.Snapshot{}, corememory.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockMemoryConfig(ctx, tx, true); err != nil {
		return corememory.Snapshot{}, corememory.ErrRepository
	}
	config, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return corememory.Snapshot{}, err
	}
	if !config.Enabled {
		return corememory.Snapshot{}, tx.Commit(ctx)
	}
	rows, err := tx.Query(ctx, `SELECT fact_id::text,subject,predicate,value,kind,confidence,valid_from,last_confirmed_at FROM core_memory_facts WHERE state='active' ORDER BY last_confirmed_at DESC,fact_id LIMIT $1`, factLimit)
	if err != nil {
		return corememory.Snapshot{}, err
	}
	facts := make([]corememory.Fact, 0, factLimit)
	for rows.Next() {
		var fact corememory.Fact
		if err = rows.Scan(&fact.ID, &fact.Subject, &fact.Predicate, &fact.Value, &fact.Kind, &fact.Confidence, &fact.ValidFrom, &fact.LastConfirmedAt); err != nil {
			rows.Close()
			return corememory.Snapshot{}, err
		}
		facts = append(facts, fact)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return corememory.Snapshot{}, err
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT event_kind,summary,effective_at,occurred_at FROM core_memory_timeline ORDER BY occurred_at DESC,event_id LIMIT $1`, eventLimit)
	if err != nil {
		return corememory.Snapshot{}, err
	}
	defer rows.Close()
	events := make([]corememory.TimelineEvent, 0, eventLimit)
	for rows.Next() {
		var event corememory.TimelineEvent
		if err = rows.Scan(&event.Kind, &event.Summary, &event.EffectiveAt, &event.OccurredAt); err != nil {
			return corememory.Snapshot{}, err
		}
		events = append(events, event)
	}
	if err = rows.Err(); err != nil {
		return corememory.Snapshot{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return corememory.Snapshot{}, corememory.ErrRepository
	}
	return corememory.Snapshot{Facts: facts, Events: events}, nil
}

func (s *CoreMemoryStore) Status(ctx context.Context, factLimit, eventLimit int) (corememory.Status, error) {
	if ctx == nil || factLimit <= 0 || factLimit > corememory.MaxActiveFacts || eventLimit <= 0 || eventLimit > 64 {
		return corememory.Status{}, corememory.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return corememory.Status{}, corememory.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockMemoryConfig(ctx, tx, true); err != nil {
		return corememory.Status{}, corememory.ErrRepository
	}
	config, err := memoryConfigTx(ctx, tx)
	if err != nil {
		return corememory.Status{}, err
	}
	status := corememory.Status{Config: config, Facts: []corememory.Fact{}, Timeline: []corememory.TimelineEvent{}}
	if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM core_memory_facts WHERE state='active'),(SELECT count(*) FROM core_memory_timeline),(SELECT count(*) FROM core_memory_observations WHERE state IN ('pending','processing')),(SELECT count(*) FROM core_memory_observations WHERE state='dead')`).Scan(&status.ActiveFactCount, &status.TimelineEventCount, &status.PendingObservationCount, &status.FailedObservationCount); err != nil {
		return corememory.Status{}, corememory.ErrRepository
	}
	rows, err := tx.Query(ctx, `SELECT fact_id::text,subject,predicate,value,kind,confidence,valid_from,last_confirmed_at FROM core_memory_facts WHERE state='active' ORDER BY last_confirmed_at DESC,fact_id LIMIT $1`, factLimit)
	if err != nil {
		return corememory.Status{}, corememory.ErrRepository
	}
	for rows.Next() {
		var fact corememory.Fact
		if err = rows.Scan(&fact.ID, &fact.Subject, &fact.Predicate, &fact.Value, &fact.Kind, &fact.Confidence, &fact.ValidFrom, &fact.LastConfirmedAt); err != nil {
			rows.Close()
			return corememory.Status{}, corememory.ErrRepository
		}
		status.Facts = append(status.Facts, fact)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return corememory.Status{}, corememory.ErrRepository
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT event_kind,summary,effective_at,occurred_at FROM core_memory_timeline ORDER BY occurred_at DESC,event_id LIMIT $1`, eventLimit)
	if err != nil {
		return corememory.Status{}, corememory.ErrRepository
	}
	for rows.Next() {
		var event corememory.TimelineEvent
		if err = rows.Scan(&event.Kind, &event.Summary, &event.EffectiveAt, &event.OccurredAt); err != nil {
			rows.Close()
			return corememory.Status{}, corememory.ErrRepository
		}
		status.Timeline = append(status.Timeline, event)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return corememory.Status{}, corememory.ErrRepository
	}
	rows.Close()
	if err = tx.Commit(ctx); err != nil {
		return corememory.Status{}, corememory.ErrRepository
	}
	return status, nil
}

var _ corememory.Store = (*CoreMemoryStore)(nil)
