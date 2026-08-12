package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreMemoryStore struct{ *Store }

func NewCoreMemoryStore(store *Store) (*CoreMemoryStore, error) {
	if store == nil || store.pool == nil {
		return nil, errors.New("postgres store is required")
	}
	return &CoreMemoryStore{Store: store}, nil
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
	_, err := tx.Exec(ctx, `INSERT INTO core_memory_observations(observation_id,conversation_id,profile_id,user_text,assistant_text,observed_at,next_attempt_at)
		VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(observation_id) DO NOTHING`, observationID, conversationID, profileID, userText, assistantText, observedAt)
	return err
}

func (s *CoreMemoryStore) ClaimObservation(ctx context.Context, now time.Time, ttl time.Duration) (corememory.ObservationLease, bool, error) {
	if ctx == nil || ttl <= 0 {
		return corememory.ObservationLease{}, false, corememory.ErrInvalid
	}
	leaseID := uuid.NewString()
	if _, err := s.pool.Exec(ctx, `UPDATE core_memory_observations SET state='dead',lease_id=NULL,lease_expires_at=NULL,last_error='memory_consolidation_abandoned',updated_at=$1 WHERE state='processing' AND attempt>=5 AND lease_expires_at<=$1`, now); err != nil {
		return corememory.ObservationLease{}, false, err
	}
	row := s.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT observation_id FROM core_memory_observations
		WHERE attempt<5 AND ((state='pending' AND next_attempt_at<=$1) OR (state='processing' AND lease_expires_at<=$1))
		ORDER BY observed_at,observation_id FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE core_memory_observations o SET state='processing',attempt=attempt+1,lease_id=$2,lease_expires_at=$3,updated_at=$1
	FROM candidate c WHERE o.observation_id=c.observation_id
	RETURNING o.observation_id::text,o.conversation_id::text,o.profile_id::text,o.user_text,o.assistant_text,o.observed_at,o.attempt`, now, leaseID, now.Add(ttl))
	var lease corememory.ObservationLease
	if err := row.Scan(&lease.ID, &lease.ConversationID, &lease.ProfileID, &lease.UserText, &lease.AssistantText, &lease.ObservedAt, &lease.Attempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return corememory.ObservationLease{}, false, nil
		}
		return corememory.ObservationLease{}, false, err
	}
	lease.LeaseID = leaseID
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
		if _, err = tx.Exec(ctx, `UPDATE core_memory_facts SET state='retracted',valid_to=$2,last_confirmed_at=$2 WHERE fact_id=$1 AND state='active'`, current.ID, now); err != nil {
			return err
		}
		return insertMemoryTimeline(ctx, tx, observationID, "retracted", current.ID, "", memorySummary(current.Subject, current.Predicate, current.Value), now)
	}
	if err == nil && current.Value == candidate.Value {
		if _, err = tx.Exec(ctx, `UPDATE core_memory_facts SET confidence=GREATEST(confidence,$2),last_confirmed_at=$3 WHERE fact_id=$1 AND state='active'`, current.ID, candidate.Confidence, now); err != nil {
			return err
		}
		return insertMemoryTimeline(ctx, tx, observationID, "confirmed", current.ID, "", memorySummary(candidate.Subject, candidate.Predicate, candidate.Value), now)
	}
	newID := uuid.NewString()
	previousID := ""
	eventKind := "added"
	if err == nil {
		previousID, eventKind = current.ID, "replaced"
		if _, err = tx.Exec(ctx, `UPDATE core_memory_facts SET state='superseded',valid_to=$2 WHERE fact_id=$1 AND state='active'`, current.ID, now); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_memory_facts(fact_id,subject,predicate,value,kind,confidence,state,valid_from,last_confirmed_at,source_observation_id,supersedes_fact_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,'active',$7,$7,$8,$9,$7)`, newID, candidate.Subject, candidate.Predicate, candidate.Value, candidate.Kind, candidate.Confidence, now, observationID, nullableUUIDPG(previousID)); err != nil {
		return err
	}
	return insertMemoryTimeline(ctx, tx, observationID, eventKind, newID, previousID, memorySummary(candidate.Subject, candidate.Predicate, candidate.Value), now)
}

func insertMemoryTimeline(ctx context.Context, tx pgx.Tx, observationID, kind, factID, previousID, summary string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO core_memory_timeline(event_id,observation_id,event_kind,fact_id,previous_fact_id,summary,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.NewString(), observationID, kind, factID, nullableUUIDPG(previousID), summary, now)
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
	facts, err := s.ListActiveFacts(ctx, factLimit)
	if err != nil {
		return corememory.Snapshot{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT event_kind,summary,occurred_at FROM core_memory_timeline ORDER BY occurred_at DESC,event_id LIMIT $1`, eventLimit)
	if err != nil {
		return corememory.Snapshot{}, err
	}
	defer rows.Close()
	events := make([]corememory.TimelineEvent, 0, eventLimit)
	for rows.Next() {
		var event corememory.TimelineEvent
		if err = rows.Scan(&event.Kind, &event.Summary, &event.OccurredAt); err != nil {
			return corememory.Snapshot{}, err
		}
		events = append(events, event)
	}
	return corememory.Snapshot{Facts: facts, Events: events}, rows.Err()
}

var _ corememory.Store = (*CoreMemoryStore)(nil)
