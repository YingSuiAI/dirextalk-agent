package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

// The methods in this file are the public Execution V2 read boundary. Unlike
// controller reads, they never accept an empty owner and always include the
// immutable account generation in the SQL predicate.

func (s *CloudWorkerStore) GetPlanForAuthority(ctx context.Context, owner string, accountGeneration uint64, id string, revision uint64) (cloudworker.Plan, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || !coretask.ValidUUID(id) {
		return cloudworker.Plan{}, cloudworker.ErrInvalid
	}
	return scanCloudWorkerPlan(s.store.pool.QueryRow(ctx, cloudWorkerPlanSelect+`
		WHERE plan_id=$1 AND owner_id=$2 AND account_generation=$3 AND ($4=0 OR revision=$4)`,
		id, owner, accountGeneration, revision))
}

func (s *CloudWorkerStore) ListPlansForAuthority(ctx context.Context, owner string, accountGeneration uint64, cursor string, limit int) ([]cloudworker.Plan, string, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || limit < 1 || limit > 200 {
		return nil, "", cloudworker.ErrInvalid
	}
	after, err := decodeCloudWorkerAuthorityCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.store.pool.Query(ctx, cloudWorkerPlanSelect+` WHERE owner_id=$1 AND account_generation=$2 AND
		($3::timestamptz IS NULL OR (created_at,plan_id)<($3,$4::uuid))
		ORDER BY created_at DESC,plan_id DESC LIMIT $5`, owner, accountGeneration,
		nullableTimePG(after.CreatedAt), nullableUUIDPG(after.ID), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([]cloudworker.Plan, 0, limit+1)
	for rows.Next() {
		plan, scanErr := scanCloudWorkerPlan(rows)
		if scanErr != nil {
			return nil, "", scanErr
		}
		result = append(result, plan)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return paginateCloudWorkerPlans(result, limit)
}

func (s *CloudWorkerStore) GetExecutionForAuthority(ctx context.Context, owner string, accountGeneration uint64, id string) (cloudworker.Execution, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || !coretask.ValidUUID(id) {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	return scanCloudWorkerExecution(s.store.pool.QueryRow(ctx, cloudWorkerExecutionSelect+`
		WHERE execution_json->>'run_id'=$1 AND owner_id=$2 AND account_generation=$3`, id, owner, accountGeneration))
}

func (s *CloudWorkerStore) ListExecutionsForAuthority(ctx context.Context, owner string, accountGeneration uint64, cursor string, limit int) ([]cloudworker.Execution, string, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || limit < 1 || limit > 200 {
		return nil, "", cloudworker.ErrInvalid
	}
	after, err := decodeCloudWorkerAuthorityCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.store.pool.Query(ctx, cloudWorkerExecutionSelect+` WHERE owner_id=$1 AND account_generation=$2 AND
		($3::timestamptz IS NULL OR (created_at,execution_id)<($3,$4::uuid))
		ORDER BY created_at DESC,execution_id DESC LIMIT $5`, owner, accountGeneration,
		nullableTimePG(after.CreatedAt), nullableUUIDPG(after.ID), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([]cloudworker.Execution, 0, limit+1)
	for rows.Next() {
		execution, scanErr := scanCloudWorkerExecution(rows)
		if scanErr != nil {
			return nil, "", scanErr
		}
		result = append(result, execution)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return paginateCloudWorkerExecutions(result, limit)
}

func (s *CloudWorkerStore) EventsForAuthority(ctx context.Context, owner string, accountGeneration uint64, id string, after uint64, limit int) ([]cloudworker.Event, uint64, bool, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || !coretask.ValidUUID(id) || limit < 1 || limit > 200 {
		return nil, after, false, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, after, false, err
	}
	defer tx.Rollback(ctx)
	var executionID string
	var truncatedThrough uint64
	err = tx.QueryRow(ctx, `SELECT execution_id::text,event_history_truncated_through FROM core_cloud_worker_executions
		WHERE execution_json->>'run_id'=$1 AND owner_id=$2 AND account_generation=$3`, id, owner, accountGeneration).Scan(&executionID, &truncatedThrough)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, after, false, cloudworker.ErrNotFound
	}
	if err != nil {
		return nil, after, false, err
	}
	historyTruncated := after < truncatedThrough
	effectiveAfter := after
	if historyTruncated {
		effectiveAfter = truncatedThrough
	}
	rows, err := tx.Query(ctx, `SELECT event.kind,event.worker_progress_sequence,event.payload_json
		FROM core_cloud_worker_events event
		JOIN core_cloud_worker_executions execution ON execution.execution_id=event.execution_id
		WHERE event.execution_id=$1 AND event.owner_id=$2 AND execution.owner_id=$2
		AND execution.account_generation=$3 AND event.sequence>$4
		ORDER BY event.sequence LIMIT $5`, executionID, owner, accountGeneration, effectiveAfter, limit)
	if err != nil {
		return nil, after, false, err
	}
	defer rows.Close()
	result := make([]cloudworker.Event, 0, limit)
	next := effectiveAfter
	for rows.Next() {
		var kind string
		var workerProgressSequence *uint64
		var raw []byte
		var event cloudworker.Event
		if err = rows.Scan(&kind, &workerProgressSequence, &raw); err != nil || json.Unmarshal(raw, &event) != nil ||
			event.ExecutionID != executionID || event.RunID != id || event.OwnerID != owner ||
			event.AccountGeneration != accountGeneration || event.Sequence != next+1 || event.Type != kind ||
			workerProgressSequence != nil || event.Type == "worker_progress" {
			return nil, after, false, cloudworker.ErrConflict
		}
		result = append(result, event)
		next = event.Sequence
	}
	if err = rows.Err(); err != nil {
		return nil, after, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, after, false, err
	}
	return result, next, historyTruncated, nil
}

func decodeCloudWorkerAuthorityCursor(value string) (cloudWorkerListCursor, error) {
	if value == "" {
		return cloudWorkerListCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	var cursor cloudWorkerListCursor
	if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.CreatedAt.IsZero() || !coretask.ValidUUID(cursor.ID) {
		return cloudWorkerListCursor{}, cloudworker.ErrInvalid
	}
	return cursor, nil
}

func encodeCloudWorkerAuthorityCursor(value cloudWorkerListCursor) string {
	raw, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func paginateCloudWorkerPlans(values []cloudworker.Plan, limit int) ([]cloudworker.Plan, string, error) {
	if len(values) <= limit {
		return values, "", nil
	}
	last := values[limit-1]
	return values[:limit], encodeCloudWorkerAuthorityCursor(cloudWorkerListCursor{CreatedAt: last.CreatedAt, ID: last.PlanID}), nil
}

func paginateCloudWorkerExecutions(values []cloudworker.Execution, limit int) ([]cloudworker.Execution, string, error) {
	if len(values) <= limit {
		return values, "", nil
	}
	last := values[limit-1]
	return values[:limit], encodeCloudWorkerAuthorityCursor(cloudWorkerListCursor{CreatedAt: last.CreatedAt, ID: last.ExecutionID}), nil
}
