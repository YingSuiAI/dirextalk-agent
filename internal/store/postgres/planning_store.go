package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) ClaimResearch(ctx context.Context, scope task.MutationScope, command planning.ResearchCommand) (planning.ResearchSession, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if err := command.Validate(); err != nil {
		return planning.ResearchSession{}, err
	}
	digest := command.Digest()
	sessionID, err := uuid.NewV7()
	if err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	quoteState := planning.QuoteAwaitingConnection
	if command.Binding.ConnectionID != "" {
		quoteState = planning.QuoteAwaitingQuote
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	defer func() { _ = tx.Rollback(ctx) }()

	result, err := tx.Exec(ctx, `
		INSERT INTO planning_sessions
		    (session_id, request_id, request_hash, caller_client_id, caller_credential_id,
		     owner_id, conversation_id, connection_id, recipe_id, retention_policy, quote_state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT DO NOTHING`,
		sessionID, command.Binding.RequestID, digest[:], caller.ClientID, caller.CredentialID,
		command.Binding.OwnerID, command.Binding.ConversationID, command.Binding.ConnectionID,
		command.Binding.RecipeID, command.Binding.Retention, quoteState,
	)
	if err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	created := result.RowsAffected() == 1
	session, storedCaller, storedHash, err := lockResearchByBinding(ctx, tx, command.Binding)
	if errors.Is(err, planning.ErrNotFound) {
		return planning.ResearchSession{}, planning.ErrIdempotencyConflict
	}
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if storedCaller != caller {
		return planning.ResearchSession{}, planning.ErrScopeMismatch
	}
	if !bytes.Equal(storedHash, digest[:]) || session.Binding != command.Binding {
		return planning.ResearchSession{}, planning.ErrIdempotencyConflict
	}
	if created {
		if err := appendPlanningSessionEvent(ctx, tx, session, caller, "agent.planning.research_claimed"); err != nil {
			return planning.ResearchSession{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	return session, nil
}

func (store *Store) AttachResearchTask(ctx context.Context, scope task.MutationScope, binding planning.Binding, taskID string) (planning.ResearchSession, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if err := binding.Validate(); err != nil {
		return planning.ResearchSession{}, err
	}
	parsedTaskID, err := uuid.Parse(taskID)
	if err != nil {
		return planning.ResearchSession{}, planning.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	defer func() { _ = tx.Rollback(ctx) }()
	session, storedCaller, _, err := lockResearchByBinding(ctx, tx, binding)
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if storedCaller != caller {
		return planning.ResearchSession{}, planning.ErrScopeMismatch
	}
	if session.Binding != binding {
		return planning.ResearchSession{}, planning.ErrIdempotencyConflict
	}
	if session.TaskID != "" {
		if session.TaskID != parsedTaskID.String() {
			return planning.ResearchSession{}, planning.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return planning.ResearchSession{}, planning.ErrPersistence
		}
		return session, nil
	}
	var ownerID string
	var retention task.RetentionPolicy
	if err := tx.QueryRow(ctx, `SELECT owner_id, retention_policy FROM tasks WHERE task_id=$1 FOR SHARE`, parsedTaskID).Scan(&ownerID, &retention); err != nil {
		return planning.ResearchSession{}, planning.ErrTaskOperation
	}
	if ownerID != binding.OwnerID || retention != binding.Retention {
		return planning.ResearchSession{}, planning.ErrTaskOperation
	}
	if err := tx.QueryRow(ctx, `
		UPDATE planning_sessions SET task_id=$2, revision=revision+1, updated_at=clock_timestamp()
		WHERE session_id=$1
		RETURNING revision, updated_at`, session.SessionID, parsedTaskID).Scan(&session.Revision, &session.UpdatedAt); err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	session.TaskID = parsedTaskID.String()
	session.UpdatedAt = session.UpdatedAt.UTC()
	if err := appendPlanningSessionEvent(ctx, tx, session, caller, "agent.planning.task_attached"); err != nil {
		return planning.ResearchSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	return session, nil
}

func (store *Store) GetResearch(ctx context.Context, scope task.MutationScope, binding planning.Binding) (planning.ResearchSession, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if err := binding.Validate(); err != nil {
		return planning.ResearchSession{}, err
	}
	session, storedCaller, _, err := readResearchByBinding(ctx, store.pool, binding, false)
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if storedCaller.ClientID != caller.ClientID {
		return planning.ResearchSession{}, planning.ErrScopeMismatch
	}
	if !session.Binding.SameSession(binding) {
		return planning.ResearchSession{}, planning.ErrIdempotencyConflict
	}
	candidates, err := loadPlanningCandidates(ctx, store.pool, session.SessionID)
	if err != nil {
		return planning.ResearchSession{}, err
	}
	if session.CandidateRevision == 0 && len(candidates) != 0 {
		return planning.ResearchSession{}, planning.ErrPersistence
	}
	if session.CandidateRevision > 0 {
		if err := planning.ValidateResourceCandidates(candidates, session.QuoteState); err != nil {
			return planning.ResearchSession{}, planning.ErrPersistence
		}
	}
	session.Candidates = candidates
	return session, nil
}

type planningQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func lockResearchByBinding(ctx context.Context, tx pgx.Tx, binding planning.Binding) (planning.ResearchSession, idempotencyCaller, []byte, error) {
	return readResearchByBinding(ctx, tx, binding, true)
}

func readResearchByBinding(ctx context.Context, query planningQuerier, binding planning.Binding, lock bool) (planning.ResearchSession, idempotencyCaller, []byte, error) {
	statement := `
		SELECT session_id, request_id, request_hash, caller_client_id, caller_credential_id,
		       owner_id, conversation_id, connection_id, recipe_id, retention_policy,
		       COALESCE(task_id::text,''), quote_state, candidate_revision, revision, created_at, updated_at
		FROM planning_sessions WHERE owner_id=$1 AND conversation_id=$2 AND recipe_id=$3`
	if lock {
		statement += " FOR UPDATE"
	}
	var session planning.ResearchSession
	var caller idempotencyCaller
	var requestHash []byte
	if err := query.QueryRow(ctx, statement, binding.OwnerID, binding.ConversationID, binding.RecipeID).Scan(
		&session.SessionID, &session.Binding.RequestID, &requestHash, &caller.ClientID, &caller.CredentialID,
		&session.Binding.OwnerID, &session.Binding.ConversationID, &session.Binding.ConnectionID,
		&session.Binding.RecipeID, &session.Binding.Retention, &session.TaskID, &session.QuoteState,
		&session.CandidateRevision, &session.Revision, &session.CreatedAt, &session.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return planning.ResearchSession{}, idempotencyCaller{}, nil, planning.ErrNotFound
		}
		return planning.ResearchSession{}, idempotencyCaller{}, nil, planning.ErrPersistence
	}
	session.CreatedAt = session.CreatedAt.UTC()
	session.UpdatedAt = session.UpdatedAt.UTC()
	return session, caller, requestHash, nil
}

func loadPlanningCandidates(ctx context.Context, query planningQuerier, sessionID string) ([]planning.ResourceCandidateV1, error) {
	rows, err := query.Query(ctx, `
		SELECT candidate_json FROM planning_resource_candidates
		WHERE session_id=$1 ORDER BY CASE tier WHEN 'economy' THEN 1 WHEN 'recommended' THEN 2 ELSE 3 END`, sessionID)
	if err != nil {
		return nil, planning.ErrPersistence
	}
	defer rows.Close()
	var candidates []planning.ResourceCandidateV1
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, planning.ErrPersistence
		}
		var candidate planning.ResourceCandidateV1
		if err := json.Unmarshal(encoded, &candidate); err != nil {
			return nil, planning.ErrPersistence
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, planning.ErrPersistence
	}
	return candidates, nil
}

func planningBindingKey(binding planning.Binding) string {
	return strings.Join([]string{binding.OwnerID, binding.ConversationID, binding.RecipeID}, "\x00")
}
