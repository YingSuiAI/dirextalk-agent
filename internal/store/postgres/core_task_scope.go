package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func internalEntityOwnerID(kind, id string) string {
	return coretask.ReservedInternalOwnerPrefix + strings.TrimSpace(kind) + "__:" + strings.TrimSpace(id)
}

func ownerScopeOrInternal(ctx context.Context, kind, id string) (string, int64, error) {
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		if scope.Validate() != nil {
			return "", 0, coretask.ErrInvalid
		}
		return scope.OwnerID, scope.AccountGeneration, nil
	}
	ownerID := internalEntityOwnerID(kind, id)
	if len(ownerID) > 256 {
		return "", 0, coretask.ErrInvalid
	}
	return ownerID, 1, nil
}

func replayOwnerScope(ctx context.Context, domain, key string) (string, int64, error) {
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		return scope.OwnerID, scope.AccountGeneration, nil
	}
	return ownerScopeOrInternal(ctx, domain+"_replay", key)
}

func ownerScopedStableUUID(ctx context.Context, namespace, key string) string {
	seed := namespace + "/" + key
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		seed = fmt.Sprintf("%s/%s/%d/%s", namespace, scope.OwnerID, scope.AccountGeneration, key)
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(seed)).String()
}

func copyTaskOwnerScopeFromScheduleTx(ctx context.Context, tx pgx.Tx, taskID, scheduleID string) error {
	if ctx == nil || tx == nil || !coretask.ValidUUID(taskID) || !coretask.ValidUUID(scheduleID) {
		return coretask.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE core_task_scopes task_scope
		SET owner_id=schedule.owner_id,account_generation=schedule.account_generation
		FROM core_schedules schedule
		WHERE task_scope.task_id=$1 AND schedule.schedule_id=$2`, taskID, scheduleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrNotFound
	}
	return nil
}

func bindTaskOwnerScopeTx(ctx context.Context, tx pgx.Tx, taskID string) error {
	scope, ok := coretask.OwnerScopeFromContext(ctx)
	if !ok {
		return nil
	}
	return setTaskOwnerScopeTx(ctx, tx, taskID, scope)
}

func setTaskOwnerScopeTx(ctx context.Context, tx pgx.Tx, taskID string, scope coretask.OwnerScope) error {
	if ctx == nil || tx == nil || !coretask.ValidUUID(taskID) || scope.Validate() != nil {
		return coretask.ErrInvalid
	}
	return setTaskOwnerScopeValuesTx(ctx, tx, taskID, scope.OwnerID, scope.AccountGeneration)
}

func setTaskOwnerScopeValuesTx(ctx context.Context, tx pgx.Tx, taskID, ownerID string, generation int64) error {
	if ctx == nil || tx == nil || !coretask.ValidUUID(taskID) || strings.TrimSpace(ownerID) == "" || len(ownerID) > 256 || generation <= 0 || strings.ContainsAny(ownerID, "\r\n\x00") {
		return coretask.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE core_task_scopes SET owner_id=$2,account_generation=$3 WHERE task_id=$1`, taskID, ownerID, generation)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrNotFound
	}
	return nil
}

func bindKnowledgeSourceOwnerScopeTx(ctx context.Context, tx pgx.Tx, sourceID string) error {
	if ctx == nil || tx == nil || !coretask.ValidUUID(sourceID) {
		return coretask.ErrInvalid
	}
	scope, ok := coretask.OwnerScopeFromContext(ctx)
	if !ok {
		return nil
	}
	if scope.Validate() != nil {
		return coretask.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE core_knowledge_sources SET owner_id=$2,account_generation=$3 WHERE source_id=$1`, sourceID, scope.OwnerID, scope.AccountGeneration)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrNotFound
	}
	return nil
}

func requireTaskOwnerScopeTx(ctx context.Context, tx pgx.Tx, taskID string) error {
	scope, ok := coretask.OwnerScopeFromContext(ctx)
	if !ok {
		return nil
	}
	var ownerID string
	var generation int64
	err := tx.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_task_scopes WHERE task_id=$1 FOR UPDATE`, taskID).Scan(&ownerID, &generation)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerID != scope.OwnerID || generation != scope.AccountGeneration) {
		return coretask.ErrNotFound
	}
	return err
}

func requireTaskOwnerScope(ctx context.Context, store *Store, taskID string) error {
	scope, ok := coretask.OwnerScopeFromContext(ctx)
	if !ok {
		return nil
	}
	var exists bool
	err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core_task_scopes WHERE task_id=$1 AND owner_id=$2 AND account_generation=$3)`, taskID, scope.OwnerID, scope.AccountGeneration).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !exists {
		return coretask.ErrNotFound
	}
	return err
}

func requireConfirmationOwnerScopeTx(ctx context.Context, tx pgx.Tx, confirmationID string) error {
	scope, ok := coretask.OwnerScopeFromContext(ctx)
	if !ok {
		return nil
	}
	var ownerID string
	var generation int64
	err := tx.QueryRow(ctx, `SELECT scope.owner_id,scope.account_generation
		FROM core_confirmations confirmation
		JOIN core_task_scopes scope ON scope.task_id=confirmation.task_id
		WHERE confirmation.confirmation_id=$1
		FOR UPDATE OF scope`, confirmationID).Scan(&ownerID, &generation)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerID != scope.OwnerID || generation != scope.AccountGeneration) {
		return coreconfirmation.ErrNotFound
	}
	return err
}
