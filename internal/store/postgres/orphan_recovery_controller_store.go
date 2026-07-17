package postgres

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OrphanRecoveryErrorCode is deliberately a fixed, de-secreted classification.
// Provider errors, tags, ARNs, and credential details never reach the durable
// controller state or its public alert event.
type OrphanRecoveryErrorCode string

const (
	OrphanRecoveryErrorProviderUnavailable OrphanRecoveryErrorCode = "provider_unavailable"
	OrphanRecoveryErrorUnavailable         OrphanRecoveryErrorCode = "recovery_unavailable"
	OrphanRecoveryErrorInvalid             OrphanRecoveryErrorCode = "recovery_invalid"
)

type OrphanRecoveryAlertState string

const (
	OrphanRecoveryAlertClear  OrphanRecoveryAlertState = "clear"
	OrphanRecoveryAlertRaised OrphanRecoveryAlertState = "raised"
)

// OrphanRecoveryControllerRecord is the durable scheduler fact for one
// active Connection. Connection is used only to obtain a scoped, read-only
// provider client; it is never copied into controller events.
type OrphanRecoveryControllerRecord struct {
	AgentInstanceID string
	Connection      cloudapp.Connection
	Revision        int64
	Attempt         int
	NextAttemptAt   time.Time
	LastSuccessAt   *time.Time
	SafeErrorCode   OrphanRecoveryErrorCode
	AlertState      OrphanRecoveryAlertState
	AlertErrorCode  OrphanRecoveryErrorCode
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const orphanRecoveryControllerColumns = `
	controller.agent_instance_id, controller.connection_id, controller.revision, controller.attempt,
	controller.next_attempt_at, controller.last_success_at, controller.safe_error_code,
	controller.alert_state, controller.alert_error_code, controller.created_at, controller.updated_at,
	connection.owner_id, connection.account_id, connection.region, connection.control_role_arn,
	connection.foundation_stack_id, connection.status, connection.revision`

// ClaimDueOrphanRecoveryControllers persists a short in-flight lease before
// returning any active Connection. A crash after the claim is therefore
// recoverable from next_attempt_at; a second controller cannot run the same
// revision concurrently. The table is seeded only from active PostgreSQL
// Connections, never from DynamoDB inventory.
func (store *Store) ClaimDueOrphanRecoveryControllers(ctx context.Context, now, claimUntil time.Time, limit int) ([]OrphanRecoveryControllerRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || !validOrphanRecoveryTime(now) || !validOrphanRecoveryTime(claimUntil) ||
		!claimUntil.After(now) || limit < 1 || limit > 256 {
		return nil, cloudapp.ErrInvalid
	}
	now = now.UTC()
	claimUntil = claimUntil.UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO cloud_orphan_recovery_controllers
			(agent_instance_id, connection_id, revision, attempt, next_attempt_at)
		SELECT $1, connection.connection_id, 1, 0, $2
		FROM cloud_connections AS connection
		WHERE connection.agent_instance_id=$1 AND connection.status='active'
		ON CONFLICT (agent_instance_id, connection_id) DO NOTHING`, store.instanceID, now); err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `
		SELECT `+orphanRecoveryControllerColumns+`
		FROM cloud_orphan_recovery_controllers AS controller
		JOIN cloud_connections AS connection ON connection.connection_id=controller.connection_id
		WHERE controller.agent_instance_id=$1
		  AND connection.agent_instance_id=$1
		  AND connection.status='active'
		  AND controller.next_attempt_at <= $2
		ORDER BY controller.next_attempt_at, controller.connection_id
		LIMIT $3
		FOR UPDATE OF controller SKIP LOCKED`, store.instanceID, now, limit)
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	claimed := make([]OrphanRecoveryControllerRecord, 0, limit)
	for rows.Next() {
		record, scanErr := scanOrphanRecoveryController(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		claimed = append(claimed, record)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, cloudapp.ErrUnavailable
	}
	for index := range claimed {
		current := &claimed[index]
		row := tx.QueryRow(ctx, `
			UPDATE cloud_orphan_recovery_controllers
			SET revision=revision+1, next_attempt_at=$4, updated_at=clock_timestamp()
			WHERE agent_instance_id=$1 AND connection_id=$2 AND revision=$3
			RETURNING revision, attempt, next_attempt_at, last_success_at, safe_error_code,
			          alert_state, alert_error_code, created_at, updated_at`,
			store.instanceID, current.Connection.ConnectionID, current.Revision, claimUntil)
		if err := scanOrphanRecoveryControllerState(row, current); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	return cloneOrphanRecoveryControllers(claimed), nil
}

// ConfirmActiveOrphanRecoveryConnection is the final PostgreSQL CAS read
// before orphan recovery creates a scoped AWS client. It binds the original
// controller and Connection revisions to the same owner and active state;
// callers must treat a conflict as retryable and must not call AWS.
func (store *Store) ConfirmActiveOrphanRecoveryConnection(ctx context.Context, connectionID, ownerID string, expectedControllerRevision, expectedConnectionRevision int64) (cloudapp.Connection, error) {
	if store == nil || store.pool == nil || ctx == nil || !validControllerID(connectionID) || strings.TrimSpace(ownerID) == "" ||
		expectedControllerRevision < 1 || expectedConnectionRevision < 1 {
		return cloudapp.Connection{}, cloudapp.ErrInvalid
	}
	var connection cloudapp.Connection
	err := store.pool.QueryRow(ctx, `
		SELECT connection.connection_id, connection.owner_id, connection.account_id, connection.region,
		       connection.control_role_arn, connection.foundation_stack_id, connection.status, connection.revision
		FROM cloud_orphan_recovery_controllers AS controller
		JOIN cloud_connections AS connection ON connection.connection_id=controller.connection_id
		WHERE controller.agent_instance_id=$1 AND controller.connection_id=$2 AND controller.revision=$3
		  AND connection.agent_instance_id=$1 AND connection.owner_id=$4
		  AND connection.status='active' AND connection.revision=$5`,
		store.instanceID, connectionID, expectedControllerRevision, ownerID, expectedConnectionRevision,
	).Scan(&connection.ConnectionID, &connection.OwnerID, &connection.AccountID, &connection.Region,
		&connection.ControlRoleARN, &connection.FoundationStack, &connection.Status, &connection.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return cloudapp.Connection{}, cloudapp.ErrRevisionConflict
	}
	if err != nil || connection.ConnectionID != connectionID || connection.OwnerID != ownerID || connection.Status != "active" || connection.Revision != expectedConnectionRevision {
		return cloudapp.Connection{}, cloudapp.ErrUnavailable
	}
	return connection, nil
}

// RecordOrphanRecoverySuccess clears the alert and attempts only after the
// caller completed a read-only provider discovery. It does not issue any
// provider mutation and it intentionally emits no success event.
func (store *Store) RecordOrphanRecoverySuccess(ctx context.Context, connectionID string, expectedRevision int64, succeededAt, nextAttemptAt time.Time) (OrphanRecoveryControllerRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || !validControllerID(connectionID) || expectedRevision < 1 ||
		!validOrphanRecoveryTime(succeededAt) || !validOrphanRecoveryTime(nextAttemptAt) || !nextAttemptAt.After(succeededAt) {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrInvalid
	}
	succeededAt, nextAttemptAt = succeededAt.UTC(), nextAttemptAt.UTC()
	row := store.pool.QueryRow(ctx, `
		WITH updated AS (
			UPDATE cloud_orphan_recovery_controllers AS controller
			SET revision=controller.revision+1, attempt=0, next_attempt_at=$4, last_success_at=$5,
			    safe_error_code=NULL, alert_state='clear', alert_error_code=NULL, updated_at=clock_timestamp()
			WHERE controller.agent_instance_id=$1 AND controller.connection_id=$2 AND controller.revision=$3
			  AND EXISTS (
				SELECT 1 FROM cloud_connections AS connection
				WHERE connection.connection_id=controller.connection_id
				  AND connection.agent_instance_id=$1 AND connection.status='active'
			  )
			RETURNING controller.agent_instance_id, controller.connection_id, controller.revision, controller.attempt,
			          controller.next_attempt_at, controller.last_success_at, controller.safe_error_code,
			          controller.alert_state, controller.alert_error_code, controller.created_at, controller.updated_at
		)
		SELECT updated.agent_instance_id, updated.connection_id, updated.revision, updated.attempt,
		       updated.next_attempt_at, updated.last_success_at, updated.safe_error_code,
		       updated.alert_state, updated.alert_error_code, updated.created_at, updated.updated_at,
		       connection.owner_id, connection.account_id, connection.region, connection.control_role_arn,
		       connection.foundation_stack_id, connection.status, connection.revision
		FROM updated JOIN cloud_connections AS connection ON connection.connection_id=updated.connection_id`,
		store.instanceID, connectionID, expectedRevision, nextAttemptAt, succeededAt)
	record, err := scanOrphanRecoveryController(row)
	if errors.Is(err, cloudapp.ErrNotFound) {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrRevisionConflict
	}
	return record, err
}

// RecordOrphanRecoveryFailure keeps a bounded-retry fact durable. The alert
// outbox row is inserted in the same transaction only when the fixed error
// state changes, so restarts and repeated retries cannot flood consumers.
func (store *Store) RecordOrphanRecoveryFailure(ctx context.Context, connectionID string, expectedRevision int64, failedAt, nextAttemptAt time.Time, code OrphanRecoveryErrorCode) (OrphanRecoveryControllerRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || !validControllerID(connectionID) || expectedRevision < 1 ||
		!validOrphanRecoveryTime(failedAt) || !validOrphanRecoveryTime(nextAttemptAt) || !nextAttemptAt.After(failedAt) || !validOrphanRecoveryErrorCode(code) {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrInvalid
	}
	failedAt, nextAttemptAt = failedAt.UTC(), nextAttemptAt.UTC()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readOrphanRecoveryController(ctx, tx, store.instanceID, connectionID, true)
	if errors.Is(err, cloudapp.ErrNotFound) {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrRevisionConflict
	}
	if err != nil {
		return OrphanRecoveryControllerRecord{}, err
	}
	if current.Revision != expectedRevision || current.Connection.Status != "active" {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrRevisionConflict
	}
	attempt := current.Attempt
	if attempt < math.MaxInt32 {
		attempt++
	}
	alertChanged := current.AlertState != OrphanRecoveryAlertRaised || current.AlertErrorCode != code
	row := tx.QueryRow(ctx, `
		WITH updated AS (
			UPDATE cloud_orphan_recovery_controllers AS controller
			SET revision=controller.revision+1, attempt=$4, next_attempt_at=$5,
			    safe_error_code=$6, alert_state='raised', alert_error_code=$6, updated_at=clock_timestamp()
			WHERE controller.agent_instance_id=$1 AND controller.connection_id=$2 AND controller.revision=$3
			  AND EXISTS (
				SELECT 1 FROM cloud_connections AS connection
				WHERE connection.connection_id=controller.connection_id
				  AND connection.agent_instance_id=$1 AND connection.status='active'
			  )
			RETURNING controller.agent_instance_id, controller.connection_id, controller.revision, controller.attempt,
			          controller.next_attempt_at, controller.last_success_at, controller.safe_error_code,
			          controller.alert_state, controller.alert_error_code, controller.created_at, controller.updated_at
		)
		SELECT updated.agent_instance_id, updated.connection_id, updated.revision, updated.attempt,
		       updated.next_attempt_at, updated.last_success_at, updated.safe_error_code,
		       updated.alert_state, updated.alert_error_code, updated.created_at, updated.updated_at,
		       connection.owner_id, connection.account_id, connection.region, connection.control_role_arn,
		       connection.foundation_stack_id, connection.status, connection.revision
		FROM updated JOIN cloud_connections AS connection ON connection.connection_id=updated.connection_id`,
		store.instanceID, connectionID, expectedRevision, attempt, nextAttemptAt, string(code))
	record, err := scanOrphanRecoveryController(row)
	if errors.Is(err, cloudapp.ErrNotFound) {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrRevisionConflict
	}
	if err != nil {
		return OrphanRecoveryControllerRecord{}, err
	}
	if alertChanged {
		summary := struct {
			ControllerID string                  `json:"controller_id"`
			ConnectionID string                  `json:"connection_id"`
			ErrorCode    OrphanRecoveryErrorCode `json:"error_code"`
			Revision     int64                   `json:"revision"`
			OccurredAt   time.Time               `json:"occurred_at"`
		}{
			ControllerID: connectionID,
			ConnectionID: connectionID,
			ErrorCode:    code,
			Revision:     record.Revision,
			OccurredAt:   record.UpdatedAt.UTC(),
		}
		if err := appendCloudFactEvent(ctx, tx, uuid.MustParse(connectionID), "orphan_recovery_controller", "cloud.alert.raised", uint64(record.Revision), summary); err != nil {
			return OrphanRecoveryControllerRecord{}, cloudapp.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrUnavailable
	}
	return record, nil
}

func readOrphanRecoveryController(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, agentInstanceID uuid.UUID, connectionID string, forUpdate bool) (OrphanRecoveryControllerRecord, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE OF controller"
	}
	return scanOrphanRecoveryController(query.QueryRow(ctx, `
		SELECT `+orphanRecoveryControllerColumns+`
		FROM cloud_orphan_recovery_controllers AS controller
		JOIN cloud_connections AS connection ON connection.connection_id=controller.connection_id
		WHERE controller.agent_instance_id=$1 AND controller.connection_id=$2 AND connection.agent_instance_id=$1`+suffix,
		agentInstanceID, connectionID))
}

type orphanRecoveryRowScanner interface{ Scan(...any) error }

func scanOrphanRecoveryController(row orphanRecoveryRowScanner) (OrphanRecoveryControllerRecord, error) {
	var record OrphanRecoveryControllerRecord
	var lastSuccess *time.Time
	var safeCode, alertCode *string
	if err := row.Scan(
		&record.AgentInstanceID, &record.Connection.ConnectionID, &record.Revision, &record.Attempt,
		&record.NextAttemptAt, &lastSuccess, &safeCode, &record.AlertState, &alertCode, &record.CreatedAt, &record.UpdatedAt,
		&record.Connection.OwnerID, &record.Connection.AccountID, &record.Connection.Region, &record.Connection.ControlRoleARN,
		&record.Connection.FoundationStack, &record.Connection.Status, &record.Connection.Revision,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrphanRecoveryControllerRecord{}, cloudapp.ErrNotFound
		}
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrUnavailable
	}
	if lastSuccess != nil {
		value := lastSuccess.UTC()
		record.LastSuccessAt = &value
	}
	if safeCode != nil {
		record.SafeErrorCode = OrphanRecoveryErrorCode(*safeCode)
	}
	if alertCode != nil {
		record.AlertErrorCode = OrphanRecoveryErrorCode(*alertCode)
	}
	record.NextAttemptAt, record.CreatedAt, record.UpdatedAt = record.NextAttemptAt.UTC(), record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if !validOrphanRecoveryController(record) {
		return OrphanRecoveryControllerRecord{}, cloudapp.ErrUnavailable
	}
	return record, nil
}

func scanOrphanRecoveryControllerState(row orphanRecoveryRowScanner, record *OrphanRecoveryControllerRecord) error {
	if record == nil {
		return cloudapp.ErrInvalid
	}
	var lastSuccess *time.Time
	var safeCode, alertCode *string
	if err := row.Scan(&record.Revision, &record.Attempt, &record.NextAttemptAt, &lastSuccess, &safeCode,
		&record.AlertState, &alertCode, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapp.ErrRevisionConflict
		}
		return cloudapp.ErrUnavailable
	}
	if lastSuccess == nil {
		record.LastSuccessAt = nil
	} else {
		value := lastSuccess.UTC()
		record.LastSuccessAt = &value
	}
	if safeCode == nil {
		record.SafeErrorCode = ""
	} else {
		record.SafeErrorCode = OrphanRecoveryErrorCode(*safeCode)
	}
	if alertCode == nil {
		record.AlertErrorCode = ""
	} else {
		record.AlertErrorCode = OrphanRecoveryErrorCode(*alertCode)
	}
	record.NextAttemptAt, record.CreatedAt, record.UpdatedAt = record.NextAttemptAt.UTC(), record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if !validOrphanRecoveryController(*record) {
		return cloudapp.ErrUnavailable
	}
	return nil
}

func validOrphanRecoveryController(record OrphanRecoveryControllerRecord) bool {
	if parsed, err := uuid.Parse(record.AgentInstanceID); err != nil || parsed == uuid.Nil || parsed.String() != record.AgentInstanceID {
		return false
	}
	if !validControllerID(record.Connection.ConnectionID) || record.Revision < 1 || record.Attempt < 0 || !validOrphanRecoveryTime(record.NextAttemptAt) ||
		!validOrphanRecoveryTime(record.CreatedAt) || !validOrphanRecoveryTime(record.UpdatedAt) || record.Connection.Status != "active" {
		return false
	}
	if record.LastSuccessAt != nil && !validOrphanRecoveryTime(*record.LastSuccessAt) {
		return false
	}
	if record.SafeErrorCode != "" && !validOrphanRecoveryErrorCode(record.SafeErrorCode) {
		return false
	}
	switch record.AlertState {
	case OrphanRecoveryAlertClear:
		return record.AlertErrorCode == ""
	case OrphanRecoveryAlertRaised:
		return validOrphanRecoveryErrorCode(record.AlertErrorCode)
	default:
		return false
	}
}

func validOrphanRecoveryErrorCode(code OrphanRecoveryErrorCode) bool {
	switch code {
	case OrphanRecoveryErrorProviderUnavailable, OrphanRecoveryErrorUnavailable, OrphanRecoveryErrorInvalid:
		return true
	default:
		return false
	}
}

func validControllerID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOrphanRecoveryTime(value time.Time) bool { return !value.IsZero() }

func cloneOrphanRecoveryControllers(records []OrphanRecoveryControllerRecord) []OrphanRecoveryControllerRecord {
	cloned := make([]OrphanRecoveryControllerRecord, len(records))
	copy(cloned, records)
	for index := range cloned {
		if records[index].LastSuccessAt != nil {
			value := *records[index].LastSuccessAt
			cloned[index].LastSuccessAt = &value
		}
	}
	return cloned
}
