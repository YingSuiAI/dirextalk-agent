package postgres

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ cloudexecution.Repository = (*Store)(nil)
var _ cloudexecution.ConnectionReader = (*Store)(nil)
var _ cloudexecution.DeploymentLaunchReader = (*Store)(nil)

const cloudLaunchColumns = `operation_id, caller_client_id, caller_credential_id, idempotency_key,
       request_hash, owner_id, plan_id, approval_id, connection_id, task_step_id, deployment_id,
       task_id, state, operation_json, redacted_error, revision, created_at, updated_at`

func (store *Store) Begin(ctx context.Context, intent cloudexecution.Intent) (cloudexecution.Operation, bool, error) {
	if store == nil || store.pool == nil || validateLaunchIntent(intent) != nil {
		return cloudexecution.Operation{}, false, cloudexecution.ErrInvalid
	}
	initial := cloudexecution.Operation{
		Intent: intent, State: cloudexecution.StateIntent, Revision: 1,
		CreatedAt: intent.RecordedAt.UTC(), UpdatedAt: intent.RecordedAt.UTC(),
	}
	encoded, err := json.Marshal(initial)
	if err != nil {
		return cloudexecution.Operation{}, false, cloudexecution.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudexecution.Operation{}, false, cloudexecution.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, readErr := readCloudLaunch(ctx, tx, ` WHERE operation_id=$1 FOR UPDATE`, intent.OperationID)
	if readErr == nil {
		if !sameLaunchIntent(existing.Intent, intent) {
			return cloudexecution.Operation{}, false, cloudexecution.ErrRevisionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudexecution.Operation{}, false, cloudexecution.ErrUnavailable
		}
		return existing, false, nil
	}
	if !errors.Is(readErr, cloudexecution.ErrNotReady) {
		return cloudexecution.Operation{}, false, readErr
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO cloud_launch_operations (
			operation_id, agent_instance_id, caller_client_id, caller_credential_id, idempotency_key,
			request_hash, owner_id, plan_id, approval_id, connection_id, task_step_id, deployment_id,
			task_id, state, operation_json, redacted_error, revision, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,$13,$14,NULL,$15,$16,$17)`,
		intent.OperationID, store.instanceID, intent.Caller.ClientID, intent.Caller.CredentialID,
		intent.Launch.IdempotencyKey, intent.RequestHash[:], intent.Launch.OwnerID, intent.Launch.PlanID,
		intent.Launch.ApprovalID, intent.ConnectionID, intent.TaskStepID, intent.DeploymentID,
		initial.State, encoded, initial.Revision, initial.CreatedAt, initial.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return cloudexecution.Operation{}, false, cloudexecution.ErrRevisionConflict
		}
		return cloudexecution.Operation{}, false, cloudexecution.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudexecution.Operation{}, false, cloudexecution.ErrUnavailable
	}
	return initial, true, nil
}

func (store *Store) Save(ctx context.Context, next cloudexecution.Operation, expectedRevision int64) (cloudexecution.Operation, error) {
	if store == nil || store.pool == nil || expectedRevision < 1 {
		return cloudexecution.Operation{}, cloudexecution.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readCloudLaunch(ctx, tx, ` WHERE operation_id=$1 FOR UPDATE`, next.OperationID)
	if err != nil {
		return cloudexecution.Operation{}, err
	}
	if current.Revision != expectedRevision || !sameLaunchIntent(current.Intent, next.Intent) || !validLaunchTransition(current, next) {
		return cloudexecution.Operation{}, cloudexecution.ErrRevisionConflict
	}
	next.Revision = expectedRevision + 1
	if next.CreatedAt.IsZero() {
		next.CreatedAt = current.CreatedAt
	}
	if next.UpdatedAt.Before(current.UpdatedAt) {
		return cloudexecution.Operation{}, cloudexecution.ErrRevisionConflict
	}
	if err := validateLaunchOperation(next); err != nil {
		return cloudexecution.Operation{}, err
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrInvalid
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_launch_operations SET
		task_id=$4, state=$5, operation_json=$6, redacted_error=$7, revision=$8, updated_at=$9
		WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=$3`,
		next.OperationID, store.instanceID, expectedRevision, nullableUUID(next.TaskID), next.State,
		encoded, nullableLaunchString(next.RedactedError), next.Revision, next.UpdatedAt.UTC(),
	)
	if err != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return cloudexecution.Operation{}, cloudexecution.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	return next, nil
}

func (store *Store) GetByPlan(ctx context.Context, ownerID, planID string) (cloudexecution.Operation, error) {
	if store == nil || store.pool == nil || strings.TrimSpace(ownerID) == "" {
		return cloudexecution.Operation{}, cloudexecution.ErrInvalid
	}
	if parsed, err := uuid.Parse(strings.TrimSpace(planID)); err != nil || parsed == uuid.Nil {
		return cloudexecution.Operation{}, cloudexecution.ErrInvalid
	}
	return readCloudLaunch(ctx, store.pool, ` WHERE owner_id=$1 AND plan_id=$2`, ownerID, planID)
}

func (store *Store) GetByDeployment(ctx context.Context, deploymentID string) (cloudexecution.Operation, error) {
	if store == nil || store.pool == nil {
		return cloudexecution.Operation{}, cloudexecution.ErrInvalid
	}
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil {
		return cloudexecution.Operation{}, cloudexecution.ErrInvalid
	}
	return readCloudLaunch(ctx, store.pool, ` WHERE agent_instance_id=$1 AND deployment_id=$2`, store.instanceID, parsed)
}

func (store *Store) ListRecoverable(ctx context.Context, limit int) ([]cloudexecution.Operation, error) {
	if store == nil || store.pool == nil || limit < 1 || limit > 256 {
		return nil, cloudexecution.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `SELECT `+cloudLaunchColumns+` FROM cloud_launch_operations
		WHERE agent_instance_id=$1 AND state IN ('intent','task_ready','bundles_ready','worker_registered','bootstrap_ready','provisioning','failed_retriable')
		ORDER BY updated_at, operation_id LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, cloudexecution.ErrUnavailable
	}
	defer rows.Close()
	result := make([]cloudexecution.Operation, 0, limit)
	for rows.Next() {
		value, scanErr := scanCloudLaunchRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, value)
	}
	if rows.Err() != nil {
		return nil, cloudexecution.ErrUnavailable
	}
	return result, nil
}

func (store *Store) LoadConnection(ctx context.Context, ownerID, connectionID string) (cloudappConnection cloudapp.Connection, err error) {
	if store == nil || store.pool == nil || strings.TrimSpace(ownerID) == "" {
		return cloudappConnection, cloudexecution.ErrInvalid
	}
	parsed, parseErr := uuid.Parse(strings.TrimSpace(connectionID))
	if parseErr != nil || parsed == uuid.Nil {
		return cloudappConnection, cloudexecution.ErrInvalid
	}
	value, readErr := readCloudConnection(ctx, store.pool, parsed.String())
	if readErr != nil {
		if errors.Is(readErr, cloudapp.ErrNotFound) {
			return cloudappConnection, cloudexecution.ErrNotReady
		}
		return cloudappConnection, cloudexecution.ErrUnavailable
	}
	if value.OwnerID != strings.TrimSpace(ownerID) {
		return cloudappConnection, cloudexecution.ErrNotReady
	}
	return value, nil
}

type launchRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readCloudLaunch(ctx context.Context, query launchRowQuerier, suffix string, args ...any) (cloudexecution.Operation, error) {
	return scanCloudLaunchRow(query.QueryRow(ctx, `SELECT `+cloudLaunchColumns+` FROM cloud_launch_operations`+suffix, args...))
}

type cloudLaunchRow interface{ Scan(...any) error }

func scanCloudLaunchRow(row cloudLaunchRow) (cloudexecution.Operation, error) {
	var operationID, callerCredentialID, idempotencyKey, planID, approvalID, connectionID, taskStepID, deploymentID uuid.UUID
	var taskID *uuid.UUID
	var callerClientID, ownerID string
	var requestHash, operationJSON []byte
	var state cloudexecution.State
	var redactedError *string
	var revision int64
	var createdAt, updatedAt time.Time
	err := row.Scan(
		&operationID, &callerClientID, &callerCredentialID, &idempotencyKey, &requestHash,
		&ownerID, &planID, &approvalID, &connectionID, &taskStepID, &deploymentID,
		&taskID, &state, &operationJSON, &redactedError, &revision, &createdAt, &updatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return cloudexecution.Operation{}, cloudexecution.ErrNotReady
	}
	if err != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	var value cloudexecution.Operation
	if len(requestHash) != 32 || json.Unmarshal(operationJSON, &value) != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	var digest [32]byte
	copy(digest[:], requestHash)
	if value.OperationID != operationID.String() || value.Caller.ClientID != callerClientID || value.Caller.CredentialID != callerCredentialID.String() ||
		value.Launch.IdempotencyKey != idempotencyKey.String() || subtle.ConstantTimeCompare(value.RequestHash[:], digest[:]) != 1 ||
		value.Launch.OwnerID != ownerID || value.Launch.PlanID != planID.String() || value.Launch.ApprovalID != approvalID.String() ||
		value.ConnectionID != connectionID.String() || value.TaskStepID != taskStepID.String() || value.DeploymentID != deploymentID.String() ||
		value.State != state || value.Revision != revision || !value.CreatedAt.Equal(createdAt.UTC()) || !value.UpdatedAt.Equal(updatedAt.UTC()) ||
		(taskID == nil && value.TaskID != "") || (taskID != nil && value.TaskID != taskID.String()) ||
		(redactedError == nil && value.RedactedError != "") || (redactedError != nil && value.RedactedError != *redactedError) {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	if err := validateLaunchOperation(value); err != nil {
		return cloudexecution.Operation{}, cloudexecution.ErrUnavailable
	}
	return value, nil
}

func validateLaunchIntent(value cloudexecution.Intent) error {
	for _, identifier := range []string{value.OperationID, value.Caller.CredentialID, value.Launch.IdempotencyKey, value.Launch.PlanID, value.Launch.ApprovalID, value.ConnectionID, value.TaskStepID, value.DeploymentID} {
		parsed, err := uuid.Parse(strings.TrimSpace(identifier))
		if err != nil || parsed == uuid.Nil {
			return cloudexecution.ErrInvalid
		}
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(value.RequestHash[:], zero[:]) == 1 || strings.TrimSpace(value.Caller.ClientID) == "" || strings.TrimSpace(value.Launch.OwnerID) == "" || value.RecordedAt.IsZero() || !strings.HasPrefix(value.ApprovedPlanHash, "sha256:") || len(value.ApprovedPlanHash) != 71 {
		return cloudexecution.ErrInvalid
	}
	return nil
}

func validateLaunchOperation(value cloudexecution.Operation) error {
	if validateLaunchIntent(value.Intent) != nil || value.Revision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || len(value.RedactedError) > 512 || security.ContainsLikelySecret(value.RedactedError) {
		return cloudexecution.ErrInvalid
	}
	if cloudexecution.ValidateInstallerOperation(value) != nil {
		return cloudexecution.ErrInvalid
	}
	if value.State != cloudexecution.StateIntent && value.State != cloudexecution.StateFailedRetriable && value.TaskID == "" {
		return cloudexecution.ErrInvalid
	}
	if value.TaskID != "" {
		if parsed, err := uuid.Parse(value.TaskID); err != nil || parsed == uuid.Nil {
			return cloudexecution.ErrInvalid
		}
	}
	if value.State == cloudexecution.StateActive && len(value.ResourceIDs) == 0 {
		return cloudexecution.ErrInvalid
	}
	for _, resourceID := range value.ResourceIDs {
		if parsed, err := uuid.Parse(resourceID); err != nil || parsed == uuid.Nil {
			return cloudexecution.ErrInvalid
		}
	}
	return nil
}

func validLaunchTransition(current, next cloudexecution.Operation) bool {
	if current.InstallerDelivery != nil && (!reflect.DeepEqual(current.InstallerDelivery, next.InstallerDelivery) ||
		!slices.Equal(current.InstallerCommandIDs, next.InstallerCommandIDs) || !reflect.DeepEqual(current.InstallerRootTrust, next.InstallerRootTrust)) {
		return false
	}
	if len(current.InstallerSecrets) != 0 && !reflect.DeepEqual(current.InstallerSecrets, next.InstallerSecrets) {
		return false
	}
	if current.State == cloudexecution.StateActive || current.State == cloudexecution.StateDestroyBlocked {
		return current.State == next.State && bytes.Equal(current.RequestHash[:], next.RequestHash[:])
	}
	if next.State == cloudexecution.StateFailedRetriable || next.State == cloudexecution.StateDestroyBlocked {
		return true
	}
	rank := map[cloudexecution.State]int{
		cloudexecution.StateIntent: 0, cloudexecution.StateTaskReady: 1, cloudexecution.StateBundlesReady: 2,
		cloudexecution.StateWorkerRegistered: 3, cloudexecution.StateBootstrapReady: 4,
		cloudexecution.StateProvisioning: 5, cloudexecution.StateActive: 6,
	}
	if current.State == cloudexecution.StateFailedRetriable {
		return rank[next.State] > 0
	}
	return rank[next.State] >= rank[current.State]
}

func sameLaunchIntent(left, right cloudexecution.Intent) bool {
	// SecretClientID records the original service identity solely so the
	// internal recovery dispatcher can reopen that service's encrypted
	// bootstrap session. Recovery recomputes the intent under the stable
	// internal launcher identity, so this auxiliary authorization coordinate is
	// deliberately not part of provider/idempotency intent equality.
	return left.OperationID == right.OperationID && left.Caller == right.Caller && left.Launch == right.Launch &&
		left.ConnectionID == right.ConnectionID && left.ApprovedPlanHash == right.ApprovedPlanHash && left.TaskStepID == right.TaskStepID && left.DeploymentID == right.DeploymentID &&
		subtle.ConstantTimeCompare(left.RequestHash[:], right.RequestHash[:]) == 1
}

func nullableLaunchString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
