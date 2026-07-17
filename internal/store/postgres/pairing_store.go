package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type PairingStore struct{ base *Store }

func (store *Store) Pairing() *PairingStore { return &PairingStore{base: store} }

func (store *PairingStore) Create(ctx context.Context, mutation pairing.Mutation, expectedRevision int64, value pairing.SessionV1) (pairing.SessionV1, error) {
	if ctx == nil || mutation.Validate() != nil || expectedRevision != 0 || value.Validate() != nil ||
		value.OwnerID != mutation.OwnerID || value.Revision != 1 || value.Status != pairing.StatusWaitingPayload {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	tx, err := store.base.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return pairing.SessionV1{}, fmt.Errorf("begin pairing create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, replayErr := readPairingReplay(ctx, tx, store, mutation, "create"); replayErr != nil {
		return pairing.SessionV1{}, replayErr
	} else if found {
		return replay, tx.Commit(ctx)
	}
	if err := validatePairingBindings(ctx, tx, store, value); err != nil {
		return pairing.SessionV1{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pairing_sessions
		(session_id,agent_instance_id,owner_id,deployment_id,deployment_revision,plan_id,connection_id,task_id,step_id,recipe_id,recipe_digest,recipe_revision,
		 execution_manifest_digest,begin_command,resume_command,status,expires_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,1,$18,$18)
		ON CONFLICT (session_id) DO NOTHING`,
		value.SessionID, store.base.instanceID, value.OwnerID, value.DeploymentID, value.DeploymentRevision, value.PlanID, value.ConnectionID,
		value.TaskID, value.StepID, value.RecipeID, value.RecipeDigest, value.RecipeRevision,
		value.ExecutionManifestDigest, value.BeginCommand, value.ResumeCommand,
		value.Status, value.ExpiresAt.UTC(), value.CreatedAt.UTC())
	if err != nil {
		return pairing.SessionV1{}, fmt.Errorf("persist pairing session: %w", err)
	}
	stored, err := readPairing(ctx, tx, store, mutation.OwnerID, value.SessionID, true)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if !sameCreatedPairing(stored, value) {
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if err := insertPairingReplay(ctx, tx, store, mutation, "create", stored, value.CreatedAt); err != nil {
		return pairing.SessionV1{}, err
	}
	replayed, found, err := readPairingReplay(ctx, tx, store, mutation, "create")
	if err != nil || !found || replayed.SessionID != value.SessionID || replayed.Revision != stored.Revision {
		if err != nil {
			return pairing.SessionV1{}, err
		}
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return pairing.SessionV1{}, fmt.Errorf("commit pairing create: %w", err)
	}
	return stored, nil
}

func (store *PairingStore) Get(ctx context.Context, ownerID, sessionID string) (pairing.SessionV1, error) {
	if ctx == nil || pairing.ValidateLookup(ownerID, sessionID) != nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	return readPairing(ctx, store.base.pool, store, ownerID, sessionID, false)
}

// ReservePayload durably fences the first recipient/scope before any Worker
// dispatch.  A session row lock serializes contenders: the first recipient
// wins, an exact retry receives the same reservation, and a different
// recipient is rejected before it can ask the Worker/root-helper for a new
// envelope.
func (store *PairingStore) ReservePayload(ctx context.Context, mutation pairing.Mutation, sessionID string,
	expectedRevision int64, recipientKeyDigest, operationID string, at time.Time,
) (pairing.SessionV1, pairing.PayloadReservationV1, bool, error) {
	reservation := pairing.PayloadReservationV1{
		SessionID: sessionID, OwnerID: mutation.OwnerID, PayloadScopeRevision: expectedRevision,
		RecipientKeyDigest: recipientKeyDigest, OperationID: operationID, CreatedAt: at.UTC(),
	}
	if ctx == nil || mutation.Validate() != nil || expectedRevision < 1 || at.IsZero() || reservation.Validate() != nil {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, pairing.ErrInvalid
	}
	tx, err := store.base.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, fmt.Errorf("begin pairing payload reservation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readPairing(ctx, tx, store, mutation.OwnerID, sessionID, true)
	if err != nil {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, err
	}
	if current.Envelope != nil {
		if current.RecipientKeyDigest != recipientKeyDigest || current.PayloadScopeRevision != expectedRevision {
			return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, pairing.ErrRevisionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, fmt.Errorf("commit pairing payload replay: %w", err)
		}
		return current, pairing.PayloadReservationV1{}, false, nil
	}
	if current.Status != pairing.StatusWaitingPayload || current.Revision != expectedRevision || !at.Before(current.ExpiresAt) {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, pairing.ErrRevisionConflict
	}
	if existing, found, readErr := readPairingPayloadReservation(ctx, tx, store, mutation.OwnerID, sessionID, true); readErr != nil {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, readErr
	} else if found {
		if existing.PayloadScopeRevision != expectedRevision || existing.RecipientKeyDigest != recipientKeyDigest || existing.OperationID != operationID {
			return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, pairing.ErrRevisionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, fmt.Errorf("commit pairing payload reservation replay: %w", err)
		}
		return current, existing, false, nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO pairing_payload_reservations
		(session_id,agent_instance_id,owner_id,payload_scope_revision,recipient_key_digest,operation_id,created_at)
		SELECT $1,$2,$3,$4,$5,$6,$7
		WHERE EXISTS (
			SELECT 1 FROM pairing_sessions
			WHERE agent_instance_id=$2 AND owner_id=$3 AND session_id=$1
			  AND status='waiting_payload' AND revision=$4
			  AND expires_at>$7 AND expires_at>clock_timestamp()
		)
		ON CONFLICT (session_id) DO NOTHING`,
		reservation.SessionID, store.base.instanceID, reservation.OwnerID, reservation.PayloadScopeRevision,
		reservation.RecipientKeyDigest, reservation.OperationID, reservation.CreatedAt)
	if err != nil {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, fmt.Errorf("persist pairing payload reservation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, pairing.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return pairing.SessionV1{}, pairing.PayloadReservationV1{}, false, fmt.Errorf("commit pairing payload reservation: %w", err)
	}
	return current, reservation, true, nil
}

func (store *PairingStore) RecordEnvelope(ctx context.Context, mutation pairing.Mutation, sessionID string, expectedRevision int64,
	recipientKeyDigest, operationID string, envelope secretbootstrap.RecipientEnvelopeV1, associatedDataCBOR []byte, payloadDigest string, at time.Time,
) (pairing.SessionV1, error) {
	reservation := pairing.PayloadReservationV1{SessionID: sessionID, OwnerID: mutation.OwnerID,
		PayloadScopeRevision: expectedRevision, RecipientKeyDigest: recipientKeyDigest, OperationID: operationID, CreatedAt: at.UTC()}
	if mutation.Validate() != nil || at.IsZero() || reservation.Validate() != nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	return store.mutatePairing(ctx, mutation, "record_envelope", sessionID, expectedRevision, at, func(tx pgx.Tx, current pairing.SessionV1) error {
		nextStatus, transitionErr := pairing.RecordEnvelopeStatus(current.Status)
		if transitionErr != nil {
			return transitionErr
		}
		storedReservation, found, reservationErr := readPairingPayloadReservation(ctx, tx, store, mutation.OwnerID, sessionID, true)
		if reservationErr != nil {
			return reservationErr
		}
		if !found || storedReservation.PayloadScopeRevision != expectedRevision ||
			storedReservation.RecipientKeyDigest != recipientKeyDigest || storedReservation.OperationID != operationID {
			return pairing.ErrRevisionConflict
		}
		candidate := current
		candidate.Status, candidate.RecipientKeyDigest, candidate.Envelope, candidate.PayloadDigest =
			nextStatus, recipientKeyDigest, &envelope, payloadDigest
		candidate.AssociatedDataCBOR = append([]byte(nil), associatedDataCBOR...)
		candidate.PayloadScopeRevision = expectedRevision
		candidate.Revision, candidate.UpdatedAt = expectedRevision+1, at.UTC()
		if candidate.Validate() != nil || !at.Before(current.ExpiresAt) {
			return pairing.ErrRevisionConflict
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE pairing_sessions SET
			status=$5,recipient_key_digest=$6,recipient_envelope=$7,associated_data_cbor=$8,
			payload_digest=$9,payload_scope_revision=$4,revision=revision+1,updated_at=$10
			WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3 AND revision=$4
			  AND status='waiting_payload' AND expires_at>$10 AND expires_at>clock_timestamp()`,
			store.base.instanceID, mutation.OwnerID, sessionID, expectedRevision, nextStatus, recipientKeyDigest, encoded,
			associatedDataCBOR, payloadDigest, at.UTC())
		if updateErr != nil {
			return fmt.Errorf("record pairing envelope: %w", updateErr)
		}
		if tag.RowsAffected() != 1 {
			return pairing.ErrRevisionConflict
		}
		deleted, deleteErr := tx.Exec(ctx, `DELETE FROM pairing_payload_reservations
			WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3
			  AND payload_scope_revision=$4 AND recipient_key_digest=$5 AND operation_id=$6`,
			store.base.instanceID, mutation.OwnerID, sessionID, expectedRevision, recipientKeyDigest, operationID)
		if deleteErr != nil {
			return fmt.Errorf("clear pairing payload reservation: %w", deleteErr)
		}
		if deleted.RowsAffected() != 1 {
			return pairing.ErrRevisionConflict
		}
		return nil
	})
}

// Expire is deliberately independent of client idempotency.  Any observer
// that sees an expired non-terminal session may win this one-way transition;
// the transaction clears the durable dispatch reservation and all encrypted
// material together.
func (store *PairingStore) Expire(ctx context.Context, ownerID, sessionID string, at time.Time) (pairing.SessionV1, error) {
	if ctx == nil || pairing.ValidateLookup(ownerID, sessionID) != nil || at.IsZero() {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	tx, err := store.base.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return pairing.SessionV1{}, fmt.Errorf("begin pairing expiry: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readPairing(ctx, tx, store, ownerID, sessionID, true)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if at.Before(current.ExpiresAt) {
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if !pairing.IsTerminal(current.Status) {
		completedAt := at.UTC()
		candidate := current
		candidate.Status, candidate.RecipientKeyDigest, candidate.Envelope, candidate.AssociatedDataCBOR = pairing.StatusTimedOut, "", nil, nil
		candidate.PayloadDigest, candidate.PayloadScopeRevision = "", 0
		candidate.FailureCode, candidate.CompletedAt = "pairing_timed_out", &completedAt
		candidate.Revision, candidate.UpdatedAt = current.Revision+1, completedAt
		if candidate.Validate() != nil {
			return pairing.SessionV1{}, pairing.ErrInvalid
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE pairing_sessions SET
			status='timed_out',recipient_key_digest=NULL,recipient_envelope=NULL,associated_data_cbor=NULL,
			payload_digest=NULL,payload_scope_revision=NULL,failure_code='pairing_timed_out',completed_at=$5,
			revision=revision+1,updated_at=$5
			WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3 AND revision=$4
			  AND status NOT IN ('succeeded','timed_out','failed') AND expires_at<=$5`,
			store.base.instanceID, ownerID, sessionID, current.Revision, completedAt)
		if updateErr != nil {
			return pairing.SessionV1{}, fmt.Errorf("expire pairing session: %w", updateErr)
		}
		if tag.RowsAffected() != 1 {
			return pairing.SessionV1{}, pairing.ErrRevisionConflict
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM pairing_payload_reservations
		WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3`, store.base.instanceID, ownerID, sessionID); err != nil {
		return pairing.SessionV1{}, fmt.Errorf("clear expired pairing reservation: %w", err)
	}
	result, err := readPairing(ctx, tx, store, ownerID, sessionID, false)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return pairing.SessionV1{}, fmt.Errorf("commit pairing expiry: %w", err)
	}
	return result, nil
}

func (store *PairingStore) BeginResume(ctx context.Context, mutation pairing.Mutation, sessionID string, expectedRevision int64, at time.Time) (pairing.SessionV1, error) {
	if mutation.Validate() != nil || at.IsZero() {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	return store.mutatePairing(ctx, mutation, "begin_resume", sessionID, expectedRevision, at, func(tx pgx.Tx, current pairing.SessionV1) error {
		if !pairing.CanBeginResume(current.Status) || !at.Before(current.ExpiresAt) {
			return pairing.ErrRevisionConflict
		}
		tag, err := tx.Exec(ctx, `UPDATE pairing_sessions SET status='resuming',resume_started_at=$5,
			revision=revision+1,updated_at=$5 WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3 AND revision=$4
			  AND status IN ('payload_ready','waiting_user') AND expires_at>$5 AND expires_at>clock_timestamp()`,
			store.base.instanceID, mutation.OwnerID, sessionID, expectedRevision, at.UTC())
		if err != nil {
			return fmt.Errorf("begin pairing resume: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return pairing.ErrRevisionConflict
		}
		return nil
	})
}

func (store *PairingStore) CompleteResume(ctx context.Context, mutation pairing.Mutation, sessionID string, expectedRevision int64,
	status pairing.Status, failureCode string, at time.Time,
) (pairing.SessionV1, error) {
	if mutation.Validate() != nil || !pairing.CanCompleteResume(status) || at.IsZero() {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	return store.mutatePairing(ctx, mutation, "complete_resume", sessionID, expectedRevision, at, func(tx pgx.Tx, current pairing.SessionV1) error {
		if pairing.CanCompleteResume(current.Status) {
			return pairing.ErrRevisionConflict
		}
		if status != pairing.StatusTimedOut && current.Status != pairing.StatusResuming {
			return pairing.ErrRevisionConflict
		}
		if status == pairing.StatusSucceeded {
			failureCode = ""
		} else if failureCode == "" {
			return pairing.ErrInvalid
		}
		if status == pairing.StatusTimedOut && at.Before(current.ExpiresAt) || status != pairing.StatusTimedOut && !at.Before(current.ExpiresAt) {
			return pairing.ErrRevisionConflict
		}
		candidate := current
		completedAt := at.UTC()
		candidate.Status, candidate.FailureCode, candidate.CompletedAt = status, failureCode, &completedAt
		candidate.Revision, candidate.UpdatedAt = current.Revision+1, completedAt
		if status == pairing.StatusTimedOut {
			candidate.RecipientKeyDigest, candidate.Envelope, candidate.AssociatedDataCBOR = "", nil, nil
			candidate.PayloadDigest, candidate.PayloadScopeRevision = "", 0
		}
		if candidate.Validate() != nil {
			return pairing.ErrInvalid
		}
		var tag pgconn.CommandTag
		var err error
		if status == pairing.StatusTimedOut {
			tag, err = tx.Exec(ctx, `UPDATE pairing_sessions SET status=$5,failure_code=$6,
				recipient_key_digest=NULL,recipient_envelope=NULL,associated_data_cbor=NULL,payload_digest=NULL,payload_scope_revision=NULL,
				completed_at=$7,revision=revision+1,updated_at=$7
				WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3 AND revision=$4
				  AND status='resuming' AND expires_at<=$7`,
				store.base.instanceID, mutation.OwnerID, sessionID, expectedRevision, status, failureCode, completedAt)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE pairing_sessions SET status=$5,failure_code=NULLIF($6,''),
				completed_at=$7,revision=revision+1,updated_at=$7
				WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3 AND revision=$4
				  AND status='resuming' AND expires_at>$7 AND expires_at>clock_timestamp()`,
				store.base.instanceID, mutation.OwnerID, sessionID, expectedRevision, status, failureCode, completedAt)
		}
		if err != nil {
			return fmt.Errorf("complete pairing resume: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return pairing.ErrRevisionConflict
		}
		return nil
	})
}

type pairingMutation func(pgx.Tx, pairing.SessionV1) error

func (store *PairingStore) mutatePairing(ctx context.Context, mutation pairing.Mutation, operation, sessionID string,
	expectedRevision int64, at time.Time, apply pairingMutation,
) (pairing.SessionV1, error) {
	if ctx == nil || expectedRevision < 1 {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	tx, err := store.base.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return pairing.SessionV1{}, fmt.Errorf("begin pairing mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, replayErr := readPairingReplay(ctx, tx, store, mutation, operation); replayErr != nil {
		return pairing.SessionV1{}, replayErr
	} else if found {
		return replay, tx.Commit(ctx)
	}
	current, err := readPairing(ctx, tx, store, mutation.OwnerID, sessionID, true)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if replay, found, replayErr := readPairingReplay(ctx, tx, store, mutation, operation); replayErr != nil {
		return pairing.SessionV1{}, replayErr
	} else if found {
		return replay, tx.Commit(ctx)
	}
	if current.Revision != expectedRevision {
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if err := apply(tx, current); err != nil {
		return pairing.SessionV1{}, err
	}
	result, err := readPairing(ctx, tx, store, mutation.OwnerID, sessionID, false)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if result.Validate() != nil || result.Revision != expectedRevision+1 {
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if err := insertPairingReplay(ctx, tx, store, mutation, operation, result, at); err != nil {
		return pairing.SessionV1{}, err
	}
	replay, found, err := readPairingReplay(ctx, tx, store, mutation, operation)
	if err != nil || !found || replay.SessionID != sessionID || replay.Revision != result.Revision {
		if err != nil {
			return pairing.SessionV1{}, err
		}
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return pairing.SessionV1{}, fmt.Errorf("commit pairing mutation: %w", err)
	}
	return result, nil
}

type pairingQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

const validatePairingBindingsSQL = `SELECT EXISTS(
		SELECT 1
		FROM worker_deployments d
		JOIN cloud_launch_operations l ON l.deployment_id=d.deployment_id
		JOIN cloud_plans p ON p.plan_id=l.plan_id
		JOIN cloud_connections c ON c.connection_id=l.connection_id
		JOIN task_steps s ON s.task_id=$6 AND s.step_id=$7
		JOIN tasks t ON t.task_id=s.task_id
		WHERE d.deployment_id=$3
		  AND d.agent_instance_id=$1 AND d.owner_id=$2 AND d.task_id=$6 AND d.step_id=$7
		  AND d.revision=$8
		  AND l.agent_instance_id=$1 AND l.owner_id=$2 AND l.plan_id=$4 AND l.connection_id=$5
		  AND l.task_id=$6 AND l.task_step_id=$7
		  AND p.agent_instance_id=$1 AND p.owner_id=$2 AND p.plan_id=$4 AND p.connection_id=$5::text
		  AND c.agent_instance_id=$1 AND c.owner_id=$2 AND c.connection_id=$5
		  AND t.owner_id=$2
	)`

func validatePairingBindings(ctx context.Context, query pairingQuery, store *PairingStore, value pairing.SessionV1) error {
	var valid bool
	err := query.QueryRow(ctx, validatePairingBindingsSQL, store.base.instanceID, value.OwnerID, value.DeploymentID, value.PlanID, value.ConnectionID,
		value.TaskID, value.StepID, value.DeploymentRevision).Scan(&valid)
	if err != nil {
		return fmt.Errorf("verify pairing bindings: %w", err)
	}
	if !valid {
		return pairing.ErrRevisionConflict
	}
	return nil
}

func readPairing(ctx context.Context, query pairingQuery, store *PairingStore, ownerID, sessionID string, lock bool) (pairing.SessionV1, error) {
	if ctx == nil || pairing.ValidateLookup(ownerID, sessionID) != nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var value pairing.SessionV1
	var envelope, associatedDataCBOR []byte
	var recipientDigest, payloadDigest, failureCode *string
	var payloadScopeRevision *int64
	err := query.QueryRow(ctx, `SELECT session_id,owner_id,deployment_id,deployment_revision,plan_id,connection_id,task_id,step_id,recipe_id,recipe_digest,
		recipe_revision,execution_manifest_digest,begin_command,resume_command,status,recipient_key_digest,recipient_envelope,
		associated_data_cbor,payload_digest,payload_scope_revision,
		expires_at,revision,created_at,updated_at,resume_started_at,completed_at,failure_code
		FROM pairing_sessions WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3`+suffix,
		store.base.instanceID, ownerID, sessionID).Scan(
		&value.SessionID, &value.OwnerID, &value.DeploymentID, &value.DeploymentRevision, &value.PlanID, &value.ConnectionID,
		&value.TaskID, &value.StepID, &value.RecipeID, &value.RecipeDigest, &value.RecipeRevision,
		&value.ExecutionManifestDigest, &value.BeginCommand, &value.ResumeCommand, &value.Status,
		&recipientDigest, &envelope, &associatedDataCBOR, &payloadDigest, &payloadScopeRevision,
		&value.ExpiresAt, &value.Revision, &value.CreatedAt,
		&value.UpdatedAt, &value.ResumeStartedAt, &value.CompletedAt, &failureCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return pairing.SessionV1{}, pairing.ErrNotFound
	}
	if err != nil {
		return pairing.SessionV1{}, fmt.Errorf("read pairing session: %w", err)
	}
	value.SchemaVersion = pairing.SchemaV1
	if recipientDigest != nil {
		value.RecipientKeyDigest = *recipientDigest
	}
	if payloadDigest != nil {
		value.PayloadDigest = *payloadDigest
	}
	value.AssociatedDataCBOR = append([]byte(nil), associatedDataCBOR...)
	if payloadScopeRevision != nil {
		value.PayloadScopeRevision = *payloadScopeRevision
	}
	if failureCode != nil {
		value.FailureCode = *failureCode
	}
	if len(envelope) != 0 {
		var decoded secretbootstrap.RecipientEnvelopeV1
		if json.Unmarshal(envelope, &decoded) != nil {
			return pairing.SessionV1{}, pairing.ErrInvalid
		}
		value.Envelope = &decoded
	}
	if value.Validate() != nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	return value, nil
}

func readPairingPayloadReservation(ctx context.Context, query pairingQuery, store *PairingStore,
	ownerID, sessionID string, lock bool,
) (pairing.PayloadReservationV1, bool, error) {
	if ctx == nil || pairing.ValidateLookup(ownerID, sessionID) != nil {
		return pairing.PayloadReservationV1{}, false, pairing.ErrInvalid
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var value pairing.PayloadReservationV1
	err := query.QueryRow(ctx, `SELECT session_id,owner_id,payload_scope_revision,recipient_key_digest,operation_id,created_at
		FROM pairing_payload_reservations
		WHERE agent_instance_id=$1 AND owner_id=$2 AND session_id=$3`+suffix,
		store.base.instanceID, ownerID, sessionID).Scan(
		&value.SessionID, &value.OwnerID, &value.PayloadScopeRevision, &value.RecipientKeyDigest, &value.OperationID, &value.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return pairing.PayloadReservationV1{}, false, nil
	}
	if err != nil {
		return pairing.PayloadReservationV1{}, false, fmt.Errorf("read pairing payload reservation: %w", err)
	}
	if value.Validate() != nil || value.OwnerID != ownerID || value.SessionID != sessionID {
		return pairing.PayloadReservationV1{}, false, pairing.ErrInvalid
	}
	return value, true, nil
}

func readPairingReplay(ctx context.Context, query pairingQuery, store *PairingStore, mutation pairing.Mutation, operation string) (pairing.SessionV1, bool, error) {
	var sessionID, requestDigest string
	var resultRevision int64
	var encoded []byte
	err := query.QueryRow(ctx, `SELECT session_id,request_digest,result_revision,result_json FROM pairing_mutation_replays
		WHERE agent_instance_id=$1 AND owner_id=$2 AND operation=$3 AND idempotency_key=$4`,
		store.base.instanceID, mutation.OwnerID, operation, mutation.IdempotencyKey).Scan(&sessionID, &requestDigest, &resultRevision, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return pairing.SessionV1{}, false, nil
	}
	if err != nil {
		return pairing.SessionV1{}, false, fmt.Errorf("read pairing replay: %w", err)
	}
	if requestDigest != mutation.RequestDigest {
		return pairing.SessionV1{}, false, pairing.ErrRevisionConflict
	}
	var value pairing.SessionV1
	if json.Unmarshal(encoded, &value) != nil || value.Validate() != nil ||
		value.OwnerID != mutation.OwnerID || value.SessionID != sessionID || value.Revision != resultRevision {
		return pairing.SessionV1{}, false, pairing.ErrRevisionConflict
	}
	return value, true, nil
}

func insertPairingReplay(ctx context.Context, tx pgx.Tx, store *PairingStore, mutation pairing.Mutation, operation string, result pairing.SessionV1, at time.Time) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return pairing.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO pairing_mutation_replays
		(agent_instance_id,owner_id,operation,idempotency_key,request_digest,session_id,result_revision,result_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
		store.base.instanceID, mutation.OwnerID, operation, mutation.IdempotencyKey, mutation.RequestDigest,
		result.SessionID, result.Revision, encoded, at.UTC())
	if err != nil {
		return fmt.Errorf("persist pairing replay: %w", err)
	}
	return nil
}

func sameCreatedPairing(stored, expected pairing.SessionV1) bool {
	expected.CreatedAt, expected.UpdatedAt = expected.CreatedAt.UTC(), expected.CreatedAt.UTC()
	expected.ExpiresAt = expected.ExpiresAt.UTC()
	return reflect.DeepEqual(stored, expected)
}

var _ pairing.Repository = (*PairingStore)(nil)
