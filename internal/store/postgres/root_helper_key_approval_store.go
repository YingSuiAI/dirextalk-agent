package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/jackc/pgx/v5"
)

func (store *RootHelperKeyStore) CreateApprovalIdempotent(ctx context.Context, value helperkey.ApprovalChallenge, mutation helperkey.ApprovalMutation) (helperkey.ApprovalChallenge, error) {
	if value.Validate() != nil || value.Binding.AgentInstanceID != store.instanceID.String() || mutation.ExpectedRevision != 0 {
		return helperkey.ApprovalChallenge{}, helperkey.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, err := readHelperApprovalReplay(ctx, tx, value.Binding.DeliveryID, "prepare", mutation); err != nil {
		return helperkey.ApprovalChallenge{}, err
	} else if found {
		if tx.Commit(ctx) != nil {
			return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
		}
		return replay, nil
	}
	raw, _ := json.Marshal(value)
	tag, err := tx.Exec(ctx, `INSERT INTO root_helper_key_delivery_approvals
		(delivery_id,challenge_id,agent_instance_id,owner_id,device_signer_key_id,status,revision,
		 public_key,nonce,signing_payload_cbor,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING`,
		value.Binding.DeliveryID, value.ChallengeID, store.instanceID, value.Binding.OwnerID, value.DeviceSignerKeyID,
		value.Status, value.Revision, value.PublicKey, value.Nonce, value.SigningPayloadCBOR, raw, value.CreatedAt, value.UpdatedAt)
	if err != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		replay, found, replayErr := readHelperApprovalReplay(ctx, tx, value.Binding.DeliveryID, "prepare", mutation)
		if replayErr != nil || !found {
			return helperkey.ApprovalChallenge{}, helperkey.ErrConflict
		}
		if tx.Commit(ctx) != nil {
			return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
		}
		return replay, nil
	}
	if err := insertHelperApprovalReplay(ctx, tx, value.Binding.DeliveryID, "prepare", mutation, value); err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	if tx.Commit(ctx) != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
	}
	return value.Clone(), nil
}

func (store *RootHelperKeyStore) GetApproval(ctx context.Context, deliveryID string) (helperkey.ApprovalChallenge, error) {
	return scanHelperApproval(store.pool.QueryRow(ctx, `SELECT snapshot_json FROM root_helper_key_delivery_approvals
		WHERE delivery_id=$1 AND agent_instance_id=$2`, deliveryID, store.instanceID))
}

func (store *RootHelperKeyStore) ApproveIdempotent(ctx context.Context, deliveryID string, mutation helperkey.ApprovalMutation, update func(*helperkey.ApprovalChallenge) error) (helperkey.ApprovalChallenge, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, err := readHelperApprovalReplay(ctx, tx, deliveryID, "approve", mutation); err != nil {
		return helperkey.ApprovalChallenge{}, err
	} else if found {
		if tx.Commit(ctx) != nil {
			return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
		}
		return replay, nil
	}
	current, err := scanHelperApproval(tx.QueryRow(ctx, `SELECT snapshot_json FROM root_helper_key_delivery_approvals
		WHERE delivery_id=$1 AND agent_instance_id=$2 FOR UPDATE`, deliveryID, store.instanceID))
	if err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	if current.Revision != mutation.ExpectedRevision {
		if replay, found, replayErr := readHelperApprovalReplay(ctx, tx, deliveryID, "approve", mutation); replayErr == nil && found {
			if tx.Commit(ctx) != nil {
				return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
			}
			return replay, nil
		}
		return helperkey.ApprovalChallenge{}, helperkey.ErrConflict
	}
	next := current.Clone()
	if update == nil || update(&next) != nil || next.Validate() != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrInvalid
	}
	raw, _ := json.Marshal(next)
	tag, err := tx.Exec(ctx, `UPDATE root_helper_key_delivery_approvals
		SET status=$1,revision=$2,snapshot_json=$3,updated_at=$4
		WHERE delivery_id=$5 AND agent_instance_id=$6 AND revision=$7`,
		next.Status, next.Revision, raw, next.UpdatedAt, deliveryID, store.instanceID, current.Revision)
	if err != nil || tag.RowsAffected() != 1 {
		return helperkey.ApprovalChallenge{}, helperkey.ErrConflict
	}
	if err := insertHelperApprovalReplay(ctx, tx, deliveryID, "approve", mutation, next); err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	if tx.Commit(ctx) != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
	}
	return next.Clone(), nil
}

type helperApprovalRow interface{ Scan(...any) error }

func scanHelperApproval(row helperApprovalRow) (helperkey.ApprovalChallenge, error) {
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return helperkey.ApprovalChallenge{}, helperkey.ErrNotFound
		}
		return helperkey.ApprovalChallenge{}, helperkey.ErrUnavailable
	}
	var value helperkey.ApprovalChallenge
	if json.Unmarshal(raw, &value) != nil || value.Validate() != nil {
		return helperkey.ApprovalChallenge{}, helperkey.ErrInvalid
	}
	return value, nil
}

func readHelperApprovalReplay(ctx context.Context, tx pgx.Tx, deliveryID, operation string, mutation helperkey.ApprovalMutation) (helperkey.ApprovalChallenge, bool, error) {
	var stored, raw []byte
	err := tx.QueryRow(ctx, `SELECT request_hash,response_json FROM root_helper_key_delivery_approval_replays
		WHERE delivery_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
		deliveryID, operation, mutation.IdempotencyKey).Scan(&stored, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return helperkey.ApprovalChallenge{}, false, nil
	}
	if err != nil {
		return helperkey.ApprovalChallenge{}, false, helperkey.ErrUnavailable
	}
	if subtle.ConstantTimeCompare(stored, mutation.RequestHash[:]) != 1 {
		return helperkey.ApprovalChallenge{}, false, helperkey.ErrConflict
	}
	var value helperkey.ApprovalChallenge
	if json.Unmarshal(raw, &value) != nil || value.Validate() != nil {
		return helperkey.ApprovalChallenge{}, false, helperkey.ErrInvalid
	}
	return value, true, nil
}

func insertHelperApprovalReplay(ctx context.Context, tx pgx.Tx, deliveryID, operation string, mutation helperkey.ApprovalMutation, value helperkey.ApprovalChallenge) error {
	raw, _ := json.Marshal(value)
	if _, err := tx.Exec(ctx, `INSERT INTO root_helper_key_delivery_approval_replays
		(delivery_id,operation,idempotency_key,request_hash,response_revision,response_json)
		VALUES($1,$2,$3,$4,$5,$6)`, deliveryID, operation, mutation.IdempotencyKey,
		mutation.RequestHash[:], value.Revision, raw); err != nil {
		return helperkey.ErrUnavailable
	}
	return nil
}

var _ helperkey.ApprovalRepository = (*RootHelperKeyStore)(nil)
