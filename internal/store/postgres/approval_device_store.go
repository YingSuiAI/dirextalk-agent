package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	registerApprovalDeviceOperation  = "cloud.approval_device.register"
	bootstrapApprovalDeviceOperation = "cloud.approval_device.bootstrap_first"
	revokeApprovalDeviceOperation    = "cloud.approval_device.revoke"
)

var ErrApprovalDeviceAlreadyBootstrapped = errors.New("approval device already exists for owner")

var _ cloudapproval.DeviceKeyRepository = (*Store)(nil)

type approvalDeviceSnapshot struct {
	SchemaVersion int                  `json:"schema_version"`
	Record        ApprovalDeviceRecord `json:"record"`
}

func (store *Store) RegisterApprovalDevice(ctx context.Context, scope task.MutationScope, command RegisterApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	return store.registerApprovalDevice(ctx, caller, registerApprovalDeviceOperation, command, false)
}

// BootstrapFirstApprovalDevice is the out-of-band trust-anchor path. It uses a
// server-derived local actor, supports exact idempotent replay, and serializes
// by owner so only that owner's first device can be installed. Runtime and
// gRPC callers must continue to use the device-signed rotation protocol once
// that protocol is available; they must never call this bootstrap method.
func (store *Store) BootstrapFirstApprovalDevice(ctx context.Context, command RegisterApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error) {
	caller := idempotencyCaller{
		ClientID:     "local-approval-device-bootstrap",
		CredentialID: uuid.NewSHA1(store.instanceID, []byte("local-approval-device-bootstrap/v1")),
	}
	return store.registerApprovalDevice(ctx, caller, bootstrapApprovalDeviceOperation, command, true)
}

func (store *Store) registerApprovalDevice(
	ctx context.Context,
	caller idempotencyCaller,
	operation string,
	command RegisterApprovalDeviceCommand,
	requireFirstForOwner bool,
) (cloudapproval.DeviceKeyV1, error) {
	if err := command.validate(); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	agentID, err := uuid.Parse(command.Device.AgentInstanceID)
	if err != nil || agentID != store.instanceID {
		return cloudapproval.DeviceKeyV1{}, ErrCloudFactScope
	}
	deviceID := approvalDeviceID(store.instanceID, command.Device.KeyID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("begin register approval device: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, operation, command.IdempotencyKey, requestDigest[:], deviceID)
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if existing {
		record, err := decodeApprovalDeviceSnapshot(response)
		if err != nil {
			return cloudapproval.DeviceKeyV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudapproval.DeviceKeyV1{}, fmt.Errorf("commit device replay: %w", err)
		}
		return record.Device, nil
	}
	if requireFirstForOwner {
		lockKey := store.instanceID.String() + ":" + command.Device.OwnerID
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
			return cloudapproval.DeviceKeyV1{}, fmt.Errorf("lock first approval device for owner: %w", err)
		}
		var ownerHasDevice bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM cloud_approval_devices
				WHERE agent_instance_id=$1 AND owner_id=$2
			)`, store.instanceID, command.Device.OwnerID).Scan(&ownerHasDevice); err != nil {
			return cloudapproval.DeviceKeyV1{}, fmt.Errorf("check owner approval device: %w", err)
		}
		if ownerHasDevice {
			return cloudapproval.DeviceKeyV1{}, ErrApprovalDeviceAlreadyBootstrapped
		}
	}
	var alreadyExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cloud_approval_devices WHERE key_id=$1)`, command.Device.KeyID).Scan(&alreadyExists); err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("check device existence: %w", err)
	}
	if alreadyExists {
		return cloudapproval.DeviceKeyV1{}, ErrCloudFactRevision
	}
	record := ApprovalDeviceRecord{Device: cloneApprovalDevice(command.Device)}
	if err := tx.QueryRow(ctx, `
		INSERT INTO cloud_approval_devices
		    (device_id, key_id, agent_instance_id, owner_id, public_key, status, revision,
		     not_before, expires_at, revoked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING created_at, updated_at`,
		deviceID, command.Device.KeyID, agentID, command.Device.OwnerID, []byte(command.Device.PublicKey),
		command.Device.Status, int64(command.Device.Revision), command.Device.NotBefore.UTC(),
		command.Device.ExpiresAt.UTC(), command.Device.RevokedAt,
	).Scan(&record.CreatedAt, &record.UpdatedAt); err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("insert approval device: %w", err)
	}
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if err := appendApprovalDeviceEvent(ctx, tx, caller, deviceID, record); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, operation, command.IdempotencyKey, approvalDeviceSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Record: record}); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("commit register approval device: %w", err)
	}
	return record.Device, nil
}

func (store *Store) RevokeApprovalDevice(ctx context.Context, scope task.MutationScope, command RevokeApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if err := command.validate(); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	deviceID := approvalDeviceID(store.instanceID, command.KeyID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("begin revoke approval device: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, revokeApprovalDeviceOperation, command.IdempotencyKey, requestDigest[:], deviceID)
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if existing {
		record, err := decodeApprovalDeviceSnapshot(response)
		if err != nil {
			return cloudapproval.DeviceKeyV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudapproval.DeviceKeyV1{}, fmt.Errorf("commit device revoke replay: %w", err)
		}
		return record.Device, nil
	}
	record, err := readApprovalDevice(ctx, tx, command.KeyID, true)
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if record.Device.AgentInstanceID != store.instanceID.String() {
		return cloudapproval.DeviceKeyV1{}, ErrCloudFactScope
	}
	if record.Device.Revision != command.ExpectedRevision || record.Device.Status != cloudapproval.DeviceKeyActive {
		return cloudapproval.DeviceKeyV1{}, ErrCloudFactRevision
	}
	var revokedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&revokedAt); err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("read revoke time: %w", err)
	}
	revokedAt = revokedAt.UTC()
	record.Device.Status = cloudapproval.DeviceKeyRevoked
	record.Device.Revision++
	record.Device.RevokedAt = &revokedAt
	if err := tx.QueryRow(ctx, `
		UPDATE cloud_approval_devices
		SET status='revoked', revision=$2, revoked_at=$3, updated_at=clock_timestamp()
		WHERE key_id=$1 AND revision=$4 AND status='active'
		RETURNING updated_at`, command.KeyID, int64(record.Device.Revision), revokedAt, int64(command.ExpectedRevision),
	).Scan(&record.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapproval.DeviceKeyV1{}, ErrCloudFactRevision
		}
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("revoke approval device: %w", err)
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	if err := appendApprovalDeviceEvent(ctx, tx, caller, deviceID, record); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, revokeApprovalDeviceOperation, command.IdempotencyKey, approvalDeviceSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Record: record}); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapproval.DeviceKeyV1{}, fmt.Errorf("commit revoke approval device: %w", err)
	}
	return record.Device, nil
}

func (store *Store) GetDeviceKey(ctx context.Context, keyID string) (cloudapproval.DeviceKeyV1, error) {
	record, err := readApprovalDevice(ctx, store.pool, keyID, false)
	if err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	if record.Device.AgentInstanceID != store.instanceID.String() {
		return cloudapproval.DeviceKeyV1{}, ErrCloudFactScope
	}
	return cloneApprovalDevice(record.Device), nil
}

type approvalDeviceQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readApprovalDevice(ctx context.Context, query approvalDeviceQuerier, keyID string, lock bool) (ApprovalDeviceRecord, error) {
	statement := `
		SELECT agent_instance_id, owner_id, public_key, status, revision, not_before, expires_at,
		       revoked_at, created_at, updated_at
		FROM cloud_approval_devices WHERE key_id=$1`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		agentID   uuid.UUID
		publicKey []byte
		status    string
		revision  int64
		revokedAt *time.Time
		record    ApprovalDeviceRecord
	)
	if err := query.QueryRow(ctx, statement, keyID).Scan(
		&agentID, &record.Device.OwnerID, &publicKey, &status, &revision,
		&record.Device.NotBefore, &record.Device.ExpiresAt, &revokedAt, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ApprovalDeviceRecord{}, cloudapproval.ErrDeviceNotFound
		}
		return ApprovalDeviceRecord{}, fmt.Errorf("read approval device: %w", err)
	}
	record.Device.KeyID = keyID
	record.Device.AgentInstanceID = agentID.String()
	record.Device.PublicKey = append(ed25519.PublicKey(nil), publicKey...)
	record.Device.Status = cloudapproval.DeviceKeyStatus(status)
	record.Device.Revision = uint64(revision)
	record.Device.NotBefore, record.Device.ExpiresAt = record.Device.NotBefore.UTC(), record.Device.ExpiresAt.UTC()
	if revokedAt != nil {
		value := revokedAt.UTC()
		record.Device.RevokedAt = &value
	}
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if err := validateDeviceForStorage(record.Device, true); err != nil {
		return ApprovalDeviceRecord{}, ErrCloudFactCorrupt
	}
	return record, nil
}

func validateDeviceForStorage(value cloudapproval.DeviceKeyV1, allowRevoked bool) error {
	if strings.TrimSpace(value.KeyID) == "" || len(value.KeyID) > 128 || strings.TrimSpace(value.OwnerID) == "" || len(value.OwnerID) > 255 {
		return fmt.Errorf("%w: device key/owner is invalid", ErrCloudFactInvalid)
	}
	if _, err := uuid.Parse(value.AgentInstanceID); err != nil || value.Revision == 0 || len(value.PublicKey) != ed25519.PublicKeySize ||
		value.NotBefore.IsZero() || value.ExpiresAt.IsZero() || !value.NotBefore.Before(value.ExpiresAt) {
		return fmt.Errorf("%w: device identity, revision, key, or validity is invalid", ErrCloudFactInvalid)
	}
	switch value.Status {
	case cloudapproval.DeviceKeyActive:
		if value.RevokedAt != nil {
			return fmt.Errorf("%w: active device cannot have revoked_at", ErrCloudFactInvalid)
		}
	case cloudapproval.DeviceKeyRevoked:
		if !allowRevoked || value.RevokedAt == nil || value.RevokedAt.IsZero() {
			return fmt.Errorf("%w: revoked device is invalid", ErrCloudFactInvalid)
		}
	default:
		return fmt.Errorf("%w: device status is invalid", ErrCloudFactInvalid)
	}
	return nil
}

func approvalDeviceID(instanceID uuid.UUID, keyID string) uuid.UUID {
	return uuid.NewSHA1(instanceID, []byte("approval-device:"+keyID))
}

func cloneApprovalDevice(value cloudapproval.DeviceKeyV1) cloudapproval.DeviceKeyV1 {
	value.PublicKey = append(ed25519.PublicKey(nil), value.PublicKey...)
	if value.RevokedAt != nil {
		copy := *value.RevokedAt
		value.RevokedAt = &copy
	}
	return value
}

func decodeApprovalDeviceSnapshot(encoded []byte) (ApprovalDeviceRecord, error) {
	var snapshot approvalDeviceSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != cloudFactSnapshotSchemaV1 {
		return ApprovalDeviceRecord{}, ErrCloudFactCorrupt
	}
	if err := validateDeviceForStorage(snapshot.Record.Device, true); err != nil {
		return ApprovalDeviceRecord{}, ErrCloudFactCorrupt
	}
	snapshot.Record.Device = cloneApprovalDevice(snapshot.Record.Device)
	snapshot.Record.CreatedAt, snapshot.Record.UpdatedAt = snapshot.Record.CreatedAt.UTC(), snapshot.Record.UpdatedAt.UTC()
	return snapshot.Record, nil
}

func appendApprovalDeviceEvent(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, deviceID uuid.UUID, record ApprovalDeviceRecord) error {
	summary := struct {
		KeyID     string                        `json:"key_id"`
		OwnerID   string                        `json:"owner_id"`
		Status    cloudapproval.DeviceKeyStatus `json:"status"`
		Revision  uint64                        `json:"revision"`
		NotBefore time.Time                     `json:"not_before"`
		ExpiresAt time.Time                     `json:"expires_at"`
		Actor     cloudEventActor               `json:"actor"`
	}{record.Device.KeyID, record.Device.OwnerID, record.Device.Status, record.Device.Revision, record.Device.NotBefore.UTC(), record.Device.ExpiresAt.UTC(), newCloudEventActor(caller)}
	return appendCloudFactEvent(ctx, tx, deviceID, "approval_device", "cloud.approval_device.changed", record.Device.Revision, summary)
}
