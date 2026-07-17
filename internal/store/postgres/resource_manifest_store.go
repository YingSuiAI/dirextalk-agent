package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ResourceManifestMirrorStatus string

const (
	ResourceManifestPending         ResourceManifestMirrorStatus = "pending"
	ResourceManifestMirrored        ResourceManifestMirrorStatus = "mirrored"
	ResourceManifestFailedRetriable ResourceManifestMirrorStatus = "failed"
	// ResourceManifestFailed is retained as a source-compatible alias. The
	// persisted "failed" state is explicitly retried by the recovery loop.
	ResourceManifestFailed   = ResourceManifestFailedRetriable
	resourceManifestSchemaV1 = 1
)

var errResourceManifestReadBack = errors.New("resource manifest read-back did not match the pending generation")

type ResourceManifestRecord struct {
	Manifest   resource.Manifest
	Generation int64
	Status     ResourceManifestMirrorStatus
	LastError  string
	MirroredAt time.Time
	UpdatedAt  time.Time
}

// TrackedResourceManifestMirror composes the PostgreSQL recovery ledger with
// the actual DynamoDB-backed mirror. The remote Put must itself be idempotent;
// a crash after the remote write leaves a pending local generation that is
// safely retried and then marked mirrored.
type TrackedResourceManifestMirror struct {
	store  *ResourceStore
	remote resource.ManifestMirror
}

var _ resource.ManifestMirror = (*TrackedResourceManifestMirror)(nil)

func NewTrackedResourceManifestMirror(store *ResourceStore, remote resource.ManifestMirror) (*TrackedResourceManifestMirror, error) {
	if store == nil || remote == nil {
		return nil, resource.ErrInvalid
	}
	return &TrackedResourceManifestMirror{store: store, remote: remote}, nil
}

func (mirror *TrackedResourceManifestMirror) Put(ctx context.Context, manifest resource.Manifest) error {
	if err := resource.NormalizeLegacyApprovalBindings(&manifest); err != nil {
		return resource.ErrInvalid
	}
	expected := int64(0)
	if current, err := mirror.store.GetResourceManifestRecord(ctx, manifest.DeploymentID); err == nil {
		expected = current.Generation
		candidate := cloneManifest(manifest)
		candidate.Revision = current.Manifest.Revision
		currentJSON, currentErr := encodeResourceManifest(current.Manifest)
		candidateJSON, candidateErr := encodeResourceManifest(candidate)
		if currentErr != nil || candidateErr != nil {
			return resource.ErrInvalid
		}
		if bytes.Equal(currentJSON, candidateJSON) {
			manifest = current.Manifest
		} else {
			manifest.Revision = current.Manifest.Revision + 1
		}
	} else if !errors.Is(err, resource.ErrNotFound) {
		return err
	} else {
		manifest.Revision = 1
	}
	record, err := mirror.store.PutResourceManifestPending(ctx, manifest, expected)
	if err != nil {
		return err
	}
	if record.Status == ResourceManifestMirrored {
		return nil
	}
	return mirror.mirrorRecord(ctx, record)
}

// Replay retries exactly one persisted generation. It re-reads the local row
// before any remote call so a stale scanner result cannot overwrite or mark a
// newer PostgreSQL generation.
func (mirror *TrackedResourceManifestMirror) Replay(ctx context.Context, record ResourceManifestRecord) error {
	current, err := mirror.store.GetResourceManifestRecord(ctx, record.Manifest.DeploymentID)
	if err != nil {
		return err
	}
	currentJSON, currentErr := encodeResourceManifest(current.Manifest)
	recordJSON, recordErr := encodeResourceManifest(record.Manifest)
	if currentErr != nil || recordErr != nil || current.Generation != record.Generation || !bytes.Equal(currentJSON, recordJSON) {
		return resource.ErrRevisionConflict
	}
	if current.Status == ResourceManifestMirrored {
		return nil
	}
	if current.Status != ResourceManifestPending && current.Status != ResourceManifestFailedRetriable {
		return resource.ErrRevisionConflict
	}
	return mirror.mirrorRecord(ctx, current)
}

func (mirror *TrackedResourceManifestMirror) mirrorRecord(ctx context.Context, record ResourceManifestRecord) error {
	putErr := mirror.remote.Put(ctx, record.Manifest)
	if reader, ok := mirror.remote.(resource.ManifestReadBack); ok {
		observed, readErr := reader.Get(ctx, record.Manifest.DeploymentID)
		observedJSON, observedErr := encodeResourceManifest(observed)
		expectedJSON, expectedErr := encodeResourceManifest(record.Manifest)
		if readErr == nil && observedErr == nil && expectedErr == nil && bytes.Equal(observedJSON, expectedJSON) {
			putErr = nil // UpdateItem may have committed before its response was lost.
		} else if putErr == nil {
			putErr = errResourceManifestReadBack
		} else if readErr != nil {
			putErr = errors.Join(putErr, readErr)
		} else {
			putErr = errors.Join(putErr, errResourceManifestReadBack)
		}
	}
	if putErr != nil {
		_, markErr := mirror.store.MarkResourceManifestFailed(ctx, record.Manifest.DeploymentID, record.Generation, putErr)
		if markErr != nil {
			return errors.Join(putErr, markErr)
		}
		return putErr
	}
	_, err := mirror.store.MarkResourceManifestMirrored(ctx, record.Manifest.DeploymentID, record.Generation)
	return err
}

func (mirror *TrackedResourceManifestMirror) ListExpired(ctx context.Context, before time.Time) ([]resource.Manifest, error) {
	return mirror.remote.ListExpired(ctx, before)
}

// PutResourceManifestPending records the exact graph that must be mirrored to
// DynamoDB before the caller exposes it as active. expectedGeneration is zero
// for the first write. An exact retry returns the original generation.
func (store *ResourceStore) PutResourceManifestPending(ctx context.Context, manifest resource.Manifest, expectedGeneration int64) (ResourceManifestRecord, error) {
	if err := resource.NormalizeLegacyApprovalBindings(&manifest); err != nil {
		return ResourceManifestRecord{}, resource.ErrInvalid
	}
	if err := store.validateManifest(manifest); err != nil || expectedGeneration < 0 {
		return ResourceManifestRecord{}, resource.ErrInvalid
	}
	encoded, err := encodeResourceManifest(manifest)
	if err != nil {
		return ResourceManifestRecord{}, err
	}
	deploymentID, _ := uuid.Parse(manifest.DeploymentID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ResourceManifestRecord{}, fmt.Errorf("begin resource manifest intent: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, _, err := loadManifestRecordForUpdate(ctx, tx, deploymentID, store.instanceID)
	if errors.Is(err, pgx.ErrNoRows) {
		if expectedGeneration != 0 {
			return ResourceManifestRecord{}, resource.ErrRevisionConflict
		}
		var updatedAt time.Time
		if err := tx.QueryRow(ctx, `
			INSERT INTO resource_manifest_mirror (
				deployment_id, agent_instance_id, owner_id, task_id, manifest_revision,
				manifest_json, mirror_generation, mirror_status
			) VALUES ($1,$2,$3,$4,$5,$6,1,$7)
			RETURNING updated_at`,
			deploymentID, store.instanceID, manifest.OwnerID, manifest.TaskID,
			manifest.Revision, encoded, ResourceManifestPending,
		).Scan(&updatedAt); err != nil {
			return ResourceManifestRecord{}, fmt.Errorf("persist resource manifest intent: %w", err)
		}
		result := ResourceManifestRecord{Manifest: cloneManifest(manifest), Generation: 1, Status: ResourceManifestPending, UpdatedAt: updatedAt.UTC()}
		if err := tx.Commit(ctx); err != nil {
			return ResourceManifestRecord{}, fmt.Errorf("commit resource manifest intent: %w", err)
		}
		return result, nil
	}
	if err != nil {
		return ResourceManifestRecord{}, err
	}
	currentCanonical, canonicalErr := encodeResourceManifest(current.Manifest)
	if canonicalErr != nil {
		return ResourceManifestRecord{}, canonicalErr
	}
	if bytes.Equal(currentCanonical, encoded) && (current.Status == ResourceManifestPending || current.Status == ResourceManifestMirrored || current.Status == ResourceManifestFailedRetriable) {
		if err := tx.Commit(ctx); err != nil {
			return ResourceManifestRecord{}, fmt.Errorf("commit resource manifest replay: %w", err)
		}
		return current, nil
	}
	if current.Generation != expectedGeneration || manifest.Revision < current.Manifest.Revision || (manifest.Revision == current.Manifest.Revision && !bytes.Equal(currentCanonical, encoded)) {
		return ResourceManifestRecord{}, resource.ErrRevisionConflict
	}
	var updatedAt time.Time
	newGeneration := current.Generation + 1
	if err := tx.QueryRow(ctx, `
		UPDATE resource_manifest_mirror
		SET owner_id=$3, task_id=$4, manifest_revision=$5, manifest_json=$6,
		    mirror_generation=$7, mirror_status=$8, last_error='', mirrored_at=NULL,
		    updated_at=clock_timestamp()
		WHERE deployment_id=$1 AND agent_instance_id=$2 AND mirror_generation=$9
		RETURNING updated_at`,
		deploymentID, store.instanceID, manifest.OwnerID, manifest.TaskID, manifest.Revision,
		encoded, newGeneration, ResourceManifestPending, expectedGeneration,
	).Scan(&updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResourceManifestRecord{}, resource.ErrRevisionConflict
		}
		return ResourceManifestRecord{}, fmt.Errorf("update resource manifest intent: %w", err)
	}
	result := ResourceManifestRecord{Manifest: cloneManifest(manifest), Generation: newGeneration, Status: ResourceManifestPending, UpdatedAt: updatedAt.UTC()}
	if err := tx.Commit(ctx); err != nil {
		return ResourceManifestRecord{}, fmt.Errorf("commit resource manifest update: %w", err)
	}
	return result, nil
}

func (store *ResourceStore) MarkResourceManifestMirrored(ctx context.Context, deploymentID string, generation int64) (ResourceManifestRecord, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil || generation < 1 {
		return ResourceManifestRecord{}, resource.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ResourceManifestRecord{}, fmt.Errorf("begin mark manifest mirrored: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, _, err := loadManifestRecordForUpdate(ctx, tx, parsed, store.instanceID)
	if err != nil {
		return ResourceManifestRecord{}, mapManifestLoadError(err)
	}
	if current.Generation != generation {
		return ResourceManifestRecord{}, resource.ErrRevisionConflict
	}
	if current.Status == ResourceManifestMirrored {
		if err := tx.Commit(ctx); err != nil {
			return ResourceManifestRecord{}, err
		}
		return current, nil
	}
	if current.Status != ResourceManifestPending && current.Status != ResourceManifestFailedRetriable {
		return ResourceManifestRecord{}, resource.ErrRevisionConflict
	}
	if err := tx.QueryRow(ctx, `
		UPDATE resource_manifest_mirror
		SET mirror_status=$4, last_error='', mirrored_at=clock_timestamp(), updated_at=clock_timestamp()
		WHERE deployment_id=$1 AND agent_instance_id=$2 AND mirror_generation=$3 AND mirror_status IN ($5,$6)
		RETURNING mirrored_at, updated_at`,
		parsed, store.instanceID, generation, ResourceManifestMirrored, ResourceManifestPending, ResourceManifestFailedRetriable,
	).Scan(&current.MirroredAt, &current.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResourceManifestRecord{}, resource.ErrRevisionConflict
		}
		return ResourceManifestRecord{}, fmt.Errorf("mark manifest mirrored: %w", err)
	}
	current.Status = ResourceManifestMirrored
	current.MirroredAt, current.UpdatedAt = current.MirroredAt.UTC(), current.UpdatedAt.UTC()
	if err := tx.Commit(ctx); err != nil {
		return ResourceManifestRecord{}, fmt.Errorf("commit manifest mirrored: %w", err)
	}
	return current, nil
}

func (store *ResourceStore) MarkResourceManifestFailed(ctx context.Context, deploymentID string, generation int64, cause error) (ResourceManifestRecord, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil || generation < 1 || cause == nil {
		return ResourceManifestRecord{}, resource.ErrInvalid
	}
	reason := security.RedactText(strings.TrimSpace(cause.Error()))
	if reason == "" {
		reason = "manifest mirror failed"
	}
	if len(reason) > 4096 {
		reason = reason[:4096]
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ResourceManifestRecord{}, fmt.Errorf("begin mark manifest failed: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, _, err := loadManifestRecordForUpdate(ctx, tx, parsed, store.instanceID)
	if err != nil {
		return ResourceManifestRecord{}, mapManifestLoadError(err)
	}
	if current.Generation != generation || current.Status == ResourceManifestMirrored {
		return ResourceManifestRecord{}, resource.ErrRevisionConflict
	}
	if err := tx.QueryRow(ctx, `
		UPDATE resource_manifest_mirror
		SET mirror_status=$4, last_error=$5, mirrored_at=NULL, updated_at=clock_timestamp()
		WHERE deployment_id=$1 AND agent_instance_id=$2 AND mirror_generation=$3 AND mirror_status IN ($6,$4)
		RETURNING updated_at`,
		parsed, store.instanceID, generation, ResourceManifestFailed, reason, ResourceManifestPending,
	).Scan(&current.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResourceManifestRecord{}, resource.ErrRevisionConflict
		}
		return ResourceManifestRecord{}, fmt.Errorf("mark manifest failed: %w", err)
	}
	current.Status, current.LastError, current.MirroredAt = ResourceManifestFailed, reason, time.Time{}
	current.UpdatedAt = current.UpdatedAt.UTC()
	if err := tx.Commit(ctx); err != nil {
		return ResourceManifestRecord{}, fmt.Errorf("commit manifest failed: %w", err)
	}
	return current, nil
}

func (store *ResourceStore) GetResourceManifestRecord(ctx context.Context, deploymentID string) (ResourceManifestRecord, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil {
		return ResourceManifestRecord{}, resource.ErrInvalid
	}
	record, _, err := loadManifestRecord(ctx, store.pool, parsed, store.instanceID, false)
	if err != nil {
		return ResourceManifestRecord{}, mapManifestLoadError(err)
	}
	return record, nil
}

func (store *ResourceStore) ListResourceManifestsNeedingRecovery(ctx context.Context, limit int) ([]ResourceManifestRecord, error) {
	if limit < 1 || limit > 1000 {
		return nil, resource.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT manifest_json, mirror_generation, mirror_status, last_error, mirrored_at, updated_at
		FROM resource_manifest_mirror
		WHERE agent_instance_id=$1 AND mirror_status IN ($2,$3)
		ORDER BY updated_at, deployment_id
		LIMIT $4`, store.instanceID, ResourceManifestPending, ResourceManifestFailedRetriable, limit)
	if err != nil {
		return nil, fmt.Errorf("list resource manifest recovery: %w", err)
	}
	defer rows.Close()
	result := make([]ResourceManifestRecord, 0)
	for rows.Next() {
		record, err := scanManifestRecord(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

type manifestSnapshotV1 struct {
	SchemaVersion int               `json:"schema_version"`
	Manifest      resource.Manifest `json:"manifest"`
}

func encodeResourceManifest(manifest resource.Manifest) ([]byte, error) {
	encoded, err := json.Marshal(manifestSnapshotV1{SchemaVersion: resourceManifestSchemaV1, Manifest: manifest})
	if err != nil {
		return nil, fmt.Errorf("encode resource manifest: %w", err)
	}
	return encoded, nil
}

func decodeResourceManifest(encoded []byte) (resource.Manifest, error) {
	var snapshot manifestSnapshotV1
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != resourceManifestSchemaV1 {
		return resource.Manifest{}, errors.New("resource manifest snapshot is invalid")
	}
	if err := resource.NormalizeLegacyApprovalBindings(&snapshot.Manifest); err != nil {
		return resource.Manifest{}, errors.New("resource manifest snapshot is invalid")
	}
	return snapshot.Manifest, nil
}

func loadManifestRecordForUpdate(ctx context.Context, tx pgx.Tx, deploymentID, instanceID uuid.UUID) (ResourceManifestRecord, []byte, error) {
	return loadManifestRecord(ctx, tx, deploymentID, instanceID, true)
}

type manifestQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadManifestRecord(ctx context.Context, query manifestQuerier, deploymentID, instanceID uuid.UUID, lock bool) (ResourceManifestRecord, []byte, error) {
	statement := `
		SELECT manifest_json, mirror_generation, mirror_status, last_error, mirrored_at, updated_at
		FROM resource_manifest_mirror
		WHERE deployment_id=$1 AND agent_instance_id=$2`
	if lock {
		statement += ` FOR UPDATE`
	}
	var encoded []byte
	var record ResourceManifestRecord
	var mirroredAt *time.Time
	if err := query.QueryRow(ctx, statement, deploymentID, instanceID).Scan(
		&encoded, &record.Generation, &record.Status, &record.LastError, &mirroredAt, &record.UpdatedAt,
	); err != nil {
		return ResourceManifestRecord{}, nil, err
	}
	manifest, err := decodeResourceManifest(encoded)
	if err != nil {
		return ResourceManifestRecord{}, nil, err
	}
	record.Manifest, record.UpdatedAt = manifest, record.UpdatedAt.UTC()
	if mirroredAt != nil {
		record.MirroredAt = mirroredAt.UTC()
	}
	return record, encoded, nil
}

func scanManifestRecord(row interface{ Scan(...any) error }) (ResourceManifestRecord, error) {
	var encoded []byte
	var record ResourceManifestRecord
	var mirroredAt *time.Time
	if err := row.Scan(&encoded, &record.Generation, &record.Status, &record.LastError, &mirroredAt, &record.UpdatedAt); err != nil {
		return ResourceManifestRecord{}, err
	}
	manifest, err := decodeResourceManifest(encoded)
	if err != nil {
		return ResourceManifestRecord{}, err
	}
	record.Manifest, record.UpdatedAt = manifest, record.UpdatedAt.UTC()
	if mirroredAt != nil {
		record.MirroredAt = mirroredAt.UTC()
	}
	return record, nil
}

func (store *ResourceStore) validateManifest(manifest resource.Manifest) error {
	canonical := manifest
	if err := resource.NormalizeLegacyApprovalBindings(&canonical); err != nil {
		return resource.ErrInvalid
	}
	manifest = canonical
	for _, value := range []string{manifest.ManifestID, manifest.AgentInstanceID, manifest.TaskID, manifest.DeploymentID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return resource.ErrInvalid
		}
	}
	if manifest.AgentInstanceID != store.instanceID.String() || manifest.ManifestID != manifest.DeploymentID || manifest.OwnerID == "" ||
		security.ContainsLikelySecret(manifest.OwnerID) || manifest.Revision < 1 || manifest.UpdatedAt.IsZero() || len(manifest.Resources) == 0 {
		return resource.ErrInvalid
	}
	if err := manifest.ValidateResourceApprovalScope(); err != nil {
		return resource.ErrInvalid
	}
	for _, item := range manifest.Resources {
		if err := store.validateResource(item); err != nil {
			return err
		}
		if manifest.Managed && item.State != resource.StateRetainedManaged {
			return resource.ErrInvalid
		}
	}
	return nil
}

func cloneManifest(manifest resource.Manifest) resource.Manifest {
	encoded, _ := json.Marshal(manifest)
	var result resource.Manifest
	_ = json.Unmarshal(encoded, &result)
	return result
}

func mapManifestLoadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ErrNotFound
	}
	return err
}
