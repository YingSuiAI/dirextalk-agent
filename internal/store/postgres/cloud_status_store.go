package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	cloudStatusWorkerCursor   = "worker"
	cloudStatusResourceCursor = "resource"
)

type CloudStatusStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

var _ cloudstatus.Reader = (*CloudStatusStore)(nil)

func NewCloudStatusStore(store *Store) (*CloudStatusStore, error) {
	if store == nil || store.pool == nil || store.instanceID == uuid.Nil {
		return nil, cloudstatus.ErrInvalid
	}
	return &CloudStatusStore{pool: store.pool, instanceID: store.instanceID}, nil
}

func (store *CloudStatusStore) GetWorker(ctx context.Context, ownerID, deploymentID string) (worker.Deployment, error) {
	owner, parsedDeployment, err := validateOwnedStatusID(ownerID, deploymentID)
	if err != nil {
		return worker.Deployment{}, err
	}
	item, err := scanWorkerDeployment(store.pool.QueryRow(ctx, workerSelectSQL+`
		WHERE deployment_id=$1 AND owner_id=$2 AND agent_instance_id=$3`, parsedDeployment, owner, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, cloudstatus.ErrNotFound
	}
	if err != nil {
		return worker.Deployment{}, fmt.Errorf("get owned Worker status: %w", err)
	}
	return item, nil
}

func (store *CloudStatusStore) ListWorkers(ctx context.Context, query cloudstatus.ListQuery) (cloudstatus.WorkerPage, error) {
	if err := query.Validate(); err != nil || strings.TrimSpace(query.DeploymentID) != "" {
		return cloudstatus.WorkerPage{}, cloudstatus.ErrInvalid
	}
	pageSize := statusPageSize(query.PageSize)
	cursor, err := decodeCloudStatusCursor(query.PageToken, cloudStatusWorkerCursor)
	if err != nil {
		return cloudstatus.WorkerPage{}, cloudstatus.ErrInvalid
	}
	owner := strings.TrimSpace(query.OwnerID)
	arguments := []any{store.instanceID, owner}
	where := ` WHERE agent_instance_id=$1 AND owner_id=$2`
	if cursor != nil {
		arguments = append(arguments, cursor.CreatedAt, cursor.ID)
		where += ` AND (created_at, deployment_id) > ($3, $4)`
	}
	arguments = append(arguments, pageSize+1)
	rows, err := store.pool.Query(ctx, workerSelectSQL+where+fmt.Sprintf(` ORDER BY created_at, deployment_id LIMIT $%d`, len(arguments)), arguments...)
	if err != nil {
		return cloudstatus.WorkerPage{}, fmt.Errorf("list owned Worker statuses: %w", err)
	}
	defer rows.Close()
	items := make([]worker.Deployment, 0, pageSize+1)
	for rows.Next() {
		item, scanErr := scanWorkerDeployment(rows)
		if scanErr != nil {
			return cloudstatus.WorkerPage{}, fmt.Errorf("scan owned Worker status: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return cloudstatus.WorkerPage{}, fmt.Errorf("iterate owned Worker statuses: %w", err)
	}
	result := cloudstatus.WorkerPage{Workers: items}
	if len(items) > pageSize {
		result.Workers = items[:pageSize]
		result.NextPageToken, err = encodeCloudStatusCursor(cloudStatusWorkerCursor, result.Workers[pageSize-1].CreatedAt, result.Workers[pageSize-1].DeploymentID)
		if err != nil {
			return cloudstatus.WorkerPage{}, err
		}
	}
	return result, nil
}

func (store *CloudStatusStore) GetResource(ctx context.Context, ownerID, resourceID string) (resource.ResourceV1, error) {
	owner, parsedResource, err := validateOwnedStatusID(ownerID, resourceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	item, err := scanResource(store.pool.QueryRow(ctx, resourceSelectSQL+`
		WHERE resource_id=$1 AND owner_id=$2 AND agent_instance_id=$3`, parsedResource, owner, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ResourceV1{}, cloudstatus.ErrNotFound
	}
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("get owned resource status: %w", err)
	}
	return item, nil
}

func (store *CloudStatusStore) ListResources(ctx context.Context, query cloudstatus.ListQuery) (cloudstatus.ResourcePage, error) {
	if err := query.Validate(); err != nil {
		return cloudstatus.ResourcePage{}, cloudstatus.ErrInvalid
	}
	pageSize := statusPageSize(query.PageSize)
	cursor, err := decodeCloudStatusCursor(query.PageToken, cloudStatusResourceCursor)
	if err != nil {
		return cloudstatus.ResourcePage{}, cloudstatus.ErrInvalid
	}
	arguments := []any{store.instanceID, strings.TrimSpace(query.OwnerID)}
	where := ` WHERE agent_instance_id=$1 AND owner_id=$2`
	if rawDeployment := strings.TrimSpace(query.DeploymentID); rawDeployment != "" {
		deploymentID, parseErr := uuid.Parse(rawDeployment)
		if parseErr != nil || deploymentID == uuid.Nil {
			return cloudstatus.ResourcePage{}, cloudstatus.ErrInvalid
		}
		arguments = append(arguments, deploymentID)
		where += fmt.Sprintf(` AND deployment_id=$%d`, len(arguments))
	}
	if cursor != nil {
		arguments = append(arguments, cursor.CreatedAt, cursor.ID)
		where += fmt.Sprintf(` AND (created_at, resource_id) > ($%d, $%d)`, len(arguments)-1, len(arguments))
	}
	arguments = append(arguments, pageSize+1)
	rows, err := store.pool.Query(ctx, resourceSelectSQL+where+fmt.Sprintf(` ORDER BY created_at, resource_id LIMIT $%d`, len(arguments)), arguments...)
	if err != nil {
		return cloudstatus.ResourcePage{}, fmt.Errorf("list owned resource statuses: %w", err)
	}
	defer rows.Close()
	items, err := scanResources(rows)
	if err != nil {
		return cloudstatus.ResourcePage{}, err
	}
	result := cloudstatus.ResourcePage{Resources: items}
	if len(items) > pageSize {
		result.Resources = items[:pageSize]
		result.NextPageToken, err = encodeCloudStatusCursor(cloudStatusResourceCursor, result.Resources[pageSize-1].CreatedAt, result.Resources[pageSize-1].ResourceID)
		if err != nil {
			return cloudstatus.ResourcePage{}, err
		}
	}
	return result, nil
}

func (store *CloudStatusStore) ListDeploymentResources(ctx context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	owner, parsedDeployment, err := validateOwnedStatusID(ownerID, deploymentID)
	if err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, resourceSelectSQL+`
		WHERE deployment_id=$1 AND owner_id=$2 AND agent_instance_id=$3 ORDER BY created_at, resource_id`, parsedDeployment, owner, store.instanceID)
	if err != nil {
		return nil, fmt.Errorf("list owned deployment resources: %w", err)
	}
	defer rows.Close()
	return scanResources(rows)
}

type cloudStatusCursor struct {
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

func encodeCloudStatusCursor(kind string, createdAt time.Time, rawID string) (string, error) {
	id, err := uuid.Parse(rawID)
	if err != nil || id == uuid.Nil || createdAt.IsZero() {
		return "", cloudstatus.ErrInvalid
	}
	encoded, err := json.Marshal(cloudStatusCursor{Kind: kind, CreatedAt: createdAt.UTC(), ID: id})
	if err != nil {
		return "", fmt.Errorf("encode cloud status cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCloudStatusCursor(value, expectedKind string) (*cloudStatusCursor, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > 1024 {
		return nil, cloudstatus.ErrInvalid
	}
	var cursor cloudStatusCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.Kind != expectedKind || cursor.CreatedAt.IsZero() || cursor.ID == uuid.Nil {
		return nil, cloudstatus.ErrInvalid
	}
	cursor.CreatedAt = cursor.CreatedAt.UTC()
	return &cursor, nil
}

func validateOwnedStatusID(ownerID, rawID string) (string, uuid.UUID, error) {
	if err := cloudstatus.ValidateOwnerID(ownerID); err != nil {
		return "", uuid.Nil, err
	}
	id, err := uuid.Parse(strings.TrimSpace(rawID))
	if err != nil || id == uuid.Nil {
		return "", uuid.Nil, cloudstatus.ErrInvalid
	}
	return strings.TrimSpace(ownerID), id, nil
}

func statusPageSize(value int) int {
	if value == 0 {
		return 50
	}
	return value
}
