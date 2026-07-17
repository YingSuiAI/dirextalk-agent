package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	cloudStatusPlanCursor       = "plan"
	cloudStatusConnectionCursor = "connection"
	cloudStatusDeploymentCursor = "deployment"
	cloudStatusWorkerCursor     = "worker"
	cloudStatusResourceCursor   = "resource"
)

type CloudStatusStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
	facts      *Store
	health     cloudstatus.HealthReader
}

func (store *CloudStatusStore) ListPlans(ctx context.Context, query cloudstatus.ListQuery) (cloudstatus.PlanPage, error) {
	if err := query.Validate(); err != nil || strings.TrimSpace(query.DeploymentID) != "" {
		return cloudstatus.PlanPage{}, cloudstatus.ErrInvalid
	}
	pageSize := statusPageSize(query.PageSize)
	cursor, err := decodeCloudOwnedStatusCursor(query.PageToken, cloudStatusPlanCursor, query.OwnerID)
	if err != nil {
		return cloudstatus.PlanPage{}, cloudstatus.ErrInvalid
	}
	arguments := []any{store.instanceID, strings.TrimSpace(query.OwnerID)}
	where := ` WHERE agent_instance_id=$1 AND owner_id=$2`
	if cursor != nil {
		arguments = append(arguments, cursor.CreatedAt, cursor.ID)
		where += ` AND (created_at, plan_id) > ($3, $4)`
	}
	arguments = append(arguments, pageSize+1)
	rows, err := store.pool.Query(ctx, `SELECT plan_id, created_at FROM cloud_plans`+where+
		fmt.Sprintf(` ORDER BY created_at, plan_id LIMIT $%d`, len(arguments)), arguments...)
	if err != nil {
		return cloudstatus.PlanPage{}, fmt.Errorf("list owned cloud Plan links: %w", err)
	}
	defer rows.Close()
	type planLink struct {
		id        uuid.UUID
		createdAt time.Time
	}
	links := make([]planLink, 0, pageSize+1)
	for rows.Next() {
		var link planLink
		if err := rows.Scan(&link.id, &link.createdAt); err != nil || link.id == uuid.Nil || link.createdAt.IsZero() {
			if err == nil {
				err = errors.New("invalid persisted cloud Plan link")
			}
			return cloudstatus.PlanPage{}, fmt.Errorf("scan owned cloud Plan link: %w", err)
		}
		link.createdAt = link.createdAt.UTC()
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return cloudstatus.PlanPage{}, fmt.Errorf("iterate owned cloud Plan links: %w", err)
	}
	rows.Close()
	visible := links
	result := cloudstatus.PlanPage{Plans: make([]cloudapproval.PlanV1, 0, min(len(links), pageSize))}
	if len(links) > pageSize {
		visible = links[:pageSize]
		last := visible[pageSize-1]
		result.NextPageToken, err = encodeCloudOwnedStatusCursor(cloudStatusPlanCursor, query.OwnerID, last.createdAt, last.id.String())
		if err != nil {
			return cloudstatus.PlanPage{}, err
		}
	}
	for _, link := range visible {
		plan, readErr := store.facts.GetPlan(ctx, strings.TrimSpace(query.OwnerID), link.id.String())
		if readErr != nil {
			return cloudstatus.PlanPage{}, fmt.Errorf("read owned cloud Plan status: %w", readErr)
		}
		if plan.AgentInstanceID != store.instanceID.String() || plan.OwnerID != strings.TrimSpace(query.OwnerID) {
			return cloudstatus.PlanPage{}, errors.New("cloud Plan link does not match persisted fact")
		}
		result.Plans = append(result.Plans, plan)
	}
	return result, nil
}

func (store *CloudStatusStore) GetConnection(ctx context.Context, ownerID, connectionID string) (cloudstatus.Connection, error) {
	owner, parsedConnection, err := validateOwnedStatusCanonicalID(ownerID, connectionID)
	if err != nil {
		return cloudstatus.Connection{}, err
	}
	item, err := scanCloudConnectionStatus(store.pool.QueryRow(ctx, cloudConnectionStatusSelectSQL+`
		WHERE connection_id=$1 AND owner_id=$2 AND agent_instance_id=$3`, parsedConnection, owner, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return cloudstatus.Connection{}, cloudstatus.ErrNotFound
	}
	if err != nil {
		return cloudstatus.Connection{}, fmt.Errorf("get owned cloud connection status: %w", err)
	}
	return item, nil
}

func (store *CloudStatusStore) ListConnections(ctx context.Context, query cloudstatus.ListQuery) (cloudstatus.ConnectionPage, error) {
	if err := query.Validate(); err != nil || strings.TrimSpace(query.DeploymentID) != "" {
		return cloudstatus.ConnectionPage{}, cloudstatus.ErrInvalid
	}
	pageSize := statusPageSize(query.PageSize)
	cursor, err := decodeCloudConnectionCursor(query.PageToken, query.OwnerID)
	if err != nil {
		return cloudstatus.ConnectionPage{}, cloudstatus.ErrInvalid
	}
	arguments := []any{store.instanceID, strings.TrimSpace(query.OwnerID)}
	where := ` WHERE agent_instance_id=$1 AND owner_id=$2`
	if cursor != nil {
		arguments = append(arguments, cursor.CreatedAt, cursor.ID)
		where += ` AND (created_at, connection_id) > ($3, $4)`
	}
	arguments = append(arguments, pageSize+1)
	rows, err := store.pool.Query(ctx, cloudConnectionStatusSelectSQL+where+
		fmt.Sprintf(` ORDER BY created_at, connection_id LIMIT $%d`, len(arguments)), arguments...)
	if err != nil {
		return cloudstatus.ConnectionPage{}, fmt.Errorf("list owned cloud connection statuses: %w", err)
	}
	defer rows.Close()
	items := make([]cloudstatus.Connection, 0, pageSize+1)
	for rows.Next() {
		item, scanErr := scanCloudConnectionStatus(rows)
		if scanErr != nil {
			return cloudstatus.ConnectionPage{}, fmt.Errorf("scan owned cloud connection status: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return cloudstatus.ConnectionPage{}, fmt.Errorf("iterate owned cloud connection statuses: %w", err)
	}
	result := cloudstatus.ConnectionPage{Connections: items}
	if len(items) > pageSize {
		result.Connections = items[:pageSize]
		last := result.Connections[pageSize-1]
		result.NextPageToken, err = encodeCloudConnectionCursor(query.OwnerID, last.CreatedAt, last.ConnectionID)
		if err != nil {
			return cloudstatus.ConnectionPage{}, err
		}
	}
	return result, nil
}

const cloudConnectionStatusSelectSQL = `SELECT connection_id, owner_id, account_id, region, control_role_arn,
	foundation_stack_id, credential_generation, status, revision, created_at, updated_at FROM cloud_connections `

type cloudConnectionStatusRow interface{ Scan(...any) error }

func scanCloudConnectionStatus(row cloudConnectionStatusRow) (cloudstatus.Connection, error) {
	var item cloudstatus.Connection
	var connectionID uuid.UUID
	if err := row.Scan(&connectionID, &item.OwnerID, &item.AccountID, &item.Region, &item.ControlRoleARN,
		&item.FoundationStackID, &item.CredentialGeneration, &item.Status, &item.Revision,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return cloudstatus.Connection{}, err
	}
	item.ConnectionID = connectionID.String()
	item.CreatedAt, item.UpdatedAt = item.CreatedAt.UTC(), item.UpdatedAt.UTC()
	providerBindingPresent := strings.TrimSpace(item.ControlRoleARN) != "" && strings.TrimSpace(item.FoundationStackID) != ""
	providerBindingRemoved := strings.TrimSpace(item.ControlRoleARN) == "" && strings.TrimSpace(item.FoundationStackID) == ""
	if connectionID == uuid.Nil || cloudstatus.ValidateOwnerID(item.OwnerID) != nil ||
		!awsAccountPattern.MatchString(item.AccountID) || !awsRegionPattern.MatchString(item.Region) ||
		(!providerBindingPresent && !providerBindingRemoved) || (item.Status != "destroyed" && !providerBindingPresent) ||
		item.CredentialGeneration < 1 || item.Revision < 1 || item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) ||
		!validCloudConnectionStatus(item.Status) {
		return cloudstatus.Connection{}, errors.New("invalid persisted cloud connection status")
	}
	return item, nil
}

func validCloudConnectionStatus(value string) bool {
	switch value {
	case "establishing", "active", "degraded", "tearing_down", "teardown_blocked", "destroyed":
		return true
	default:
		return false
	}
}

var _ cloudstatus.Reader = (*CloudStatusStore)(nil)

func NewCloudStatusStore(store *Store, healthReaders ...cloudstatus.HealthReader) (*CloudStatusStore, error) {
	if store == nil || store.pool == nil || store.instanceID == uuid.Nil || len(healthReaders) > 1 {
		return nil, cloudstatus.ErrInvalid
	}
	var healthReader cloudstatus.HealthReader
	if len(healthReaders) == 1 {
		healthReader = healthReaders[0]
	} else {
		var err error
		healthReader, err = store.NewHealthProbeStore()
		if err != nil {
			return nil, err
		}
	}
	if healthReader == nil {
		return nil, cloudstatus.ErrInvalid
	}
	return &CloudStatusStore{pool: store.pool, instanceID: store.instanceID, facts: store, health: healthReader}, nil
}

func (store *CloudStatusStore) GetDeployment(ctx context.Context, ownerID, deploymentID string) (cloudstatus.Deployment, error) {
	owner, parsedDeployment, err := validateOwnedStatusID(ownerID, deploymentID)
	if err != nil {
		return cloudstatus.Deployment{}, err
	}
	link, err := scanCloudDeploymentLink(store.pool.QueryRow(ctx, `
		SELECT lo.deployment_id, wd.created_at, lo.plan_id, lo.connection_id
		FROM cloud_launch_operations lo
		JOIN worker_deployments wd
		  ON wd.deployment_id=lo.deployment_id
		 AND wd.agent_instance_id=lo.agent_instance_id
		 AND wd.owner_id=lo.owner_id
		WHERE lo.deployment_id=$1 AND lo.owner_id=$2 AND lo.agent_instance_id=$3`, parsedDeployment, owner, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return cloudstatus.Deployment{}, cloudstatus.ErrNotFound
	}
	if err != nil {
		return cloudstatus.Deployment{}, fmt.Errorf("get owned cloud deployment link: %w", err)
	}
	item, err := store.GetWorker(ctx, owner, link.DeploymentID)
	if err != nil {
		return cloudstatus.Deployment{}, err
	}
	if !item.CreatedAt.Equal(link.CreatedAt) {
		return cloudstatus.Deployment{}, fmt.Errorf("cloud deployment link does not match Worker fact")
	}
	health, err := store.health.GetDeploymentHealth(ctx, owner, link.DeploymentID)
	if err != nil {
		return cloudstatus.Deployment{}, err
	}
	return cloudstatus.Deployment{Worker: item, PlanID: link.PlanID, ConnectionID: link.ConnectionID, Health: health}, nil
}

func (store *CloudStatusStore) ListDeployments(ctx context.Context, query cloudstatus.ListQuery) (cloudstatus.DeploymentPage, error) {
	if err := query.Validate(); err != nil || strings.TrimSpace(query.DeploymentID) != "" {
		return cloudstatus.DeploymentPage{}, cloudstatus.ErrInvalid
	}
	pageSize := statusPageSize(query.PageSize)
	cursor, err := decodeCloudStatusCursor(query.PageToken, cloudStatusDeploymentCursor)
	if err != nil {
		return cloudstatus.DeploymentPage{}, cloudstatus.ErrInvalid
	}
	arguments := []any{store.instanceID, strings.TrimSpace(query.OwnerID)}
	where := ` WHERE lo.agent_instance_id=$1 AND lo.owner_id=$2`
	if cursor != nil {
		arguments = append(arguments, cursor.CreatedAt, cursor.ID)
		where += ` AND (wd.created_at, wd.deployment_id) > ($3, $4)`
	}
	arguments = append(arguments, pageSize+1)
	rows, err := store.pool.Query(ctx, `
		SELECT lo.deployment_id, wd.created_at, lo.plan_id, lo.connection_id
		FROM cloud_launch_operations lo
		JOIN worker_deployments wd
		  ON wd.deployment_id=lo.deployment_id
		 AND wd.agent_instance_id=lo.agent_instance_id
		 AND wd.owner_id=lo.owner_id`+where+fmt.Sprintf(` ORDER BY wd.created_at, wd.deployment_id LIMIT $%d`, len(arguments)), arguments...)
	if err != nil {
		return cloudstatus.DeploymentPage{}, fmt.Errorf("list owned cloud deployment links: %w", err)
	}
	defer rows.Close()
	links := make([]cloudDeploymentLink, 0, pageSize+1)
	for rows.Next() {
		link, scanErr := scanCloudDeploymentLink(rows)
		if scanErr != nil {
			return cloudstatus.DeploymentPage{}, fmt.Errorf("scan owned cloud deployment link: %w", scanErr)
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return cloudstatus.DeploymentPage{}, fmt.Errorf("iterate owned cloud deployment links: %w", err)
	}
	result := cloudstatus.DeploymentPage{Deployments: make([]cloudstatus.Deployment, 0, min(len(links), pageSize))}
	visible := links
	if len(links) > pageSize {
		visible = links[:pageSize]
		last := visible[pageSize-1]
		result.NextPageToken, err = encodeCloudStatusCursor(cloudStatusDeploymentCursor, last.CreatedAt, last.DeploymentID)
		if err != nil {
			return cloudstatus.DeploymentPage{}, err
		}
	}
	for _, link := range visible {
		item, readErr := store.GetWorker(ctx, query.OwnerID, link.DeploymentID)
		if readErr != nil {
			return cloudstatus.DeploymentPage{}, readErr
		}
		if !item.CreatedAt.Equal(link.CreatedAt) {
			return cloudstatus.DeploymentPage{}, fmt.Errorf("cloud deployment link does not match Worker fact")
		}
		health, healthErr := store.health.GetDeploymentHealth(ctx, query.OwnerID, link.DeploymentID)
		if healthErr != nil {
			return cloudstatus.DeploymentPage{}, healthErr
		}
		result.Deployments = append(result.Deployments, cloudstatus.Deployment{
			Worker: item, PlanID: link.PlanID, ConnectionID: link.ConnectionID, Health: health,
		})
	}
	return result, nil
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

type cloudDeploymentLink struct {
	DeploymentID string
	CreatedAt    time.Time
	PlanID       string
	ConnectionID string
}

type cloudDeploymentLinkRow interface{ Scan(...any) error }

func scanCloudDeploymentLink(row cloudDeploymentLinkRow) (cloudDeploymentLink, error) {
	var deploymentID, planID, connectionID uuid.UUID
	var createdAt time.Time
	if err := row.Scan(&deploymentID, &createdAt, &planID, &connectionID); err != nil {
		return cloudDeploymentLink{}, err
	}
	return cloudDeploymentLink{
		DeploymentID: deploymentID.String(), CreatedAt: createdAt.UTC(),
		PlanID: planID.String(), ConnectionID: connectionID.String(),
	}, nil
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
	OwnerID   string    `json:"owner_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

func encodeCloudConnectionCursor(ownerID string, createdAt time.Time, rawID string) (string, error) {
	return encodeCloudOwnedStatusCursor(cloudStatusConnectionCursor, ownerID, createdAt, rawID)
}

func encodeCloudOwnedStatusCursor(kind, ownerID string, createdAt time.Time, rawID string) (string, error) {
	if err := cloudstatus.ValidateOwnerID(ownerID); err != nil {
		return "", err
	}
	id, err := uuid.Parse(rawID)
	if err != nil || id == uuid.Nil || rawID != id.String() || createdAt.IsZero() {
		return "", cloudstatus.ErrInvalid
	}
	encoded, err := json.Marshal(cloudStatusCursor{
		Kind: kind, OwnerID: strings.TrimSpace(ownerID), CreatedAt: createdAt.UTC(), ID: id,
	})
	if err != nil {
		return "", fmt.Errorf("encode cloud connection cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCloudConnectionCursor(value, ownerID string) (*cloudStatusCursor, error) {
	return decodeCloudOwnedStatusCursor(value, cloudStatusConnectionCursor, ownerID)
}

func decodeCloudOwnedStatusCursor(value, kind, ownerID string) (*cloudStatusCursor, error) {
	if err := cloudstatus.ValidateOwnerID(ownerID); err != nil {
		return nil, err
	}
	cursor, err := decodeCloudStatusCursor(value, kind)
	if err != nil || (cursor != nil && cursor.OwnerID != strings.TrimSpace(ownerID)) {
		return nil, cloudstatus.ErrInvalid
	}
	return cursor, nil
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

func validateOwnedStatusCanonicalID(ownerID, rawID string) (string, uuid.UUID, error) {
	owner, id, err := validateOwnedStatusID(ownerID, rawID)
	if err != nil || rawID != id.String() {
		return "", uuid.Nil, cloudstatus.ErrInvalid
	}
	return owner, id, nil
}

func statusPageSize(value int) int {
	if value == 0 {
		return 50
	}
	return value
}
