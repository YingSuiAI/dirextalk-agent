package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var resourceSHA256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type ResourceStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

var _ resource.Repository = (*ResourceStore)(nil)

func (store *Store) NewResourceStore() (*ResourceStore, error) {
	if store == nil || store.pool == nil {
		return nil, resource.ErrInvalid
	}
	return &ResourceStore{pool: store.pool, instanceID: store.instanceID}, nil
}

func (store *ResourceStore) CreateIntent(ctx context.Context, item resource.ResourceV1) (resource.ResourceV1, error) {
	if err := store.validateResource(item); err != nil {
		return resource.ResourceV1{}, err
	}
	if item.State == resource.StateOrphaned {
		return resource.ResourceV1{}, resource.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("begin resource intent: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.validateResourceIntentOrigin(ctx, tx, item); err != nil {
		return resource.ResourceV1{}, err
	}
	inserted, err := store.insertResource(ctx, tx, item)
	if err != nil {
		if isUniqueViolation(err) {
			return resource.ResourceV1{}, resource.ErrAlreadyExists
		}
		return resource.ResourceV1{}, fmt.Errorf("create resource intent: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("commit resource intent: %w", err)
	}
	if !inserted {
		return store.Get(ctx, item.ResourceID)
	}
	return cloneResource(item), nil
}

// validateResourceIntentOrigin is the durable authorization boundary for a
// billable resource intent.  cloud_resources has two intentionally distinct
// approval origins: the original Worker purchase approval, or a later
// separately device-approved public-entry operation.  Do not weaken this to a
// generic foreign key: entry_approval_id is deliberately not a cloud_approvals
// row.  Both paths are locked in the insert transaction so a lifecycle state
// change cannot race a new intent.
func (store *ResourceStore) validateResourceIntentOrigin(ctx context.Context, tx pgx.Tx, item resource.ResourceV1) error {
	taskID, err := uuid.Parse(item.TaskID)
	if err != nil || taskID == uuid.Nil {
		return resource.ErrInvalid
	}
	deploymentID, err := uuid.Parse(item.DeploymentID)
	if err != nil || deploymentID == uuid.Nil {
		return resource.ErrInvalid
	}
	approvalID, err := uuid.Parse(item.ApprovalID)
	if err != nil || approvalID == uuid.Nil {
		return resource.ErrInvalid
	}

	if err := tx.QueryRow(ctx, workerResourceIntentOriginSQL,
		store.instanceID, item.OwnerID, taskID, deploymentID, approvalID, item.ApprovedPlanHash, item.Region,
	).Scan(new(uuid.UUID)); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("verify Worker resource intent origin: %w", err)
	}

	if err := tx.QueryRow(ctx, entryResourceIntentOriginSQL,
		store.instanceID, item.OwnerID, taskID, deploymentID, approvalID, item.ApprovedPlanHash, item.Region,
	).Scan(new(uuid.UUID)); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("verify entry resource intent origin: %w", err)
	}
	return resource.ErrInvalid
}

const workerResourceIntentOriginSQL = `
	SELECT launch.operation_id
	FROM cloud_launch_operations AS launch
	JOIN cloud_approvals AS approval ON approval.approval_id=launch.approval_id
	JOIN cloud_plans AS plan ON plan.plan_id=launch.plan_id
	JOIN cloud_connections AS connection ON connection.connection_id=launch.connection_id
	WHERE launch.agent_instance_id=$1
	  AND launch.owner_id=$2
	  AND launch.task_id=$3
	  AND launch.deployment_id=$4
	  AND launch.approval_id=$5
	  AND launch.state='provisioning'
	  AND approval.agent_instance_id=$1
	  AND approval.owner_id=$2
	  AND approval.plan_id=launch.plan_id
	  AND approval.plan_hash=$6
	  AND approval.plan_revision=plan.revision
	  AND plan.agent_instance_id=$1
	  AND plan.owner_id=$2
	  AND plan.connection_id=launch.connection_id::text
	  AND plan.plan_hash=$6
	  AND plan.status='approved'
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	  AND connection.region=$7
	  AND connection.status='active'
	FOR SHARE OF launch, approval, plan, connection`

const entryResourceIntentOriginSQL = `
	SELECT operation.operation_id
	FROM cloud_entry_operations AS operation
	JOIN cloud_entry_plans AS entry_plan ON entry_plan.entry_plan_id=operation.entry_plan_id
	JOIN cloud_launch_operations AS launch ON launch.deployment_id=operation.deployment_id
	JOIN cloud_plans AS original_plan ON original_plan.plan_id=operation.original_plan_id
	JOIN cloud_approvals AS original_approval ON original_approval.approval_id=operation.original_approval_id
	JOIN cloud_connections AS connection ON connection.connection_id=operation.connection_id
	WHERE operation.agent_instance_id=$1
	  AND operation.owner_id=$2
	  AND operation.task_id=$3
	  AND operation.deployment_id=$4
	  AND operation.entry_approval_id=$5
	  AND operation.entry_plan_hash=$6
	  AND operation.status='provisioning'
	  AND operation.signature_json IS NOT NULL
	  AND operation.signature IS NOT NULL
	  AND operation.approved_at IS NOT NULL
	  AND entry_plan.agent_instance_id=$1
	  AND entry_plan.owner_id=$2
	  AND entry_plan.task_id=$3
	  AND entry_plan.deployment_id=$4
	  AND entry_plan.status='approved'
	  AND entry_plan.revision=operation.expected_entry_plan_revision
	  AND entry_plan.plan_hash=$6
	  AND entry_plan.plan_hash=operation.entry_plan_hash
	  AND entry_plan.original_plan_id=operation.original_plan_id
	  AND entry_plan.original_plan_hash=operation.original_plan_hash
	  AND entry_plan.original_approval_id=operation.original_approval_id
	  AND entry_plan.connection_id=operation.connection_id
	  AND launch.agent_instance_id=$1
	  AND launch.owner_id=$2
	  AND launch.task_id=$3
	  AND launch.deployment_id=$4
	  AND launch.plan_id=operation.original_plan_id
	  AND launch.approval_id=operation.original_approval_id
	  AND launch.connection_id=operation.connection_id
	  AND original_plan.agent_instance_id=$1
	  AND original_plan.owner_id=$2
	  AND original_plan.connection_id=operation.connection_id::text
	  AND original_plan.plan_hash=operation.original_plan_hash
	  AND original_plan.status='approved'
	  AND original_approval.agent_instance_id=$1
	  AND original_approval.owner_id=$2
	  AND original_approval.plan_id=operation.original_plan_id
	  AND original_approval.plan_hash=operation.original_plan_hash
	  AND original_approval.plan_revision=original_plan.revision
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	  AND connection.region=$7
	  AND connection.status='active'
	FOR SHARE OF operation, entry_plan, launch, original_plan, original_approval, connection`

func (store *ResourceStore) Get(ctx context.Context, resourceID string) (resource.ResourceV1, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(resourceID))
	if err != nil || parsed == uuid.Nil {
		return resource.ResourceV1{}, resource.ErrInvalid
	}
	item, err := scanResource(store.pool.QueryRow(ctx, resourceSelectSQL+` WHERE resource_id=$1 AND agent_instance_id=$2`, parsed, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ResourceV1{}, resource.ErrNotFound
	}
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("get resource: %w", err)
	}
	return item, nil
}

func (store *ResourceStore) ListDeployment(ctx context.Context, deploymentID string) ([]resource.ResourceV1, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil {
		return nil, resource.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, resourceSelectSQL+` WHERE deployment_id=$1 AND agent_instance_id=$2 ORDER BY resource_id`, parsed, store.instanceID)
	if err != nil {
		return nil, fmt.Errorf("list deployment resources: %w", err)
	}
	defer rows.Close()
	return scanResources(rows)
}

func (store *ResourceStore) ListByAgent(ctx context.Context, agentInstanceID string) ([]resource.ResourceV1, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed != store.instanceID {
		return nil, resource.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, resourceSelectSQL+` WHERE agent_instance_id=$1 ORDER BY deployment_id, resource_id`, store.instanceID)
	if err != nil {
		return nil, fmt.Errorf("list agent resources: %w", err)
	}
	defer rows.Close()
	return scanResources(rows)
}

func (store *ResourceStore) Save(ctx context.Context, item resource.ResourceV1, expectedRevision int64) (resource.ResourceV1, error) {
	if expectedRevision < 1 || item.Revision != expectedRevision+1 || store.validateResource(item) != nil {
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	resourceID, _ := uuid.Parse(item.ResourceID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("begin resource save: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadResourceForUpdate(ctx, tx, resourceID, store.instanceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	if current.Revision != expectedRevision || !sameResourceIdentity(current, item) {
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	if err := saveResourceTx(ctx, tx, store.instanceID, expectedRevision, item); err != nil {
		return resource.ResourceV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("commit resource save: %w", err)
	}
	return cloneResource(item), nil
}

func (store *ResourceStore) AcceptManaged(
	ctx context.Context,
	deploymentID string,
	managed resource.ManagedServiceV1,
	expected map[string]int64,
) ([]resource.ResourceV1, error) {
	parsedDeployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsedDeployment == uuid.Nil || managed.Contract.Validate() != nil || managed.Contract.DeploymentID != parsedDeployment.String() || managed.Revision < 1 || managed.CreatedAt.IsZero() || managed.UpdatedAt.IsZero() {
		return nil, resource.ErrInvalid
	}
	serviceID, err := uuid.Parse(managed.ServiceID)
	if err != nil || serviceID == uuid.Nil || managed.State != "active" {
		return nil, resource.ErrInvalid
	}
	contractJSON, err := json.Marshal(managed.Contract)
	if err != nil {
		return nil, resource.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin managed acceptance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingJSON []byte
	var existingServiceID uuid.UUID
	var existingState string
	var existingRevision int64
	err = tx.QueryRow(ctx, `
		SELECT service_id, contract_json, state, revision
		FROM managed_services
		WHERE deployment_id=$1 AND agent_instance_id=$2
		FOR UPDATE`, parsedDeployment, store.instanceID).Scan(&existingServiceID, &existingJSON, &existingState, &existingRevision)
	if err == nil {
		var existingContract resource.ManagedContractV1
		if json.Unmarshal(existingJSON, &existingContract) != nil {
			return nil, errors.New("managed service contract snapshot is invalid")
		}
		existingCanonical, _ := json.Marshal(existingContract)
		if !slices.Equal(existingCanonical, contractJSON) || existingServiceID != serviceID || existingState != managed.State || existingRevision != managed.Revision {
			return nil, resource.ErrRevisionConflict
		}
		items, loadErr := listResourcesTx(ctx, tx, parsedDeployment, store.instanceID, false)
		if loadErr != nil {
			return nil, loadErr
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit managed acceptance replay: %w", err)
		}
		return items, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("read managed acceptance: %w", err)
	}
	items, err := listResourcesTx(ctx, tx, parsedDeployment, store.instanceID, true)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 || len(items) != len(expected) {
		return nil, resource.ErrRevisionConflict
	}
	for _, item := range items {
		if expected[item.ResourceID] != item.Revision || item.OwnerID != managed.Contract.OwnerID || (item.State != resource.StateActive && item.State != resource.StateDestroyScheduled) {
			return nil, resource.ErrRevisionConflict
		}
	}
	for index := range items {
		item := items[index]
		item.State = resource.StateRetainedManaged
		item.Retention = task.RetentionManaged
		item.DestroyDeadline = time.Time{}
		item.AutoDestroyApproved = false
		item.Tags[resource.TagRetention] = string(task.RetentionManaged)
		item.Tags[resource.TagDestroyDeadline] = "managed"
		item.Revision++
		item.UpdatedAt = managed.UpdatedAt.UTC()
		if err := store.validateResource(item); err != nil {
			return nil, err
		}
		if err := saveResourceTx(ctx, tx, store.instanceID, item.Revision-1, item); err != nil {
			return nil, err
		}
		items[index] = item
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO managed_services (
			service_id, deployment_id, agent_instance_id, owner_id, contract_json, state, revision, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		serviceID, parsedDeployment, store.instanceID, managed.Contract.OwnerID, contractJSON,
		managed.State, managed.Revision, managed.CreatedAt.UTC(), managed.UpdatedAt.UTC(),
	); err != nil {
		return nil, fmt.Errorf("persist managed acceptance: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit managed acceptance: %w", err)
	}
	return cloneResources(items), nil
}

func (store *ResourceStore) ImportOrphan(ctx context.Context, item resource.ResourceV1) (resource.ResourceV1, error) {
	if item.State != resource.StateOrphaned || store.validateResource(item) != nil {
		return resource.ResourceV1{}, resource.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("begin orphan import: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.validateOrphanResourceOrigin(ctx, tx, item); err != nil {
		return resource.ResourceV1{}, err
	}
	inserted, err := store.insertResource(ctx, tx, item)
	if err != nil {
		if isUniqueViolation(err) {
			return resource.ResourceV1{}, resource.ErrAlreadyExists
		}
		return resource.ResourceV1{}, fmt.Errorf("import orphan resource: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("commit orphan import: %w", err)
	}
	if !inserted {
		return resource.ResourceV1{}, resource.ErrAlreadyExists
	}
	return cloneResource(item), nil
}

// validateOrphanResourceOrigin keeps recovery from becoming a generic ledger
// insert after the approval foreign key was removed for entry resources. The
// provider tags carry the exact non-secret approval binding, so an orphan may
// only be adopted after either its original Worker approval or its separately
// signed Entry operation proves the full durable scope. Older resources without
// those tags deliberately fail closed instead of being guessed into ownership.
func (store *ResourceStore) validateOrphanResourceOrigin(ctx context.Context, tx pgx.Tx, item resource.ResourceV1) error {
	taskID, err := uuid.Parse(item.TaskID)
	if err != nil || taskID == uuid.Nil {
		return resource.ErrInvalid
	}
	deploymentID, err := uuid.Parse(item.DeploymentID)
	if err != nil || deploymentID == uuid.Nil {
		return resource.ErrInvalid
	}
	approvalID, err := uuid.Parse(item.ApprovalID)
	if err != nil || approvalID == uuid.Nil || !resourceSHA256Pattern.MatchString(item.ApprovedPlanHash) ||
		item.Tags[resource.TagApprovedPlanHash] != item.ApprovedPlanHash || item.Tags[resource.TagApprovalID] != approvalID.String() {
		return resource.ErrInvalid
	}
	if err := tx.QueryRow(ctx, workerOrphanResourceOriginSQL,
		store.instanceID, item.OwnerID, taskID, deploymentID, approvalID, item.ApprovedPlanHash,
	).Scan(new(uuid.UUID)); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("verify Worker orphan resource origin: %w", err)
	}
	if err := tx.QueryRow(ctx, entryOrphanResourceOriginSQL,
		store.instanceID, item.OwnerID, taskID, deploymentID, approvalID, item.ApprovedPlanHash,
	).Scan(new(uuid.UUID)); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("verify entry orphan resource origin: %w", err)
	}
	return resource.ErrInvalid
}

const workerOrphanResourceOriginSQL = `
	SELECT launch.operation_id
	FROM cloud_launch_operations AS launch
	JOIN cloud_approvals AS approval ON approval.approval_id=launch.approval_id
	JOIN cloud_plans AS plan ON plan.plan_id=launch.plan_id
	JOIN cloud_connections AS connection ON connection.connection_id=launch.connection_id
	WHERE launch.agent_instance_id=$1
	  AND launch.owner_id=$2
	  AND launch.task_id=$3
	  AND launch.deployment_id=$4
	  AND launch.approval_id=$5
	  AND approval.agent_instance_id=$1
	  AND approval.owner_id=$2
	  AND approval.plan_id=launch.plan_id
	  AND approval.plan_hash=$6
	  AND approval.plan_revision=plan.revision
	  AND plan.agent_instance_id=$1
	  AND plan.owner_id=$2
	  AND plan.connection_id=launch.connection_id::text
	  AND plan.plan_hash=$6
	  AND plan.status='approved'
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	FOR SHARE OF launch, approval, plan, connection`

const entryOrphanResourceOriginSQL = `
	SELECT operation.operation_id
	FROM cloud_entry_operations AS operation
	JOIN cloud_entry_plans AS entry_plan ON entry_plan.entry_plan_id=operation.entry_plan_id
	JOIN cloud_launch_operations AS launch ON launch.deployment_id=operation.deployment_id
	JOIN cloud_plans AS original_plan ON original_plan.plan_id=operation.original_plan_id
	JOIN cloud_approvals AS original_approval ON original_approval.approval_id=operation.original_approval_id
	JOIN cloud_connections AS connection ON connection.connection_id=operation.connection_id
	WHERE operation.agent_instance_id=$1
	  AND operation.owner_id=$2
	  AND operation.task_id=$3
	  AND operation.deployment_id=$4
	  AND operation.entry_approval_id=$5
	  AND operation.entry_plan_hash=$6
	  AND operation.status <> 'awaiting_approval'
	  AND operation.status <> 'approved'
	  AND operation.signature_json IS NOT NULL
	  AND operation.signature IS NOT NULL
	  AND operation.approved_at IS NOT NULL
	  AND entry_plan.agent_instance_id=$1
	  AND entry_plan.owner_id=$2
	  AND entry_plan.task_id=$3
	  AND entry_plan.deployment_id=$4
	  AND entry_plan.status='approved'
	  AND entry_plan.revision=operation.expected_entry_plan_revision
	  AND entry_plan.plan_hash=$6
	  AND entry_plan.plan_hash=operation.entry_plan_hash
	  AND entry_plan.original_plan_id=operation.original_plan_id
	  AND entry_plan.original_plan_hash=operation.original_plan_hash
	  AND entry_plan.original_approval_id=operation.original_approval_id
	  AND entry_plan.connection_id=operation.connection_id
	  AND launch.agent_instance_id=$1
	  AND launch.owner_id=$2
	  AND launch.task_id=$3
	  AND launch.deployment_id=$4
	  AND launch.plan_id=operation.original_plan_id
	  AND launch.approval_id=operation.original_approval_id
	  AND launch.connection_id=operation.connection_id
	  AND original_plan.agent_instance_id=$1
	  AND original_plan.owner_id=$2
	  AND original_plan.connection_id=operation.connection_id::text
	  AND original_plan.plan_hash=operation.original_plan_hash
	  AND original_plan.status='approved'
	  AND original_approval.agent_instance_id=$1
	  AND original_approval.owner_id=$2
	  AND original_approval.plan_id=operation.original_plan_id
	  AND original_approval.plan_hash=operation.original_plan_hash
	  AND original_approval.plan_revision=original_plan.revision
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	FOR SHARE OF operation, entry_plan, launch, original_plan, original_approval, connection`

const resourceSelectSQL = `
	SELECT resource_id, agent_instance_id, owner_id, task_id, deployment_id, resource_type,
	       logical_name, region, spec_digest, approved_plan_hash, approval_id, provider_id,
	       provider_candidate_ids, depends_on, retention, destroy_deadline, auto_destroy_approved, tags, state,
	       intent_operation, intent_client_token, intent_recorded_at, readback_exists,
	       provider_create_started_at,
	       readback_provider_id, readback_observed_at, readback_tag_digest, blocked_reason,
	       revision, created_at, updated_at
	FROM cloud_resources`

type resourceRow interface{ Scan(...any) error }

func scanResource(row resourceRow) (resource.ResourceV1, error) {
	var item resource.ResourceV1
	var resourceID, agentID, taskID, deploymentID uuid.UUID
	var approvalID *uuid.UUID
	var dependencies []uuid.UUID
	var providerCandidateIDs []string
	var destroyDeadline, intentRecordedAt, providerCreateStartedAt, readbackObservedAt *time.Time
	var tagsJSON []byte
	if err := row.Scan(
		&resourceID, &agentID, &item.OwnerID, &taskID, &deploymentID, &item.Type,
		&item.LogicalName, &item.Region, &item.SpecDigest, &item.ApprovedPlanHash, &approvalID, &item.ProviderID,
		&providerCandidateIDs, &dependencies, &item.Retention, &destroyDeadline, &item.AutoDestroyApproved, &tagsJSON, &item.State,
		&item.Intent.Operation, &item.Intent.ClientToken, &intentRecordedAt, &item.ReadBack.Exists,
		&providerCreateStartedAt,
		&item.ReadBack.ProviderID, &readbackObservedAt, &item.ReadBack.TagDigest, &item.BlockedReason,
		&item.Revision, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return resource.ResourceV1{}, err
	}
	item.ResourceID, item.AgentInstanceID, item.TaskID, item.DeploymentID = resourceID.String(), agentID.String(), taskID.String(), deploymentID.String()
	item.ProviderCandidateIDs = slices.Clone(providerCandidateIDs)
	if approvalID != nil {
		item.ApprovalID = approvalID.String()
	}
	item.DependsOn = make([]string, len(dependencies))
	for index, dependency := range dependencies {
		item.DependsOn[index] = dependency.String()
	}
	if destroyDeadline != nil {
		item.DestroyDeadline = destroyDeadline.UTC()
	}
	if intentRecordedAt != nil {
		item.Intent.RecordedAt = intentRecordedAt.UTC()
	}
	if providerCreateStartedAt != nil {
		item.Intent.ProviderCreateStartedAt = providerCreateStartedAt.UTC()
	}
	if readbackObservedAt != nil {
		item.ReadBack.ObservedAt = readbackObservedAt.UTC()
	}
	if err := json.Unmarshal(tagsJSON, &item.Tags); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("decode resource tags: %w", err)
	}
	item.CreatedAt, item.UpdatedAt = item.CreatedAt.UTC(), item.UpdatedAt.UTC()
	return item, nil
}

func scanResources(rows pgx.Rows) ([]resource.ResourceV1, error) {
	items := make([]resource.ResourceV1, 0)
	for rows.Next() {
		item, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	return items, nil
}

func (store *ResourceStore) insertResource(ctx context.Context, query interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, item resource.ResourceV1) (bool, error) {
	tagsJSON, err := json.Marshal(item.Tags)
	if err != nil {
		return false, resource.ErrInvalid
	}
	dependencies, err := parseResourceDependencies(item.DependsOn)
	if err != nil {
		return false, resource.ErrInvalid
	}
	result, err := query.Exec(ctx, `
		INSERT INTO cloud_resources (
			resource_id, agent_instance_id, owner_id, task_id, deployment_id, resource_type,
			logical_name, region, spec_digest, approved_plan_hash, approval_id, provider_id,
			provider_candidate_ids, depends_on, retention, destroy_deadline, auto_destroy_approved, tags, state,
			intent_operation, intent_client_token, intent_recorded_at, readback_exists,
			provider_create_started_at,
			readback_provider_id, readback_observed_at, readback_tag_digest, blocked_reason,
			revision, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
		ON CONFLICT (resource_id) DO NOTHING`,
		item.ResourceID, store.instanceID, item.OwnerID, item.TaskID, item.DeploymentID, item.Type,
		item.LogicalName, item.Region, item.SpecDigest, item.ApprovedPlanHash, nullableUUID(item.ApprovalID), item.ProviderID,
		nonNilStrings(item.ProviderCandidateIDs), dependencies, item.Retention, nullableTime(item.DestroyDeadline), item.AutoDestroyApproved, tagsJSON, item.State,
		item.Intent.Operation, item.Intent.ClientToken, nullableTime(item.Intent.RecordedAt), item.ReadBack.Exists,
		nullableTime(item.Intent.ProviderCreateStartedAt),
		item.ReadBack.ProviderID, nullableTime(item.ReadBack.ObservedAt), item.ReadBack.TagDigest, item.BlockedReason,
		item.Revision, item.CreatedAt.UTC(), item.UpdatedAt.UTC(),
	)
	return result.RowsAffected() == 1, err
}

func loadResourceForUpdate(ctx context.Context, tx pgx.Tx, resourceID, instanceID uuid.UUID) (resource.ResourceV1, error) {
	item, err := scanResource(tx.QueryRow(ctx, resourceSelectSQL+` WHERE resource_id=$1 AND agent_instance_id=$2 FOR UPDATE`, resourceID, instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ResourceV1{}, resource.ErrNotFound
	}
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("lock resource: %w", err)
	}
	return item, nil
}

func listResourcesTx(ctx context.Context, tx pgx.Tx, deploymentID, instanceID uuid.UUID, lock bool) ([]resource.ResourceV1, error) {
	query := resourceSelectSQL + ` WHERE deployment_id=$1 AND agent_instance_id=$2 ORDER BY resource_id`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, query, deploymentID, instanceID)
	if err != nil {
		return nil, fmt.Errorf("list transaction resources: %w", err)
	}
	defer rows.Close()
	return scanResources(rows)
}

func saveResourceTx(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, expectedRevision int64, item resource.ResourceV1) error {
	tagsJSON, err := json.Marshal(item.Tags)
	if err != nil {
		return resource.ErrInvalid
	}
	result, err := tx.Exec(ctx, `
		UPDATE cloud_resources SET
			provider_id=$4, provider_candidate_ids=$5, retention=$6, destroy_deadline=$7, auto_destroy_approved=$8,
			tags=$9, state=$10, intent_operation=$11, intent_client_token=$12, intent_recorded_at=$13,
			readback_exists=$14, provider_create_started_at=$15, readback_provider_id=$16, readback_observed_at=$17,
			readback_tag_digest=$18, blocked_reason=$19, revision=$20, updated_at=$21
		WHERE resource_id=$1 AND agent_instance_id=$2 AND revision=$3`,
		item.ResourceID, instanceID, expectedRevision, item.ProviderID, nonNilStrings(item.ProviderCandidateIDs), item.Retention,
		nullableTime(item.DestroyDeadline), item.AutoDestroyApproved, tagsJSON, item.State,
		item.Intent.Operation, item.Intent.ClientToken, nullableTime(item.Intent.RecordedAt), item.ReadBack.Exists,
		nullableTime(item.Intent.ProviderCreateStartedAt), item.ReadBack.ProviderID, nullableTime(item.ReadBack.ObservedAt), item.ReadBack.TagDigest,
		item.BlockedReason, item.Revision, item.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("save resource: %w", err)
	}
	if result.RowsAffected() != 1 {
		return resource.ErrRevisionConflict
	}
	return nil
}

func (store *ResourceStore) validateResource(item resource.ResourceV1) error {
	for _, value := range []string{item.ResourceID, item.AgentInstanceID, item.TaskID, item.DeploymentID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return resource.ErrInvalid
		}
	}
	if item.AgentInstanceID != store.instanceID.String() || item.OwnerID == "" || len(item.OwnerID) > 255 || security.ContainsLikelySecret(item.OwnerID) ||
		item.LogicalName == "" || len(item.LogicalName) > 128 || security.ContainsLikelySecret(item.LogicalName) || item.Revision < 1 || item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
		return resource.ErrInvalid
	}
	switch item.Type {
	case resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeEIP, resource.TypeSG, resource.TypeEndpoint, resource.TypeSnapshot,
		resource.TypeALB, resource.TypeTargetGroup, resource.TypeListener, resource.TypeSecurityGroupRule:
	default:
		return resource.ErrInvalid
	}
	switch item.State {
	case resource.StateProvisioning, resource.StateActive, resource.StateDestroyScheduled, resource.StateRetainedManaged,
		resource.StateDestroying, resource.StateVerifiedDestroyed, resource.StateDestroyBlocked, resource.StateOrphaned:
	default:
		return resource.ErrInvalid
	}
	if item.Retention == task.RetentionEphemeralAutoDestroy {
		if item.DestroyDeadline.IsZero() {
			return resource.ErrInvalid
		}
	} else if item.Retention != task.RetentionManaged || !item.DestroyDeadline.IsZero() || item.AutoDestroyApproved {
		return resource.ErrInvalid
	}
	if !resourceSHA256Pattern.MatchString(item.ApprovedPlanHash) {
		return resource.ErrInvalid
	}
	approval, err := uuid.Parse(item.ApprovalID)
	if err != nil || approval == uuid.Nil {
		return resource.ErrInvalid
	}
	if item.State != resource.StateOrphaned {
		if !resourceSHA256Pattern.MatchString(item.SpecDigest) {
			return resource.ErrInvalid
		}
		if item.Region == "" {
			return resource.ErrInvalid
		}
	}
	if item.Intent.Operation == "" {
		if item.Intent.ClientToken != "" || !item.Intent.RecordedAt.IsZero() || !item.Intent.ProviderCreateStartedAt.IsZero() {
			return resource.ErrInvalid
		}
	} else if (item.Intent.Operation != resource.MutationCreate && item.Intent.Operation != resource.MutationDestroy) || item.Intent.ClientToken == "" || item.Intent.RecordedAt.IsZero() || security.ContainsLikelySecret(item.Intent.ClientToken) {
		return resource.ErrInvalid
	}
	if (!item.Intent.ProviderCreateStartedAt.IsZero() && (item.Intent.Operation != resource.MutationCreate || item.Intent.ProviderCreateStartedAt.Before(item.Intent.RecordedAt))) ||
		(item.Intent.Operation == resource.MutationDestroy && !item.Intent.ProviderCreateStartedAt.IsZero()) {
		return resource.ErrInvalid
	}
	if item.State == resource.StateVerifiedDestroyed && (item.ReadBack.Exists || item.ReadBack.ObservedAt.IsZero()) {
		return resource.ErrInvalid
	}
	if item.State == resource.StateActive || item.State == resource.StateDestroyScheduled || item.State == resource.StateRetainedManaged || item.State == resource.StateOrphaned {
		if item.ProviderID == "" || !item.ReadBack.Exists || item.ReadBack.ObservedAt.IsZero() || item.ReadBack.ProviderID != item.ProviderID {
			return resource.ErrInvalid
		}
	}
	if item.State == resource.StateDestroying && item.ProviderID == "" {
		return resource.ErrInvalid
	}
	if item.State == resource.StateRetainedManaged && item.Retention != task.RetentionManaged {
		return resource.ErrInvalid
	}
	if item.ReadBack.TagDigest != "" && !resourceSHA256Pattern.MatchString(item.ReadBack.TagDigest) {
		return resource.ErrInvalid
	}
	if security.ContainsLikelySecret(item.BlockedReason) || security.ContainsLikelySecret(item.ProviderID) || len(item.ProviderID) > 512 || len(item.BlockedReason) > 4096 || len(item.DependsOn) > 64 || len(item.Intent.ClientToken) > 128 {
		return resource.ErrInvalid
	}
	if !slices.IsSorted(item.ProviderCandidateIDs) {
		return resource.ErrInvalid
	}
	for index, providerID := range item.ProviderCandidateIDs {
		if strings.TrimSpace(providerID) != providerID || providerID == "" || len(providerID) > 512 || security.ContainsLikelySecret(providerID) ||
			(index > 0 && item.ProviderCandidateIDs[index-1] == providerID) {
			return resource.ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(item.DependsOn))
	for _, dependency := range item.DependsOn {
		parsed, err := uuid.Parse(dependency)
		if err != nil || parsed == uuid.Nil || dependency == item.ResourceID {
			return resource.ErrInvalid
		}
		if _, duplicate := seen[dependency]; duplicate {
			return resource.ErrInvalid
		}
		seen[dependency] = struct{}{}
	}
	for _, key := range []string{resource.TagAgentInstanceID, resource.TagOwnerID, resource.TagTaskID, resource.TagDeploymentID, resource.TagResourceID, resource.TagRetention, resource.TagDestroyDeadline, resource.TagApprovedPlanHash, resource.TagApprovalID} {
		if item.Tags[key] == "" || security.ContainsLikelySecret(item.Tags[key]) {
			return resource.ErrInvalid
		}
	}
	for key, value := range item.Tags {
		if key == "" || len(key) > 128 || len(value) > 512 || security.ContainsLikelySecret(key) || security.ContainsLikelySecret(value) {
			return resource.ErrInvalid
		}
	}
	if item.Tags[resource.TagAgentInstanceID] != item.AgentInstanceID || item.Tags[resource.TagOwnerID] != item.OwnerID || item.Tags[resource.TagTaskID] != item.TaskID ||
		item.Tags[resource.TagDeploymentID] != item.DeploymentID || item.Tags[resource.TagResourceID] != item.ResourceID || item.Tags[resource.TagRetention] != string(item.Retention) ||
		item.Tags[resource.TagApprovedPlanHash] != item.ApprovedPlanHash || item.Tags[resource.TagApprovalID] != approval.String() {
		return resource.ErrInvalid
	}
	expectedDeadline := "managed"
	if item.Retention == task.RetentionEphemeralAutoDestroy {
		expectedDeadline = item.DestroyDeadline.UTC().Format(time.RFC3339)
	}
	if item.Tags[resource.TagDestroyDeadline] != expectedDeadline {
		return resource.ErrInvalid
	}
	return nil
}

func sameResourceIdentity(left, right resource.ResourceV1) bool {
	return left.ResourceID == right.ResourceID && left.AgentInstanceID == right.AgentInstanceID && left.OwnerID == right.OwnerID &&
		left.TaskID == right.TaskID && left.DeploymentID == right.DeploymentID && left.Type == right.Type &&
		left.LogicalName == right.LogicalName && left.Region == right.Region && left.SpecDigest == right.SpecDigest &&
		left.ApprovedPlanHash == right.ApprovedPlanHash && left.ApprovalID == right.ApprovalID &&
		slices.Equal(left.DependsOn, right.DependsOn) && left.CreatedAt.Equal(right.CreatedAt)
}

func parseResourceDependencies(values []string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil {
			return nil, resource.ErrInvalid
		}
		result[index] = parsed
	}
	return result, nil
}

func cloneResource(item resource.ResourceV1) resource.ResourceV1 {
	item.ProviderCandidateIDs = slices.Clone(item.ProviderCandidateIDs)
	item.DependsOn = slices.Clone(item.DependsOn)
	item.Tags = maps.Clone(item.Tags)
	return item
}

func cloneResources(items []resource.ResourceV1) []resource.ResourceV1 {
	result := make([]resource.ResourceV1, len(items))
	for index, item := range items {
		result[index] = cloneResource(item)
	}
	return result
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
