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
var _ resource.DeploymentFencer = (*ResourceStore)(nil)

func (store *Store) NewResourceStore() (*ResourceStore, error) {
	if store == nil || store.pool == nil {
		return nil, resource.ErrInvalid
	}
	return &ResourceStore{pool: store.pool, instanceID: store.instanceID}, nil
}

// WithDeploymentFence serializes an externally coordinated create/destroy
// transition for one deployment. The advisory lock is session scoped, so it
// deliberately owns a dedicated pool connection for the whole callback rather
// than relying on a transaction connection that a caller cannot retain.
//
// The callback may use normal Store methods; it must not assume its database
// work is part of this lock connection's transaction. On an unlock failure the
// session is discarded so a lock-bearing connection can never return to the
// pool.
func (store *ResourceStore) WithDeploymentFence(ctx context.Context, deploymentID string, fn func(context.Context) error) (result error) {
	if store == nil || store.pool == nil || ctx == nil || fn == nil {
		return resource.ErrInvalid
	}
	deployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || deployment == uuid.Nil {
		return resource.ErrInvalid
	}

	connection, err := store.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire deployment fence connection: %w", err)
	}
	lockKey := "dirextalk-agent:resource-deployment-fence:" + store.instanceID.String() + ":" + deployment.String()
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		connection.Release()
		return fmt.Errorf("acquire deployment fence: %w", err)
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var unlocked bool
		unlockErr := connection.QueryRow(cleanupContext, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockKey).Scan(&unlocked)
		if unlockErr == nil && unlocked {
			connection.Release()
			return
		}

		// pgxpool would otherwise make this session available for reuse while it
		// may still own a session advisory lock. Hijack removes it from the pool;
		// closing the physical connection makes PostgreSQL release every lock.
		physical := connection.Hijack()
		_ = physical.Close(cleanupContext)
		if result == nil {
			if unlockErr != nil {
				result = fmt.Errorf("release deployment fence: %w", unlockErr)
			} else {
				result = fmt.Errorf("release deployment fence: advisory lock was not held")
			}
		}
	}()

	return fn(ctx)
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
	if err := store.rejectCreateDuringDestroy(ctx, tx, item.DeploymentID); err != nil {
		return resource.ResourceV1{}, err
	}
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

// rejectCreateDuringDestroy is intentionally in the same transaction as the
// intent insert. WithDeploymentFence prevents a concurrent approve/destroy
// transition from crossing this read; this durable check still rejects retries
// and callers that arrive after a destruction operation is already visible.
func (store *ResourceStore) rejectCreateDuringDestroy(ctx context.Context, tx pgx.Tx, deploymentID string) error {
	deployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || deployment == uuid.Nil {
		return resource.ErrInvalid
	}
	var found bool
	err = tx.QueryRow(ctx, `
		SELECT true
		FROM cloud_destroy_operations
		WHERE agent_instance_id=$1 AND deployment_id=$2
		  AND status IN ('approved','destroying','destroy_blocked')
		LIMIT 1
		FOR KEY SHARE`, store.instanceID, deployment).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check deployment destruction state: %w", err)
	}
	if found {
		return resource.ErrInvalid
	}
	return nil
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
	if item.IntentOrigin == resource.IntentOriginManagedPreparation {
		if len(item.DependsOn) != 1 {
			return resource.ErrInvalid
		}
		if err := tx.QueryRow(ctx, managedPreparationResourceIntentOriginSQL,
			store.instanceID, item.OwnerID, taskID, deploymentID, approvalID, item.ApprovedPlanHash, item.Region,
			item.OriginScopeDigest, item.ResourceID, item.DependsOn[0], item.Type, item.Retention,
			nullableTime(item.DestroyDeadline), item.AutoDestroyApproved,
		).Scan(new(uuid.UUID)); err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("verify managed preparation resource intent origin: %w", err)
		}
		return resource.ErrInvalid
	}
	if item.IntentOrigin != "" {
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
	  AND plan.agent_instance_id=$1
	  AND plan.owner_id=$2
	  AND plan.connection_id=launch.connection_id::text
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
	  AND original_plan.status='approved'
	  AND original_approval.agent_instance_id=$1
	  AND original_approval.owner_id=$2
	  AND original_approval.plan_id=operation.original_plan_id
	  AND original_approval.plan_hash=operation.original_plan_hash
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	  AND connection.region=$7
	  AND connection.status='active'
	FOR SHARE OF operation, entry_plan, launch, original_plan, original_approval, connection`

const managedPreparationResourceIntentOriginSQL = `
	SELECT operation.operation_id
	FROM cloud_service_operations AS operation
	JOIN cloud_service_operation_steps AS step
	  ON step.operation_id=operation.operation_id
	JOIN cloud_approval_devices AS device
	  ON device.key_id=operation.signer_key_id
	JOIN cloud_plans AS plan ON plan.plan_id=operation.plan_id
	JOIN cloud_connections AS connection ON connection.connection_id=operation.connection_id
	JOIN worker_deployments AS deployment ON deployment.deployment_id=operation.deployment_id
	JOIN LATERAL jsonb_array_elements(operation.challenge_json->'scope'->'volumes') AS volume ON true
	JOIN cloud_resources AS source
	  ON source.resource_id=(volume->'source_volume'->>'resource_id')::uuid
	LEFT JOIN cloud_resources AS snapshot
	  ON snapshot.resource_id=(volume->>'snapshot_resource_id')::uuid
	WHERE operation.operation_id=$5
	  AND operation.agent_instance_id=$1
	  AND operation.owner_id=$2
	  AND operation.deployment_id=$4
	  AND operation.status='running'
	  AND operation.signature IS NOT NULL
	  AND octet_length(operation.signature)=64
	  AND operation.approved_at IS NOT NULL
	  AND operation.scope_digest=$8
	  AND operation.scope_digest=operation.challenge_json->>'scope_digest'
	  AND operation.plan_hash=$6
	  AND operation.current_phase=CASE $11::text WHEN 'snapshot' THEN 'backup' WHEN 'ebs' THEN 'restore_create' ELSE '' END
	  AND step.phase=operation.current_phase
	  AND step.status='running'
	  AND device.agent_instance_id=$1
	  AND device.owner_id=$2
	  AND device.status='active'
	  AND operation.approved_at>=device.not_before
	  AND operation.approved_at<device.expires_at
	  AND plan.agent_instance_id=$1
	  AND plan.owner_id=$2
	  AND plan.plan_id=operation.plan_id
	  AND plan.connection_id=operation.connection_id::text
	  AND plan.revision=operation.plan_revision
	  AND plan.plan_hash=$6
	  AND plan.status='approved'
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	  AND connection.connection_id=operation.connection_id
	  AND connection.revision=operation.connection_revision
	  AND connection.region=$7
	  AND connection.status='active'
	  AND deployment.agent_instance_id=$1
	  AND deployment.owner_id=$2
	  AND deployment.deployment_id=$4
	  AND deployment.task_id=$3
	  AND deployment.revision=operation.deployment_revision
	  AND operation.challenge_json->'scope'->>'preparation_operation_id'=operation.operation_id::text
	  AND operation.challenge_json->'scope'->>'agent_instance_id'=$1::text
	  AND operation.challenge_json->'scope'->>'owner_id'=$2
	  AND operation.challenge_json->'scope'->>'deployment_id'=$4::text
	  AND (operation.challenge_json->'scope'->>'deployment_revision')::bigint=operation.deployment_revision
	  AND operation.challenge_json->'scope'->>'connection_id'=operation.connection_id::text
	  AND (operation.challenge_json->'scope'->>'connection_revision')::bigint=operation.connection_revision
	  AND operation.challenge_json->'scope'->>'plan_id'=operation.plan_id::text
	  AND (operation.challenge_json->'scope'->>'plan_revision')::bigint=operation.plan_revision
	  AND operation.challenge_json->'scope'->>'plan_hash'=$6
	  AND source.agent_instance_id=$1
	  AND source.owner_id=$2
	  AND source.task_id=$3
	  AND source.deployment_id=$4
	  AND source.resource_id=(volume->'source_volume'->>'resource_id')::uuid
	  AND source.provider_id=volume->'source_volume'->>'provider_id'
	  AND source.revision=(volume->'source_volume'->>'revision')::bigint
	  AND source.spec_digest=volume->'source_volume'->>'spec_digest'
	  AND source.readback_tag_digest=volume->'source_volume'->>'tag_digest'
	  AND (
	    -- V1 is frozen: retain its original same-retention authorization
	    -- predicate byte-for-byte in meaning while V2 gets its own finite
	    -- snapshot branch below.
    (operation.challenge_json->>'schema_version'='dirextalk.agent.cloud.service-operation-challenge/v1'
      AND operation.challenge_json->'scope'->>'schema_version'='dirextalk.agent.cloud.service-operation-scope/v1'
      AND source.state='active'
	      AND source.retention=$12
	      AND source.destroy_deadline IS NOT DISTINCT FROM $13::timestamptz
	      AND source.auto_destroy_approved=$14
	      AND (
	        ($11::text='snapshot'
	          AND volume->>'snapshot_resource_id'=$9::text
	          AND volume->'source_volume'->>'resource_id'=$10::text)
	        OR
	        ($11::text='ebs'
	          AND volume->>'replacement_volume_resource_id'=$9::text
	          AND volume->>'snapshot_resource_id'=$10::text
	          AND snapshot.agent_instance_id=$1
	          AND snapshot.owner_id=$2
	          AND snapshot.task_id=$3
	          AND snapshot.deployment_id=$4
	          AND snapshot.resource_id=$10
	          AND snapshot.resource_type='snapshot'
	          AND snapshot.state='active'
	          AND snapshot.intent_origin='managed_preparation'
	          AND snapshot.origin_scope_digest=$8
	          AND snapshot.approval_id=$5
	          AND snapshot.approved_plan_hash=$6
	          AND snapshot.depends_on=ARRAY[source.resource_id]::uuid[])
	      ))
	    OR
	    -- V2 permits exactly one finite exception: a signed preparation
	    -- snapshot remains provider-retained but is ledgered as ephemeral.
	    (operation.challenge_json->>'schema_version'='dirextalk.agent.cloud.service-operation-challenge/v2'
	      AND operation.challenge_json->'scope'->>'schema_version'='dirextalk.agent.cloud.service-operation-scope/v2'
	      AND source.state='active'
	      AND source.retention='managed'
	      AND source.destroy_deadline IS NULL
	      AND source.auto_destroy_approved=false
	      AND plan.plan_json->>'schema_version'='dirextalk.agent.cloud.plan/v2'
	      AND (volume->>'snapshot_max_retention_seconds') ~ '^[1-9][0-9]*$'
	      AND (volume->>'snapshot_max_retention_seconds')::bigint <= 31536000
	      AND EXISTS (
	        SELECT 1
	        FROM jsonb_array_elements(plan.plan_json->'service_operations'->'snapshots') AS template
	        WHERE template->>'operation_key'=volume->>'snapshot_operation_key'
	          AND template->>'source_volume_slot_id'=volume->>'slot_id'
	          AND template->>'source_volume_spec_digest'=volume->>'snapshot_source_volume_scope_digest'
	          AND template->>'disposition'='retain_with_managed_service'
	          AND template->>'max_retention_seconds'=volume->>'snapshot_max_retention_seconds'
	      )
	      AND (
	        ($11::text='snapshot'
	          AND volume->>'snapshot_resource_id'=$9::text
	          AND volume->'source_volume'->>'resource_id'=$10::text
	          AND $12::text='ephemeral_auto_destroy'
	          AND $14=true
	          AND $13::timestamptz=date_trunc('microseconds',
	            (operation.challenge_json->>'issued_at')::timestamptz +
	            ((volume->>'snapshot_max_retention_seconds')::bigint * interval '1 second')))
	        OR
	        ($11::text='ebs'
	          AND volume->>'replacement_volume_resource_id'=$9::text
	          AND volume->>'snapshot_resource_id'=$10::text
	          AND $12::text='managed'
	          AND $13::timestamptz IS NULL
	          AND $14=false
	          AND snapshot.agent_instance_id=$1
	          AND snapshot.owner_id=$2
	          AND snapshot.task_id=$3
	          AND snapshot.deployment_id=$4
	          AND snapshot.resource_id=$10
	          AND snapshot.resource_type='snapshot'
	          AND snapshot.state='active'
	          AND snapshot.intent_origin='managed_preparation'
	          AND snapshot.origin_scope_digest=$8
	          AND snapshot.approval_id=$5
	          AND snapshot.approved_plan_hash=$6
	          AND snapshot.retention='ephemeral_auto_destroy'
	          AND snapshot.auto_destroy_approved=true
	          AND snapshot.destroy_deadline=date_trunc('microseconds',
	            (operation.challenge_json->>'issued_at')::timestamptz +
	            ((volume->>'snapshot_max_retention_seconds')::bigint * interval '1 second'))
	          AND snapshot.depends_on=ARRAY[source.resource_id]::uuid[])
	      ))
	  )
	FOR SHARE OF operation, step, device, plan, connection, deployment, source`

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
	if current.Intent.ProviderCreateStartedAt.IsZero() && !item.Intent.ProviderCreateStartedAt.IsZero() {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT connection.status='active'
		 FROM cloud_launch_operations launch
		 JOIN cloud_connections connection ON connection.agent_instance_id=launch.agent_instance_id AND connection.connection_id=launch.connection_id
		 WHERE launch.agent_instance_id=$1 AND launch.owner_id=$2 AND launch.deployment_id=$3
		 FOR UPDATE OF connection`, store.instanceID, item.OwnerID, item.DeploymentID).Scan(&active); err != nil || !active {
			return resource.ResourceV1{}, resource.ErrRevisionConflict
		}
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
		for _, item := range items {
			if !managedAcceptanceStableResource(item) {
				return nil, resource.ErrRevisionConflict
			}
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
		if expected[item.ResourceID] != item.Revision || item.OwnerID != managed.Contract.OwnerID ||
			!managedAcceptanceCandidateResource(item) {
			return nil, resource.ErrRevisionConflict
		}
	}
	for index := range items {
		item := items[index]
		if resource.IsBoundedManagedPreparationSnapshot(item) || item.State == resource.StateVerifiedDestroyed {
			continue
		}
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

func managedAcceptanceCandidateResource(item resource.ResourceV1) bool {
	if resource.IsBoundedManagedPreparationSnapshot(item) {
		return item.State == resource.StateActive || item.State == resource.StateVerifiedDestroyed
	}
	return item.State == resource.StateActive ||
		(item.State == resource.StateVerifiedDestroyed && item.Retention == task.RetentionManaged)
}

func managedAcceptanceStableResource(item resource.ResourceV1) bool {
	if resource.IsBoundedManagedPreparationSnapshot(item) {
		return item.State == resource.StateActive || item.State == resource.StateVerifiedDestroyed
	}
	return item.Retention == task.RetentionManaged &&
		(item.State == resource.StateRetainedManaged || item.State == resource.StateVerifiedDestroyed)
}

func (store *ResourceStore) GetManaged(
	ctx context.Context,
	deploymentID string,
) (resource.ManagedServiceV1, []resource.ResourceV1, error) {
	parsedDeployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if ctx == nil || err != nil || parsedDeployment == uuid.Nil || parsedDeployment.String() != deploymentID {
		return resource.ManagedServiceV1{}, nil, resource.ErrInvalid
	}
	var managed resource.ManagedServiceV1
	var contractJSON []byte
	err = store.pool.QueryRow(ctx, `
		SELECT service_id::text,contract_json,state,revision,created_at,updated_at
		FROM managed_services
		WHERE deployment_id=$1 AND agent_instance_id=$2`,
		parsedDeployment, store.instanceID).Scan(
		&managed.ServiceID, &contractJSON, &managed.State, &managed.Revision, &managed.CreatedAt, &managed.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ManagedServiceV1{}, nil, resource.ErrNotFound
	}
	if err != nil {
		return resource.ManagedServiceV1{}, nil, fmt.Errorf("read managed service replay: %w", err)
	}
	if json.Unmarshal(contractJSON, &managed.Contract) != nil || managed.Contract.Validate() != nil {
		return resource.ManagedServiceV1{}, nil, resource.ErrInvalid
	}
	items, err := store.ListDeployment(ctx, deploymentID)
	if err != nil {
		return resource.ManagedServiceV1{}, nil, err
	}
	return managed, items, nil
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
	  AND plan.agent_instance_id=$1
	  AND plan.owner_id=$2
	  AND plan.connection_id=launch.connection_id::text
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
	  AND original_plan.status='approved'
	  AND original_approval.agent_instance_id=$1
	  AND original_approval.owner_id=$2
	  AND original_approval.plan_id=operation.original_plan_id
	  AND original_approval.plan_hash=operation.original_plan_hash
	  AND connection.agent_instance_id=$1
	  AND connection.owner_id=$2
	FOR SHARE OF operation, entry_plan, launch, original_plan, original_approval, connection`

const resourceSelectSQL = `
	SELECT resource_id, agent_instance_id, owner_id, task_id, deployment_id, resource_type,
	       logical_name, region, spec_digest, approved_plan_hash, approval_id, provider_id,
	       intent_origin, origin_scope_digest,
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
		&item.IntentOrigin, &item.OriginScopeDigest,
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
			intent_origin, origin_scope_digest,
			provider_candidate_ids, depends_on, retention, destroy_deadline, auto_destroy_approved, tags, state,
			intent_operation, intent_client_token, intent_recorded_at, readback_exists,
			provider_create_started_at,
			readback_provider_id, readback_observed_at, readback_tag_digest, blocked_reason,
			revision, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
		ON CONFLICT (resource_id) DO NOTHING`,
		item.ResourceID, store.instanceID, item.OwnerID, item.TaskID, item.DeploymentID, item.Type,
		item.LogicalName, item.Region, item.SpecDigest, item.ApprovedPlanHash, nullableUUID(item.ApprovalID), item.ProviderID,
		item.IntentOrigin, item.OriginScopeDigest,
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
	dependencies, err := parseResourceDependencies(item.DependsOn)
	if err != nil {
		return resource.ErrInvalid
	}
	result, err := tx.Exec(ctx, `
		UPDATE cloud_resources SET
			provider_id=$4, intent_origin=$5, origin_scope_digest=$6, provider_candidate_ids=$7, depends_on=$8,
			retention=$9, destroy_deadline=$10, auto_destroy_approved=$11, tags=$12, state=$13,
			intent_operation=$14, intent_client_token=$15, intent_recorded_at=$16,
			readback_exists=$17, provider_create_started_at=$18, readback_provider_id=$19, readback_observed_at=$20,
			readback_tag_digest=$21, blocked_reason=$22, revision=$23, updated_at=$24
		WHERE resource_id=$1 AND agent_instance_id=$2 AND revision=$3`,
		item.ResourceID, instanceID, expectedRevision, item.ProviderID, item.IntentOrigin, item.OriginScopeDigest,
		nonNilStrings(item.ProviderCandidateIDs), dependencies, item.Retention,
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
	switch item.IntentOrigin {
	case "":
		if item.OriginScopeDigest != "" || item.Tags[resource.TagIntentOrigin] != "" || item.Tags[resource.TagOriginScopeDigest] != "" {
			return resource.ErrInvalid
		}
	case resource.IntentOriginManagedPreparation:
		if !resourceSHA256Pattern.MatchString(item.OriginScopeDigest) || (item.Type != resource.TypeSnapshot && item.Type != resource.TypeEBS) ||
			item.Tags[resource.TagIntentOrigin] != string(item.IntentOrigin) || item.Tags[resource.TagOriginScopeDigest] != item.OriginScopeDigest {
			return resource.ErrInvalid
		}
	default:
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
		left.IntentOrigin == right.IntentOrigin && left.OriginScopeDigest == right.OriginScopeDigest &&
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
