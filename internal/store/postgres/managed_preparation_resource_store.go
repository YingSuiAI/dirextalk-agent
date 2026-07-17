package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ resource.ManagedPreparationRepository = (*ResourceStore)(nil)

func (store *ResourceStore) CommitManagedPreparationSwap(
	ctx context.Context,
	request resource.ManagedPreparationSwapRequest,
	at time.Time,
) (resource.ManagedPreparationSwapRecord, resource.ResourceV1, error) {
	if store == nil || store.pool == nil || ctx == nil || request.Validate() != nil || at.IsZero() {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrInvalid
	}
	at = at.UTC().Truncate(time.Microsecond)
	if request.AttachmentObservedAt.UTC().After(at) {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrInvalid
	}
	ids, err := parseManagedPreparationIDs(request.OperationID, request.DeploymentID, request.EC2ResourceID,
		request.SourceResourceID, request.SnapshotResourceID, request.ReplacementResourceID)
	if err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, fmt.Errorf("begin managed preparation swap: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"managed-preparation-swap:"+ids[0].String()+":"+ids[3].String()); err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, fmt.Errorf("lock managed preparation swap: %w", err)
	}

	var scopeDigest string
	if err := tx.QueryRow(ctx, managedPreparationSwapAuthorizationSQL,
		store.instanceID, request.OwnerID, ids[0], ids[1], ids[2], ids[3], ids[4], ids[5],
		request.InstanceID, request.ReplacementVolumeID, request.DeviceName, request.AttachmentObservedAt.UTC(),
	).Scan(&scopeDigest); errors.Is(err, pgx.ErrNoRows) {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrRevisionConflict
	} else if err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, fmt.Errorf("authorize managed preparation swap: %w", err)
	}

	values, err := listResourcesTx(ctx, tx, ids[1], store.instanceID, true)
	if err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
	}
	byID := resourcesByID(values)
	ec2, source, snapshot, replacement := byID[request.EC2ResourceID], byID[request.SourceResourceID], byID[request.SnapshotResourceID], byID[request.ReplacementResourceID]
	if !exactManagedPreparationSwapResources(ec2, source, snapshot, replacement, request, scopeDigest) {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrRevisionConflict
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO managed_preparation_resource_swaps (
			operation_id, agent_instance_id, owner_id, deployment_id, ec2_resource_id,
			source_resource_id, snapshot_resource_id, replacement_resource_id, device_name,
			attachment_evidence_digest, attachment_observed_at, status, revision, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'intent',1,$12,$12)
		ON CONFLICT (operation_id, source_resource_id) DO NOTHING`,
		ids[0], store.instanceID, request.OwnerID, ids[1], ids[2], ids[3], ids[4], ids[5], request.DeviceName,
		request.AttachmentEvidenceDigest, request.AttachmentObservedAt.UTC(), at,
	); err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, fmt.Errorf("persist managed preparation swap intent: %w", err)
	}
	record, err := loadManagedPreparationSwapForUpdate(ctx, tx, ids[0], ids[3])
	if err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
	}
	if !sameManagedPreparationSwap(record, request, store.instanceID.String()) {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrRevisionConflict
	}

	sourceIndex, replacementIndex := dependencyIndexes(ec2.DependsOn, request.SourceResourceID, request.ReplacementResourceID)
	switch {
	case record.Status == "intent" && sourceIndex >= 0 && replacementIndex < 0:
		expected := ec2.Revision
		ec2.DependsOn[sourceIndex] = request.ReplacementResourceID
		ec2.Revision++
		ec2.UpdatedAt = at
		if err := store.validateResource(ec2); err != nil {
			return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
		}
		if err := saveResourceTx(ctx, tx, store.instanceID, expected, ec2); err != nil {
			return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
		}
		result, err := tx.Exec(ctx, `
			UPDATE managed_preparation_resource_swaps
			SET status='swapped', revision=revision+1, updated_at=$3
			WHERE operation_id=$1 AND source_resource_id=$2 AND status='intent'`,
			ids[0], ids[3], at,
		)
		if err != nil {
			return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, fmt.Errorf("complete managed preparation swap: %w", err)
		}
		if result.RowsAffected() != 1 {
			return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrRevisionConflict
		}
	case record.Status == "swapped" && sourceIndex < 0 && replacementIndex >= 0:
		// Exact response-loss replay.
	default:
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrRevisionConflict
	}

	record, err = loadManagedPreparationSwapForUpdate(ctx, tx, ids[0], ids[3])
	if err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
	}
	ec2, err = loadResourceForUpdate(ctx, tx, ids[2], store.instanceID)
	if err != nil || record.Status != "swapped" || !reflect.DeepEqual(ec2.DependsOn, replaceDependency(valuesByID(values, request.EC2ResourceID).DependsOn, request.SourceResourceID, request.ReplacementResourceID)) {
		if err != nil {
			return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, err
		}
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ManagedPreparationSwapRecord{}, resource.ResourceV1{}, fmt.Errorf("commit managed preparation swap: %w", err)
	}
	return record, ec2, nil
}

func (store *ResourceStore) BeginManagedPreparationRetire(
	ctx context.Context,
	request resource.ManagedPreparationRetireRequest,
	at time.Time,
) (resource.ResourceV1, error) {
	if store == nil || store.pool == nil || ctx == nil || request.Validate() != nil || at.IsZero() {
		return resource.ResourceV1{}, resource.ErrInvalid
	}
	at = at.UTC().Truncate(time.Microsecond)
	ids, err := parseManagedPreparationIDs(request.OperationID, request.DeploymentID, request.ResourceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("begin managed preparation retirement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"managed-preparation-retire:"+ids[0].String()+":"+ids[2].String()); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("lock managed preparation retirement: %w", err)
	}

	var ec2ID, replacementID uuid.UUID
	var scopeDigest string
	if err := tx.QueryRow(ctx, managedPreparationRetireAuthorizationSQL,
		store.instanceID, request.OwnerID, ids[0], ids[1], ids[2],
	).Scan(&ec2ID, &replacementID, &scopeDigest); errors.Is(err, pgx.ErrNoRows) {
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	} else if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("authorize managed preparation retirement: %w", err)
	}
	values, err := listResourcesTx(ctx, tx, ids[1], store.instanceID, true)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	byID := resourcesByID(values)
	source, ec2, replacement := byID[request.ResourceID], byID[ec2ID.String()], byID[replacementID.String()]
	if source.ResourceID == "" || ec2.ResourceID == "" || source.OwnerID != request.OwnerID ||
		source.DeploymentID != request.DeploymentID || source.Type != resource.TypeEBS ||
		ec2.OwnerID != request.OwnerID || ec2.DeploymentID != request.DeploymentID ||
		ec2.Type != resource.TypeEC2 || ec2.State != resource.StateActive ||
		replacement.OwnerID != request.OwnerID || replacement.DeploymentID != request.DeploymentID ||
		replacement.Type != resource.TypeEBS || replacement.State != resource.StateActive ||
		replacement.IntentOrigin != resource.IntentOriginManagedPreparation ||
		replacement.OriginScopeDigest != scopeDigest || replacement.ApprovalID != request.OperationID ||
		containsString(ec2.DependsOn, request.ResourceID) || !containsString(ec2.DependsOn, replacementID.String()) {
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	token := managedPreparationRetireToken(request.OperationID)
	switch source.State {
	case resource.StateActive:
		expected := source.Revision
		source.State = resource.StateDestroying
		source.Intent = resource.MutationIntent{
			Operation: resource.MutationDestroy, ClientToken: token, RecordedAt: at,
		}
		source.ReadBack = resource.ReadBackEvidence{}
		source.Revision++
		source.UpdatedAt = at
		if err := store.validateResource(source); err != nil {
			return resource.ResourceV1{}, err
		}
		if err := saveResourceTx(ctx, tx, store.instanceID, expected, source); err != nil {
			return resource.ResourceV1{}, err
		}
	case resource.StateDestroying:
		if source.Intent.Operation != resource.MutationDestroy || source.Intent.ClientToken != token {
			return resource.ResourceV1{}, resource.ErrRevisionConflict
		}
	case resource.StateVerifiedDestroyed:
		if source.Intent.Operation != resource.MutationDestroy || source.Intent.ClientToken != token || source.ReadBack.Exists {
			return resource.ResourceV1{}, resource.ErrRevisionConflict
		}
	default:
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("commit managed preparation retirement intent: %w", err)
	}
	return source, nil
}

func (store *ResourceStore) CompleteManagedPreparationRetire(
	ctx context.Context,
	request resource.ManagedPreparationRetireRequest,
	evidence resource.ReadBackEvidence,
	at time.Time,
) (resource.ResourceV1, error) {
	if store == nil || store.pool == nil || ctx == nil || request.Validate() != nil || at.IsZero() ||
		evidence.Exists || evidence.ObservedAt.IsZero() || evidence.ObservedAt.After(at) {
		return resource.ResourceV1{}, resource.ErrInvalid
	}
	ids, err := parseManagedPreparationIDs(request.OperationID, request.DeploymentID, request.ResourceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ResourceV1{}, fmt.Errorf("begin managed preparation retirement completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	item, err := loadResourceForUpdate(ctx, tx, ids[2], store.instanceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	token := managedPreparationRetireToken(request.OperationID)
	if item.OwnerID != request.OwnerID || item.DeploymentID != request.DeploymentID ||
		item.Intent.Operation != resource.MutationDestroy || item.Intent.ClientToken != token ||
		evidence.ProviderID != item.ProviderID || evidence.ObservedAt.Before(item.Intent.RecordedAt) {
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	if item.State == resource.StateVerifiedDestroyed {
		if !reflect.DeepEqual(item.ReadBack, evidence) {
			return resource.ResourceV1{}, resource.ErrRevisionConflict
		}
		return item, tx.Commit(ctx)
	}
	if item.State != resource.StateDestroying {
		return resource.ResourceV1{}, resource.ErrRevisionConflict
	}
	expected := item.Revision
	item.State = resource.StateVerifiedDestroyed
	item.ReadBack = evidence
	item.ProviderCandidateIDs = nil
	item.BlockedReason = ""
	item.Revision++
	item.UpdatedAt = at.UTC().Truncate(time.Microsecond)
	if err := store.validateResource(item); err != nil {
		return resource.ResourceV1{}, err
	}
	if err := saveResourceTx(ctx, tx, store.instanceID, expected, item); err != nil {
		return resource.ResourceV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ResourceV1{}, fmt.Errorf("commit managed preparation retirement completion: %w", err)
	}
	return item, nil
}

const managedPreparationSwapAuthorizationSQL = `
	SELECT operation.scope_digest
	FROM cloud_service_operations AS operation
	JOIN cloud_service_operation_steps AS step
	  ON step.operation_id=operation.operation_id AND step.phase='restore_swap'
	JOIN LATERAL jsonb_array_elements(operation.challenge_json->'scope'->'volumes') AS volume ON true
	JOIN cloud_resources AS ec2
	  ON ec2.resource_id=(operation.challenge_json->'scope'->'ec2'->>'resource_id')::uuid
	JOIN cloud_resources AS source
	  ON source.resource_id=(volume->'source_volume'->>'resource_id')::uuid
	JOIN cloud_resources AS snapshot
	  ON snapshot.resource_id=(volume->>'snapshot_resource_id')::uuid
	JOIN cloud_resources AS replacement
	  ON replacement.resource_id=(volume->>'replacement_volume_resource_id')::uuid
	WHERE operation.operation_id=$3
	  AND operation.agent_instance_id=$1
	  AND operation.owner_id=$2
	  AND operation.deployment_id=$4
	  AND operation.status='running'
	  AND operation.current_phase='restore_swap'
	  AND operation.signature IS NOT NULL
	  AND operation.approved_at IS NOT NULL
	  AND operation.scope_digest=operation.challenge_json->>'scope_digest'
	  AND step.status='running'
	  AND step.started_at<=$12
	  AND operation.challenge_json->'scope'->'ec2'->>'resource_id'=$5::text
	  AND operation.challenge_json->'scope'->'ec2'->>'provider_id'=$9
	  AND volume->'source_volume'->>'resource_id'=$6::text
	  AND volume->>'snapshot_resource_id'=$7::text
	  AND volume->>'replacement_volume_resource_id'=$8::text
	  AND volume->>'device_name'=$11
	  AND ec2.agent_instance_id=$1
	  AND ec2.owner_id=$2
	  AND ec2.deployment_id=$4
	  AND ec2.resource_type='ec2'
	  AND ec2.provider_id=$9
	  AND (
	    ec2.revision=(operation.challenge_json->'scope'->'ec2'->>'revision')::bigint
	    OR EXISTS (
	      SELECT 1 FROM managed_preparation_resource_swaps AS replay
	      WHERE replay.operation_id=operation.operation_id
	        AND replay.source_resource_id=(volume->'source_volume'->>'resource_id')::uuid
	        AND replay.replacement_resource_id=(volume->>'replacement_volume_resource_id')::uuid
	        AND replay.status='swapped'
	    )
	  )
	  AND ec2.spec_digest=operation.challenge_json->'scope'->'ec2'->>'spec_digest'
	  AND ec2.readback_tag_digest=operation.challenge_json->'scope'->'ec2'->>'tag_digest'
	  AND ec2.state='active'
	  AND source.agent_instance_id=$1
	  AND source.owner_id=$2
	  AND source.deployment_id=$4
	  AND source.resource_type='ebs'
	  AND source.provider_id=volume->'source_volume'->>'provider_id'
	  AND source.revision=(volume->'source_volume'->>'revision')::bigint
	  AND source.spec_digest=volume->'source_volume'->>'spec_digest'
	  AND source.readback_tag_digest=volume->'source_volume'->>'tag_digest'
	  AND source.state='active'
	  AND snapshot.agent_instance_id=$1
	  AND snapshot.owner_id=$2
	  AND snapshot.deployment_id=$4
	  AND snapshot.resource_type='snapshot'
	  AND snapshot.intent_origin='managed_preparation'
	  AND snapshot.origin_scope_digest=operation.scope_digest
	  AND snapshot.approval_id=operation.operation_id
	  AND snapshot.depends_on=ARRAY[source.resource_id]::uuid[]
	  AND snapshot.state='active'
	  AND replacement.agent_instance_id=$1
	  AND replacement.owner_id=$2
	  AND replacement.deployment_id=$4
	  AND replacement.resource_type='ebs'
	  AND replacement.intent_origin='managed_preparation'
	  AND replacement.origin_scope_digest=operation.scope_digest
	  AND replacement.approval_id=operation.operation_id
	  AND replacement.provider_id=$10
	  AND replacement.depends_on=ARRAY[snapshot.resource_id]::uuid[]
	  AND replacement.state='active'
	FOR UPDATE OF operation, step, ec2, source, snapshot, replacement`

const managedPreparationRetireAuthorizationSQL = `
	SELECT (operation.challenge_json->'scope'->'ec2'->>'resource_id')::uuid,
	       (volume->>'replacement_volume_resource_id')::uuid,
	       operation.scope_digest
	FROM cloud_service_operations AS operation
	JOIN cloud_service_operation_steps AS health
	  ON health.operation_id=operation.operation_id AND health.phase='semantic_health'
	JOIN cloud_service_operation_steps AS swap
	  ON swap.operation_id=operation.operation_id AND swap.phase='restore_swap'
	JOIN cloud_service_operation_steps AS finalize
	  ON finalize.operation_id=operation.operation_id AND finalize.phase='finalize'
	JOIN LATERAL jsonb_array_elements(operation.challenge_json->'scope'->'volumes') AS volume ON true
	JOIN managed_preparation_resource_swaps AS ledger_swap
	  ON ledger_swap.operation_id=operation.operation_id
	 AND ledger_swap.source_resource_id=(volume->'source_volume'->>'resource_id')::uuid
	WHERE operation.operation_id=$3
	  AND operation.agent_instance_id=$1
	  AND operation.owner_id=$2
	  AND operation.deployment_id=$4
	  AND operation.status='running'
	  AND operation.current_phase='finalize'
	  AND operation.signature IS NOT NULL
	  AND operation.approved_at IS NOT NULL
	  AND health.status='succeeded'
	  AND health.started_at>ledger_swap.attachment_observed_at
	  AND health.completed_at IS NOT NULL
	  AND swap.status='succeeded'
	  AND swap.completed_at>=ledger_swap.attachment_observed_at
	  AND finalize.status='running'
	  AND ledger_swap.agent_instance_id=$1
	  AND ledger_swap.owner_id=$2
	  AND ledger_swap.deployment_id=$4
	  AND ledger_swap.status='swapped'
	  AND ledger_swap.ec2_resource_id=(operation.challenge_json->'scope'->'ec2'->>'resource_id')::uuid
	  AND volume->'source_volume'->>'resource_id'=$5::text
	  AND ledger_swap.snapshot_resource_id=(volume->>'snapshot_resource_id')::uuid
	  AND ledger_swap.replacement_resource_id=(volume->>'replacement_volume_resource_id')::uuid
	FOR UPDATE OF operation, health, swap, finalize, ledger_swap`

func loadManagedPreparationSwapForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	operationID, sourceID uuid.UUID,
) (resource.ManagedPreparationSwapRecord, error) {
	var record resource.ManagedPreparationSwapRecord
	var operation, agent, deployment, ec2, source, snapshot, replacement uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT operation_id, agent_instance_id, owner_id, deployment_id, ec2_resource_id,
		       source_resource_id, snapshot_resource_id, replacement_resource_id, device_name,
		       attachment_evidence_digest, attachment_observed_at, status, revision, created_at, updated_at
		FROM managed_preparation_resource_swaps
		WHERE operation_id=$1 AND source_resource_id=$2
		FOR UPDATE`,
		operationID, sourceID,
	).Scan(&operation, &agent, &record.OwnerID, &deployment, &ec2, &source, &snapshot, &replacement,
		&record.DeviceName, &record.AttachmentEvidenceDigest, &record.AttachmentObservedAt, &record.Status,
		&record.Revision, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return resource.ManagedPreparationSwapRecord{}, resource.ErrNotFound
		}
		return resource.ManagedPreparationSwapRecord{}, fmt.Errorf("load managed preparation swap: %w", err)
	}
	record.OperationID, record.AgentInstanceID, record.DeploymentID = operation.String(), agent.String(), deployment.String()
	record.EC2ResourceID, record.SourceResourceID = ec2.String(), source.String()
	record.SnapshotResourceID, record.ReplacementResourceID = snapshot.String(), replacement.String()
	record.AttachmentObservedAt = record.AttachmentObservedAt.UTC()
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	return record, nil
}

func exactManagedPreparationSwapResources(
	ec2, source, snapshot, replacement resource.ResourceV1,
	request resource.ManagedPreparationSwapRequest,
	scopeDigest string,
) bool {
	if ec2.ResourceID == "" || source.ResourceID == "" || snapshot.ResourceID == "" || replacement.ResourceID == "" ||
		ec2.OwnerID != request.OwnerID || source.OwnerID != request.OwnerID ||
		snapshot.OwnerID != request.OwnerID || replacement.OwnerID != request.OwnerID ||
		ec2.DeploymentID != request.DeploymentID || source.DeploymentID != request.DeploymentID ||
		snapshot.DeploymentID != request.DeploymentID || replacement.DeploymentID != request.DeploymentID ||
		ec2.Type != resource.TypeEC2 || source.Type != resource.TypeEBS ||
		snapshot.Type != resource.TypeSnapshot || replacement.Type != resource.TypeEBS ||
		ec2.State != resource.StateActive || source.State != resource.StateActive ||
		snapshot.State != resource.StateActive || replacement.State != resource.StateActive ||
		ec2.ProviderID != request.InstanceID || replacement.ProviderID != request.ReplacementVolumeID {
		return false
	}
	for _, item := range []resource.ResourceV1{snapshot, replacement} {
		if item.IntentOrigin != resource.IntentOriginManagedPreparation ||
			item.OriginScopeDigest != scopeDigest || item.ApprovalID != request.OperationID ||
			item.ApprovedPlanHash != source.ApprovedPlanHash ||
			item.Retention != source.Retention || item.AutoDestroyApproved != source.AutoDestroyApproved ||
			!item.DestroyDeadline.Equal(source.DestroyDeadline) {
			return false
		}
	}
	return reflect.DeepEqual(snapshot.DependsOn, []string{source.ResourceID}) &&
		reflect.DeepEqual(replacement.DependsOn, []string{snapshot.ResourceID})
}

func sameManagedPreparationSwap(record resource.ManagedPreparationSwapRecord, request resource.ManagedPreparationSwapRequest, agentID string) bool {
	return record.OperationID == request.OperationID && record.AgentInstanceID == agentID &&
		record.OwnerID == request.OwnerID && record.DeploymentID == request.DeploymentID &&
		record.EC2ResourceID == request.EC2ResourceID && record.SourceResourceID == request.SourceResourceID &&
		record.SnapshotResourceID == request.SnapshotResourceID && record.ReplacementResourceID == request.ReplacementResourceID &&
		record.DeviceName == request.DeviceName && record.AttachmentEvidenceDigest == request.AttachmentEvidenceDigest &&
		record.AttachmentObservedAt.Equal(request.AttachmentObservedAt.UTC())
}

func parseManagedPreparationIDs(values ...string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return nil, resource.ErrInvalid
		}
		result[index] = parsed
	}
	return result, nil
}

func resourcesByID(values []resource.ResourceV1) map[string]resource.ResourceV1 {
	result := make(map[string]resource.ResourceV1, len(values))
	for _, item := range values {
		result[item.ResourceID] = item
	}
	return result
}

func valuesByID(values []resource.ResourceV1, resourceID string) resource.ResourceV1 {
	for _, item := range values {
		if item.ResourceID == resourceID {
			return item
		}
	}
	return resource.ResourceV1{}
}

func dependencyIndexes(values []string, sourceID, replacementID string) (int, int) {
	sourceIndex, replacementIndex := -1, -1
	for index, value := range values {
		switch value {
		case sourceID:
			if sourceIndex >= 0 {
				return -2, replacementIndex
			}
			sourceIndex = index
		case replacementID:
			if replacementIndex >= 0 {
				return sourceIndex, -2
			}
			replacementIndex = index
		}
	}
	return sourceIndex, replacementIndex
}

func replaceDependency(values []string, sourceID, replacementID string) []string {
	result := append([]string(nil), values...)
	for index, value := range result {
		if value == sourceID {
			result[index] = replacementID
		}
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func managedPreparationRetireToken(operationID string) string {
	return "managed-preparation-retire:" + strings.TrimSpace(operationID)
}
