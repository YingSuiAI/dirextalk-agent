package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managedlifecycle"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ManagedKnowledgeLifecycleStore struct {
	store *Store
}

var (
	_ managedlifecycle.Repository   = (*ManagedKnowledgeLifecycleStore)(nil)
	_ managedlifecycle.ScopeBuilder = (*ManagedKnowledgeLifecycleStore)(nil)
)

func NewManagedKnowledgeLifecycleStore(store *Store) (*ManagedKnowledgeLifecycleStore, error) {
	if store == nil || store.pool == nil || store.instanceID == uuid.Nil {
		return nil, managedlifecycle.ErrInvalid
	}
	return &ManagedKnowledgeLifecycleStore{store: store}, nil
}

func (store *ManagedKnowledgeLifecycleStore) BuildManagedKnowledgeLifecycleScope(
	ctx context.Context, ownerID, deploymentID, serviceID string, action managedlifecycle.Action,
) (managedlifecycle.ScopeV1, error) {
	if ctx == nil || !action.Valid() {
		return managedlifecycle.ScopeV1{}, managedlifecycle.ErrInvalid
	}
	var (
		deploymentRevision, serviceRevision, bindingRevision                  int64
		bindingID, storedOwner, storedDeployment, storedService, recipeDigest string
		executionDigest                                                       []byte
		challengeJSON, contractJSON                                           []byte
	)
	err := store.store.pool.QueryRow(ctx, `SELECT
			k.binding_id::text,k.owner_id,k.deployment_id::text,k.managed_service_id::text,k.recipe_digest,k.revision,
			d.revision,d.execution_bundle_sha256,m.revision,m.contract_json,a.challenge_json
		FROM knowledge_configs k
		JOIN worker_deployments d ON d.agent_instance_id=k.agent_instance_id AND d.deployment_id=k.deployment_id
			AND d.owner_id=k.owner_id
		JOIN managed_services m ON m.agent_instance_id=k.agent_instance_id AND m.service_id=k.managed_service_id
			AND m.deployment_id=k.deployment_id AND m.owner_id=k.owner_id
		JOIN cloud_managed_acceptance_operations a ON a.agent_instance_id=k.agent_instance_id
			AND a.owner_id=k.owner_id AND a.deployment_id=k.deployment_id
			AND a.operation_id=(m.contract_json->>'AcceptanceApprovalID')::uuid
			AND a.challenge_json->'scope'->>'service_id'=m.service_id::text
		WHERE k.agent_instance_id=$1 AND k.owner_id=$2 AND k.deployment_id=$3 AND k.managed_service_id=$4
			AND k.enabled=true AND a.status='succeeded' AND m.state <> 'destroyed'`,
		store.store.instanceID, ownerID, deploymentID, serviceID,
	).Scan(&bindingID, &storedOwner, &storedDeployment, &storedService, &recipeDigest, &bindingRevision,
		&deploymentRevision, &executionDigest, &serviceRevision, &contractJSON, &challengeJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return managedlifecycle.ScopeV1{}, managedlifecycle.ErrNotFound
	}
	if err != nil {
		return managedlifecycle.ScopeV1{}, fmt.Errorf("read managed Knowledge lifecycle scope: %w", err)
	}
	var challenge cloudmanaged.ChallengeV1
	var contract resource.ManagedContractV1
	if json.Unmarshal(challengeJSON, &challenge) != nil || json.Unmarshal(contractJSON, &contract) != nil ||
		challenge.Scope.Validate() != nil || contract.Validate() != nil ||
		challenge.Scope.OwnerID != storedOwner || challenge.Scope.DeploymentID != storedDeployment ||
		challenge.Scope.ServiceID != storedService || challenge.Scope.RecipeDigest != recipeDigest ||
		contract.AcceptanceApprovalID != challenge.Scope.AcceptanceID || contract.OwnerID != storedOwner ||
		contract.DeploymentID != storedDeployment {
		return managedlifecycle.ScopeV1{}, managedlifecycle.ErrRevisionConflict
	}
	lifecycleRef := lifecycleReference(challenge.Scope.Lifecycle, action)
	if contractRef := managedContractLifecycleReference(contract, action); contractRef != "" && lifecycleRef != contractRef {
		return managedlifecycle.ScopeV1{}, managedlifecycle.ErrRevisionConflict
	}
	value := managedlifecycle.ScopeV1{
		SchemaVersion: managedlifecycle.ScopeSchemaV1, AgentInstanceID: store.store.instanceID.String(),
		OwnerID: storedOwner, DeploymentID: storedDeployment, ManagedServiceID: storedService,
		KnowledgeBindingID: bindingID, DeploymentRevision: deploymentRevision,
		ManagedServiceRevision: serviceRevision, KnowledgeBindingRevision: bindingRevision,
		RecipeDigest: recipeDigest, Action: action, LifecycleRef: lifecycleRef,
		ExecutionBundleDigest:   "sha256:" + hex.EncodeToString(executionDigest),
		InstalledManifestDigest: challenge.Scope.InstalledManifestDigest,
	}
	if value.Validate() != nil {
		return managedlifecycle.ScopeV1{}, managedlifecycle.ErrRevisionConflict
	}
	return value, nil
}

func managedContractLifecycleReference(value resource.ManagedContractV1, action managedlifecycle.Action) string {
	switch action {
	case managedlifecycle.ActionBackup:
		return value.BackupRef
	case managedlifecycle.ActionRestore:
		return value.RestoreRef
	case managedlifecycle.ActionUpgrade:
		return value.UpgradeRef
	case managedlifecycle.ActionRollback:
		return value.RollbackRef
	case managedlifecycle.ActionDestroy:
		return value.DestroyRef
	default:
		return ""
	}
}

func lifecycleReference(value cloudmanaged.LifecycleV1, action managedlifecycle.Action) string {
	switch action {
	case managedlifecycle.ActionStop:
		return value.Stop
	case managedlifecycle.ActionBackup:
		return value.Backup
	case managedlifecycle.ActionRestore:
		return value.Restore
	case managedlifecycle.ActionUpgrade:
		return value.Upgrade
	case managedlifecycle.ActionRollback:
		return value.Rollback
	case managedlifecycle.ActionDestroy:
		return value.Destroy
	default:
		return ""
	}
}

func (store *ManagedKnowledgeLifecycleStore) CreateChallenge(ctx context.Context, mutation managedlifecycle.Mutation, challenge managedlifecycle.ChallengeV1) (managedlifecycle.ChallengeV1, error) {
	if ctx == nil || mutation.Validate() != nil || challenge.Validate() != nil ||
		challenge.Scope.AgentInstanceID != store.store.instanceID.String() {
		return managedlifecycle.ChallengeV1{}, managedlifecycle.ErrInvalid
	}
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managedlifecycle.ChallengeV1{}, fmt.Errorf("begin managed Knowledge lifecycle prepare: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, err := readManagedLifecycleReplay[managedlifecycle.ChallengeV1](ctx, tx, "prepare", mutation, ""); err != nil {
		return managedlifecycle.ChallengeV1{}, err
	} else if found {
		if err := tx.Commit(ctx); err != nil {
			return managedlifecycle.ChallengeV1{}, err
		}
		return replay, nil
	}
	now := challenge.IssuedAt.UTC()
	operation := managedlifecycle.OperationV1{Challenge: challenge, Status: managedlifecycle.StatusAwaitingApproval,
		Revision: 1, CreatedAt: now, UpdatedAt: now}
	snapshot, err := json.Marshal(operation)
	if err != nil || operation.Validate() != nil {
		return managedlifecycle.ChallengeV1{}, managedlifecycle.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `INSERT INTO managed_knowledge_lifecycle_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,managed_service_id,knowledge_binding_id,action,status,
		 worker_operation_id,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,1,$9,$10,$10) ON CONFLICT DO NOTHING`,
		challenge.OperationID, store.store.instanceID, challenge.Scope.OwnerID, challenge.Scope.DeploymentID,
		challenge.Scope.ManagedServiceID, challenge.Scope.KnowledgeBindingID, challenge.Scope.Action,
		managedlifecycle.StatusAwaitingApproval, snapshot, now)
	if err != nil {
		return managedlifecycle.ChallengeV1{}, fmt.Errorf("insert managed Knowledge lifecycle challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return managedlifecycle.ChallengeV1{}, managedlifecycle.ErrIdempotencyConflict
	}
	if err := insertManagedLifecycleReplay(ctx, tx, challenge.OperationID, "prepare", mutation, challenge.Revision, challenge); err != nil {
		return managedlifecycle.ChallengeV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return managedlifecycle.ChallengeV1{}, err
	}
	return challenge, nil
}

func (store *ManagedKnowledgeLifecycleStore) GetChallenge(ctx context.Context, ownerID, challengeID string) (managedlifecycle.ChallengeV1, error) {
	value, err := store.get(ctx, `owner_id=$2 AND snapshot_json->'Challenge'->>'ChallengeID'=$3`, ownerID, challengeID)
	return value.Challenge, err
}

func (store *ManagedKnowledgeLifecycleStore) Approve(ctx context.Context, mutation managedlifecycle.Mutation, signature managedlifecycle.SignatureV1, workerID string, at time.Time) (managedlifecycle.OperationV1, error) {
	if ctx == nil || mutation.Validate() != nil || !managedlifecycle.CanonicalUUID(workerID) || at.IsZero() {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managedlifecycle.OperationV1{}, fmt.Errorf("begin managed Knowledge lifecycle approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, err := readManagedLifecycleReplay[managedlifecycle.OperationV1](ctx, tx, "approve", mutation, ""); err != nil {
		return managedlifecycle.OperationV1{}, err
	} else if found {
		if err := tx.Commit(ctx); err != nil {
			return managedlifecycle.OperationV1{}, err
		}
		return replay, nil
	}
	current, err := scanManagedLifecycleOperation(tx.QueryRow(ctx, managedLifecycleSelect+
		` WHERE agent_instance_id=$1 AND owner_id=$2 AND snapshot_json->'Challenge'->>'ChallengeID'=$3 FOR UPDATE`,
		store.store.instanceID, mutation.OwnerID, signature.ChallengeID))
	if err != nil {
		return managedlifecycle.OperationV1{}, err
	}
	if current.Status != managedlifecycle.StatusAwaitingApproval || current.Revision != 1 ||
		current.Challenge.ChallengeID != signature.ChallengeID || current.Challenge.ApprovalID != signature.ApprovalID {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
	}
	scope := current.Challenge.Scope
	var deploymentRevision, serviceRevision, bindingRevision int64
	var executionDigest []byte
	var recipeDigest string
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT d.revision,d.execution_bundle_sha256,m.revision,k.revision,k.recipe_digest,k.enabled
		FROM worker_deployments d
		JOIN managed_services m ON m.agent_instance_id=d.agent_instance_id AND m.deployment_id=d.deployment_id
			AND m.service_id=$3 AND m.owner_id=d.owner_id AND m.state <> 'destroyed'
		JOIN knowledge_configs k ON k.agent_instance_id=d.agent_instance_id AND k.owner_id=d.owner_id
			AND k.deployment_id=d.deployment_id AND k.managed_service_id=m.service_id AND k.binding_id=$4
		WHERE d.agent_instance_id=$1 AND d.deployment_id=$2 AND d.owner_id=$5
		FOR SHARE OF d,m,k`,
		store.store.instanceID, scope.DeploymentID, scope.ManagedServiceID, scope.KnowledgeBindingID, scope.OwnerID,
	).Scan(&deploymentRevision, &executionDigest, &serviceRevision, &bindingRevision, &recipeDigest, &enabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
		}
		return managedlifecycle.OperationV1{}, fmt.Errorf("fence managed Knowledge lifecycle approval: %w", err)
	}
	if !enabled || deploymentRevision != scope.DeploymentRevision || serviceRevision != scope.ManagedServiceRevision ||
		bindingRevision != scope.KnowledgeBindingRevision || recipeDigest != scope.RecipeDigest ||
		"sha256:"+hex.EncodeToString(executionDigest) != scope.ExecutionBundleDigest {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
	}
	approved := at.UTC()
	next := current
	next.Status, next.WorkerOperationID, next.Revision, next.UpdatedAt, next.ApprovedAt =
		managedlifecycle.StatusScheduled, workerID, 2, approved, &approved
	if next.Validate() != nil {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	worker := workeroperation.Operation{
		SchemaVersion: workeroperation.SchemaV1, OperationID: workerID,
		DeploymentID: next.Challenge.Scope.DeploymentID, OwnerID: next.Challenge.Scope.OwnerID,
		Action: workeroperation.Action(next.Challenge.Scope.Action), LifecycleRestartRef: next.Challenge.Scope.LifecycleRef,
		ExecutionBundleDigest:            next.Challenge.Scope.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  next.Challenge.Scope.InstalledManifestDigest,
		ExpectedDeploymentRevision:       next.Challenge.Scope.DeploymentRevision,
		ExpectedManagedServiceRevision:   next.Challenge.Scope.ManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: next.Challenge.Scope.KnowledgeBindingRevision,
		State:                            workeroperation.StatePending, Revision: 1, CreatedAt: approved, UpdatedAt: approved,
	}
	workerSnapshot, err := json.Marshal(worker)
	if err != nil || worker.Validate() != nil {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO worker_service_operations
		(operation_id,agent_instance_id,deployment_id,owner_id,action,lifecycle_restart_ref,execution_bundle_digest,
		 expected_installed_manifest_digest,state,worker_id,lease_epoch,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,0,1,$10,$11,$11)`,
		worker.OperationID, store.store.instanceID, worker.DeploymentID, worker.OwnerID, worker.Action,
		worker.LifecycleRestartRef, worker.ExecutionBundleDigest, worker.ExpectedInstalledManifestDigest,
		worker.State, workerSnapshot, approved); err != nil {
		if isUniqueViolation(err) {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrIdempotencyConflict
		}
		return managedlifecycle.OperationV1{}, fmt.Errorf("insert managed lifecycle Worker operation: %w", err)
	}
	snapshot, _ := json.Marshal(next)
	tag, err := tx.Exec(ctx, `UPDATE managed_knowledge_lifecycle_operations SET
		status=$1,worker_operation_id=$2,revision=$3,snapshot_json=$4,updated_at=$5
		WHERE operation_id=$6 AND agent_instance_id=$7 AND revision=1 AND status='awaiting_approval'`,
		next.Status, workerID, next.Revision, snapshot, approved, next.Challenge.OperationID, store.store.instanceID)
	if err != nil || tag.RowsAffected() != 1 {
		if err != nil {
			if isUniqueViolation(err) {
				return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
			}
			return managedlifecycle.OperationV1{}, fmt.Errorf("schedule managed Knowledge lifecycle: %w", err)
		}
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
	}
	if err := insertManagedLifecycleReplay(ctx, tx, next.Challenge.OperationID, "approve", mutation, next.Revision, next); err != nil {
		return managedlifecycle.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return managedlifecycle.OperationV1{}, err
	}
	return next, nil
}

func (store *ManagedKnowledgeLifecycleStore) Get(ctx context.Context, ownerID, operationID string) (managedlifecycle.OperationV1, error) {
	return store.get(ctx, `owner_id=$2 AND operation_id=$3`, ownerID, operationID)
}

func (store *ManagedKnowledgeLifecycleStore) ListActive(ctx context.Context, limit int) ([]managedlifecycle.OperationV1, error) {
	if ctx == nil || limit < 1 || limit > 100 {
		return nil, managedlifecycle.ErrInvalid
	}
	rows, err := store.store.pool.Query(ctx, managedLifecycleSelect+`
		WHERE agent_instance_id=$1 AND status IN ('scheduled','running')
		ORDER BY updated_at,operation_id LIMIT $2`, store.store.instanceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list active managed Knowledge lifecycle operations: %w", err)
	}
	defer rows.Close()
	values := make([]managedlifecycle.OperationV1, 0)
	for rows.Next() {
		value, err := scanManagedLifecycleOperation(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active managed Knowledge lifecycle operations: %w", err)
	}
	return values, nil
}

func (store *ManagedKnowledgeLifecycleStore) FenceManagedKnowledgeLifecycleExecution(
	ctx context.Context, assignment workeroperation.Assignment, at time.Time,
) error {
	if ctx == nil || at.IsZero() || assignment.Action == workeroperation.ActionRestart ||
		!assignment.Action.Valid() || assignment.ExpectedDeploymentRevision < 1 ||
		assignment.ExpectedManagedServiceRevision < 1 || assignment.ExpectedKnowledgeBindingRevision < 1 {
		return workeroperation.ErrInvalid
	}
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin managed Knowledge lifecycle execution fence: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	value, err := scanManagedLifecycleOperation(tx.QueryRow(ctx, managedLifecycleSelect+
		` WHERE agent_instance_id=$1 AND worker_operation_id=$2 FOR UPDATE`,
		store.store.instanceID, assignment.OperationID))
	if err != nil {
		return workeroperation.ErrRevisionConflict
	}
	scope := value.Challenge.Scope
	if value.Status != managedlifecycle.StatusScheduled && value.Status != managedlifecycle.StatusRunning {
		return workeroperation.ErrRevisionConflict
	}
	if assignment.DeploymentID != scope.DeploymentID || assignment.OwnerID != scope.OwnerID ||
		string(assignment.Action) != string(scope.Action) || assignment.LifecycleRestartRef != scope.LifecycleRef ||
		assignment.ExecutionBundleDigest != scope.ExecutionBundleDigest ||
		assignment.ExpectedInstalledManifestDigest != scope.InstalledManifestDigest ||
		assignment.ExpectedDeploymentRevision != scope.DeploymentRevision ||
		assignment.ExpectedManagedServiceRevision != scope.ManagedServiceRevision ||
		assignment.ExpectedKnowledgeBindingRevision != scope.KnowledgeBindingRevision {
		return workeroperation.ErrRevisionConflict
	}
	var fencedAt *time.Time
	var fencedServiceRevision *int64
	var executionDataEpoch *int64
	var catalogDigest *string
	var targetGeneration *string
	if err := tx.QueryRow(ctx, `SELECT execution_fenced_at,execution_service_revision,execution_data_epoch,
			execution_catalog_digest,target_generation_digest
		FROM managed_knowledge_lifecycle_operations
		WHERE agent_instance_id=$1 AND operation_id=$2`,
		store.store.instanceID, value.Challenge.OperationID,
	).Scan(&fencedAt, &fencedServiceRevision, &executionDataEpoch, &catalogDigest, &targetGeneration); err != nil {
		return fmt.Errorf("read managed Knowledge lifecycle execution fence: %w", err)
	}
	if fencedAt != nil || fencedServiceRevision != nil {
		if fencedAt == nil || fencedServiceRevision == nil ||
			executionDataEpoch == nil || *fencedServiceRevision != scope.ManagedServiceRevision+1 {
			return workeroperation.ErrRevisionConflict
		}
	}
	var deploymentRevision, serviceRevision, bindingRevision, dataEpoch int64
	var executionDigest []byte
	var recipeDigest string
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT d.revision,d.execution_bundle_sha256,m.revision,k.revision,k.recipe_digest,k.enabled,k.data_epoch
		FROM worker_deployments d
		JOIN managed_services m ON m.agent_instance_id=d.agent_instance_id AND m.deployment_id=d.deployment_id
			AND m.service_id=$3 AND m.owner_id=d.owner_id AND m.state <> 'destroyed'
		JOIN knowledge_configs k ON k.agent_instance_id=d.agent_instance_id AND k.owner_id=d.owner_id
			AND k.deployment_id=d.deployment_id AND k.managed_service_id=m.service_id AND k.binding_id=$4
		WHERE d.agent_instance_id=$1 AND d.deployment_id=$2 AND d.owner_id=$5
		FOR UPDATE OF d,m,k`,
		store.store.instanceID, scope.DeploymentID, scope.ManagedServiceID, scope.KnowledgeBindingID, scope.OwnerID,
	).Scan(&deploymentRevision, &executionDigest, &serviceRevision, &bindingRevision, &recipeDigest, &enabled, &dataEpoch); err != nil {
		return workeroperation.ErrRevisionConflict
	}
	expectedServiceRevision := scope.ManagedServiceRevision
	if fencedServiceRevision != nil {
		expectedServiceRevision = *fencedServiceRevision
	}
	if !enabled || deploymentRevision != scope.DeploymentRevision || serviceRevision != expectedServiceRevision ||
		bindingRevision != scope.KnowledgeBindingRevision || recipeDigest != scope.RecipeDigest ||
		"sha256:"+hex.EncodeToString(executionDigest) != scope.ExecutionBundleDigest {
		return workeroperation.ErrRevisionConflict
	}
	if fencedServiceRevision != nil {
		if executionDataEpoch == nil || *executionDataEpoch != dataEpoch {
			return workeroperation.ErrRevisionConflict
		}
		return tx.Commit(ctx)
	}
	switch scope.Action {
	case managedlifecycle.ActionBackup, managedlifecycle.ActionUpgrade:
		var digest string
		digest, err = snapshotKnowledgeCatalog(ctx, tx, value.Challenge.OperationID,
			store.store.instanceID, scope.OwnerID, scope.KnowledgeBindingID)
		catalogDigest = &digest
	case managedlifecycle.ActionRestore, managedlifecycle.ActionRollback:
		err = tx.QueryRow(ctx, `SELECT backend_generation_digest
			FROM knowledge_data_generations
			WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
			ORDER BY created_at DESC,snapshot_operation_id DESC
			LIMIT 1`,
			store.store.instanceID, scope.OwnerID, scope.KnowledgeBindingID,
		).Scan(&targetGeneration)
		if errors.Is(err, pgx.ErrNoRows) {
			return workeroperation.ErrRevisionConflict
		}
	}
	if err != nil {
		return fmt.Errorf("bind managed Knowledge lifecycle data generation: %w", err)
	}
	serviceTag, err := tx.Exec(ctx, `UPDATE managed_services SET revision=revision+1,updated_at=$1
		WHERE agent_instance_id=$2 AND service_id=$3 AND owner_id=$4 AND deployment_id=$5 AND revision=$6`,
		at.UTC(), store.store.instanceID, scope.ManagedServiceID, scope.OwnerID, scope.DeploymentID, scope.ManagedServiceRevision)
	if err != nil || serviceTag.RowsAffected() != 1 {
		return workeroperation.ErrRevisionConflict
	}
	fenceTag, err := tx.Exec(ctx, `UPDATE managed_knowledge_lifecycle_operations
		SET execution_fenced_at=$1,execution_service_revision=$2,execution_data_epoch=$3,
		    execution_catalog_digest=$4,target_generation_digest=$5
		WHERE agent_instance_id=$6 AND operation_id=$7 AND execution_fenced_at IS NULL`,
		at.UTC(), scope.ManagedServiceRevision+1, dataEpoch, catalogDigest, targetGeneration,
		store.store.instanceID, value.Challenge.OperationID)
	if err != nil || fenceTag.RowsAffected() != 1 {
		return workeroperation.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit managed Knowledge lifecycle execution fence: %w", err)
	}
	return nil
}

func (store *ManagedKnowledgeLifecycleStore) get(ctx context.Context, predicate string, args ...any) (managedlifecycle.OperationV1, error) {
	if ctx == nil {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	values := []any{store.store.instanceID}
	values = append(values, args...)
	return scanManagedLifecycleOperation(store.store.pool.QueryRow(ctx, managedLifecycleSelect+
		` WHERE agent_instance_id=$1 AND `+predicate, values...))
}

func (store *ManagedKnowledgeLifecycleStore) Transition(ctx context.Context, operationID string, expected int64, next managedlifecycle.Status, code string, at time.Time) (managedlifecycle.OperationV1, error) {
	if ctx == nil || expected < 1 || at.IsZero() {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managedlifecycle.OperationV1{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanManagedLifecycleOperation(tx.QueryRow(ctx, managedLifecycleSelect+
		` WHERE agent_instance_id=$1 AND operation_id=$2 FOR UPDATE`, store.store.instanceID, operationID))
	if err != nil {
		return managedlifecycle.OperationV1{}, err
	}
	if current.Revision != expected {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
	}
	var executionFencedAt, reservationReleasedAt *time.Time
	var executionServiceRevision, executionDataEpoch *int64
	var catalogDigest *string
	var targetGeneration *string
	if err := tx.QueryRow(ctx, `SELECT execution_fenced_at,execution_service_revision,reservation_released_at,
			execution_data_epoch,execution_catalog_digest,target_generation_digest
		FROM managed_knowledge_lifecycle_operations
		WHERE agent_instance_id=$1 AND operation_id=$2`,
		store.store.instanceID, operationID,
	).Scan(&executionFencedAt, &executionServiceRevision, &reservationReleasedAt,
		&executionDataEpoch, &catalogDigest, &targetGeneration); err != nil {
		return managedlifecycle.OperationV1{}, fmt.Errorf("read managed Knowledge lifecycle reservation: %w", err)
	}
	value := current
	value.Status, value.ErrorCode, value.Revision, value.UpdatedAt = next, code, current.Revision+1, at.UTC()
	value.RequiresNewApproval = next == managedlifecycle.StatusDestroyBlocked
	if value.Validate() != nil {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
	}
	terminal := next == managedlifecycle.StatusSucceeded || next == managedlifecycle.StatusFailed ||
		next == managedlifecycle.StatusDestroyBlocked
	if terminal && executionFencedAt != nil {
		scope := current.Challenge.Scope
		if next == managedlifecycle.StatusFailed &&
			(scope.Action == managedlifecycle.ActionRestore ||
				scope.Action == managedlifecycle.ActionRollback ||
				scope.Action == managedlifecycle.ActionUpgrade) {
			// Once a generation-changing command has crossed its execution
			// fence, an unsigned Worker failure cannot prove whether the live
			// backend is the target or the pre-swap generation. Keep the
			// operation and its mutation fence active until root-observed
			// recovery produces a signed generation receipt.
			return current, nil
		}
		if executionServiceRevision == nil || executionDataEpoch == nil || reservationReleasedAt != nil ||
			*executionServiceRevision != scope.ManagedServiceRevision+1 {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
		}
		var completedGeneration string
		recoveredOriginal := false
		if next == managedlifecycle.StatusSucceeded &&
			(scope.Action == managedlifecycle.ActionBackup || scope.Action == managedlifecycle.ActionRestore ||
				scope.Action == managedlifecycle.ActionUpgrade ||
				scope.Action == managedlifecycle.ActionRollback) {
			completedGeneration, err = store.completedKnowledgeGeneration(ctx, tx, current.WorkerOperationID)
			if err != nil {
				return managedlifecycle.OperationV1{}, err
			}
			if (scope.Action == managedlifecycle.ActionRestore || scope.Action == managedlifecycle.ActionRollback) &&
				targetGeneration == nil {
				return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
			}
			if (scope.Action == managedlifecycle.ActionRestore || scope.Action == managedlifecycle.ActionRollback) &&
				completedGeneration != *targetGeneration {
				// The installer recovered the pre-swap live generation and
				// root independently observed it. This is a safe failed
				// restore/rollback outcome: retain the fenced catalog, bind it
				// to the observed generation, then release the reservation.
				recoveredOriginal = true
				next = managedlifecycle.StatusFailed
				value.Status = managedlifecycle.StatusFailed
				value.ErrorCode = "recovered_original_generation"
				if value.Validate() != nil {
					return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
				}
			}
		}
		var currentDataEpoch int64
		var currentGeneration *string
		var currentBindingRevision int64
		if err := tx.QueryRow(ctx, `SELECT revision,data_epoch,backend_generation_digest
			FROM knowledge_configs
			WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
			  AND deployment_id=$4 AND managed_service_id=$5
			FOR UPDATE`,
			store.store.instanceID, scope.OwnerID, scope.KnowledgeBindingID,
			scope.DeploymentID, scope.ManagedServiceID,
		).Scan(&currentBindingRevision, &currentDataEpoch, &currentGeneration); err != nil ||
			currentBindingRevision != scope.KnowledgeBindingRevision || currentDataEpoch != *executionDataEpoch {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
		}
		state := ""
		if recoveredOriginal {
			state = "active"
		} else if next == managedlifecycle.StatusSucceeded {
			switch scope.Action {
			case managedlifecycle.ActionStop:
				state = "stopped"
			case managedlifecycle.ActionRestore, managedlifecycle.ActionUpgrade, managedlifecycle.ActionRollback:
				state = "active"
			case managedlifecycle.ActionDestroy:
				state = "destroyed"
			case managedlifecycle.ActionBackup:
			default:
				return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
			}
		}
		var serviceRows int64
		if state == "" {
			serviceTag, updateErr := tx.Exec(ctx, `UPDATE managed_services SET revision=revision+1,updated_at=$1
				WHERE agent_instance_id=$2 AND service_id=$3 AND owner_id=$4 AND deployment_id=$5
				  AND state <> 'destroyed' AND revision=$6`,
				value.UpdatedAt, store.store.instanceID, scope.ManagedServiceID, scope.OwnerID,
				scope.DeploymentID, *executionServiceRevision)
			err = updateErr
			serviceRows = serviceTag.RowsAffected()
		} else {
			serviceTag, updateErr := tx.Exec(ctx, `UPDATE managed_services SET state=$1,revision=revision+1,updated_at=$2
				WHERE agent_instance_id=$3 AND service_id=$4 AND owner_id=$5 AND deployment_id=$6
				  AND state <> 'destroyed' AND revision=$7`,
				state, value.UpdatedAt, store.store.instanceID, scope.ManagedServiceID, scope.OwnerID,
				scope.DeploymentID, *executionServiceRevision)
			err = updateErr
			serviceRows = serviceTag.RowsAffected()
		}
		if err != nil {
			return managedlifecycle.OperationV1{}, fmt.Errorf("advance managed service lifecycle revision: %w", err)
		}
		if serviceRows != 1 {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
		}
		enabled := true
		if next == managedlifecycle.StatusSucceeded && scope.Action == managedlifecycle.ActionDestroy {
			enabled = false
		}
		dataEpoch := currentDataEpoch
		var generation any
		if currentGeneration != nil {
			generation = *currentGeneration
		}
		if next == managedlifecycle.StatusSucceeded &&
			(scope.Action == managedlifecycle.ActionBackup || scope.Action == managedlifecycle.ActionUpgrade) {
			if catalogDigest == nil {
				return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
			}
			generation = completedGeneration
			if err := persistKnowledgeGeneration(ctx, tx, store.store.instanceID, scope.OwnerID,
				scope.KnowledgeBindingID, completedGeneration, *catalogDigest, *executionDataEpoch,
				operationID, value.UpdatedAt); err != nil {
				return managedlifecycle.OperationV1{}, err
			}
		}
		if recoveredOriginal {
			recoveredCatalogDigest, snapshotErr := snapshotKnowledgeCatalog(ctx, tx, operationID,
				store.store.instanceID, scope.OwnerID, scope.KnowledgeBindingID)
			if snapshotErr != nil {
				return managedlifecycle.OperationV1{}, snapshotErr
			}
			generation = completedGeneration
			if err := persistKnowledgeGeneration(ctx, tx, store.store.instanceID, scope.OwnerID,
				scope.KnowledgeBindingID, completedGeneration, recoveredCatalogDigest, *executionDataEpoch,
				operationID, value.UpdatedAt); err != nil {
				return managedlifecycle.OperationV1{}, err
			}
		}
		if next == managedlifecycle.StatusSucceeded &&
			(scope.Action == managedlifecycle.ActionRestore || scope.Action == managedlifecycle.ActionRollback) {
			if targetGeneration == nil {
				return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
			}
			if err := restoreKnowledgeCatalog(ctx, tx, store.store.instanceID, scope.OwnerID,
				scope.KnowledgeBindingID, *targetGeneration, scope.KnowledgeBindingRevision+1); err != nil {
				return managedlifecycle.OperationV1{}, err
			}
			dataEpoch++
			generation = completedGeneration
		}
		bindingTag, err := tx.Exec(ctx, `UPDATE knowledge_configs
			SET enabled=$1,revision=revision+1,updated_at=$2,data_epoch=$9,backend_generation_digest=$10
			WHERE agent_instance_id=$3 AND owner_id=$4 AND binding_id=$5 AND deployment_id=$6
			  AND managed_service_id=$7 AND revision=$8 AND enabled=true`,
			enabled, value.UpdatedAt, store.store.instanceID, scope.OwnerID, scope.KnowledgeBindingID,
			scope.DeploymentID, scope.ManagedServiceID, scope.KnowledgeBindingRevision, dataEpoch, generation)
		if err != nil {
			return managedlifecycle.OperationV1{}, fmt.Errorf("advance reserved Knowledge binding revision: %w", err)
		}
		if bindingTag.RowsAffected() != 1 {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
		}
		if enabled {
			if _, err := tx.Exec(ctx, `UPDATE knowledge_uploads SET binding_revision=$1
				WHERE agent_instance_id=$2 AND owner_id=$3 AND binding_id=$4 AND status='receiving'`,
				scope.KnowledgeBindingRevision+1, store.store.instanceID, scope.OwnerID, scope.KnowledgeBindingID); err != nil {
				return managedlifecycle.OperationV1{}, fmt.Errorf("reconcile Knowledge upload binding revision: %w", err)
			}
		}
		reservationReleasedAt = &value.UpdatedAt
	}
	snapshot, _ := json.Marshal(value)
	tag, err := tx.Exec(ctx, `UPDATE managed_knowledge_lifecycle_operations
		SET status=$1,revision=$2,snapshot_json=$3,updated_at=$4,reservation_released_at=$5
		WHERE agent_instance_id=$6 AND operation_id=$7 AND revision=$8`,
		value.Status, value.Revision, snapshot, value.UpdatedAt, reservationReleasedAt,
		store.store.instanceID, operationID, current.Revision)
	if err != nil || tag.RowsAffected() != 1 {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return managedlifecycle.OperationV1{}, err
	}
	return value, nil
}

const knowledgeCatalogSnapshotSchemaV1 = 1

type knowledgeCatalogSnapshot struct {
	SchemaVersion int                      `json:"schema_version"`
	Sources       []knowledgeCatalogSource `json:"sources"`
	Uploads       []knowledgeCatalogUpload `json:"uploads"`
	Chunks        []knowledgeCatalogChunk  `json:"chunks"`
}

type knowledgeCatalogSource struct {
	SourceID             uuid.UUID  `json:"source_id"`
	Kind                 string     `json:"kind"`
	Status               string     `json:"status"`
	MediaType            string     `json:"media_type"`
	Title                string     `json:"title"`
	SizeBytes            int64      `json:"size_bytes"`
	ContentSHA256        string     `json:"content_sha256"`
	BackendPointID       *uuid.UUID `json:"backend_point_id,omitempty"`
	IndexedSegments      int32      `json:"indexed_segment_count"`
	ErrorCode            string     `json:"error_code"`
	ChunkCount           int32      `json:"chunk_count"`
	Revision             int64      `json:"revision"`
	CreatedAt, UpdatedAt time.Time
}

type knowledgeCatalogUpload struct {
	SourceID, UploadID                   uuid.UUID
	Status, MediaType                    string
	DeclaredSizeBytes, ReceivedSizeBytes int64
	NextChunkOrdinal                     int32
	BindingRevision, Revision            int64
	CreatedAt, UpdatedAt                 time.Time
}

type knowledgeCatalogChunk struct {
	UploadID     uuid.UUID
	ChunkOrdinal int32
	OffsetBytes  int64
	SizeBytes    int32
	ChunkSHA256  string
	CreatedAt    time.Time
}

func persistKnowledgeGeneration(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID,
	ownerID, bindingID, backendGenerationDigest, catalogDigest string, dataEpoch int64,
	snapshotOperationID string, createdAt time.Time,
) error {
	tag, err := tx.Exec(ctx, `INSERT INTO knowledge_data_generations
		(agent_instance_id,owner_id,binding_id,backend_generation_digest,catalog_digest,
		 data_epoch,snapshot_operation_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (agent_instance_id,owner_id,binding_id,backend_generation_digest)
		DO UPDATE SET created_at=EXCLUDED.created_at
		WHERE knowledge_data_generations.data_epoch=EXCLUDED.data_epoch
		  AND knowledge_data_generations.catalog_digest=EXCLUDED.catalog_digest`,
		instanceID, ownerID, bindingID, backendGenerationDigest, catalogDigest,
		dataEpoch, snapshotOperationID, createdAt)
	if err != nil {
		return fmt.Errorf("persist Knowledge backup generation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return managedlifecycle.ErrRevisionConflict
	}
	return nil
}

func snapshotKnowledgeCatalog(ctx context.Context, tx pgx.Tx, operationID string,
	instanceID uuid.UUID, ownerID, bindingID string,
) (string, error) {
	value := knowledgeCatalogSnapshot{SchemaVersion: knowledgeCatalogSnapshotSchemaV1}
	rows, err := tx.Query(ctx, `SELECT source_id,kind,status,media_type,title,size_bytes,content_sha256,
			backend_point_id,indexed_segment_count,error_code,chunk_count,revision,created_at,updated_at
		FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
		ORDER BY source_id`, instanceID, ownerID, bindingID)
	if err != nil {
		return "", fmt.Errorf("read Knowledge source catalog snapshot: %w", err)
	}
	for rows.Next() {
		var item knowledgeCatalogSource
		if err := rows.Scan(&item.SourceID, &item.Kind, &item.Status, &item.MediaType, &item.Title,
			&item.SizeBytes, &item.ContentSHA256, &item.BackendPointID, &item.IndexedSegments,
			&item.ErrorCode, &item.ChunkCount, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return "", fmt.Errorf("scan Knowledge source catalog snapshot: %w", err)
		}
		value.Sources = append(value.Sources, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", fmt.Errorf("iterate Knowledge source catalog snapshot: %w", err)
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT source_id,upload_id,status,media_type,declared_size_bytes,
			received_size_bytes,next_chunk_ordinal,binding_revision,revision,created_at,updated_at
		FROM knowledge_uploads
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
		ORDER BY upload_id`, instanceID, ownerID, bindingID)
	if err != nil {
		return "", fmt.Errorf("read Knowledge upload catalog snapshot: %w", err)
	}
	for rows.Next() {
		var item knowledgeCatalogUpload
		if err := rows.Scan(&item.SourceID, &item.UploadID, &item.Status, &item.MediaType,
			&item.DeclaredSizeBytes, &item.ReceivedSizeBytes, &item.NextChunkOrdinal,
			&item.BindingRevision, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return "", fmt.Errorf("scan Knowledge upload catalog snapshot: %w", err)
		}
		value.Uploads = append(value.Uploads, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", fmt.Errorf("iterate Knowledge upload catalog snapshot: %w", err)
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT upload_id,chunk_ordinal,offset_bytes,size_bytes,chunk_sha256,created_at
		FROM knowledge_upload_chunks
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
		ORDER BY upload_id,chunk_ordinal`, instanceID, ownerID, bindingID)
	if err != nil {
		return "", fmt.Errorf("read Knowledge chunk catalog snapshot: %w", err)
	}
	for rows.Next() {
		var item knowledgeCatalogChunk
		if err := rows.Scan(&item.UploadID, &item.ChunkOrdinal, &item.OffsetBytes,
			&item.SizeBytes, &item.ChunkSHA256, &item.CreatedAt); err != nil {
			rows.Close()
			return "", fmt.Errorf("scan Knowledge chunk catalog snapshot: %w", err)
		}
		value.Chunks = append(value.Chunks, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", fmt.Errorf("iterate Knowledge chunk catalog snapshot: %w", err)
	}
	rows.Close()
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode Knowledge catalog snapshot: %w", err)
	}
	digest := sha256.Sum256(encoded)
	catalogDigest := "sha256:" + hex.EncodeToString(digest[:])
	for _, item := range value.Sources {
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_data_snapshot_sources
			(snapshot_operation_id,agent_instance_id,owner_id,binding_id,source_id,kind,status,media_type,
			 title,size_bytes,content_sha256,backend_point_id,indexed_segment_count,error_code,chunk_count,
			 source_revision,source_created_at,source_updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
			operationID, instanceID, ownerID, bindingID, item.SourceID, item.Kind, item.Status,
			item.MediaType, item.Title, item.SizeBytes, item.ContentSHA256, item.BackendPointID,
			item.IndexedSegments, item.ErrorCode, item.ChunkCount, item.Revision,
			item.CreatedAt, item.UpdatedAt); err != nil {
			return "", fmt.Errorf("persist Knowledge source catalog snapshot: %w", err)
		}
	}
	for _, item := range value.Uploads {
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_data_snapshot_uploads
			(snapshot_operation_id,agent_instance_id,owner_id,binding_id,source_id,upload_id,status,media_type,
			 declared_size_bytes,received_size_bytes,next_chunk_ordinal,binding_revision,upload_revision,
			 upload_created_at,upload_updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			operationID, instanceID, ownerID, bindingID, item.SourceID, item.UploadID, item.Status,
			item.MediaType, item.DeclaredSizeBytes, item.ReceivedSizeBytes, item.NextChunkOrdinal,
			item.BindingRevision, item.Revision, item.CreatedAt, item.UpdatedAt); err != nil {
			return "", fmt.Errorf("persist Knowledge upload catalog snapshot: %w", err)
		}
	}
	for _, item := range value.Chunks {
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_data_snapshot_chunks
			(snapshot_operation_id,agent_instance_id,owner_id,binding_id,upload_id,chunk_ordinal,
			 offset_bytes,size_bytes,chunk_sha256,chunk_created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			operationID, instanceID, ownerID, bindingID, item.UploadID, item.ChunkOrdinal,
			item.OffsetBytes, item.SizeBytes, item.ChunkSHA256, item.CreatedAt); err != nil {
			return "", fmt.Errorf("persist Knowledge chunk catalog snapshot: %w", err)
		}
	}
	return catalogDigest, nil
}

func loadKnowledgeCatalogSnapshot(ctx context.Context, tx pgx.Tx, operationID string,
	instanceID uuid.UUID, ownerID, bindingID string,
) (knowledgeCatalogSnapshot, error) {
	value := knowledgeCatalogSnapshot{SchemaVersion: knowledgeCatalogSnapshotSchemaV1}
	rows, err := tx.Query(ctx, `SELECT source_id,kind,status,media_type,title,size_bytes,content_sha256,
			backend_point_id,indexed_segment_count,error_code,chunk_count,source_revision,
			source_created_at,source_updated_at
		FROM knowledge_data_snapshot_sources
		WHERE snapshot_operation_id=$1 AND agent_instance_id=$2 AND owner_id=$3 AND binding_id=$4
		ORDER BY source_id`, operationID, instanceID, ownerID, bindingID)
	if err != nil {
		return knowledgeCatalogSnapshot{}, fmt.Errorf("read persisted Knowledge source snapshot: %w", err)
	}
	for rows.Next() {
		var item knowledgeCatalogSource
		if err := rows.Scan(&item.SourceID, &item.Kind, &item.Status, &item.MediaType, &item.Title,
			&item.SizeBytes, &item.ContentSHA256, &item.BackendPointID, &item.IndexedSegments,
			&item.ErrorCode, &item.ChunkCount, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return knowledgeCatalogSnapshot{}, fmt.Errorf("scan persisted Knowledge source snapshot: %w", err)
		}
		value.Sources = append(value.Sources, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return knowledgeCatalogSnapshot{}, fmt.Errorf("iterate persisted Knowledge source snapshot: %w", err)
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT source_id,upload_id,status,media_type,declared_size_bytes,
			received_size_bytes,next_chunk_ordinal,binding_revision,upload_revision,
			upload_created_at,upload_updated_at
		FROM knowledge_data_snapshot_uploads
		WHERE snapshot_operation_id=$1 AND agent_instance_id=$2 AND owner_id=$3 AND binding_id=$4
		ORDER BY upload_id`, operationID, instanceID, ownerID, bindingID)
	if err != nil {
		return knowledgeCatalogSnapshot{}, fmt.Errorf("read persisted Knowledge upload snapshot: %w", err)
	}
	for rows.Next() {
		var item knowledgeCatalogUpload
		if err := rows.Scan(&item.SourceID, &item.UploadID, &item.Status, &item.MediaType,
			&item.DeclaredSizeBytes, &item.ReceivedSizeBytes, &item.NextChunkOrdinal,
			&item.BindingRevision, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return knowledgeCatalogSnapshot{}, fmt.Errorf("scan persisted Knowledge upload snapshot: %w", err)
		}
		value.Uploads = append(value.Uploads, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return knowledgeCatalogSnapshot{}, fmt.Errorf("iterate persisted Knowledge upload snapshot: %w", err)
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT upload_id,chunk_ordinal,offset_bytes,size_bytes,chunk_sha256,chunk_created_at
		FROM knowledge_data_snapshot_chunks
		WHERE snapshot_operation_id=$1 AND agent_instance_id=$2 AND owner_id=$3 AND binding_id=$4
		ORDER BY upload_id,chunk_ordinal`, operationID, instanceID, ownerID, bindingID)
	if err != nil {
		return knowledgeCatalogSnapshot{}, fmt.Errorf("read persisted Knowledge chunk snapshot: %w", err)
	}
	for rows.Next() {
		var item knowledgeCatalogChunk
		if err := rows.Scan(&item.UploadID, &item.ChunkOrdinal, &item.OffsetBytes,
			&item.SizeBytes, &item.ChunkSHA256, &item.CreatedAt); err != nil {
			rows.Close()
			return knowledgeCatalogSnapshot{}, fmt.Errorf("scan persisted Knowledge chunk snapshot: %w", err)
		}
		value.Chunks = append(value.Chunks, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return knowledgeCatalogSnapshot{}, fmt.Errorf("iterate persisted Knowledge chunk snapshot: %w", err)
	}
	rows.Close()
	return value, nil
}

func restoreKnowledgeCatalog(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID string,
	generationDigest string, bindingRevision int64,
) error {
	if generationDigest == "" || bindingRevision < 1 {
		return managedlifecycle.ErrRevisionConflict
	}
	var snapshotOperationID, catalogDigest string
	if err := tx.QueryRow(ctx, `SELECT snapshot_operation_id::text,catalog_digest
		FROM knowledge_data_generations
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND backend_generation_digest=$4`,
		instanceID, ownerID, bindingID, generationDigest,
	).Scan(&snapshotOperationID, &catalogDigest); err != nil {
		return managedlifecycle.ErrRevisionConflict
	}
	value, err := loadKnowledgeCatalogSnapshot(ctx, tx, snapshotOperationID, instanceID, ownerID, bindingID)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return managedlifecycle.ErrRevisionConflict
	}
	digest := sha256.Sum256(encoded)
	if "sha256:"+hex.EncodeToString(digest[:]) != catalogDigest {
		return managedlifecycle.ErrRevisionConflict
	}
	for _, statement := range []string{
		`DELETE FROM knowledge_upload_chunks WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		`DELETE FROM knowledge_uploads WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		`DELETE FROM knowledge_sources WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
	} {
		if _, err := tx.Exec(ctx, statement, instanceID, ownerID, bindingID); err != nil {
			return fmt.Errorf("clear current Knowledge catalog: %w", err)
		}
	}
	for _, item := range value.Sources {
		if item.SourceID == uuid.Nil || item.Revision < 1 || item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
			return managedlifecycle.ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_sources
			(agent_instance_id,owner_id,binding_id,source_id,kind,status,media_type,title,size_bytes,
			 content_sha256,backend_point_id,indexed_segment_count,error_code,chunk_count,revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			instanceID, ownerID, bindingID, item.SourceID, item.Kind, item.Status, item.MediaType,
			item.Title, item.SizeBytes, item.ContentSHA256, item.BackendPointID, item.IndexedSegments,
			item.ErrorCode, item.ChunkCount, item.Revision, item.CreatedAt, item.UpdatedAt); err != nil {
			return fmt.Errorf("restore Knowledge source catalog: %w", err)
		}
	}
	for _, item := range value.Uploads {
		if item.SourceID == uuid.Nil || item.UploadID == uuid.Nil || item.Revision < 1 ||
			item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
			return managedlifecycle.ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_uploads
			(agent_instance_id,owner_id,binding_id,source_id,upload_id,status,media_type,
			 declared_size_bytes,received_size_bytes,next_chunk_ordinal,binding_revision,revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			instanceID, ownerID, bindingID, item.SourceID, item.UploadID, item.Status, item.MediaType,
			item.DeclaredSizeBytes, item.ReceivedSizeBytes, item.NextChunkOrdinal, bindingRevision,
			item.Revision, item.CreatedAt, item.UpdatedAt); err != nil {
			return fmt.Errorf("restore Knowledge upload catalog: %w", err)
		}
	}
	for _, item := range value.Chunks {
		if item.UploadID == uuid.Nil || item.ChunkOrdinal < 0 || item.CreatedAt.IsZero() {
			return managedlifecycle.ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_upload_chunks
			(agent_instance_id,owner_id,binding_id,upload_id,chunk_ordinal,offset_bytes,size_bytes,chunk_sha256,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			instanceID, ownerID, bindingID, item.UploadID, item.ChunkOrdinal, item.OffsetBytes,
			item.SizeBytes, item.ChunkSHA256, item.CreatedAt); err != nil {
			return fmt.Errorf("restore Knowledge chunk catalog: %w", err)
		}
	}
	return nil
}

func (store *ManagedKnowledgeLifecycleStore) completedKnowledgeGeneration(ctx context.Context, tx pgx.Tx, workerID string) (string, error) {
	var snapshot []byte
	if err := tx.QueryRow(ctx, `SELECT snapshot_json FROM worker_service_operations
		WHERE agent_instance_id=$1 AND operation_id=$2 AND state='succeeded'`,
		store.store.instanceID, workerID).Scan(&snapshot); err != nil {
		return "", managedlifecycle.ErrRevisionConflict
	}
	var value workeroperation.Operation
	if json.Unmarshal(snapshot, &value) != nil || value.Validate() != nil || value.Receipt == nil ||
		value.OperationID != workerID || value.Receipt.RestartObservationDigest == "" {
		return "", managedlifecycle.ErrRevisionConflict
	}
	encoded := strings.TrimPrefix(value.Receipt.RestartObservationDigest, "sha256:")
	if len(encoded) != 64 {
		return "", managedlifecycle.ErrRevisionConflict
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return "", managedlifecycle.ErrRevisionConflict
	}
	return value.Receipt.RestartObservationDigest, nil
}

const managedLifecycleSelect = `SELECT operation_id,deployment_id,managed_service_id,knowledge_binding_id,owner_id,
	action,status,worker_operation_id,revision,snapshot_json,created_at,updated_at
	FROM managed_knowledge_lifecycle_operations`

type managedLifecycleScanner interface{ Scan(...any) error }

func scanManagedLifecycleOperation(scanner managedLifecycleScanner) (managedlifecycle.OperationV1, error) {
	var operationID, deploymentID, serviceID, bindingID uuid.UUID
	var workerID *uuid.UUID
	var owner string
	var action managedlifecycle.Action
	var status managedlifecycle.Status
	var revision int64
	var snapshot []byte
	var created, updated time.Time
	if err := scanner.Scan(&operationID, &deploymentID, &serviceID, &bindingID, &owner, &action, &status,
		&workerID, &revision, &snapshot, &created, &updated); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return managedlifecycle.OperationV1{}, managedlifecycle.ErrNotFound
		}
		return managedlifecycle.OperationV1{}, fmt.Errorf("scan managed Knowledge lifecycle: %w", err)
	}
	var value managedlifecycle.OperationV1
	if json.Unmarshal(snapshot, &value) != nil {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	signingPayload, signingErr := value.Challenge.SigningPayload()
	scopeDigest, scopeErr := managedlifecycle.ScopeDigest(value.Challenge.Scope)
	if value.Validate() != nil || signingErr != nil || scopeErr != nil ||
		scopeDigest != value.Challenge.ScopeDigest || !bytes.Equal(signingPayload, value.Challenge.SigningCBOR) ||
		value.Challenge.OperationID != operationID.String() || value.Challenge.Scope.DeploymentID != deploymentID.String() ||
		value.Challenge.Scope.ManagedServiceID != serviceID.String() || value.Challenge.Scope.KnowledgeBindingID != bindingID.String() ||
		value.Challenge.Scope.OwnerID != owner || value.Challenge.Scope.Action != action || value.Status != status ||
		value.Revision != revision || !value.CreatedAt.Equal(created) || !value.UpdatedAt.Equal(updated) ||
		(workerID == nil) != (value.WorkerOperationID == "") ||
		(workerID != nil && workerID.String() != value.WorkerOperationID) {
		return managedlifecycle.OperationV1{}, managedlifecycle.ErrInvalid
	}
	return value, nil
}

type managedLifecycleQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readManagedLifecycleReplay[T any](ctx context.Context, query managedLifecycleQuery, operation string,
	mutation managedlifecycle.Mutation, operationID string,
) (T, bool, error) {
	var zero T
	sql := `SELECT request_hash,response_json FROM managed_knowledge_lifecycle_replays
		WHERE operation=$1 AND caller_client_id=$2 AND caller_credential_id=$3 AND idempotency_key=$4`
	args := []any{operation, mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey}
	if operationID != "" {
		sql += ` AND operation_id=$5`
		args = append(args, operationID)
	}
	var hash string
	var response []byte
	err := query.QueryRow(ctx, sql+` FOR UPDATE`, args...).Scan(&hash, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(mutation.RequestHash)) != 1 {
		return zero, false, managedlifecycle.ErrIdempotencyConflict
	}
	if json.Unmarshal(response, &zero) != nil {
		return zero, false, managedlifecycle.ErrInvalid
	}
	return zero, true, nil
}

func insertManagedLifecycleReplay(ctx context.Context, tx pgx.Tx, operationID, operation string,
	mutation managedlifecycle.Mutation, revision int64, response any,
) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return managedlifecycle.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO managed_knowledge_lifecycle_replays
		(operation_id,operation,caller_client_id,caller_credential_id,idempotency_key,request_hash,response_revision,response_json)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		operationID, operation, mutation.Caller.ClientID, mutation.Caller.CredentialID,
		mutation.IdempotencyKey, mutation.RequestHash, revision, payload)
	if err != nil {
		if isUniqueViolation(err) {
			return managedlifecycle.ErrIdempotencyConflict
		}
		return err
	}
	return nil
}
