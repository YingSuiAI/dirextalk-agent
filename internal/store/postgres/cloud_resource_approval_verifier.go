package postgres

import (
	"context"
	"errors"

	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/jackc/pgx/v5"
)

// VerifyResourceApproval is the only Store read used by destroy/lifecycle
// controllers to authorize a resource in a deployment containing multiple
// approval sources.  It deliberately does not expose entry operations, plans,
// or general SQL to those controllers.
//
// A resource using the original Worker plan must match the original launch
// approval exactly.  Any other plan hash is accepted only when it is the
// separately device-approved entry operation bound to the same original
// Worker, owner, task, deployment, connection and lifecycle scope.
func (store *Store) VerifyResourceApproval(ctx context.Context, proof clouddestroy.ResourceApprovalProofV1) error {
	if store == nil || store.pool == nil || ctx == nil || proof.Validate() != nil || proof.AgentInstanceID != store.instanceID.String() {
		return clouddestroy.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return clouddestroy.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	originalApprovalID, err := store.verifyOriginalDestroyLineage(ctx, tx, proof)
	if err != nil {
		return err
	}
	if err := store.verifyDestroyLedgerResource(ctx, tx, proof); err != nil {
		return err
	}
	if proof.ApprovedPlanHash == proof.OriginalPlanHash {
		if proof.ApprovalID != originalApprovalID {
			return clouddestroy.ErrInvalid
		}
	} else if err := store.verifyEntryDestroyApproval(ctx, tx, proof, originalApprovalID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return clouddestroy.ErrUnavailable
	}
	return nil
}

func (store *Store) verifyOriginalDestroyLineage(ctx context.Context, tx pgx.Tx, proof clouddestroy.ResourceApprovalProofV1) (string, error) {
	var approvalID string
	err := tx.QueryRow(ctx, `
		SELECT launch.approval_id::text
		FROM cloud_launch_operations launch
		JOIN cloud_plans plan ON plan.plan_id=launch.plan_id
		JOIN cloud_approvals approval ON approval.approval_id=launch.approval_id
		WHERE launch.agent_instance_id=$1 AND launch.owner_id=$2 AND launch.task_id=$3
		  AND launch.deployment_id=$4 AND launch.connection_id=$5 AND launch.plan_id=$6
		  AND plan.agent_instance_id=$1 AND plan.owner_id=$2 AND plan.plan_id=$6
		  AND plan.plan_hash=$7 AND plan.status='approved'
		  AND approval.agent_instance_id=$1 AND approval.owner_id=$2 AND approval.plan_id=$6
		  AND approval.plan_hash=$7
		FOR SHARE OF launch, plan, approval`,
		store.instanceID, proof.OwnerID, proof.TaskID, proof.DeploymentID, proof.ConnectionID,
		proof.OriginalPlanID, proof.OriginalPlanHash).Scan(&approvalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", clouddestroy.ErrInvalid
	}
	if err != nil {
		return "", clouddestroy.ErrUnavailable
	}
	return approvalID, nil
}

func (store *Store) verifyDestroyLedgerResource(ctx context.Context, tx pgx.Tx, proof clouddestroy.ResourceApprovalProofV1) error {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT true
		FROM cloud_resources resource
		WHERE resource.resource_id=$1 AND resource.agent_instance_id=$2 AND resource.owner_id=$3
		  AND resource.task_id=$4 AND resource.deployment_id=$5
		  AND resource.approved_plan_hash=$6 AND resource.approval_id=$7
		  AND resource.retention=$8 AND resource.destroy_deadline IS NOT DISTINCT FROM $9
		  AND resource.auto_destroy_approved=$10 AND resource.state=$11
		FOR SHARE`,
		proof.ResourceID, store.instanceID, proof.OwnerID, proof.TaskID, proof.DeploymentID,
		proof.ApprovedPlanHash, proof.ApprovalID, proof.Retention, proof.DestroyDeadline.UTC(), proof.AutoDestroy, proof.State).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) || !found {
		return clouddestroy.ErrInvalid
	}
	if err != nil {
		return clouddestroy.ErrUnavailable
	}
	return nil
}

func (store *Store) verifyEntryDestroyApproval(ctx context.Context, tx pgx.Tx, proof clouddestroy.ResourceApprovalProofV1, originalApprovalID string) error {
	operation, err := readEntryOperationRow(ctx, tx, ` WHERE agent_instance_id=$1 AND entry_approval_id=$2 AND entry_plan_hash=$3 FOR SHARE`,
		store.instanceID, proof.ApprovalID, proof.ApprovedPlanHash)
	if err != nil {
		return mapEntryDestroyVerificationError(err)
	}
	plan, err := readEntryPlanRow(ctx, tx, ` WHERE agent_instance_id=$1 AND entry_plan_id=$2 FOR SHARE`, store.instanceID, operation.EntryPlanID)
	if err != nil {
		return mapEntryDestroyVerificationError(err)
	}
	if !entryPlanMatchesRecoveryOperation(store.instanceID, plan, operation) ||
		operation.OwnerID != proof.OwnerID || operation.DeploymentID != proof.DeploymentID || operation.TaskID != proof.TaskID ||
		operation.OriginalPlanID != proof.OriginalPlanID || operation.OriginalPlanHash != proof.OriginalPlanHash ||
		operation.OriginalApprovalID != originalApprovalID ||
		operation.ConnectionID != proof.ConnectionID || operation.Operation.Challenge.ApprovalID != proof.ApprovalID ||
		operation.Operation.Challenge.PlanHash != proof.ApprovedPlanHash ||
		!entryOperationAllowsCleanup(operation.Operation.Status, proof.State) ||
		!entryRetentionMatchesProof(plan.Plan, proof) {
		return clouddestroy.ErrInvalid
	}
	return nil
}

func entryRetentionMatchesProof(plan entrypoint.PlanV1, proof clouddestroy.ResourceApprovalProofV1) bool {
	return plan.Scope.Retention.Class == entrypoint.RetentionEphemeral && plan.Scope.Retention.AutoDestroy &&
		proof.Retention == task.RetentionEphemeralAutoDestroy && proof.AutoDestroy &&
		plan.Scope.Retention.DestroyDeadline.UTC().Equal(proof.DestroyDeadline.UTC())
}

func entryOperationAllowsCleanup(status entrypoint.Status, resourceState resource.State) bool {
	switch status {
	case entrypoint.StatusProvisioning, entrypoint.StatusVerifying, entrypoint.StatusActive,
		entrypoint.StatusFailed, entrypoint.StatusDestroying, entrypoint.StatusDestroyBlocked:
		return true
	case entrypoint.StatusDestroyed:
		return resourceState == resource.StateVerifiedDestroyed
	default:
		return false
	}
}

func mapEntryDestroyVerificationError(err error) error {
	if errors.Is(err, entrypoint.ErrNotFound) || errors.Is(err, entrypoint.ErrInvalid) || errors.Is(err, entrypoint.ErrRevisionConflict) {
		return clouddestroy.ErrInvalid
	}
	return clouddestroy.ErrUnavailable
}

var _ clouddestroy.ResourceApprovalVerifier = (*Store)(nil)
