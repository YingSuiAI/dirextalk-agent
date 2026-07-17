package postgres

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type VerifiedWorkerPrincipal struct {
	DeploymentID string
	OwnerID      string
	WorkerID     string
	InstanceID   string
	PrincipalID  string
	AccountID    string
	Region       string
}

// GetCurrentVerifiedWorkerPrincipal reads the provider-verified enrollment
// bound to the current Worker deployment. It never accepts an instance,
// principal, account, or region from an owner request.
func (store *WorkerStore) GetCurrentVerifiedWorkerPrincipal(ctx context.Context, ownerID, deploymentID string) (VerifiedWorkerPrincipal, error) {
	deployment, err := uuid.Parse(deploymentID)
	if store == nil || err != nil || deployment == uuid.Nil || deployment.String() != deploymentID || ownerID == "" {
		return VerifiedWorkerPrincipal{}, worker.ErrInvalid
	}
	var value VerifiedWorkerPrincipal
	var storedDeployment, workerID uuid.UUID
	err = store.pool.QueryRow(ctx, `
		SELECT wd.deployment_id, wd.owner_id, wd.worker_id, replay.provider_instance_id,
		       replay.principal_id, challenge.account_id, challenge.region
		FROM worker_deployments wd
		JOIN worker_identity_enrollment_replays replay
		  ON replay.deployment_id=wd.deployment_id AND replay.caller_worker_id=wd.worker_id
		JOIN worker_identity_challenges challenge
		  ON challenge.challenge_id=replay.challenge_id AND challenge.deployment_id=wd.deployment_id
		WHERE wd.agent_instance_id=$1 AND wd.owner_id=$2 AND wd.deployment_id=$3
		  AND wd.provider_instance_id=replay.provider_instance_id
		ORDER BY replay.created_at DESC LIMIT 1`,
		store.instanceID, ownerID, deployment,
	).Scan(&storedDeployment, &value.OwnerID, &workerID, &value.InstanceID, &value.PrincipalID, &value.AccountID, &value.Region)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifiedWorkerPrincipal{}, worker.ErrIdentityUnavailable
	}
	if err != nil {
		return VerifiedWorkerPrincipal{}, err
	}
	value.DeploymentID, value.WorkerID = storedDeployment.String(), workerID.String()
	if value.DeploymentID != deploymentID || value.OwnerID != ownerID || value.InstanceID == "" || value.PrincipalID == "" {
		return VerifiedWorkerPrincipal{}, worker.ErrIdentityUnavailable
	}
	return value, nil
}
