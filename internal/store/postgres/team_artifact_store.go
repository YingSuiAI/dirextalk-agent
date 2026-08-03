package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type teamArtifactScanner interface {
	Scan(...any) error
}

func (store *Store) ListTeamArtifacts(
	ctx context.Context,
	ownerID,
	executionID string,
) ([]teamartifact.ArtifactV1, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		ownerID == "" ||
		!canonicalStoreUUID(executionID) {
		return nil, teamartifact.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT artifact_id,
		       schema_version,
		       agent_instance_id,
		       owner_id,
		       execution_id,
		       operation_id,
		       task_id,
		       plan_id,
		       plan_revision,
		       connection_id,
		       role_id,
		       action_id,
		       deployment_id,
		       name,
		       kind,
		       media_type,
		       size_bytes,
		       sha256,
		       object_ref,
		       verification,
		       created_at,
		       retention_expires_at
		FROM team_artifacts
		WHERE agent_instance_id=$1
		  AND owner_id=$2
		  AND execution_id=$3
		ORDER BY role_id, action_id, name, artifact_id`,
		store.instanceID,
		ownerID,
		uuid.MustParse(executionID),
	)
	if err != nil {
		return nil, fmt.Errorf("list Team artifacts: %w", err)
	}
	defer rows.Close()
	artifacts := make([]teamartifact.ArtifactV1, 0)
	for rows.Next() {
		artifact, scanErr := scanTeamArtifact(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		artifacts = append(artifacts, artifact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Team artifacts: %w", err)
	}
	return artifacts, nil
}

func (store *Store) GetTeamArtifact(
	ctx context.Context,
	ownerID,
	artifactID string,
) (teamartifact.ArtifactV1, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		ownerID == "" ||
		!canonicalStoreUUID(artifactID) {
		return teamartifact.ArtifactV1{}, teamartifact.ErrInvalid
	}
	artifact, err := scanTeamArtifact(store.pool.QueryRow(ctx, `
		SELECT artifact_id,
		       schema_version,
		       agent_instance_id,
		       owner_id,
		       execution_id,
		       operation_id,
		       task_id,
		       plan_id,
		       plan_revision,
		       connection_id,
		       role_id,
		       action_id,
		       deployment_id,
		       name,
		       kind,
		       media_type,
		       size_bytes,
		       sha256,
		       object_ref,
		       verification,
		       created_at,
		       retention_expires_at
		FROM team_artifacts
		WHERE artifact_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`,
		uuid.MustParse(artifactID),
		store.instanceID,
		ownerID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return teamartifact.ArtifactV1{}, teamartifact.ErrNotFound
	}
	return artifact, err
}

func scanTeamArtifact(row teamArtifactScanner) (teamartifact.ArtifactV1, error) {
	var artifact teamartifact.ArtifactV1
	var artifactID uuid.UUID
	var agentInstanceID uuid.UUID
	var executionID uuid.UUID
	var operationID uuid.UUID
	var taskID uuid.UUID
	var planID uuid.UUID
	var planRevision int64
	var connectionID uuid.UUID
	var deploymentID uuid.UUID
	var kind string
	var verification string
	if err := row.Scan(
		&artifactID,
		&artifact.SchemaVersion,
		&agentInstanceID,
		&artifact.OwnerID,
		&executionID,
		&operationID,
		&taskID,
		&planID,
		&planRevision,
		&connectionID,
		&artifact.RoleID,
		&artifact.ActionID,
		&deploymentID,
		&artifact.Name,
		&kind,
		&artifact.MediaType,
		&artifact.SizeBytes,
		&artifact.SHA256,
		&artifact.ObjectRef,
		&verification,
		&artifact.CreatedAt,
		&artifact.RetentionExpires,
	); err != nil {
		return teamartifact.ArtifactV1{}, err
	}
	if planRevision < 1 {
		return teamartifact.ArtifactV1{}, teamartifact.ErrFactMismatch
	}
	artifact.ArtifactID = artifactID.String()
	artifact.AgentInstanceID = agentInstanceID.String()
	artifact.ExecutionID = executionID.String()
	artifact.OperationID = operationID.String()
	artifact.TaskID = taskID.String()
	artifact.PlanID = planID.String()
	artifact.PlanRevision = uint64(planRevision)
	artifact.ConnectionID = connectionID.String()
	artifact.DeploymentID = deploymentID.String()
	artifact.Kind = teamartifact.Kind(kind)
	artifact.Verification = teamartifact.VerificationState(verification)
	artifact.CreatedAt = artifact.CreatedAt.UTC()
	artifact.RetentionExpires = artifact.RetentionExpires.UTC()
	if artifact.Validate() != nil {
		return teamartifact.ArtifactV1{}, teamartifact.ErrFactMismatch
	}
	return artifact, nil
}

func sameTeamArtifact(left, right teamartifact.ArtifactV1) bool {
	left.CreatedAt = left.CreatedAt.UTC()
	left.RetentionExpires = left.RetentionExpires.UTC()
	right.CreatedAt = right.CreatedAt.UTC()
	right.RetentionExpires = right.RetentionExpires.UTC()
	return left == right
}

func canonicalStoreUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

var _ teamartifact.Reader = (*Store)(nil)
