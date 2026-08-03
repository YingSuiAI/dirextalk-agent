package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func persistTeamTaskInput(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	taskID string,
	plan teamplan.Plan,
) error {
	input, err := taskinput.FromBinding(
		plan.OwnerID,
		taskID,
		plan.GoalDigest,
		plan.TaskInput,
	)
	if err != nil {
		return ErrTeamFactInvalid
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return ErrTeamFactInvalid
	}
	inputCBOR, err := input.CanonicalCBOR()
	if err != nil {
		return ErrTeamFactInvalid
	}
	var repository taskinput.GitRepositoryV1
	var workspace taskinput.BindingV1
	if input.SourceKind == taskinput.SourceGitHubRepository {
		repository = input.Repository
	} else {
		workspace = input.Workspace
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO team_task_inputs (
		    input_id, input_digest, agent_instance_id, owner_id, task_id,
		    goal_digest, schema_version, source_digest, source_kind,
		    repository_provider, repository_host,
		    repository_connection_id, repository_id, repository_owner,
		    repository_name, repository_base_commit_sha, repository_base_ref,
		    workspace_snapshot_id, workspace_snapshot_digest,
		    workspace_digest, workspace_size_bytes, workspace_media_type,
		    input_json, input_cbor
		)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,
		    NULLIF($10::text,''),NULLIF($11::text,''),
		    NULLIF($12::text,'')::uuid,NULLIF($13::text,''),
		    NULLIF($14::text,''),NULLIF($15::text,''),
		    NULLIF($16::text,''),NULLIF($17::text,''),
		    NULLIF($18::text,'')::uuid,NULLIF($19::text,''),
		    NULLIF($20::text,''),NULLIF($21::bigint,0),
		    NULLIF($22::text,''),$23,$24
		)
		ON CONFLICT (input_id, input_digest) DO NOTHING`,
		input.InputID,
		plan.TaskInput.InputDigest,
		instanceID,
		input.OwnerID,
		input.TaskID,
		input.GoalDigest,
		input.SchemaVersion,
		input.SourceDigest,
		input.SourceKind,
		repository.Provider,
		repository.Host,
		repository.ConnectionID,
		repository.RepositoryID,
		repository.Owner,
		repository.Name,
		repository.BaseCommitSHA,
		repository.BaseRef,
		workspace.SnapshotID,
		workspace.SnapshotDigest,
		workspace.WorkspaceDigest,
		workspace.WorkspaceSizeBytes,
		workspace.WorkspaceMediaType,
		inputJSON,
		inputCBOR,
	); err != nil {
		return fmt.Errorf("persist Team TaskInput: %w", err)
	}
	return verifyStoredTeamTaskInput(
		ctx,
		tx,
		instanceID,
		taskID,
		plan,
	)
}

func verifyStoredTeamTaskInput(
	ctx context.Context,
	query teamPlanQuerier,
	instanceID uuid.UUID,
	taskID string,
	plan teamplan.Plan,
) error {
	if plan.SchemaVersion != teamplan.SchemaV3 {
		return nil
	}
	expected, err := taskinput.FromBinding(
		plan.OwnerID,
		taskID,
		plan.GoalDigest,
		plan.TaskInput,
	)
	if err != nil {
		return ErrTeamFactCorrupt
	}
	var (
		ownerID, storedTaskID, goalDigest string
		schemaVersion, sourceDigest       string
		sourceKind, inputDigest           string
		inputJSON, inputCBOR              []byte
	)
	if err := query.QueryRow(ctx, `
		SELECT owner_id, task_id::text, goal_digest, schema_version,
		       source_digest, source_kind, input_digest, input_json, input_cbor
		FROM team_task_inputs
		WHERE input_id=$1
		  AND input_digest=$2
		  AND agent_instance_id=$3`,
		plan.TaskInput.InputID,
		plan.TaskInput.InputDigest,
		instanceID,
	).Scan(
		&ownerID,
		&storedTaskID,
		&goalDigest,
		&schemaVersion,
		&sourceDigest,
		&sourceKind,
		&inputDigest,
		&inputJSON,
		&inputCBOR,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamFactCorrupt
		}
		return fmt.Errorf("read Team TaskInput: %w", err)
	}
	var stored taskinput.InputV2
	if json.Unmarshal(inputJSON, &stored) != nil ||
		stored.Validate() != nil ||
		stored != expected ||
		ownerID != expected.OwnerID ||
		storedTaskID != expected.TaskID ||
		goalDigest != expected.GoalDigest ||
		schemaVersion != expected.SchemaVersion ||
		sourceDigest != expected.SourceDigest ||
		sourceKind != string(expected.SourceKind) ||
		inputDigest != plan.TaskInput.InputDigest {
		return ErrTeamFactCorrupt
	}
	actualDigest, err := stored.Digest()
	actualCBOR, cborErr := stored.CanonicalCBOR()
	if err != nil ||
		cborErr != nil ||
		actualDigest != inputDigest ||
		!bytes.Equal(actualCBOR, inputCBOR) {
		return ErrTeamFactCorrupt
	}
	return nil
}
