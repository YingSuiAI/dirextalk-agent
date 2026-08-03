package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	materializeTeamWorkerInputOperation = "team.worker_input.materialize"
	teamWorkerInputReplaySchemaV1       = 1
	maxTeamWorkerInputJSONBytes         = 8 << 20
)

type teamWorkerInputReplay struct {
	SchemaVersion int            `json:"schema_version"`
	Fact          teaminput.Fact `json:"fact"`
}

type storedTeamWorkerInput struct {
	fact            teaminput.Fact
	manifestJSON    []byte
	executionBundle []byte
}

func (store *Store) FindMaterializedInput(
	ctx context.Context,
	scope task.MutationScope,
	request teaminput.MaterializeRequest,
) (teaminput.Fact, bool, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return teaminput.Fact{}, false, teaminput.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teaminput.Fact{}, false, err
	}
	requestDigest, inputID, err := teamWorkerInputRequestDigest(
		request.IdempotencyKey,
		request.OwnerID,
		request.ExecutionID,
		request.RoleID,
	)
	if err != nil {
		return teaminput.Fact{}, false, err
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teaminput.Fact{}, false,
			fmt.Errorf("begin Team Worker input replay read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var storedDigest, response []byte
	var aggregateID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT request_hash, aggregate_id, response_json
		FROM idempotency_records
		WHERE operation=$1
		  AND caller_client_id=$2
		  AND caller_credential_id=$3
		  AND idempotency_key=$4`,
		materializeTeamWorkerInputOperation,
		caller.ClientID,
		caller.CredentialID,
		request.IdempotencyKey,
	).Scan(&storedDigest, &aggregateID, &response)
	if !errors.Is(err, pgx.ErrNoRows) {
		if err != nil {
			return teaminput.Fact{}, false,
				fmt.Errorf("find Team Worker input replay: %w", err)
		}
		if !bytes.Equal(storedDigest, requestDigest[:]) {
			return teaminput.Fact{}, false, idempotency.ErrConflict
		}
		replayed, decodeErr := decodeTeamWorkerInputReplay(response)
		if decodeErr != nil ||
			aggregateID != inputID ||
			replayed.Materialization.InputID != inputID.String() ||
			!teamWorkerInputMatchesRequest(replayed, request) {
			return teaminput.Fact{}, false, teaminput.ErrFactMismatch
		}
		persisted, readErr := readTeamWorkerInput(
			ctx,
			tx,
			store.instanceID,
			request.OwnerID,
			inputID,
			false,
		)
		if readErr != nil ||
			!sameTeamWorkerInputMaterialization(
				replayed,
				persisted.fact,
			) {
			return teaminput.Fact{}, false, teaminput.ErrFactMismatch
		}
		if err := tx.Commit(ctx); err != nil {
			return teaminput.Fact{}, false,
				fmt.Errorf("commit Team Worker input replay read: %w", err)
		}
		return replayed, true, nil
	}

	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"team-worker-input:"+inputID.String(),
	); err != nil {
		return teaminput.Fact{}, false,
			fmt.Errorf("lock Team Worker input replay aggregate: %w", err)
	}
	persisted, found, err := findTeamWorkerInput(
		ctx,
		tx,
		store.instanceID,
		request.OwnerID,
		inputID,
		true,
	)
	if err != nil {
		return teaminput.Fact{}, false, err
	}
	if !found {
		return teaminput.Fact{}, false, nil
	}
	if !teamWorkerInputMatchesRequest(persisted.fact, request) {
		return teaminput.Fact{}, false, teaminput.ErrFactMismatch
	}
	replayed, aggregateID, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		materializeTeamWorkerInputOperation,
		request.IdempotencyKey,
		requestDigest[:],
		inputID,
	)
	if err != nil {
		return teaminput.Fact{}, false, err
	}
	if replayed {
		fact, decodeErr := decodeTeamWorkerInputReplay(response)
		if decodeErr != nil ||
			aggregateID != inputID ||
			!sameTeamWorkerInputMaterialization(
				fact,
				persisted.fact,
			) {
			return teaminput.Fact{}, false, teaminput.ErrFactMismatch
		}
		persisted.fact = fact
	} else if err := setTeamWorkerInputReplay(
		ctx,
		tx,
		caller,
		request.IdempotencyKey,
		persisted.fact,
	); err != nil {
		return teaminput.Fact{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return teaminput.Fact{}, false,
			fmt.Errorf("commit converged Team Worker input replay: %w", err)
	}
	return persisted.fact, true, nil
}

func (store *Store) PersistMaterializedInput(
	ctx context.Context,
	scope task.MutationScope,
	command teaminput.PersistCommand,
) (teaminput.Fact, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return teaminput.Fact{}, teaminput.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teaminput.Fact{}, err
	}
	materializationJSON, requestDigest, inputID, err :=
		validateTeamWorkerInputCommand(command)
	if err != nil {
		return teaminput.Fact{}, err
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teaminput.Fact{},
			fmt.Errorf("begin materialize Team Worker input: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"team-worker-input:"+inputID.String(),
	); err != nil {
		return teaminput.Fact{},
			fmt.Errorf("lock Team Worker input aggregate: %w", err)
	}
	replayed, aggregateID, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		materializeTeamWorkerInputOperation,
		command.IdempotencyKey,
		requestDigest[:],
		inputID,
	)
	if err != nil {
		return teaminput.Fact{}, err
	}
	if replayed {
		fact, decodeErr := decodeTeamWorkerInputReplay(response)
		if decodeErr != nil ||
			aggregateID != inputID ||
			!reflect.DeepEqual(
				fact.Materialization,
				command.Materialization,
			) {
			return teaminput.Fact{}, idempotency.ErrConflict
		}
		persisted, readErr := readTeamWorkerInput(
			ctx,
			tx,
			store.instanceID,
			command.Materialization.OwnerID,
			inputID,
			false,
		)
		if readErr != nil ||
			!sameTeamWorkerInputMaterialization(
				fact,
				persisted.fact,
			) {
			return teaminput.Fact{}, teaminput.ErrFactMismatch
		}
		if !bytes.Equal(persisted.manifestJSON, command.ManifestJSON) ||
			!bytes.Equal(
				persisted.executionBundle,
				command.ExecutionBundleJSON,
			) {
			return teaminput.Fact{}, idempotency.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return teaminput.Fact{},
				fmt.Errorf("commit Team Worker input replay: %w", err)
		}
		return fact, nil
	}

	persisted, found, err := findTeamWorkerInput(
		ctx,
		tx,
		store.instanceID,
		command.Materialization.OwnerID,
		inputID,
		true,
	)
	if err != nil {
		return teaminput.Fact{}, err
	}
	if found {
		if !reflect.DeepEqual(
			persisted.fact.Materialization,
			command.Materialization,
		) ||
			!bytes.Equal(persisted.manifestJSON, command.ManifestJSON) ||
			!bytes.Equal(
				persisted.executionBundle,
				command.ExecutionBundleJSON,
			) {
			return teaminput.Fact{}, teaminput.ErrFactMismatch
		}
		if err := setTeamWorkerInputReplay(
			ctx,
			tx,
			caller,
			command.IdempotencyKey,
			persisted.fact,
		); err != nil {
			return teaminput.Fact{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return teaminput.Fact{},
				fmt.Errorf(
					"commit converged Team Worker input: %w",
					err,
				)
		}
		return persisted.fact, nil
	}
	if err := verifyTeamWorkerInputBinding(
		ctx,
		tx,
		store.instanceID,
		command.Materialization,
	); err != nil {
		return teaminput.Fact{}, err
	}
	fact, err := insertTeamWorkerInput(
		ctx,
		tx,
		store.instanceID,
		command,
		materializationJSON,
	)
	if err != nil {
		return teaminput.Fact{}, err
	}
	if err := setTeamWorkerInputReplay(
		ctx,
		tx,
		caller,
		command.IdempotencyKey,
		fact,
	); err != nil {
		return teaminput.Fact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return teaminput.Fact{},
			fmt.Errorf("commit materialize Team Worker input: %w", err)
	}
	return fact, nil
}

func teamWorkerInputRequestDigest(
	idempotencyKey,
	ownerID,
	executionID,
	roleID string,
) ([sha256.Size]byte, uuid.UUID, error) {
	inputIDText, err := teaminput.InputID(executionID, roleID)
	if err != nil ||
		!canonicalTeamUUID(idempotencyKey) ||
		!validTeamWorkerInputOwnerID(ownerID) {
		return [sha256.Size]byte{}, uuid.Nil, teaminput.ErrInvalid
	}
	digest, err := teamMutationDigest(struct {
		SchemaVersion string `json:"schema_version"`
		OwnerID       string `json:"owner_id"`
		ExecutionID   string `json:"execution_id"`
		RoleID        string `json:"role_id"`
	}{
		SchemaVersion: teaminput.MaterializationSchemaV1,
		OwnerID:       ownerID,
		ExecutionID:   executionID,
		RoleID:        roleID,
	})
	if err != nil {
		return [sha256.Size]byte{}, uuid.Nil, teaminput.ErrInvalid
	}
	return digest, uuid.MustParse(inputIDText), nil
}

func validateTeamWorkerInputCommand(
	command teaminput.PersistCommand,
) ([]byte, [sha256.Size]byte, uuid.UUID, error) {
	if command.Validate() != nil ||
		len(command.ManifestJSON) > maxTeamWorkerInputJSONBytes ||
		len(command.ExecutionBundleJSON) > maxTeamWorkerInputJSONBytes ||
		security.ContainsLikelySecret(string(command.ManifestJSON)) ||
		security.ContainsLikelySecret(string(command.ExecutionBundleJSON)) {
		return nil, [sha256.Size]byte{}, uuid.Nil, teaminput.ErrInvalid
	}
	materializationJSON, err := json.Marshal(command.Materialization)
	if err != nil ||
		len(materializationJSON) == 0 ||
		len(materializationJSON) > maxTeamWorkerInputJSONBytes ||
		security.ContainsLikelySecret(string(materializationJSON)) {
		clear(materializationJSON)
		return nil, [sha256.Size]byte{}, uuid.Nil, teaminput.ErrInvalid
	}
	if err := validateTeamWorkerExecutionBundle(
		command.ExecutionBundleJSON,
		command.Materialization,
	); err != nil {
		clear(materializationJSON)
		return nil, [sha256.Size]byte{}, uuid.Nil, err
	}
	requestDigest, inputID, err := teamWorkerInputRequestDigest(
		command.IdempotencyKey,
		command.Materialization.OwnerID,
		command.Materialization.ExecutionID,
		command.Materialization.RoleID,
	)
	if err != nil ||
		inputID.String() != command.Materialization.InputID {
		clear(materializationJSON)
		return nil, [sha256.Size]byte{}, uuid.Nil, teaminput.ErrInvalid
	}
	return materializationJSON, requestDigest, inputID, nil
}

func validateTeamWorkerExecutionBundle(
	encoded []byte,
	materialization teaminput.MaterializationV1,
) error {
	var bundle workerrunner.ExecutionBundleV1
	digest := sha256.Sum256(encoded)
	if "sha256:"+hex.EncodeToString(digest[:]) !=
		materialization.ExecutionBundleDigest ||
		decodeStrictTeamWorkerInputJSON(encoded, &bundle) != nil ||
		bundle.SchemaVersion != 1 ||
		bundle.RecipeSHA256 != strings.TrimPrefix(
			materialization.ManifestDigest,
			"sha256:",
		) ||
		len(bundle.Actions) != 2 {
		return teaminput.ErrInvalid
	}
	inputAction := bundle.Actions[0]
	runtimeAction := bundle.Actions[1]
	if inputAction.ID != "materialize-input" ||
		inputAction.Kind != workerrunner.InputMaterializeActionKind ||
		inputAction.TimeoutSeconds != uint32(
			materialization.CredentialGrant.MaximumDurationSeconds,
		) ||
		inputAction.Noop != nil ||
		inputAction.Installer != nil ||
		inputAction.Input == nil ||
		inputAction.Runtime != nil ||
		inputAction.Input.Workspace == nil ||
		validateTeamWorkerInputObject(
			inputAction.Input.Context,
			"context",
			materialization.ContextDigest,
			"application/json",
			workerruntime.MaxContextBytes,
		) != nil ||
		validateTeamWorkerInputObject(
			*inputAction.Input.Workspace,
			"workspace",
			materialization.WorkspaceDigest,
			"application/x-tar",
			workerrunner.MaxWorkspaceArchiveBytes,
		) != nil ||
		runtimeAction.ID != "execute-role" ||
		runtimeAction.Kind != workerrunner.RuntimeExecuteActionKind ||
		runtimeAction.TimeoutSeconds != uint32(
			materialization.CredentialGrant.MaximumDurationSeconds,
		) ||
		runtimeAction.Noop != nil ||
		runtimeAction.Installer != nil ||
		runtimeAction.Input != nil ||
		runtimeAction.Runtime == nil ||
		!reflect.DeepEqual(
			runtimeAction.Runtime.Task,
			materialization.RuntimeTask,
		) {
		return teaminput.ErrInvalid
	}
	return nil
}

func validateTeamWorkerInputObject(
	object workerrunner.MaterializeObjectV1,
	kind string,
	digest string,
	contentType string,
	maximum int64,
) error {
	if object.SHA256 != digest ||
		object.ContentType != contentType ||
		object.SizeBytes < 1 || object.SizeBytes > maximum ||
		object.S3Ref != "" {
		return teaminput.ErrInvalid
	}
	expected := "team-" + kind + "-" +
		strings.TrimPrefix(digest, "sha256:")
	switch kind {
	case "context":
		expected += ".json"
	case "workspace":
		expected += ".tar"
	default:
		return teaminput.ErrInvalid
	}
	if object.ObjectName != expected {
		return teaminput.ErrInvalid
	}
	return nil
}

func verifyTeamWorkerInputBinding(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	value teaminput.MaterializationV1,
) error {
	var (
		ownerID, executionDigest, status string
		roleID, roleDigest               string
		taskID, taskStepID               uuid.UUID
		deploymentID, expectedWorkerID   uuid.UUID
		credentialSlot                   string
	)
	err := tx.QueryRow(ctx, `
		SELECT execution.owner_id, execution.execution_digest,
		       execution.status, role.role_id, role.role_digest,
		       role.task_id, role.task_step_id, role.deployment_id,
		       role.expected_worker_id, role.model_credential_slot
		FROM team_executions execution
		JOIN team_execution_roles role
		  ON role.execution_id=execution.execution_id
		 AND role.role_id=$3
		WHERE execution.execution_id=$1
		  AND execution.agent_instance_id=$2
		FOR SHARE OF execution, role`,
		value.ExecutionID,
		instanceID,
		value.RoleID,
	).Scan(
		&ownerID,
		&executionDigest,
		&status,
		&roleID,
		&roleDigest,
		&taskID,
		&taskStepID,
		&deploymentID,
		&expectedWorkerID,
		&credentialSlot,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return teaminput.ErrFactMismatch
	}
	if err != nil {
		return fmt.Errorf("verify Team Worker input binding: %w", err)
	}
	if ownerID != value.OwnerID ||
		executionDigest != value.ExecutionDigest ||
		status != "dispatching" && status != "running" ||
		roleID != value.RoleID ||
		roleDigest != value.RoleDigest ||
		taskID.String() != value.TaskID ||
		taskStepID.String() != value.TaskStepID ||
		deploymentID.String() != value.DeploymentID ||
		expectedWorkerID.String() != value.ExpectedWorkerID ||
		credentialSlot != value.CredentialGrant.CredentialSlot {
		if status != "dispatching" && status != "running" {
			return teaminput.ErrNotReady
		}
		return teaminput.ErrFactMismatch
	}
	return nil
}

func insertTeamWorkerInput(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	command teaminput.PersistCommand,
	materializationJSON []byte,
) (teaminput.Fact, error) {
	value := command.Materialization
	var fact teaminput.Fact
	fact.Materialization = value
	fact.Status = teaminput.StatusMaterialized
	fact.RecordRevision = 1
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_worker_inputs (
		    input_id, agent_instance_id, owner_id,
		    execution_id, execution_digest, role_id, role_digest,
		    task_id, task_step_id, deployment_id, expected_worker_id,
		    context_snapshot_id, context_digest,
		    workspace_snapshot_id, workspace_digest,
		    manifest_digest, runtime_task_digest,
		    execution_bundle_digest, credential_grant_digest,
		    materialization_json, manifest_json, manifest_raw,
		    execution_bundle_json, execution_bundle_raw,
		    status, record_revision
		)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		    $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26
		)
		RETURNING created_at, updated_at`,
		value.InputID,
		instanceID,
		value.OwnerID,
		value.ExecutionID,
		value.ExecutionDigest,
		value.RoleID,
		value.RoleDigest,
		value.TaskID,
		value.TaskStepID,
		value.DeploymentID,
		value.ExpectedWorkerID,
		value.ContextSnapshotID,
		value.ContextDigest,
		value.WorkspaceSnapshotID,
		value.WorkspaceDigest,
		value.ManifestDigest,
		value.RuntimeTaskDigest,
		value.ExecutionBundleDigest,
		value.CredentialGrantDigest,
		materializationJSON,
		command.ManifestJSON,
		command.ManifestJSON,
		command.ExecutionBundleJSON,
		command.ExecutionBundleJSON,
		fact.Status,
		int64(fact.RecordRevision),
	).Scan(&fact.CreatedAt, &fact.UpdatedAt); err != nil {
		return teaminput.Fact{},
			fmt.Errorf("insert Team Worker input: %w", err)
	}
	fact.CreatedAt = fact.CreatedAt.UTC()
	fact.UpdatedAt = fact.UpdatedAt.UTC()
	return fact, nil
}

func findTeamWorkerInput(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID uuid.UUID,
	ownerID string,
	inputID uuid.UUID,
	lock bool,
) (storedTeamWorkerInput, bool, error) {
	value, err := readTeamWorkerInput(
		ctx,
		query,
		instanceID,
		ownerID,
		inputID,
		lock,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedTeamWorkerInput{}, false, nil
	}
	if err != nil {
		return storedTeamWorkerInput{}, false, err
	}
	return value, true, nil
}

func readTeamWorkerInput(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID uuid.UUID,
	ownerID string,
	inputID uuid.UUID,
	lock bool,
) (storedTeamWorkerInput, error) {
	statement := `
		SELECT input.owner_id, input.execution_id, input.execution_digest,
		       input.role_id, input.role_digest,
		       input.task_id, input.task_step_id, input.deployment_id,
		       input.expected_worker_id,
		       input.context_snapshot_id, input.context_digest,
		       input.workspace_snapshot_id, input.workspace_digest,
		       input.manifest_digest, input.runtime_task_digest,
		       input.execution_bundle_digest,
		       input.credential_grant_digest,
		       input.materialization_json,
		       input.manifest_json, input.manifest_raw,
		       input.execution_bundle_json, input.execution_bundle_raw,
		       input.status, input.record_revision,
		       input.created_at, input.updated_at
		FROM team_worker_inputs input
		JOIN team_executions execution
		  ON execution.execution_id=input.execution_id
		 AND execution.agent_instance_id=input.agent_instance_id
		 AND execution.owner_id=input.owner_id
		 AND execution.task_id=input.task_id
		 AND execution.execution_digest=input.execution_digest
		JOIN team_execution_roles role
		  ON role.execution_id=input.execution_id
		 AND role.role_id=input.role_id
		 AND role.role_digest=input.role_digest
		 AND role.task_step_id=input.task_step_id
		 AND role.deployment_id=input.deployment_id
		 AND role.expected_worker_id=input.expected_worker_id
		WHERE input.input_id=$1
		  AND input.agent_instance_id=$2
		  AND input.owner_id=$3`
	if lock {
		statement += " FOR UPDATE OF input"
	}
	var (
		stored                       storedTeamWorkerInput
		storedOwner, executionDigest string
		roleID, roleDigest, status   string
		contextDigest                string
		workspaceDigest              string
		manifestDigest               string
		runtimeTaskDigest            string
		executionBundleDigest        string
		credentialGrantDigest        string
		executionID, taskID          uuid.UUID
		taskStepID, deploymentID     uuid.UUID
		expectedWorkerID             uuid.UUID
		contextSnapshotID            uuid.UUID
		workspaceSnapshotID          uuid.UUID
		materializationJSON          []byte
		manifestDocument             []byte
		executionBundleDocument      []byte
		recordRevision               int64
	)
	err := query.QueryRow(
		ctx,
		statement,
		inputID,
		instanceID,
		ownerID,
	).Scan(
		&storedOwner,
		&executionID,
		&executionDigest,
		&roleID,
		&roleDigest,
		&taskID,
		&taskStepID,
		&deploymentID,
		&expectedWorkerID,
		&contextSnapshotID,
		&contextDigest,
		&workspaceSnapshotID,
		&workspaceDigest,
		&manifestDigest,
		&runtimeTaskDigest,
		&executionBundleDigest,
		&credentialGrantDigest,
		&materializationJSON,
		&manifestDocument,
		&stored.manifestJSON,
		&executionBundleDocument,
		&stored.executionBundle,
		&status,
		&recordRevision,
		&stored.fact.CreatedAt,
		&stored.fact.UpdatedAt,
	)
	if err != nil {
		return storedTeamWorkerInput{}, err
	}
	if recordRevision <= 0 ||
		decodeStrictTeamWorkerInputJSON(
			materializationJSON,
			&stored.fact.Materialization,
		) != nil ||
		stored.fact.Materialization.Validate() != nil ||
		!validTeamWorkerInputStatus(teaminput.Status(status)) ||
		security.ContainsLikelySecret(string(materializationJSON)) ||
		security.ContainsLikelySecret(string(stored.manifestJSON)) ||
		security.ContainsLikelySecret(string(stored.executionBundle)) {
		return storedTeamWorkerInput{}, teaminput.ErrFactMismatch
	}
	stored.fact.Status = teaminput.Status(status)
	stored.fact.RecordRevision = uint64(recordRevision)
	stored.fact.CreatedAt = stored.fact.CreatedAt.UTC()
	stored.fact.UpdatedAt = stored.fact.UpdatedAt.UTC()
	value := stored.fact.Materialization
	if value.InputID != inputID.String() ||
		value.OwnerID != storedOwner ||
		value.ExecutionID != executionID.String() ||
		value.ExecutionDigest != executionDigest ||
		value.RoleID != roleID ||
		value.RoleDigest != roleDigest ||
		value.TaskID != taskID.String() ||
		value.TaskStepID != taskStepID.String() ||
		value.DeploymentID != deploymentID.String() ||
		value.ExpectedWorkerID != expectedWorkerID.String() ||
		value.ContextSnapshotID != contextSnapshotID.String() ||
		value.ContextDigest != contextDigest ||
		value.WorkspaceSnapshotID != workspaceSnapshotID.String() ||
		value.WorkspaceDigest != workspaceDigest ||
		value.ManifestDigest != manifestDigest ||
		value.RuntimeTaskDigest != runtimeTaskDigest ||
		value.ExecutionBundleDigest != executionBundleDigest ||
		value.CredentialGrantDigest != credentialGrantDigest {
		return storedTeamWorkerInput{}, teaminput.ErrFactMismatch
	}
	expectedManifest, err := json.Marshal(value.Manifest)
	if err != nil ||
		!bytes.Equal(expectedManifest, stored.manifestJSON) ||
		!jsonDocumentsEqual(manifestDocument, stored.manifestJSON) ||
		!jsonDocumentsEqual(
			executionBundleDocument,
			stored.executionBundle,
		) ||
		validateTeamWorkerExecutionBundle(
			stored.executionBundle,
			value,
		) != nil {
		clear(expectedManifest)
		return storedTeamWorkerInput{}, teaminput.ErrFactMismatch
	}
	clear(expectedManifest)
	return stored, nil
}

func teamWorkerInputMatchesRequest(
	fact teaminput.Fact,
	request teaminput.MaterializeRequest,
) bool {
	return fact.Materialization.OwnerID == request.OwnerID &&
		fact.Materialization.ExecutionID == request.ExecutionID &&
		fact.Materialization.RoleID == request.RoleID
}

func sameTeamWorkerInputMaterialization(
	left,
	right teaminput.Fact,
) bool {
	return reflect.DeepEqual(
		left.Materialization,
		right.Materialization,
	) &&
		left.CreatedAt.Equal(right.CreatedAt) &&
		left.RecordRevision <= right.RecordRevision
}

func setTeamWorkerInputReplay(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	key string,
	fact teaminput.Fact,
) error {
	return setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		materializeTeamWorkerInputOperation,
		key,
		teamWorkerInputReplay{
			SchemaVersion: teamWorkerInputReplaySchemaV1,
			Fact:          fact,
		},
	)
}

func decodeTeamWorkerInputReplay(
	encoded []byte,
) (teaminput.Fact, error) {
	var replay teamWorkerInputReplay
	if decodeStrictTeamWorkerInputJSON(encoded, &replay) != nil ||
		replay.SchemaVersion != teamWorkerInputReplaySchemaV1 ||
		replay.Fact.Materialization.Validate() != nil ||
		!validTeamWorkerInputStatus(replay.Fact.Status) ||
		replay.Fact.RecordRevision == 0 ||
		replay.Fact.CreatedAt.IsZero() ||
		replay.Fact.UpdatedAt.IsZero() {
		return teaminput.Fact{}, teaminput.ErrFactMismatch
	}
	replay.Fact.CreatedAt = replay.Fact.CreatedAt.UTC()
	replay.Fact.UpdatedAt = replay.Fact.UpdatedAt.UTC()
	return replay.Fact, nil
}

func decodeStrictTeamWorkerInputJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return teaminput.ErrFactMismatch
	}
	return nil
}

func jsonDocumentsEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil &&
		json.Unmarshal(right, &rightValue) == nil &&
		reflect.DeepEqual(leftValue, rightValue)
}

func validTeamWorkerInputStatus(status teaminput.Status) bool {
	switch status {
	case teaminput.StatusMaterialized,
		teaminput.StatusPublished,
		teaminput.StatusCredentialReady,
		teaminput.StatusLaunchReady:
		return true
	default:
		return false
	}
}

func validTeamWorkerInputOwnerID(value string) bool {
	if !validTeamOwnerID(value) ||
		!utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

var _ teaminput.Repository = (*Store)(nil)
