package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	claimTeamRoleDispatchOperation = "team.role_dispatch.claim"
	teamRoleDispatchReplaySchemaV1 = 1
)

type teamRoleDispatchReplay struct {
	SchemaVersion int               `json:"schema_version"`
	Fact          teamdispatch.Fact `json:"fact"`
}

func (store *Store) ClaimRole(
	ctx context.Context,
	scope task.MutationScope,
	command teamdispatch.ClaimCommand,
) (teamdispatch.Fact, bool, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil {
		return teamdispatch.Fact{}, false, teamdispatch.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teamdispatch.Fact{}, false, err
	}
	requestDigest, err := teamMutationDigest(command)
	if err != nil {
		return teamdispatch.Fact{}, false, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.Intent.OperationID)
	executionID := uuid.MustParse(command.Intent.ExecutionID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{}, false,
			fmt.Errorf("begin Team role dispatch claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replayed, aggregateID, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		claimTeamRoleDispatchOperation,
		command.IdempotencyKey,
		requestDigest[:],
		operationID,
	)
	if err != nil {
		return teamdispatch.Fact{}, false, err
	}
	if replayed {
		snapshot, decodeErr := decodeTeamRoleDispatchReplay(response)
		persisted, readErr := readTeamRoleDispatch(
			ctx,
			tx,
			store.instanceID,
			command.Intent.OwnerID,
			operationID,
			false,
		)
		if decodeErr != nil ||
			readErr != nil ||
			aggregateID != operationID ||
			!sameTeamRoleDispatchIntent(
				snapshot.Intent,
				command.Intent,
			) ||
			!sameTeamRoleDispatchIntent(
				persisted.Intent,
				command.Intent,
			) {
			return teamdispatch.Fact{}, false,
				teamdispatch.ErrFactMismatch
		}
		if err := tx.Commit(ctx); err != nil {
			return teamdispatch.Fact{}, false,
				fmt.Errorf("commit Team role dispatch replay: %w", err)
		}
		return persisted, true, nil
	}

	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		command.Intent.OwnerID,
		executionID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, false, mapTeamDispatchReadError(err)
	}
	approval, err := readStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		execution.Execution,
	)
	if err != nil {
		return teamdispatch.Fact{}, false, err
	}
	authorized := teamdispatch.AuthorizedExecution{
		Approval:  approval,
		Execution: execution,
	}
	var databaseNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return teamdispatch.Fact{}, false,
			fmt.Errorf("read Team dispatch database time: %w", err)
	}
	if authorized.ValidateForLaunch(databaseNow.UTC()) != nil ||
		command.Intent.ValidateAgainst(authorized) != nil ||
		command.MaxConcurrentRoles !=
			execution.Execution.MaxConcurrentWorkers {
		return teamdispatch.Fact{}, false, teamdispatch.ErrNotReady
	}

	existing, found, err := findTeamRoleDispatchByRole(
		ctx,
		tx,
		store.instanceID,
		command.Intent.OwnerID,
		executionID,
		command.Intent.RoleID,
	)
	if err != nil {
		return teamdispatch.Fact{}, false, err
	}
	if found {
		if !sameTeamRoleDispatchIntent(existing.Intent, command.Intent) {
			return teamdispatch.Fact{}, false,
				teamdispatch.ErrFactMismatch
		}
		if err := setTeamRoleDispatchReplay(
			ctx,
			tx,
			caller,
			command.IdempotencyKey,
			existing,
		); err != nil {
			return teamdispatch.Fact{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return teamdispatch.Fact{}, false,
				fmt.Errorf(
					"commit converged Team role dispatch: %w",
					err,
				)
		}
		return existing, true, nil
	}
	ready, err := teamRoleReadyForDispatch(
		ctx,
		tx,
		executionID,
		command.Intent.TaskID,
		command.Intent.TaskStepID,
		command.Intent.RoleID,
	)
	if err != nil {
		return teamdispatch.Fact{}, false, err
	}
	if !ready {
		return teamdispatch.Fact{}, false, teamdispatch.ErrNotReady
	}
	var reserved uint32
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM team_role_dispatches
		WHERE execution_id=$1
		  AND phase <> 'completed'`,
		executionID,
	).Scan(&reserved); err != nil {
		return teamdispatch.Fact{}, false,
			fmt.Errorf("count reserved Team role dispatches: %w", err)
	}
	if reserved >= command.MaxConcurrentRoles {
		return teamdispatch.Fact{}, false,
			teamdispatch.ErrConcurrencyLimit
	}
	intentJSON, err := json.Marshal(command.Intent)
	if err != nil || len(intentJSON) == 0 || len(intentJSON) > 1<<20 {
		return teamdispatch.Fact{}, false, teamdispatch.ErrInvalid
	}
	intentDigest, err := command.Intent.Digest()
	if err != nil {
		return teamdispatch.Fact{}, false, teamdispatch.ErrInvalid
	}
	fact := teamdispatch.Fact{
		Intent:         command.Intent,
		IntentDigest:   intentDigest,
		Phase:          teamdispatch.PhaseIntent,
		Outcome:        task.OutcomePending,
		RecordRevision: 1,
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_role_dispatches (
		    operation_id, agent_instance_id, owner_id,
		    execution_id, execution_digest,
		    plan_id, plan_revision, plan_digest, approval_id,
		    launch_authorization_id, launch_authorization_digest,
		    role_id, role_digest, task_id, task_step_id,
		    deployment_id, expected_worker_id, model_credential_ref,
		    maximum_approved_cost_micros, launch_not_after,
		    intent_digest, intent_json, phase, outcome_status,
		    attempt, record_revision
		)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
		    $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26
		)
		RETURNING created_at, updated_at`,
		command.Intent.OperationID,
		store.instanceID,
		command.Intent.OwnerID,
		command.Intent.ExecutionID,
		command.Intent.ExecutionDigest,
		command.Intent.PlanID,
		int64(command.Intent.PlanRevision),
		command.Intent.PlanDigest,
		command.Intent.ApprovalID,
		command.Intent.LaunchAuthorizationID,
		command.Intent.LaunchAuthorizationDigest,
		command.Intent.RoleID,
		command.Intent.RoleDigest,
		command.Intent.TaskID,
		command.Intent.TaskStepID,
		command.Intent.DeploymentID,
		command.Intent.ExpectedWorkerID,
		command.Intent.ModelCredentialRef,
		int64(command.Intent.MaximumApprovedCostMicros),
		command.Intent.LaunchNotAfter,
		fact.IntentDigest,
		intentJSON,
		fact.Phase,
		fact.Outcome,
		fact.Attempt,
		int64(fact.RecordRevision),
	).Scan(&fact.CreatedAt, &fact.UpdatedAt); err != nil {
		return teamdispatch.Fact{}, false,
			fmt.Errorf("insert Team role dispatch: %w", err)
	}
	fact.CreatedAt = fact.CreatedAt.UTC()
	fact.UpdatedAt = fact.UpdatedAt.UTC()
	if fact.Validate() != nil {
		return teamdispatch.Fact{}, false, teamdispatch.ErrFactMismatch
	}
	if err := setTeamRoleDispatchReplay(
		ctx,
		tx,
		caller,
		command.IdempotencyKey,
		fact,
	); err != nil {
		return teamdispatch.Fact{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{}, false,
			fmt.Errorf("commit Team role dispatch claim: %w", err)
	}
	return fact, false, nil
}

func (store *Store) ListExecutionOperations(
	ctx context.Context,
	ownerID,
	executionID string,
) ([]teamdispatch.Fact, error) {
	parsed, err := uuid.Parse(executionID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID {
		return nil, teamdispatch.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, teamRoleDispatchSelect+`
		WHERE dispatch.agent_instance_id=$1
		  AND dispatch.owner_id=$2
		  AND dispatch.execution_id=$3
		ORDER BY dispatch.role_id`,
		store.instanceID,
		ownerID,
		parsed,
	)
	if err != nil {
		return nil, fmt.Errorf("query Team role dispatches: %w", err)
	}
	return readTeamRoleDispatchRows(rows)
}

func (store *Store) GetRoleOperation(
	ctx context.Context,
	ownerID,
	operationID string,
) (teamdispatch.Fact, error) {
	parsed, err := uuid.Parse(operationID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != operationID {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	return readTeamRoleDispatch(
		ctx,
		store.pool,
		store.instanceID,
		ownerID,
		parsed,
		false,
	)
}

func (store *Store) AdvanceRole(
	ctx context.Context,
	command teamdispatch.AdvanceCommand,
) (teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil ||
		command.ToPhase == teamdispatch.PhaseArtifactsReady {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.OperationID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("begin Team role phase advance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		operationID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	if current.RecordRevision != command.ExpectedRevision ||
		current.Phase != command.FromPhase {
		if current.Phase == command.ToPhase &&
			current.Outcome == command.Outcome {
			if err := tx.Commit(ctx); err != nil {
				return teamdispatch.Fact{},
					fmt.Errorf(
						"commit converged Team role phase: %w",
						err,
					)
			}
			return current, nil
		}
		return teamdispatch.Fact{},
			teamdispatch.ErrRevisionConflict
	}
	if err := tx.QueryRow(ctx, `
		UPDATE team_role_dispatches
		SET phase=$4,
		    outcome_status=$5,
		    retry_after=NULL,
		    failure_code=NULL,
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, clock_timestamp())
		WHERE operation_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND phase=$6
		  AND record_revision=$7
		RETURNING record_revision, updated_at`,
		operationID,
		store.instanceID,
		command.OwnerID,
		command.ToPhase,
		command.Outcome,
		command.FromPhase,
		int64(command.ExpectedRevision),
	).Scan(
		&current.RecordRevision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.Fact{},
				teamdispatch.ErrRevisionConflict
		}
		return teamdispatch.Fact{},
			fmt.Errorf("advance Team role dispatch phase: %w", err)
	}
	current.Phase = command.ToPhase
	current.Outcome = command.Outcome
	current.RetryAfter = nil
	current.FailureCode = ""
	current.UpdatedAt = current.UpdatedAt.UTC()
	if current.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("commit Team role phase advance: %w", err)
	}
	return current, nil
}

func (store *Store) PublishRoleArtifacts(
	ctx context.Context,
	command teamdispatch.PublishArtifactsCommand,
) (teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.OperationID)
	evidenceDigest, err := command.Evidence.Digest()
	if err != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	evidenceJSON, err := json.Marshal(command.Evidence)
	if err != nil || len(evidenceJSON) == 0 || len(evidenceJSON) > 1<<20 {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("begin Team artifact publication: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		operationID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	if current.Phase == teamdispatch.PhaseArtifactsReady &&
		current.PublishedEvidence != nil {
		currentDigest, digestErr := current.PublishedEvidence.Digest()
		if digestErr == nil &&
			currentDigest == evidenceDigest &&
			current.PublishedEvidenceDigest == evidenceDigest {
			if err := tx.Commit(ctx); err != nil {
				return teamdispatch.Fact{},
					fmt.Errorf(
						"commit converged Team artifact publication: %w",
						err,
					)
			}
			return current, nil
		}
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if current.RecordRevision != command.ExpectedRevision ||
		current.Phase != teamdispatch.PhaseInputReady ||
		command.Evidence.ValidateAgainst(current.Intent) != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		uuid.MustParse(current.Intent.ExecutionID),
		false,
	)
	if err != nil {
		return teamdispatch.Fact{}, mapTeamDispatchReadError(err)
	}
	approval, err := readStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		execution.Execution,
	)
	if err != nil ||
		approval.Approval.Authorization == nil ||
		command.Evidence.ConnectionID !=
			approval.Approval.Authorization.ProviderScope.ConnectionID {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	var databaseNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("read Team publication database time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if err := tx.QueryRow(ctx, `
		UPDATE team_role_dispatches
		SET published_evidence_digest=$4,
		    published_evidence_json=$5,
		    published_at=$6,
		    phase='artifacts_ready',
		    outcome_status='pending',
		    retry_after=NULL,
		    failure_code=NULL,
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, $6)
		WHERE operation_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND phase='input_ready'
		  AND record_revision=$7
		RETURNING record_revision, updated_at`,
		operationID,
		store.instanceID,
		command.OwnerID,
		evidenceDigest,
		evidenceJSON,
		databaseNow,
		int64(command.ExpectedRevision),
	).Scan(
		&current.RecordRevision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.Fact{},
				teamdispatch.ErrRevisionConflict
		}
		return teamdispatch.Fact{},
			fmt.Errorf("freeze Team artifact publication: %w", err)
	}
	evidence := command.Evidence
	publishedAt := databaseNow
	current.PublishedEvidence = &evidence
	current.PublishedEvidenceDigest = evidenceDigest
	current.PublishedAt = &publishedAt
	current.Phase = teamdispatch.PhaseArtifactsReady
	current.Outcome = task.OutcomePending
	current.RetryAfter = nil
	current.FailureCode = ""
	current.UpdatedAt = current.UpdatedAt.UTC()
	if current.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("commit Team artifact publication: %w", err)
	}
	return current, nil
}

func (store *Store) RecordRoleResult(
	ctx context.Context,
	command teamdispatch.RecordResultCommand,
) (teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	evidenceDigest, err := command.Evidence.Digest()
	if err != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	evidenceJSON, err := json.Marshal(command.Evidence)
	if err != nil ||
		len(evidenceJSON) == 0 ||
		len(evidenceJSON) > 1<<20 {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.OperationID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("begin Team result recording: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		operationID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	if current.ResultEvidence != nil {
		currentDigest, digestErr := current.ResultEvidence.Digest()
		if digestErr == nil &&
			currentDigest == evidenceDigest &&
			current.ResultEvidenceDigest == evidenceDigest {
			if err := writeAndVerifyTeamArtifacts(
				ctx,
				tx,
				store.instanceID,
				current.Intent,
				command.Artifacts,
			); err != nil {
				return teamdispatch.Fact{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return teamdispatch.Fact{},
					fmt.Errorf(
						"commit converged Team result: %w",
						err,
					)
			}
			return current, nil
		}
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if current.RecordRevision != command.ExpectedRevision ||
		current.Phase != teamdispatch.PhaseActive ||
		command.Evidence.OperationID !=
			current.Intent.OperationID ||
		command.Evidence.ExecutionID !=
			current.Intent.ExecutionID ||
		command.Evidence.RoleID != current.Intent.RoleID ||
		command.Evidence.DeploymentID !=
			current.Intent.DeploymentID ||
		command.Evidence.ExpectedWorkerID !=
			current.Intent.ExpectedWorkerID ||
		command.Evidence.TaskID != current.Intent.TaskID ||
		command.Evidence.TaskStepID !=
			current.Intent.TaskStepID {
		return teamdispatch.Fact{},
			teamdispatch.ErrRevisionConflict
	}
	deployment, err := loadWorkerForUpdate(
		ctx,
		tx,
		uuid.MustParse(current.Intent.DeploymentID),
		store.instanceID,
	)
	if err != nil {
		if errors.Is(err, worker.ErrNotFound) {
			return teamdispatch.Fact{}, teamdispatch.ErrNotReady
		}
		return teamdispatch.Fact{}, err
	}
	if validateWorkerDeployment(deployment) != nil ||
		!workerResultEvidenceMatches(
			current.Intent,
			deployment,
			command.Evidence,
		) {
		return teamdispatch.Fact{},
			teamdispatch.ErrFactMismatch
	}
	var databaseNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("read Team result database time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if err := tx.QueryRow(ctx, `
		UPDATE team_role_dispatches
		SET result_evidence_digest=$4,
		    result_evidence_json=$5,
		    result_verified_at=$6,
		    phase='result_ready',
		    outcome_status='pending',
		    retry_after=NULL,
		    failure_code=NULL,
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, $6)
		WHERE operation_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND phase='active'
		  AND record_revision=$7
		RETURNING record_revision, updated_at`,
		operationID,
		store.instanceID,
		command.OwnerID,
		evidenceDigest,
		evidenceJSON,
		databaseNow,
		int64(command.ExpectedRevision),
	).Scan(
		&current.RecordRevision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.Fact{},
				teamdispatch.ErrRevisionConflict
		}
		return teamdispatch.Fact{},
			fmt.Errorf("freeze Team role result: %w", err)
	}
	if err := writeAndVerifyTeamArtifacts(
		ctx,
		tx,
		store.instanceID,
		current.Intent,
		command.Artifacts,
	); err != nil {
		return teamdispatch.Fact{}, err
	}
	evidence := command.Evidence
	verifiedAt := databaseNow
	current.ResultEvidence = &evidence
	current.ResultEvidenceDigest = evidenceDigest
	current.ResultVerifiedAt = &verifiedAt
	current.Phase = teamdispatch.PhaseResultReady
	current.Outcome = task.OutcomePending
	current.RetryAfter = nil
	current.FailureCode = ""
	current.UpdatedAt = current.UpdatedAt.UTC()
	if current.Validate() != nil {
		return teamdispatch.Fact{},
			teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("commit Team role result: %w", err)
	}
	return current, nil
}

func writeAndVerifyTeamArtifacts(
	ctx context.Context,
	tx pgx.Tx,
	agentInstanceID uuid.UUID,
	intent teamdispatch.IntentV1,
	artifacts []teamartifact.ArtifactV1,
) error {
	if ctx == nil || tx == nil || intent.Validate() != nil ||
		len(artifacts) == 0 ||
		len(artifacts) > teamartifact.MaximumArtifactsPerRole {
		return teamdispatch.ErrInvalid
	}
	for _, artifact := range artifacts {
		if artifact.Validate() != nil ||
			artifact.AgentInstanceID != agentInstanceID.String() ||
			artifact.OwnerID != intent.OwnerID ||
			artifact.ExecutionID != intent.ExecutionID ||
			artifact.OperationID != intent.OperationID ||
			artifact.TaskID != intent.TaskID ||
			artifact.PlanID != intent.PlanID ||
			artifact.PlanRevision != intent.PlanRevision ||
			artifact.RoleID != intent.RoleID ||
			artifact.DeploymentID != intent.DeploymentID {
			return teamdispatch.ErrFactMismatch
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO team_artifacts (
			    artifact_id,
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
			) VALUES (
			    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
			    $12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
			)
			ON CONFLICT (artifact_id) DO NOTHING`,
			uuid.MustParse(artifact.ArtifactID),
			artifact.SchemaVersion,
			agentInstanceID,
			artifact.OwnerID,
			uuid.MustParse(artifact.ExecutionID),
			uuid.MustParse(artifact.OperationID),
			uuid.MustParse(artifact.TaskID),
			uuid.MustParse(artifact.PlanID),
			int64(artifact.PlanRevision),
			uuid.MustParse(artifact.ConnectionID),
			artifact.RoleID,
			artifact.ActionID,
			uuid.MustParse(artifact.DeploymentID),
			artifact.Name,
			string(artifact.Kind),
			artifact.MediaType,
			artifact.SizeBytes,
			artifact.SHA256,
			artifact.ObjectRef,
			string(artifact.Verification),
			artifact.CreatedAt,
			artifact.RetentionExpires,
		); err != nil {
			return fmt.Errorf("persist Team artifact: %w", err)
		}
	}
	rows, err := tx.Query(ctx, `
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
		WHERE operation_id=$1
		ORDER BY artifact_id`,
		uuid.MustParse(intent.OperationID),
	)
	if err != nil {
		return fmt.Errorf("read persisted Team artifacts: %w", err)
	}
	defer rows.Close()
	expected := make(map[string]teamartifact.ArtifactV1, len(artifacts))
	for _, artifact := range artifacts {
		expected[artifact.ArtifactID] = artifact
	}
	seen := 0
	for rows.Next() {
		artifact, scanErr := scanTeamArtifact(rows)
		if scanErr != nil {
			return scanErr
		}
		want, found := expected[artifact.ArtifactID]
		if !found || !sameTeamArtifact(want, artifact) {
			return teamdispatch.ErrFactMismatch
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate persisted Team artifacts: %w", err)
	}
	if seen != len(expected) {
		return teamdispatch.ErrFactMismatch
	}
	return nil
}

func workerResultEvidenceMatches(
	intent teamdispatch.IntentV1,
	deployment worker.Deployment,
	evidence teamresult.EvidenceV1,
) bool {
	if evidence.Validate() != nil ||
		deployment.DeploymentID != intent.DeploymentID ||
		deployment.OwnerID != intent.OwnerID ||
		deployment.TaskID != intent.TaskID ||
		deployment.StepID != intent.TaskStepID ||
		deployment.WorkerID != intent.ExpectedWorkerID ||
		deployment.State != worker.StateFinished ||
		deployment.Outcome != worker.OutcomeSucceeded ||
		deployment.Lease.Attempt != evidence.Attempt ||
		deployment.Lease.Epoch != evidence.LeaseEpoch ||
		deployment.ResultRef != evidence.ResultRef {
		return false
	}
	found := false
	for _, claim := range deployment.Evidence {
		if claim.Kind != "artifact" ||
			claim.Ref != evidence.ResultRef {
			continue
		}
		if found ||
			claim.Trust != worker.TrustWorkerClaim ||
			claim.Attempt != evidence.Attempt ||
			claim.LeaseEpoch != evidence.LeaseEpoch ||
			claim.ObjectSHA256 != evidence.ResultSHA256 ||
			claim.SizeBytes != evidence.ResultSizeBytes ||
			claim.MediaType != evidence.ResultMediaType {
			return false
		}
		found = true
	}
	return found
}

func (store *Store) ScheduleRoleRetry(
	ctx context.Context,
	command teamdispatch.RetryCommand,
) (teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.OperationID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("begin Team role retry schedule: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		operationID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	if current.RecordRevision != command.ExpectedRevision ||
		current.Phase != command.Phase {
		if current.Phase == command.Phase &&
			current.FailureCode == command.FailureCode &&
			current.RetryAfter != nil &&
			current.RetryAfter.Equal(command.RetryAfter) {
			if err := tx.Commit(ctx); err != nil {
				return teamdispatch.Fact{},
					fmt.Errorf(
						"commit converged Team role retry: %w",
						err,
					)
			}
			return current, nil
		}
		return teamdispatch.Fact{},
			teamdispatch.ErrRevisionConflict
	}
	var databaseNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("read Team retry database time: %w", err)
	}
	if command.RetryAfter.Before(
		databaseNow.UTC().Truncate(time.Microsecond),
	) {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	if current.Attempt >= 100 {
		return teamdispatch.Fact{}, teamdispatch.ErrNotReady
	}
	if err := tx.QueryRow(ctx, `
		UPDATE team_role_dispatches
		SET attempt=attempt+1,
		    retry_after=$4,
		    failure_code=$5,
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, clock_timestamp())
		WHERE operation_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND phase=$6
		  AND record_revision=$7
		RETURNING attempt, record_revision, updated_at`,
		operationID,
		store.instanceID,
		command.OwnerID,
		command.RetryAfter,
		command.FailureCode,
		command.Phase,
		int64(command.ExpectedRevision),
	).Scan(
		&current.Attempt,
		&current.RecordRevision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.Fact{},
				teamdispatch.ErrRevisionConflict
		}
		return teamdispatch.Fact{},
			fmt.Errorf("schedule Team role dispatch retry: %w", err)
	}
	retryAfter := command.RetryAfter
	current.RetryAfter = &retryAfter
	current.FailureCode = command.FailureCode
	current.UpdatedAt = current.UpdatedAt.UTC()
	if current.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("commit Team role retry schedule: %w", err)
	}
	return current, nil
}

func (store *Store) BeginProvisioning(
	ctx context.Context,
	command teamdispatch.BeginProvisioningCommand,
) (teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	quoteDigest, err := command.Quote.Digest()
	if err != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	quoteJSON, err := json.Marshal(command.Quote)
	if err != nil || len(quoteJSON) == 0 || len(quoteJSON) > 1<<20 {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.OperationID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("begin Team role provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		operationID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	if current.RecordRevision != command.ExpectedRevision ||
		current.Phase != teamdispatch.PhaseBootstrapReady {
		if current.ProvisioningQuote != nil &&
			current.ProvisioningQuoteDigest == quoteDigest &&
			current.ProvisioningWorkerRevision ==
				command.WorkerDeploymentRevision {
			if err := tx.Commit(ctx); err != nil {
				return teamdispatch.Fact{},
					fmt.Errorf(
						"commit converged Team provisioning: %w",
						err,
					)
			}
			return current, nil
		}
		return teamdispatch.Fact{},
			teamdispatch.ErrRevisionConflict
	}
	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		uuid.MustParse(current.Intent.ExecutionID),
		false,
	)
	if err != nil {
		return teamdispatch.Fact{}, mapTeamDispatchReadError(err)
	}
	approval, err := readStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		execution.Execution,
	)
	if err != nil || approval.Approval.Authorization == nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	authorization := *approval.Approval.Authorization
	if command.Quote.ValidateAgainstAuthorization(
		authorization,
	) != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	deployment, err := loadWorkerForUpdate(
		ctx,
		tx,
		uuid.MustParse(current.Intent.DeploymentID),
		store.instanceID,
	)
	if err != nil {
		if errors.Is(err, worker.ErrNotFound) {
			return teamdispatch.Fact{}, teamdispatch.ErrNotReady
		}
		return teamdispatch.Fact{}, err
	}
	if validateWorkerDeployment(deployment) != nil ||
		deployment.DeploymentID != current.Intent.DeploymentID ||
		deployment.OwnerID != current.Intent.OwnerID ||
		deployment.TaskID != current.Intent.TaskID ||
		deployment.StepID != current.Intent.TaskStepID {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if deployment.Revision <= 0 ||
		uint64(deployment.Revision) !=
			command.WorkerDeploymentRevision {
		return teamdispatch.Fact{},
			teamdispatch.ErrRevisionConflict
	}
	if deployment.State != worker.StatePendingEnrollment ||
		deployment.Outcome != worker.OutcomePending ||
		deployment.WorkerID != "" ||
		deployment.ProviderInstanceID != "" {
		return teamdispatch.Fact{}, teamdispatch.ErrNotReady
	}
	var databaseNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("read Team provisioning database time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if authorization.ValidateAt(databaseNow) != nil ||
		databaseNow.Before(command.Quote.CapturedAt) ||
		!databaseNow.Before(command.Quote.ValidUntil) ||
		!databaseNow.Before(deployment.Enrollment.ExpiresAt) {
		return teamdispatch.Fact{}, teamdispatch.ErrNotReady
	}
	if err := tx.QueryRow(ctx, `
		UPDATE team_role_dispatches
		SET provisioning_quote_digest=$4,
		    provisioning_quote_json=$5,
		    provisioning_quote_valid_until=$6,
		    provisioning_started_at=$7,
		    provisioning_worker_revision=$8,
		    provisioning_enrollment_expires_at=$9,
		    phase='provisioning',
		    outcome_status='pending',
		    retry_after=NULL,
		    failure_code=NULL,
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, $7)
		WHERE operation_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND phase='bootstrap_ready'
		  AND record_revision=$10
		RETURNING record_revision, updated_at`,
		operationID,
		store.instanceID,
		command.OwnerID,
		quoteDigest,
		quoteJSON,
		command.Quote.ValidUntil,
		databaseNow,
		deployment.Revision,
		deployment.Enrollment.ExpiresAt,
		int64(command.ExpectedRevision),
	).Scan(
		&current.RecordRevision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.Fact{},
				teamdispatch.ErrRevisionConflict
		}
		return teamdispatch.Fact{},
			fmt.Errorf("freeze Team role provisioning quote: %w", err)
	}
	quote := command.Quote
	startedAt := databaseNow
	enrollmentExpires := deployment.Enrollment.ExpiresAt.UTC()
	current.ProvisioningQuote = &quote
	current.ProvisioningQuoteDigest = quoteDigest
	current.ProvisioningStartedAt = &startedAt
	current.ProvisioningWorkerRevision = uint64(deployment.Revision)
	current.ProvisioningEnrollmentExpires = &enrollmentExpires
	current.Phase = teamdispatch.PhaseProvisioning
	current.Outcome = task.OutcomePending
	current.RetryAfter = nil
	current.FailureCode = ""
	current.UpdatedAt = current.UpdatedAt.UTC()
	if current.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("commit Team role provisioning: %w", err)
	}
	return current, nil
}

func (store *Store) RefreshProvisioningQuote(
	ctx context.Context,
	command teamdispatch.RefreshProvisioningQuoteCommand,
) (teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		command.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	quoteDigest, err := command.Quote.Digest()
	if err != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	quoteJSON, err := json.Marshal(command.Quote)
	if err != nil || len(quoteJSON) == 0 || len(quoteJSON) > 1<<20 {
		return teamdispatch.Fact{}, teamdispatch.ErrInvalid
	}
	operationID := uuid.MustParse(command.OperationID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("begin Team quote refresh: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		operationID,
		true,
	)
	if err != nil {
		return teamdispatch.Fact{}, err
	}
	if current.Phase == teamdispatch.PhaseProvisioning &&
		current.ProvisioningQuoteDigest == quoteDigest {
		if err := tx.Commit(ctx); err != nil {
			return teamdispatch.Fact{},
				fmt.Errorf("commit converged Team quote refresh: %w", err)
		}
		return current, nil
	}
	if current.RecordRevision != command.ExpectedRevision ||
		current.Phase != teamdispatch.PhaseProvisioning ||
		current.ProvisioningQuote == nil ||
		current.ProvisioningStartedAt == nil ||
		current.ProvisioningWorkerRevision == 0 ||
		current.ProvisioningEnrollmentExpires == nil ||
		!command.Quote.CapturedAt.After(
			current.ProvisioningQuote.CapturedAt,
		) {
		return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
	}
	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		uuid.MustParse(current.Intent.ExecutionID),
		false,
	)
	if err != nil {
		return teamdispatch.Fact{}, mapTeamDispatchReadError(err)
	}
	approval, err := readStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		execution.Execution,
	)
	if err != nil || approval.Approval.Authorization == nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	authorization := *approval.Approval.Authorization
	if command.Quote.ValidateAgainstAuthorization(
		authorization,
	) != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	deployment, err := loadWorkerForUpdate(
		ctx,
		tx,
		uuid.MustParse(current.Intent.DeploymentID),
		store.instanceID,
	)
	if err != nil {
		if errors.Is(err, worker.ErrNotFound) {
			return teamdispatch.Fact{}, teamdispatch.ErrNotReady
		}
		return teamdispatch.Fact{}, err
	}
	if validateWorkerDeployment(deployment) != nil ||
		deployment.DeploymentID != current.Intent.DeploymentID ||
		deployment.OwnerID != current.Intent.OwnerID ||
		deployment.TaskID != current.Intent.TaskID ||
		deployment.StepID != current.Intent.TaskStepID ||
		deployment.Revision <= 0 ||
		uint64(deployment.Revision) !=
			current.ProvisioningWorkerRevision ||
		deployment.State != worker.StatePendingEnrollment ||
		deployment.Outcome != worker.OutcomePending ||
		deployment.WorkerID != "" ||
		deployment.ProviderInstanceID != "" ||
		!deployment.Enrollment.ExpiresAt.Equal(
			*current.ProvisioningEnrollmentExpires,
		) {
		return teamdispatch.Fact{}, teamdispatch.ErrNotReady
	}
	var databaseNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT clock_timestamp()`,
	).Scan(&databaseNow); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("read Team quote refresh database time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if authorization.ValidateAt(databaseNow) != nil ||
		databaseNow.Before(command.Quote.CapturedAt) ||
		!databaseNow.Before(command.Quote.ValidUntil) ||
		!databaseNow.Before(deployment.Enrollment.ExpiresAt) {
		return teamdispatch.Fact{}, teamdispatch.ErrNotReady
	}
	if err := tx.QueryRow(ctx, `
		UPDATE team_role_dispatches
		SET provisioning_quote_digest=$4,
		    provisioning_quote_json=$5,
		    provisioning_quote_valid_until=$6,
		    provisioning_started_at=$7,
		    retry_after=NULL,
		    failure_code=NULL,
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, $7)
		WHERE operation_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND phase='provisioning'
		  AND outcome_status='pending'
		  AND record_revision=$8
		  AND provisioning_quote_digest=$9
		RETURNING record_revision, updated_at`,
		operationID,
		store.instanceID,
		command.OwnerID,
		quoteDigest,
		quoteJSON,
		command.Quote.ValidUntil,
		databaseNow,
		int64(command.ExpectedRevision),
		current.ProvisioningQuoteDigest,
	).Scan(
		&current.RecordRevision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.Fact{}, teamdispatch.ErrRevisionConflict
		}
		return teamdispatch.Fact{},
			fmt.Errorf("refresh Team provisioning quote: %w", err)
	}
	quote := command.Quote
	startedAt := databaseNow
	current.ProvisioningQuote = &quote
	current.ProvisioningQuoteDigest = quoteDigest
	current.ProvisioningStartedAt = &startedAt
	current.RetryAfter = nil
	current.FailureCode = ""
	current.UpdatedAt = current.UpdatedAt.UTC()
	if current.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("commit Team quote refresh: %w", err)
	}
	return current, nil
}

func (store *Store) ListRecoverableRoleDispatches(
	ctx context.Context,
	cursor *teamdispatch.RecoverableCursor,
	limit uint32,
	now time.Time,
) ([]teamdispatch.Fact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		limit == 0 ||
		limit > 256 ||
		now.IsZero() {
		return nil, teamdispatch.ErrInvalid
	}
	var (
		cursorTime any
		cursorID   any
	)
	if cursor != nil {
		parsed, err := uuid.Parse(cursor.OperationID)
		if cursor.UpdatedAt.IsZero() ||
			err != nil ||
			parsed == uuid.Nil ||
			parsed.String() != cursor.OperationID {
			return nil, teamdispatch.ErrInvalid
		}
		cursorTime = cursor.UpdatedAt.UTC()
		cursorID = parsed
	}
	rows, err := store.pool.Query(ctx, teamRoleDispatchSelect+`
		WHERE dispatch.agent_instance_id=$1
		  AND (
		      (
		          dispatch.phase <> 'completed'
		          AND (
		              dispatch.retry_after IS NULL
		              OR dispatch.retry_after <= $2
		              OR (
		                  dispatch.phase='provisioning'
		                  AND dispatch.failure_code='launch_authorization_expired'
		                  AND dispatch.provisioning_quote_valid_until <= $2
		                  AND dispatch.provisioning_enrollment_expires_at > $2
		              )
		          )
		      )
		      OR (
		          dispatch.phase='completed'
		          AND dispatch.outcome_status='canceled'
		          AND EXISTS (
		              SELECT 1
		              FROM tasks task_projection
		              WHERE task_projection.task_id=dispatch.task_id
		                AND NOT (
		                    task_projection.execution_status='finished'
		                    AND task_projection.outcome_status='canceled'
		                )
		          )
		      )
		  )
		  AND (
		      $3::timestamptz IS NULL
		      OR (dispatch.updated_at, dispatch.operation_id) >
		         ($3::timestamptz, $4::uuid)
		  )
		ORDER BY dispatch.updated_at, dispatch.operation_id
		LIMIT $5`,
		store.instanceID,
		now.UTC(),
		cursorTime,
		cursorID,
		int64(limit),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"query recoverable Team role dispatches: %w",
			err,
		)
	}
	return readTeamRoleDispatchRows(rows)
}

const teamRoleDispatchSelect = `
	SELECT dispatch.operation_id, dispatch.agent_instance_id,
	       dispatch.owner_id, dispatch.execution_id,
	       dispatch.execution_digest, dispatch.plan_id,
	       dispatch.plan_revision, dispatch.plan_digest,
	       dispatch.approval_id, dispatch.launch_authorization_id,
	       dispatch.launch_authorization_digest, dispatch.role_id,
	       dispatch.role_digest, dispatch.task_id,
	       dispatch.task_step_id, dispatch.deployment_id,
	       dispatch.expected_worker_id, dispatch.model_credential_ref,
		       dispatch.maximum_approved_cost_micros,
		       dispatch.launch_not_after, dispatch.intent_digest,
		       dispatch.intent_json, dispatch.published_evidence_digest,
		       dispatch.published_evidence_json, dispatch.published_at,
		       dispatch.provisioning_quote_digest,
	       dispatch.provisioning_quote_json,
	       dispatch.provisioning_quote_valid_until,
	       dispatch.provisioning_started_at,
	       dispatch.provisioning_worker_revision,
	       dispatch.provisioning_enrollment_expires_at,
	       dispatch.result_evidence_digest,
	       dispatch.result_evidence_json,
	       dispatch.result_verified_at,
	       dispatch.phase,
	       dispatch.outcome_status, dispatch.attempt,
	       dispatch.retry_after, dispatch.failure_code,
	       dispatch.record_revision, dispatch.created_at,
	       dispatch.updated_at
	FROM team_role_dispatches dispatch`

func readTeamRoleDispatchRows(
	rows pgx.Rows,
) ([]teamdispatch.Fact, error) {
	defer rows.Close()
	result := make([]teamdispatch.Fact, 0, 8)
	for rows.Next() {
		fact, err := scanTeamRoleDispatch(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Team role dispatches: %w", err)
	}
	return result, nil
}

type teamRoleDispatchScanner interface {
	Scan(...any) error
}

func scanTeamRoleDispatch(
	row teamRoleDispatchScanner,
) (teamdispatch.Fact, error) {
	var (
		fact                teamdispatch.Fact
		operationID         uuid.UUID
		agentInstanceID     uuid.UUID
		executionID         uuid.UUID
		planID              uuid.UUID
		approvalID          uuid.UUID
		authorizationID     uuid.UUID
		taskID              uuid.UUID
		taskStepID          uuid.UUID
		deploymentID        uuid.UUID
		expectedWorkerID    uuid.UUID
		planRevision        int64
		maximumApprovedCost int64
		recordRevision      int64
		intentJSON          []byte
		evidenceDigest      *string
		evidenceJSON        []byte
		publishedAt         *time.Time
		quoteDigest         *string
		quoteJSON           []byte
		quoteValidUntil     *time.Time
		provisioningStarted *time.Time
		workerRevision      *int64
		enrollmentExpires   *time.Time
		resultDigest        *string
		resultJSON          []byte
		resultVerifiedAt    *time.Time
		retryAfter          *time.Time
		failureCode         *string
	)
	if err := row.Scan(
		&operationID,
		&agentInstanceID,
		&fact.Intent.OwnerID,
		&executionID,
		&fact.Intent.ExecutionDigest,
		&planID,
		&planRevision,
		&fact.Intent.PlanDigest,
		&approvalID,
		&authorizationID,
		&fact.Intent.LaunchAuthorizationDigest,
		&fact.Intent.RoleID,
		&fact.Intent.RoleDigest,
		&taskID,
		&taskStepID,
		&deploymentID,
		&expectedWorkerID,
		&fact.Intent.ModelCredentialRef,
		&maximumApprovedCost,
		&fact.Intent.LaunchNotAfter,
		&fact.IntentDigest,
		&intentJSON,
		&evidenceDigest,
		&evidenceJSON,
		&publishedAt,
		&quoteDigest,
		&quoteJSON,
		&quoteValidUntil,
		&provisioningStarted,
		&workerRevision,
		&enrollmentExpires,
		&resultDigest,
		&resultJSON,
		&resultVerifiedAt,
		&fact.Phase,
		&fact.Outcome,
		&fact.Attempt,
		&retryAfter,
		&failureCode,
		&recordRevision,
		&fact.CreatedAt,
		&fact.UpdatedAt,
	); err != nil {
		return teamdispatch.Fact{},
			fmt.Errorf("scan Team role dispatch: %w", err)
	}
	if planRevision <= 0 ||
		maximumApprovedCost <= 0 ||
		recordRevision <= 0 ||
		decodeStrictTeamDispatchJSON(intentJSON, &fact.Intent) != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	if evidenceDigest != nil ||
		evidenceJSON != nil ||
		publishedAt != nil {
		if evidenceDigest == nil ||
			evidenceJSON == nil ||
			publishedAt == nil {
			return teamdispatch.Fact{},
				teamdispatch.ErrFactMismatch
		}
		var evidence teamdispatch.PublishedEvidenceV1
		if decodeStrictTeamDispatchJSON(
			evidenceJSON,
			&evidence,
		) != nil {
			return teamdispatch.Fact{},
				teamdispatch.ErrFactMismatch
		}
		fact.PublishedEvidence = &evidence
		fact.PublishedEvidenceDigest = *evidenceDigest
		at := publishedAt.UTC()
		fact.PublishedAt = &at
	}
	fact.RetryAfter = retryAfter
	if retryAfter != nil {
		normalized := retryAfter.UTC()
		fact.RetryAfter = &normalized
	}
	if failureCode != nil {
		fact.FailureCode = *failureCode
	}
	if quoteDigest != nil ||
		quoteJSON != nil ||
		quoteValidUntil != nil ||
		provisioningStarted != nil ||
		workerRevision != nil ||
		enrollmentExpires != nil {
		if quoteDigest == nil ||
			quoteJSON == nil ||
			quoteValidUntil == nil ||
			provisioningStarted == nil ||
			workerRevision == nil ||
			*workerRevision <= 0 ||
			enrollmentExpires == nil {
			return teamdispatch.Fact{},
				teamdispatch.ErrFactMismatch
		}
		var quote teamlaunch.FreshQuoteV1
		if decodeStrictTeamDispatchJSON(
			quoteJSON,
			&quote,
		) != nil ||
			!quote.ValidUntil.Equal(quoteValidUntil.UTC()) {
			return teamdispatch.Fact{},
				teamdispatch.ErrFactMismatch
		}
		fact.ProvisioningQuote = &quote
		fact.ProvisioningQuoteDigest = *quoteDigest
		startedAt := provisioningStarted.UTC()
		fact.ProvisioningStartedAt = &startedAt
		fact.ProvisioningWorkerRevision = uint64(*workerRevision)
		expiresAt := enrollmentExpires.UTC()
		fact.ProvisioningEnrollmentExpires = &expiresAt
	}
	if resultDigest != nil ||
		resultJSON != nil ||
		resultVerifiedAt != nil {
		if resultDigest == nil ||
			resultJSON == nil ||
			resultVerifiedAt == nil {
			return teamdispatch.Fact{},
				teamdispatch.ErrFactMismatch
		}
		var evidence teamresult.EvidenceV1
		if decodeStrictTeamDispatchJSON(
			resultJSON,
			&evidence,
		) != nil {
			return teamdispatch.Fact{},
				teamdispatch.ErrFactMismatch
		}
		fact.ResultEvidence = &evidence
		fact.ResultEvidenceDigest = *resultDigest
		verifiedAt := resultVerifiedAt.UTC()
		fact.ResultVerifiedAt = &verifiedAt
	}
	fact.RecordRevision = uint64(recordRevision)
	fact.CreatedAt = fact.CreatedAt.UTC()
	fact.UpdatedAt = fact.UpdatedAt.UTC()
	if fact.Intent.OperationID != operationID.String() ||
		fact.Intent.AgentInstanceID != agentInstanceID.String() ||
		fact.Intent.ExecutionID != executionID.String() ||
		fact.Intent.PlanID != planID.String() ||
		fact.Intent.PlanRevision != uint64(planRevision) ||
		fact.Intent.ApprovalID != approvalID.String() ||
		fact.Intent.LaunchAuthorizationID !=
			authorizationID.String() ||
		fact.Intent.TaskID != taskID.String() ||
		fact.Intent.TaskStepID != taskStepID.String() ||
		fact.Intent.DeploymentID != deploymentID.String() ||
		fact.Intent.ExpectedWorkerID != expectedWorkerID.String() ||
		fact.Intent.MaximumApprovedCostMicros !=
			uint64(maximumApprovedCost) ||
		fact.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	return fact, nil
}

func readTeamRoleDispatch(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID uuid.UUID,
	ownerID string,
	operationID uuid.UUID,
	lock bool,
) (teamdispatch.Fact, error) {
	statement := teamRoleDispatchSelect + `
		WHERE dispatch.operation_id=$1
		  AND dispatch.agent_instance_id=$2
		  AND dispatch.owner_id=$3`
	if lock {
		statement += " FOR UPDATE OF dispatch"
	}
	fact, err := scanTeamRoleDispatch(
		query.QueryRow(
			ctx,
			statement,
			operationID,
			instanceID,
			ownerID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return teamdispatch.Fact{}, teamdispatch.ErrNotFound
	}
	return fact, err
}

func findTeamRoleDispatchByRole(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID uuid.UUID,
	ownerID string,
	executionID uuid.UUID,
	roleID string,
) (teamdispatch.Fact, bool, error) {
	fact, err := scanTeamRoleDispatch(query.QueryRow(
		ctx,
		teamRoleDispatchSelect+`
			WHERE dispatch.agent_instance_id=$1
			  AND dispatch.owner_id=$2
			  AND dispatch.execution_id=$3
			  AND dispatch.role_id=$4`,
		instanceID,
		ownerID,
		executionID,
		roleID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return teamdispatch.Fact{}, false, nil
	}
	return fact, err == nil, err
}

func teamRoleReadyForDispatch(
	ctx context.Context,
	query teamExecutionQuerier,
	executionID uuid.UUID,
	taskID,
	taskStepID,
	roleID string,
) (bool, error) {
	var ready bool
	if err := query.QueryRow(ctx, `
		SELECT step.execution_status='queued'
		   AND step.outcome_status='pending'
		   AND NOT EXISTS (
		       SELECT 1
		       FROM team_execution_role_dependencies dependency
		       JOIN team_execution_roles required_role
		         ON required_role.execution_id=dependency.execution_id
		        AND required_role.role_id=dependency.depends_on_role_id
		       JOIN task_steps required_step
		         ON required_step.task_id=required_role.task_id
		        AND required_step.step_id=required_role.task_step_id
		       WHERE dependency.execution_id=$1
		         AND dependency.role_id=$4
		         AND NOT (
		             required_step.execution_status='finished'
		             AND required_step.outcome_status='succeeded'
		         )
		   )
		FROM team_execution_roles role
		JOIN task_steps step
		  ON step.task_id=role.task_id
		 AND step.step_id=role.task_step_id
		WHERE role.execution_id=$1
		  AND role.task_id=$2
		  AND role.task_step_id=$3
		  AND role.role_id=$4`,
		executionID,
		taskID,
		taskStepID,
		roleID,
	).Scan(&ready); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("verify Team role dispatch readiness: %w", err)
	}
	return ready, nil
}

func setTeamRoleDispatchReplay(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	key string,
	fact teamdispatch.Fact,
) error {
	return setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		claimTeamRoleDispatchOperation,
		key,
		teamRoleDispatchReplay{
			SchemaVersion: teamRoleDispatchReplaySchemaV1,
			Fact:          fact,
		},
	)
}

func decodeTeamRoleDispatchReplay(
	encoded []byte,
) (teamdispatch.Fact, error) {
	var replay teamRoleDispatchReplay
	if decodeStrictTeamDispatchJSON(encoded, &replay) != nil ||
		replay.SchemaVersion != teamRoleDispatchReplaySchemaV1 ||
		replay.Fact.Validate() != nil {
		return teamdispatch.Fact{}, teamdispatch.ErrFactMismatch
	}
	return replay.Fact, nil
}

func decodeStrictTeamDispatchJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return teamdispatch.ErrFactMismatch
	}
	return nil
}

func sameTeamRoleDispatchIntent(
	left,
	right teamdispatch.IntentV1,
) bool {
	return reflect.DeepEqual(left, right)
}

func mapTeamDispatchReadError(err error) error {
	if errors.Is(err, teamexecution.ErrNotFound) ||
		errors.Is(err, pgx.ErrNoRows) {
		return teamdispatch.ErrNotFound
	}
	return err
}

var _ teamdispatch.Repository = (*Store)(nil)
