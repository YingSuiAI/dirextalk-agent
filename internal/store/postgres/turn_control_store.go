package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/turncontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	turnSnapshotSchemaV1 = 1
	beginTurnOperation   = "turn.begin"
	advanceTurnOperation = "turn.advance"
	retryTurnOperation   = "turn.retry"
)

type turnSnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	Turn          turncontrol.Turn `json:"turn"`
}

var _ turncontrol.Store = (*Store)(nil)

func (store *Store) BeginTurn(
	ctx context.Context,
	scope task.MutationScope,
	command turncontrol.BeginCommand,
) (turncontrol.Turn, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return turncontrol.Turn{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return turncontrol.Turn{}, err
	}
	turnID, _ := uuid.Parse(command.TurnID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return turncontrol.Turn{}, fmt.Errorf("begin Turn creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		beginTurnOperation,
		command.IdempotencyKey,
		requestDigest[:],
		turnID,
	)
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if existing {
		turn, err := decodeTurnSnapshot(response)
		if err != nil {
			return turncontrol.Turn{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return turncontrol.Turn{}, fmt.Errorf("commit Turn creation replay: %w", err)
		}
		return turn, nil
	}
	turn, err := scanTurn(tx.QueryRow(ctx, `
		INSERT INTO agent_turns (
		    turn_id, agent_instance_id, caller_client_id,
		    caller_credential_id, request_id, owner_id, conversation_id,
		    goal_digest, phase, route, status, phase_attempt,
		    phase_deadline, revision)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,
		    'prepare','undecided','active',1,$9,1)
		RETURNING `+turnColumns,
		turnID,
		store.instanceID,
		caller.ClientID,
		caller.CredentialID,
		command.RequestID,
		command.OwnerID,
		command.ConversationID,
		command.GoalDigest,
		command.PhaseDeadline.UTC(),
	))
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(fmt.Errorf("insert Turn: %w", err))
	}
	event := turncontrol.Event{
		TurnID:    turn.TurnID,
		Revision:  turn.Revision,
		FromPhase: turncontrol.PhasePrepare,
		ToPhase:   turncontrol.PhasePrepare,
		Authority: turncontrol.AuthorityController,
		Artifact: turncontrol.Artifact{
			Kind:   turncontrol.ArtifactNone,
			Origin: turncontrol.OriginController,
		},
		ValidationOutcome: turncontrol.ValidationUnspecified,
		OccurredAt:        turn.UpdatedAt,
	}
	if err := insertTurnEvent(ctx, tx, event); err != nil {
		return turncontrol.Turn{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		beginTurnOperation,
		command.IdempotencyKey,
		turnSnapshot{SchemaVersion: turnSnapshotSchemaV1, Turn: turn},
	); err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return turncontrol.Turn{}, fmt.Errorf("commit Turn creation: %w", err)
	}
	return turn, nil
}

func (store *Store) GetTurn(
	ctx context.Context,
	ownerID,
	turnID string,
) (turncontrol.Turn, error) {
	parsed, err := uuid.Parse(turnID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != turnID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" ||
		len(ownerID) > 255 {
		return turncontrol.Turn{}, turncontrol.ErrInvalid
	}
	turn, err := scanTurn(store.pool.QueryRow(ctx, `
		SELECT `+turnColumns+`
		FROM agent_turns
		WHERE agent_instance_id=$1 AND owner_id=$2 AND turn_id=$3`,
		store.instanceID,
		ownerID,
		parsed,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return turncontrol.Turn{}, turncontrol.ErrNotFound
	}
	if err != nil {
		return turncontrol.Turn{}, fmt.Errorf("read Turn: %w", err)
	}
	return turn, nil
}

func (store *Store) AdvanceTurn(
	ctx context.Context,
	scope task.MutationScope,
	command turncontrol.AdvanceCommand,
) (turncontrol.Turn, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return turncontrol.Turn{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return turncontrol.Turn{}, err
	}
	turnID, _ := uuid.Parse(command.TurnID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return turncontrol.Turn{}, fmt.Errorf("begin Turn transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		advanceTurnOperation,
		command.IdempotencyKey,
		requestDigest[:],
		turnID,
	)
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if existing {
		turn, err := decodeTurnSnapshot(response)
		if err != nil {
			return turncontrol.Turn{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return turncontrol.Turn{}, fmt.Errorf("commit Turn transition replay: %w", err)
		}
		return turn, nil
	}
	current, err := readCallerTurnForUpdate(
		ctx,
		tx,
		store.instanceID,
		caller,
		command.OwnerID,
		turnID,
	)
	if err != nil {
		return turncontrol.Turn{}, err
	}
	if err := command.ValidateAgainst(current); err != nil {
		return turncontrol.Turn{}, err
	}
	if err := store.verifyTurnAdvance(ctx, tx, current, command); err != nil {
		return turncontrol.Turn{}, err
	}

	targetRoute := current.Route
	if current.Phase == turncontrol.PhaseDecideLocalOrDelegate {
		targetRoute = command.Route
	}
	next := current
	next.Phase = command.NextPhase
	next.Route = targetRoute
	next.Status = turnStatus(command.NextPhase)
	next.PhaseAttempt = 1
	next.PhaseDeadline = command.PhaseDeadline.UTC()
	if command.NextPhase == turncontrol.PhaseFinalize {
		next.PhaseDeadline = time.Time{}
	}
	switch {
	case current.Phase == turncontrol.PhaseProposeTeam &&
		command.NextPhase == turncontrol.PhaseCompileAndQuote:
		next.ProposalRef = command.Artifact.Ref
		next.ProposalDigest = command.Artifact.Digest
	case current.Phase == turncontrol.PhaseCompileAndQuote &&
		command.NextPhase == turncontrol.PhaseAwaitApproval:
		next.Plan = command.Plan
	case current.Phase == turncontrol.PhaseAwaitApproval &&
		command.NextPhase == turncontrol.PhaseExecute:
		next.ApprovalID = command.ApprovalID
	case current.Phase == turncontrol.PhaseObserve &&
		command.NextPhase == turncontrol.PhaseValidate:
		next.ResultRef = command.Artifact.Ref
		next.ResultDigest = command.Artifact.Digest
	case current.Phase == turncontrol.PhaseValidate:
		next.ValidationRef = command.Artifact.Ref
		next.ValidationDigest = command.Artifact.Digest
	case current.Phase == turncontrol.PhaseSynthesize &&
		command.NextPhase == turncontrol.PhaseFinalize:
		next.ResponseRef = command.Artifact.Ref
		next.ResponseDigest = command.Artifact.Digest
	}
	next, err = updateTurn(ctx, tx, store.instanceID, caller, current, next)
	if err != nil {
		return turncontrol.Turn{}, err
	}
	event := turncontrol.Event{
		TurnID:            next.TurnID,
		Revision:          next.Revision,
		FromPhase:         current.Phase,
		ToPhase:           next.Phase,
		Authority:         command.Authority,
		Artifact:          command.Artifact,
		ValidationOutcome: command.Validation,
		OccurredAt:        next.UpdatedAt,
	}
	if err := insertTurnEvent(ctx, tx, event); err != nil {
		return turncontrol.Turn{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		advanceTurnOperation,
		command.IdempotencyKey,
		turnSnapshot{SchemaVersion: turnSnapshotSchemaV1, Turn: next},
	); err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return turncontrol.Turn{}, fmt.Errorf("commit Turn transition: %w", err)
	}
	return next, nil
}

func (store *Store) RetryTurn(
	ctx context.Context,
	scope task.MutationScope,
	command turncontrol.RetryCommand,
) (turncontrol.Turn, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return turncontrol.Turn{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return turncontrol.Turn{}, err
	}
	turnID, _ := uuid.Parse(command.TurnID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return turncontrol.Turn{}, fmt.Errorf("begin Turn retry: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		retryTurnOperation,
		command.IdempotencyKey,
		requestDigest[:],
		turnID,
	)
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if existing {
		turn, err := decodeTurnSnapshot(response)
		if err != nil {
			return turncontrol.Turn{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return turncontrol.Turn{}, fmt.Errorf("commit Turn retry replay: %w", err)
		}
		return turn, nil
	}
	current, err := readCallerTurnForUpdate(
		ctx,
		tx,
		store.instanceID,
		caller,
		command.OwnerID,
		turnID,
	)
	if err != nil {
		return turncontrol.Turn{}, err
	}
	if err := command.ValidateAgainst(current); err != nil {
		return turncontrol.Turn{}, err
	}
	next := current
	next.PhaseAttempt++
	next.PhaseDeadline = command.PhaseDeadline.UTC()
	next, err = updateTurn(ctx, tx, store.instanceID, caller, current, next)
	if err != nil {
		return turncontrol.Turn{}, err
	}
	failureDigest := sha256.Sum256([]byte(command.FailureCode))
	event := turncontrol.Event{
		TurnID:    next.TurnID,
		Revision:  next.Revision,
		FromPhase: current.Phase,
		ToPhase:   current.Phase,
		Authority: turncontrol.AuthorityController,
		Artifact: turncontrol.Artifact{
			Kind:   turncontrol.ArtifactPhaseFailure,
			Origin: turncontrol.OriginController,
			Ref:    "turn://phase-failure/" + command.FailureCode,
			Digest: "sha256:" + hex.EncodeToString(failureDigest[:]),
		},
		ValidationOutcome: turncontrol.ValidationUnspecified,
		FailureCode:       command.FailureCode,
		OccurredAt:        next.UpdatedAt,
	}
	if err := insertTurnEvent(ctx, tx, event); err != nil {
		return turncontrol.Turn{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		retryTurnOperation,
		command.IdempotencyKey,
		turnSnapshot{SchemaVersion: turnSnapshotSchemaV1, Turn: next},
	); err != nil {
		return turncontrol.Turn{}, turnStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return turncontrol.Turn{}, fmt.Errorf("commit Turn retry: %w", err)
	}
	return next, nil
}

func (store *Store) TurnEvents(
	ctx context.Context,
	query turncontrol.EventQuery,
) ([]turncontrol.Event, error) {
	turnID, err := uuid.Parse(query.TurnID)
	if err != nil ||
		turnID == uuid.Nil ||
		turnID.String() != query.TurnID ||
		query.OwnerID != strings.TrimSpace(query.OwnerID) ||
		query.OwnerID == "" ||
		len(query.OwnerID) > 255 ||
		query.AfterRevision < 0 ||
		query.Limit < 1 ||
		query.Limit > 512 {
		return nil, turncontrol.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT e.turn_id, e.revision, e.from_phase, e.to_phase,
		       e.authority, e.artifact_kind, e.artifact_origin,
		       e.artifact_ref, e.artifact_digest, e.validation_outcome,
		       e.failure_code, e.occurred_at
		FROM agent_turn_events e
		JOIN agent_turns t ON t.turn_id=e.turn_id
		WHERE t.agent_instance_id=$1
		  AND t.owner_id=$2
		  AND e.turn_id=$3
		  AND e.revision>$4
		ORDER BY e.revision
		LIMIT $5`,
		store.instanceID,
		query.OwnerID,
		turnID,
		query.AfterRevision,
		query.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list Turn events: %w", err)
	}
	defer rows.Close()
	events := make([]turncontrol.Event, 0, query.Limit)
	for rows.Next() {
		var (
			event   turncontrol.Event
			eventID uuid.UUID
		)
		if err := rows.Scan(
			&eventID,
			&event.Revision,
			&event.FromPhase,
			&event.ToPhase,
			&event.Authority,
			&event.Artifact.Kind,
			&event.Artifact.Origin,
			&event.Artifact.Ref,
			&event.Artifact.Digest,
			&event.ValidationOutcome,
			&event.FailureCode,
			&event.OccurredAt,
		); err != nil {
			return nil, fmt.Errorf("scan Turn event: %w", err)
		}
		event.TurnID = eventID.String()
		event.OccurredAt = event.OccurredAt.UTC()
		if err := event.Validate(); err != nil {
			return nil, errors.New("stored Turn event is invalid")
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Turn events: %w", err)
	}
	return events, nil
}

func (store *Store) verifyTurnAdvance(
	ctx context.Context,
	tx pgx.Tx,
	current turncontrol.Turn,
	command turncontrol.AdvanceCommand,
) error {
	switch {
	case current.Phase == turncontrol.PhaseCompileAndQuote &&
		command.NextPhase == turncontrol.PhaseAwaitApproval:
		var valid bool
		err := tx.QueryRow(ctx, `
			SELECT true
			FROM team_plans p
			JOIN tasks t ON t.task_id=p.task_id
			WHERE p.agent_instance_id=$1
			  AND p.owner_id=$2
			  AND p.plan_id=$3
			  AND p.plan_revision=$4
			  AND p.plan_digest=$5
			  AND p.task_id=$6
			  AND p.goal_digest=$7
			  AND p.status='ready_for_confirmation'
			  AND p.valid_until>clock_timestamp()
			  AND t.owner_id=p.owner_id`,
			store.instanceID,
			current.OwnerID,
			command.Plan.PlanID,
			int64(command.Plan.PlanRevision),
			command.Plan.PlanDigest,
			command.Plan.TaskID,
			current.GoalDigest,
		).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return turncontrol.ErrInvalidTransition
		}
		if err != nil {
			return fmt.Errorf("verify Turn Team Plan: %w", err)
		}
	case command.NextPhase == turncontrol.PhaseExecute:
		approvalID := current.ApprovalID
		if current.Phase == turncontrol.PhaseAwaitApproval {
			approvalID = command.ApprovalID
		}
		if err := store.verifyApprovedTurnPlan(
			ctx,
			tx,
			current,
			approvalID,
			[]string{"approved", "executing"},
		); err != nil {
			return err
		}
	case current.Phase == turncontrol.PhaseObserve &&
		command.NextPhase == turncontrol.PhaseValidate:
		var valid bool
		err := tx.QueryRow(ctx, `
			SELECT true
			FROM tasks t
			WHERE t.task_id=$1
			  AND t.owner_id=$2
			  AND t.execution_status='finished'
			  AND t.outcome_status='succeeded'`,
			current.Plan.TaskID,
			current.OwnerID,
		).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return turncontrol.ErrArbitration
		}
		if err != nil {
			return fmt.Errorf("verify completed Turn Task: %w", err)
		}
	case command.NextPhase == turncontrol.PhaseFinalize &&
		current.Route == turncontrol.RouteDelegate:
		if err := store.verifyApprovedTurnPlan(
			ctx,
			tx,
			current,
			current.ApprovalID,
			[]string{"completed"},
		); err != nil {
			if errors.Is(err, turncontrol.ErrApprovalRequired) {
				return turncontrol.ErrArbitration
			}
			return err
		}
		var valid bool
		err := tx.QueryRow(ctx, `
			SELECT true
			FROM tasks t
			WHERE t.task_id=$1
			  AND t.owner_id=$2
			  AND t.execution_status='finished'
			  AND t.outcome_status='succeeded'`,
			current.Plan.TaskID,
			current.OwnerID,
		).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return turncontrol.ErrArbitration
		}
		if err != nil {
			return fmt.Errorf("arbitrate final Turn Task: %w", err)
		}
	}
	return nil
}

func (store *Store) verifyApprovedTurnPlan(
	ctx context.Context,
	tx pgx.Tx,
	current turncontrol.Turn,
	approvalID string,
	allowedStatuses []string,
) error {
	if current.Plan.PlanRevision > uint64(math.MaxInt64) {
		return turncontrol.ErrApprovalRequired
	}
	var valid bool
	err := tx.QueryRow(ctx, `
		SELECT true
		FROM team_plans p
		JOIN team_plan_approvals a
		  ON a.plan_id=p.plan_id
		 AND a.plan_revision=p.plan_revision
		JOIN tasks t ON t.task_id=p.task_id
		WHERE p.agent_instance_id=$1
		  AND p.owner_id=$2
		  AND p.plan_id=$3
		  AND p.plan_revision=$4
		  AND p.plan_digest=$5
		  AND p.task_id=$6
		  AND p.goal_digest=$7
		  AND p.status=ANY($8::text[])
		  AND a.agent_instance_id=p.agent_instance_id
		  AND a.owner_id=p.owner_id
		  AND a.approval_id=$9
		  AND a.plan_digest=p.plan_digest
		  AND t.owner_id=p.owner_id`,
		store.instanceID,
		current.OwnerID,
		current.Plan.PlanID,
		int64(current.Plan.PlanRevision),
		current.Plan.PlanDigest,
		current.Plan.TaskID,
		current.GoalDigest,
		allowedStatuses,
		approvalID,
	).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return turncontrol.ErrApprovalRequired
	}
	if err != nil {
		return fmt.Errorf("verify approved Turn Plan: %w", err)
	}
	return nil
}

func readCallerTurnForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	caller idempotencyCaller,
	ownerID string,
	turnID uuid.UUID,
) (turncontrol.Turn, error) {
	turn, err := scanTurn(tx.QueryRow(ctx, `
		SELECT `+turnColumns+`
		FROM agent_turns
		WHERE agent_instance_id=$1
		  AND caller_client_id=$2
		  AND caller_credential_id=$3
		  AND owner_id=$4
		  AND turn_id=$5
		FOR UPDATE`,
		instanceID,
		caller.ClientID,
		caller.CredentialID,
		ownerID,
		turnID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return turncontrol.Turn{}, turncontrol.ErrNotFound
	}
	if err != nil {
		return turncontrol.Turn{}, fmt.Errorf("lock Turn: %w", err)
	}
	return turn, nil
}

func updateTurn(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	caller idempotencyCaller,
	current,
	next turncontrol.Turn,
) (turncontrol.Turn, error) {
	var deadline any
	if !next.PhaseDeadline.IsZero() {
		deadline = next.PhaseDeadline.UTC()
	}
	var (
		planID       any
		planRevision any
		taskID       any
		approvalID   any
	)
	if next.Plan.PlanID != "" {
		planID = next.Plan.PlanID
		planRevision = int64(next.Plan.PlanRevision)
		taskID = next.Plan.TaskID
	}
	if next.ApprovalID != "" {
		approvalID = next.ApprovalID
	}
	updated, err := scanTurn(tx.QueryRow(ctx, `
		UPDATE agent_turns SET
		    phase=$6,
		    route=$7,
		    status=$8,
		    phase_attempt=$9,
		    phase_deadline=$10,
		    proposal_ref=$11,
		    proposal_digest=$12,
		    plan_id=$13,
		    plan_revision=$14,
		    plan_digest=$15,
		    task_id=$16,
		    approval_id=$17,
		    result_ref=$18,
		    result_digest=$19,
		    validation_ref=$20,
		    validation_digest=$21,
		    response_ref=$22,
		    response_digest=$23,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE agent_instance_id=$1
		  AND caller_client_id=$2
		  AND caller_credential_id=$3
		  AND turn_id=$4
		  AND revision=$5
		RETURNING `+turnColumns,
		instanceID,
		caller.ClientID,
		caller.CredentialID,
		current.TurnID,
		current.Revision,
		next.Phase,
		next.Route,
		next.Status,
		next.PhaseAttempt,
		deadline,
		next.ProposalRef,
		next.ProposalDigest,
		planID,
		planRevision,
		next.Plan.PlanDigest,
		taskID,
		approvalID,
		next.ResultRef,
		next.ResultDigest,
		next.ValidationRef,
		next.ValidationDigest,
		next.ResponseRef,
		next.ResponseDigest,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return turncontrol.Turn{}, turncontrol.ErrRevisionConflict
	}
	if err != nil {
		return turncontrol.Turn{}, turnStoreError(fmt.Errorf("update Turn: %w", err))
	}
	return updated, nil
}

func insertTurnEvent(
	ctx context.Context,
	tx pgx.Tx,
	event turncontrol.Event,
) error {
	if err := event.Validate(); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO agent_turn_events (
		    turn_id, revision, from_phase, to_phase, authority,
		    artifact_kind, artifact_origin, artifact_ref, artifact_digest,
		    validation_outcome, failure_code, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		event.TurnID,
		event.Revision,
		event.FromPhase,
		event.ToPhase,
		event.Authority,
		event.Artifact.Kind,
		event.Artifact.Origin,
		event.Artifact.Ref,
		event.Artifact.Digest,
		event.ValidationOutcome,
		event.FailureCode,
		event.OccurredAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("append Turn event: %w", err)
	}
	return nil
}

const turnColumns = `
	turn_id, request_id, owner_id, conversation_id, goal_digest,
	phase, route, status, phase_attempt, phase_deadline,
	proposal_ref, proposal_digest, plan_id, plan_revision, plan_digest,
	task_id, approval_id, result_ref, result_digest,
	validation_ref, validation_digest, response_ref, response_digest,
	revision, created_at, updated_at`

type turnScanner interface {
	Scan(...any) error
}

func scanTurn(scanner turnScanner) (turncontrol.Turn, error) {
	var (
		turn          turncontrol.Turn
		turnID        uuid.UUID
		phaseDeadline *time.Time
		planID        *uuid.UUID
		planRevision  *int64
		taskID        *uuid.UUID
		approvalID    *uuid.UUID
	)
	if err := scanner.Scan(
		&turnID,
		&turn.RequestID,
		&turn.OwnerID,
		&turn.ConversationID,
		&turn.GoalDigest,
		&turn.Phase,
		&turn.Route,
		&turn.Status,
		&turn.PhaseAttempt,
		&phaseDeadline,
		&turn.ProposalRef,
		&turn.ProposalDigest,
		&planID,
		&planRevision,
		&turn.Plan.PlanDigest,
		&taskID,
		&approvalID,
		&turn.ResultRef,
		&turn.ResultDigest,
		&turn.ValidationRef,
		&turn.ValidationDigest,
		&turn.ResponseRef,
		&turn.ResponseDigest,
		&turn.Revision,
		&turn.CreatedAt,
		&turn.UpdatedAt,
	); err != nil {
		return turncontrol.Turn{}, err
	}
	turn.TurnID = turnID.String()
	if phaseDeadline != nil {
		turn.PhaseDeadline = phaseDeadline.UTC()
	}
	if planID != nil && planRevision != nil && taskID != nil {
		if *planRevision < 1 {
			return turncontrol.Turn{}, errors.New("stored Turn Plan revision is invalid")
		}
		turn.Plan.PlanID = planID.String()
		turn.Plan.PlanRevision = uint64(*planRevision)
		turn.Plan.TaskID = taskID.String()
	}
	if approvalID != nil {
		turn.ApprovalID = approvalID.String()
	}
	turn.CreatedAt = turn.CreatedAt.UTC()
	turn.UpdatedAt = turn.UpdatedAt.UTC()
	if err := turn.Validate(); err != nil {
		return turncontrol.Turn{}, errors.New("stored Turn is invalid")
	}
	return turn, nil
}

func decodeTurnSnapshot(encoded []byte) (turncontrol.Turn, error) {
	var snapshot turnSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil ||
		snapshot.SchemaVersion != turnSnapshotSchemaV1 ||
		snapshot.Turn.Validate() != nil {
		return turncontrol.Turn{}, errors.New("invalid Turn idempotency snapshot")
	}
	return snapshot.Turn, nil
}

func turnStatus(phase turncontrol.Phase) turncontrol.Status {
	switch phase {
	case turncontrol.PhaseAwaitApproval:
		return turncontrol.StatusWaitingApproval
	case turncontrol.PhaseFinalize:
		return turncontrol.StatusCompleted
	default:
		return turncontrol.StatusActive
	}
}

func turnStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, turncontrol.ErrInvalid) ||
		errors.Is(err, turncontrol.ErrNotFound) ||
		errors.Is(err, turncontrol.ErrRevisionConflict) ||
		errors.Is(err, turncontrol.ErrInvalidTransition) ||
		errors.Is(err, turncontrol.ErrAttemptsExhausted) ||
		errors.Is(err, turncontrol.ErrApprovalRequired) ||
		errors.Is(err, turncontrol.ErrArbitration) ||
		errors.Is(err, turncontrol.ErrIdempotency) {
		return err
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505":
			return turncontrol.ErrIdempotency
		case "23503", "23514", "P0001":
			return turncontrol.ErrInvalidTransition
		}
	}
	return err
}
