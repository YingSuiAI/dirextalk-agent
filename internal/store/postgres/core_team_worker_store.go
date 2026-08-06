package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	teamWorkerReplayClaim     = "claim"
	teamWorkerReplayHeartbeat = "heartbeat"
	teamWorkerReplayMilestone = "milestone"
	teamWorkerReplayComplete  = "complete"
)

type CoreTeamWorkerStore struct{ store *Store }

func NewCoreTeamWorkerStore(store *Store) *CoreTeamWorkerStore {
	return &CoreTeamWorkerStore{store: store}
}

func (s *CoreTeamWorkerStore) CreateChallenge(ctx context.Context, challenge coreteamworker.Challenge) (coreteamworker.Challenge, bool, error) {
	if !s.ready(ctx) || challenge.Validate() != nil {
		return coreteamworker.Challenge{}, false, coreteamworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.Challenge{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamWorkerAdmissionScope(ctx, tx, challenge.Scope); err != nil {
		return coreteamworker.Challenge{}, false, err
	}
	if err = lockTeamWorkerReplay(ctx, tx, challenge.Scope.OwnerID, "challenge", challenge.IdempotencyKey); err != nil {
		return coreteamworker.Challenge{}, false, err
	}
	existing, readErr := scanTeamWorkerChallenge(tx.QueryRow(ctx, `SELECT challenge_id::text,worker_id::text,owner_id,account_generation,execution_id::text,role_id,attempt,identity_digest,idempotency_key::text,request_digest,created_at,expires_at,consumed_at FROM core_team_worker_challenges WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, challenge.Scope.OwnerID, challenge.Scope.AccountGeneration, challenge.IdempotencyKey))
	if readErr == nil {
		if existing.Validate() != nil || existing.RequestDigest != challenge.RequestDigest || existing.ExecutionID != challenge.ExecutionID || existing.RoleID != challenge.RoleID || existing.Attempt != challenge.Attempt || existing.IdentityDigest != challenge.IdentityDigest {
			return coreteamworker.Challenge{}, false, coreteamworker.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteamworker.Challenge{}, false, err
		}
		return existing, true, nil
	}
	if !errors.Is(readErr, pgx.ErrNoRows) {
		return coreteamworker.Challenge{}, false, readErr
	}
	var runStatus, executionStatus, taskStatus string
	var attempt int
	err = tx.QueryRow(ctx, `
		SELECT run.status,run.attempt,execution.status,task.status
		FROM core_team_role_runs run
		JOIN core_team_executions execution ON execution.owner_id=run.owner_id AND execution.account_generation=run.account_generation AND execution.execution_id=run.execution_id
		JOIN core_tasks task ON task.task_id=execution.task_id
		WHERE run.owner_id=$1 AND run.account_generation=$2 AND run.execution_id=$3 AND run.role_id=$4
		FOR UPDATE OF run`, challenge.Scope.OwnerID, challenge.Scope.AccountGeneration, challenge.ExecutionID, challenge.RoleID).Scan(&runStatus, &attempt, &executionStatus, &taskStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteamworker.Challenge{}, false, coreteamworker.ErrNotFound
	}
	if err != nil {
		return coreteamworker.Challenge{}, false, err
	}
	if runStatus != string(coreteam.ExecutionQueued) || uint32(attempt) != challenge.Attempt ||
		(executionStatus != string(coreteam.ExecutionQueued) && executionStatus != string(coreteam.ExecutionRunning)) ||
		(taskStatus != "queued" && taskStatus != "running") {
		return coreteamworker.Challenge{}, false, coreteamworker.ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_team_worker_challenges(challenge_id,worker_id,owner_id,account_generation,execution_id,role_id,attempt,identity_digest,idempotency_key,request_digest,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		challenge.ChallengeID, challenge.WorkerID, challenge.Scope.OwnerID, challenge.Scope.AccountGeneration,
		challenge.ExecutionID, challenge.RoleID, challenge.Attempt, challenge.IdentityDigest, challenge.IdempotencyKey, challenge.RequestDigest, challenge.CreatedAt.UTC(), challenge.ExpiresAt.UTC())
	if err != nil {
		return coreteamworker.Challenge{}, false, teamWorkerWriteError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.Challenge{}, false, err
	}
	return challenge, false, nil
}

func (s *CoreTeamWorkerStore) GetChallenge(ctx context.Context, challengeID string) (coreteamworker.Challenge, error) {
	if !s.ready(ctx) || !coreteamworkerValidUUID(challengeID) {
		return coreteamworker.Challenge{}, coreteamworker.ErrInvalid
	}
	challenge, err := scanTeamWorkerChallenge(s.store.pool.QueryRow(ctx, `SELECT challenge_id::text,worker_id::text,owner_id,account_generation,execution_id::text,role_id,attempt,identity_digest,idempotency_key::text,request_digest,created_at,expires_at,consumed_at FROM core_team_worker_challenges WHERE challenge_id=$1`, challengeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteamworker.Challenge{}, coreteamworker.ErrNotFound
	}
	if err != nil {
		return coreteamworker.Challenge{}, err
	}
	if challenge.Validate() != nil {
		return coreteamworker.Challenge{}, coreteamworker.ErrRuntimeUnavailable
	}
	return challenge, nil
}

func (s *CoreTeamWorkerStore) Enroll(ctx context.Context, command coreteamworker.EnrollmentCommand) (coreteamworker.Enrollment, bool, error) {
	if !s.ready(ctx) || command.Validate() != nil {
		return coreteamworker.Enrollment{}, false, coreteamworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = lockTeamWorkerDeprovisionGuard(ctx, tx); err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	challenge, consumedAt, err := getTeamWorkerChallengeTx(ctx, tx, command.ChallengeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteamworker.Enrollment{}, false, coreteamworker.ErrNotFound
	}
	if err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	if challenge.Validate() != nil || challenge.WorkerID != command.WorkerID || challenge.IdentityDigest != command.IdentityDigest {
		return coreteamworker.Enrollment{}, false, coreteamworker.ErrUnauthorized
	}
	if err = checkTeamWorkerAdmissionTx(ctx, tx, challenge.Scope); err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	if consumedAt != nil {
		enrollment, readErr := readTeamWorkerEnrollment(ctx, tx, command.WorkerID, command.IdentityDigest)
		if readErr != nil {
			return coreteamworker.Enrollment{}, false, readErr
		}
		if enrollment.Validate(challenge.CreatedAt) != nil || enrollment.ExecutionID != challenge.ExecutionID || enrollment.RoleID != challenge.RoleID || enrollment.Attempt != challenge.Attempt {
			return coreteamworker.Enrollment{}, false, coreteamworker.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteamworker.Enrollment{}, false, err
		}
		return enrollment, true, nil
	}
	if !challenge.ExpiresAt.After(command.At) {
		return coreteamworker.Enrollment{}, false, coreteamworker.ErrExpired
	}
	var runStatus string
	var attempt int
	var existingWorker string
	err = tx.QueryRow(ctx, `SELECT status,attempt,COALESCE(worker_id::text,'') FROM core_team_role_runs WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND role_id=$4 FOR UPDATE`, challenge.Scope.OwnerID, challenge.Scope.AccountGeneration, challenge.ExecutionID, challenge.RoleID).Scan(&runStatus, &attempt, &existingWorker)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteamworker.Enrollment{}, false, coreteamworker.ErrNotFound
	}
	if err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	if runStatus != string(coreteam.ExecutionQueued) || uint32(attempt) != challenge.Attempt || existingWorker != "" {
		return coreteamworker.Enrollment{}, false, coreteamworker.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_team_workers(worker_id,owner_id,account_generation,execution_id,role_id,attempt,identity_digest,status,enrollment_expires_at,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,'enrolled',$8,$9,$9)`,
		challenge.WorkerID, challenge.Scope.OwnerID, challenge.Scope.AccountGeneration, challenge.ExecutionID, challenge.RoleID,
		challenge.Attempt, command.IdentityDigest, command.ExpiresAt.UTC(), command.At.UTC()); err != nil {
		return coreteamworker.Enrollment{}, false, teamWorkerWriteError(err)
	}
	result, err := tx.Exec(ctx, `UPDATE core_team_role_runs SET worker_id=$5,worker_identity_digest=$6,revision=revision+1,updated_at=$7 WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND role_id=$4 AND status='queued' AND attempt=$8 AND worker_id IS NULL`,
		challenge.Scope.OwnerID, challenge.Scope.AccountGeneration, challenge.ExecutionID, challenge.RoleID,
		challenge.WorkerID, command.IdentityDigest, command.At.UTC(), challenge.Attempt)
	if err != nil || result.RowsAffected() != 1 {
		if err == nil {
			err = coreteamworker.ErrConflict
		}
		return coreteamworker.Enrollment{}, false, teamWorkerWriteError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE core_team_worker_challenges SET consumed_at=$2 WHERE challenge_id=$1 AND consumed_at IS NULL`, challenge.ChallengeID, command.At.UTC()); err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	enrollment := coreteamworker.Enrollment{
		WorkerID: challenge.WorkerID, ExecutionID: challenge.ExecutionID, RoleID: challenge.RoleID,
		Attempt: challenge.Attempt, ExpiresAt: command.ExpiresAt.UTC(),
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.Enrollment{}, false, err
	}
	return enrollment, false, nil
}

func (s *CoreTeamWorkerStore) GetAssignment(ctx context.Context, access coreteamworker.WorkerAccess) (coreteamworker.Assignment, error) {
	if !s.ready(ctx) || access.Validate() != nil {
		return coreteamworker.Assignment{}, coreteamworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.Assignment{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockTeamWorkerDeprovisionGuard(ctx, tx); err != nil {
		return coreteamworker.Assignment{}, err
	}
	var assignment coreteamworker.Assignment
	var scope coreteam.Scope
	var identityDigest, workerStatus, runStatus string
	var enrollmentExpires time.Time
	var capabilitiesRaw []byte
	err = tx.QueryRow(ctx, `
		SELECT worker.worker_id::text,worker.owner_id,worker.account_generation,worker.identity_digest,worker.status,worker.enrollment_expires_at,
		       run.execution_id::text,run.plan_id::text,run.role_id,run.attempt,run.status,
		       plan.digest,role.goal,role.capabilities,plan.runtime_id,plan.output_tokens
		FROM core_team_workers worker
		JOIN core_team_role_runs run ON run.owner_id=worker.owner_id AND run.account_generation=worker.account_generation AND run.execution_id=worker.execution_id AND run.role_id=worker.role_id AND run.worker_id=worker.worker_id
		JOIN core_team_plans plan ON plan.owner_id=run.owner_id AND plan.account_generation=run.account_generation AND plan.plan_id=run.plan_id
		JOIN core_team_roles role ON role.owner_id=run.owner_id AND role.account_generation=run.account_generation AND role.plan_id=run.plan_id AND role.role_id=run.role_id
		WHERE worker.worker_id=$1`, access.WorkerID).Scan(
		&assignment.WorkerID, &scope.OwnerID, &scope.AccountGeneration, &identityDigest, &workerStatus, &enrollmentExpires,
		&assignment.ExecutionID, &assignment.PlanID, &assignment.RoleID, &assignment.Attempt, &runStatus,
		&assignment.PlanDigest, &assignment.Goal, &capabilitiesRaw, &assignment.RuntimeID, &assignment.OutputTokens,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteamworker.Assignment{}, coreteamworker.ErrNotFound
	}
	if err != nil {
		return coreteamworker.Assignment{}, err
	}
	if err = checkTeamWorkerAdmissionTx(ctx, tx, scope); err != nil {
		return coreteamworker.Assignment{}, err
	}
	if identityDigest != access.IdentityDigest {
		return coreteamworker.Assignment{}, coreteamworker.ErrUnauthorized
	}
	if !enrollmentExpires.After(access.At) {
		return coreteamworker.Assignment{}, coreteamworker.ErrExpired
	}
	if (workerStatus != "enrolled" && workerStatus != "active") || (runStatus != string(coreteam.ExecutionQueued) && runStatus != string(coreteam.ExecutionRunning)) {
		return coreteamworker.Assignment{}, coreteamworker.ErrConflict
	}
	if json.Unmarshal(capabilitiesRaw, &assignment.Capabilities) != nil {
		return coreteamworker.Assignment{}, coreteamworker.ErrRuntimeUnavailable
	}
	assignment.ResultSchemaVersion = coreteamworker.ResultSchemaVersion
	if assignment.Validate() != nil {
		return coreteamworker.Assignment{}, coreteamworker.ErrRuntimeUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.Assignment{}, err
	}
	return assignment, nil
}

func (s *CoreTeamWorkerStore) Claim(ctx context.Context, command coreteamworker.ClaimCommand) (coreteamworker.Lease, bool, error) {
	if !s.ready(ctx) || command.Validate() != nil {
		return coreteamworker.Lease{}, false, coreteamworker.ErrInvalid
	}
	digest := teamWorkerRequestDigest(struct {
		Identity, ExecutionID, RoleID, ClaimID string
		Attempt                                uint32
		TTL                                    int64
	}{command.Access.IdentityDigest, command.ExecutionID, command.RoleID, command.ClaimID, command.Attempt, int64(command.TTL)})
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.Lease{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamWorkerAdmissionByWorker(ctx, tx, command.Access.WorkerID); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = lockTeamWorkerReplay(ctx, tx, command.Access.WorkerID, teamWorkerReplayClaim, command.ClaimID); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if replay, found, replayErr := readTeamWorkerReplay[coreteamworker.Lease](ctx, tx, command.Access.WorkerID, teamWorkerReplayClaim, command.ClaimID, digest); found || replayErr != nil {
		if replayErr == nil {
			replayErr = replay.ValidateReceipt()
		}
		if replayErr != nil {
			return coreteamworker.Lease{}, false, replayErr
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteamworker.Lease{}, false, err
		}
		return replay, true, nil
	}
	state, err := lockTeamWorkerRun(ctx, tx, command.Access.WorkerID)
	if err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = state.authorize(command.Access); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if state.ExecutionID != command.ExecutionID || state.RoleID != command.RoleID || state.Attempt != command.Attempt || state.RunStatus != string(coreteam.ExecutionQueued) {
		return coreteamworker.Lease{}, false, coreteamworker.ErrConflict
	}
	fence := coreteamworker.LeaseFence{ExecutionID: state.ExecutionID, RoleID: state.RoleID, WorkerID: state.WorkerID, Attempt: state.Attempt, LeaseEpoch: state.LeaseEpoch + 1}
	lease := coreteamworker.Lease{Fence: fence, ExpiresAt: command.Access.At.Add(command.TTL).UTC()}
	result, err := tx.Exec(ctx, `UPDATE core_team_role_runs SET status='running',claim_id=$5,lease_epoch=$6,lease_expires_at=$7,revision=revision+1,updated_at=$8 WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND role_id=$4 AND status='queued' AND attempt=$9 AND worker_id=$10 AND lease_epoch=$11`,
		state.OwnerID, state.AccountGeneration, state.ExecutionID, state.RoleID, command.ClaimID, fence.LeaseEpoch,
		lease.ExpiresAt, command.Access.At.UTC(), command.Attempt, command.Access.WorkerID, state.LeaseEpoch)
	if err != nil || result.RowsAffected() != 1 {
		if err == nil {
			err = coreteamworker.ErrLeaseConflict
		}
		return coreteamworker.Lease{}, false, teamWorkerWriteError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE core_team_workers SET status='active',last_seen_at=$2 WHERE worker_id=$1 AND status='enrolled'`, command.Access.WorkerID, command.Access.At.UTC()); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = writeTeamWorkerReplay(ctx, tx, command.Access.WorkerID, teamWorkerReplayClaim, command.ClaimID, digest, lease, command.Access.At); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	return lease, false, nil
}

func (s *CoreTeamWorkerStore) Heartbeat(ctx context.Context, command coreteamworker.HeartbeatCommand) (coreteamworker.Lease, bool, error) {
	if !s.ready(ctx) || command.Validate() != nil {
		return coreteamworker.Lease{}, false, coreteamworker.ErrInvalid
	}
	digest := teamWorkerRequestDigest(struct {
		Identity, ExecutionID, RoleID, WorkerID, HeartbeatID string
		Attempt                                              uint32
		LeaseEpoch                                           uint64
		TTL                                                  int64
	}{command.Access.IdentityDigest, command.Fence.ExecutionID, command.Fence.RoleID, command.Fence.WorkerID, command.HeartbeatID, command.Fence.Attempt, command.Fence.LeaseEpoch, int64(command.TTL)})
	return s.mutateLease(ctx, command.Access, teamWorkerReplayHeartbeat, command.HeartbeatID, digest, command.Fence, func(tx pgx.Tx, state teamWorkerRunState) (coreteamworker.Lease, error) {
		candidate := command.Access.At.Add(command.TTL).UTC()
		lease := coreteamworker.Lease{Fence: command.Fence, ExpiresAt: candidate}
		err := tx.QueryRow(ctx, `UPDATE core_team_role_runs SET lease_expires_at=GREATEST(lease_expires_at,$5),revision=revision+1,updated_at=GREATEST(updated_at,$6) WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND role_id=$4 AND status='running' AND worker_id=$7 AND attempt=$8 AND lease_epoch=$9 AND lease_expires_at>$6 RETURNING lease_expires_at`,
			state.OwnerID, state.AccountGeneration, state.ExecutionID, state.RoleID, candidate, command.Access.At.UTC(), command.Access.WorkerID, command.Fence.Attempt, command.Fence.LeaseEpoch).Scan(&lease.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return coreteamworker.Lease{}, coreteamworker.ErrLeaseConflict
		}
		if err != nil {
			return coreteamworker.Lease{}, teamWorkerWriteError(err)
		}
		lease.ExpiresAt = lease.ExpiresAt.UTC()
		_, err = tx.Exec(ctx, `UPDATE core_team_workers SET last_seen_at=GREATEST(last_seen_at,$2) WHERE worker_id=$1 AND status='active'`, command.Access.WorkerID, command.Access.At.UTC())
		return lease, err
	})
}

func (s *CoreTeamWorkerStore) EmitMilestone(ctx context.Context, command coreteamworker.MilestoneCommand) (coreteamworker.MilestoneReceipt, bool, error) {
	if !s.ready(ctx) || command.Validate() != nil {
		return coreteamworker.MilestoneReceipt{}, false, coreteamworker.ErrInvalid
	}
	digest := teamWorkerRequestDigest(struct {
		Identity, ExecutionID, RoleID, WorkerID, EventID, Stage, Health, EventDigest string
		Attempt                                                                      uint32
		LeaseEpoch, Sequence                                                         uint64
	}{command.Access.IdentityDigest, command.Fence.ExecutionID, command.Fence.RoleID, command.Fence.WorkerID, command.EventID, string(command.Stage), string(command.Health), command.EventDigest, command.Fence.Attempt, command.Fence.LeaseEpoch, command.Sequence})
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamWorkerAdmissionByWorker(ctx, tx, command.Access.WorkerID); err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	if err = lockTeamWorkerReplay(ctx, tx, command.Access.WorkerID, teamWorkerReplayMilestone, command.EventID); err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	if replay, found, replayErr := readTeamWorkerReplay[coreteamworker.MilestoneReceipt](ctx, tx, command.Access.WorkerID, teamWorkerReplayMilestone, command.EventID, digest); found || replayErr != nil {
		if replayErr == nil && (replay.Validate() != nil || replay.EventID != command.EventID || replay.Sequence != command.Sequence) {
			replayErr = coreteamworker.ErrRuntimeUnavailable
		}
		if replayErr != nil {
			return coreteamworker.MilestoneReceipt{}, false, replayErr
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteamworker.MilestoneReceipt{}, false, err
		}
		return replay, true, nil
	}
	state, err := lockTeamWorkerRun(ctx, tx, command.Access.WorkerID)
	if err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	if err = state.requireFence(command.Access, command.Fence); err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	if command.Sequence != state.LastMilestoneSequence+1 {
		return coreteamworker.MilestoneReceipt{}, false, coreteamworker.ErrConflict
	}
	result, err := tx.Exec(ctx, `UPDATE core_team_role_runs SET last_milestone_event_id=$5,last_milestone_sequence=$6,last_milestone_digest=$7,last_milestone_accepted_at=$8,revision=revision+1,updated_at=$8 WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND role_id=$4 AND status='running' AND worker_id=$9 AND attempt=$10 AND lease_epoch=$11 AND lease_expires_at>$8 AND last_milestone_sequence=$12`,
		state.OwnerID, state.AccountGeneration, state.ExecutionID, state.RoleID, command.EventID, command.Sequence,
		command.EventDigest, command.Access.At.UTC(), command.Access.WorkerID, command.Fence.Attempt, command.Fence.LeaseEpoch, state.LastMilestoneSequence)
	if err != nil {
		return coreteamworker.MilestoneReceipt{}, false, teamWorkerWriteError(err)
	}
	if result.RowsAffected() != 1 {
		return coreteamworker.MilestoneReceipt{}, false, coreteamworker.ErrLeaseConflict
	}
	receipt := coreteamworker.MilestoneReceipt{EventID: command.EventID, Sequence: command.Sequence, AcceptedAt: command.Access.At.UTC()}
	if err = writeTeamWorkerReplay(ctx, tx, command.Access.WorkerID, teamWorkerReplayMilestone, command.EventID, digest, receipt, command.Access.At); err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.MilestoneReceipt{}, false, err
	}
	return receipt, false, nil
}

func (s *CoreTeamWorkerStore) Complete(ctx context.Context, command coreteamworker.CompleteCommand) (coreteamworker.CompletionReceipt, bool, error) {
	if !s.ready(ctx) || command.Validate() != nil {
		return coreteamworker.CompletionReceipt{}, false, coreteamworker.ErrInvalid
	}
	digest := teamWorkerRequestDigest(struct {
		Identity, ExecutionID, RoleID, WorkerID, CompletionID, Outcome, ResultDigest, FailureCode string
		Attempt                                                                                   uint32
		LeaseEpoch, ResultSize                                                                    uint64
		ResultSchema                                                                              uint32
	}{command.Access.IdentityDigest, command.Fence.ExecutionID, command.Fence.RoleID, command.Fence.WorkerID, command.CompletionID, string(command.Outcome), command.Result.Digest, string(command.FailureCode), command.Fence.Attempt, command.Fence.LeaseEpoch, command.Result.SizeBytes, command.Result.SchemaVersion})
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamWorkerAdmissionByWorker(ctx, tx, command.Access.WorkerID); err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	if err = lockTeamWorkerReplay(ctx, tx, command.Access.WorkerID, teamWorkerReplayComplete, command.CompletionID); err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	if replay, found, replayErr := readTeamWorkerReplay[coreteamworker.CompletionReceipt](ctx, tx, command.Access.WorkerID, teamWorkerReplayComplete, command.CompletionID, digest); found || replayErr != nil {
		if replayErr == nil && (replay.Validate() != nil || replay.CompletionID != command.CompletionID || replay.Outcome != command.Outcome) {
			replayErr = coreteamworker.ErrRuntimeUnavailable
		}
		if replayErr != nil {
			return coreteamworker.CompletionReceipt{}, false, replayErr
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteamworker.CompletionReceipt{}, false, err
		}
		return replay, true, nil
	}
	state, err := lockTeamWorkerRun(ctx, tx, command.Access.WorkerID)
	if err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	if err = state.requireFence(command.Access, command.Fence); err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	status := string(coreteam.ExecutionCleaningUp)
	var schema, size any
	var resultDigest, resultPayload, failure any
	if command.Outcome == coreteamworker.OutcomeSucceeded {
		schema, resultDigest, size, resultPayload = command.Result.SchemaVersion, command.Result.Digest, command.Result.SizeBytes, command.Result.PayloadJSON
	} else {
		failure = string(command.FailureCode)
	}
	result, err := tx.Exec(ctx, `UPDATE core_team_role_runs SET status=$5,completion_id=$6,completion_outcome=$7,result_schema_version=$8,result_digest=$9,result_size_bytes=$10,result_payload=$11,failure_code=$12,completed_at=$13,lease_expires_at=NULL,revision=revision+1,updated_at=$13 WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND role_id=$4 AND status='running' AND worker_id=$14 AND attempt=$15 AND lease_epoch=$16 AND lease_expires_at>$13`,
		state.OwnerID, state.AccountGeneration, state.ExecutionID, state.RoleID, status, command.CompletionID,
		string(command.Outcome), schema, resultDigest, size, resultPayload, failure, command.Access.At.UTC(), command.Access.WorkerID, command.Fence.Attempt, command.Fence.LeaseEpoch)
	if err != nil {
		return coreteamworker.CompletionReceipt{}, false, teamWorkerWriteError(err)
	}
	if result.RowsAffected() != 1 {
		return coreteamworker.CompletionReceipt{}, false, coreteamworker.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_team_workers SET status='completed',last_seen_at=$2 WHERE worker_id=$1 AND status='active'`, command.Access.WorkerID, command.Access.At.UTC()); err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	receipt := coreteamworker.CompletionReceipt{CompletionID: command.CompletionID, Outcome: command.Outcome, AcceptedAt: command.Access.At.UTC()}
	if err = writeTeamWorkerReplay(ctx, tx, command.Access.WorkerID, teamWorkerReplayComplete, command.CompletionID, digest, receipt, command.Access.At); err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.CompletionReceipt{}, false, err
	}
	return receipt, false, nil
}

func (s *CoreTeamWorkerStore) mutateLease(ctx context.Context, access coreteamworker.WorkerAccess, operation, idempotencyID, digest string, fence coreteamworker.LeaseFence, mutate func(pgx.Tx, teamWorkerRunState) (coreteamworker.Lease, error)) (coreteamworker.Lease, bool, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteamworker.Lease{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamWorkerAdmissionByWorker(ctx, tx, access.WorkerID); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = lockTeamWorkerReplay(ctx, tx, access.WorkerID, operation, idempotencyID); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if replay, found, replayErr := readTeamWorkerReplay[coreteamworker.Lease](ctx, tx, access.WorkerID, operation, idempotencyID, digest); found || replayErr != nil {
		if replayErr == nil {
			replayErr = replay.ValidateReceipt()
		}
		if replayErr != nil {
			return coreteamworker.Lease{}, false, replayErr
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteamworker.Lease{}, false, err
		}
		return replay, true, nil
	}
	state, err := lockTeamWorkerRun(ctx, tx, access.WorkerID)
	if err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = state.requireFence(access, fence); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	lease, err := mutate(tx, state)
	if err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = writeTeamWorkerReplay(ctx, tx, access.WorkerID, operation, idempotencyID, digest, lease, access.At); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteamworker.Lease{}, false, err
	}
	return lease, false, nil
}

type teamWorkerRunState struct {
	WorkerID, IdentityDigest, WorkerStatus, OwnerID, ExecutionID, RoleID, RunStatus string
	AccountGeneration                                                               int64
	Attempt                                                                         uint32
	LeaseEpoch                                                                      uint64
	LeaseExpires                                                                    *time.Time
	EnrollmentExpires                                                               time.Time
	LastMilestoneSequence                                                           uint64
}

func lockTeamWorkerRun(ctx context.Context, tx pgx.Tx, workerID string) (teamWorkerRunState, error) {
	var state teamWorkerRunState
	var attempt int
	var epoch, sequence int64
	err := tx.QueryRow(ctx, `
		SELECT worker.worker_id::text,worker.identity_digest,worker.status,worker.owner_id,worker.account_generation,worker.enrollment_expires_at,
		       run.execution_id::text,run.role_id,run.attempt,run.status,run.lease_epoch,run.lease_expires_at,run.last_milestone_sequence
		FROM core_team_workers worker
		JOIN core_team_role_runs run ON run.owner_id=worker.owner_id AND run.account_generation=worker.account_generation AND run.execution_id=worker.execution_id AND run.role_id=worker.role_id AND run.worker_id=worker.worker_id
		WHERE worker.worker_id=$1 FOR UPDATE OF worker,run`, workerID).Scan(
		&state.WorkerID, &state.IdentityDigest, &state.WorkerStatus, &state.OwnerID, &state.AccountGeneration, &state.EnrollmentExpires,
		&state.ExecutionID, &state.RoleID, &attempt, &state.RunStatus, &epoch, &state.LeaseExpires, &sequence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, coreteamworker.ErrNotFound
	}
	if err != nil {
		return state, err
	}
	if attempt <= 0 || epoch < 0 || sequence < 0 {
		return state, coreteamworker.ErrRuntimeUnavailable
	}
	state.Attempt, state.LeaseEpoch, state.LastMilestoneSequence = uint32(attempt), uint64(epoch), uint64(sequence)
	return state, nil
}

func (s teamWorkerRunState) authorize(access coreteamworker.WorkerAccess) error {
	if access.Validate() != nil || access.WorkerID != s.WorkerID || access.IdentityDigest != s.IdentityDigest {
		return coreteamworker.ErrUnauthorized
	}
	if !s.EnrollmentExpires.After(access.At) {
		return coreteamworker.ErrExpired
	}
	if s.WorkerStatus != "enrolled" && s.WorkerStatus != "active" {
		return coreteamworker.ErrConflict
	}
	return nil
}

func (s teamWorkerRunState) requireFence(access coreteamworker.WorkerAccess, fence coreteamworker.LeaseFence) error {
	if err := s.authorize(access); err != nil {
		return err
	}
	if fence.Validate() != nil || fence.WorkerID != s.WorkerID || fence.ExecutionID != s.ExecutionID || fence.RoleID != s.RoleID ||
		fence.Attempt != s.Attempt || fence.LeaseEpoch != s.LeaseEpoch || s.RunStatus != string(coreteam.ExecutionRunning) ||
		s.LeaseExpires == nil || !s.LeaseExpires.After(access.At) {
		return coreteamworker.ErrLeaseConflict
	}
	return nil
}

func getTeamWorkerChallengeTx(ctx context.Context, tx pgx.Tx, challengeID string) (coreteamworker.Challenge, *time.Time, error) {
	challenge, err := scanTeamWorkerChallenge(tx.QueryRow(ctx, `SELECT challenge_id::text,worker_id::text,owner_id,account_generation,execution_id::text,role_id,attempt,identity_digest,idempotency_key::text,request_digest,created_at,expires_at,consumed_at FROM core_team_worker_challenges WHERE challenge_id=$1 FOR UPDATE`, challengeID))
	var consumedAt *time.Time
	if !challenge.ConsumedAt.IsZero() {
		consumed := challenge.ConsumedAt
		consumedAt = &consumed
	}
	return challenge, consumedAt, err
}

func scanTeamWorkerChallenge(row interface{ Scan(...any) error }) (coreteamworker.Challenge, error) {
	var challenge coreteamworker.Challenge
	var attempt int
	var consumedAt *time.Time
	err := row.Scan(&challenge.ChallengeID, &challenge.WorkerID, &challenge.Scope.OwnerID, &challenge.Scope.AccountGeneration,
		&challenge.ExecutionID, &challenge.RoleID, &attempt, &challenge.IdentityDigest, &challenge.IdempotencyKey, &challenge.RequestDigest,
		&challenge.CreatedAt, &challenge.ExpiresAt, &consumedAt)
	if attempt > 0 {
		challenge.Attempt = uint32(attempt)
	}
	challenge.CreatedAt, challenge.ExpiresAt = challenge.CreatedAt.UTC(), challenge.ExpiresAt.UTC()
	if consumedAt != nil {
		challenge.ConsumedAt = consumedAt.UTC()
	}
	return challenge, err
}

func readTeamWorkerEnrollment(ctx context.Context, tx pgx.Tx, workerID, identityDigest string) (coreteamworker.Enrollment, error) {
	var enrollment coreteamworker.Enrollment
	var storedIdentity string
	var attempt int
	err := tx.QueryRow(ctx, `SELECT worker_id::text,execution_id::text,role_id,attempt,identity_digest,enrollment_expires_at FROM core_team_workers WHERE worker_id=$1`, workerID).Scan(&enrollment.WorkerID, &enrollment.ExecutionID, &enrollment.RoleID, &attempt, &storedIdentity, &enrollment.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return enrollment, coreteamworker.ErrConflict
	}
	if err != nil {
		return enrollment, err
	}
	if storedIdentity != identityDigest || attempt <= 0 {
		return enrollment, coreteamworker.ErrUnauthorized
	}
	enrollment.Attempt, enrollment.ExpiresAt = uint32(attempt), enrollment.ExpiresAt.UTC()
	return enrollment, nil
}

func lockTeamWorkerReplay(ctx context.Context, tx pgx.Tx, workerID, operation, idempotencyID string) error {
	key := fmt.Sprintf("team-worker:%s:%s:%s", workerID, operation, idempotencyID)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key)
	return err
}

func lockTeamWorkerDeprovisionGuard(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName)
	return err
}

func requireTeamWorkerAdmissionScope(ctx context.Context, tx pgx.Tx, scope coreteam.Scope) error {
	if scope.Validate() != nil {
		return coreteamworker.ErrInvalid
	}
	if err := lockTeamWorkerDeprovisionGuard(ctx, tx); err != nil {
		return err
	}
	return checkTeamWorkerAdmissionTx(ctx, tx, scope)
}

func requireTeamWorkerAdmissionByWorker(ctx context.Context, tx pgx.Tx, workerID string) error {
	if err := lockTeamWorkerDeprovisionGuard(ctx, tx); err != nil {
		return err
	}
	var scope coreteam.Scope
	err := tx.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_team_workers WHERE worker_id=$1`, workerID).Scan(&scope.OwnerID, &scope.AccountGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteamworker.ErrNotFound
	}
	if err != nil {
		return err
	}
	return checkTeamWorkerAdmissionTx(ctx, tx, scope)
}

func checkTeamWorkerAdmissionTx(ctx context.Context, tx pgx.Tx, scope coreteam.Scope) error {
	if scope.Validate() != nil {
		return coreteamworker.ErrRuntimeUnavailable
	}
	var fenced bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, scope.OwnerID, scope.AccountGeneration).Scan(&fenced); err != nil {
		return err
	}
	if fenced {
		return coreteamworker.ErrConflict
	}
	return nil
}

func readTeamWorkerReplay[T any](ctx context.Context, tx pgx.Tx, workerID, operation, idempotencyID, digest string) (T, bool, error) {
	var zero T
	var storedDigest string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_team_worker_replays WHERE worker_id=$1 AND operation=$2 AND idempotency_id=$3`, workerID, operation, idempotencyID).Scan(&storedDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if storedDigest != digest {
		return zero, true, coreteamworker.ErrConflict
	}
	if json.Unmarshal(raw, &zero) != nil {
		return zero, true, coreteamworker.ErrRuntimeUnavailable
	}
	return zero, true, nil
}

func writeTeamWorkerReplay(ctx context.Context, tx pgx.Tx, workerID, operation, idempotencyID, digest string, response any, at time.Time) error {
	raw, err := json.Marshal(response)
	if err != nil {
		return coreteamworker.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_team_worker_replays(worker_id,operation,idempotency_id,request_digest,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6)`, workerID, operation, idempotencyID, digest, raw, at.UTC())
	return teamWorkerWriteError(err)
}

func teamWorkerRequestDigest(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (s *CoreTeamWorkerStore) ready(ctx context.Context) bool {
	return s != nil && s.store != nil && s.store.pool != nil && ctx != nil
}

func coreteamworkerValidUUID(value string) bool {
	return coretask.ValidUUID(value)
}

func teamWorkerWriteError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{coreteamworker.ErrInvalid, coreteamworker.ErrNotFound, coreteamworker.ErrConflict, coreteamworker.ErrExpired, coreteamworker.ErrUnauthorized, coreteamworker.ErrLeaseConflict} {
		if errors.Is(err, known) {
			return known
		}
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505", "23503":
			return coreteamworker.ErrConflict
		case "23514", "22P02":
			return coreteamworker.ErrInvalid
		}
	}
	return err
}

var _ coreteamworker.Repository = (*CoreTeamWorkerStore)(nil)
