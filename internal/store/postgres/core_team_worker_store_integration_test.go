package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestCoreTeamWorkerPostgresEnrollmentLeaseAndExactReplay(t *testing.T) {
	ctx, store, teamRepo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, _, err := teamRepo.CreatePlan(ctx, command); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_tasks SET status='queued',updated_at=$2,revision=revision+1 WHERE task_id=$1`, command.Plan.TaskID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	repo := NewCoreTeamWorkerStore(store)
	workerID := uuid.NewString()
	challengeID := uuid.NewString()
	identityDigest := strings.Repeat("a", 64)
	challenge := coreteamworker.Challenge{
		ChallengeID: challengeID, WorkerID: workerID, Scope: command.Scope, ExecutionID: command.InitialExecutionID,
		RoleID: "research", Attempt: 1, IdentityDigest: identityDigest, IdempotencyKey: uuid.NewString(),
		RequestDigest: strings.Repeat("9", 64), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	createdChallenge, replay, err := repo.CreateChallenge(ctx, challenge)
	if err != nil || replay || createdChallenge != challenge {
		t.Fatalf("created challenge=%+v replay=%v err=%v", createdChallenge, replay, err)
	}
	retryChallenge := challenge
	retryChallenge.ChallengeID = uuid.NewString()
	retryChallenge.WorkerID = uuid.NewString()
	replayedChallenge, replay, err := repo.CreateChallenge(ctx, retryChallenge)
	if err != nil || !replay || replayedChallenge != challenge {
		t.Fatalf("replayed challenge=%+v replay=%v err=%v", replayedChallenge, replay, err)
	}
	conflictingChallenge := retryChallenge
	conflictingChallenge.RequestDigest = strings.Repeat("8", 64)
	if _, _, err := repo.CreateChallenge(ctx, conflictingChallenge); !errors.Is(err, coreteamworker.ErrConflict) {
		t.Fatalf("changed challenge request err=%v", err)
	}
	read, err := repo.GetChallenge(ctx, challengeID)
	if err != nil || read != challenge {
		t.Fatalf("challenge=%+v err=%v", read, err)
	}

	enrollCommand := coreteamworker.EnrollmentCommand{
		ChallengeID: challengeID, WorkerID: workerID, IdentityDigest: identityDigest,
		At: now.Add(time.Second), ExpiresAt: now.Add(31 * time.Minute),
	}
	enrolled, replay, err := repo.Enroll(ctx, enrollCommand)
	if err != nil || replay || enrolled.WorkerID != workerID || enrolled.Attempt != 1 {
		t.Fatalf("enrolled=%+v replay=%v err=%v", enrolled, replay, err)
	}
	sameEnrollment, replay, err := repo.Enroll(ctx, enrollCommand)
	if err != nil || !replay || sameEnrollment != enrolled {
		t.Fatalf("same enrollment=%+v replay=%v err=%v", sameEnrollment, replay, err)
	}
	changedEnrollment := enrollCommand
	changedEnrollment.IdentityDigest = strings.Repeat("b", 64)
	if _, _, err := repo.Enroll(ctx, changedEnrollment); !errors.Is(err, coreteamworker.ErrUnauthorized) {
		t.Fatalf("changed enrollment err=%v", err)
	}

	access := coreteamworker.WorkerAccess{WorkerID: workerID, IdentityDigest: identityDigest, At: now.Add(2 * time.Second)}
	assignment, err := repo.GetAssignment(ctx, access)
	if err != nil || assignment.ExecutionID != command.InitialExecutionID || assignment.RoleID != "research" ||
		assignment.Goal != command.Plan.Roles[0].Goal || assignment.PlanDigest != command.Plan.Digest || assignment.RuntimeID != coreteam.OfficialRuntimeID {
		t.Fatalf("assignment=%+v err=%v", assignment, err)
	}
	foreign := access
	foreign.IdentityDigest = strings.Repeat("c", 64)
	if _, err := repo.GetAssignment(ctx, foreign); !errors.Is(err, coreteamworker.ErrUnauthorized) {
		t.Fatalf("foreign assignment err=%v", err)
	}

	claim := coreteamworker.ClaimCommand{
		Access: access, ExecutionID: command.InitialExecutionID, RoleID: "research", Attempt: 1,
		ClaimID: uuid.NewString(), TTL: time.Minute,
	}
	type claimResult struct {
		lease  coreteamworker.Lease
		replay bool
		err    error
	}
	const claimers = 6
	results := make(chan claimResult, claimers)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(claimers)
	for range claimers {
		go func() {
			ready.Done()
			<-start
			lease, replay, err := repo.Claim(ctx, claim)
			results <- claimResult{lease: lease, replay: replay, err: err}
		}()
	}
	ready.Wait()
	close(start)
	var lease coreteamworker.Lease
	created := 0
	for index := range claimers {
		result := <-results
		if result.err != nil || result.lease.Fence.LeaseEpoch != 1 || result.lease.Fence.WorkerID != workerID {
			t.Fatalf("claim[%d]=%+v", index, result)
		}
		if !result.replay {
			created++
		}
		if index == 0 {
			lease = result.lease
		} else if !reflect.DeepEqual(result.lease, lease) {
			t.Fatalf("non-exact concurrent claim: %+v != %+v", result.lease, lease)
		}
	}
	if created != 1 {
		t.Fatalf("claim mutations=%d want=1", created)
	}
	expiredClaimReplay := claim
	expiredClaimReplay.Access.At = lease.ExpiresAt.Add(time.Second)
	sameExpiredLease, replay, err := repo.Claim(ctx, expiredClaimReplay)
	if err != nil || !replay || sameExpiredLease != lease {
		t.Fatalf("expired claim replay=%+v replay=%v err=%v", sameExpiredLease, replay, err)
	}
	conflictingClaim := claim
	conflictingClaim.ClaimID = uuid.NewString()
	if _, _, err := repo.Claim(ctx, conflictingClaim); !errors.Is(err, coreteamworker.ErrConflict) {
		t.Fatalf("conflicting claim err=%v", err)
	}

	heartbeat := coreteamworker.HeartbeatCommand{
		Access: coreteamworker.WorkerAccess{WorkerID: workerID, IdentityDigest: identityDigest, At: now.Add(10 * time.Second)},
		Fence:  lease.Fence, HeartbeatID: uuid.NewString(), TTL: time.Minute,
	}
	renewed, replay, err := repo.Heartbeat(ctx, heartbeat)
	if err != nil || replay || !renewed.ExpiresAt.Equal(heartbeat.Access.At.Add(time.Minute)) {
		t.Fatalf("renewed=%+v replay=%v err=%v", renewed, replay, err)
	}
	replayedHeartbeat := heartbeat
	replayedHeartbeat.Access.At = heartbeat.Access.At.Add(time.Second)
	sameRenewal, replay, err := repo.Heartbeat(ctx, replayedHeartbeat)
	if err != nil || !replay || sameRenewal != renewed {
		t.Fatalf("same renewal=%+v replay=%v err=%v", sameRenewal, replay, err)
	}
	expiredHeartbeatReplay := heartbeat
	expiredHeartbeatReplay.Access.At = renewed.ExpiresAt.Add(time.Second)
	sameExpiredRenewal, replay, err := repo.Heartbeat(ctx, expiredHeartbeatReplay)
	if err != nil || !replay || sameExpiredRenewal != renewed {
		t.Fatalf("expired heartbeat replay=%+v replay=%v err=%v", sameExpiredRenewal, replay, err)
	}
	laterHeartbeat := heartbeat
	laterHeartbeat.HeartbeatID = uuid.NewString()
	laterHeartbeat.Access.At = now.Add(20 * time.Second)
	laterRenewal, replay, err := repo.Heartbeat(ctx, laterHeartbeat)
	if err != nil || replay || !laterRenewal.ExpiresAt.Equal(now.Add(80*time.Second)) {
		t.Fatalf("later renewal=%+v replay=%v err=%v", laterRenewal, replay, err)
	}
	invertedHeartbeat := heartbeat
	invertedHeartbeat.HeartbeatID = uuid.NewString()
	invertedHeartbeat.Access.At = now.Add(15 * time.Second)
	invertedRenewal, replay, err := repo.Heartbeat(ctx, invertedHeartbeat)
	if err != nil || replay || !invertedRenewal.ExpiresAt.Equal(laterRenewal.ExpiresAt) {
		t.Fatalf("inverted renewal=%+v replay=%v err=%v", invertedRenewal, replay, err)
	}
	var lastSeen time.Time
	if err := store.pool.QueryRow(ctx, `SELECT last_seen_at FROM core_team_workers WHERE worker_id=$1`, workerID).Scan(&lastSeen); err != nil || !lastSeen.Equal(laterHeartbeat.Access.At) {
		t.Fatalf("last_seen_at=%v err=%v", lastSeen, err)
	}
	stale := heartbeat
	stale.HeartbeatID = uuid.NewString()
	stale.Fence.LeaseEpoch++
	if _, _, err := repo.Heartbeat(ctx, stale); !errors.Is(err, coreteamworker.ErrLeaseConflict) {
		t.Fatalf("stale heartbeat err=%v", err)
	}

	milestone := coreteamworker.MilestoneCommand{
		Access: heartbeat.Access, Fence: lease.Fence, EventID: uuid.NewString(), Sequence: 1,
		Stage: coreteamworker.StageRunning, Health: coreteamworker.HealthHealthy,
		EventDigest: strings.Repeat("d", 64),
	}
	receipt, replay, err := repo.EmitMilestone(ctx, milestone)
	if err != nil || replay || receipt.Sequence != 1 {
		t.Fatalf("milestone=%+v replay=%v err=%v", receipt, replay, err)
	}
	sameReceipt, replay, err := repo.EmitMilestone(ctx, milestone)
	if err != nil || !replay || sameReceipt != receipt {
		t.Fatalf("same milestone=%+v replay=%v err=%v", sameReceipt, replay, err)
	}
	changedMilestone := milestone
	changedMilestone.EventDigest = strings.Repeat("e", 64)
	if _, _, err := repo.EmitMilestone(ctx, changedMilestone); !errors.Is(err, coreteamworker.ErrConflict) {
		t.Fatalf("changed milestone err=%v", err)
	}

	unsafePayload := []byte(`{"schema_version":1,"status":"completed","summary":"unsafe result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10},"stdout":"raw provider output"}`)
	unsafeComplete := coreteamworker.CompleteCommand{
		Access: heartbeat.Access, Fence: lease.Fence, CompletionID: uuid.NewString(), Outcome: coreteamworker.OutcomeSucceeded,
		Result: coreteamworker.ResultMetadata{SchemaVersion: 1, Digest: teamWorkerResultDigest(unsafePayload), SizeBytes: uint64(len(unsafePayload)), PayloadJSON: unsafePayload},
	}
	type durableState struct {
		RoleJSON, WorkerJSON string
		CompleteReplays      int64
	}
	readDurableState := func() durableState {
		t.Helper()
		var state durableState
		if err := store.pool.QueryRow(ctx, `
			SELECT to_jsonb(run)::text,to_jsonb(worker)::text,
			       (SELECT count(*) FROM core_team_worker_replays replay WHERE replay.worker_id=worker.worker_id AND replay.operation='complete')
			FROM core_team_role_runs run
			JOIN core_team_workers worker ON worker.worker_id=run.worker_id
			WHERE run.execution_id=$1 AND run.role_id='research'`, command.InitialExecutionID).Scan(&state.RoleJSON, &state.WorkerJSON, &state.CompleteReplays); err != nil {
			t.Fatal(err)
		}
		return state
	}
	beforeUnsafeComplete := readDurableState()
	if _, _, err := repo.Complete(ctx, unsafeComplete); !errors.Is(err, coreteamworker.ErrInvalid) {
		t.Fatalf("unsafe completion err=%v", err)
	}
	afterUnsafeComplete := readDurableState()
	if afterUnsafeComplete != beforeUnsafeComplete {
		t.Fatalf("unsafe completion mutated durable state:\nbefore=%+v\nafter=%+v", beforeUnsafeComplete, afterUnsafeComplete)
	}

	resultPayload := []byte(`{"schema_version":1,"status":"completed","summary":"stored result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10}}`)
	complete := coreteamworker.CompleteCommand{
		Access: heartbeat.Access, Fence: lease.Fence, CompletionID: uuid.NewString(), Outcome: coreteamworker.OutcomeSucceeded,
		Result: coreteamworker.ResultMetadata{
			SchemaVersion: 1,
			Digest:        teamWorkerResultDigest(resultPayload),
			SizeBytes:     uint64(len(resultPayload)),
			PayloadJSON:   resultPayload,
		},
	}
	completed, replay, err := repo.Complete(ctx, complete)
	if err != nil || replay || completed.Outcome != coreteamworker.OutcomeSucceeded {
		t.Fatalf("completed=%+v replay=%v err=%v", completed, replay, err)
	}
	var roleStatus, storedResultDigest string
	var storedResult []byte
	var storedResultSize int64
	if err := store.pool.QueryRow(ctx, `SELECT status,result_digest,result_size_bytes,result_payload FROM core_team_role_runs WHERE execution_id=$1 AND role_id='research'`, command.InitialExecutionID).Scan(&roleStatus, &storedResultDigest, &storedResultSize, &storedResult); err != nil || roleStatus != string(coreteam.ExecutionCleaningUp) || storedResultDigest != complete.Result.Digest || storedResultSize != int64(len(complete.Result.PayloadJSON)) || !bytes.Equal(storedResult, complete.Result.PayloadJSON) {
		t.Fatalf("role status=%q digest=%q size=%d payload=%q err=%v", roleStatus, storedResultDigest, storedResultSize, storedResult, err)
	}
	sameCompletion, replay, err := repo.Complete(ctx, complete)
	if err != nil || !replay || sameCompletion != completed {
		t.Fatalf("same completion=%+v replay=%v err=%v", sameCompletion, replay, err)
	}
	changedCompletion := complete
	changedCompletion.Outcome = coreteamworker.OutcomeFailed
	changedCompletion.Result = coreteamworker.ResultMetadata{}
	changedCompletion.FailureCode = coreteamworker.FailureInternal
	if _, _, err := repo.Complete(ctx, changedCompletion); !errors.Is(err, coreteamworker.ErrConflict) {
		t.Fatalf("changed completion err=%v", err)
	}
}

func teamWorkerResultDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func TestCoreTeamWorkerPostgresRejectsExpiredEnrollment(t *testing.T) {
	ctx, store, teamRepo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, _, err := teamRepo.CreatePlan(ctx, command); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_tasks SET status='queued' WHERE task_id=$1`, command.Plan.TaskID); err != nil {
		t.Fatal(err)
	}
	repo := NewCoreTeamWorkerStore(store)
	challenge := coreteamworker.Challenge{
		ChallengeID: uuid.NewString(), WorkerID: uuid.NewString(), Scope: command.Scope, ExecutionID: command.InitialExecutionID,
		RoleID: "research", Attempt: 1, IdentityDigest: strings.Repeat("a", 64), IdempotencyKey: uuid.NewString(),
		RequestDigest: strings.Repeat("8", 64), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second),
	}
	if _, _, err := repo.CreateChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	_, _, err := repo.Enroll(ctx, coreteamworker.EnrollmentCommand{
		ChallengeID: challenge.ChallengeID, WorkerID: challenge.WorkerID, IdentityDigest: challenge.IdentityDigest,
		At: now, ExpiresAt: now.Add(time.Hour),
	})
	if !errors.Is(err, coreteamworker.ErrExpired) {
		t.Fatalf("expired enrollment err=%v", err)
	}
}

func TestCoreTeamWorkerPostgresSerializesWithUncommittedAccountDeprovision(t *testing.T) {
	ctx, store, teamRepo, cleanup := teamStoreFixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := teamCreatePlanCommand(t, ctx, store, now)
	if _, _, err := teamRepo.CreatePlan(ctx, command); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_tasks SET status='queued',updated_at=$2,revision=revision+1 WHERE task_id=$1`, command.Plan.TaskID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	repo := NewCoreTeamWorkerStore(store)
	workerID := uuid.NewString()
	identityDigest := strings.Repeat("a", 64)
	challenge := coreteamworker.Challenge{
		ChallengeID: uuid.NewString(), WorkerID: workerID, Scope: command.Scope, ExecutionID: command.InitialExecutionID,
		RoleID: "research", Attempt: 1, IdentityDigest: identityDigest, IdempotencyKey: uuid.NewString(),
		RequestDigest: strings.Repeat("9", 64), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if _, _, err := repo.CreateChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Enroll(ctx, coreteamworker.EnrollmentCommand{
		ChallengeID: challenge.ChallengeID, WorkerID: workerID, IdentityDigest: identityDigest,
		At: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	claim, _, err := repo.Claim(ctx, coreteamworker.ClaimCommand{
		Access:      coreteamworker.WorkerAccess{WorkerID: workerID, IdentityDigest: identityDigest, At: now.Add(2 * time.Second)},
		ExecutionID: command.InitialExecutionID, RoleID: "research", Attempt: 1, ClaimID: uuid.NewString(), TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	deprovisionTx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deprovisionOpen := true
	defer func() {
		if deprovisionOpen {
			_ = deprovisionTx.Rollback(context.Background())
		}
	}()
	if _, err = deprovisionTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		t.Fatal(err)
	}
	if _, err = deprovisionTx.Exec(ctx, `INSERT INTO agent_account_deprovisions(owner_id,account_generation,idempotency_key,request_digest,state) VALUES($1,$2,$3,$4,'running')`, command.Scope.OwnerID, command.Scope.AccountGeneration, uuid.New(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, _, heartbeatErr := repo.Heartbeat(ctx, coreteamworker.HeartbeatCommand{
			Access: coreteamworker.WorkerAccess{WorkerID: workerID, IdentityDigest: identityDigest, At: now.Add(3 * time.Second)},
			Fence:  claim.Fence, HeartbeatID: uuid.NewString(), TTL: time.Minute,
		})
		result <- heartbeatErr
	}()
	select {
	case heartbeatErr := <-result:
		t.Fatalf("Worker heartbeat escaped uncommitted deprovision fence: %v", heartbeatErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err = deprovisionTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	deprovisionOpen = false
	select {
	case heartbeatErr := <-result:
		if !errors.Is(heartbeatErr, coreteamworker.ErrConflict) {
			t.Fatalf("heartbeat after deprovision commit err=%v", heartbeatErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Worker heartbeat remained blocked after deprovision commit")
	}
	var leaseExpires time.Time
	if err := store.pool.QueryRow(ctx, `SELECT lease_expires_at FROM core_team_role_runs WHERE execution_id=$1 AND role_id='research'`, command.InitialExecutionID).Scan(&leaseExpires); err != nil || !leaseExpires.Equal(claim.ExpiresAt) {
		t.Fatalf("lease expiry changed across deprovision fence: got=%v want=%v err=%v", leaseExpires, claim.ExpiresAt, err)
	}
}
