package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

func TestTeamExecutionMaterializationIsAtomicConcurrentAndRestartable(
	t *testing.T,
) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		45*time.Second,
	)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "team-execution-integration",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-team-execution"
	connectionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region,
		     control_role_arn, foundation_stack_id, credential_generation,
		     status, revision)
		VALUES ($1,$2,$3,'123456789012','us-east-1',
		        'arn:aws:iam::123456789012:role/test-control',
		        'test-foundation-stack',1,'active',1)`,
		connectionID,
		instanceID,
		ownerID,
	); err != nil {
		t.Fatal(err)
	}
	goal := "Implement the approved change and independently review it."
	createdTask, err := store.Create(
		ctx,
		scope,
		task.CreateCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Goal:           goal,
			Retention:      task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := teamOfferSnapshotFixture(
		t,
		connectionID,
		now.Add(-time.Minute),
	)
	if _, err := store.CreateTeamOfferSnapshot(
		ctx,
		scope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Snapshot:       snapshot,
		},
	); err != nil {
		t.Fatal(err)
	}
	plan := twoWorkerTeamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
	)
	plan = bindTeamPlanGitHubInput(t, plan, createdTask.TaskID)
	planRecord, err := store.CreateTeamPlan(
		ctx,
		scope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         createdTask.TaskID,
			Plan:           plan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("Team execution approval device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signerKeyID := "team-execution-device-1"
	if _, err := store.RegisterApprovalDevice(
		ctx,
		scope,
		postgres.RegisterApprovalDeviceCommand{
			IdempotencyKey: uuid.NewString(),
			Device: cloudapproval.DeviceKeyV1{
				KeyID:           signerKeyID,
				AgentInstanceID: instanceID,
				OwnerID:         ownerID,
				Revision:        1,
				Status:          cloudapproval.DeviceKeyActive,
				PublicKey:       publicKey,
				NotBefore:       now.Add(-time.Hour),
				ExpiresAt:       now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	approvalID, launchAuthorization :=
		newTeamLaunchAuthorizationFixture(t, plan, instanceID)
	challenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		scope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     plan.PlanID,
			PlanRevision:               plan.Revision,
			ExpectedPlanRecordRevision: planRecord.RecordRevision,
			ApprovalID:                 approvalID,
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
			Authorization:              launchAuthorization,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	approvalKey := uuid.NewString()
	approvalSignature := signTeamApproval(
		t,
		challenge.Challenge,
		privateKey,
	)
	approvedPlan, err := store.ApproveTeamPlan(
		ctx,
		scope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  approvalKey,
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      planRecord.RecordRevision,
			ExpectedChallengeRecordRevision: challenge.RecordRevision,
			Signature:                       approvalSignature,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := store.GetTeamApprovalForPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization := teamorchestration.ApprovedPlanFact{
		Plan: teamorchestration.PlanFact{
			TaskID:         approvedPlan.TaskID,
			Plan:           approvedPlan.Plan,
			PlanDigest:     approvedPlan.PlanDigest,
			Status:         teamorchestration.PlanApproved,
			RecordRevision: approvedPlan.RecordRevision,
			CreatedAt:      approvedPlan.CreatedAt,
			UpdatedAt:      approvedPlan.UpdatedAt,
		},
		Approval: teamorchestration.ApprovalFact{
			Signature:     approval.Signature,
			Authorization: approval.Authorization,
			ApprovedAt:    approval.ApprovedAt,
			CreatedAt:     approval.CreatedAt,
		},
	}
	execution, err := teamexecution.Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	executionJSON, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	executionCBOR, err := execution.CanonicalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO team_executions (
		    execution_id, agent_instance_id, owner_id, task_id,
		    plan_id, plan_revision, plan_digest, approval_id,
		    provider, connection_id, connection_revision, account_id, region,
		    catalog_revision, policy_revision,
		    pricing_snapshot_id, pricing_snapshot_digest,
		    worker_count, max_concurrent_workers, currency,
		    hard_budget_micros, execution_digest, execution_json,
		    execution_cbor, status, record_revision, authorized_at
		)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
		    $18,$19,$20,$21,$22,
		    jsonb_set(
		        $23::jsonb,
		        '{credential_ref}',
		        to_jsonb('secret_ref:forbidden'::text)
		    ),
		    $24,$25,$26,$27
		)`,
		execution.ExecutionID,
		instanceID,
		execution.OwnerID,
		execution.TaskID,
		execution.PlanID,
		int64(execution.PlanRevision),
		execution.PlanDigest,
		execution.ApprovalID,
		execution.ProviderScope.Provider,
		execution.ProviderScope.ConnectionID,
		int64(execution.ProviderScope.ConnectionRevision),
		execution.ProviderScope.AccountID,
		execution.Region,
		execution.CatalogRevision,
		execution.PolicyRevision,
		execution.PricingSnapshotID,
		execution.PricingSnapshotDigest,
		int32(execution.WorkerCount),
		int32(execution.MaxConcurrentWorkers),
		execution.Currency,
		int64(execution.HardBudgetMicros),
		executionDigest,
		executionJSON,
		executionCBOR,
		teamexecution.StatusMaterialized,
		int64(1),
		execution.AuthorizedAt,
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"Team execution JSON contains unknown or missing fields",
		) {
		t.Fatalf("unknown execution field rejection error=%v", err)
	}
	pending, err := store.ListPendingMaterializations(ctx, nil, 16)
	if err != nil ||
		len(pending) != 1 ||
		pending[0].OwnerID != ownerID ||
		pending[0].PlanID != plan.PlanID ||
		pending[0].PlanRevision != plan.Revision {
		t.Fatalf("pending Team materializations=%#v error=%v", pending, err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE cloud_connections SET status='degraded' WHERE connection_id=$1`,
		connectionID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: uuid.NewString(),
			Authorization:  authorization,
			Execution:      execution,
		},
	); err != nil {
		t.Fatalf(
			"non-spending materialization depended on current Connection: %v",
			err,
		)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE cloud_connections SET status='active' WHERE connection_id=$1`,
		connectionID,
	); err != nil {
		t.Fatal(err)
	}

	const contenders = 8
	facts := make(chan teamexecution.Fact, contenders)
	failures := make(chan error, contenders)
	var wait sync.WaitGroup
	wait.Add(contenders)
	for index := 0; index < contenders; index++ {
		go func() {
			defer wait.Done()
			fact, err := store.PersistExecution(
				ctx,
				scope,
				teamexecution.PersistCommand{
					IdempotencyKey: uuid.NewString(),
					Authorization:  authorization,
					Execution:      execution,
				},
			)
			if err != nil {
				failures <- err
				return
			}
			facts <- fact
		}()
	}
	wait.Wait()
	close(facts)
	close(failures)
	for err := range failures {
		t.Errorf("concurrent materialization failed: %v", err)
	}
	var first teamexecution.Fact
	count := 0
	for fact := range facts {
		if count == 0 {
			first = fact
		} else if fact.Execution.ExecutionID != first.Execution.ExecutionID ||
			fact.ExecutionDigest != first.ExecutionDigest {
			t.Errorf("concurrent materialization drifted: %#v", fact)
		}
		count++
	}
	if count != contenders {
		t.Fatalf("successful materializations=%d, want %d", count, contenders)
	}
	if first.Status != teamexecution.StatusMaterialized ||
		first.RecordRevision != 1 ||
		len(first.Execution.Roles) != 2 {
		t.Fatalf("materialized Team execution = %#v", first)
	}
	pending, err = store.ListPendingMaterializations(ctx, nil, 16)
	if err != nil || len(pending) != 0 {
		t.Fatalf("materialized Plan remained pending=%#v error=%v", pending, err)
	}
	byPlan, found, err := store.FindTeamExecutionByPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	)
	if err != nil ||
		!found ||
		byPlan.Execution.ExecutionID != first.Execution.ExecutionID ||
		byPlan.ExecutionDigest != first.ExecutionDigest {
		t.Fatalf(
			"Team execution Plan lookup=%#v found=%v error=%v",
			byPlan,
			found,
			err,
		)
	}

	replayKey := uuid.NewString()
	replayed, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: replayKey,
			Authorization:  authorization,
			Execution:      execution,
		},
	)
	if err != nil ||
		replayed.ExecutionDigest != first.ExecutionDigest {
		t.Fatalf("cross-key replay=%#v error=%v", replayed, err)
	}
	dispatchKey := uuid.NewString()
	dispatched, err := store.BeginDispatch(
		ctx,
		scope,
		teamexecution.BeginDispatchCommand{
			IdempotencyKey: dispatchKey,
			OwnerID:        ownerID,
			ExecutionID:    execution.ExecutionID,
			Authorization:  &authorization,
		},
	)
	if err != nil ||
		dispatched.Status != teamexecution.StatusDispatching ||
		dispatched.RecordRevision != 2 {
		t.Fatalf("begin Team dispatch=%#v error=%v", dispatched, err)
	}
	approvalReplay, found, err := store.FindApprovedTeamPlan(
		ctx,
		scope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  approvalKey,
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      planRecord.RecordRevision,
			ExpectedChallengeRecordRevision: challenge.RecordRevision,
			Signature:                       approvalSignature,
		},
	)
	if err != nil ||
		!found ||
		approvalReplay.Status != postgres.TeamPlanApproved ||
		approvalReplay.RecordRevision != approvedPlan.RecordRevision {
		t.Fatalf(
			"advanced Plan approval replay=%#v found=%v error=%v",
			approvalReplay,
			found,
			err,
		)
	}
	crossKeyLookup, found, err := store.FindMaterializedExecution(
		ctx,
		scope,
		teamexecution.MaterializeRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			PlanID:         plan.PlanID,
			PlanRevision:   plan.Revision,
		},
	)
	if err != nil ||
		!found ||
		crossKeyLookup.Status != teamexecution.StatusDispatching ||
		crossKeyLookup.RecordRevision != 2 {
		t.Fatalf(
			"cross-key materialization lookup=%#v found=%v error=%v",
			crossKeyLookup,
			found,
			err,
		)
	}
	stableReplay, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: replayKey,
			Authorization:  authorization,
			Execution:      execution,
		},
	)
	if err != nil ||
		stableReplay.Status != teamexecution.StatusMaterialized ||
		stableReplay.RecordRevision != 1 {
		t.Fatalf(
			"advanced lifecycle stable replay=%#v error=%v",
			stableReplay,
			err,
		)
	}
	currentReplayKey := uuid.NewString()
	currentReplay, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: currentReplayKey,
			Authorization:  authorization,
			Execution:      execution,
		},
	)
	if err != nil ||
		currentReplay.Status != teamexecution.StatusDispatching ||
		currentReplay.RecordRevision != 2 {
		t.Fatalf(
			"advanced lifecycle current replay=%#v error=%v",
			currentReplay,
			err,
		)
	}
	currentReplayAgain, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: currentReplayKey,
			Authorization:  authorization,
			Execution:      execution,
		},
	)
	if err != nil ||
		currentReplayAgain.Status != teamexecution.StatusDispatching ||
		currentReplayAgain.RecordRevision != 2 {
		t.Fatalf(
			"advanced lifecycle repeated current replay=%#v error=%v",
			currentReplayAgain,
			err,
		)
	}
	var executionRows, roleRows, dependencyRows int
	if err := pool.QueryRow(ctx, `
		SELECT
		    (SELECT count(*) FROM team_executions
		     WHERE plan_id=$1 AND plan_revision=$2),
		    (SELECT count(*) FROM team_execution_roles
		     WHERE execution_id=$3),
		    (SELECT count(*) FROM team_execution_role_dependencies
		     WHERE execution_id=$3)`,
		plan.PlanID,
		int64(plan.Revision),
		execution.ExecutionID,
	).Scan(
		&executionRows,
		&roleRows,
		&dependencyRows,
	); err != nil {
		t.Fatal(err)
	}
	if executionRows != 1 || roleRows != 2 || dependencyRows != 1 {
		t.Fatalf(
			"rows execution=%d roles=%d dependencies=%d",
			executionRows,
			roleRows,
			dependencyRows,
		)
	}
	storedTask, err := store.Get(ctx, createdTask.TaskID)
	if err != nil ||
		storedTask.ExecutionStatus != task.ExecutionQueued ||
		storedTask.OutcomeStatus != task.OutcomePending ||
		storedTask.ApprovedPlanID != plan.PlanID {
		t.Fatalf("queued Team Task=%#v error=%v", storedTask, err)
	}
	steps, err := store.ListSteps(ctx, createdTask.TaskID)
	if err != nil || len(steps) != 2 {
		t.Fatalf("Team Task steps=%#v error=%v", steps, err)
	}
	stepByID := make(map[string]task.Step, len(steps))
	for _, step := range steps {
		stepByID[step.StepID] = step
	}
	implementation := execution.Roles[0]
	review := execution.Roles[1]
	if stepByID[implementation.TaskStepID].ExecutorKind !=
		task.ExecutorCloudWorker ||
		stepByID[review.TaskStepID].ExecutorKind != task.ExecutorCloudWorker ||
		len(stepByID[review.TaskStepID].DependsOnStepIDs) != 1 ||
		stepByID[review.TaskStepID].DependsOnStepIDs[0] !=
			implementation.TaskStepID {
		t.Fatalf("persisted Team Task DAG=%#v", steps)
	}
	baseAcquire := task.AcquireReadyStepCommand{
		TaskID:        createdTask.TaskID,
		StepID:        implementation.TaskStepID,
		WorkerID:      implementation.ExpectedWorkerID,
		ExecutorKind:  task.ExecutorCloudWorker,
		LeaseDuration: time.Minute,
	}
	missingDeployment := baseAcquire
	missingDeployment.IdempotencyKey = uuid.NewString()
	if _, _, err := store.AcquireReadyStep(
		ctx,
		scope,
		missingDeployment,
	); !errors.Is(err, teamexecution.ErrNotReady) {
		t.Fatalf("unbound Team Worker claim error=%v", err)
	}
	wrongWorker := baseAcquire
	wrongWorker.IdempotencyKey = uuid.NewString()
	wrongWorker.DeploymentID = implementation.DeploymentID
	wrongWorker.WorkerID = uuid.NewString()
	if _, _, err := store.AcquireReadyStep(
		ctx,
		scope,
		wrongWorker,
	); !errors.Is(err, teamexecution.ErrNotReady) {
		t.Fatalf("wrong Team Worker identity claim error=%v", err)
	}
	firstAcquire := baseAcquire
	firstAcquire.IdempotencyKey = uuid.NewString()
	firstAcquire.DeploymentID = implementation.DeploymentID
	firstAttempt, found, err := store.AcquireReadyStep(
		ctx,
		scope,
		firstAcquire,
	)
	if err != nil || !found ||
		firstAttempt.WorkerID != implementation.ExpectedWorkerID ||
		firstAttempt.StepID != implementation.TaskStepID {
		t.Fatalf("first Team Worker claim=%#v found=%v error=%v", firstAttempt, found, err)
	}
	concurrentAcquire := task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(),
		DeploymentID:   review.DeploymentID,
		TaskID:         createdTask.TaskID,
		StepID:         review.TaskStepID,
		WorkerID:       review.ExpectedWorkerID,
		ExecutorKind:   task.ExecutorCloudWorker,
		LeaseDuration:  time.Minute,
	}
	if _, _, err := store.AcquireReadyStep(
		ctx,
		scope,
		concurrentAcquire,
	); !errors.Is(err, teamexecution.ErrConcurrencyLimit) {
		t.Fatalf("concurrent Team Worker claim error=%v", err)
	}
	if _, err := store.CompleteStep(
		ctx,
		scope,
		task.CompleteStepCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         createdTask.TaskID,
			StepID:         implementation.TaskStepID,
			Attempt:        firstAttempt.Attempt,
			LeaseEpoch:     firstAttempt.LeaseEpoch,
			WorkerID:       implementation.ExpectedWorkerID,
			Outcome:        task.OutcomeSucceeded,
			ResultRef: "s3://team-results/" +
				implementation.RoleID + "/final.json",
		},
	); err != nil {
		t.Fatalf("complete first Team Worker Step: %v", err)
	}
	concurrentAcquire.IdempotencyKey = uuid.NewString()
	secondAttempt, found, err := store.AcquireReadyStep(
		ctx,
		scope,
		concurrentAcquire,
	)
	if err != nil || !found ||
		secondAttempt.WorkerID != review.ExpectedWorkerID ||
		secondAttempt.StepID != review.TaskStepID {
		t.Fatalf(
			"dependent Team Worker claim=%#v found=%v error=%v",
			secondAttempt,
			found,
			err,
		)
	}
	stableDispatch, err := store.BeginDispatch(
		ctx,
		scope,
		teamexecution.BeginDispatchCommand{
			IdempotencyKey: dispatchKey,
			OwnerID:        ownerID,
			ExecutionID:    execution.ExecutionID,
		},
	)
	if err != nil ||
		stableDispatch.Status != teamexecution.StatusDispatching ||
		stableDispatch.RecordRevision != 2 {
		t.Fatalf(
			"advanced lifecycle stable dispatch replay=%#v error=%v",
			stableDispatch,
			err,
		)
	}
	currentDispatchKey := uuid.NewString()
	currentDispatch, err := store.BeginDispatch(
		ctx,
		scope,
		teamexecution.BeginDispatchCommand{
			IdempotencyKey: currentDispatchKey,
			OwnerID:        ownerID,
			ExecutionID:    execution.ExecutionID,
		},
	)
	if err != nil ||
		currentDispatch.Status != teamexecution.StatusRunning ||
		currentDispatch.RecordRevision != 3 {
		t.Fatalf(
			"advanced lifecycle current dispatch=%#v error=%v",
			currentDispatch,
			err,
		)
	}
	currentDispatchReplay, err := store.BeginDispatch(
		ctx,
		scope,
		teamexecution.BeginDispatchCommand{
			IdempotencyKey: currentDispatchKey,
			OwnerID:        ownerID,
			ExecutionID:    execution.ExecutionID,
		},
	)
	if err != nil ||
		currentDispatchReplay.Status != teamexecution.StatusRunning ||
		currentDispatchReplay.RecordRevision != 3 {
		t.Fatalf(
			"repeated current dispatch=%#v error=%v",
			currentDispatchReplay,
			err,
		)
	}
	if _, err := store.CompleteStep(
		ctx,
		scope,
		task.CompleteStepCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         createdTask.TaskID,
			StepID:         review.TaskStepID,
			Attempt:        secondAttempt.Attempt,
			LeaseEpoch:     secondAttempt.LeaseEpoch,
			WorkerID:       review.ExpectedWorkerID,
			Outcome:        task.OutcomeSucceeded,
			ResultRef: "s3://team-results/" +
				review.RoleID + "/final.json",
		},
	); err != nil {
		t.Fatalf("complete final Team Worker Step: %v", err)
	}
	verifying, err := store.GetTeamExecution(
		ctx,
		ownerID,
		execution.ExecutionID,
	)
	if err != nil ||
		verifying.Status != teamexecution.StatusVerifying ||
		verifying.RecordRevision != 4 {
		t.Fatalf("verifying Team execution=%#v error=%v", verifying, err)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	readBack, err := restarted.GetTeamExecution(
		ctx,
		ownerID,
		execution.ExecutionID,
	)
	if err != nil ||
		readBack.ExecutionDigest != first.ExecutionDigest ||
		readBack.Status != teamexecution.StatusVerifying ||
		readBack.RecordRevision != 4 ||
		readBack.Execution.ValidateAgainst(authorization) != nil {
		t.Fatalf("restarted Team execution=%#v error=%v", readBack, err)
	}
	foreign, err := postgres.New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.GetTeamExecution(
		ctx,
		ownerID,
		execution.ExecutionID,
	); !errors.Is(err, teamexecution.ErrNotFound) {
		t.Fatalf("cross-Agent Team execution read error=%v", err)
	}

	objectiveMarker := plan.Assignments[0].Objective
	var leakedEvents int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM task_events
		WHERE summary_json::text LIKE '%' || $1 || '%'`,
		objectiveMarker,
	).Scan(&leakedEvents); err != nil {
		t.Fatal(err)
	}
	if leakedEvents != 0 {
		t.Fatalf("Worker objective leaked into %d public events", leakedEvents)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO team_execution_roles (
		    execution_id, task_id, role_id, step_declaration_id,
		    task_step_id, deployment_id, expected_worker_id,
		    model_credential_slot, role_digest, role_json, role_cbor
		)
		SELECT execution_id, task_id, 'injected', step_declaration_id,
		       task_step_id, deployment_id, expected_worker_id,
		       model_credential_slot, role_digest,
		       jsonb_set(role_json, '{role_id}', '"injected"'::jsonb),
		       role_cbor
		FROM team_execution_roles
		WHERE execution_id=$1 AND role_id='implementation'`,
		execution.ExecutionID,
	); err == nil {
		t.Fatal("role outside the immutable execution was inserted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO team_execution_role_dependencies (
		    execution_id, role_id, depends_on_role_id
		)
		VALUES ($1,'implementation','review')`,
		execution.ExecutionID,
	); err == nil {
		t.Fatal("dependency outside the immutable role was inserted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO task_step_dependencies (
		    task_id, step_id, depends_on_step_id
		)
		VALUES ($1,$2,$3)`,
		createdTask.TaskID,
		implementation.TaskStepID,
		review.TaskStepID,
	); err == nil {
		t.Fatal("extra dependency outside the immutable Task DAG was inserted")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_execution_roles
		SET role_json=jsonb_set(role_json, '{title}', '"tampered"'::jsonb)
		WHERE execution_id=$1 AND role_id='implementation'`,
		execution.ExecutionID,
	); err == nil {
		t.Fatal("immutable Team execution role mutation succeeded")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_executions
		SET execution_json=jsonb_set(
		        execution_json,
		        '{worker_count}',
		        '1'::jsonb
		    ),
		    status='failed',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE execution_id=$1`,
		execution.ExecutionID,
	); err == nil {
		t.Fatal("immutable Team execution mutation succeeded")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_executions
		SET task_input_source_digest=$2,
		    status='failed',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE execution_id=$1`,
		execution.ExecutionID,
		"sha256:"+strings.Repeat("d", 64),
	); err == nil {
		t.Fatal("immutable Team execution TaskInput reference mutation succeeded")
	}

	blockedTask, err := store.Create(
		ctx,
		scope,
		task.CreateCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Goal:           "Do not append Workers while this step is queued.",
			Retention:      task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedPlan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		blockedTask.Goal,
		uuid.NewString(),
		1,
	)
	blockedPlanRecord, err := store.CreateTeamPlan(
		ctx,
		scope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         blockedTask.TaskID,
			Plan:           blockedPlan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedApprovalID, blockedLaunchAuthorization :=
		newTeamLaunchAuthorizationFixture(t, blockedPlan, instanceID)
	blockedChallenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		scope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			PlanID:         blockedPlan.PlanID,
			PlanRevision:   blockedPlan.Revision,
			ExpectedPlanRecordRevision: blockedPlanRecord.
				RecordRevision,
			ApprovalID:    blockedApprovalID,
			ChallengeID:   uuid.NewString(),
			SignerKeyID:   signerKeyID,
			Authorization: blockedLaunchAuthorization,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedApproved, err := store.ApproveTeamPlan(
		ctx,
		scope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			ExpectedPlanRecordRevision: blockedPlanRecord.
				RecordRevision,
			ExpectedChallengeRecordRevision: blockedChallenge.
				RecordRevision,
			Signature: signTeamApproval(
				t,
				blockedChallenge.Challenge,
				privateKey,
			),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedApproval, err := store.GetTeamApprovalForPlan(
		ctx,
		ownerID,
		blockedPlan.PlanID,
		blockedPlan.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedAuthorization := teamorchestration.ApprovedPlanFact{
		Plan: teamorchestration.PlanFact{
			TaskID:         blockedApproved.TaskID,
			Plan:           blockedApproved.Plan,
			PlanDigest:     blockedApproved.PlanDigest,
			Status:         teamorchestration.PlanApproved,
			RecordRevision: blockedApproved.RecordRevision,
			CreatedAt:      blockedApproved.CreatedAt,
			UpdatedAt:      blockedApproved.UpdatedAt,
		},
		Approval: teamorchestration.ApprovalFact{
			Signature:     blockedApproval.Signature,
			Authorization: blockedApproval.Authorization,
			ApprovedAt:    blockedApproval.ApprovedAt,
			CreatedAt:     blockedApproval.CreatedAt,
		},
	}
	blockedStepID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO task_steps (
		    step_id, task_id, name, executor_kind,
		    execution_status, outcome_status
		)
		VALUES ($1,$2,'unfinished_control_step','control_plane',
		        'queued','pending')`,
		blockedStepID,
		blockedTask.TaskID,
	); err != nil {
		t.Fatal(err)
	}
	blockedExecution, err := teamexecution.Materialize(
		blockedAuthorization,
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedMaterializeKey := uuid.NewString()
	if _, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: blockedMaterializeKey,
			Authorization:  blockedAuthorization,
			Execution:      blockedExecution,
		},
	); !errors.Is(err, teamexecution.ErrNotReady) {
		t.Fatalf("unfinished Task materialization error=%v", err)
	}
	var blockedExecutionRows, blockedStepRows, blockedReplayRows int
	if err := pool.QueryRow(ctx, `
		SELECT
		    (SELECT count(*) FROM team_executions WHERE task_id=$1),
		    (SELECT count(*) FROM task_steps WHERE task_id=$1),
		    (SELECT count(*) FROM idempotency_records
		     WHERE operation='team.execution.materialize'
		       AND idempotency_key=$2)`,
		blockedTask.TaskID,
		blockedMaterializeKey,
	).Scan(
		&blockedExecutionRows,
		&blockedStepRows,
		&blockedReplayRows,
	); err != nil {
		t.Fatal(err)
	}
	if blockedExecutionRows != 0 ||
		blockedStepRows != 1 ||
		blockedReplayRows != 0 {
		t.Fatalf(
			"failed materialization left execution=%d steps=%d replay=%d",
			blockedExecutionRows,
			blockedStepRows,
			blockedReplayRows,
		)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_plans
		SET status='failed',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE plan_id=$1
		  AND plan_revision=$2
		  AND status='executing'`,
		plan.PlanID,
		int64(plan.Revision),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.GetTeamExecution(
		ctx,
		ownerID,
		execution.ExecutionID,
	); !errors.Is(err, teamexecution.ErrFactMismatch) {
		t.Fatalf("Execution/Plan status drift read error=%v", err)
	}
}

func twoWorkerTeamPlanFixture(
	t *testing.T,
	snapshot *teamplan.OfferSnapshot,
	ownerID,
	goal,
	planID string,
) teamplan.Plan {
	t.Helper()
	plan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		planID,
		1,
	)
	implementation := plan.Assignments[0]
	implementation.RoleID = "implementation"
	review := implementation
	review.RoleID = "review"
	review.Title = "Independent review"
	review.Objective = "worker-review-objective-private-marker"
	review.WorkClass = teamplan.WorkSoftwareReview
	review.RequiredCapabilities = []teamplan.Capability{
		teamplan.CapabilityCodeReview,
	}
	review.DependsOnRoleIDs = []string{"implementation"}
	review.RuntimeReleaseID = uuid.NewSHA1(
		uuid.MustParse(planID),
		[]byte("runtime:review"),
	).String()
	plan.Assignments = []teamplan.WorkerAssignment{
		implementation,
		review,
	}
	plan.WorkerCount = 2
	plan.MaxConcurrentWorkers = 1
	plan.ProposalRationale =
		"One implementation Worker followed by one independent reviewer."
	plan.Schedule = teamplan.ScheduleEstimate{
		MinimumWallTime:  2 * time.Minute,
		ExpectedWallTime: 4 * time.Minute,
		MaximumWallTime:  6 * time.Minute,
	}
	firstCost := plan.Cost.Roles[0]
	firstCost.RoleID = "implementation"
	secondCost := firstCost
	secondCost.RoleID = "review"
	plan.Cost.MinimumMicros = firstCost.TotalMinimumMicros * 2
	plan.Cost.ExpectedMicros = firstCost.TotalExpectedMicros * 2
	plan.Cost.MaximumMicros = firstCost.TotalMaximumMicros * 2
	plan.Cost.HardBudgetMicros = 464_640
	plan.Cost.Roles = []teamplan.RoleCostEstimate{
		firstCost,
		secondCost,
	}
	policy := teamPlanPolicyFixture()
	policy.MaxWorkers = 2
	policy.MaxConcurrentWorkers = 1
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.PolicyRevision = policyDigest
	if err := plan.Validate(); err != nil {
		t.Fatalf("two-Worker Team Plan fixture is invalid: %v", err)
	}
	if err := snapshot.VerifyPlanPricing(
		plan,
		time.Now().UTC().Truncate(time.Microsecond),
	); err != nil {
		t.Fatalf("two-Worker Team Plan pricing is invalid: %v", err)
	}
	return plan
}
