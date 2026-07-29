package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCancelTeamExecutionUpdatesTaskPlanAndExecutionAtomically(
	t *testing.T,
) {
	for _, state := range []string{
		"approved",
		"materialized",
		"dispatching",
		"running",
	} {
		state := state
		t.Run(state, func(t *testing.T) {
			fixture := newTeamCancellationFixture(t, state != "approved")
			switch state {
			case "dispatching", "running":
				if _, err := fixture.store.BeginDispatch(
					fixture.ctx,
					fixture.scope,
					teamexecution.BeginDispatchCommand{
						IdempotencyKey: uuid.NewString(),
						OwnerID:        fixture.ownerID,
						ExecutionID:    fixture.execution.ExecutionID,
						Authorization:  &fixture.authorization,
					},
				); err != nil {
					t.Fatal(err)
				}
			}
			if state == "running" {
				role := fixture.execution.Roles[0]
				if _, _, err := fixture.store.AcquireReadyStep(
					fixture.ctx,
					fixture.scope,
					task.AcquireReadyStepCommand{
						IdempotencyKey: uuid.NewString(),
						DeploymentID:   role.DeploymentID,
						TaskID:         fixture.task.TaskID,
						StepID:         role.TaskStepID,
						WorkerID:       role.ExpectedWorkerID,
						ExecutorKind:   task.ExecutorCloudWorker,
						LeaseDuration:  time.Minute,
					},
				); err != nil {
					t.Fatal(err)
				}
			}

			current, err := fixture.store.Get(
				fixture.ctx,
				fixture.task.TaskID,
			)
			if err != nil {
				t.Fatal(err)
			}
			cancelKey := uuid.NewString()
			canceled, err := fixture.store.Cancel(
				fixture.ctx,
				fixture.scope,
				task.CancelCommand{
					IdempotencyKey:   cancelKey,
					TaskID:           current.TaskID,
					ExpectedRevision: current.Revision,
					Reason:           "owner canceled approved Team execution",
				},
			)
			if err != nil ||
				canceled.ExecutionStatus != task.ExecutionFinished ||
				canceled.OutcomeStatus != task.OutcomeCanceled {
				t.Fatalf("canceled Task=%#v error=%v", canceled, err)
			}
			replayed, err := fixture.store.Cancel(
				fixture.ctx,
				fixture.scope,
				task.CancelCommand{
					IdempotencyKey:   cancelKey,
					TaskID:           current.TaskID,
					ExpectedRevision: current.Revision,
					Reason:           "owner canceled approved Team execution",
				},
			)
			if err != nil || replayed.Revision != canceled.Revision {
				t.Fatalf("cancel replay=%#v error=%v", replayed, err)
			}
			plan, err := fixture.store.GetTeamPlan(
				fixture.ctx,
				fixture.ownerID,
				fixture.plan.PlanID,
				fixture.plan.Revision,
			)
			if err != nil || plan.Status != postgres.TeamPlanCanceled {
				t.Fatalf("canceled Team Plan=%#v error=%v", plan, err)
			}
			if state != "approved" {
				execution, err := fixture.store.GetTeamExecution(
					fixture.ctx,
					fixture.ownerID,
					fixture.execution.ExecutionID,
				)
				if err != nil ||
					execution.Status != teamexecution.StatusCanceled {
					t.Fatalf(
						"canceled Team execution=%#v error=%v",
						execution,
						err,
					)
				}
			}
			var activePlans, activeExecutions int
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT
				    (SELECT count(*)
				     FROM team_plans
				     WHERE task_id=$1
				       AND status IN (
				           'ready_for_confirmation',
				           'approved',
				           'executing'
				       )),
				    (SELECT count(*)
				     FROM team_executions
				     WHERE task_id=$1
				       AND status IN (
				           'materialized',
				           'dispatching',
				           'running',
				           'verifying'
				       ))`,
				fixture.task.TaskID,
			).Scan(&activePlans, &activeExecutions); err != nil {
				t.Fatal(err)
			}
			if activePlans != 0 || activeExecutions != 0 {
				t.Fatalf(
					"active state remained plans=%d executions=%d",
					activePlans,
					activeExecutions,
				)
			}
		})
	}
}

type teamCancellationFixture struct {
	ctx           context.Context
	pool          *pgxpool.Pool
	store         *postgres.Store
	scope         task.MutationScope
	ownerID       string
	task          task.Task
	plan          teamplan.Plan
	authorization teamorchestration.ApprovedPlanFact
	execution     teamexecution.ExecutionV1
}

func newTeamCancellationFixture(
	t *testing.T,
	materialize bool,
) teamCancellationFixture {
	t.Helper()
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	scope := task.MutationScope{
		ClientID:     "team-execution-cancel-test",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-team-execution-cancel"
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
	goal := "Cancel this approved Team execution consistently."
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
	snapshot := teamOfferSnapshotFixture(t, connectionID, now.Add(-time.Minute))
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
	seed := sha256.Sum256([]byte("Team execution cancellation device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signerKeyID := "team-execution-cancel-device"
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
				PublicKey:       privateKey.Public().(ed25519.PublicKey),
				NotBefore:       now.Add(-time.Hour),
				ExpiresAt:       now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	challenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		scope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     plan.PlanID,
			PlanRevision:               plan.Revision,
			ExpectedPlanRecordRevision: planRecord.RecordRevision,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	approvedPlan, err := store.ApproveTeamPlan(
		ctx,
		scope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      planRecord.RecordRevision,
			ExpectedChallengeRecordRevision: challenge.RecordRevision,
			Signature: signTeamApproval(
				t,
				challenge.Challenge,
				privateKey,
			),
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
			Signature:  approval.Signature,
			ApprovedAt: approval.ApprovedAt,
			CreatedAt:  approval.CreatedAt,
		},
	}
	execution, err := teamexecution.Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if materialize {
		if _, err := store.PersistExecution(
			ctx,
			scope,
			teamexecution.PersistCommand{
				IdempotencyKey: uuid.NewString(),
				Authorization:  authorization,
				Execution:      execution,
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	return teamCancellationFixture{
		ctx:           ctx,
		pool:          pool,
		store:         store,
		scope:         scope,
		ownerID:       ownerID,
		task:          createdTask,
		plan:          plan,
		authorization: authorization,
		execution:     execution,
	}
}
