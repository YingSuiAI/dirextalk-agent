package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type pgCloudWorkerHarness struct {
	ctx           context.Context
	store         *Store
	cloud         *CloudWorkerStore
	tasks         *CoreTaskStore
	confirmations *CoreConfirmationStore
	confirmation  *coreconfirmation.Service
	conversation  *CoreConversationStore
	service       *cloudworker.Service
	lease         core.TurnLease
	command       cloudworker.ProposeCommand
	now           time.Time
	owner         string
	generation    uint64
	cleanup       func()
}

func pgCloudDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func pgCloudDefaults() cloudworker.Defaults {
	return cloudworker.Defaults{
		AWS: cloudworker.AWSBinding{AccountID: "123456789012", Region: "us-east-1",
			CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("pg-cloud-credential")).String(), CredentialRevision: 3},
		Compute: cloudworker.ComputeSpec{InstanceType: "c7i.large", Architecture: "x86_64", RootDeviceName: "/dev/xvda",
			VolumeGiB: 32, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
			AMIID: "ami-0123456789abcdef0", AMIDigest: pgCloudDigest("ami"), WorkerReleaseDigest: pgCloudDigest("worker"),
			PiRuntimeDigest: pgCloudDigest("pi"), HostNetworkPolicySHA256: pgCloudDigest("host-network")},
		Placement: cloudworker.PlacementSpec{VPCID: "vpc-01234567", SubnetID: "subnet-01234567"},
		NetworkPolicy: cloudworker.NetworkPolicy{
			DNSResolverCIDRs: []string{"10.0.0.2/32"}, TLSProxyCIDRs: []string{"10.0.0.3/32"},
			AllowedFQDNs:     []string{"relay.example.test", "worker.example.test"},
			OutboundProxyURL: "https://proxy.example.test:443", OutboundProxyServerName: "proxy.example.test",
			OutboundProxyTrustBundleSHA256: pgCloudDigest("proxy-ca"),
		},
		ArtifactBucket: "dirextalk-worker-artifacts", ArtifactBasePrefix: "executions/",
		ArtifactKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		ArtifactVersioned: true,
		WorkerBootstrap: cloudworker.WorkerBootstrap{Protocol: cloudworker.WorkerControlProtocolV1,
			Endpoint: "https://worker.example.test:8443", TLSServerName: "worker.example.test", TrustBundleDigest: pgCloudDigest("worker-ca")},
		ModelRelay:               cloudworker.ModelRelayBinding{Endpoint: "https://relay.example.test/v1", TLSServerName: "relay.example.test", TrustBundleDigest: pgCloudDigest("relay-ca")},
		Limits:                   cloudworker.Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20},
		ArtifactRetentionSeconds: 3600, QuoteAmountMicros: 1000, MaximumAuthorizedMicros: 2000, QuoteTTL: time.Hour,
	}
}

func newPGCloudWorkerHarness(t *testing.T) *pgCloudWorkerHarness {
	t.Helper()
	ctx, store, profileID, cleanup := corePG18Fixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	conversation, err := NewCoreConversationStore(store)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	owner, generation := "@cloud-owner:example.test", uint64(7)
	snapshot := coremodel.ExecutionSnapshot{ProfileID: profileID, Revision: 1, CredentialVersion: 1,
		Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://example.invalid", Model: "test", APIKey: "test", ContextWindow: 32768}
	conversationID := uuid.NewString()
	turn, err := conversation.StartTurn(ctx, core.TurnStartCommand{RequestID: uuid.NewString(), OwnerID: owner,
		AccountGeneration: generation, ConversationID: conversationID, Prompt: "Run this heavy task on AWS.",
		ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1, ProfileSnapshot: snapshot})
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	lease, err := conversation.ClaimTurn(ctx, turn.ID, now, 30*time.Minute)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	cloudStore := NewCloudWorkerStore(store)
	defaults := pgCloudDefaults()
	credential := coreaws.RehydrateCredentialsWithTestedAt(
		defaults.AWS.CredentialID, "cloud-worker-test", defaults.AWS.Region,
		defaults.AWS.AccountID, "arn:aws:iam::123456789012:user/cloud-worker-test",
		[]byte("AKIATESTOUTPUTJOURNAL"), []byte("test-secret-access-key"), nil,
		int64(defaults.AWS.CredentialRevision), int64(defaults.AWS.CredentialRevision), now, now, now,
	)
	if _, err = NewCoreAWSStore(store).CreateCredential(ctx, credential); err != nil {
		cleanup()
		t.Fatal(err)
	}
	quoter := cloudworker.FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: time.Hour,
		Now: func() time.Time { return now }}
	service, err := cloudworker.NewService(cloudStore, defaults, quoter, func() time.Time { return now })
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	authorization := cloudworker.ModelAuthorization{ModelProfileID: profileID, ModelProfileRevision: 1,
		Provider: "openai_compatible", Model: "test", Interface: "openai_compatible", CredentialVersion: 1,
		CredentialBindingDigest: pgCloudDigest("credential-binding")}
	if err = authorization.Seal(); err != nil {
		cleanup()
		t.Fatal(err)
	}
	confirmationStore := NewCoreConfirmationStore(store)
	confirmationService, err := coreconfirmation.NewService(confirmationStore, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	command := cloudworker.ProposeCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: uuid.NewString(),
		ConversationID: conversationID, TurnID: turn.ID, TurnLeaseID: lease.LeaseID, TurnLeaseEpoch: lease.Epoch,
		ExpectedTurnRevision: lease.Turn.Revision, Objective: "Produce a verified cloud result",
		ObjectiveSummary: "Verified cloud result", UserPromptDigest: pgCloudDigest(lease.Turn.Prompt),
		ProposalReason: cloudworker.ProposalReasonExplicitUserCloud, InputManifest: cloudworker.InputManifest{},
		WorkspaceMode: cloudworker.WorkspaceNone, ModelAuthorization: authorization}
	return &pgCloudWorkerHarness{ctx: ctx, store: store, cloud: cloudStore, tasks: NewCoreTaskStore(store),
		confirmations: confirmationStore, confirmation: confirmationService, conversation: conversation,
		service: service, lease: lease, command: command, now: now, owner: owner, generation: generation, cleanup: cleanup}
}

func (h *pgCloudWorkerHarness) propose(t *testing.T) cloudworker.Offer {
	t.Helper()
	offer, err := h.service.Propose(h.ctx, h.command)
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

func TestCloudWorkerPostgresCreateOfferAtomicRollbackAndReplay(t *testing.T) {
	t.Run("late failure rolls back every projection", func(t *testing.T) {
		h := newPGCloudWorkerHarness(t)
		defer h.cleanup()
		if _, err := h.store.pool.Exec(h.ctx, `CREATE FUNCTION reject_cloud_offer_outbox() RETURNS trigger
			LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced late offer failure'; END $$;
			CREATE TRIGGER reject_cloud_offer_outbox BEFORE INSERT ON core_cloud_worker_offer_outbox
			FOR EACH ROW EXECUTE FUNCTION reject_cloud_offer_outbox()`); err != nil {
			t.Fatal(err)
		}
		if _, err := h.service.Propose(h.ctx, h.command); err == nil {
			t.Fatal("forced late CreateOffer failure unexpectedly committed")
		}
		var plans, tasks, confirmations, messages, offerEvents int
		if err := h.store.pool.QueryRow(h.ctx, `SELECT
			(SELECT count(*) FROM core_cloud_worker_plans WHERE turn_id=$1),
			(SELECT count(*) FROM core_tasks WHERE task_kind='cloud_worker'),
			(SELECT count(*) FROM core_confirmations WHERE operation_domain=$2),
			(SELECT count(*) FROM core_messages WHERE conversation_id=$3),
			(SELECT count(*) FROM core_cloud_worker_offer_outbox)`, h.lease.Turn.ID, cloudworker.OperationDomain,
			h.command.ConversationID).Scan(&plans, &tasks, &confirmations, &messages, &offerEvents); err != nil {
			t.Fatal(err)
		}
		if plans+tasks+confirmations+messages+offerEvents != 0 {
			t.Fatalf("partial CreateOffer commit plans=%d tasks=%d confirmations=%d messages=%d outbox=%d",
				plans, tasks, confirmations, messages, offerEvents)
		}
		turn, err := h.conversation.GetTurn(h.ctx, h.lease.Turn.ID)
		if err != nil || turn.State != core.TurnRunning || turn.Revision != h.lease.Turn.Revision {
			t.Fatalf("turn changed after rollback: %+v err=%v", turn, err)
		}
	})

	t.Run("exact replay and changed payload conflict", func(t *testing.T) {
		h := newPGCloudWorkerHarness(t)
		defer h.cleanup()
		first := h.propose(t)
		replayed, err := h.service.Propose(h.ctx, h.command)
		if err != nil || replayed.Plan.PlanID != first.Plan.PlanID || replayed.Execution.ExecutionID != first.Execution.ExecutionID {
			t.Fatalf("offer replay=%+v err=%v", replayed, err)
		}
		changed := h.command
		changed.Objective = "different authorized objective"
		if _, err = h.service.Propose(h.ctx, changed); !errors.Is(err, cloudworker.ErrConflict) {
			t.Fatalf("changed offer replay err=%v", err)
		}
		var taskCount, confirmationCount, planCount, executionCount, outboxCount int
		if err = h.store.pool.QueryRow(h.ctx, `SELECT
			(SELECT count(*) FROM core_tasks WHERE task_kind='cloud_worker'),
			(SELECT count(*) FROM core_confirmations WHERE operation_domain=$1),
			(SELECT count(*) FROM core_cloud_worker_plans),
			(SELECT count(*) FROM core_cloud_worker_executions),
			(SELECT count(*) FROM core_cloud_worker_offer_outbox)`, cloudworker.OperationDomain).Scan(
			&taskCount, &confirmationCount, &planCount, &executionCount, &outboxCount); err != nil {
			t.Fatal(err)
		}
		if taskCount != 1 || confirmationCount != 1 || planCount != 1 || executionCount != 1 || outboxCount != 1 {
			t.Fatalf("non-idempotent offer graph task=%d confirmation=%d plan=%d execution=%d outbox=%d",
				taskCount, confirmationCount, planCount, executionCount, outboxCount)
		}
	})
}

func TestCloudWorkerPostgresConfirmationAndPredispatchCancelProjection(t *testing.T) {
	t.Run("confirm queues the real task and execution", func(t *testing.T) {
		h := newPGCloudWorkerHarness(t)
		defer h.cleanup()
		offer := h.propose(t)
		confirmed, err := h.confirmation.Confirm(h.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: offer.Confirmation.ConfirmationID,
			IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now.Add(time.Second)})
		if err != nil || confirmed.State != coreconfirmation.StateConfirmed {
			t.Fatalf("confirmed=%+v err=%v", confirmed, err)
		}
		var taskStatus, executionState, turnState string
		if err = h.store.pool.QueryRow(h.ctx, `SELECT t.status,e.state,u.state FROM core_tasks t
			JOIN core_cloud_worker_executions e ON e.task_id=t.task_id
			JOIN core_conversation_turns u ON u.turn_id=e.turn_id WHERE t.task_id=$1`, offer.Task.ID).Scan(
			&taskStatus, &executionState, &turnState); err != nil {
			t.Fatal(err)
		}
		if taskStatus != "queued" || executionState != string(cloudworker.StateQueued) || turnState != string(core.TurnWaitingConfirmation) {
			t.Fatalf("task=%s execution=%s turn=%s", taskStatus, executionState, turnState)
		}
	})

	for name, test := range map[string]struct {
		mutate           func(*pgCloudWorkerHarness, cloudworker.Offer) error
		wantConfirmation string
		wantExecution    cloudworker.ExecutionState
		wantTask         string
		wantTurn         core.TurnState
	}{
		"reject": {mutate: func(h *pgCloudWorkerHarness, offer cloudworker.Offer) error {
			_, err := h.confirmation.Reject(h.ctx, coreconfirmation.RejectCommand{ConfirmationID: offer.Confirmation.ConfirmationID,
				IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, Reason: "not authorized", At: h.now.Add(time.Second)})
			return err
		}, wantConfirmation: "rejected", wantExecution: cloudworker.StateRejected, wantTask: "canceled", wantTurn: core.TurnCanceled},
		"expire": {mutate: func(h *pgCloudWorkerHarness, offer cloudworker.Offer) error {
			_, err := h.confirmation.Expire(h.ctx, coreconfirmation.ExpireCommand{ConfirmationID: offer.Confirmation.ConfirmationID,
				IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, Reason: coreconfirmation.ReasonExpired,
				At: h.now.Add(time.Second)})
			return err
		}, wantConfirmation: "expired", wantExecution: cloudworker.StateExpired, wantTask: "failed", wantTurn: core.TurnFailed},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPGCloudWorkerHarness(t)
			defer h.cleanup()
			offer := h.propose(t)
			if err := test.mutate(h, offer); err != nil {
				t.Fatal(err)
			}
			var confirmationState, executionState, taskStatus, turnState string
			var providerStarted bool
			var resourceCount, ledgerCount, terminalMessages int
			if err := h.store.pool.QueryRow(h.ctx, `SELECT c.state,e.state,t.status,u.state,e.provider_mutation_started,
				(SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=e.execution_id),
				(SELECT count(*) FROM core_cloud_worker_aws_ledger WHERE execution_id=e.execution_id),
				(SELECT count(*) FROM core_messages WHERE conversation_id=e.conversation_id)
				FROM core_cloud_worker_executions e JOIN core_confirmations c ON c.confirmation_id=e.confirmation_id
				JOIN core_tasks t ON t.task_id=e.task_id JOIN core_conversation_turns u ON u.turn_id=e.turn_id
				WHERE e.execution_id=$1`, offer.Execution.ExecutionID).Scan(&confirmationState, &executionState, &taskStatus,
				&turnState, &providerStarted, &resourceCount, &ledgerCount, &terminalMessages); err != nil {
				t.Fatal(err)
			}
			if confirmationState != test.wantConfirmation || executionState != string(test.wantExecution) || taskStatus != test.wantTask ||
				turnState != string(test.wantTurn) || providerStarted || resourceCount != 0 || ledgerCount != 0 || terminalMessages != 3 {
				t.Fatalf("confirmation=%s execution=%s task=%s turn=%s provider=%t resources=%d ledger=%d messages=%d",
					confirmationState, executionState, taskStatus, turnState, providerStarted, resourceCount, ledgerCount, terminalMessages)
			}
		})
	}

	for _, confirmed := range []bool{false, true} {
		name := "waiting_user"
		if confirmed {
			name = "queued"
		}
		t.Run("cancel "+name+" is controller-terminalized and idempotent", func(t *testing.T) {
			h := newPGCloudWorkerHarness(t)
			defer h.cleanup()
			offer := h.propose(t)
			current := offer.Execution
			if confirmed {
				if _, err := h.confirmation.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
					ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
					ExpectedRevision: offer.Confirmation.Revision, At: h.now.Add(time.Second),
				}); err != nil {
					t.Fatal(err)
				}
				var err error
				current, err = h.cloud.GetExecutionForAuthority(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID)
				if err != nil || current.State != cloudworker.StateQueued {
					t.Fatalf("confirmed execution=%+v err=%v", current, err)
				}
			}
			key := uuid.NewString()
			requested, err := h.cloud.RequestCancel(h.ctx, h.owner, h.generation, current.ExecutionID, current.Revision, key)
			if err != nil || requested.State != cloudworker.StateQueued || requested.TerminalIntent != string(cloudworker.StateCanceled) {
				t.Fatalf("cancel request=%+v err=%v", requested, err)
			}
			replayed, err := h.cloud.RequestCancel(h.ctx, h.owner, h.generation, current.ExecutionID, current.Revision, key)
			if err != nil || replayed.Revision != requested.Revision {
				t.Fatalf("cancel request replay=%+v err=%v", replayed, err)
			}
			var confirmationState, taskStatus, turnState string
			var completionCount int
			if err = h.store.pool.QueryRow(h.ctx, `SELECT c.state,t.status,u.state,
				(SELECT count(*) FROM core_cloud_worker_completion_outbox WHERE execution_id=e.execution_id)
				FROM core_cloud_worker_executions e JOIN core_confirmations c ON c.confirmation_id=e.confirmation_id
				JOIN core_tasks t ON t.task_id=e.task_id JOIN core_conversation_turns u ON u.turn_id=e.turn_id
				WHERE e.execution_id=$1`, current.ExecutionID).Scan(&confirmationState, &taskStatus, &turnState, &completionCount); err != nil {
				t.Fatal(err)
			}
			if confirmationState != "expired" || taskStatus != "queued" || turnState != string(core.TurnWaitingConfirmation) || completionCount != 0 {
				t.Fatalf("pre-controller confirmation=%s task=%s turn=%s outbox=%d", confirmationState, taskStatus, turnState, completionCount)
			}

			task, _, err := h.tasks.ClaimNextDue(h.ctx, uuid.NewString(), h.now.Add(2*time.Second), 30*time.Minute, 4)
			if err != nil || task.ID != offer.Task.ID {
				t.Fatalf("claim cancellation task=%+v err=%v", task, err)
			}
			cleaning, err := h.cloud.BeginCleanup(h.ctx, task, requested.Revision, cloudworker.StateCanceled,
				"user_canceled", "Cloud Worker task canceled")
			if err != nil || cleaning.State != cloudworker.StateCleaning {
				t.Fatalf("begin cancel cleanup=%+v err=%v", cleaning, err)
			}
			terminal, outbox, err := h.cloud.CancelExecution(h.ctx, task, cleaning.Revision,
				"user_canceled", "Cloud Worker task canceled")
			if err != nil || terminal.State != cloudworker.StateCanceled || outbox.ExecutionID != current.ExecutionID {
				t.Fatalf("cancel terminal=%+v outbox=%+v err=%v", terminal, outbox, err)
			}
			canceledTask, err := h.tasks.GetTask(h.ctx, offer.Task.ID)
			if err != nil || canceledTask.Status != coretask.StatusCanceled || canceledTask.Result != nil ||
				canceledTask.FailureCode != "user_canceled" || canceledTask.FailureSummary != "Cloud Worker task canceled" {
				t.Fatalf("canceled task terminal contract mismatch: task=%+v err=%v", canceledTask, err)
			}
			replayed, err = h.cloud.RequestCancel(h.ctx, h.owner, h.generation, current.ExecutionID, current.Revision, key)
			if err != nil || replayed.State != cloudworker.StateCanceled || replayed.Revision != terminal.Revision {
				t.Fatalf("terminal cancel replay=%+v err=%v", replayed, err)
			}

			var beginCount, launchCount, ledgerCount, resourceCount, resultMessages int
			if err = h.store.pool.QueryRow(h.ctx, `SELECT
				(SELECT count(*) FROM core_cloud_worker_begin_authorizations WHERE execution_id=$1),
				(SELECT count(*) FROM core_cloud_worker_launch_material WHERE execution_id=$1),
				(SELECT count(*) FROM core_cloud_worker_aws_ledger WHERE execution_id=$1),
				(SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=$1),
				(SELECT count(*) FROM core_messages WHERE message_id=$2)`, current.ExecutionID, outbox.ResultMessageID).Scan(
				&beginCount, &launchCount, &ledgerCount, &resourceCount, &resultMessages); err != nil {
				t.Fatal(err)
			}
			if beginCount+launchCount+ledgerCount+resourceCount != 0 || resultMessages != 1 {
				t.Fatalf("cancel graph begin=%d launch=%d ledger=%d resources=%d result_messages=%d",
					beginCount, launchCount, ledgerCount, resourceCount, resultMessages)
			}
		})
	}
}

func preparePGCloudLaunch(t *testing.T, h *pgCloudWorkerHarness) (cloudworker.Offer, coretask.Task, cloudworker.BeginResult, cloudworker.RuntimeTaskMaterial) {
	t.Helper()
	offer := h.propose(t)
	if _, err := h.confirmation.Confirm(h.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: offer.Confirmation.ConfirmationID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision,
		At: time.Now().UTC().Truncate(time.Microsecond)}); err != nil {
		t.Fatal(err)
	}
	task, _, err := h.tasks.ClaimNextDue(h.ctx, uuid.NewString(), h.now.Add(2*time.Second), 30*time.Minute, 4)
	if err != nil || task.ID != offer.Task.ID {
		t.Fatalf("claim task=%+v err=%v", task, err)
	}
	begin, err := h.cloud.BeginExecution(h.ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	staged := cloudworker.StagedInputManifest{ExecutionID: begin.Plan.ExecutionID}
	qualification := cloudworker.RuntimeQualification{PiRuntimeDigest: begin.Plan.Compute.PiRuntimeDigest, PiVersion: "pi-pg-test",
		PiExecutableSHA256: pgCloudDigest("pi-executable"), ResultExtensionSHA256: pgCloudDigest("result-extension")}
	fence := cloudworker.RuntimeTaskFence{ExecutionID: begin.Plan.ExecutionID, TaskID: begin.Plan.TaskID,
		AccountGeneration: begin.Plan.AccountGeneration, Attempt: begin.Prerequisite.TaskAttempt, LeaseEpoch: begin.Prerequisite.LeaseEpoch}
	material, err := cloudworker.BuildRuntimeTask(begin.Plan, begin.Execution, staged, fence, qualification)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.cloud.AuthorizeLaunch(h.ctx, cloudworker.AuthorizeLaunchCommand{Task: task,
		ExpectedExecutionRevision: begin.Execution.Revision, StagedManifest: staged, Qualification: qualification, Material: material}); err != nil {
		material.Destroy()
		t.Fatal(err)
	}
	return offer, task, begin, material
}

func TestCloudWorkerPostgresExpiredDomainDeadlineReclaimsLease(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	if _, err := h.confirmation.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: offer.Confirmation.Revision, At: h.now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	first, _, err := h.tasks.ClaimNextDue(h.ctx, uuid.NewString(), h.now.Add(2*time.Second), time.Minute, 4)
	if err != nil || first.ID != offer.Task.ID || first.ExecutionDeadlineAt == nil {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	expiredAt := h.now.Add(3 * time.Second)
	if _, err = h.store.pool.Exec(h.ctx, `UPDATE core_tasks SET lease_expires_at=$2,execution_deadline_at=$2
		WHERE task_id=$1 AND status='running'`, first.ID, expiredAt); err != nil {
		t.Fatal(err)
	}
	reclaimed, _, err := h.tasks.ClaimNextDue(h.ctx, uuid.NewString(), expiredAt.Add(time.Second), time.Minute, 4)
	if err != nil || reclaimed.ID != first.ID || reclaimed.Status != coretask.StatusRunning ||
		reclaimed.Attempt != first.Attempt || reclaimed.LeaseEpoch != first.LeaseEpoch+1 || reclaimed.FailureCode != "" {
		t.Fatalf("deadline reclaim=%+v first=%+v err=%v", reclaimed, first, err)
	}
	var timeoutEvents int
	if err = h.store.pool.QueryRow(h.ctx, `SELECT count(*) FROM core_task_events
		WHERE task_id=$1 AND error_code='task_timed_out'`, first.ID).Scan(&timeoutEvents); err != nil {
		t.Fatal(err)
	}
	if timeoutEvents != 0 {
		t.Fatalf("Cloud Worker was terminalized by generic deadline: events=%d", timeoutEvents)
	}
}

func TestCloudWorkerPostgresCancelAfterPreparedIntentRequiresLedgerCleanup(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer, task, _, material := preparePGCloudLaunch(t, h)
	defer material.Destroy()

	resume, err := h.cloud.GetResumeContext(h.ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	awsPlan, intent, err := cloudworker.BuildAWSDispatch(resume.Plan, resume.Execution, resume.InitialAuthorization,
		resume.StagedManifest, resume.Material, resume.Plan.Quote, h.now.Add(4*time.Minute))
	if err != nil {
		resume.Destroy()
		t.Fatal(err)
	}
	ledger, err := cloudaws.NewPostgresLedger(h.store.pool)
	if err != nil {
		resume.Destroy()
		t.Fatal(err)
	}
	record, err := cloudaws.NewLedgerRecord(awsPlan, intent, h.now.Add(4*time.Minute))
	if err != nil {
		resume.Destroy()
		t.Fatal(err)
	}
	if record, err = ledger.CreateIntent(h.ctx, record); err != nil {
		resume.Destroy()
		t.Fatal(err)
	}
	expectedRevision := resume.Execution.Revision
	resume.Destroy()

	requested, err := h.cloud.RequestCancel(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID,
		expectedRevision, uuid.NewString())
	if err != nil || requested.TerminalIntent != string(cloudworker.StateCanceled) || requested.ProviderMutationStarted {
		t.Fatalf("prepared-intent cancel=%+v err=%v", requested, err)
	}
	cancelResume, err := h.cloud.GetResumeContext(h.ctx, task)
	if err != nil || cancelResume.AWSRecord.Revision != record.Revision || cancelResume.DispatchPrepared ||
		!cancelResume.AWSRecord.Identity.Equal(record.Identity) {
		t.Fatalf("cancel resume=%+v err=%v", cancelResume, err)
	}
	cancelResume.Destroy()

	// Provider.Prepare is mutation-free, but its durable ledger must still be
	// reconciled to verified_destroyed before the controller may terminalize.
	record = destroyPGCloudLedger(t, h.ctx, ledger, record, h.now.Add(5*time.Minute))
	cleaning, err := h.cloud.BeginCleanup(h.ctx, task, requested.Revision, cloudworker.StateCanceled,
		"user_canceled", "Cloud Worker task canceled")
	if err != nil {
		t.Fatal(err)
	}
	terminal, outbox, err := h.cloud.CancelExecution(h.ctx, task, cleaning.Revision,
		"user_canceled", "Cloud Worker task canceled")
	if err != nil || terminal.State != cloudworker.StateCanceled || outbox.ExecutionID != offer.Execution.ExecutionID {
		t.Fatalf("terminal=%+v outbox=%+v err=%v", terminal, outbox, err)
	}
	var state string
	if err = h.store.pool.QueryRow(h.ctx, `SELECT state FROM core_cloud_worker_aws_ledger WHERE execution_id=$1`,
		offer.Execution.ExecutionID).Scan(&state); err != nil || state != string(cloudaws.LifecycleVerifiedDestroyed) {
		t.Fatalf("ledger state=%s err=%v", state, err)
	}
}

func TestCloudWorkerPostgresResumeControlCleanupAndTerminalOutbox(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer, firstTask, _, material := preparePGCloudLaunch(t, h)
	defer material.Destroy()

	beforePrepare, err := h.cloud.GetResumeContext(h.ctx, firstTask)
	if err != nil {
		t.Fatal(err)
	}
	if beforePrepare.DispatchPrepared || beforePrepare.AWSRecord.Revision != 0 || len(beforePrepare.Resources) != 0 {
		t.Fatalf("unexpected pre-Prepare resume: prepared=%t ledger_revision=%d resources=%d",
			beforePrepare.DispatchPrepared, beforePrepare.AWSRecord.Revision, len(beforePrepare.Resources))
	}
	beforePrepare.Destroy()

	// Reclaim the real CoreTask after AuthorizeLaunch. The original launch
	// material remains on epoch 1 while the controller/Worker fence rotates.
	if _, err = h.store.pool.Exec(h.ctx, `UPDATE core_tasks SET lease_expires_at=$2 WHERE task_id=$1`, firstTask.ID, h.now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	reclaimed, _, err := h.tasks.ClaimNextDue(h.ctx, uuid.NewString(), h.now.Add(3*time.Minute), 30*time.Minute, 4)
	if err != nil || reclaimed.ID != firstTask.ID || reclaimed.LeaseEpoch == firstTask.LeaseEpoch {
		t.Fatalf("reclaimed=%+v first=%+v err=%v", reclaimed, firstTask, err)
	}
	if _, err = h.cloud.GetResumeContext(h.ctx, firstTask); !errors.Is(err, cloudworker.ErrLeaseConflict) {
		t.Fatalf("stale first fence resumed: %v", err)
	}
	resumed, err := h.cloud.GetResumeContext(h.ctx, reclaimed)
	if err != nil || resumed.DispatchPrepared || resumed.Material.RuntimeTaskSHA256 != material.RuntimeTaskSHA256 ||
		resumed.CurrentFence.LeaseEpoch != reclaimed.LeaseEpoch || resumed.Material.Fence.LeaseEpoch == reclaimed.LeaseEpoch {
		t.Fatalf("resume=%+v err=%v", resumed, err)
	}

	awsPlan, intent, err := cloudworker.BuildAWSDispatch(resumed.Plan, resumed.Execution, resumed.InitialAuthorization,
		resumed.StagedManifest, resumed.Material, resumed.Plan.Quote, h.now.Add(4*time.Minute))
	if err != nil {
		resumed.Destroy()
		t.Fatal(err)
	}
	ledger, err := cloudaws.NewPostgresLedger(h.store.pool)
	if err != nil {
		resumed.Destroy()
		t.Fatal(err)
	}
	record, err := cloudaws.NewLedgerRecord(awsPlan, intent, h.now.Add(4*time.Minute))
	if err != nil {
		resumed.Destroy()
		t.Fatal(err)
	}
	if record, err = ledger.CreateIntent(h.ctx, record); err != nil {
		resumed.Destroy()
		t.Fatal(err)
	}
	resumed.Destroy()

	preparedNotMarked, err := h.cloud.GetResumeContext(h.ctx, reclaimed)
	if err != nil || preparedNotMarked.DispatchPrepared || preparedNotMarked.AWSRecord.Revision != 1 ||
		!preparedNotMarked.AWSRecord.Identity.Equal(record.Identity) {
		t.Fatalf("Prepare/Mark crash resume=%+v err=%v", preparedNotMarked, err)
	}
	preparedNotMarked.Destroy()
	execution, err := h.cloud.MarkDispatchPrepared(h.ctx, reclaimed, offer.Execution.Revision+2, record.Identity, record.Intent.IntentDigest)
	if err != nil || !execution.ProviderMutationStarted {
		t.Fatalf("mark prepared execution=%+v err=%v", execution, err)
	}
	afterMark, err := h.cloud.GetResumeContext(h.ctx, reclaimed)
	if err != nil || !afterMark.DispatchPrepared || !afterMark.AWSRecord.Identity.Equal(record.Identity) || len(afterMark.Resources) != 0 {
		t.Fatalf("marked resume=%+v err=%v", afterMark, err)
	}
	afterMark.Destroy()

	// Pre-worker fencing is a safe no-op: there is no expectation/session FK
	// target yet, so this must not invent a session fence row.
	controlStore := NewCloudWorkerControlStore(h.store)
	if empty, fenceErr := controlStore.FenceExecutionSessions(h.ctx, reclaimed, offer.Execution.ExecutionID, "pre-worker check"); fenceErr != nil || empty.SessionID != "" {
		t.Fatalf("empty pre-worker fence=%+v err=%v", empty, fenceErr)
	}

	record = activatePGCloudLedger(t, h.ctx, ledger, record, h.now.Add(5*time.Minute))
	resources := pgCloudResources(record, h.now.Add(5*time.Minute), cloudworker.ResourceCreated, 1)
	execution, err = h.cloud.RecordResources(h.ctx, reclaimed, execution.Revision, resources, cloudworker.StateAwaitingWorker)
	if err != nil || execution.Cleanup.ResourcesTotal != uint64(len(cloudaws.AllResourceKinds())) {
		t.Fatalf("record exact resources execution=%+v err=%v", execution, err)
	}

	expectation := pgCloudExpectation(record)
	if err = controlStore.SetLaunchExpectation(h.ctx, reclaimed, expectation); err != nil {
		t.Fatal(err)
	}
	fence := control.TaskFence{ExecutionID: offer.Execution.ExecutionID, TaskID: reclaimed.ID,
		AccountGeneration: h.generation, Attempt: reclaimed.Attempt, LeaseEpoch: reclaimed.LeaseEpoch}
	firstSession := claimPGCloudSession(t, h.ctx, controlStore, fence, expectation, "first")
	secondSession := claimPGCloudSession(t, h.ctx, controlStore, fence, expectation, "second")
	storedFirst, err := controlStore.GetSession(h.ctx, firstSession.SessionID)
	if err != nil || storedFirst.State != control.SessionFailed || storedFirst.FailureCode != "session_superseded" || secondSession.State != control.SessionActive {
		t.Fatalf("first=%+v second=%+v err=%v", storedFirst, secondSession, err)
	}
	if _, err = controlStore.FenceExecutionSessions(h.ctx, reclaimed, offer.Execution.ExecutionID, "terminal cleanup"); err != nil {
		t.Fatal(err)
	}
	if _, err = controlStore.Heartbeat(h.ctx, control.SessionMutation{SessionID: secondSession.SessionID,
		TokenDigest: sha256.Sum256([]byte("second-token")), Fence: fence, ProgressSequence: 1,
		IdempotencyKey: uuid.NewString(), RequestDigest: pgCloudDigest("stale-heartbeat"), At: h.now.Add(6 * time.Minute)}); !errors.Is(err, control.ErrTerminal) {
		t.Fatalf("fenced session heartbeat err=%v", err)
	}

	execution, err = h.cloud.BeginCleanup(h.ctx, reclaimed, execution.Revision, cloudworker.StateFailed, "worker_failed", "worker failed safely")
	if err != nil {
		t.Fatal(err)
	}
	partial := append([]cloudworker.Resource(nil), resources...)
	partialAt := h.now.Add(6*time.Minute + 30*time.Second)
	for index := range partial {
		partial[index].State = cloudworker.ResourceDeleteRequested
		partial[index].Revision++
		partial[index].UpdatedAt = partialAt
	}
	partial[0].State = cloudworker.ResourceVerifiedDestroyed
	partial[0].VerifiedAt = &partialAt
	if _, partialErr := h.cloud.RecordResources(h.ctx, reclaimed, execution.Revision, partial, cloudworker.StateCleaning); !errors.Is(partialErr, cloudworker.ErrConflict) {
		t.Fatalf("mixed public cleanup evidence accepted: %v", partialErr)
	}
	record = destroyPGCloudLedger(t, h.ctx, ledger, record, h.now.Add(7*time.Minute))
	destroyedAt := h.now.Add(7 * time.Minute)
	for index := range resources {
		resources[index].State = cloudworker.ResourceVerifiedDestroyed
		resources[index].Revision++
		resources[index].UpdatedAt = destroyedAt
		resources[index].VerifiedAt = &destroyedAt
	}
	execution, err = h.cloud.RecordResources(h.ctx, reclaimed, execution.Revision, resources, cloudworker.StateCleaning)
	if err != nil || !execution.Cleanup.VerifiedDestroyed {
		t.Fatalf("cleanup projection=%+v err=%v", execution, err)
	}
	terminal, outbox, err := h.cloud.FailExecution(h.ctx, reclaimed, execution.Revision, "worker_failed", "worker failed safely")
	if err != nil || terminal.State != cloudworker.StateFailed || outbox.ExecutionID != offer.Execution.ExecutionID {
		t.Fatalf("terminal=%+v outbox=%+v err=%v", terminal, outbox, err)
	}
	failedTask, err := h.tasks.GetTask(h.ctx, offer.Task.ID)
	if err != nil || failedTask.Status != coretask.StatusFailed || failedTask.Result != nil ||
		failedTask.FailureCode != "worker_failed" || failedTask.FailureSummary != "worker failed safely" {
		t.Fatalf("failed task terminal contract mismatch: task=%+v err=%v", failedTask, err)
	}
	replayedTerminal, replayedOutbox, err := h.cloud.FailExecution(h.ctx, reclaimed, execution.Revision, "worker_failed", "worker failed safely")
	if err != nil || replayedTerminal.Revision != terminal.Revision || replayedOutbox.EventID != outbox.EventID {
		t.Fatalf("lost-response replay terminal=%+v outbox=%+v err=%v", replayedTerminal, replayedOutbox, err)
	}
	var resultMessages, completionRows, activeReservations, runningCount int
	if err = h.store.pool.QueryRow(h.ctx, `SELECT
		(SELECT count(*) FROM core_messages WHERE message_id=$1),
		(SELECT count(*) FROM core_cloud_worker_completion_outbox WHERE execution_id=$2),
		(SELECT count(*) FROM core_confirmation_reservations WHERE confirmation_id=$3 AND active=true),
		(SELECT running_count FROM core_task_runtime_concurrency WHERE singleton=true)`, outbox.ResultMessageID,
		offer.Execution.ExecutionID, offer.Confirmation.ConfirmationID).Scan(&resultMessages, &completionRows, &activeReservations, &runningCount); err != nil {
		t.Fatal(err)
	}
	if resultMessages != 1 || completionRows != 1 || activeReservations != 0 || runningCount != 0 {
		t.Fatalf("terminal invariants message=%d outbox=%d reservation=%d running=%d",
			resultMessages, completionRows, activeReservations, runningCount)
	}
}

func activatePGCloudLedger(t *testing.T, ctx context.Context, ledger *cloudaws.PostgresLedger, record cloudaws.LedgerRecord, at time.Time) cloudaws.LedgerRecord {
	t.Helper()
	at = at.UTC()
	mutationStartedAt := record.Intent.RecordedAt.UTC()
	mutationLeaseUntil := mutationStartedAt.Add(30 * time.Second)
	if !mutationLeaseUntil.Before(record.Intent.Authorization.QuoteExpiresAt) {
		mutationLeaseUntil = record.Intent.Authorization.QuoteExpiresAt.Add(-time.Microsecond)
	}
	record.CreateMutation = cloudaws.MutationRecord{
		Token: record.Intent.ClientToken, StartedAt: mutationStartedAt, LeaseUntil: mutationLeaseUntil,
		DispatchedAt: mutationStartedAt, CompletedAt: at, AcceptedAt: at, Attempts: 1,
	}
	stackProviderID := "arn:aws:cloudformation:" + record.Identity.Region + ":" + record.Identity.AccountID +
		":stack/" + record.Intent.StackName + "/11111111-1111-4111-8111-111111111111"
	record.StackProviderID = stackProviderID
	record.StackCreationIdentity = cloudaws.StackCreationIdentity{
		StackID: stackProviderID, StackName: record.Intent.StackName, ClientRequestToken: record.Intent.ClientToken,
		CreationEventID: "event-create-pg-cloud-worker", CreationTime: mutationStartedAt, ObservedAt: at,
	}
	tags := cloudaws.RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest)
	for _, kind := range cloudaws.AllResourceKinds() {
		entry := record.Resources[kind]
		providerID := "resource-" + string(kind)
		switch kind {
		case cloudaws.ResourceEC2:
			providerID = "i-0123456789abcdef0"
		case cloudaws.ResourceEBS:
			providerID = "vol-0123456789abcdef0"
		case cloudaws.ResourceENI:
			providerID = "eni-0123456789abcdef0"
		case cloudaws.ResourceEIP:
			providerID = "eipalloc-0123456789abcdef0"
		case cloudaws.ResourceSecurityGroup:
			providerID = "sg-0123456789abcdef0"
		case cloudaws.ResourceIAMRole:
			providerID = "AROA1234567890ABCDEFG"
		case cloudaws.ResourceInstanceProfile:
			providerID = "AIPA1234567890ABCDEFG"
			entry.IdentityState = cloudaws.ResourceIdentityVerified
		case cloudaws.ResourceStack:
			providerID = stackProviderID
		}
		entry.ProviderID, entry.State = providerID, cloudaws.ResourceActive
		entry.Observation = cloudaws.ResourceObservation{Kind: kind, LogicalID: entry.LogicalID, ProviderID: providerID,
			Exists: true, Tags: tags, LaunchIdentity: record.Identity.LaunchIdentity,
			Generation: record.Identity.Generation, ObservedAt: at.UTC()}
		record.Resources[kind] = entry
	}
	record.State, record.Revision, record.UpdatedAt = cloudaws.LifecycleActive, record.Revision+1, at
	next, err := ledger.CompareAndSwap(ctx, record, record.Revision-1)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func destroyPGCloudLedger(t *testing.T, ctx context.Context, ledger *cloudaws.PostgresLedger, record cloudaws.LedgerRecord, at time.Time) cloudaws.LedgerRecord {
	t.Helper()
	at = at.UTC()
	for _, kind := range cloudaws.AllResourceKinds() {
		entry := record.Resources[kind]
		entry.State = cloudaws.ResourceVerifiedDestroyed
		record.Resources[kind] = entry
	}
	record.State, record.Revision, record.UpdatedAt = cloudaws.LifecycleVerifiedDestroyed, record.Revision+1, at
	if record.CleanupRequestedAt.IsZero() {
		record.CleanupRequestedAt = at
	}
	record.VerifiedDestroyedAt = record.UpdatedAt
	record.LastTombstoneAuditAt = record.UpdatedAt
	record.TombstoneAuditUntil = record.UpdatedAt.Add(24 * time.Hour)
	next, err := ledger.CompareAndSwap(ctx, record, record.Revision-1)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func pgCloudResources(record cloudaws.LedgerRecord, at time.Time, state cloudworker.ResourceState, revision uint64) []cloudworker.Resource {
	resources := make([]cloudworker.Resource, 0, len(cloudaws.AllResourceKinds()))
	for _, kind := range cloudaws.AllResourceKinds() {
		entry := record.Resources[kind]
		resources = append(resources, cloudworker.Resource{
			ResourceID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-aws-resource:"+record.Identity.ExecutionID+":"+string(kind))).String(),
			ExecutionID: record.Identity.ExecutionID, AccountGeneration: record.Identity.AccountGeneration,
			Provider: "aws", Kind: string(kind), ProviderID: entry.ProviderID, AccountID: record.Identity.AccountID,
			Region: record.Identity.Region, LaunchIdentity: record.Identity.LaunchIdentity, State: state,
			Revision: revision, CreatedAt: at.UTC(), UpdatedAt: at.UTC(),
		})
	}
	return resources
}

func pgCloudExpectation(record cloudaws.LedgerRecord) control.IdentityExpectation {
	return control.IdentityExpectation{OwnerID: record.Identity.OwnerID, AccountGeneration: record.Identity.AccountGeneration,
		AccountID: record.Identity.AccountID, Region: record.Identity.Region,
		InstanceID: record.Resources[cloudaws.ResourceEC2].ProviderID, LaunchIdentity: record.Identity.LaunchIdentity,
		RoleARN:           "arn:aws:iam::" + record.Identity.AccountID + ":role/" + record.Plan.IAMRoleName,
		RoleID:            record.Resources[cloudaws.ResourceIAMRole].ProviderID,
		InstanceProfileID: record.Resources[cloudaws.ResourceInstanceProfile].ProviderID,
		RequiredTags:      cloudaws.RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest)}
}

func claimPGCloudSession(t *testing.T, ctx context.Context, store *CloudWorkerControlStore, fence control.TaskFence, expectation control.IdentityExpectation, seed string) control.Session {
	t.Helper()
	nonce := sha256.Sum256([]byte(seed + "-nonce"))
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := control.ChallengeRecord{ChallengeID: uuid.NewString(), NonceDigest: nonce, Fence: fence,
		Expectation: expectation, ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if err := store.CreateChallenge(ctx, record); err != nil {
		t.Fatal(err)
	}
	claims := control.IdentityClaims{AccountGeneration: expectation.AccountGeneration, AccountID: expectation.AccountID,
		Region: expectation.Region, InstanceID: expectation.InstanceID, LaunchIdentity: expectation.LaunchIdentity,
		RoleARN: expectation.RoleARN, RoleID: expectation.RoleID, InstanceProfileID: expectation.InstanceProfileID,
		Tags: expectation.RequiredTags}
	session, err := store.Claim(ctx, control.ClaimMutation{ChallengeID: record.ChallengeID, NonceDigest: nonce,
		Fence: fence, Identity: claims, SessionID: uuid.NewString(), TokenDigest: sha256.Sum256([]byte(seed + "-token")), At: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestCloudWorkerPostgresAuthorityEventGenerationFence(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	events, next, err := h.cloud.EventsForAuthority(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID, 0, 10)
	if err != nil || len(events) != 1 || next != 1 || events[0].AccountGeneration != h.generation {
		t.Fatalf("events=%+v next=%d err=%v", events, next, err)
	}
	if _, _, err = h.cloud.EventsForAuthority(h.ctx, h.owner, h.generation+1, offer.Execution.ExecutionID, 0, 10); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.pool.Exec(h.ctx, `UPDATE core_cloud_worker_events SET payload_json=jsonb_set(payload_json,'{account_generation}','99'::jsonb)
		WHERE execution_id=$1`, offer.Execution.ExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.cloud.EventsForAuthority(h.ctx, h.owner, h.generation, offer.Execution.ExecutionID, 0, 10); !errors.Is(err, cloudworker.ErrConflict) {
		t.Fatalf("tampered event generation err=%v", err)
	}
}

func TestCloudWorkerPostgresRejectForeignOwnerAndGeneration(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	for _, test := range []struct {
		owner      string
		generation uint64
	}{
		{owner: "@foreign:example.test", generation: h.generation},
		{owner: h.owner, generation: h.generation + 1},
	} {
		if _, err := h.cloud.GetExecutionForAuthority(h.ctx, test.owner, test.generation, offer.Execution.ExecutionID); err == nil {
			t.Fatalf("foreign authority read accepted owner=%s generation=%d", test.owner, test.generation)
		}
	}
	if strings.TrimSpace(offer.Plan.Objective) == "" {
		t.Fatal("private plan objective missing from authoritative store fixture")
	}
}
