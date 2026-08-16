package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
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
	confirmations *CoreConfirmationStore
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
	return cloudworker.Defaults{Limits: cloudworker.Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20}}
}

func pgCloudAWSBinding() cloudworker.AWSBinding {
	return cloudworker.AWSBinding{AccountID: "123456789012", Region: "us-east-1",
		CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("pg-cloud-credential")).String(), CredentialRevision: 3}
}

type pgCloudComputeSelector struct{}

func (pgCloudComputeSelector) SelectCompute(context.Context, cloudworker.AWSBinding, cloudworker.ComputeRequirements) (cloudworker.ComputeSpec, error) {
	return cloudworker.ComputeSpec{InstanceType: "c7i.large", Architecture: "x86_64", VCPU: 2, MemoryGiB: 4,
		RootDeviceName: "/dev/xvda", VolumeGiB: 32, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}, nil
}

type pgCloudReuseResolver struct{}

func (pgCloudReuseResolver) ResolveIdleWorker(context.Context, string, uint64, cloudworker.AWSBinding, cloudworker.ComputeRequirements, *cloudworker.ServiceSpec) (cloudworker.WorkerReuseSelection, bool, error) {
	return cloudworker.WorkerReuseSelection{}, false, nil
}

func (pgCloudReuseResolver) CheckCreateWorkerCapacity(context.Context, string, uint64, cloudworker.AWSBinding) error {
	return nil
}

type pgCloudRetainedReuseResolver struct{ workerID string }

func (r pgCloudRetainedReuseResolver) ResolveIdleWorker(context.Context, string, uint64, cloudworker.AWSBinding, cloudworker.ComputeRequirements, *cloudworker.ServiceSpec) (cloudworker.WorkerReuseSelection, bool, error) {
	return cloudworker.WorkerReuseSelection{WorkerID: r.workerID, Compute: cloudworker.ComputeSpec{
		InstanceType: "c7i.large", Architecture: "x86_64", VCPU: 2, MemoryGiB: 4,
		RootDeviceName: "/dev/xvda", VolumeGiB: 32, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
	}}, true, nil
}

func (pgCloudRetainedReuseResolver) CheckCreateWorkerCapacity(context.Context, string, uint64, cloudworker.AWSBinding) error {
	return nil
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
	defaults := pgCloudDefaults()
	binding := pgCloudAWSBinding()
	credential := coreaws.RehydrateCredentialsWithTestedAt(
		binding.CredentialID, "cloud-worker-test", binding.Region,
		binding.AccountID, "arn:aws:iam::123456789012:user/cloud-worker-test",
		[]byte("AKIATESTOUTPUTJOURNAL"), []byte("test-secret-access-key"), nil,
		int64(binding.CredentialRevision), int64(binding.CredentialRevision), now, now, now,
	)
	if _, err = NewCoreAWSStore(store).CreateCredential(ctx, credential); err != nil {
		cleanup()
		t.Fatal(err)
	}
	cloudStore := NewCloudWorkerStore(store)
	service, err := cloudworker.NewServiceWithAWSBindingResolver(cloudStore, defaults, cloudworker.FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000, ComputeMicrosPerHour: 100000, TTL: time.Hour, Now: func() time.Time { return now },
	}, cloudworker.AWSBindingResolverFunc(func(context.Context) (cloudworker.AWSBinding, error) { return binding, nil }), func() time.Time { return now })
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err = service.EnableDynamicComputeSelection(pgCloudComputeSelector{}); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err = service.EnablePersistentWorkerReuse(pgCloudReuseResolver{}); err != nil {
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
	command := cloudworker.ProposeCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: uuid.NewString(),
		ConversationID: conversationID, TurnID: turn.ID, TurnLeaseID: lease.LeaseID, TurnLeaseEpoch: lease.Epoch,
		ExpectedTurnRevision: lease.Turn.Revision, Objective: "Produce a verified cloud result",
		ObjectiveSummary: "Verified cloud result", UserPromptDigest: pgCloudDigest(lease.Turn.Prompt),
		ProposalReason: cloudworker.ProposalReasonLocalBudgetExceeded,
		LocalBudgetEvidence: &cloudworker.LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1,
			Digest: pgCloudDigest("local-budget")}, InputManifest: cloudworker.InputManifest{},
		WorkspaceMode: cloudworker.WorkspaceNone, ModelAuthorization: authorization,
		ComputeRequirements: cloudworker.ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 4, DiskGiB: 32, EstimatedRuntimeMinutes: 60}}
	arguments, _ := json.Marshal(map[string]any{"objective": command.Objective, "workspace_mode": string(command.WorkspaceMode)})
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: string(arguments)}
	if _, err = conversation.PrepareTurnModel(ctx, lease); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err = conversation.RecordTurnModelResult(ctx, lease, core.ModelRunResult{ToolCalls: []core.ToolCall{call}}); err != nil {
		cleanup()
		t.Fatal(err)
	}
	return &pgCloudWorkerHarness{ctx: ctx, store: store, cloud: cloudStore, confirmations: NewCoreConfirmationStore(store),
		conversation: conversation, service: service, lease: lease, command: command, now: now,
		owner: owner, generation: generation, cleanup: cleanup}
}

func (h *pgCloudWorkerHarness) propose(t *testing.T) cloudworker.Offer {
	t.Helper()
	offer, err := h.service.Propose(h.ctx, h.command)
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

func (h *pgCloudWorkerHarness) proposeAdditional(t *testing.T) cloudworker.Offer {
	t.Helper()
	conversationID := uuid.NewString()
	profileID := h.command.ModelAuthorization.ModelProfileID
	snapshot := coremodel.ExecutionSnapshot{ProfileID: profileID, Revision: 1, CredentialVersion: 1,
		Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://example.invalid", Model: "test", APIKey: "test", ContextWindow: 32768}
	turn, err := h.conversation.StartTurn(h.ctx, core.TurnStartCommand{RequestID: uuid.NewString(), OwnerID: h.owner,
		AccountGeneration: h.generation, ConversationID: conversationID, Prompt: "Run a second heavy task on AWS.",
		ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1, ProfileSnapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.conversation.ClaimTurn(h.ctx, turn.ID, h.now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	command := h.command
	command.IdempotencyKey = uuid.NewString()
	command.ConversationID = conversationID
	command.TurnID = turn.ID
	command.TurnLeaseID = lease.LeaseID
	command.TurnLeaseEpoch = lease.Epoch
	command.ExpectedTurnRevision = lease.Turn.Revision
	command.UserPromptDigest = pgCloudDigest(lease.Turn.Prompt)
	arguments, _ := json.Marshal(map[string]any{"objective": command.Objective, "workspace_mode": string(command.WorkspaceMode)})
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: string(arguments)}
	if _, err = h.conversation.PrepareTurnModel(h.ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err = h.conversation.RecordTurnModelResult(h.ctx, lease, core.ModelRunResult{ToolCalls: []core.ToolCall{call}}); err != nil {
		t.Fatal(err)
	}
	offer, err := h.service.Propose(h.ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

func seedDeletedLegacyCloudWorkerOffer(t *testing.T, h *pgCloudWorkerHarness, mutate func(*coreconfirmation.Binding)) cloudworker.Offer {
	t.Helper()
	offer := h.propose(t)
	legacyExecution := offer.Execution
	legacyExecution.RunID = legacyExecution.ExecutionID
	legacyExecutionRaw, _ := json.Marshal(legacyExecution)
	legacyBinding := offer.Confirmation.Binding
	legacyBinding.RunID = legacyExecution.RunID
	legacyBinding.Quote = nil
	if mutate != nil {
		mutate(&legacyBinding)
	}
	legacyBinding.Digest = ""
	legacyBindingRaw, _ := json.Marshal(legacyBinding)
	legacyBinding.Digest = coreconfirmation.Digest(pgCloudDigest(string(legacyBindingRaw)))
	legacyBindingRaw, _ = json.Marshal(legacyBinding)
	for _, update := range []struct {
		query string
		args  []any
	}{
		{`UPDATE core_cloud_worker_executions SET execution_json=$2 WHERE execution_id=$1`, []any{offer.Execution.ExecutionID, legacyExecutionRaw}},
		{`UPDATE core_confirmations SET binding_json=$2 WHERE confirmation_id=$1`, []any{offer.Confirmation.ConfirmationID, legacyBindingRaw}},
		{`UPDATE core_confirmation_target_bindings SET binding_json=$2 WHERE confirmation_id=$1`, []any{offer.Confirmation.ConfirmationID, legacyBindingRaw}},
		{`UPDATE core_confirmation_current_bindings SET binding_json=$3 WHERE operation_domain=$1 AND target_id=$2`, []any{cloudworker.OperationDomain, offer.Execution.ExecutionID, legacyBindingRaw}},
	} {
		if _, err := h.store.pool.Exec(h.ctx, update.query, update.args...); err != nil {
			t.Fatal(err)
		}
	}
	var conversationRevision uint64
	if err := h.store.pool.QueryRow(h.ctx, `SELECT revision FROM core_conversations WHERE conversation_id=$1`, offer.Plan.ConversationID).Scan(&conversationRevision); err != nil {
		t.Fatal(err)
	}
	if err := h.conversation.DeleteConversation(h.ctx, offer.Plan.ConversationID, conversationRevision); err != nil {
		t.Fatal(err)
	}
	return offer
}

func rewriteCloudWorkerBinding(t *testing.T, h *pgCloudWorkerHarness, offer cloudworker.Offer, mutate func(*coreconfirmation.Binding)) {
	t.Helper()
	binding := offer.Confirmation.Binding
	mutate(&binding)
	binding.Digest = ""
	raw, _ := json.Marshal(binding)
	binding.Digest = coreconfirmation.Digest(pgCloudDigest(string(raw)))
	raw, _ = json.Marshal(binding)
	for _, update := range []struct {
		query string
		args  []any
	}{
		{`UPDATE core_confirmations SET binding_json=$2 WHERE confirmation_id=$1`, []any{offer.Confirmation.ConfirmationID, raw}},
		{`UPDATE core_confirmation_target_bindings SET binding_json=$2 WHERE confirmation_id=$1`, []any{offer.Confirmation.ConfirmationID, raw}},
		{`UPDATE core_confirmation_current_bindings SET binding_json=$3 WHERE operation_domain=$1 AND target_id=$2`, []any{cloudworker.OperationDomain, offer.Execution.ExecutionID, raw}},
	} {
		if _, err := h.store.pool.Exec(h.ctx, update.query, update.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCloudWorkerPostgresExecutesOfferWithFrozenPreChangeTargetKind(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	h.command.WorkloadKind = cloudworker.WorkloadService
	h.command.Service = &cloudworker.ServiceSpec{WorkloadID: "gitea", Port: 3000, HealthPath: "/api/healthz"}
	offer := h.propose(t)
	if offer.Confirmation.Binding.TargetKind != coreconfirmation.TargetKindPersistentService {
		t.Fatalf("new service target kind=%q", offer.Confirmation.Binding.TargetKind)
	}
	rewriteCloudWorkerBinding(t, h, offer, func(binding *coreconfirmation.Binding) {
		binding.TargetKind = "persistent_ssh_worker"
	})
	confirmationService, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := confirmationService.ConfirmAuthorized(h.ctx, coreconfirmation.Authority{OwnerID: h.owner, AccountGeneration: h.generation}, coreconfirmation.ConfirmCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now.Add(time.Second),
	})
	if err != nil || confirmed.State != coreconfirmation.StateConfirmed || confirmed.Binding.TargetKind != "persistent_ssh_worker" {
		t.Fatalf("confirmed=%+v err=%v", confirmed, err)
	}
	claimed, _, err := NewCoreTaskStore(h.store).ClaimNextDue(h.ctx, "frozen-binding-worker", h.now.Add(2*time.Second), time.Minute, 4)
	if err != nil || claimed.ID != offer.Task.ID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	var confirmationState, executionState string
	if err = h.store.pool.QueryRow(h.ctx, `SELECT c.state,e.state FROM core_confirmations c JOIN core_cloud_worker_executions e ON e.confirmation_id=c.confirmation_id WHERE c.confirmation_id=$1`, offer.Confirmation.ConfirmationID).Scan(&confirmationState, &executionState); err != nil {
		t.Fatal(err)
	}
	if confirmationState != string(coreconfirmation.StateConsumed) || executionState != string(cloudworker.StateProvisioning) {
		t.Fatalf("confirmation=%s execution=%s", confirmationState, executionState)
	}
}

func TestCloudWorkerPostgresReusesRetainedWorkerTwiceInOneTurn(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	workerID := uuid.NewString()
	if err := h.service.EnablePersistentWorkerReuse(pgCloudRetainedReuseResolver{workerID: workerID}); err != nil {
		t.Fatal(err)
	}
	first := h.propose(t)
	if !first.Plan.PersistentWorkerReuse || first.Plan.ReuseWorkerID != workerID {
		t.Fatalf("first offer did not reuse retained Worker: %+v", first.Plan)
	}

	leaseID := uuid.NewString()
	var revision, epoch uint64
	if err := h.store.pool.QueryRow(h.ctx, `UPDATE core_conversation_turns
		SET state='running',revision=revision+1,lease_id=$2,lease_epoch=lease_epoch+1,
			lease_expires_at=$3,updated_at=$4
		WHERE turn_id=$1
		RETURNING revision,lease_epoch`, h.command.TurnID, leaseID, h.now.Add(30*time.Minute), h.now).Scan(&revision, &epoch); err != nil {
		t.Fatal(err)
	}
	secondCommand := h.command
	secondCommand.IdempotencyKey = uuid.NewString()
	secondCommand.TurnLeaseID = leaseID
	secondCommand.TurnLeaseEpoch = epoch
	secondCommand.ExpectedTurnRevision = revision
	secondCommand.Objective = "Add disk usage to the retained Worker report"
	secondCommand.ObjectiveSummary = secondCommand.Objective
	second, err := h.service.Propose(h.ctx, secondCommand)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Plan.PersistentWorkerReuse || second.Plan.ReuseWorkerID != workerID || second.Plan.PlanID == first.Plan.PlanID || second.Plan.TurnID != first.Plan.TurnID {
		t.Fatalf("follow-up offer=%+v first=%+v", second.Plan, first.Plan)
	}
	var userMessages int
	if err = h.store.pool.QueryRow(h.ctx, `SELECT count(*) FROM core_messages
		WHERE conversation_id=$1 AND role='user'`, h.command.ConversationID).Scan(&userMessages); err != nil {
		t.Fatal(err)
	}
	if userMessages != 1 {
		t.Fatalf("same-turn Worker reuse persisted %d original user messages", userMessages)
	}
}

func TestCloudWorkerPostgresExpiredConfirmationSurvivesDeletedConversation(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := seedDeletedLegacyCloudWorkerOffer(t, h, nil)
	count, err := h.confirmations.SweepExpired(h.ctx, offer.Confirmation.ExpiresAt.Add(time.Second), 100)
	if err != nil || count != 1 {
		t.Fatalf("expired confirmation sweep count=%d err=%v", count, err)
	}
	var confirmationState, executionState, taskStatus, turnState string
	var messageCount int
	if err = h.store.pool.QueryRow(h.ctx, `SELECT c.state,e.state,t.status,u.state,
		(SELECT count(*) FROM core_messages WHERE conversation_id=e.conversation_id)
		FROM core_cloud_worker_executions e JOIN core_confirmations c ON c.confirmation_id=e.confirmation_id
		JOIN core_tasks t ON t.task_id=e.task_id JOIN core_conversation_turns u ON u.turn_id=e.turn_id
		WHERE e.execution_id=$1`, offer.Execution.ExecutionID).Scan(
		&confirmationState, &executionState, &taskStatus, &turnState, &messageCount); err != nil {
		t.Fatal(err)
	}
	if confirmationState != string(coreconfirmation.StateExpired) || executionState != string(cloudworker.StateExpired) ||
		taskStatus != string(coretask.StatusFailed) || turnState != string(core.TurnWaitingConfirmation) || messageCount != 2 {
		t.Fatalf("deleted conversation terminal projection confirmation=%s execution=%s task=%s turn=%s messages=%d",
			confirmationState, executionState, taskStatus, turnState, messageCount)
	}
}

func TestCloudWorkerPostgresDeletedConversationDoesNotHideStaleBinding(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := seedDeletedLegacyCloudWorkerOffer(t, h, func(binding *coreconfirmation.Binding) {
		binding.PlanDigest = coreconfirmation.Digest(pgCloudDigest("unrelated-plan"))
	})
	valid := h.proposeAdditional(t)
	count, err := h.confirmations.SweepExpired(h.ctx, offer.Confirmation.ExpiresAt.Add(time.Second), 100)
	if !errors.Is(err, coreconfirmation.ErrStale) || count != 1 {
		t.Fatalf("stale binding sweep count=%d err=%v", count, err)
	}
	var confirmationState, executionState, taskStatus string
	if err = h.store.pool.QueryRow(h.ctx, `SELECT c.state,e.state,t.status FROM core_cloud_worker_executions e
		JOIN core_confirmations c ON c.confirmation_id=e.confirmation_id JOIN core_tasks t ON t.task_id=e.task_id
		WHERE e.execution_id=$1`, offer.Execution.ExecutionID).Scan(&confirmationState, &executionState, &taskStatus); err != nil {
		t.Fatal(err)
	}
	if confirmationState != string(coreconfirmation.StatePending) || executionState != string(cloudworker.StateWaitingUser) || taskStatus != string(coretask.StatusWaitingUser) {
		t.Fatalf("stale binding mutated state confirmation=%s execution=%s task=%s", confirmationState, executionState, taskStatus)
	}
	if err = h.store.pool.QueryRow(h.ctx, `SELECT c.state,e.state,t.status FROM core_cloud_worker_executions e
		JOIN core_confirmations c ON c.confirmation_id=e.confirmation_id JOIN core_tasks t ON t.task_id=e.task_id
		WHERE e.execution_id=$1`, valid.Execution.ExecutionID).Scan(&confirmationState, &executionState, &taskStatus); err != nil {
		t.Fatal(err)
	}
	if confirmationState != string(coreconfirmation.StateExpired) || executionState != string(cloudworker.StateExpired) || taskStatus != string(coretask.StatusFailed) {
		t.Fatalf("valid sibling did not expire confirmation=%s execution=%s task=%s", confirmationState, executionState, taskStatus)
	}
}

func TestCloudWorkerPostgresCancelPendingOfferAndReplay(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	key := uuid.NewString()
	canceled, err := h.cloud.RequestCancel(h.ctx, h.owner, h.generation, offer.Execution.RunID, offer.Execution.Revision, key)
	if err != nil || canceled.State != cloudworker.StateCanceled || canceled.Revision != offer.Execution.Revision+1 {
		t.Fatalf("canceled=%+v err=%v", canceled, err)
	}
	replayed, err := h.cloud.RequestCancel(h.ctx, h.owner, h.generation, offer.Execution.RunID, offer.Execution.Revision, key)
	if err != nil || replayed.Digest != canceled.Digest {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	var confirmationState, taskStatus, turnState string
	if err = h.store.pool.QueryRow(h.ctx, `SELECT c.state,t.status,u.state FROM core_cloud_worker_executions e
		JOIN core_confirmations c ON c.confirmation_id=e.confirmation_id JOIN core_tasks t ON t.task_id=e.task_id
		JOIN core_conversation_turns u ON u.turn_id=e.turn_id WHERE e.execution_id=$1`, offer.Execution.ExecutionID).Scan(
		&confirmationState, &taskStatus, &turnState); err != nil {
		t.Fatal(err)
	}
	if confirmationState != string(coreconfirmation.StateExpired) || taskStatus != string(coretask.StatusCanceled) || turnState != string(core.TurnCanceled) {
		t.Fatalf("confirmation=%s task=%s turn=%s", confirmationState, taskStatus, turnState)
	}
}
