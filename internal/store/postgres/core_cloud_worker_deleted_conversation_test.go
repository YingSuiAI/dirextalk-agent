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
	return cloudworker.Defaults{
		AWS: cloudworker.AWSBinding{AccountID: "123456789012", Region: "us-east-1",
			CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("pg-cloud-credential")).String(), CredentialRevision: 3},
		Compute: cloudworker.ComputeSpec{InstanceType: "c7i.large", Architecture: "x86_64", VCPU: 2, MemoryGiB: 4,
			RootDeviceName: "/dev/xvda", VolumeGiB: 32, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125},
		Limits:            cloudworker.Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20},
		QuoteAmountMicros: 1000, MaximumAuthorizedMicros: 2000, QuoteTTL: time.Hour,
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
	cloudStore := NewCloudWorkerStore(store)
	service, err := cloudworker.NewService(cloudStore, defaults, cloudworker.FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: time.Hour, Now: func() time.Time { return now },
	}, func() time.Time { return now })
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
	command := cloudworker.ProposeCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: uuid.NewString(),
		ConversationID: conversationID, TurnID: turn.ID, TurnLeaseID: lease.LeaseID, TurnLeaseEpoch: lease.Epoch,
		ExpectedTurnRevision: lease.Turn.Revision, Objective: "Produce a verified cloud result",
		ObjectiveSummary: "Verified cloud result", UserPromptDigest: pgCloudDigest(lease.Turn.Prompt),
		ProposalReason: cloudworker.ProposalReasonExplicitUserCloud, InputManifest: cloudworker.InputManifest{},
		WorkspaceMode: cloudworker.WorkspaceNone, ModelAuthorization: authorization}
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
