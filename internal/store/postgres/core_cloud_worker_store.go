package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CloudWorkerStore is the PostgreSQL authority for the single ephemeral Pi
// Worker execution path. It deliberately shares Store's pool so offer,
// confirmation, task, conversation and execution mutations can be committed
// in one PostgreSQL transaction.
type CloudWorkerStore struct{ store *Store }

func NewCloudWorkerStore(store *Store) *CloudWorkerStore { return &CloudWorkerStore{store: store} }

type privateCloudWorkerPlan struct {
	Objective       string                        `json:"objective"`
	InputManifest   cloudworker.InputManifest     `json:"input_manifest"`
	Placement       cloudworker.PlacementSpec     `json:"placement"`
	NetworkPolicy   cloudworker.NetworkPolicy     `json:"network_policy"`
	ArtifactGrant   cloudworker.ArtifactGrant     `json:"artifact_grant"`
	WorkerBootstrap cloudworker.WorkerBootstrap   `json:"worker_bootstrap"`
	ModelRelay      cloudworker.ModelRelayBinding `json:"model_relay"`
}

type cloudWorkerReplay struct {
	PlanID string `json:"plan_id"`
}

func marshalCloudWorkerPlan(plan cloudworker.Plan) ([]byte, []byte, error) {
	copy := plan
	if err := copy.Seal(); err != nil || copy.Digest != plan.Digest || copy.ExecutionDigest != plan.ExecutionDigest {
		return nil, nil, cloudworker.ErrInvalid
	}
	publicRaw, err := json.Marshal(copy)
	if err != nil {
		return nil, nil, err
	}
	privateRaw, err := json.Marshal(privateCloudWorkerPlan{
		Objective: copy.Objective, InputManifest: copy.InputManifest,
		Placement: copy.Placement, NetworkPolicy: copy.NetworkPolicy,
		ArtifactGrant: copy.ArtifactGrant, WorkerBootstrap: copy.WorkerBootstrap,
		ModelRelay: copy.ModelRelay,
	})
	if err != nil || len(publicRaw) > 1<<20 || len(privateRaw) > 1<<20 {
		return nil, nil, cloudworker.ErrInvalid
	}
	return publicRaw, privateRaw, nil
}

type cloudWorkerRowScanner interface{ Scan(...any) error }

func scanCloudWorkerPlan(row cloudWorkerRowScanner) (cloudworker.Plan, error) {
	var plan cloudworker.Plan
	var publicRaw, privateRaw []byte
	var storedRevision int64
	var storedCredentialRevision int64
	var storedCredentialID string
	var storedDigest, storedExecutionDigest, storedAuthorization, storedQuote, storedManifest, storedModel string
	err := row.Scan(&publicRaw, &privateRaw, &storedRevision, &storedDigest, &storedExecutionDigest,
		&storedAuthorization, &storedQuote, &storedManifest, &storedModel, &storedCredentialID, &storedCredentialRevision)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return plan, cloudworker.ErrNotFound
		}
		return plan, err
	}
	var private privateCloudWorkerPlan
	if json.Unmarshal(publicRaw, &plan) != nil || json.Unmarshal(privateRaw, &private) != nil {
		return cloudworker.Plan{}, cloudworker.ErrConflict
	}
	plan.Objective, plan.InputManifest = private.Objective, private.InputManifest
	plan.Placement, plan.NetworkPolicy = private.Placement, private.NetworkPolicy
	plan.ArtifactGrant, plan.WorkerBootstrap, plan.ModelRelay = private.ArtifactGrant, private.WorkerBootstrap, private.ModelRelay
	if plan.Seal() != nil || plan.Revision != uint64(storedRevision) || plan.Digest != storedDigest ||
		plan.ExecutionDigest != storedExecutionDigest || plan.AuthorizationBasisDigest != storedAuthorization ||
		plan.Quote.Digest != storedQuote || plan.InputManifestDigest != storedManifest ||
		plan.ModelAuthorization.BindingDigest != storedModel || plan.AWS.CredentialID != storedCredentialID ||
		storedCredentialRevision < 1 || plan.AWS.CredentialRevision != uint64(storedCredentialRevision) {
		return cloudworker.Plan{}, cloudworker.ErrConflict
	}
	return plan, nil
}

const cloudWorkerPlanSelect = `SELECT plan_json,private_json,revision,digest,execution_digest,
authorization_basis_digest,quote_digest,input_manifest_digest,model_binding_digest,credential_id::text,credential_revision
FROM core_cloud_worker_plans`

func marshalCloudWorkerExecution(execution cloudworker.Execution) ([]byte, error) {
	copy := execution
	if err := copy.Seal(); err != nil || copy.Digest != execution.Digest {
		return nil, cloudworker.ErrInvalid
	}
	raw, err := json.Marshal(copy)
	if err != nil || len(raw) > 1<<20 {
		return nil, cloudworker.ErrInvalid
	}
	return raw, nil
}

func scanCloudWorkerExecution(row cloudWorkerRowScanner) (cloudworker.Execution, error) {
	var execution cloudworker.Execution
	var raw []byte
	var state, digest, terminalIntent string
	var revision int64
	var providerStarted, needsReconcile bool
	err := row.Scan(&raw, &state, &revision, &digest, &providerStarted, &terminalIntent, &needsReconcile)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return execution, cloudworker.ErrNotFound
		}
		return execution, err
	}
	if json.Unmarshal(raw, &execution) != nil {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	execution.State, execution.Status = cloudworker.ExecutionState(state), cloudworker.ExecutionState(state)
	execution.Revision, execution.ProviderMutationStarted = uint64(revision), providerStarted
	execution.TerminalIntent, execution.NeedsReconcile = terminalIntent, needsReconcile
	if execution.Seal() != nil || execution.Digest != digest {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	return execution, nil
}

const cloudWorkerExecutionSelect = `SELECT execution_json,state,revision,digest,
provider_mutation_started,terminal_intent,needs_reconcile FROM core_cloud_worker_executions`

func (s *CloudWorkerStore) CreateOffer(ctx context.Context, command cloudworker.CreateOfferCommand) (cloudworker.Offer, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(command.IdempotencyKey) ||
		!coretask.ValidDigest(command.RequestDigest) || !coretask.ValidUUID(command.TurnLeaseID) ||
		command.TurnLeaseEpoch == 0 || command.ExpectedTurnRevision == 0 {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	plan, execution := command.Plan, command.Execution
	if plan.Seal() != nil || execution.Seal() != nil || plan.ExecutionID != execution.ExecutionID ||
		plan.TaskID != execution.TaskID || plan.ConfirmationID != execution.ConfirmationID ||
		plan.Digest != execution.PlanDigest || plan.ExecutionDigest != execution.ExecutionDigest ||
		command.TaskPayload.ExecutionID != plan.ExecutionID || command.TaskPayload.PlanID != plan.PlanID ||
		command.TaskPayload.PlanDigest != plan.Digest || command.TaskPayload.ConfirmationID != plan.ConfirmationID ||
		command.TaskPayload.AccountGeneration != plan.AccountGeneration || command.TaskPayload.TurnID != plan.TurnID ||
		command.TaskPayload.ConversationID != plan.ConversationID || command.TaskPayload.QuoteDigest != plan.Quote.Digest ||
		command.TaskPayload.ExecutionDigest != plan.ExecutionDigest {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	expectedBinding, err := cloudworker.BindingForPlan(plan)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	var suppliedBinding coreconfirmation.Binding
	if json.Unmarshal(command.BindingJSON, &suppliedBinding) != nil {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	normalizedBinding, err := suppliedBinding.Normalize()
	if err != nil || !normalizedBinding.Equal(expectedBinding) {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	bindingRaw, _ := json.Marshal(normalizedBinding)
	planRaw, privateRaw, err := marshalCloudWorkerPlan(plan)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	executionRaw, err := marshalCloudWorkerExecution(execution)
	if err != nil {
		return cloudworker.Offer{}, err
	}

	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Offer{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cloud-worker:offer:"+command.IdempotencyKey); err != nil {
		return cloudworker.Offer{}, err
	}
	var replayDigest string
	var replayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_cloud_worker_offer_replays WHERE idempotency_key=$1 FOR UPDATE`, command.IdempotencyKey).Scan(&replayDigest, &replayRaw)
	if err == nil {
		if replayDigest != command.RequestDigest {
			return cloudworker.Offer{}, cloudworker.ErrConflict
		}
		var replay cloudWorkerReplay
		if json.Unmarshal(replayRaw, &replay) != nil || replay.PlanID != plan.PlanID {
			return cloudworker.Offer{}, cloudworker.ErrConflict
		}
		offer, loadErr := s.offerTx(ctx, tx, replay.PlanID)
		if loadErr != nil {
			return cloudworker.Offer{}, loadErr
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.Offer{}, err
		}
		return offer, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return cloudworker.Offer{}, err
	}

	var turn struct {
		RequestID, OwnerID, ConversationID, Prompt, ProfileID, State, LeaseID string
		AccountGeneration, LeaseEpoch, Revision, LastSequence                 uint64
		LeaseExpiresAt                                                        *time.Time
		CancelRequested                                                       bool
	}
	err = tx.QueryRow(ctx, `SELECT request_id::text,owner_id,account_generation,conversation_id::text,prompt,profile_id::text,
		state,COALESCE(lease_id::text,''),lease_epoch,lease_expires_at,cancel_requested,revision,last_sequence
		FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, plan.TurnID).Scan(
		&turn.RequestID, &turn.OwnerID, &turn.AccountGeneration, &turn.ConversationID, &turn.Prompt, &turn.ProfileID,
		&turn.State, &turn.LeaseID, &turn.LeaseEpoch, &turn.LeaseExpiresAt, &turn.CancelRequested, &turn.Revision, &turn.LastSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return cloudworker.Offer{}, cloudworker.ErrNotFound
	}
	if err != nil {
		return cloudworker.Offer{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if turn.State != "running" || turn.CancelRequested || turn.LeaseID != command.TurnLeaseID ||
		turn.LeaseEpoch != command.TurnLeaseEpoch || turn.Revision != command.ExpectedTurnRevision ||
		turn.LeaseExpiresAt == nil || !turn.LeaseExpiresAt.After(now) || turn.OwnerID != plan.OwnerID ||
		turn.AccountGeneration != plan.AccountGeneration || turn.ConversationID != plan.ConversationID ||
		turn.ProfileID != plan.ModelAuthorization.ModelProfileID {
		return cloudworker.Offer{}, cloudworker.ErrLeaseConflict
	}
	if plan.CreatedAt.After(now.Add(time.Second)) || !plan.Quote.ExpiresAt.After(now) {
		return cloudworker.Offer{}, cloudworker.ErrQuoteExpired
	}

	taskTimeout, err := cloudWorkerTaskTimeout(plan.Limits)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	spec, err := (coretask.TaskSpec{
		Kind: coretask.TaskKindCloudWorker, Payload: coretask.TaskPayload{CloudWorker: &command.TaskPayload},
		Goal: plan.Objective, ConversationID: plan.ConversationID,
		ModelProfileID: plan.ModelAuthorization.ModelProfileID,
		TimeoutSeconds: taskTimeout, IdempotencyKey: command.IdempotencyKey,
		AvailableAt: plan.CreatedAt,
	}).Normalize()
	if err != nil {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	var profileRevision, credentialVersion int64
	var provider, modelName string
	if err = tx.QueryRow(ctx, `SELECT revision,credential_version,provider,model_name FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR SHARE`, spec.ModelProfileID).Scan(&profileRevision, &credentialVersion, &provider, &modelName); err != nil {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	if uint64(profileRevision) != plan.ModelAuthorization.ModelProfileRevision || uint64(credentialVersion) != plan.ModelAuthorization.CredentialVersion || provider != plan.ModelAuthorization.Provider || modelName != plan.ModelAuthorization.Model {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	snapshot, err := resolveTaskSnapshotTx(ctx, tx, spec)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	snapshotRaw, _ := json.Marshal(snapshot)
	payloadRaw, _ := json.Marshal(spec.Payload)
	emptyArray := []byte(`[]`)
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,
		attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,lease_epoch,
		lease_holder,available_at,revision,created_at,updated_at,task_kind,payload_json)
		VALUES($1,$2,$3,$4,$5,$6,$6,$6,$7,'waiting_user',0,1,0,'',$8,1,$9,$9,'cloud_worker',$10)`,
		plan.TaskID, spec.Goal, spec.ConversationID, spec.ModelProfileID, spec.IdempotencyKey, emptyArray,
		spec.TimeoutSeconds, spec.AvailableAt, plan.CreatedAt, payloadRaw); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, plan.TaskID, snapshotRaw, snapshot.Digest); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, plan.TaskID, spec.ModelProfileID); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at)
		VALUES($1,1,$2,0,'waiting_user','confirmation','waiting for owner confirmation',$3)`, plan.TaskID, deterministicCloudWorkerUUID("task-event", plan.TaskID), plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,
		task_id,state,consumed_released,revision,created_at,updated_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,'pending',false,1,$7,$7,$8)`, plan.ConfirmationID,
		normalizedBinding.OperationDomain, normalizedBinding.TargetID, normalizedBinding.TargetRevision,
		bindingRaw, plan.TaskID, plan.CreatedAt, plan.Quote.ExpiresAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at)
		VALUES($1,$2,$3,$4,$5)`, normalizedBinding.OperationDomain, normalizedBinding.TargetID,
		normalizedBinding.TargetRevision, bindingRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, plan.ConfirmationID, bindingRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_plans(plan_id,owner_id,account_generation,revision,digest,
		execution_digest,authorization_basis_digest,quote_digest,input_manifest_digest,model_binding_digest,
		credential_id,credential_revision,
		execution_id,task_id,confirmation_id,conversation_id,turn_id,recipe_id,adapter,workspace_mode,status,
		quote_expires_at,plan_json,private_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,'waiting_user',$21,$22,$23,$24,$25)`,
		plan.PlanID, plan.OwnerID, plan.AccountGeneration, plan.Revision, plan.Digest, plan.ExecutionDigest,
		plan.AuthorizationBasisDigest, plan.Quote.Digest, plan.InputManifestDigest, plan.ModelAuthorization.BindingDigest,
		plan.AWS.CredentialID, plan.AWS.CredentialRevision,
		plan.ExecutionID, plan.TaskID, plan.ConfirmationID, plan.ConversationID, plan.TurnID, plan.RecipeID,
		plan.Adapter, plan.WorkspaceMode, plan.Quote.ExpiresAt, planRaw, privateRaw, plan.CreatedAt, plan.UpdatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_executions(execution_id,owner_id,account_generation,plan_id,
		plan_revision,plan_digest,task_id,confirmation_id,conversation_id,turn_id,state,revision,digest,quote_digest,
		execution_digest,provider_mutation_started,terminal_intent,needs_reconcile,execution_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'waiting_user',$11,$12,$13,$14,false,'',false,$15,$16,$17)`,
		execution.ExecutionID, execution.OwnerID, execution.AccountGeneration, execution.PlanID, execution.PlanRevision,
		execution.PlanDigest, execution.TaskID, execution.ConfirmationID, execution.ConversationID, execution.TurnID,
		execution.Revision, execution.Digest, execution.QuoteDigest, execution.ExecutionDigest, executionRaw,
		execution.CreatedAt, execution.UpdatedAt); err != nil {
		return cloudworker.Offer{}, err
	}

	references := cloudWorkerReferences(plan, execution, normalizedBinding, 1, "pending")
	userMessage := core.Message{ID: deterministicCloudWorkerUUID("conversation-turn-user", turn.RequestID), Role: core.RoleUser,
		Content: turn.Prompt, ModelProfileID: turn.ProfileID, CreatedAt: plan.CreatedAt.Add(-time.Microsecond)}
	offerMessage := core.Message{ID: deterministicCloudWorkerUUID("cloud-worker-offer-message", plan.ExecutionID), Role: core.RoleAssistant,
		Content: "Cloud Worker quote is ready for confirmation.", ModelProfileID: turn.ProfileID,
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, References: references,
		CreatedAt: plan.CreatedAt}
	if userMessage.Validate() != nil || offerMessage.Validate() != nil {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	var conversationRevision uint64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL FOR UPDATE`, plan.ConversationID).Scan(&conversationRevision); err != nil {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}
	var nextMessageSequence int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_messages WHERE conversation_id=$1`, plan.ConversationID).Scan(&nextMessageSequence); err != nil {
		return cloudworker.Offer{}, err
	}
	for index, message := range []core.Message{userMessage, offerMessage} {
		if err = insertCloudWorkerMessageTx(ctx, tx, plan.ConversationID, nextMessageSequence+int64(index), message); err != nil {
			return cloudworker.Offer{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('conversation',$1,$2) ON CONFLICT DO NOTHING`, plan.ConversationID, turn.ProfileID); err != nil {
		return cloudworker.Offer{}, err
	}
	conversationUpdate, err := tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2 WHERE conversation_id=$1 AND revision=$3`, plan.ConversationID, plan.CreatedAt, conversationRevision)
	if err != nil || conversationUpdate.RowsAffected() != 1 {
		if err == nil {
			err = cloudworker.ErrConflict
		}
		return cloudworker.Offer{}, err
	}
	event := core.TurnEvent{Kind: core.TurnEventWaitingConfirmation, Message: &offerMessage,
		ConfirmationID: plan.ConfirmationID, ExecutionID: plan.ExecutionID, Status: string(cloudworker.StateWaitingUser),
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, References: references}
	event.TurnID, event.Sequence, event.CreatedAt = plan.TurnID, int64(turn.LastSequence+1), plan.CreatedAt
	eventRaw, _ := json.Marshal(event)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`,
		plan.TurnID, event.Sequence, string(event.Kind), eventRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='waiting_confirmation',revision=revision+1,
		last_sequence=$2,lease_id=NULL,lease_expires_at=NULL,updated_at=$3
		WHERE turn_id=$1 AND state='running' AND lease_id=$4 AND lease_epoch=$5 AND revision=$6 AND cancel_requested=false`,
		plan.TurnID, event.Sequence, plan.CreatedAt, command.TurnLeaseID, command.TurnLeaseEpoch, command.ExpectedTurnRevision)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return cloudworker.Offer{}, err
		}
		return cloudworker.Offer{}, cloudworker.ErrLeaseConflict
	}

	executionEvent := cloudworker.Event{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		RunID: plan.ExecutionID, ExecutionID: plan.ExecutionID,
		Sequence: 1, EventID: deterministicCloudWorkerUUID("execution-event-offer", plan.ExecutionID), Type: "offer_created",
		State: cloudworker.StateWaitingUser, Revision: execution.Revision, CreatedAt: plan.CreatedAt}
	executionEvent.PayloadDigest = digestCloudWorkerValue(struct {
		PlanID, TaskID, ConfirmationID, QuoteDigest string
	}{plan.PlanID, plan.TaskID, plan.ConfirmationID, plan.Quote.Digest})
	executionEventRaw, _ := json.Marshal(executionEvent)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_events(execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at)
		VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`, plan.ExecutionID, executionEvent.EventID, plan.OwnerID,
		executionEvent.Type, executionEvent.State, executionEvent.Revision, executionEvent.PayloadDigest, executionEventRaw, executionEvent.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	offerOutboxRaw, _ := json.Marshal(struct {
		PlanID, ExecutionID, TaskID, ConfirmationID string
	}{plan.PlanID, plan.ExecutionID, plan.TaskID, plan.ConfirmationID})
	offerOutboxDigest := sha256.Sum256(offerOutboxRaw)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_offer_outbox(event_id,plan_id,execution_id,conversation_id,turn_id,payload_digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, deterministicCloudWorkerUUID("offer-outbox", plan.ExecutionID), plan.PlanID,
		plan.ExecutionID, plan.ConversationID, plan.TurnID, hex.EncodeToString(offerOutboxDigest[:]), offerOutboxRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	replayRaw, _ = json.Marshal(cloudWorkerReplay{PlanID: plan.PlanID})
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_offer_replays(idempotency_key,request_digest,plan_id,response_json,created_at) VALUES($1,$2,$3,$4,$5)`, command.IdempotencyKey, command.RequestDigest, plan.PlanID, replayRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	offer, err := s.offerTx(ctx, tx, plan.PlanID)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Offer{}, err
	}
	return offer, nil
}

func (s *CloudWorkerStore) offerTx(ctx context.Context, tx pgx.Tx, planID string) (cloudworker.Offer, error) {
	plan, err := scanCloudWorkerPlan(tx.QueryRow(ctx, cloudWorkerPlanSelect+` WHERE plan_id=$1`, planID))
	if err != nil {
		return cloudworker.Offer{}, err
	}
	execution, err := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1`, plan.ExecutionID))
	if err != nil {
		return cloudworker.Offer{}, err
	}
	task, err := NewCoreTaskStore(s.store).taskTx(ctx, tx, plan.TaskID, false)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1`, plan.ConfirmationID))
	if err != nil {
		return cloudworker.Offer{}, err
	}
	return cloudworker.Offer{Plan: plan, Execution: execution, Task: task, Confirmation: confirmation}, nil
}

func insertCloudWorkerMessageTx(ctx context.Context, tx pgx.Tx, conversationID string, sequence int64, message core.Message) error {
	payload, _ := json.Marshal(message)
	taskIDs := append([]string{}, message.RelatedTaskIDs...)
	planIDs := append([]string{}, message.RelatedPlanIDs...)
	referenceValues := append([]core.Reference{}, message.References...)
	toolSummaries := append([]string{}, message.ToolSummaries...)
	tasks, _ := json.Marshal(taskIDs)
	plans, _ := json.Marshal(planIDs)
	references, _ := json.Marshal(referenceValues)
	summaries, _ := json.Marshal(toolSummaries)
	result, err := tx.Exec(ctx, `INSERT INTO core_messages(message_id,conversation_id,sequence,role,content,model_profile_id,
		payload_json,related_task_ids,related_plan_ids,references_json,tool_summaries,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(message_id) DO NOTHING`,
		message.ID, conversationID, sequence, message.Role, message.Content, message.ModelProfileID,
		payload, tasks, plans, references, summaries, message.CreatedAt)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var existingConversation, existingRole, existingContent string
	var existingSequence int64
	var existingProfile uuid.UUID
	var existingPayload []byte
	if err = tx.QueryRow(ctx, `SELECT conversation_id::text,sequence,role,content,model_profile_id,payload_json FROM core_messages WHERE message_id=$1`, message.ID).Scan(
		&existingConversation, &existingSequence, &existingRole, &existingContent, &existingProfile, &existingPayload); err != nil {
		return err
	}
	var expectedValue, existingValue any
	_ = json.Unmarshal(payload, &expectedValue)
	_ = json.Unmarshal(existingPayload, &existingValue)
	if existingConversation != conversationID || existingSequence != sequence || existingRole != string(message.Role) ||
		existingContent != message.Content || existingProfile.String() != message.ModelProfileID || !reflect.DeepEqual(expectedValue, existingValue) {
		return cloudworker.ErrConflict
	}
	return nil
}

func cloudWorkerReferences(plan cloudworker.Plan, execution cloudworker.Execution, binding coreconfirmation.Binding, confirmationRevision uint64, confirmationState string) []core.Reference {
	base := core.Reference{AccountGeneration: plan.AccountGeneration, TaskID: plan.TaskID, PlanID: plan.PlanID,
		PlanRevision: plan.Revision, PlanDigest: plan.Digest, RunID: execution.RunID, RunRevision: execution.Revision,
		RunDigest: execution.Digest, ExecutionID: execution.ExecutionID, ConfirmationID: plan.ConfirmationID,
		ConfirmationRevision: confirmationRevision, BindingDigest: string(binding.Digest), QuoteDigest: plan.Quote.Digest,
		ExecutionDigest: plan.ExecutionDigest}
	planReference, runReference, confirmationReference := base, base, base
	planReference.Kind, planReference.Status = "execution_plan", string(execution.State)
	runReference.Kind, runReference.Status = "execution_run", string(execution.State)
	confirmationReference.Kind, confirmationReference.State = "execution_confirmation", confirmationState
	return []core.Reference{planReference, runReference, confirmationReference}
}

func deterministicCloudWorkerUUID(domain, value string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(domain+":"+value)).String()
}

func digestCloudWorkerValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloudWorkerTaskTimeout(limits cloudworker.Limits) (int64, error) {
	if limits.MaxRuntimeSeconds == 0 || limits.MaxRuntimeSeconds > uint64(coretask.MaxTimeoutSeconds) ||
		cloudworker.EphemeralCleanupReserveSeconds > uint64(coretask.MaxTimeoutSeconds) ||
		limits.MaxRuntimeSeconds > uint64(coretask.MaxTimeoutSeconds)-cloudworker.EphemeralCleanupReserveSeconds {
		return 0, cloudworker.ErrInvalid
	}
	return int64(limits.MaxRuntimeSeconds + cloudworker.EphemeralCleanupReserveSeconds), nil
}

func (s *CloudWorkerStore) GetPlan(ctx context.Context, owner, id string, revision uint64) (cloudworker.Plan, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(id) {
		return cloudworker.Plan{}, cloudworker.ErrInvalid
	}
	plan, err := scanCloudWorkerPlan(s.store.pool.QueryRow(ctx, cloudWorkerPlanSelect+` WHERE plan_id=$1 AND ($2='' OR owner_id=$2) AND ($3=0 OR revision=$3)`, id, strings.TrimSpace(owner), revision))
	return plan, err
}

func (s *CloudWorkerStore) GetExecution(ctx context.Context, owner, id string) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(id) {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	return scanCloudWorkerExecution(s.store.pool.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1 AND ($2='' OR owner_id=$2)`, id, strings.TrimSpace(owner)))
}

type cloudWorkerListCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func (s *CloudWorkerStore) ListExecutions(ctx context.Context, owner, cursor string, limit int) ([]cloudworker.Execution, string, error) {
	if s == nil || s.store == nil || strings.TrimSpace(owner) == "" || limit < 1 || limit > 200 {
		return nil, "", cloudworker.ErrInvalid
	}
	var after cloudWorkerListCursor
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(raw, &after) != nil || after.CreatedAt.IsZero() || !coretask.ValidUUID(after.ID) {
			return nil, "", cloudworker.ErrInvalid
		}
	}
	rows, err := s.store.pool.Query(ctx, cloudWorkerExecutionSelect+` WHERE owner_id=$1 AND
		($2::timestamptz IS NULL OR (created_at,execution_id)<($2,$3::uuid))
		ORDER BY created_at DESC,execution_id DESC LIMIT $4`, strings.TrimSpace(owner), nullableTimePG(after.CreatedAt), nullableUUIDPG(after.ID), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([]cloudworker.Execution, 0, limit+1)
	for rows.Next() {
		execution, scanErr := scanCloudWorkerExecution(rows)
		if scanErr != nil {
			return nil, "", scanErr
		}
		result = append(result, execution)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(result) > limit {
		last := result[limit-1]
		result = result[:limit]
		raw, _ := json.Marshal(cloudWorkerListCursor{CreatedAt: last.CreatedAt, ID: last.ExecutionID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return result, next, nil
}

func nullableTimePG(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func (s *CloudWorkerStore) GetArtifact(ctx context.Context, owner, id string) (cloudworker.Artifact, error) {
	if s == nil || s.store == nil || strings.TrimSpace(owner) == "" || !coretask.ValidUUID(id) {
		return cloudworker.Artifact{}, cloudworker.ErrInvalid
	}
	var artifact cloudworker.Artifact
	var raw []byte
	err := s.store.pool.QueryRow(ctx, `SELECT a.artifact_json FROM core_cloud_worker_artifacts a
		JOIN core_cloud_worker_executions e ON e.execution_id=a.execution_id
		WHERE a.artifact_id=$1 AND e.owner_id=$2`, id, strings.TrimSpace(owner)).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return artifact, cloudworker.ErrNotFound
	}
	if err != nil {
		return artifact, err
	}
	if json.Unmarshal(raw, &artifact) != nil || artifact.ArtifactID != id || artifact.ExecutionID == "" {
		return cloudworker.Artifact{}, cloudworker.ErrConflict
	}
	return artifact, nil
}

func (s *CloudWorkerStore) Events(ctx context.Context, owner, id string, after uint64, limit int) ([]cloudworker.Event, uint64, error) {
	if s == nil || s.store == nil || strings.TrimSpace(owner) == "" || !coretask.ValidUUID(id) || limit < 1 || limit > 200 {
		return nil, 0, cloudworker.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT payload_json FROM core_cloud_worker_events WHERE execution_id=$1 AND owner_id=$2 AND sequence>$3 ORDER BY sequence LIMIT $4`, id, strings.TrimSpace(owner), after, limit)
	if err != nil {
		return nil, after, err
	}
	defer rows.Close()
	result := make([]cloudworker.Event, 0, limit)
	next := after
	for rows.Next() {
		var raw []byte
		var event cloudworker.Event
		if err = rows.Scan(&raw); err != nil || json.Unmarshal(raw, &event) != nil || event.ExecutionID != id || event.OwnerID != strings.TrimSpace(owner) || event.Sequence <= next {
			return nil, after, cloudworker.ErrConflict
		}
		result, next = append(result, event), event.Sequence
	}
	return result, next, rows.Err()
}

func validateCloudWorkerTaskFence(current, supplied coretask.Task, now time.Time) error {
	if current.ID != supplied.ID || current.Spec.Kind != coretask.TaskKindCloudWorker || current.Spec.Payload.CloudWorker == nil ||
		supplied.Spec.Kind != coretask.TaskKindCloudWorker || supplied.Spec.Payload.CloudWorker == nil ||
		current.Status != coretask.StatusRunning || supplied.Status != coretask.StatusRunning ||
		current.Attempt == 0 || current.Attempt != supplied.Attempt || current.LeaseEpoch == 0 ||
		current.LeaseEpoch != supplied.LeaseEpoch || current.Revision != supplied.Revision ||
		current.Lease == nil || supplied.Lease == nil || current.Lease.Holder != supplied.Lease.Holder ||
		current.Lease.Epoch != supplied.Lease.Epoch || !current.Lease.ExpiresAt.After(now) ||
		!reflect.DeepEqual(current.Spec.Payload.CloudWorker, supplied.Spec.Payload.CloudWorker) {
		return cloudworker.ErrLeaseConflict
	}
	return nil
}

func (s *CloudWorkerStore) GetControllerContext(ctx context.Context, supplied coretask.Task) (cloudworker.ControllerContext, error) {
	if s == nil || s.store == nil || supplied.Lease == nil || supplied.Spec.Payload.CloudWorker == nil {
		return cloudworker.ControllerContext{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.ControllerContext{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.ControllerContext{}, cloudworker.ErrLeaseConflict
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.ControllerContext{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.ControllerContext{}, err
	}
	return cloudworker.ControllerContext{Plan: plan, Execution: execution}, nil
}

func cloudWorkerPlanAndExecutionTx(ctx context.Context, tx pgx.Tx, payload *coretask.CloudWorkerTaskPayload, lock bool) (cloudworker.Plan, cloudworker.Execution, error) {
	if payload == nil {
		return cloudworker.Plan{}, cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	lockSQL := ""
	if lock {
		lockSQL = " FOR UPDATE"
	}
	plan, err := scanCloudWorkerPlan(tx.QueryRow(ctx, cloudWorkerPlanSelect+` WHERE plan_id=$1 AND revision=$2`+lockSQL, payload.PlanID, payload.PlanRevision))
	if err != nil {
		return cloudworker.Plan{}, cloudworker.Execution{}, err
	}
	execution, err := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1`+lockSQL, payload.ExecutionID))
	if err != nil {
		return cloudworker.Plan{}, cloudworker.Execution{}, err
	}
	if plan.ExecutionID != payload.ExecutionID || plan.TaskID == "" || plan.ConfirmationID != payload.ConfirmationID ||
		plan.Digest != payload.PlanDigest || plan.Quote.Digest != payload.QuoteDigest ||
		plan.ExecutionDigest != payload.ExecutionDigest || plan.AccountGeneration != payload.AccountGeneration ||
		plan.TurnID != payload.TurnID || plan.ConversationID != payload.ConversationID ||
		execution.ExecutionID != plan.ExecutionID || execution.PlanDigest != plan.Digest ||
		execution.ExecutionDigest != plan.ExecutionDigest || execution.TaskID != plan.TaskID ||
		execution.ConfirmationID != plan.ConfirmationID {
		return cloudworker.Plan{}, cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	return plan, execution, nil
}

func (s *CloudWorkerStore) BeginExecution(ctx context.Context, supplied coretask.Task) (cloudworker.BeginResult, error) {
	if s == nil || s.store == nil || supplied.Spec.Payload.CloudWorker == nil || supplied.Lease == nil {
		return cloudworker.BeginResult{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.BeginResult{}, err
	}
	defer tx.Rollback(ctx)
	current, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil {
		return cloudworker.BeginResult{}, cloudworker.ErrLeaseConflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err = validateCloudWorkerTaskFence(current, supplied, now); err != nil {
		return cloudworker.BeginResult{}, err
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, current.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.BeginResult{}, err
	}
	if plan.TaskID != current.ID || !plan.Quote.ExpiresAt.After(now) {
		return cloudworker.BeginResult{}, cloudworker.ErrQuoteExpired
	}
	expectedBinding, err := cloudworker.BindingForPlan(plan)
	if err != nil {
		return cloudworker.BeginResult{}, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
	if err != nil {
		return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
	}
	var immutableRaw, currentRaw []byte
	if err = tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_target_bindings WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID).Scan(&immutableRaw); err != nil {
		return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
	}
	if err = tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2 FOR UPDATE`, expectedBinding.OperationDomain, expectedBinding.TargetID).Scan(&currentRaw); err != nil {
		return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
	}
	var immutable, authoritative coreconfirmation.Binding
	if json.Unmarshal(immutableRaw, &immutable) != nil || json.Unmarshal(currentRaw, &authoritative) != nil ||
		!immutable.Equal(expectedBinding) || !authoritative.Equal(expectedBinding) || !confirmation.Binding.Equal(expectedBinding) {
		return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
	}

	var stored cloudworker.LaunchPrerequisite
	var storedTaskID, storedConfirmationID string
	storedErr := tx.QueryRow(ctx, `SELECT task_id::text,task_attempt,lease_epoch,account_generation,confirmation_id::text,
		confirmation_revision,confirmation_binding_digest,confirmed_at
		FROM core_cloud_worker_begin_authorizations WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(
		&storedTaskID, &stored.TaskAttempt, &stored.LeaseEpoch, &stored.AccountGeneration, &storedConfirmationID,
		&stored.ConfirmationRevision, &stored.ConfirmationBindingDigest, &stored.ConfirmedAt)
	if storedErr == nil {
		stored.ConfirmedAt = stored.ConfirmedAt.UTC()
		if storedTaskID != plan.TaskID || storedConfirmationID != plan.ConfirmationID || validateLaunchPrerequisiteForStore(stored, plan, string(expectedBinding.Digest)) != nil {
			return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
		}
		if stored.TaskAttempt == current.Attempt && stored.LeaseEpoch == current.LeaseEpoch {
			if confirmation.State != coreconfirmation.StateConsumed || execution.State != cloudworker.StateProvisioning {
				return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
			}
			if err = tx.Commit(ctx); err != nil {
				return cloudworker.BeginResult{}, err
			}
			return cloudworker.BeginResult{Plan: plan, Execution: execution, Prerequisite: stored}, nil
		}
		var launchCount int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_launch_material WHERE execution_id=$1`, plan.ExecutionID).Scan(&launchCount); err != nil || launchCount != 0 || execution.ProviderMutationStarted || confirmation.State != coreconfirmation.StateConsumed {
			return cloudworker.BeginResult{}, cloudworker.ErrLeaseConflict
		}
		stored.TaskAttempt, stored.LeaseEpoch = current.Attempt, current.LeaseEpoch
		if _, err = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET acquired_attempt=$2,acquired_lease_epoch=$3,task_revision=$4,active=true WHERE confirmation_id=$1`, plan.ConfirmationID, current.Attempt, current.LeaseEpoch, current.Revision); err != nil {
			return cloudworker.BeginResult{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE core_cloud_worker_begin_authorizations SET task_attempt=$2,lease_epoch=$3,created_at=$4 WHERE execution_id=$1`, plan.ExecutionID, current.Attempt, current.LeaseEpoch, now); err != nil {
			return cloudworker.BeginResult{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.BeginResult{}, err
		}
		return cloudworker.BeginResult{Plan: plan, Execution: execution, Prerequisite: stored}, nil
	}
	if !errors.Is(storedErr, pgx.ErrNoRows) {
		return cloudworker.BeginResult{}, storedErr
	}
	if confirmation.State != coreconfirmation.StateConfirmed || execution.State != cloudworker.StateQueued {
		return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
	}
	confirmedAt := confirmation.UpdatedAt.UTC()
	confirmationRevision := confirmation.Revision + 1
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=$2 WHERE confirmation_id=$1 AND state='confirmed' AND revision=$3`, plan.ConfirmationID, now, confirmation.Revision); err != nil {
		return cloudworker.BeginResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_reservations(confirmation_id,task_id,acquired_attempt,acquired_lease_epoch,task_revision,active)
		VALUES($1,$2,$3,$4,$5,true)`, plan.ConfirmationID, plan.TaskID, current.Attempt, current.LeaseEpoch, current.Revision); err != nil {
		return cloudworker.BeginResult{}, err
	}
	next, err := execution.Transition(cloudworker.StateProvisioning, now)
	if err != nil {
		return cloudworker.BeginResult{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, next, "execution_started"); err != nil {
		return cloudworker.BeginResult{}, err
	}
	prerequisite := cloudworker.LaunchPrerequisite{ConfirmationBindingDigest: string(expectedBinding.Digest),
		ConfirmationRevision: confirmationRevision, ConfirmedAt: confirmedAt,
		TaskAttempt: current.Attempt, LeaseEpoch: current.LeaseEpoch, AccountGeneration: plan.AccountGeneration}
	if validateLaunchPrerequisiteForStore(prerequisite, plan, string(expectedBinding.Digest)) != nil {
		return cloudworker.BeginResult{}, cloudworker.ErrStaleAuthorization
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_begin_authorizations(execution_id,task_id,task_attempt,lease_epoch,
		account_generation,confirmation_id,confirmation_revision,confirmation_binding_digest,confirmed_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, plan.ExecutionID, plan.TaskID, current.Attempt,
		current.LeaseEpoch, plan.AccountGeneration, plan.ConfirmationID, confirmationRevision,
		prerequisite.ConfirmationBindingDigest, prerequisite.ConfirmedAt, now); err != nil {
		return cloudworker.BeginResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.BeginResult{}, err
	}
	return cloudworker.BeginResult{Plan: plan, Execution: next, Prerequisite: prerequisite}, nil
}

func saveCloudWorkerExecutionTx(ctx context.Context, tx pgx.Tx, previous, next cloudworker.Execution, eventType string) error {
	if next.Revision != previous.Revision+1 || next.ExecutionID != previous.ExecutionID || next.Seal() != nil {
		return cloudworker.ErrInvalid
	}
	raw, err := marshalCloudWorkerExecution(next)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_executions SET state=$2,revision=$3,digest=$4,
		provider_mutation_started=$5,terminal_intent=$6,needs_reconcile=$7,execution_json=$8,updated_at=$9
		WHERE execution_id=$1 AND revision=$10 AND digest=$11`, next.ExecutionID, next.State, next.Revision, next.Digest,
		next.ProviderMutationStarted, next.TerminalIntent, next.NeedsReconcile, raw, next.UpdatedAt,
		previous.Revision, previous.Digest)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return cloudworker.ErrRevisionConflict
	}
	var sequence uint64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_cloud_worker_events WHERE execution_id=$1`, next.ExecutionID).Scan(&sequence); err != nil {
		return err
	}
	event := cloudworker.Event{OwnerID: next.OwnerID, AccountGeneration: next.AccountGeneration,
		RunID: next.RunID, ExecutionID: next.ExecutionID,
		Sequence: sequence, EventID: deterministicCloudWorkerUUID(eventType, fmt.Sprintf("%s:%d", next.ExecutionID, next.Revision)),
		Type: eventType, State: next.State, Revision: next.Revision, CreatedAt: next.UpdatedAt}
	event.PayloadDigest = digestCloudWorkerValue(struct {
		State    cloudworker.ExecutionState
		Revision uint64
	}{next.State, next.Revision})
	payloadRaw, _ := json.Marshal(event)
	_, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_events(execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, next.ExecutionID, sequence, event.EventID, next.OwnerID,
		event.Type, event.State, event.Revision, event.PayloadDigest, payloadRaw, event.CreatedAt)
	return err
}

func (s *CloudWorkerStore) AuthorizeLaunch(ctx context.Context, command cloudworker.AuthorizeLaunchCommand) (cloudworker.LaunchAuthorization, error) {
	if s == nil || s.store == nil || command.Task.Lease == nil || command.ExpectedExecutionRevision == 0 {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	defer tx.Rollback(ctx)
	current, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, command.Task.ID, false)
	if err != nil {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrLeaseConflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err = validateCloudWorkerTaskFence(current, command.Task, now); err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, current.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	if execution.Revision != command.ExpectedExecutionRevision || execution.State != cloudworker.StateProvisioning || !plan.Quote.ExpiresAt.After(now) {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	expectedBinding, err := cloudworker.BindingForPlan(plan)
	if err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
	if err != nil || confirmation.State != coreconfirmation.StateConsumed || !confirmation.Binding.Equal(expectedBinding) {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	var reservationAttempt int
	var reservationEpoch, reservationRevision int64
	var reservationActive bool
	if err = tx.QueryRow(ctx, `SELECT acquired_attempt,acquired_lease_epoch,task_revision,active FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID).Scan(&reservationAttempt, &reservationEpoch, &reservationRevision, &reservationActive); err != nil || !reservationActive || reservationAttempt != int(current.Attempt) || reservationEpoch != int64(current.LeaseEpoch) || reservationRevision != int64(current.Revision) {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	var prerequisite cloudworker.LaunchPrerequisite
	var beginTaskID, beginConfirmationID string
	if err = tx.QueryRow(ctx, `SELECT task_id::text,task_attempt,lease_epoch,account_generation,confirmation_id::text,
		confirmation_revision,confirmation_binding_digest,confirmed_at FROM core_cloud_worker_begin_authorizations
		WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(&beginTaskID, &prerequisite.TaskAttempt,
		&prerequisite.LeaseEpoch, &prerequisite.AccountGeneration, &beginConfirmationID,
		&prerequisite.ConfirmationRevision, &prerequisite.ConfirmationBindingDigest, &prerequisite.ConfirmedAt); err != nil {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	prerequisite.ConfirmedAt = prerequisite.ConfirmedAt.UTC()
	if beginTaskID != plan.TaskID || beginConfirmationID != plan.ConfirmationID || prerequisite.TaskAttempt != current.Attempt || prerequisite.LeaseEpoch != current.LeaseEpoch || validateLaunchPrerequisiteForStore(prerequisite, plan, string(expectedBinding.Digest)) != nil {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	fence := cloudworker.RuntimeTaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID,
		AccountGeneration: plan.AccountGeneration, Attempt: current.Attempt, LeaseEpoch: current.LeaseEpoch}
	rebuilt, err := cloudworker.BuildRuntimeTask(plan, execution, command.StagedManifest, fence, command.Qualification)
	if err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	defer rebuilt.Destroy()
	material := command.Material
	if material.Task != rebuilt.Task || material.RuntimeTaskSHA256 != rebuilt.RuntimeTaskSHA256 ||
		material.InputManifestSHA256 != rebuilt.InputManifestSHA256 || material.SourceManifestSHA256 != rebuilt.SourceManifestSHA256 ||
		material.StagedManifestSHA256 != rebuilt.StagedManifestSHA256 || material.Fence != rebuilt.Fence ||
		!bytes.Equal(material.RuntimeTaskJSON, rebuilt.RuntimeTaskJSON) || !bytes.Equal(material.InputManifestJSON, rebuilt.InputManifestJSON) {
		return cloudworker.LaunchAuthorization{}, cloudworker.ErrStaleAuthorization
	}
	stagedRaw, err := command.StagedManifest.CanonicalJSON(plan.InputManifest)
	if err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	qualificationRaw, _ := json.Marshal(command.Qualification)
	authorization := cloudworker.LaunchAuthorization{LaunchPrerequisite: prerequisite,
		RuntimeTaskSHA256: rebuilt.RuntimeTaskSHA256, InputManifestSHA256: rebuilt.InputManifestSHA256,
		StagedManifestSHA256: rebuilt.StagedManifestSHA256, AuthorizedAt: now}
	var stored struct {
		RuntimeTaskSHA256, InputManifestSHA256, StagedManifestSHA256 string
		TaskAttempt                                                  uint32
		LeaseEpoch                                                   uint64
		AuthorizedAt                                                 time.Time
		RuntimeRaw, InputRaw, StagedRaw, QualificationRaw            []byte
	}
	storedErr := tx.QueryRow(ctx, `SELECT task_attempt,lease_epoch,runtime_task_sha256,input_manifest_sha256,
		staged_manifest_sha256,authorized_at,runtime_task_json,input_manifest_json,staged_manifest_json,qualification_json
		FROM core_cloud_worker_launch_material WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(
		&stored.TaskAttempt, &stored.LeaseEpoch, &stored.RuntimeTaskSHA256, &stored.InputManifestSHA256,
		&stored.StagedManifestSHA256, &stored.AuthorizedAt, &stored.RuntimeRaw, &stored.InputRaw, &stored.StagedRaw, &stored.QualificationRaw)
	if storedErr == nil {
		if stored.TaskAttempt != current.Attempt || stored.LeaseEpoch != current.LeaseEpoch ||
			stored.RuntimeTaskSHA256 != rebuilt.RuntimeTaskSHA256 || stored.InputManifestSHA256 != rebuilt.InputManifestSHA256 ||
			stored.StagedManifestSHA256 != rebuilt.StagedManifestSHA256 || !bytes.Equal(stored.RuntimeRaw, rebuilt.RuntimeTaskJSON) ||
			!bytes.Equal(stored.InputRaw, rebuilt.InputManifestJSON) || !jsonEquivalent(stored.StagedRaw, stagedRaw) ||
			!jsonEquivalent(stored.QualificationRaw, qualificationRaw) {
			return cloudworker.LaunchAuthorization{}, cloudworker.ErrConflict
		}
		authorization.AuthorizedAt = stored.AuthorizedAt.UTC()
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.LaunchAuthorization{}, err
		}
		return authorization, nil
	}
	if !errors.Is(storedErr, pgx.ErrNoRows) {
		return cloudworker.LaunchAuthorization{}, storedErr
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_launch_material(execution_id,plan_id,plan_revision,
		execution_revision,task_id,task_attempt,lease_epoch,account_generation,confirmation_id,confirmation_revision,
		confirmation_binding_digest,confirmed_at,source_manifest_sha256,staged_manifest_sha256,input_manifest_sha256,
		runtime_task_sha256,staged_manifest_json,input_manifest_json,runtime_task_json,qualification_json,authorized_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		plan.ExecutionID, plan.PlanID, plan.Revision, execution.Revision, plan.TaskID, current.Attempt,
		current.LeaseEpoch, plan.AccountGeneration, plan.ConfirmationID, prerequisite.ConfirmationRevision,
		prerequisite.ConfirmationBindingDigest, prerequisite.ConfirmedAt, rebuilt.SourceManifestSHA256,
		rebuilt.StagedManifestSHA256, rebuilt.InputManifestSHA256, rebuilt.RuntimeTaskSHA256, stagedRaw,
		rebuilt.InputManifestJSON, rebuilt.RuntimeTaskJSON, qualificationRaw, now); err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.LaunchAuthorization{}, err
	}
	return authorization, nil
}

func (s *CloudWorkerStore) GetResumeContext(ctx context.Context, supplied coretask.Task) (cloudworker.ResumeContext, error) {
	if s == nil || s.store == nil || supplied.Spec.Payload.CloudWorker == nil || supplied.Lease == nil {
		return cloudworker.ResumeContext{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.ResumeContext{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.ResumeContext{}, cloudworker.ErrLeaseConflict
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.ResumeContext{}, err
	}
	if execution.State == cloudworker.StateWaitingUser || execution.State == cloudworker.StateQueued ||
		execution.State == cloudworker.StateSucceeded || execution.State == cloudworker.StateFailed || execution.State == cloudworker.StateCanceled ||
		execution.State == cloudworker.StateRejected || execution.State == cloudworker.StateExpired {
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	var authorization cloudworker.LaunchAuthorization
	var stagedRaw, inputRaw, runtimeRaw, qualificationRaw, identityRaw []byte
	var sourceDigest, launchIdentity, intentDigest string
	err = tx.QueryRow(ctx, `SELECT task_attempt,lease_epoch,account_generation,confirmation_revision,
		confirmation_binding_digest,confirmed_at,runtime_task_sha256,input_manifest_sha256,staged_manifest_sha256,
		authorized_at,source_manifest_sha256,staged_manifest_json,input_manifest_json,runtime_task_json,qualification_json,
		launch_identity,intent_digest,aws_identity_json
		FROM core_cloud_worker_launch_material WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(
		&authorization.TaskAttempt, &authorization.LeaseEpoch, &authorization.AccountGeneration,
		&authorization.ConfirmationRevision, &authorization.ConfirmationBindingDigest, &authorization.ConfirmedAt,
		&authorization.RuntimeTaskSHA256, &authorization.InputManifestSHA256, &authorization.StagedManifestSHA256,
		&authorization.AuthorizedAt, &sourceDigest, &stagedRaw, &inputRaw, &runtimeRaw, &qualificationRaw,
		&launchIdentity, &intentDigest, &identityRaw)
	if err != nil {
		return cloudworker.ResumeContext{}, cloudworker.ErrStaleAuthorization
	}
	authorization.ConfirmedAt, authorization.AuthorizedAt = authorization.ConfirmedAt.UTC(), authorization.AuthorizedAt.UTC()
	binding, err := cloudworker.BindingForPlan(plan)
	if err != nil || validateLaunchPrerequisiteForStore(authorization.LaunchPrerequisite, plan, string(binding.Digest)) != nil {
		return cloudworker.ResumeContext{}, cloudworker.ErrStaleAuthorization
	}
	var staged cloudworker.StagedInputManifest
	if json.Unmarshal(stagedRaw, &staged) != nil {
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	stagedDigest, err := staged.Seal(plan.InputManifest)
	if err != nil || stagedDigest != authorization.StagedManifestSHA256 {
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	var qualification cloudworker.RuntimeQualification
	if json.Unmarshal(qualificationRaw, &qualification) != nil {
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	material := cloudworker.RuntimeTaskMaterial{RuntimeTaskJSON: bytes.Clone(runtimeRaw), RuntimeTaskSHA256: authorization.RuntimeTaskSHA256,
		InputManifestJSON: bytes.Clone(inputRaw), InputManifestSHA256: authorization.InputManifestSHA256,
		SourceManifestSHA256: sourceDigest, StagedManifestSHA256: authorization.StagedManifestSHA256,
		Fence: cloudworker.RuntimeTaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID,
			AccountGeneration: plan.AccountGeneration, Attempt: authorization.TaskAttempt, LeaseEpoch: authorization.LeaseEpoch}}
	if json.Unmarshal(runtimeRaw, &material.Task) != nil || material.Task.ExecutionID != plan.ExecutionID || material.Task.TaskID != plan.TaskID {
		material.Destroy()
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	runtimeDigest, digestErr := material.Task.Digest()
	inputDigest := sha256.Sum256(inputRaw)
	if digestErr != nil || runtimeDigest != authorization.RuntimeTaskSHA256 || hex.EncodeToString(inputDigest[:]) != authorization.InputManifestSHA256 || sourceDigest != plan.InputManifestDigest {
		material.Destroy()
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	// MarkDispatchPrepared updates the launch columns and execution flag in one
	// transaction. The only valid pre-mark form is therefore the all-empty
	// launch tuple paired with provider_mutation_started=false.
	dispatchPrepared := launchIdentity != "" || intentDigest != "" || jsonValuePresent(identityRaw)
	if dispatchPrepared != execution.ProviderMutationStarted ||
		(dispatchPrepared && (!coretask.ValidDigest(launchIdentity) || !coretask.ValidDigest(intentDigest))) {
		material.Destroy()
		return cloudworker.ResumeContext{}, cloudworker.ErrConflict
	}
	var storedIdentity cloudaws.ExecutionIdentity
	if dispatchPrepared {
		if json.Unmarshal(identityRaw, &storedIdentity) != nil || storedIdentity.Validate() != nil ||
			storedIdentity.LaunchIdentity != launchIdentity || storedIdentity.ExecutionID != plan.ExecutionID ||
			storedIdentity.TaskID != plan.TaskID || storedIdentity.TaskAttempt != authorization.TaskAttempt ||
			storedIdentity.LeaseEpoch != authorization.LeaseEpoch {
			material.Destroy()
			return cloudworker.ResumeContext{}, cloudworker.ErrConflict
		}
	}

	// Provider.Prepare can commit the ledger before MarkDispatchPrepared commits
	// the Core CAS. Read by the immutable owner/execution scope and then compare
	// every typed identity/digest with the canonical dispatch rebuilt at the
	// original recorded_at. A missing ledger is valid only before the Core mark.
	ledger, ledgerErr := loadCloudWorkerAWSRecordTx(ctx, tx, plan)
	if ledgerErr != nil && !errors.Is(ledgerErr, pgx.ErrNoRows) {
		material.Destroy()
		return cloudworker.ResumeContext{}, ledgerErr
	}
	var resources []cloudworker.Resource
	if ledgerErr == nil {
		expectedAWSPlan, expectedIntent, buildErr := cloudworker.BuildAWSDispatch(
			plan, execution, authorization, staged, material, plan.Quote, ledger.Intent.RecordedAt,
		)
		if buildErr != nil || !reflect.DeepEqual(ledger.Plan, expectedAWSPlan) ||
			!reflect.DeepEqual(ledger.Intent, expectedIntent) || !ledger.Identity.Equal(expectedAWSPlan.Identity) {
			material.Destroy()
			return cloudworker.ResumeContext{}, cloudworker.ErrConflict
		}
		if dispatchPrepared && (!ledger.Identity.Equal(storedIdentity) || ledger.Intent.IntentDigest != intentDigest) {
			material.Destroy()
			return cloudworker.ResumeContext{}, cloudworker.ErrConflict
		}
		resources, err = loadCloudWorkerResourcesTx(ctx, tx, plan, ledger.Identity)
		if err != nil {
			material.Destroy()
			return cloudworker.ResumeContext{}, err
		}
	} else if dispatchPrepared {
		material.Destroy()
		return cloudworker.ResumeContext{}, cloudworker.ErrStaleAuthorization
	} else {
		// No durable AWS intent means no Core resource projection can exist.
		var resourceCount int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=$1`, plan.ExecutionID).Scan(&resourceCount); err != nil || resourceCount != 0 {
			material.Destroy()
			if err != nil {
				return cloudworker.ResumeContext{}, err
			}
			return cloudworker.ResumeContext{}, cloudworker.ErrConflict
		}
	}
	resume := cloudworker.ResumeContext{Plan: plan, Execution: execution, InitialAuthorization: authorization,
		StagedManifest: staged, Qualification: qualification, Material: material, DispatchPrepared: dispatchPrepared,
		AWSRecord: ledger, Resources: resources,
		CurrentFence: cloudworker.RuntimeTaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID,
			AccountGeneration: plan.AccountGeneration, Attempt: currentTask.Attempt, LeaseEpoch: currentTask.LeaseEpoch}}
	if err = tx.Commit(ctx); err != nil {
		resume.Destroy()
		return cloudworker.ResumeContext{}, err
	}
	return resume, nil
}

// loadCloudWorkerAWSRecordTx revalidates the repeated immutable owner and
// dispatch columns before trusting record_json. Mutable labels or an
// execution UUID alone are never an authorization or cleanup boundary.
func loadCloudWorkerAWSRecordTx(ctx context.Context, tx pgx.Tx, plan cloudworker.Plan) (cloudaws.LedgerRecord, error) {
	var record cloudaws.LedgerRecord
	var identityKey, ownerID, accountID, region, executionID, taskID, providerID, launchIdentity string
	var planDigest, infrastructureDigest, intentDigest, state string
	var accountGeneration, attempt, epoch, generation, revision uint64
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT identity_key,owner_id,account_id,account_generation,region,execution_id::text,
		task_id::text,task_attempt,lease_epoch,provider_id,launch_identity,generation,plan_digest,
		infrastructure_digest,intent_digest,state,revision,record_json
		FROM core_cloud_worker_aws_ledger WHERE execution_id=$1 AND owner_id=$2 AND account_id=$3
		AND account_generation=$4 AND region=$5 FOR UPDATE`, plan.ExecutionID, plan.OwnerID, plan.AWS.AccountID,
		plan.AccountGeneration, plan.AWS.Region).Scan(&identityKey, &ownerID, &accountID, &accountGeneration,
		&region, &executionID, &taskID, &attempt, &epoch, &providerID, &launchIdentity, &generation,
		&planDigest, &infrastructureDigest, &intentDigest, &state, &revision, &raw)
	if err != nil {
		return cloudaws.LedgerRecord{}, err
	}
	if json.Unmarshal(raw, &record) != nil || record.Validate() != nil || identityKey == "" ||
		ownerID != record.Identity.OwnerID || accountID != record.Identity.AccountID ||
		accountGeneration != record.Identity.AccountGeneration || region != record.Identity.Region ||
		executionID != record.Identity.ExecutionID || taskID != record.Identity.TaskID ||
		attempt != uint64(record.Identity.TaskAttempt) || epoch != record.Identity.LeaseEpoch ||
		providerID != record.Identity.ProviderID || launchIdentity != record.Identity.LaunchIdentity ||
		generation != record.Identity.Generation || planDigest != record.Plan.Digest ||
		infrastructureDigest != record.Plan.InfrastructureDigest || intentDigest != record.Intent.IntentDigest ||
		state != string(record.State) || revision != record.Revision ||
		record.Identity.OwnerID != plan.OwnerID || record.Identity.AccountID != plan.AWS.AccountID ||
		record.Identity.AccountGeneration != plan.AccountGeneration || record.Identity.Region != plan.AWS.Region ||
		record.Identity.ExecutionID != plan.ExecutionID || record.Identity.TaskID != plan.TaskID ||
		record.Identity.TaskAttempt == 0 || record.Identity.LeaseEpoch == 0 || record.Identity.Generation != plan.Revision {
		return cloudaws.LedgerRecord{}, cloudworker.ErrConflict
	}
	return record, nil
}

func loadCloudWorkerResourcesTx(ctx context.Context, tx pgx.Tx, plan cloudworker.Plan, identity cloudaws.ExecutionIdentity) ([]cloudworker.Resource, error) {
	rows, err := tx.Query(ctx, `SELECT resource_id::text,account_generation,provider,kind,provider_id,account_id,region,
		launch_identity,state,revision,resource_json,created_at,updated_at,verified_at
		FROM core_cloud_worker_resources WHERE execution_id=$1 ORDER BY kind FOR UPDATE`, plan.ExecutionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKind := make(map[string]cloudworker.Resource, len(cloudaws.AllResourceKinds()))
	for rows.Next() {
		var typed cloudworker.Resource
		var raw []byte
		var state string
		var verified *time.Time
		if err = rows.Scan(&typed.ResourceID, &typed.AccountGeneration, &typed.Provider, &typed.Kind, &typed.ProviderID,
			&typed.AccountID, &typed.Region, &typed.LaunchIdentity, &state, &typed.Revision, &raw,
			&typed.CreatedAt, &typed.UpdatedAt, &verified); err != nil {
			return nil, err
		}
		typed.ExecutionID, typed.State = plan.ExecutionID, cloudworker.ResourceState(state)
		if verified != nil {
			at := verified.UTC()
			typed.VerifiedAt = &at
		}
		typed.CreatedAt, typed.UpdatedAt = typed.CreatedAt.UTC(), typed.UpdatedAt.UTC()
		var projected cloudworker.Resource
		expectedID := deterministicCloudWorkerUUID("cloud-worker-aws-resource", plan.ExecutionID+":"+typed.Kind)
		if json.Unmarshal(raw, &projected) != nil || !reflect.DeepEqual(projected, typed) || !cloudWorkerResourceKind(typed.Kind) ||
			typed.ValidateObservedAddresses() != nil ||
			typed.ResourceID != expectedID || typed.AccountGeneration != plan.AccountGeneration || typed.Provider != "aws" ||
			typed.AccountID != plan.AWS.AccountID || typed.Region != plan.AWS.Region || typed.LaunchIdentity != identity.LaunchIdentity ||
			typed.Revision == 0 || typed.UpdatedAt.Before(typed.CreatedAt) ||
			(typed.State == cloudworker.ResourceVerifiedDestroyed) != (typed.VerifiedAt != nil) ||
			typed.State == cloudworker.ResourceCreated && typed.ProviderID == "" {
			return nil, cloudworker.ErrConflict
		}
		if _, duplicate := byKind[typed.Kind]; duplicate {
			return nil, cloudworker.ErrConflict
		}
		byKind[typed.Kind] = typed
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(byKind) == 0 {
		return nil, nil
	}
	if len(byKind) != len(cloudaws.AllResourceKinds()) {
		return nil, cloudworker.ErrConflict
	}
	resources := make([]cloudworker.Resource, 0, len(byKind))
	for _, kind := range cloudaws.AllResourceKinds() {
		resource, ok := byKind[string(kind)]
		if !ok {
			return nil, cloudworker.ErrConflict
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func jsonEquivalent(left, right []byte) bool {
	var a, b any
	return json.Unmarshal(left, &a) == nil && json.Unmarshal(right, &b) == nil && reflect.DeepEqual(a, b)
}

func jsonValuePresent(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null"))
}

func validateLaunchPrerequisiteForStore(value cloudworker.LaunchPrerequisite, plan cloudworker.Plan, bindingDigest string) error {
	if !coretask.ValidDigest(value.ConfirmationBindingDigest) || value.ConfirmationBindingDigest != bindingDigest ||
		value.ConfirmationRevision < 3 || value.ConfirmedAt.IsZero() || value.ConfirmedAt.Location() != time.UTC ||
		value.TaskAttempt == 0 || value.LeaseEpoch == 0 || value.AccountGeneration != plan.AccountGeneration {
		return cloudworker.ErrStaleAuthorization
	}
	return nil
}

func (s *CloudWorkerStore) TransitionExecution(ctx context.Context, supplied coretask.Task, expectedRevision uint64, nextState cloudworker.ExecutionState) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || supplied.Lease == nil || supplied.Spec.Payload.CloudWorker == nil || expectedRevision == 0 {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.Execution{}, cloudworker.ErrLeaseConflict
	}
	_, current, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if current.Revision != expectedRevision {
		return cloudworker.Execution{}, cloudworker.ErrRevisionConflict
	}
	if current.TerminalIntent == string(cloudworker.StateCanceled) && nextState != cloudworker.StateCleaning {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	next, err := current.Transition(nextState, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, current, next, "state_changed"); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

func (s *CloudWorkerStore) RecordResources(ctx context.Context, supplied coretask.Task, expectedRevision uint64, resources []cloudworker.Resource, nextState cloudworker.ExecutionState) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || supplied.Lease == nil || supplied.Spec.Payload.CloudWorker == nil ||
		expectedRevision == 0 || len(resources) != len(cloudaws.AllResourceKinds()) {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.Execution{}, cloudworker.ErrLeaseConflict
	}
	plan, current, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if current.Revision != expectedRevision {
		return cloudworker.Execution{}, cloudworker.ErrRevisionConflict
	}
	if current.TerminalIntent == string(cloudworker.StateCanceled) && current.State != cloudworker.StateCleaning && nextState != cloudworker.StateCleaning {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	executionID := current.ExecutionID
	seen := make(map[string]struct{}, len(resources))
	provider, launchIdentity := "", ""
	for _, resource := range resources {
		expectedResourceID := deterministicCloudWorkerUUID("cloud-worker-aws-resource", executionID+":"+resource.Kind)
		if !cloudWorkerResourceKind(resource.Kind) || resource.ResourceID != expectedResourceID || resource.ExecutionID != executionID ||
			resource.AccountGeneration != plan.AccountGeneration || (resource.Provider != "aws" && resource.Provider != "fake") ||
			len(resource.ProviderID) > 2048 || resource.AccountID != plan.AWS.AccountID || resource.Region != plan.AWS.Region ||
			!coretask.ValidDigest(resource.LaunchIdentity) ||
			resource.Revision == 0 || resource.CreatedAt.IsZero() || resource.UpdatedAt.IsZero() || resource.UpdatedAt.Before(resource.CreatedAt) ||
			(resource.State != cloudworker.ResourcePlanned && resource.State != cloudworker.ResourceCreated && resource.State != cloudworker.ResourceDeleteRequested && resource.State != cloudworker.ResourceVerifiedDestroyed) ||
			(resource.State == cloudworker.ResourceVerifiedDestroyed) != (resource.VerifiedAt != nil) ||
			(resource.State == cloudworker.ResourceCreated && resource.ProviderID == "") || resource.ValidateObservedAddresses() != nil {
			return cloudworker.Execution{}, cloudworker.ErrInvalid
		}
		if provider == "" {
			provider, launchIdentity = resource.Provider, resource.LaunchIdentity
		} else if provider != resource.Provider || launchIdentity != resource.LaunchIdentity {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		if _, duplicate := seen[resource.Kind]; duplicate {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		seen[resource.Kind] = struct{}{}
		raw, _ := json.Marshal(resource)
		var oldRaw []byte
		var oldResourceID, oldProviderID string
		var oldRevision uint64
		readErr := tx.QueryRow(ctx, `SELECT resource_id::text,provider_id,resource_json,revision
			FROM core_cloud_worker_resources WHERE execution_id=$1 AND kind=$2 FOR UPDATE`, executionID, resource.Kind).Scan(
			&oldResourceID, &oldProviderID, &oldRaw, &oldRevision)
		if readErr == nil {
			var old cloudworker.Resource
			if json.Unmarshal(oldRaw, &old) != nil || oldResourceID != resource.ResourceID || old.ResourceID != resource.ResourceID ||
				old.ExecutionID != executionID || old.AccountGeneration != resource.AccountGeneration || old.Provider != resource.Provider ||
				old.Kind != resource.Kind || old.AccountID != resource.AccountID || old.Region != resource.Region ||
				old.LaunchIdentity != resource.LaunchIdentity || oldProviderID != old.ProviderID ||
				(oldProviderID != "" && resource.ProviderID != oldProviderID) ||
				(oldProviderID != "" && resource.ProviderID == "") || !validCloudWorkerResourceTransition(old.State, resource.State) ||
				!old.CreatedAt.Equal(resource.CreatedAt) ||
				(resource.Revision != oldRevision && resource.Revision != oldRevision+1) {
				return cloudworker.Execution{}, cloudworker.ErrConflict
			}
			if resource.Revision == oldRevision {
				if !jsonEquivalent(oldRaw, raw) {
					return cloudworker.Execution{}, cloudworker.ErrConflict
				}
				continue
			}
			updated, updateErr := tx.Exec(ctx, `UPDATE core_cloud_worker_resources SET provider_id=$2,state=$3,revision=$4,
				resource_json=$5,updated_at=$6,verified_at=$7 WHERE resource_id=$1 AND execution_id=$8 AND kind=$9 AND revision=$10`,
				resource.ResourceID, resource.ProviderID, resource.State, resource.Revision, raw, resource.UpdatedAt.UTC(),
				resource.VerifiedAt, executionID, resource.Kind, oldRevision)
			if updateErr != nil || updated.RowsAffected() != 1 {
				return cloudworker.Execution{}, cloudworker.ErrConflict
			}
			continue
		}
		if !errors.Is(readErr, pgx.ErrNoRows) || resource.Revision != 1 {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		inserted, insertErr := tx.Exec(ctx, `INSERT INTO core_cloud_worker_resources(resource_id,execution_id,account_generation,provider,kind,provider_id,account_id,region,launch_identity,state,revision,resource_json,created_at,updated_at,verified_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, resource.ResourceID, executionID,
			resource.AccountGeneration, resource.Provider, resource.Kind, resource.ProviderID, resource.AccountID, resource.Region,
			resource.LaunchIdentity, resource.State, resource.Revision, raw, resource.CreatedAt.UTC(), resource.UpdatedAt.UTC(), resource.VerifiedAt)
		if insertErr != nil || inserted.RowsAffected() != 1 {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
	}
	var total, deleteRequested, destroyed uint64
	var verifiedAt *time.Time
	if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE state='delete_requested'),
		count(*) FILTER (WHERE state='verified_destroyed'),MAX(verified_at)
		FROM core_cloud_worker_resources WHERE execution_id=$1`, executionID).Scan(&total, &deleteRequested, &destroyed, &verifiedAt); err != nil {
		return cloudworker.Execution{}, err
	}
	if total != uint64(len(cloudaws.AllResourceKinds())) {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	if (destroyed != 0 && destroyed != total) ||
		(nextState == cloudworker.StateCleaning && destroyed == 0 && deleteRequested != total) {
		// Execution V2 cleanup evidence is atomic. The private AWS ledger may
		// verify entries independently, but no caller can persist a mixed
		// public graph or leak provider provisioning state through cleaning.
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	next := current
	if nextState != current.State {
		next, err = current.Transition(nextState, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			return cloudworker.Execution{}, err
		}
	} else {
		next.Revision++
		next.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	next.Cleanup = cloudworker.CleanupSummary{ResourcesTotal: total, ResourcesVerifiedDestroyed: destroyed, VerifiedDestroyed: total > 0 && total == destroyed}
	if next.Cleanup.VerifiedDestroyed {
		at := next.UpdatedAt
		if verifiedAt != nil {
			at = verifiedAt.UTC()
		}
		next.Cleanup.VerifiedAt = &at
	}
	if err = next.Seal(); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, current, next, "resources_recorded"); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

func cloudWorkerResourceKind(value string) bool {
	for _, kind := range cloudaws.AllResourceKinds() {
		if value == string(kind) {
			return true
		}
	}
	return false
}

func validCloudWorkerResourceTransition(current, next cloudworker.ResourceState) bool {
	switch current {
	case cloudworker.ResourcePlanned:
		return next == cloudworker.ResourcePlanned || next == cloudworker.ResourceCreated ||
			next == cloudworker.ResourceDeleteRequested || next == cloudworker.ResourceVerifiedDestroyed
	case cloudworker.ResourceCreated:
		return next == cloudworker.ResourceCreated || next == cloudworker.ResourceDeleteRequested || next == cloudworker.ResourceVerifiedDestroyed
	case cloudworker.ResourceDeleteRequested:
		return next == cloudworker.ResourceDeleteRequested || next == cloudworker.ResourceVerifiedDestroyed
	case cloudworker.ResourceVerifiedDestroyed:
		return next == cloudworker.ResourceVerifiedDestroyed
	default:
		return false
	}
}

func (s *CloudWorkerStore) RecordArtifacts(ctx context.Context, supplied coretask.Task, expectedRevision uint64, artifacts []cloudworker.Artifact, nextState cloudworker.ExecutionState) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || supplied.Lease == nil || supplied.Spec.Payload.CloudWorker == nil ||
		expectedRevision == 0 || len(artifacts) == 0 || len(artifacts) > 128 {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.Execution{}, cloudworker.ErrLeaseConflict
	}
	plan, current, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if current.Revision != expectedRevision {
		return cloudworker.Execution{}, cloudworker.ErrRevisionConflict
	}
	if current.TerminalIntent == string(cloudworker.StateCanceled) {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	executionID := current.ExecutionID
	ids := make([]string, 0, len(artifacts))
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		retention := artifact.Retention
		if !coretask.ValidUUID(artifact.ArtifactID) || artifact.ExecutionID != executionID || strings.TrimSpace(artifact.Kind) == "" ||
			strings.TrimSpace(artifact.Name) == "" || strings.TrimSpace(artifact.MediaType) == "" || artifact.SizeBytes == 0 ||
			artifact.SizeBytes > cloudworker.MaxCloudWorkerOutputBytes || !coretask.ValidDigest(artifact.SHA256) ||
			artifact.Status != cloudworker.ArtifactVerified || artifact.CreatedAt.IsZero() || retention == nil ||
			retention.Validate() != nil || retention.ArtifactID != artifact.ArtifactID ||
			retention.OwnerID != plan.OwnerID || retention.AccountID != plan.AWS.AccountID ||
			retention.AccountGeneration != plan.AccountGeneration || retention.Region != plan.AWS.Region ||
			retention.CredentialID != plan.AWS.CredentialID || retention.CredentialRevision != plan.AWS.CredentialRevision ||
			retention.ExecutionID != plan.ExecutionID || retention.PlanID != plan.PlanID || retention.PlanDigest != plan.Digest ||
			retention.KeyPrefix != plan.ArtifactGrant.KeyPrefix || retention.KMSKeyARN != plan.ArtifactGrant.KMSKeyARN ||
			retention.Claim.Name != artifact.Name || retention.Claim.MediaType != artifact.MediaType ||
			retention.Claim.SizeBytes != int64(artifact.SizeBytes) || retention.Claim.SHA256 != artifact.SHA256 ||
			!retention.ExpiresAt.Equal(artifact.CreatedAt.UTC().Add(time.Duration(plan.ArtifactGrant.RetentionSeconds)*time.Second)) {
			return cloudworker.Execution{}, cloudworker.ErrInvalid
		}
		if _, duplicate := seen[artifact.ArtifactID]; duplicate {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		seen[artifact.ArtifactID] = struct{}{}
		raw, _ := json.Marshal(artifact)
		result, insertErr := tx.Exec(ctx, `INSERT INTO core_cloud_worker_artifacts(
			artifact_id,execution_id,kind,name,media_type,size_bytes,sha256,status,
			s3_bucket,s3_key,s3_version_id,retention_owner_id,retention_account_id,
			retention_account_generation,retention_region,retention_credential_id,
			retention_credential_revision,retention_provider_id,retention_plan_id,
			retention_plan_digest,retention_key_prefix,retention_kms_key_arn,
			retention_expires_at,retention_state,retention_revision,
			retention_delete_attempts,retention_next_attempt_at,retention_updated_at,
			artifact_json,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
				'retained',1,0,$23,$24,$25,$24)
			ON CONFLICT(artifact_id) DO NOTHING`, artifact.ArtifactID,
			artifact.ExecutionID, artifact.Kind, artifact.Name, artifact.MediaType, artifact.SizeBytes, artifact.SHA256,
			artifact.Status, retention.Claim.Bucket, retention.Claim.Key, retention.Claim.VersionID,
			retention.OwnerID, retention.AccountID, retention.AccountGeneration, retention.Region,
			retention.CredentialID, retention.CredentialRevision, retention.ProviderID, retention.PlanID,
			retention.PlanDigest, retention.KeyPrefix, retention.KMSKeyARN, retention.ExpiresAt,
			artifact.CreatedAt.UTC(), raw)
		if insertErr != nil {
			return cloudworker.Execution{}, insertErr
		}
		if result.RowsAffected() == 0 {
			stored, storedArtifact, loadErr := loadCloudWorkerArtifactRetentionTx(ctx, tx, artifact.ArtifactID, true)
			storedRaw, _ := json.Marshal(storedArtifact)
			if loadErr != nil || !stored.Identity.Equal(*retention) || stored.State != cloudworker.ArtifactRetained ||
				stored.Revision != 1 || stored.DeleteAttempts != 0 || !jsonEquivalent(storedRaw, raw) {
				return cloudworker.Execution{}, cloudworker.ErrConflict
			}
		}
		ids = append(ids, artifact.ArtifactID)
	}
	next, err := current.Transition(nextState, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return cloudworker.Execution{}, err
	}
	next.ArtifactIDs = append([]string(nil), ids...)
	if err = next.Seal(); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, current, next, "artifacts_verified"); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

// MarkDispatchPrepared is the post-ledger CAS. The AWS identity and intent
// can be filled once and thereafter only replayed byte-for-byte; a reclaimed
// CoreTask lease can never replace the first launch identity.
func (s *CloudWorkerStore) MarkDispatchPrepared(ctx context.Context, supplied coretask.Task, expectedExecutionRevision uint64, identity cloudaws.ExecutionIdentity, intentDigest string) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || supplied.Lease == nil || expectedExecutionRevision == 0 || identity.Validate() != nil || !coretask.ValidDigest(intentDigest) {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.Execution{}, cloudworker.ErrLeaseConflict
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if execution.Revision != expectedExecutionRevision || execution.State != cloudworker.StateProvisioning ||
		identity.OwnerID != plan.OwnerID || identity.AccountID != plan.AWS.AccountID || identity.AccountGeneration != plan.AccountGeneration ||
		identity.Region != plan.AWS.Region || identity.ExecutionID != plan.ExecutionID || identity.TaskID != plan.TaskID ||
		identity.Generation != plan.Revision {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	// This row lock closes the resolver-read -> dispatch-CAS race for every
	// sanctioned profile mutation (all such changes advance revision, and
	// credential rotation also advances credential_version). The Controller's
	// secret-bearing resolver validates the complete snapshot digest; this
	// transaction prevents that snapshot from changing before the first AWS
	// mutation boundary is durably opened.
	var profileRevision, credentialVersion int64
	var provider, modelName string
	if err = tx.QueryRow(ctx, `SELECT revision,credential_version,provider,model_name FROM core_model_profiles
		WHERE profile_id=$1 AND deleted_at IS NULL FOR SHARE`, plan.ModelAuthorization.ModelProfileID).Scan(
		&profileRevision, &credentialVersion, &provider, &modelName,
	); err != nil || uint64(profileRevision) != plan.ModelAuthorization.ModelProfileRevision ||
		uint64(credentialVersion) != plan.ModelAuthorization.CredentialVersion ||
		provider != plan.ModelAuthorization.Provider || modelName != plan.ModelAuthorization.Model {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	var confirmationState string
	if err = tx.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID).Scan(&confirmationState); err != nil || confirmationState != "consumed" {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	identityRaw, _ := json.Marshal(identity)
	var initialAttempt uint32
	var initialEpoch uint64
	var storedLaunchIdentity, storedIntent string
	var storedIdentityRaw []byte
	var preparedAt *time.Time
	if err = tx.QueryRow(ctx, `SELECT task_attempt,lease_epoch,launch_identity,intent_digest,aws_identity_json,dispatch_prepared_at
		FROM core_cloud_worker_launch_material WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(
		&initialAttempt, &initialEpoch, &storedLaunchIdentity, &storedIntent, &storedIdentityRaw, &preparedAt); err != nil {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	if identity.TaskAttempt != initialAttempt || identity.LeaseEpoch != initialEpoch {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	ledger, ledgerErr := loadCloudWorkerAWSRecordTx(ctx, tx, plan)
	if ledgerErr != nil || !ledger.Identity.Equal(identity) || ledger.Intent.IntentDigest != intentDigest {
		if ledgerErr != nil && !errors.Is(ledgerErr, pgx.ErrNoRows) {
			return cloudworker.Execution{}, ledgerErr
		}
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	if storedLaunchIdentity != "" {
		if storedLaunchIdentity != identity.LaunchIdentity || storedIntent != intentDigest || !jsonEquivalent(storedIdentityRaw, identityRaw) || preparedAt == nil || !execution.ProviderMutationStarted {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.Execution{}, err
		}
		return execution, nil
	}
	if execution.ProviderMutationStarted || storedIntent != "" || jsonValuePresent(storedIdentityRaw) || preparedAt != nil {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_launch_material SET launch_identity=$2,intent_digest=$3,
		aws_identity_json=$4,dispatch_prepared_at=$5 WHERE execution_id=$1 AND launch_identity='' AND intent_digest='' AND aws_identity_json IS NULL`,
		plan.ExecutionID, identity.LaunchIdentity, intentDigest, identityRaw, now)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return cloudworker.Execution{}, err
		}
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	next := execution
	next.Revision++
	next.UpdatedAt = now
	next.ProviderMutationStarted = true
	if err = next.Seal(); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, next, "dispatch_prepared"); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

func (s *CloudWorkerStore) BeginCleanup(ctx context.Context, supplied coretask.Task, expectedExecutionRevision uint64, terminalIntent cloudworker.ExecutionState, code, summary string) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || supplied.Lease == nil || expectedExecutionRevision == 0 ||
		(terminalIntent != cloudworker.StateSucceeded && terminalIntent != cloudworker.StateFailed && terminalIntent != cloudworker.StateCanceled) ||
		len(code) > 128 || len(summary) > 4096 {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, time.Now().UTC()) != nil {
		return cloudworker.Execution{}, cloudworker.ErrLeaseConflict
	}
	_, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if execution.Revision != expectedExecutionRevision {
		return cloudworker.Execution{}, cloudworker.ErrRevisionConflict
	}
	if execution.State == cloudworker.StateCleaning {
		if execution.TerminalIntent != string(terminalIntent) || execution.FailureCode != strings.TrimSpace(code) || execution.FailureSummary != strings.TrimSpace(summary) {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.Execution{}, err
		}
		return execution, nil
	}
	next, err := execution.Transition(cloudworker.StateCleaning, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return cloudworker.Execution{}, err
	}
	next.TerminalIntent = string(terminalIntent)
	if terminalIntent != cloudworker.StateSucceeded {
		next.FailureCode, next.FailureSummary = strings.TrimSpace(code), strings.TrimSpace(summary)
		if next.FailureCode == "" {
			return cloudworker.Execution{}, cloudworker.ErrInvalid
		}
	}
	if err = next.Seal(); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, next, "cleanup_started"); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

// RequestCancel records a durable terminal intent only. Even an unconfirmed,
// zero-resource execution is queued for the controller so cancellation always
// follows the same fence -> cleaning -> verified terminal/outbox path.
func (s *CloudWorkerStore) RequestCancel(ctx context.Context, owner string, accountGeneration uint64, executionID string, expectedRevision uint64, idempotencyKey string) (cloudworker.Execution, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || !coretask.ValidUUID(executionID) || expectedRevision == 0 || !coretask.ValidUUID(idempotencyKey) {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	requestDigest := digestCloudWorkerValue(struct {
		OwnerID           string
		AccountGeneration uint64
		ExecutionID       string
		ExpectedRevision  uint64
	}{owner, accountGeneration, executionID, expectedRevision})
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cloud-worker:request-cancel:"+idempotencyKey); err != nil {
		return cloudworker.Execution{}, err
	}
	var replayDigest, replayExecution string
	var replayRevision uint64
	err = tx.QueryRow(ctx, `SELECT request_digest,execution_id::text,response_revision FROM core_cloud_worker_mutation_replays WHERE operation='request_cancel' AND idempotency_key=$1 FOR UPDATE`, idempotencyKey).Scan(&replayDigest, &replayExecution, &replayRevision)
	if err == nil {
		if replayDigest != requestDigest || replayExecution != executionID {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		execution, loadErr := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1 AND owner_id=$2 AND account_generation=$3`, executionID, owner, accountGeneration))
		if loadErr != nil || execution.Revision < replayRevision || execution.TerminalIntent != string(cloudworker.StateCanceled) {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.Execution{}, err
		}
		return execution, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return cloudworker.Execution{}, err
	}
	// Resolve immutable row identities first, then take every mutable lock in
	// Task -> Confirmation -> Execution order. This is the same order used by
	// confirmation lifecycle mutations and avoids cancel/confirm deadlocks.
	var taskID, confirmationID string
	if err = tx.QueryRow(ctx, `SELECT task_id::text,confirmation_id::text FROM core_cloud_worker_executions
		WHERE execution_id=$1 AND owner_id=$2 AND account_generation=$3`, executionID, owner, accountGeneration).Scan(&taskID, &confirmationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudworker.Execution{}, cloudworker.ErrNotFound
		}
		return cloudworker.Execution{}, err
	}
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, taskID, false)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, confirmationID))
	if err != nil {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	plan, current, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil || plan.OwnerID != owner || plan.AccountGeneration != accountGeneration ||
		plan.ExecutionID != executionID || plan.TaskID != taskID || plan.ConfirmationID != confirmationID {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	expectedBinding, err := cloudworker.BindingForPlan(plan)
	if err != nil || !confirmation.Binding.Equal(expectedBinding) {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	if current.Revision != expectedRevision {
		return cloudworker.Execution{}, cloudworker.ErrRevisionConflict
	}
	if current.State == cloudworker.StateSucceeded || current.State == cloudworker.StateFailed || current.State == cloudworker.StateCanceled || current.State == cloudworker.StateRejected || current.State == cloudworker.StateExpired {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	preAuthorization := !current.ProviderMutationStarted &&
		(current.State == cloudworker.StateWaitingUser || current.State == cloudworker.StateQueued) &&
		(confirmation.State == coreconfirmation.StatePending || confirmation.State == coreconfirmation.StateConfirmed)
	var next cloudworker.Execution
	if preAuthorization {
		if (current.State == cloudworker.StateWaitingUser) != (confirmation.State == coreconfirmation.StatePending) ||
			(current.State == cloudworker.StateWaitingUser && currentTask.Status != coretask.StatusWaitingUser) ||
			(current.State == cloudworker.StateQueued && currentTask.Status != coretask.StatusQueued && currentTask.Status != coretask.StatusRunning) {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		if err = requireCloudWorkerZeroMutationTx(ctx, tx, executionID); err != nil {
			return cloudworker.Execution{}, err
		}
		confirmationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,
			terminal_code='user_canceled',terminal_reason='user_canceled',updated_at=$2
			WHERE confirmation_id=$1 AND state=$3 AND revision=$4`, confirmationID, now, confirmation.State, confirmation.Revision)
		if updateErr != nil || confirmationUpdate.RowsAffected() != 1 {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		if current.State == cloudworker.StateWaitingUser {
			taskUpdate, updateErr := tx.Exec(ctx, `UPDATE core_tasks SET status='queued',available_at=$2,
				revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$2
				WHERE task_id=$1 AND status='waiting_user' AND revision=$3`, taskID, now, currentTask.Revision)
			if updateErr != nil || taskUpdate.RowsAffected() != 1 {
				return cloudworker.Execution{}, cloudworker.ErrConflict
			}
			if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at)
				SELECT task_id,progress_sequence,$2,attempt,'queued','cancel_requested','Cloud Worker cancellation queued',$3
				FROM core_tasks WHERE task_id=$1`, taskID, deterministicCloudWorkerUUID("cancel-requested-task", idempotencyKey), now); err != nil {
				return cloudworker.Execution{}, err
			}
			next, err = current.Transition(cloudworker.StateQueued, now)
		} else {
			next = current
			next.Revision++
			next.UpdatedAt = now
		}
		if err != nil {
			return cloudworker.Execution{}, err
		}
		next.TerminalIntent = string(cloudworker.StateCanceled)
		next.FailureCode, next.FailureSummary = "user_canceled", "Cloud Worker cancellation requested"
		if err = next.Seal(); err != nil {
			return cloudworker.Execution{}, err
		}
		if err = saveCloudWorkerExecutionTx(ctx, tx, current, next, "cancel_requested"); err != nil {
			return cloudworker.Execution{}, err
		}
	} else {
		if confirmation.State != coreconfirmation.StateConsumed || current.State == cloudworker.StateWaitingUser ||
			current.TerminalIntent == string(cloudworker.StateCanceled) {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		next = current
		next.Revision++
		next.UpdatedAt = now
		next.TerminalIntent = string(cloudworker.StateCanceled)
		if err = next.Seal(); err != nil {
			return cloudworker.Execution{}, err
		}
		if err = saveCloudWorkerExecutionTx(ctx, tx, current, next, "cancel_requested"); err != nil {
			return cloudworker.Execution{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_mutation_replays(operation,idempotency_key,request_digest,execution_id,response_revision)
		VALUES('request_cancel',$1,$2,$3,$4)`, idempotencyKey, requestDigest, executionID, next.Revision); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

func requireCloudWorkerZeroMutationTx(ctx context.Context, tx pgx.Tx, executionID string) error {
	var count int
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core_cloud_worker_begin_authorizations WHERE execution_id=$1) +
		(SELECT count(*) FROM core_cloud_worker_launch_material WHERE execution_id=$1) +
		(SELECT count(*) FROM core_cloud_worker_aws_ledger WHERE execution_id=$1) +
		(SELECT count(*) FROM core_cloud_worker_input_staging WHERE execution_id=$1) +
		(SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=$1) +
		(SELECT count(*) FROM core_cloud_worker_sessions WHERE execution_id=$1) +
		(SELECT count(*) FROM core_cloud_worker_model_grants WHERE execution_id=$1)`, executionID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return cloudworker.ErrConflict
	}
	return nil
}

func loadCloudWorkerTaskResultResourcesTx(ctx context.Context, tx pgx.Tx, plan cloudworker.Plan) ([]cloudworker.Resource, error) {
	rows, err := tx.Query(ctx, `SELECT resource_json FROM core_cloud_worker_resources WHERE execution_id=$1 ORDER BY kind FOR UPDATE`, plan.ExecutionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	resources := make([]cloudworker.Resource, 0, len(cloudaws.AllResourceKinds()))
	for rows.Next() {
		var raw []byte
		var resource cloudworker.Resource
		if err = rows.Scan(&raw); err != nil || json.Unmarshal(raw, &resource) != nil ||
			resource.ExecutionID != plan.ExecutionID || resource.AccountGeneration != plan.AccountGeneration ||
			resource.AccountID != plan.AWS.AccountID || resource.Region != plan.AWS.Region || resource.ValidateObservedAddresses() != nil {
			return nil, cloudworker.ErrConflict
		}
		resources = append(resources, resource)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return resources, nil
}

func (s *CloudWorkerStore) CompleteExecution(ctx context.Context, task coretask.Task, expectedRevision uint64, result cloudworker.ProviderResult) (cloudworker.Execution, cloudworker.CompletionOutbox, error) {
	return s.terminalExecution(ctx, task, expectedRevision, cloudworker.StateSucceeded, "", strings.TrimSpace(result.Summary), &result)
}

func (s *CloudWorkerStore) FailExecution(ctx context.Context, task coretask.Task, expectedRevision uint64, code, summary string) (cloudworker.Execution, cloudworker.CompletionOutbox, error) {
	return s.terminalExecution(ctx, task, expectedRevision, cloudworker.StateFailed, strings.TrimSpace(code), strings.TrimSpace(summary), nil)
}

func (s *CloudWorkerStore) CancelExecution(ctx context.Context, task coretask.Task, expectedRevision uint64, code, summary string) (cloudworker.Execution, cloudworker.CompletionOutbox, error) {
	return s.terminalExecution(ctx, task, expectedRevision, cloudworker.StateCanceled, strings.TrimSpace(code), strings.TrimSpace(summary), nil)
}

func (s *CloudWorkerStore) terminalExecution(ctx context.Context, supplied coretask.Task, expectedRevision uint64, terminal cloudworker.ExecutionState, code, summary string, providerResult *cloudworker.ProviderResult) (cloudworker.Execution, cloudworker.CompletionOutbox, error) {
	if s == nil || s.store == nil || supplied.Spec.Payload.CloudWorker == nil || supplied.Lease == nil || expectedRevision == 0 ||
		(terminal != cloudworker.StateSucceeded && terminal != cloudworker.StateFailed && terminal != cloudworker.StateCanceled) ||
		len(code) > 128 || len(summary) > core.MaxSummaryBytes || (terminal == cloudworker.StateSucceeded) != (providerResult != nil) ||
		(terminal != cloudworker.StateSucceeded && code == "") {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrLeaseConflict
	}
	// A lost terminal response is recovered from the immutable completion
	// outbox even though the task no longer owns a live lease.
	if currentTask.Status == coretask.StatusSucceeded || currentTask.Status == coretask.StatusFailed || currentTask.Status == coretask.StatusCanceled {
		execution, loadErr := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE task_id=$1 FOR UPDATE`, supplied.ID))
		if loadErr != nil || execution.State != terminal {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
		}
		outbox, loadErr := scanCloudWorkerCompletionOutbox(tx.QueryRow(ctx, `SELECT payload_json FROM core_cloud_worker_completion_outbox WHERE execution_id=$1`, execution.ExecutionID))
		if loadErr != nil {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, loadErr
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
		}
		return execution, outbox, nil
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err = validateCloudWorkerTaskFence(currentTask, supplied, now); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	if execution.Revision != expectedRevision || execution.State != cloudworker.StateCleaning || execution.TerminalIntent != string(terminal) {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrRevisionConflict
	}
	if execution.ProviderMutationStarted && !execution.Cleanup.VerifiedDestroyed {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	resourceTotal, resourceRemaining, err := lockedCloudWorkerStateCounts(ctx, tx, `SELECT state FROM core_cloud_worker_resources WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID)
	if err != nil || resourceTotal != execution.Cleanup.ResourcesTotal || resourceRemaining != 0 {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	awsTotal, awsRemaining, err := lockedCloudWorkerStateCounts(ctx, tx, `SELECT state FROM core_cloud_worker_aws_ledger WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID)
	if err != nil || awsRemaining != 0 {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	if execution.ProviderMutationStarted && awsTotal == 0 {
		var fakeCount uint64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=$1 AND provider='fake'`, plan.ExecutionID).Scan(&fakeCount); err != nil || fakeCount != resourceTotal || fakeCount == 0 {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
		}
	}
	stagedTotal, stagedRemaining, err := lockedCloudWorkerStateCounts(ctx, tx, `SELECT state FROM core_cloud_worker_input_staging WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID)
	// A pre-dispatch cancellation/failure may interrupt staging before every
	// manifest entry exists. Every row that does exist must still be cleaned,
	// while a provider-started execution requires the complete authorized set.
	if err != nil || stagedRemaining != 0 || stagedTotal > plan.InputManifestItemCount ||
		(execution.ProviderMutationStarted && stagedTotal != plan.InputManifestItemCount) {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	var expectationCount uint64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_launch_expectations WHERE execution_id=$1`, plan.ExecutionID).Scan(&expectationCount); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	if expectationCount > 0 {
		if terminal == cloudworker.StateSucceeded {
			var sessionState string
			if err = tx.QueryRow(ctx, `SELECT state FROM core_cloud_worker_sessions WHERE execution_id=$1 ORDER BY claimed_at DESC LIMIT 1 FOR UPDATE`, plan.ExecutionID).Scan(&sessionState); err != nil || sessionState != "completed" {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
			}
		} else {
			var activeSessions, fenceRecords uint64
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_sessions WHERE execution_id=$1 AND state='active'`, plan.ExecutionID).Scan(&activeSessions); err != nil || activeSessions != 0 {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
			}
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_session_fences WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4`, plan.ExecutionID, plan.TaskID, currentTask.Attempt, currentTask.LeaseEpoch).Scan(&fenceRecords); err != nil || fenceRecords != 1 {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
			}
		}
	}
	if terminal == cloudworker.StateSucceeded {
		if summary == "" || len(providerResult.Artifacts) == 0 || len(providerResult.Artifacts) != len(execution.ArtifactIDs) {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrInvalid
		}
		for _, artifact := range providerResult.Artifacts {
			var storedRaw []byte
			if err = tx.QueryRow(ctx, `SELECT artifact_json FROM core_cloud_worker_artifacts WHERE artifact_id=$1 AND execution_id=$2 AND status='verified' FOR UPDATE`, artifact.ArtifactID, plan.ExecutionID).Scan(&storedRaw); err != nil {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
			}
			raw, _ := json.Marshal(artifact)
			if !jsonEquivalent(storedRaw, raw) {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
			}
		}
	} else if summary == "" {
		summary = code
	}
	next, err := execution.Transition(terminal, now)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	if terminal != cloudworker.StateSucceeded {
		next.FailureCode, next.FailureSummary = code, summary
	}
	if err = next.Seal(); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, next, "execution_"+string(terminal)); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}

	resources, err := loadCloudWorkerTaskResultResourcesTx(ctx, tx, plan)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	resultSnapshot, err := cloudworker.NewTaskResultSnapshot(plan, resources, next.ArtifactIDs)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	resultJSON, _ := json.Marshal(resultSnapshot)
	coreResult := coretask.Result{Summary: summary, JSON: resultJSON}
	if terminal == cloudworker.StateSucceeded {
		coreResult.Text = summary
	}
	if coreResult.Validate() != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrInvalid
	}
	taskResult, _ := json.Marshal(coreResult)
	taskStatus := string(coretask.StatusSucceeded)
	if terminal == cloudworker.StateFailed {
		taskStatus = string(coretask.StatusFailed)
	}
	if terminal == cloudworker.StateCanceled {
		taskStatus = string(coretask.StatusCanceled)
	}
	update, err := tx.Exec(ctx, `UPDATE core_tasks SET status=$2,result_json=$3,failure_code=$4,failure_summary=$5,
		lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$6
		WHERE task_id=$1 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$6`,
		plan.TaskID, taskStatus, taskResult, code, summary, now, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
	if err != nil || update.RowsAffected() != 1 {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrLeaseConflict
	}
	taskEventInsert, insertErr := tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,result_json,error_code,error_summary,occurred_at)
		SELECT task_id,progress_sequence,$2,attempt,$3,'cloud_worker_terminal',$4,$5,$6,$7 FROM core_tasks WHERE task_id=$1`,
		plan.TaskID, deterministicCloudWorkerUUID("task-terminal", plan.ExecutionID+":"+string(terminal)), taskStatus, taskResult, code, summary, now)
	if insertErr != nil || taskEventInsert.RowsAffected() != 1 {
		if insertErr != nil {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, insertErr
		}
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	concurrencyUpdate, updateErr := tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, now)
	if updateErr != nil || concurrencyUpdate.RowsAffected() != 1 {
		if updateErr != nil {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, updateErr
		}
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	var confirmation coreconfirmation.Confirmation
	confirmation, err = scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
	}
	confirmationReferenceRevision := uint64(confirmation.Revision)
	confirmationReferenceState := string(confirmation.State)
	if confirmation.State == coreconfirmation.StateConsumed {
		// The reservation is acquired by the first BeginExecution fence. After
		// immutable launch material exists, a CoreTask lease reclaim rotates only
		// the controller/Worker session fence; it must not rewrite the consumed
		// owner authorization. Lock and release that original reservation by its
		// immutable confirmation/task identity instead of requiring the current
		// lease epoch.
		var reservationTaskID string
		var reservationActive bool
		if err = tx.QueryRow(ctx, `SELECT task_id::text,active FROM core_confirmation_reservations
			WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID).Scan(&reservationTaskID, &reservationActive); err != nil ||
			reservationTaskID != plan.TaskID || !reservationActive {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
		}
		reservationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false
			WHERE confirmation_id=$1 AND task_id=$2 AND active=true`, plan.ConfirmationID, plan.TaskID)
		if updateErr != nil || reservationUpdate.RowsAffected() != 1 {
			if updateErr != nil {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, updateErr
			}
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
		}
		confirmationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=$2
			WHERE confirmation_id=$1 AND state='consumed' AND consumed_released=false AND revision=$3`, plan.ConfirmationID, now, confirmation.Revision)
		if updateErr != nil || confirmationUpdate.RowsAffected() != 1 {
			if updateErr != nil {
				return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, updateErr
			}
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
		}
		confirmationReferenceRevision++
	} else if confirmation.State == coreconfirmation.StateExpired && terminal == cloudworker.StateCanceled &&
		!execution.ProviderMutationStarted && confirmation.TerminalCode == "user_canceled" &&
		confirmation.TerminalReason == "user_canceled" {
		var reservationCount uint64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_confirmation_reservations
			WHERE confirmation_id=$1`, plan.ConfirmationID).Scan(&reservationCount); err != nil || reservationCount != 0 {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
		}
	} else {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
	}

	var requestID, turnState, profileID string
	var turnRevision, turnSequence uint64
	if err = tx.QueryRow(ctx, `SELECT request_id::text,state,profile_id::text,revision,last_sequence FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, plan.TurnID).Scan(&requestID, &turnState, &profileID, &turnRevision, &turnSequence); err != nil || turnState != "waiting_confirmation" {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	var conversationRevision uint64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL FOR UPDATE`, plan.ConversationID).Scan(&conversationRevision); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	binding, err := cloudworker.BindingForPlan(plan)
	if err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	if !confirmation.Binding.Equal(binding) {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrStaleAuthorization
	}
	references := cloudWorkerReferences(plan, next, binding, confirmationReferenceRevision, confirmationReferenceState)
	resultMessage := core.Message{ID: deterministicCloudWorkerUUID("cloud-worker-result-message", plan.ExecutionID), Role: core.RoleAssistant,
		Content: summary, ModelProfileID: profileID, RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID},
		References: references, CreatedAt: now}
	if resultMessage.Validate() != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrInvalid
	}
	var messageSequence int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_messages WHERE conversation_id=$1`, plan.ConversationID).Scan(&messageSequence); err != nil || insertCloudWorkerMessageTx(ctx, tx, plan.ConversationID, messageSequence, resultMessage) != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	response := core.ChatResponse{RequestID: requestID, ConversationID: plan.ConversationID,
		Revision: conversationRevision + 1, Message: resultMessage, Done: true, ModelProfileID: profileID,
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, References: references}
	responseRaw, _ := json.Marshal(response)
	conversationUpdate, err := tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2 WHERE conversation_id=$1 AND revision=$3`, plan.ConversationID, now, conversationRevision)
	if err != nil || conversationUpdate.RowsAffected() != 1 {
		if err == nil {
			err = cloudworker.ErrConflict
		}
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	turnEvent := core.TurnEvent{TurnID: plan.TurnID, Sequence: int64(turnSequence + 1), Kind: core.TurnEventDone,
		Message: &resultMessage, Response: &response, ExecutionID: plan.ExecutionID, Status: string(terminal),
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, References: references, CreatedAt: now}
	turnEventRaw, _ := json.Marshal(turnEvent)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`, plan.TurnID, turnEvent.Sequence, string(turnEvent.Kind), turnEventRaw, now); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	turnUpdate, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='completed',response_json=$2,revision=revision+1,last_sequence=$3,updated_at=$4 WHERE turn_id=$1 AND state='waiting_confirmation' AND revision=$5`, plan.TurnID, responseRaw, turnEvent.Sequence, now, turnRevision)
	if err != nil || turnUpdate.RowsAffected() != 1 {
		if err == nil {
			err = cloudworker.ErrConflict
		}
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	outbox := cloudworker.CompletionOutbox{EventID: deterministicCloudWorkerUUID("completion-outbox", plan.ExecutionID),
		ExecutionID: plan.ExecutionID, RunID: plan.ExecutionID, ConversationID: plan.ConversationID,
		TurnID: plan.TurnID, ResultMessageID: resultMessage.ID, TerminalState: string(terminal), CompletedAt: now}
	outbox.PayloadDigest = cloudworker.CompletionDigest(outbox)
	if outbox.Validate() != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrInvalid
	}
	outboxRaw, _ := json.Marshal(outbox)
	outboxInsert, insertErr := tx.Exec(ctx, `INSERT INTO core_cloud_worker_completion_outbox(event_id,execution_id,conversation_id,turn_id,result_message_id,terminal_state,payload_digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, outbox.EventID, outbox.ExecutionID, outbox.ConversationID,
		outbox.TurnID, outbox.ResultMessageID, outbox.TerminalState, outbox.PayloadDigest, outboxRaw, outbox.CompletedAt)
	if insertErr != nil || outboxInsert.RowsAffected() != 1 {
		if insertErr != nil {
			return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, insertErr
		}
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, cloudworker.CompletionOutbox{}, err
	}
	return next, outbox, nil
}

func scanCloudWorkerCompletionOutbox(row cloudWorkerRowScanner) (cloudworker.CompletionOutbox, error) {
	var raw []byte
	var outbox cloudworker.CompletionOutbox
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return outbox, cloudworker.ErrNotFound
		}
		return outbox, err
	}
	if json.Unmarshal(raw, &outbox) != nil || outbox.Validate() != nil {
		return cloudworker.CompletionOutbox{}, cloudworker.ErrConflict
	}
	return outbox, nil
}

func lockedCloudWorkerStateCounts(ctx context.Context, tx pgx.Tx, query string, args ...any) (uint64, uint64, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var total, remaining uint64
	for rows.Next() {
		var state string
		if err = rows.Scan(&state); err != nil {
			return 0, 0, err
		}
		total++
		if state != "verified_destroyed" {
			remaining++
		}
	}
	return total, remaining, rows.Err()
}

// ListPendingCompletionOutbox claims a bounded batch for this stable Agent
// instance. The payload contains only receipt identifiers/digests; message
// text and artifact details remain behind Agent read APIs.
func (s *CloudWorkerStore) ListPendingCompletionOutbox(ctx context.Context, limit int) ([]cloudworker.CompletionOutbox, error) {
	if s == nil || s.store == nil || limit < 1 || limit > 200 {
		return nil, cloudworker.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	rows, err := tx.Query(ctx, `SELECT event_id::text,payload_json FROM core_cloud_worker_completion_outbox
		WHERE (delivery_state='pending' AND next_attempt_at<=$1) OR
		      (delivery_state='claimed' AND delivery_lease_until<=$1)
		ORDER BY next_attempt_at,created_at,event_id FOR UPDATE SKIP LOCKED LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id  string
		raw []byte
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err = rows.Scan(&item.id, &item.raw); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	result := make([]cloudworker.CompletionOutbox, 0, len(candidates))
	leaseUntil := now.Add(5 * time.Minute)
	for _, item := range candidates {
		var outbox cloudworker.CompletionOutbox
		if json.Unmarshal(item.raw, &outbox) != nil || outbox.Validate() != nil || outbox.EventID != item.id {
			return nil, cloudworker.ErrConflict
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE core_cloud_worker_completion_outbox SET delivery_state='claimed',delivery_holder=$2,
			delivery_lease_until=$3,delivery_attempts=delivery_attempts+1,last_error='' WHERE event_id=$1 AND delivery_state<>'delivered'`,
			item.id, s.store.instanceID, leaseUntil)
		if updateErr != nil || tag.RowsAffected() != 1 {
			if updateErr != nil {
				return nil, updateErr
			}
			return nil, cloudworker.ErrConflict
		}
		result = append(result, outbox)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *CloudWorkerStore) MarkCompletionDelivered(ctx context.Context, eventID, payloadDigest string) error {
	if s == nil || s.store == nil || !coretask.ValidUUID(eventID) || !coretask.ValidDigest(payloadDigest) {
		return cloudworker.ErrInvalid
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tag, err := s.store.pool.Exec(ctx, `UPDATE core_cloud_worker_completion_outbox SET delivery_state='delivered',
		delivered_at=$3,delivery_holder=NULL,delivery_lease_until=NULL,last_error=''
		WHERE event_id=$1 AND payload_digest=$2 AND delivery_state='claimed' AND delivery_holder=$4 AND delivery_lease_until>$3`,
		eventID, payloadDigest, now, s.store.instanceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var state, digest string
	if readErr := s.store.pool.QueryRow(ctx, `SELECT delivery_state,payload_digest FROM core_cloud_worker_completion_outbox WHERE event_id=$1`, eventID).Scan(&state, &digest); readErr == nil && state == "delivered" && digest == payloadDigest {
		return nil
	}
	return cloudworker.ErrConflict
}

func (s *CloudWorkerStore) RecordCompletionDeliveryFailure(ctx context.Context, eventID, payloadDigest, errorSummary string, nextAttempt time.Time) error {
	errorSummary = strings.TrimSpace(errorSummary)
	if s == nil || s.store == nil || !coretask.ValidUUID(eventID) || !coretask.ValidDigest(payloadDigest) || errorSummary == "" || len(errorSummary) > 1024 || nextAttempt.IsZero() {
		return cloudworker.ErrInvalid
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !nextAttempt.After(now) {
		return cloudworker.ErrInvalid
	}
	tag, err := s.store.pool.Exec(ctx, `UPDATE core_cloud_worker_completion_outbox SET delivery_state='pending',
		delivery_holder=NULL,delivery_lease_until=NULL,last_error=$3,next_attempt_at=$4
		WHERE event_id=$1 AND payload_digest=$2 AND delivery_state='claimed' AND delivery_holder=$5`,
		eventID, payloadDigest, errorSummary, nextAttempt.UTC(), s.store.instanceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return cloudworker.ErrConflict
	}
	return nil
}

func (s *CloudWorkerStore) ReplaceWithRequote(ctx context.Context, supplied coretask.Task, command cloudworker.RequoteOfferCommand) (cloudworker.Offer, error) {
	if s == nil || s.store == nil || supplied.Spec.Payload.CloudWorker == nil || supplied.Lease == nil ||
		!coretask.ValidUUID(command.IdempotencyKey) || !coretask.ValidDigest(command.RequestDigest) ||
		!coretask.ValidUUID(command.OldExecutionID) || command.OldExecutionID != supplied.Spec.Payload.CloudWorker.ExecutionID ||
		(command.Reason != cloudworker.RequoteReasonExpired && command.Reason != cloudworker.RequoteReasonDrift) {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	plan, execution := command.Plan, command.Execution
	canonicalPlan := plan
	if canonicalPlan.Seal() != nil || !reflect.DeepEqual(canonicalPlan, plan) {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	expectedExecution, err := cloudworker.NewExecution(plan)
	if err != nil || execution.Seal() != nil || !reflect.DeepEqual(execution, expectedExecution) {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	expectedPayload := coretask.CloudWorkerTaskPayload{
		ExecutionID: plan.ExecutionID, AccountGeneration: plan.AccountGeneration,
		PlanID: plan.PlanID, PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		ConfirmationID: plan.ConfirmationID, TurnID: plan.TurnID,
		ConversationID: plan.ConversationID, QuoteDigest: plan.Quote.Digest,
		ExecutionDigest: plan.ExecutionDigest,
	}
	if !reflect.DeepEqual(command.TaskPayload, expectedPayload) || plan.ExecutionID == command.OldExecutionID {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	expectedBinding, err := cloudworker.BindingForPlan(plan)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	var suppliedBinding coreconfirmation.Binding
	if json.Unmarshal(command.BindingJSON, &suppliedBinding) != nil {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	binding, err := suppliedBinding.Normalize()
	if err != nil || !binding.Equal(expectedBinding) {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	bindingRaw, _ := json.Marshal(binding)
	planRaw, privateRaw, err := marshalCloudWorkerPlan(plan)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	executionRaw, err := marshalCloudWorkerExecution(execution)
	if err != nil {
		return cloudworker.Offer{}, err
	}

	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudworker.Offer{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cloud-worker:requote:"+command.IdempotencyKey); err != nil {
		return cloudworker.Offer{}, err
	}
	var replayDigest string
	var replayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_cloud_worker_offer_replays WHERE idempotency_key=$1 FOR UPDATE`, command.IdempotencyKey).Scan(&replayDigest, &replayRaw)
	if err == nil {
		var replay cloudWorkerReplay
		if replayDigest != command.RequestDigest || json.Unmarshal(replayRaw, &replay) != nil || replay.PlanID != plan.PlanID {
			return cloudworker.Offer{}, cloudworker.ErrConflict
		}
		offer, loadErr := s.offerTx(ctx, tx, replay.PlanID)
		if loadErr != nil {
			return cloudworker.Offer{}, loadErr
		}
		if err = tx.Commit(ctx); err != nil {
			return cloudworker.Offer{}, err
		}
		return offer, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return cloudworker.Offer{}, err
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, now) != nil {
		return cloudworker.Offer{}, cloudworker.ErrLeaseConflict
	}
	oldPayload := currentTask.Spec.Payload.CloudWorker
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, oldPayload.ConfirmationID))
	if err != nil {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	oldPlan, oldExecution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, oldPayload, true)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	if oldExecution.ExecutionID != command.OldExecutionID ||
		(oldExecution.State != cloudworker.StateQueued && oldExecution.State != cloudworker.StateProvisioning) ||
		oldExecution.ProviderMutationStarted || oldExecution.TerminalIntent != "" || oldExecution.NeedsReconcile ||
		(confirmation.State != coreconfirmation.StateConfirmed && confirmation.State != coreconfirmation.StateConsumed) ||
		(oldExecution.State == cloudworker.StateQueued) != (confirmation.State == coreconfirmation.StateConfirmed) ||
		confirmation.TaskID != oldPlan.TaskID ||
		plan.OwnerID != oldPlan.OwnerID || plan.AccountGeneration != oldPlan.AccountGeneration ||
		plan.ConversationID != oldPlan.ConversationID || plan.TurnID != oldPlan.TurnID ||
		plan.RecipeID != oldPlan.RecipeID || plan.Adapter != oldPlan.Adapter ||
		plan.Objective != oldPlan.Objective || plan.ObjectiveDigest != oldPlan.ObjectiveDigest ||
		plan.UserPromptDigest != oldPlan.UserPromptDigest || plan.InputManifestDigest != oldPlan.InputManifestDigest ||
		plan.WorkspaceMode != oldPlan.WorkspaceMode || plan.ProposalReason != oldPlan.ProposalReason ||
		!reflect.DeepEqual(plan.LocalBudgetEvidence, oldPlan.LocalBudgetEvidence) ||
		plan.PlanID == oldPlan.PlanID || plan.TaskID == oldPlan.TaskID || plan.ConfirmationID == oldPlan.ConfirmationID ||
		plan.Quote.Digest == oldPlan.Quote.Digest || !plan.Quote.ExpiresAt.After(now) || plan.CreatedAt.After(now.Add(time.Second)) {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	oldExpectedBinding, err := cloudworker.BindingForPlan(oldPlan)
	if err != nil || !confirmation.Binding.Equal(oldExpectedBinding) {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	if err = requireCloudWorkerRequoteCleanupTx(ctx, tx, oldPlan.ExecutionID); err != nil {
		return cloudworker.Offer{}, err
	}

	taskTimeout, err := cloudWorkerTaskTimeout(plan.Limits)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	spec, err := (coretask.TaskSpec{
		Kind: coretask.TaskKindCloudWorker, Payload: coretask.TaskPayload{CloudWorker: &command.TaskPayload},
		Goal: plan.Objective, ConversationID: plan.ConversationID,
		ModelProfileID: plan.ModelAuthorization.ModelProfileID,
		TimeoutSeconds: taskTimeout, IdempotencyKey: command.IdempotencyKey,
		AvailableAt: plan.CreatedAt,
	}).Normalize()
	if err != nil {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	var profileRevision, credentialVersion int64
	var provider, modelName string
	if err = tx.QueryRow(ctx, `SELECT revision,credential_version,provider,model_name FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR SHARE`, spec.ModelProfileID).Scan(&profileRevision, &credentialVersion, &provider, &modelName); err != nil ||
		uint64(profileRevision) != plan.ModelAuthorization.ModelProfileRevision || uint64(credentialVersion) != plan.ModelAuthorization.CredentialVersion ||
		provider != plan.ModelAuthorization.Provider || modelName != plan.ModelAuthorization.Model {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	snapshot, err := resolveTaskSnapshotTx(ctx, tx, spec)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	snapshotRaw, _ := json.Marshal(snapshot)
	payloadRaw, _ := json.Marshal(spec.Payload)

	confirmationUpdate, err := tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',consumed_released=CASE WHEN state='consumed' THEN true ELSE consumed_released END,
		revision=revision+1,terminal_code=$2,terminal_reason=$2,updated_at=$3
		WHERE confirmation_id=$1 AND state=$4 AND revision=$5`, oldPlan.ConfirmationID, command.Reason, now, confirmation.State, confirmation.Revision)
	if err != nil || confirmationUpdate.RowsAffected() != 1 {
		return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
	}
	if confirmation.State == coreconfirmation.StateConsumed {
		reservationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false
			WHERE confirmation_id=$1 AND task_id=$2 AND active=true`, oldPlan.ConfirmationID, oldPlan.TaskID)
		if updateErr != nil || reservationUpdate.RowsAffected() != 1 {
			return cloudworker.Offer{}, cloudworker.ErrStaleAuthorization
		}
	}
	failureSummary := "Cloud Worker quote changed before provider mutation"
	taskUpdate, err := tx.Exec(ctx, `UPDATE core_tasks SET status='failed',failure_code=$2,failure_summary=$3,
		lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$4
		WHERE task_id=$1 AND status='running' AND attempt=$5 AND lease_epoch=$6 AND revision=$7 AND lease_expires_at>$4`,
		oldPlan.TaskID, command.Reason, failureSummary, now, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
	if err != nil || taskUpdate.RowsAffected() != 1 {
		return cloudworker.Offer{}, cloudworker.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at)
		SELECT task_id,progress_sequence,$2,attempt,'failed','requote',$3,$4,$5 FROM core_tasks WHERE task_id=$1`,
		oldPlan.TaskID, deterministicCloudWorkerUUID("requote-old-task", command.IdempotencyKey), command.Reason, failureSummary, now); err != nil {
		return cloudworker.Offer{}, err
	}
	concurrencyUpdate, err := tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, now)
	if err != nil || concurrencyUpdate.RowsAffected() != 1 {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}
	expiredExecution, err := oldExecution.Transition(cloudworker.StateExpired, now)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	expiredExecution.FailureCode, expiredExecution.FailureSummary = command.Reason, failureSummary
	if expiredExecution.Seal() != nil || saveCloudWorkerExecutionTx(ctx, tx, oldExecution, expiredExecution, command.Reason) != nil {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}

	emptyArray := []byte(`[]`)
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,
		attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,lease_epoch,
		lease_holder,available_at,revision,created_at,updated_at,task_kind,payload_json)
		VALUES($1,$2,$3,$4,$5,$6,$6,$6,$7,'waiting_user',0,1,0,'',$8,1,$9,$9,'cloud_worker',$10)`,
		plan.TaskID, spec.Goal, spec.ConversationID, spec.ModelProfileID, spec.IdempotencyKey, emptyArray,
		spec.TimeoutSeconds, spec.AvailableAt, plan.CreatedAt, payloadRaw); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, plan.TaskID, snapshotRaw, snapshot.Digest); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, plan.TaskID, spec.ModelProfileID); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at)
		VALUES($1,1,$2,0,'waiting_user','confirmation','waiting for fresh owner confirmation',$3)`,
		plan.TaskID, deterministicCloudWorkerUUID("requote-task-event", command.IdempotencyKey), plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,
		task_id,state,consumed_released,revision,created_at,updated_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,'pending',false,1,$7,$7,$8)`, plan.ConfirmationID,
		binding.OperationDomain, binding.TargetID, binding.TargetRevision, bindingRaw, plan.TaskID, plan.CreatedAt, plan.Quote.ExpiresAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at)
		VALUES($1,$2,$3,$4,$5)`, binding.OperationDomain, binding.TargetID, binding.TargetRevision, bindingRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, plan.ConfirmationID, bindingRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_plans(plan_id,owner_id,account_generation,revision,digest,
		execution_digest,authorization_basis_digest,quote_digest,input_manifest_digest,model_binding_digest,
		credential_id,credential_revision,
		execution_id,task_id,confirmation_id,conversation_id,turn_id,recipe_id,adapter,workspace_mode,status,
		quote_expires_at,plan_json,private_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,'waiting_user',$21,$22,$23,$24,$25)`,
		plan.PlanID, plan.OwnerID, plan.AccountGeneration, plan.Revision, plan.Digest, plan.ExecutionDigest,
		plan.AuthorizationBasisDigest, plan.Quote.Digest, plan.InputManifestDigest, plan.ModelAuthorization.BindingDigest,
		plan.AWS.CredentialID, plan.AWS.CredentialRevision,
		plan.ExecutionID, plan.TaskID, plan.ConfirmationID, plan.ConversationID, plan.TurnID, plan.RecipeID,
		plan.Adapter, plan.WorkspaceMode, plan.Quote.ExpiresAt, planRaw, privateRaw, plan.CreatedAt, plan.UpdatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_executions(execution_id,owner_id,account_generation,plan_id,
		plan_revision,plan_digest,task_id,confirmation_id,conversation_id,turn_id,state,revision,digest,quote_digest,
		execution_digest,provider_mutation_started,terminal_intent,needs_reconcile,execution_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'waiting_user',$11,$12,$13,$14,false,'',false,$15,$16,$17)`,
		execution.ExecutionID, execution.OwnerID, execution.AccountGeneration, execution.PlanID, execution.PlanRevision,
		execution.PlanDigest, execution.TaskID, execution.ConfirmationID, execution.ConversationID, execution.TurnID,
		execution.Revision, execution.Digest, execution.QuoteDigest, execution.ExecutionDigest, executionRaw,
		execution.CreatedAt, execution.UpdatedAt); err != nil {
		return cloudworker.Offer{}, err
	}

	initialEvent := cloudworker.Event{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		RunID: plan.ExecutionID, ExecutionID: plan.ExecutionID,
		Sequence: 1, EventID: deterministicCloudWorkerUUID("requote-execution-event", command.IdempotencyKey),
		Type: "requote_created", State: cloudworker.StateWaitingUser, Revision: execution.Revision, CreatedAt: plan.CreatedAt}
	initialEvent.PayloadDigest = digestCloudWorkerValue(command.TaskPayload)
	initialEventRaw, _ := json.Marshal(initialEvent)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_events(execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at)
		VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`, plan.ExecutionID, initialEvent.EventID, plan.OwnerID,
		initialEvent.Type, initialEvent.State, initialEvent.Revision, initialEvent.PayloadDigest, initialEventRaw, initialEvent.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}

	var turn struct {
		OwnerID, ConversationID, ProfileID, State string
		AccountGeneration, LastSequence, Revision uint64
	}
	if err = tx.QueryRow(ctx, `SELECT owner_id,account_generation,conversation_id::text,profile_id::text,state,last_sequence,revision
		FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, plan.TurnID).Scan(
		&turn.OwnerID, &turn.AccountGeneration, &turn.ConversationID, &turn.ProfileID, &turn.State, &turn.LastSequence, &turn.Revision); err != nil ||
		turn.OwnerID != plan.OwnerID || turn.AccountGeneration != plan.AccountGeneration || turn.ConversationID != plan.ConversationID ||
		turn.ProfileID != plan.ModelAuthorization.ModelProfileID || turn.State != "waiting_confirmation" {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}
	var conversationRevision uint64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL FOR UPDATE`, plan.ConversationID).Scan(&conversationRevision); err != nil {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}
	references := cloudWorkerReferences(plan, execution, binding, 1, "pending")
	message := core.Message{ID: deterministicCloudWorkerUUID("requote-offer-message", command.IdempotencyKey), Role: core.RoleAssistant,
		Content: "Cloud Worker quote changed and requires fresh confirmation.", ModelProfileID: turn.ProfileID,
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, References: references, CreatedAt: plan.CreatedAt}
	if message.Validate() != nil {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	var messageSequence int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_messages WHERE conversation_id=$1`, plan.ConversationID).Scan(&messageSequence); err != nil ||
		insertCloudWorkerMessageTx(ctx, tx, plan.ConversationID, messageSequence, message) != nil {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}
	turnEvent := core.TurnEvent{TurnID: plan.TurnID, Sequence: int64(turn.LastSequence + 1), Kind: core.TurnEventWaitingConfirmation,
		Message: &message, ConfirmationID: plan.ConfirmationID, ExecutionID: plan.ExecutionID, Status: string(cloudworker.StateWaitingUser),
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, References: references, CreatedAt: plan.CreatedAt}
	turnEventRaw, _ := json.Marshal(turnEvent)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`,
		plan.TurnID, turnEvent.Sequence, string(turnEvent.Kind), turnEventRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	turnUpdate, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET revision=revision+1,last_sequence=$2,updated_at=$3
		WHERE turn_id=$1 AND state='waiting_confirmation' AND revision=$4`, plan.TurnID, turnEvent.Sequence, plan.CreatedAt, turn.Revision)
	if err != nil || turnUpdate.RowsAffected() != 1 {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}
	conversationUpdate, err := tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2 WHERE conversation_id=$1 AND revision=$3`,
		plan.ConversationID, plan.CreatedAt, conversationRevision)
	if err != nil || conversationUpdate.RowsAffected() != 1 {
		return cloudworker.Offer{}, cloudworker.ErrConflict
	}

	offerOutboxRaw, _ := json.Marshal(struct {
		PlanID, ExecutionID, TaskID, ConfirmationID string
	}{plan.PlanID, plan.ExecutionID, plan.TaskID, plan.ConfirmationID})
	offerOutboxDigest := sha256.Sum256(offerOutboxRaw)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_offer_outbox(event_id,plan_id,execution_id,conversation_id,turn_id,payload_digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, deterministicCloudWorkerUUID("offer-outbox", plan.ExecutionID), plan.PlanID,
		plan.ExecutionID, plan.ConversationID, plan.TurnID, hex.EncodeToString(offerOutboxDigest[:]), offerOutboxRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	replayRaw, _ = json.Marshal(cloudWorkerReplay{PlanID: plan.PlanID})
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_offer_replays(idempotency_key,request_digest,plan_id,response_json,created_at) VALUES($1,$2,$3,$4,$5)`,
		command.IdempotencyKey, command.RequestDigest, plan.PlanID, replayRaw, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	offer, err := s.offerTx(ctx, tx, plan.PlanID)
	if err != nil {
		return cloudworker.Offer{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Offer{}, err
	}
	return offer, nil
}

func requireCloudWorkerRequoteCleanupTx(ctx context.Context, tx pgx.Tx, executionID string) error {
	queries := []string{
		`SELECT state FROM core_cloud_worker_input_staging WHERE execution_id=$1 FOR UPDATE`,
		`SELECT state FROM core_cloud_worker_aws_ledger WHERE execution_id=$1 FOR UPDATE`,
		`SELECT state FROM core_cloud_worker_resources WHERE execution_id=$1 FOR UPDATE`,
	}
	for _, query := range queries {
		rows, err := tx.Query(ctx, query, executionID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var state string
			if err = rows.Scan(&state); err != nil {
				rows.Close()
				return err
			}
			if state != string(cloudworker.ResourceVerifiedDestroyed) {
				rows.Close()
				return cloudworker.ErrConflict
			}
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	var activeSessionCount, currentExpectationCount, activeGrantCount int
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core_cloud_worker_sessions WHERE execution_id=$1 AND state='active'),
		(SELECT count(*) FROM core_cloud_worker_launch_expectations WHERE execution_id=$1 AND current=true),
		(SELECT count(*) FROM core_cloud_worker_model_grants WHERE execution_id=$1 AND state='active')`, executionID).Scan(
		&activeSessionCount, &currentExpectationCount, &activeGrantCount); err != nil {
		return err
	}
	if activeSessionCount != 0 || currentExpectationCount != 0 || activeGrantCount != 0 {
		return cloudworker.ErrConflict
	}
	return nil
}

var _ cloudworker.Store = (*CloudWorkerStore)(nil)

// Compile-time reference retained because several transaction paths compare
// exact immutable values rather than relying on JSON text equality.
var _ = fmt.Sprintf
