package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CloudWorkerStore is the PostgreSQL authority for the retained SSH Worker
// execution path. It deliberately shares Store's pool so offer,
// confirmation, task, conversation and execution mutations can be committed
// in one PostgreSQL transaction.
type CloudWorkerStore struct{ store *Store }

func NewCloudWorkerStore(store *Store) *CloudWorkerStore { return &CloudWorkerStore{store: store} }

type privateCloudWorkerPlan struct {
	Objective             string                    `json:"objective"`
	InputManifest         cloudworker.InputManifest `json:"input_manifest"`
	PersistentWorkerReuse bool                      `json:"persistent_worker_reuse,omitempty"`
	ReuseWorkerID         string                    `json:"reuse_worker_id,omitempty"`
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
		PersistentWorkerReuse: copy.PersistentWorkerReuse, ReuseWorkerID: copy.ReuseWorkerID,
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
	plan.PersistentWorkerReuse = private.PersistentWorkerReuse
	plan.ReuseWorkerID = private.ReuseWorkerID
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
	var state, digest string
	var revision int64
	err := row.Scan(&raw, &state, &revision, &digest)
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
	execution.Revision = uint64(revision)
	if execution.Seal() != nil || execution.Digest != digest {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	return execution, nil
}

const cloudWorkerExecutionSelect = `SELECT execution_json,state,revision,digest FROM core_cloud_worker_executions`

func (s *CloudWorkerStore) CreateOffer(ctx context.Context, command cloudworker.CreateOfferCommand) (cloudworker.Offer, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(command.IdempotencyKey) ||
		!coretask.ValidDigest(command.RequestDigest) || !coretask.ValidUUID(command.TurnLeaseID) ||
		command.TurnLeaseEpoch == 0 || command.ExpectedTurnRevision == 0 {
		return cloudworker.Offer{}, cloudworker.ErrInvalid
	}
	plan, execution := command.Plan, command.Execution
	expectedExecutionState := cloudworker.StateWaitingUser
	requiresConfirmation := plan.RequiresWorkerCreationConfirmation()
	if !requiresConfirmation {
		expectedExecutionState = cloudworker.StateQueued
	}
	if plan.Seal() != nil || execution.Seal() != nil || plan.ExecutionID != execution.ExecutionID ||
		plan.TaskID != execution.TaskID || plan.ConfirmationID != execution.ConfirmationID ||
		plan.Digest != execution.PlanDigest || plan.ExecutionDigest != execution.ExecutionDigest ||
		command.TaskPayload.ExecutionID != plan.ExecutionID || command.TaskPayload.PlanID != plan.PlanID ||
		command.TaskPayload.PlanDigest != plan.Digest || command.TaskPayload.ConfirmationID != plan.ConfirmationID ||
		command.TaskPayload.AccountGeneration != plan.AccountGeneration || command.TaskPayload.TurnID != plan.TurnID ||
		command.TaskPayload.ConversationID != plan.ConversationID || command.TaskPayload.QuoteDigest != plan.Quote.Digest ||
		command.TaskPayload.ExecutionDigest != plan.ExecutionDigest || execution.State != expectedExecutionState {
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
	taskStatus, taskPhase, taskMessage := "waiting_user", "confirmation", "waiting for owner confirmation"
	if !requiresConfirmation {
		taskStatus, taskPhase, taskMessage = "queued", "worker_reuse", "existing Worker queued"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,
		attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,lease_epoch,
		lease_holder,available_at,revision,created_at,updated_at,task_kind,payload_json)
		VALUES($1,$2,$3,$4,$5,$6,$6,$6,$7,$8,0,1,0,'',$9,1,$10,$10,'cloud_worker',$11)`,
		plan.TaskID, spec.Goal, spec.ConversationID, spec.ModelProfileID, spec.IdempotencyKey, emptyArray,
		spec.TimeoutSeconds, taskStatus, spec.AvailableAt, plan.CreatedAt, payloadRaw); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, plan.TaskID, snapshotRaw, snapshot.Digest); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, plan.TaskID, spec.ModelProfileID); err != nil {
		return cloudworker.Offer{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at)
		VALUES($1,1,$2,0,$3,$4,$5,$6)`, plan.TaskID, deterministicCloudWorkerUUID("task-event", plan.TaskID), taskStatus, taskPhase, taskMessage, plan.CreatedAt); err != nil {
		return cloudworker.Offer{}, err
	}
	confirmationState := "pending"
	if !requiresConfirmation {
		// This confirmed row is an internal execution fence for using an existing
		// Worker. It is never published as a pending owner confirmation.
		confirmationState = "confirmed"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,
		task_id,state,consumed_released,revision,created_at,updated_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,false,1,$8,$8,$9)`, plan.ConfirmationID,
		normalizedBinding.OperationDomain, normalizedBinding.TargetID, normalizedBinding.TargetRevision,
		bindingRaw, plan.TaskID, confirmationState, plan.CreatedAt, plan.Quote.ExpiresAt); err != nil {
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
		execution_digest,execution_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		execution.ExecutionID, execution.OwnerID, execution.AccountGeneration, execution.PlanID, execution.PlanRevision,
		execution.PlanDigest, execution.TaskID, execution.ConfirmationID, execution.ConversationID, execution.TurnID,
		execution.State, execution.Revision, execution.Digest, execution.QuoteDigest, execution.ExecutionDigest, executionRaw,
		execution.CreatedAt, execution.UpdatedAt); err != nil {
		return cloudworker.Offer{}, err
	}

	confirmationProjection := confirmationState
	references := cloudWorkerReferences(plan, execution, 1, confirmationProjection)
	userMessage := core.Message{ID: deterministicCloudWorkerUUID("conversation-turn-user", turn.RequestID), TurnID: plan.TurnID, Role: core.RoleUser,
		Content: turn.Prompt, ModelProfileID: turn.ProfileID, CreatedAt: plan.CreatedAt.Add(-time.Microsecond)}
	offerMessage := core.Message{ID: deterministicCloudWorkerUUID("cloud-worker-offer-message", plan.ExecutionID), TurnID: plan.TurnID, Role: core.RoleAssistant,
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
	var priorTurnPlan bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_cloud_worker_plans WHERE turn_id=$1 AND plan_id<>$2)`, plan.TurnID, plan.PlanID).Scan(&priorTurnPlan); err != nil {
		return cloudworker.Offer{}, err
	}
	messages := make([]core.Message, 0, 2)
	if !priorTurnPlan {
		messages = append(messages, userMessage)
	}
	if requiresConfirmation {
		messages = append(messages, offerMessage)
	}
	for index, message := range messages {
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
	var nextTurnSequence uint64
	if requiresConfirmation {
		event, eventErr := core.NewWaitingConfirmationTurnEvent(plan.ConfirmationID, plan.ExecutionID)
		if eventErr != nil {
			return cloudworker.Offer{}, cloudworker.ErrInvalid
		}
		event.TurnID, event.Sequence, event.Revision, event.CreatedAt = plan.TurnID, int64(turn.LastSequence+1), command.ExpectedTurnRevision+1, plan.CreatedAt
		eventRaw, _ := json.Marshal(event)
		if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`,
			plan.TurnID, event.Sequence, string(event.Kind), eventRaw, plan.CreatedAt); err != nil {
			return cloudworker.Offer{}, err
		}
		nextTurnSequence = uint64(event.Sequence)
	} else {
		sequence, statusErr := insertCloudWorkerTurnStatusTx(ctx, tx, execution, plan.CreatedAt)
		if statusErr != nil {
			return cloudworker.Offer{}, statusErr
		}
		nextTurnSequence = uint64(sequence)
	}
	result, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='waiting_confirmation',revision=revision+1,
		last_sequence=$2,lease_id=NULL,lease_expires_at=NULL,updated_at=$3
		WHERE turn_id=$1 AND state='running' AND lease_id=$4 AND lease_epoch=$5 AND revision=$6 AND cancel_requested=false`,
		plan.TurnID, nextTurnSequence, plan.CreatedAt, command.TurnLeaseID, command.TurnLeaseEpoch, command.ExpectedTurnRevision)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return cloudworker.Offer{}, err
		}
		return cloudworker.Offer{}, cloudworker.ErrLeaseConflict
	}

	executionEventType := "offer_created"
	if !requiresConfirmation {
		executionEventType = "worker_reuse_queued"
	}
	executionEvent := cloudworker.Event{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		RunID: execution.RunID, ExecutionID: plan.ExecutionID,
		Sequence: 1, EventID: deterministicCloudWorkerUUID("execution-event-offer", plan.ExecutionID), Type: executionEventType,
		State: execution.State, Revision: execution.Revision, CreatedAt: plan.CreatedAt}
	executionEvent.PayloadDigest = digestCloudWorkerValue(struct {
		PlanID, TaskID, ConfirmationID, QuoteDigest string
	}{plan.PlanID, plan.TaskID, plan.ConfirmationID, plan.Quote.Digest})
	executionEventRaw, _ := json.Marshal(executionEvent)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_events(execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at)
		VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`, plan.ExecutionID, executionEvent.EventID, plan.OwnerID,
		executionEvent.Type, executionEvent.State, executionEvent.Revision, executionEvent.PayloadDigest, executionEventRaw, executionEvent.CreatedAt); err != nil {
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

func cloudWorkerReferences(plan cloudworker.Plan, execution cloudworker.Execution, confirmationRevision uint64, confirmationState string) []core.Reference {
	base := core.Reference{AccountGeneration: plan.AccountGeneration, TaskID: plan.TaskID,
		PlanID: plan.PlanID, PlanRevision: plan.Revision}
	planReference := base
	planReference.Kind, planReference.Status = "execution_plan", plan.Status
	runReference := base
	runReference.Kind, runReference.RunID, runReference.RunRevision = "execution_run", execution.RunID, execution.Revision
	runReference.ExecutionID, runReference.WorkerID, runReference.Status = execution.ExecutionID, execution.WorkerID, string(execution.State)
	confirmationReference := base
	confirmationReference.Kind, confirmationReference.ConfirmationID = "execution_confirmation", plan.ConfirmationID
	confirmationReference.ConfirmationRevision, confirmationReference.State = confirmationRevision, confirmationState
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

type cloudWorkerListCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func nullableTimePG(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
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

func (s *CloudWorkerStore) beginExecutionTx(ctx context.Context, tx pgx.Tx, current coretask.Task, now time.Time) (cloudworker.Execution, error) {
	if s == nil || s.store == nil || tx == nil || current.Spec.Payload.CloudWorker == nil || current.Lease == nil ||
		validateSSHWorkerTaskFence(current, current, now) != nil {
		return cloudworker.Execution{}, cloudworker.ErrLeaseConflict
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, current.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
	if err != nil {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	if cloudworker.ValidateFrozenBinding(plan, execution, confirmation.Binding) != nil || confirmation.State != coreconfirmation.StateConfirmed ||
		execution.State != cloudworker.StateQueued {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	updated, err := tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=$2
		WHERE confirmation_id=$1 AND state='confirmed' AND revision=$3`, plan.ConfirmationID, now, confirmation.Revision)
	if err != nil || updated.RowsAffected() != 1 {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_reservations(
		confirmation_id,task_id,acquired_attempt,acquired_lease_epoch,task_revision,acquired_lease_expires_at,active)
		VALUES($1,$2,$3,$4,$5,$6,true)`, plan.ConfirmationID, plan.TaskID, current.Attempt,
		current.LeaseEpoch, current.Revision, current.Lease.ExpiresAt); err != nil {
		return cloudworker.Execution{}, err
	}
	next, err := execution.Transition(cloudworker.StateProvisioning, now)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, next, "execution_started"); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
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
		execution_json=$5,updated_at=$6
		WHERE execution_id=$1 AND revision=$7 AND digest=$8`, next.ExecutionID, next.State, next.Revision,
		next.Digest, raw, next.UpdatedAt, previous.Revision, previous.Digest)
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
		RunID: next.RunID, ExecutionID: next.ExecutionID, Sequence: sequence,
		EventID: deterministicCloudWorkerUUID(eventType, fmt.Sprintf("%s:%d", next.ExecutionID, next.Revision)),
		Type:    eventType, State: next.State, Revision: next.Revision, CreatedAt: next.UpdatedAt}
	event.PayloadDigest = digestCloudWorkerValue(struct {
		State    cloudworker.ExecutionState
		Revision uint64
	}{next.State, next.Revision})
	payloadRaw, _ := json.Marshal(event)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_events(
		execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, next.ExecutionID, sequence, event.EventID,
		next.OwnerID, event.Type, event.State, event.Revision, event.PayloadDigest, payloadRaw, event.CreatedAt); err != nil {
		return err
	}
	if err = pruneCloudWorkerEventsTx(ctx, tx, next.ExecutionID, sequence); err != nil {
		return err
	}
	_, err = insertCloudWorkerTurnStatusTx(ctx, tx, next, next.UpdatedAt)
	return err
}

func insertCloudWorkerTurnStatusTx(ctx context.Context, tx pgx.Tx, execution cloudworker.Execution, at time.Time) (int64, error) {
	event, err := core.NewWorkerStatusTurnEvent(execution.ExecutionID, string(execution.State))
	if err != nil {
		return 0, cloudworker.ErrInvalid
	}
	var state string
	var lastSequence int64
	if err = tx.QueryRow(ctx, `SELECT state,last_sequence FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, execution.TurnID).Scan(&state, &lastSequence); err != nil {
		return 0, err
	}
	if state == string(core.TurnCompleted) || state == string(core.TurnCanceled) || state == string(core.TurnFailed) {
		return 0, cloudworker.ErrConflict
	}
	if err = insertTurnEventTx(ctx, tx, execution.TurnID, lastSequence+1, event, at); err != nil {
		return 0, err
	}
	return lastSequence + 1, nil
}

func pruneCloudWorkerEventsTx(ctx context.Context, tx pgx.Tx, executionID string, newest uint64) error {
	if newest <= cloudworker.MaxRetainedRunEvents {
		return nil
	}
	truncatedThrough := newest - cloudworker.MaxRetainedRunEvents
	if _, err := tx.Exec(ctx, `DELETE FROM core_cloud_worker_events
		WHERE execution_id=$1 AND sequence<=$2`, executionID, truncatedThrough); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE core_cloud_worker_executions
		SET event_history_truncated_through=GREATEST(event_history_truncated_through,$2)
		WHERE execution_id=$1`, executionID, truncatedThrough)
	return err
}

func cancelCloudWorkerExecutionTx(
	ctx context.Context,
	tx pgx.Tx,
	task coretask.Task,
	confirmation coreconfirmation.Confirmation,
	plan cloudworker.Plan,
	execution cloudworker.Execution,
	mutationID string,
	now time.Time,
) (cloudworker.Execution, error) {
	if tx == nil || !coretask.ValidUUID(mutationID) || now.IsZero() ||
		(execution.State != cloudworker.StateWaitingUser && execution.State != cloudworker.StateQueued &&
			execution.State != cloudworker.StateProvisioning && execution.State != cloudworker.StateRunning && execution.State != cloudworker.StateCleaning) ||
		(task.Status != coretask.StatusWaitingUser && task.Status != coretask.StatusQueued && task.Status != coretask.StatusRunning) ||
		(confirmation.State != coreconfirmation.StatePending && confirmation.State != coreconfirmation.StateConfirmed && confirmation.State != coreconfirmation.StateConsumed) ||
		plan.TaskID != task.ID || plan.ConfirmationID != confirmation.ConfirmationID ||
		cloudworker.ValidateFrozenBinding(plan, execution, confirmation.Binding) != nil {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	beforeDispatch := task.Status != coretask.StatusRunning
	summary := "Cloud Worker task stopped by user"
	if beforeDispatch {
		summary = "Cloud Worker task canceled before dispatch"
	}
	leaseEpoch := task.LeaseEpoch
	if task.Status == coretask.StatusRunning {
		leaseEpoch++
	}
	result, err := tx.Exec(ctx, `UPDATE core_tasks SET status='canceled',failure_code='user_canceled',
		failure_summary=$2,lease_epoch=$3,lease_holder='',lease_expires_at=NULL,
		revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$4
		WHERE task_id=$1 AND revision=$5 AND status=$6`, task.ID, summary, leaseEpoch, now, task.Revision, task.Status)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return cloudworker.Execution{}, err
		}
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	if task.Status == coretask.StatusRunning {
		if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency
			SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1
			WHERE singleton=true`, now); err != nil {
			return cloudworker.Execution{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at)
		SELECT task_id,progress_sequence,$2,attempt,'canceled','canceled','user_canceled',$3,$4
		FROM core_tasks WHERE task_id=$1`, task.ID, deterministicCloudWorkerUUID("cancel-task", mutationID), summary, now); err != nil {
		return cloudworker.Execution{}, err
	}
	if confirmation.State == coreconfirmation.StateConsumed {
		result, err = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false
			WHERE confirmation_id=$1 AND task_id=$2 AND active=true`, confirmation.ConfirmationID, task.ID)
		if err != nil || result.RowsAffected() != 1 {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		result, err = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=$2
			WHERE confirmation_id=$1 AND state='consumed' AND revision=$3 AND consumed_released=false`, confirmation.ConfirmationID, now, confirmation.Revision)
	} else {
		result, err = tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,
			terminal_code='user_canceled',terminal_reason='user_canceled',updated_at=$2
			WHERE confirmation_id=$1 AND revision=$3 AND state=$4`, confirmation.ConfirmationID, now, confirmation.Revision, confirmation.State)
	}
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return cloudworker.Execution{}, err
		}
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	next, err := execution.Transition(cloudworker.StateCanceled, now)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	next.FailureCode, next.FailureSummary = "user_canceled", summary
	if err = next.Seal(); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, next, "execution_canceled"); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = terminalizeCloudWorkerTurnTx(ctx, tx, confirmation, plan, next, cloudworker.StateCanceled, now); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}

func (s *CloudWorkerStore) RequestCancel(ctx context.Context, owner string, accountGeneration uint64, runID string, expectedRevision uint64, idempotencyKey string) (cloudworker.Execution, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || owner == "" || accountGeneration == 0 || !coretask.ValidUUID(runID) ||
		expectedRevision == 0 || !coretask.ValidUUID(idempotencyKey) {
		return cloudworker.Execution{}, cloudworker.ErrInvalid
	}
	requestDigest := digestCloudWorkerValue(struct {
		OwnerID           string
		AccountGeneration uint64
		RunID             string
		ExpectedRevision  uint64
	}{owner, accountGeneration, runID, expectedRevision})
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
	err = tx.QueryRow(ctx, `SELECT request_digest,execution_id::text,response_revision
		FROM core_cloud_worker_mutation_replays WHERE operation='request_cancel' AND idempotency_key=$1 FOR UPDATE`, idempotencyKey).Scan(
		&replayDigest, &replayExecution, &replayRevision)
	if err == nil {
		if replayDigest != requestDigest {
			return cloudworker.Execution{}, cloudworker.ErrConflict
		}
		execution, loadErr := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+`
			WHERE execution_id=$1 AND owner_id=$2 AND account_generation=$3`, replayExecution, owner, accountGeneration))
		if loadErr != nil || execution.Revision < replayRevision || execution.State != cloudworker.StateCanceled {
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
	var executionID, taskID, confirmationID string
	if err = tx.QueryRow(ctx, `SELECT execution_id::text,task_id::text,confirmation_id::text
		FROM core_cloud_worker_executions WHERE execution_json->>'run_id'=$1 AND owner_id=$2 AND account_generation=$3`,
		runID, owner, accountGeneration).Scan(&executionID, &taskID, &confirmationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudworker.Execution{}, cloudworker.ErrNotFound
		}
		return cloudworker.Execution{}, err
	}
	task, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, taskID, false)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, task.Spec.Payload.CloudWorker, true)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, confirmationID))
	if err != nil || plan.OwnerID != owner || plan.AccountGeneration != accountGeneration || plan.ExecutionID != executionID ||
		plan.TaskID != taskID || plan.ConfirmationID != confirmationID || cloudworker.ValidateFrozenBinding(plan, execution, confirmation.Binding) != nil {
		return cloudworker.Execution{}, cloudworker.ErrStaleAuthorization
	}
	if execution.Revision != expectedRevision {
		return cloudworker.Execution{}, cloudworker.ErrRevisionConflict
	}
	if (execution.State != cloudworker.StateWaitingUser && execution.State != cloudworker.StateQueued) ||
		(task.Status != coretask.StatusWaitingUser && task.Status != coretask.StatusQueued) ||
		(confirmation.State != coreconfirmation.StatePending && confirmation.State != coreconfirmation.StateConfirmed) {
		return cloudworker.Execution{}, cloudworker.ErrConflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	next, err := cancelCloudWorkerExecutionTx(ctx, tx, task, confirmation, plan, execution, idempotencyKey, now)
	if err != nil {
		return cloudworker.Execution{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_mutation_replays(
		operation,idempotency_key,request_digest,execution_id,response_revision)
		VALUES('request_cancel',$1,$2,$3,$4)`, idempotencyKey, requestDigest, executionID, next.Revision); err != nil {
		return cloudworker.Execution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return cloudworker.Execution{}, err
	}
	return next, nil
}
