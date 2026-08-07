package coreexecutionv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

const genericRunConfirmationTTL = 15 * time.Minute

// GenericRunEnvelope is the single durable projection for a non-Cloud-Worker
// Execution V2 run. Confirmation is the real shared CoreConfirmation record;
// no execution_v2 record with kind=confirmation is ever created.
type GenericRunEnvelope struct {
	Run          Record
	Stage        Record
	Task         coretask.Task
	Confirmation coreconfirmation.Confirmation
}

type GenericRunCreateCommand struct {
	Run          Record
	Stage        Record
	Task         coretask.Task
	Confirmation coreconfirmation.Confirmation
	At           time.Time
}

type GenericRunProjectCommand struct {
	Task                  coretask.Task
	ExpectedRunRevision   uint64
	ExpectedStageRevision uint64
	Status                string
	RunPayload            map[string]any
	StagePayload          map[string]any
	Result                coretask.Result
	FailureCode           string
	FailureSummary        string
	At                    time.Time
}

type GenericRunCancelCommand struct {
	Authority        Authority
	RunID            string
	ExpectedRevision uint64
	IdempotencyKey   string
	At               time.Time
}

// GenericRunLifecycle owns the transactions that join Execution V2 records
// to the real CoreTask/CoreConfirmation authorities. Implementations must
// validate the current task lease before consuming or projecting a run.
type GenericRunLifecycle interface {
	CreateGenericRun(context.Context, GenericRunCreateCommand) (GenericRunEnvelope, error)
	BeginGenericRun(context.Context, coretask.Task) (GenericRunEnvelope, error)
	ProjectGenericRun(context.Context, GenericRunProjectCommand) (GenericRunEnvelope, error)
	CancelGenericRun(context.Context, GenericRunCancelCommand) (GenericRunEnvelope, error)
}

// GenericRunConfirmationReader lets the typed runtime verify the real shared
// authorization record without depending on a shadow execution_v2 record.
type GenericRunConfirmationReader interface {
	ReadGenericRunConfirmation(context.Context, string, string) (coreconfirmation.Confirmation, error)
}

// GenericRunAuthoritySnapshot contains the immutable identifiers required to
// revalidate an Execution V2 run confirmation at every dispatch boundary. It
// deliberately excludes provider material and secret values.
type GenericRunAuthoritySnapshot struct {
	OwnerID           string
	AccountGeneration uint64
	RunID             string
	StageID           string
	TaskID            string
	PlanID            string
	PlanRevision      uint64
	PlanDigest        string
	ConfirmationID    string
	Operation         string
}

func newGenericRunCreateCommand(authority Authority, plan Record, operation, trigger, rollbackOf, retryOf, idempotencyKey string, now time.Time) (GenericRunCreateCommand, error) {
	authority.OwnerID = strings.TrimSpace(authority.OwnerID)
	operation = strings.TrimSpace(operation)
	trigger = strings.TrimSpace(trigger)
	rollbackOf = strings.TrimSpace(rollbackOf)
	retryOf = strings.TrimSpace(retryOf)
	if authority.OwnerID == "" || authority.AccountGeneration == 0 || plan.OwnerID != authority.OwnerID || plan.Kind != "plan" || plan.Status != "ready" || plan.Revision == 0 || !coretask.ValidDigest(plan.Digest) || !coretask.ValidUUID(idempotencyKey) || now.IsZero() || now.Location() != time.UTC || !validGenericRunOperation(operation) {
		return GenericRunCreateCommand{}, ErrInvalid
	}
	if operation == "rollback" {
		if !coretask.ValidUUID(rollbackOf) {
			return GenericRunCreateCommand{}, ErrInvalid
		}
	} else if rollbackOf != "" {
		return GenericRunCreateCommand{}, ErrInvalid
	}
	if retryOf != "" && !coretask.ValidUUID(retryOf) {
		return GenericRunCreateCommand{}, ErrInvalid
	}
	runID := deterministicID(authority.OwnerID, "agent.execution.v2.runs.create", idempotencyKey)
	if retryOf != "" {
		runID = deterministicID(authority.OwnerID, "agent.execution.v2.runs.retry", idempotencyKey)
	}
	stageID := stageIDForRun(authority.OwnerID, runID, plan.ID, operation)
	taskID := taskIDForStage(authority.OwnerID, stageID)
	confirmationID := deterministicID(authority.OwnerID, "execution-v2-confirmation", runID)
	runPayload := map[string]any{
		"plan_id": plan.ID, "plan_revision": plan.Revision, "operation": operation,
		"plan_digest": plan.Digest, "account_generation": authority.AccountGeneration,
		"trigger_kind": trigger, "status": "waiting_user", "requires_confirmation": true,
		"confirmation_id": confirmationID, "stage_id": stageID, "task_id": taskID,
		"dispatch_mode": "durable_controller",
	}
	if rollbackOf != "" {
		runPayload["rollback_of_run_id"] = rollbackOf
	}
	if retryOf != "" {
		runPayload["retry_of_run_id"] = retryOf
	}
	runPayload = ownedPayload(authority.OwnerID, runPayload)
	stagePayload := stageRecordPayload(authority.OwnerID, runID, plan.ID, operation, taskID, confirmationID, plan.Revision)
	stagePayload["plan_digest"] = plan.Digest
	stagePayload["account_generation"] = authority.AccountGeneration
	stagePayload["dispatch_mode"] = "durable_controller"
	stagePayload = ownedPayload(authority.OwnerID, stagePayload)
	run := Record{OwnerID: authority.OwnerID, Kind: "run", ID: runID, Revision: 1, Status: "waiting_user", Digest: digestPayload(runPayload), Payload: runPayload, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	stage := Record{OwnerID: authority.OwnerID, Kind: "stage", ID: stageID, Revision: 1, Status: "waiting_user", Digest: digestPayload(stagePayload), Payload: stagePayload, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	taskSpec, err := (coretask.TaskSpec{
		Kind: coretask.TaskKindExecutionV2Run,
		Payload: coretask.TaskPayload{ExecutionV2Run: &coretask.ExecutionV2RunTaskPayload{
			OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration,
			RunID: runID, StageID: stageID, PlanID: plan.ID, PlanRevision: plan.Revision,
			PlanDigest: plan.Digest, ConfirmationID: confirmationID, Operation: operation,
		}},
		Goal: "execute Execution V2 run " + runID, IdempotencyKey: idempotencyKey, AvailableAt: now.UTC(),
	}).Normalize()
	if err != nil {
		return GenericRunCreateCommand{}, ErrInvalid
	}
	task := coretask.Task{ID: taskID, Spec: taskSpec, Status: coretask.StatusWaitingUser, Attempt: 1, Revision: 1, ProgressSequence: 1, AvailableAt: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	binding := genericRunBinding(authority, plan, run, stage, task)
	if _, err := binding.Normalize(); err != nil {
		return GenericRunCreateCommand{}, ErrInvalid
	}
	confirmation := coreconfirmation.Confirmation{
		ConfirmationID: confirmationID, OwnerID: authority.OwnerID, Binding: binding,
		TaskID: taskID, State: coreconfirmation.StatePending, Revision: 1,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(), ExpiresAt: now.UTC().Add(genericRunConfirmationTTL),
	}
	command := GenericRunCreateCommand{Run: run, Stage: stage, Task: task, Confirmation: confirmation, At: now.UTC()}
	if err := validateGenericRunCreate(command); err != nil {
		return GenericRunCreateCommand{}, err
	}
	return command, nil
}

func validGenericRunOperation(value string) bool {
	switch value {
	case "execute", "deploy", "upgrade", "repair", "destroy", "rollback":
		return true
	default:
		return false
	}
}

func genericRunBinding(authority Authority, plan, run, stage Record, task coretask.Task) coreconfirmation.Binding {
	snapshot := GenericRunAuthoritySnapshot{
		OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration,
		RunID: run.ID, StageID: stage.ID, TaskID: task.ID, PlanID: plan.ID,
		PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		ConfirmationID: stringParam(run.Payload, "confirmation_id"),
		Operation:      stringParam(run.Payload, "operation"),
	}
	binding, _ := GenericRunConfirmationBinding(snapshot)
	return binding
}

func genericRunPermissionDigest(snapshot GenericRunAuthoritySnapshot) string {
	return digestGenericValue(struct {
		OwnerID           string
		AccountGeneration uint64
	}{snapshot.OwnerID, snapshot.AccountGeneration})
}

func genericRunParameterDigest(snapshot GenericRunAuthoritySnapshot) string {
	return digestGenericValue(struct {
		RunID, StageID, TaskID, PlanID, Operation string
		PlanRevision                              uint64
	}{snapshot.RunID, snapshot.StageID, snapshot.TaskID, snapshot.PlanID, snapshot.Operation, snapshot.PlanRevision})
}

// GenericRunConfirmationBinding constructs the one canonical authorization
// binding shared by creation, durable consumption, and the typed provider
// boundary. It is exported so adapters and black-box tests do not duplicate
// digest construction.
func GenericRunConfirmationBinding(snapshot GenericRunAuthoritySnapshot) (coreconfirmation.Binding, error) {
	snapshot, err := normalizeGenericRunAuthoritySnapshot(snapshot)
	if err != nil {
		return coreconfirmation.Binding{}, err
	}
	return coreconfirmation.Binding{
		OwnerID: snapshot.OwnerID, AccountGeneration: snapshot.AccountGeneration,
		OperationDomain: "execution_v2.run", TargetID: snapshot.RunID, TargetRevision: 1,
		TargetKind: "execution_v2_run", SourceVersion: SchemaVersion,
		ContentDigest:     coreconfirmation.Digest(snapshot.PlanDigest),
		PermissionDigest:  coreconfirmation.Digest(genericRunPermissionDigest(snapshot)),
		ParameterDigest:   coreconfirmation.Digest(genericRunParameterDigest(snapshot)),
		NetworkDigest:     coreconfirmation.Digest(digestGenericValue([]string{})),
		SecretGrantDigest: coreconfirmation.Digest(digestGenericValue([]string{})),
		SelectedTool:      "execution_v2.typed_runtime",
		SelectedCommand:   []string{snapshot.Operation},
	}, nil
}

func normalizeGenericRunAuthoritySnapshot(snapshot GenericRunAuthoritySnapshot) (GenericRunAuthoritySnapshot, error) {
	snapshot.OwnerID = strings.TrimSpace(snapshot.OwnerID)
	snapshot.RunID = strings.TrimSpace(snapshot.RunID)
	snapshot.StageID = strings.TrimSpace(snapshot.StageID)
	snapshot.TaskID = strings.TrimSpace(snapshot.TaskID)
	snapshot.PlanID = strings.TrimSpace(snapshot.PlanID)
	snapshot.PlanDigest = strings.TrimSpace(snapshot.PlanDigest)
	snapshot.ConfirmationID = strings.TrimSpace(snapshot.ConfirmationID)
	snapshot.Operation = strings.TrimSpace(snapshot.Operation)
	if snapshot.OwnerID == "" || snapshot.AccountGeneration == 0 ||
		!coretask.ValidUUID(snapshot.RunID) || !coretask.ValidUUID(snapshot.StageID) ||
		!coretask.ValidUUID(snapshot.TaskID) || !coretask.ValidUUID(snapshot.PlanID) ||
		snapshot.PlanRevision == 0 || !coretask.ValidDigest(snapshot.PlanDigest) ||
		!coretask.ValidUUID(snapshot.ConfirmationID) || !validGenericRunOperation(snapshot.Operation) {
		return GenericRunAuthoritySnapshot{}, ErrInvalid
	}
	return snapshot, nil
}

// ValidateGenericRunConfirmation proves that the shared CoreConfirmation is
// the consumed authorization for exactly one owner/account-generation/run/
// stage/task/plan tuple. UUID possession alone is never an authority fence.
func ValidateGenericRunConfirmation(value coreconfirmation.Confirmation, snapshot GenericRunAuthoritySnapshot, requiredState coreconfirmation.State) error {
	var err error
	snapshot, err = normalizeGenericRunAuthoritySnapshot(snapshot)
	if err != nil ||
		value.ConfirmationID != snapshot.ConfirmationID || value.OwnerID != snapshot.OwnerID ||
		value.TaskID != snapshot.TaskID || value.State != requiredState {
		return ErrConflict
	}
	expected, err := GenericRunConfirmationBinding(snapshot)
	if err != nil || !value.Binding.Equal(expected) {
		return ErrConflict
	}
	return nil
}

func digestGenericValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateGenericRunCreate(command GenericRunCreateCommand) error {
	p := command.Task.Spec.Payload.ExecutionV2Run
	if command.At.IsZero() || command.At.Location() != time.UTC || p == nil || command.Task.Validate() != nil ||
		command.Run.OwnerID == "" || command.Run.Kind != "run" || command.Run.Revision != 1 ||
		command.Stage.OwnerID != command.Run.OwnerID || command.Stage.Kind != "stage" || command.Stage.Revision != 1 ||
		command.Run.ID != p.RunID || command.Stage.ID != p.StageID || command.Task.ID == "" ||
		command.Confirmation.ConfirmationID != p.ConfirmationID || command.Confirmation.TaskID != command.Task.ID ||
		command.Confirmation.OwnerID != p.OwnerID || command.Confirmation.Binding.OwnerID != p.OwnerID ||
		command.Confirmation.Binding.AccountGeneration != p.AccountGeneration ||
		command.Confirmation.Binding.OperationDomain != "execution_v2.run" ||
		command.Confirmation.Binding.TargetID != p.RunID || command.Confirmation.State != coreconfirmation.StatePending ||
		!command.Confirmation.ExpiresAt.After(command.At) ||
		stringParam(command.Run.Payload, "plan_digest") != p.PlanDigest ||
		uintParam(command.Run.Payload, "account_generation") != p.AccountGeneration ||
		stringParam(command.Stage.Payload, "plan_digest") != p.PlanDigest ||
		uintParam(command.Stage.Payload, "account_generation") != p.AccountGeneration {
		return ErrInvalid
	}
	snapshot := GenericRunAuthoritySnapshot{
		OwnerID: p.OwnerID, AccountGeneration: p.AccountGeneration, RunID: p.RunID,
		StageID: p.StageID, TaskID: command.Task.ID, PlanID: p.PlanID,
		PlanRevision: p.PlanRevision, PlanDigest: p.PlanDigest,
		ConfirmationID: p.ConfirmationID, Operation: p.Operation,
	}
	if ValidateGenericRunConfirmation(command.Confirmation, snapshot, coreconfirmation.StatePending) != nil {
		return ErrInvalid
	}
	return nil
}

func validateGenericRunTask(task coretask.Task) (*coretask.ExecutionV2RunTaskPayload, error) {
	p := task.Spec.Payload.ExecutionV2Run
	if task.Spec.Kind != coretask.TaskKindExecutionV2Run || p == nil || task.Status != coretask.StatusRunning ||
		task.Lease == nil || task.Lease.TaskID != task.ID || task.Lease.Attempt != task.Attempt ||
		task.Lease.Epoch != task.LeaseEpoch || task.Attempt == 0 || task.LeaseEpoch == 0 ||
		task.Revision == 0 || task.Lease.Holder == "" || task.Lease.ExpiresAt.IsZero() {
		return nil, ErrInvalid
	}
	return p, nil
}

// GenericRunHandler is the internal durable controller. There is deliberately
// no public runs.reconcile action: a confirmed CoreTask is the only dispatcher.
func (s *Service) GenericRunHandler() coreruntime.TaskHandler {
	return func(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
		return s.handleGenericRunTask(ctx, task)
	}
}

func (s *Service) handleGenericRunTask(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
	payload, err := validateGenericRunTask(task)
	if err != nil || s == nil || s.runLifecycle == nil || s.providers.Reconcile == nil {
		if err == nil {
			err = ErrMissingPort
		}
		return coreruntime.ManagedOutcome{Err: err}
	}
	envelope, err := s.runLifecycle.BeginGenericRun(ctx, task)
	if err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	task = envelope.Task
	if err := ValidateGenericRunConfirmation(envelope.Confirmation, GenericRunAuthoritySnapshot{
		OwnerID: payload.OwnerID, AccountGeneration: payload.AccountGeneration,
		RunID: payload.RunID, StageID: payload.StageID, TaskID: task.ID,
		PlanID: payload.PlanID, PlanRevision: payload.PlanRevision, PlanDigest: payload.PlanDigest,
		ConfirmationID: payload.ConfirmationID, Operation: payload.Operation,
	}, coreconfirmation.StateConsumed); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	for {
		if stageTerminal(envelope.Run.Status) {
			return coreruntime.ManagedOutcome{TerminalOwned: true}
		}
		input := map[string]any{
			"run_id": payload.RunID, "stage_id": payload.StageID,
			"expected_revision": envelope.Run.Revision, "idempotency_key": task.ID,
		}
		providerPayload, providerErr := s.providers.Reconcile(ctx, payload.OwnerID, input)
		if providerErr != nil {
			if errors.Is(providerErr, context.Canceled) || errors.Is(providerErr, context.DeadlineExceeded) || ctx.Err() != nil {
				return coreruntime.ManagedOutcome{Err: providerErr}
			}
			providerPayload = map[string]any{"status": "failed", "reason": "typed_runtime_failed"}
		}
		if err := validateGenericRunProviderPayload(providerPayload, payload, task.ID); err != nil {
			providerPayload = map[string]any{"status": "failed", "reason": "typed_runtime_invalid_result"}
		}
		status := stringParam(providerPayload, "status")
		runPayload := cloneMap(envelope.Run.Payload)
		stagePayload := cloneMap(envelope.Stage.Payload)
		for key, value := range providerPayload {
			runPayload[key] = value
			stagePayload[key] = value
		}
		runPayload["status"] = status
		stagePayload["status"] = status
		stagePayload["run_revision"] = float64(envelope.Run.Revision + 1)
		resultRaw, _ := json.Marshal(map[string]any{"run_id": payload.RunID, "stage_id": payload.StageID, "status": status})
		project := GenericRunProjectCommand{
			Task: task, ExpectedRunRevision: envelope.Run.Revision, ExpectedStageRevision: envelope.Stage.Revision,
			Status: status, RunPayload: runPayload, StagePayload: stagePayload,
			Result: coretask.Result{JSON: resultRaw, Summary: "Execution V2 run " + status}, At: time.Now().UTC(),
		}
		if status != "succeeded" && stageTerminal(status) {
			project.FailureCode = "execution_v2_" + status
			project.FailureSummary = "Execution V2 run " + status
		}
		envelope, err = s.runLifecycle.ProjectGenericRun(ctx, project)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		if stageTerminal(status) {
			return coreruntime.ManagedOutcome{TerminalOwned: true}
		}
		task = envelope.Task
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return coreruntime.ManagedOutcome{Err: ctx.Err()}
		case <-timer.C:
		}
		envelope, err = s.runLifecycle.BeginGenericRun(ctx, task)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		task = envelope.Task
	}
}

func validateGenericRunProviderPayload(value map[string]any, payload *coretask.ExecutionV2RunTaskPayload, taskID string) error {
	if value == nil || validateSafeInput(value) != nil {
		return ErrUnsafeOutput
	}
	for key, expected := range map[string]string{
		"run_id": payload.RunID, "stage_id": payload.StageID,
		"confirmation_id": payload.ConfirmationID, "task_id": taskID,
	} {
		if actual := stringParam(value, key); actual != "" && actual != expected {
			return fmt.Errorf("%w: provider %s binding mismatch", ErrConflict, key)
		}
	}
	switch stringParam(value, "status") {
	case "queued", "running", "uncertain", "succeeded", "failed", "canceled", "rejected", "expired":
		return nil
	default:
		return ErrUnsafeOutput
	}
}
