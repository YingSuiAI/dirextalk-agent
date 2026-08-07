package coreexecutionv2

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type genericRunCancelReplay struct {
	Digest   string
	Envelope GenericRunEnvelope
}

func (m *MemoryStore) CreateGenericRun(_ context.Context, command GenericRunCreateCommand) (GenericRunEnvelope, error) {
	if m == nil || validateGenericRunCreate(command) != nil {
		return GenericRunEnvelope{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if replay, ok := m.genericCreateEnvelopes[command.Run.ID]; ok {
		if !genericCreateMatches(replay, command) {
			return GenericRunEnvelope{}, ErrConflict
		}
		return cloneGenericRunEnvelope(replay), nil
	}
	runKey := recordKey(command.Run.OwnerID, command.Run.Kind, command.Run.ID)
	stageKey := recordKey(command.Stage.OwnerID, command.Stage.Kind, command.Stage.ID)
	if _, ok := m.records[runKey]; ok {
		return GenericRunEnvelope{}, ErrConflict
	}
	if _, ok := m.records[stageKey]; ok {
		return GenericRunEnvelope{}, ErrConflict
	}
	if _, ok := m.genericTasks[command.Task.ID]; ok {
		return GenericRunEnvelope{}, ErrConflict
	}
	if _, ok := m.genericConfirmations[command.Confirmation.ConfirmationID]; ok {
		return GenericRunEnvelope{}, ErrConflict
	}

	m.records[runKey] = cloneRecord(command.Run)
	m.revisions[runKey] = map[uint64]Record{command.Run.Revision: cloneRecord(command.Run)}
	m.records[stageKey] = cloneRecord(command.Stage)
	m.revisions[stageKey] = map[uint64]Record{command.Stage.Revision: cloneRecord(command.Stage)}
	m.genericTasks[command.Task.ID] = cloneGenericRunTask(command.Task)
	m.genericConfirmations[command.Confirmation.ConfirmationID] = cloneGenericRunConfirmation(command.Confirmation)
	envelope := GenericRunEnvelope{Run: command.Run, Stage: command.Stage, Task: command.Task, Confirmation: command.Confirmation}
	m.genericCreateEnvelopes[command.Run.ID] = cloneGenericRunEnvelope(envelope)
	return cloneGenericRunEnvelope(envelope), nil
}

func (m *MemoryStore) BeginGenericRun(_ context.Context, task coretask.Task) (GenericRunEnvelope, error) {
	payload, err := validateGenericRunTask(task)
	if m == nil || err != nil {
		return GenericRunEnvelope{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	envelope, err := m.genericRunEnvelopeLocked(payload.OwnerID, payload.RunID)
	if err != nil {
		return GenericRunEnvelope{}, err
	}
	if err := validateGenericEnvelopeBindings(envelope, payload); err != nil || !sameGenericTaskIdentity(envelope.Task, task) {
		return GenericRunEnvelope{}, ErrConflict
	}
	if ValidateGenericRunConfirmation(envelope.Confirmation, genericRunSnapshot(envelope, payload), envelope.Confirmation.State) != nil {
		return GenericRunEnvelope{}, ErrConflict
	}
	switch envelope.Task.Status {
	case coretask.StatusQueued:
		if task.Revision <= envelope.Task.Revision {
			return GenericRunEnvelope{}, ErrConflict
		}
	case coretask.StatusRunning:
		if !sameGenericTaskFence(envelope.Task, task) && task.Revision <= envelope.Task.Revision {
			return GenericRunEnvelope{}, ErrConflict
		}
	default:
		return GenericRunEnvelope{}, ErrConflict
	}
	if envelope.Confirmation.State != coreconfirmation.StateConfirmed && envelope.Confirmation.State != coreconfirmation.StateConsumed {
		return GenericRunEnvelope{}, ErrConflict
	}

	m.genericTasks[task.ID] = cloneGenericRunTask(task)
	envelope.Task = task
	if envelope.Confirmation.State == coreconfirmation.StateConfirmed {
		envelope.Confirmation.State = coreconfirmation.StateConsumed
		envelope.Confirmation.Revision++
		envelope.Confirmation.UpdatedAt = task.UpdatedAt.UTC()
		m.genericConfirmations[envelope.Confirmation.ConfirmationID] = cloneGenericRunConfirmation(envelope.Confirmation)
	}
	if envelope.Run.Status == "queued" {
		envelope.Run = m.updateGenericRecordLocked(envelope.Run, "running", task.UpdatedAt)
		envelope.Stage = m.updateGenericRecordLocked(envelope.Stage, "running", task.UpdatedAt)
	} else if envelope.Run.Status != "running" || envelope.Stage.Status != "running" {
		return GenericRunEnvelope{}, ErrConflict
	}
	return cloneGenericRunEnvelope(envelope), nil
}

func (m *MemoryStore) ProjectGenericRun(_ context.Context, command GenericRunProjectCommand) (GenericRunEnvelope, error) {
	payload, err := validateGenericRunTask(command.Task)
	if m == nil || err != nil || command.At.IsZero() || command.At.Location() != time.UTC ||
		command.ExpectedRunRevision == 0 || command.ExpectedStageRevision == 0 ||
		!validGenericProjectionStatus(command.Status) {
		return GenericRunEnvelope{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	envelope, err := m.genericRunEnvelopeLocked(payload.OwnerID, payload.RunID)
	if err != nil {
		return GenericRunEnvelope{}, err
	}
	if err := validateGenericEnvelopeBindings(envelope, payload); err != nil ||
		!sameGenericTaskFence(envelope.Task, command.Task) ||
		envelope.Run.Revision != command.ExpectedRunRevision ||
		envelope.Stage.Revision != command.ExpectedStageRevision ||
		envelope.Run.Status != "running" || envelope.Stage.Status != "running" ||
		envelope.Confirmation.State != coreconfirmation.StateConsumed ||
		ValidateGenericRunConfirmation(envelope.Confirmation, genericRunSnapshot(envelope, payload), coreconfirmation.StateConsumed) != nil ||
		!validGenericProjectionPayload(command.RunPayload, envelope, payload) ||
		!validGenericProjectionPayload(command.StagePayload, envelope, payload) {
		return GenericRunEnvelope{}, ErrConflict
	}

	envelope.Run.Payload = cloneMap(command.RunPayload)
	envelope.Run = m.updateGenericRecordLocked(envelope.Run, command.Status, command.At)
	envelope.Stage.Payload = cloneMap(command.StagePayload)
	envelope.Stage = m.updateGenericRecordLocked(envelope.Stage, command.Status, command.At)
	envelope.Task.Revision++
	envelope.Task.ProgressSequence++
	envelope.Task.UpdatedAt = command.At
	if stageTerminal(command.Status) {
		envelope.Task.Lease = nil
		switch command.Status {
		case "succeeded":
			envelope.Task.Status = coretask.StatusSucceeded
			envelope.Task.Result = cloneGenericRunResult(&command.Result)
		case "canceled":
			envelope.Task.Status = coretask.StatusCanceled
			envelope.Task.FailureCode = strings.TrimSpace(command.FailureCode)
			envelope.Task.FailureSummary = strings.TrimSpace(command.FailureSummary)
		default:
			envelope.Task.Status = coretask.StatusFailed
			envelope.Task.FailureCode = strings.TrimSpace(command.FailureCode)
			envelope.Task.FailureSummary = strings.TrimSpace(command.FailureSummary)
		}
	} else {
		envelope.Task.Status = coretask.StatusRunning
	}
	m.genericTasks[envelope.Task.ID] = cloneGenericRunTask(envelope.Task)
	return cloneGenericRunEnvelope(envelope), nil
}

func (m *MemoryStore) CancelGenericRun(_ context.Context, command GenericRunCancelCommand) (GenericRunEnvelope, error) {
	command.Authority.OwnerID = strings.TrimSpace(command.Authority.OwnerID)
	command.RunID = strings.TrimSpace(command.RunID)
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	if m == nil || command.Authority.OwnerID == "" || command.Authority.AccountGeneration == 0 ||
		!coretask.ValidUUID(command.RunID) || command.ExpectedRevision == 0 ||
		!coretask.ValidUUID(command.IdempotencyKey) || command.At.IsZero() || command.At.Location() != time.UTC {
		return GenericRunEnvelope{}, ErrInvalid
	}
	digest := digestGenericValue(struct {
		OwnerID           string
		AccountGeneration uint64
		RunID             string
		ExpectedRevision  uint64
	}{command.Authority.OwnerID, command.Authority.AccountGeneration, command.RunID, command.ExpectedRevision})
	replayKey := replayKey(command.Authority.OwnerID, "execution_v2_run_cancel", command.IdempotencyKey)

	m.mu.Lock()
	defer m.mu.Unlock()
	if replay, ok := m.genericCancelReplays[replayKey]; ok {
		if replay.Digest != digest {
			return GenericRunEnvelope{}, ErrConflict
		}
		return cloneGenericRunEnvelope(replay.Envelope), nil
	}
	envelope, err := m.genericRunEnvelopeLocked(command.Authority.OwnerID, command.RunID)
	if err != nil {
		return GenericRunEnvelope{}, err
	}
	payload := envelope.Task.Spec.Payload.ExecutionV2Run
	if payload == nil || payload.AccountGeneration != command.Authority.AccountGeneration ||
		envelope.Run.Revision != command.ExpectedRevision || stageTerminal(envelope.Run.Status) ||
		validateGenericEnvelopeBindings(envelope, payload) != nil ||
		ValidateGenericRunConfirmation(envelope.Confirmation, genericRunSnapshot(envelope, payload), envelope.Confirmation.State) != nil {
		return GenericRunEnvelope{}, ErrConflict
	}

	envelope.Run = m.updateGenericRecordLocked(envelope.Run, "canceled", command.At)
	envelope.Stage = m.updateGenericRecordLocked(envelope.Stage, "canceled", command.At)
	switch envelope.Task.Status {
	case coretask.StatusWaitingUser, coretask.StatusQueued, coretask.StatusRunning:
		envelope.Task.Status = coretask.StatusCanceled
		envelope.Task.Lease = nil
		envelope.Task.Revision++
		envelope.Task.ProgressSequence++
		envelope.Task.UpdatedAt = command.At
		envelope.Task.FailureCode = "execution_v2_canceled"
		envelope.Task.FailureSummary = "Execution V2 run canceled"
	default:
		return GenericRunEnvelope{}, ErrConflict
	}
	if envelope.Confirmation.State == coreconfirmation.StatePending || envelope.Confirmation.State == coreconfirmation.StateConfirmed {
		envelope.Confirmation.State = coreconfirmation.StateExpired
		envelope.Confirmation.Revision++
		envelope.Confirmation.UpdatedAt = command.At
		envelope.Confirmation.TerminalCode = "task_canceled"
		envelope.Confirmation.TerminalReason = "task_canceled"
	}
	m.genericTasks[envelope.Task.ID] = cloneGenericRunTask(envelope.Task)
	m.genericConfirmations[envelope.Confirmation.ConfirmationID] = cloneGenericRunConfirmation(envelope.Confirmation)
	m.genericCancelReplays[replayKey] = genericRunCancelReplay{Digest: digest, Envelope: cloneGenericRunEnvelope(envelope)}
	return cloneGenericRunEnvelope(envelope), nil
}

func (m *MemoryStore) ReadGenericRunConfirmation(_ context.Context, owner, confirmationID string) (coreconfirmation.Confirmation, error) {
	if m == nil {
		return coreconfirmation.Confirmation{}, ErrInvalid
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.genericConfirmations[strings.TrimSpace(confirmationID)]
	if !ok || value.OwnerID != strings.TrimSpace(owner) {
		return coreconfirmation.Confirmation{}, ErrNotFound
	}
	return cloneGenericRunConfirmation(value), nil
}

// confirmGenericRun is the in-memory equivalent of the shared confirmation
// transaction. It is intentionally unexported; production composition uses
// the PostgreSQL CoreConfirmation lifecycle.
func (m *MemoryStore) confirmGenericRun(authority Authority, confirmationID string, expectedRevision int64, at time.Time) (GenericRunEnvelope, error) {
	if m == nil || strings.TrimSpace(authority.OwnerID) == "" || authority.AccountGeneration == 0 ||
		!coretask.ValidUUID(strings.TrimSpace(confirmationID)) || expectedRevision < 1 || at.IsZero() {
		return GenericRunEnvelope{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	confirmation, ok := m.genericConfirmations[confirmationID]
	if !ok || confirmation.OwnerID != authority.OwnerID {
		return GenericRunEnvelope{}, ErrNotFound
	}
	if confirmation.Binding.AccountGeneration != authority.AccountGeneration || confirmation.Revision != expectedRevision ||
		confirmation.State != coreconfirmation.StatePending || !confirmation.ExpiresAt.After(at) {
		return GenericRunEnvelope{}, ErrConflict
	}
	envelope, err := m.genericRunEnvelopeLocked(authority.OwnerID, confirmation.Binding.TargetID)
	if err != nil || envelope.Task.Status != coretask.StatusWaitingUser || envelope.Run.Status != "waiting_user" {
		return GenericRunEnvelope{}, ErrConflict
	}
	confirmation.State = coreconfirmation.StateConfirmed
	confirmation.Revision++
	confirmation.UpdatedAt = at.UTC()
	envelope.Confirmation = confirmation
	envelope.Task.Status = coretask.StatusQueued
	envelope.Task.Revision++
	envelope.Task.ProgressSequence++
	envelope.Task.AvailableAt = at.UTC()
	envelope.Task.UpdatedAt = at.UTC()
	envelope.Run = m.updateGenericRecordLocked(envelope.Run, "queued", at.UTC())
	envelope.Stage = m.updateGenericRecordLocked(envelope.Stage, "queued", at.UTC())
	m.genericConfirmations[confirmationID] = cloneGenericRunConfirmation(confirmation)
	m.genericTasks[envelope.Task.ID] = cloneGenericRunTask(envelope.Task)
	return cloneGenericRunEnvelope(envelope), nil
}

// rejectGenericRun is the in-memory equivalent of the shared confirmation
// rejection transaction. Production uses the PostgreSQL CoreConfirmation
// repository, which projects the same terminal state atomically.
func (m *MemoryStore) rejectGenericRun(authority Authority, confirmationID string, expectedRevision int64, at time.Time) (GenericRunEnvelope, error) {
	return m.terminalizeGenericRunConfirmation(authority, confirmationID, expectedRevision, coreconfirmation.StateRejected, coreconfirmation.ReasonUserRejected, at)
}

// expireGenericRun is the in-memory equivalent of the shared confirmation
// expiry transaction. It accepts both pending and confirmed authorizations;
// neither state is allowed to reach the provider after this mutation.
func (m *MemoryStore) expireGenericRun(authority Authority, confirmationID string, expectedRevision int64, reason string, at time.Time) (GenericRunEnvelope, error) {
	if reason != coreconfirmation.ReasonExpired && reason != coreconfirmation.ReasonStale {
		return GenericRunEnvelope{}, ErrInvalid
	}
	return m.terminalizeGenericRunConfirmation(authority, confirmationID, expectedRevision, coreconfirmation.StateExpired, reason, at)
}

func (m *MemoryStore) terminalizeGenericRunConfirmation(
	authority Authority,
	confirmationID string,
	expectedRevision int64,
	next coreconfirmation.State,
	reason string,
	at time.Time,
) (GenericRunEnvelope, error) {
	authority.OwnerID = strings.TrimSpace(authority.OwnerID)
	confirmationID = strings.TrimSpace(confirmationID)
	if m == nil || authority.OwnerID == "" || authority.AccountGeneration == 0 ||
		!coretask.ValidUUID(confirmationID) || expectedRevision < 1 || at.IsZero() || at.Location() != time.UTC ||
		(next != coreconfirmation.StateRejected && next != coreconfirmation.StateExpired) {
		return GenericRunEnvelope{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	confirmation, ok := m.genericConfirmations[confirmationID]
	if !ok || confirmation.OwnerID != authority.OwnerID {
		return GenericRunEnvelope{}, ErrNotFound
	}
	if confirmation.Binding.AccountGeneration != authority.AccountGeneration || confirmation.Revision != expectedRevision {
		return GenericRunEnvelope{}, ErrConflict
	}
	if next == coreconfirmation.StateRejected && confirmation.State != coreconfirmation.StatePending {
		return GenericRunEnvelope{}, ErrConflict
	}
	if next == coreconfirmation.StateExpired && confirmation.State != coreconfirmation.StatePending && confirmation.State != coreconfirmation.StateConfirmed {
		return GenericRunEnvelope{}, ErrConflict
	}
	envelope, err := m.genericRunEnvelopeLocked(authority.OwnerID, confirmation.Binding.TargetID)
	if err != nil || ValidateGenericRunConfirmation(confirmation, genericRunSnapshot(envelope, envelope.Task.Spec.Payload.ExecutionV2Run), confirmation.State) != nil {
		return GenericRunEnvelope{}, ErrConflict
	}
	switch confirmation.State {
	case coreconfirmation.StatePending:
		if envelope.Task.Status != coretask.StatusWaitingUser || envelope.Run.Status != "waiting_user" || envelope.Stage.Status != "waiting_user" {
			return GenericRunEnvelope{}, ErrConflict
		}
	case coreconfirmation.StateConfirmed:
		if envelope.Task.Status != coretask.StatusQueued || envelope.Run.Status != "queued" || envelope.Stage.Status != "queued" {
			return GenericRunEnvelope{}, ErrConflict
		}
	default:
		return GenericRunEnvelope{}, ErrConflict
	}

	status := "expired"
	taskStatus := coretask.StatusFailed
	if next == coreconfirmation.StateRejected {
		status = "rejected"
		taskStatus = coretask.StatusCanceled
	}
	confirmation.State = next
	confirmation.Revision++
	confirmation.UpdatedAt = at.UTC()
	confirmation.TerminalCode = reason
	confirmation.TerminalReason = reason
	envelope.Confirmation = confirmation
	envelope.Run = m.updateGenericRecordLocked(envelope.Run, status, at.UTC())
	envelope.Stage = m.updateGenericRecordLocked(envelope.Stage, status, at.UTC())
	envelope.Task.Status = taskStatus
	envelope.Task.Lease = nil
	envelope.Task.Revision++
	envelope.Task.ProgressSequence++
	envelope.Task.UpdatedAt = at.UTC()
	envelope.Task.FailureCode = reason
	envelope.Task.FailureSummary = reason
	m.genericConfirmations[confirmationID] = cloneGenericRunConfirmation(confirmation)
	m.genericTasks[envelope.Task.ID] = cloneGenericRunTask(envelope.Task)
	return cloneGenericRunEnvelope(envelope), nil
}

func (m *MemoryStore) genericRunEnvelopeLocked(owner, runID string) (GenericRunEnvelope, error) {
	run, ok := m.records[recordKey(owner, "run", runID)]
	if !ok {
		return GenericRunEnvelope{}, ErrNotFound
	}
	stageID := stringParam(run.Payload, "stage_id")
	stage, ok := m.records[recordKey(owner, "stage", stageID)]
	if !ok {
		return GenericRunEnvelope{}, ErrConflict
	}
	taskID := stringParam(run.Payload, "task_id")
	task, ok := m.genericTasks[taskID]
	if !ok {
		return GenericRunEnvelope{}, ErrConflict
	}
	confirmationID := stringParam(run.Payload, "confirmation_id")
	confirmation, ok := m.genericConfirmations[confirmationID]
	if !ok {
		return GenericRunEnvelope{}, ErrConflict
	}
	return GenericRunEnvelope{Run: cloneRecord(run), Stage: cloneRecord(stage), Task: cloneGenericRunTask(task), Confirmation: cloneGenericRunConfirmation(confirmation)}, nil
}

func (m *MemoryStore) updateGenericRecordLocked(record Record, status string, at time.Time) Record {
	record.Status = status
	if record.Payload == nil {
		record.Payload = map[string]any{}
	}
	record.Payload["status"] = status
	record.Revision++
	record.UpdatedAt = at.UTC()
	record.Digest = digestPayload(record.Payload)
	key := recordKey(record.OwnerID, record.Kind, record.ID)
	m.records[key] = cloneRecord(record)
	if m.revisions[key] == nil {
		m.revisions[key] = map[uint64]Record{}
	}
	m.revisions[key][record.Revision] = cloneRecord(record)
	return record
}

func genericCreateMatches(envelope GenericRunEnvelope, command GenericRunCreateCommand) bool {
	return envelope.Run.OwnerID == command.Run.OwnerID && envelope.Run.ID == command.Run.ID && envelope.Run.Digest == command.Run.Digest &&
		envelope.Stage.ID == command.Stage.ID && envelope.Stage.Digest == command.Stage.Digest &&
		sameGenericTaskIdentity(envelope.Task, command.Task) && envelope.Task.Spec.IdempotencyKey == command.Task.Spec.IdempotencyKey &&
		envelope.Confirmation.ConfirmationID == command.Confirmation.ConfirmationID &&
		envelope.Confirmation.TaskID == command.Confirmation.TaskID && envelope.Confirmation.Binding.Equal(command.Confirmation.Binding)
}

func validateGenericEnvelopeBindings(envelope GenericRunEnvelope, payload *coretask.ExecutionV2RunTaskPayload) error {
	if payload == nil || envelope.Run.OwnerID != payload.OwnerID || envelope.Stage.OwnerID != payload.OwnerID ||
		envelope.Run.ID != payload.RunID || envelope.Stage.ID != payload.StageID || envelope.Task.ID == "" ||
		envelope.Confirmation.ConfirmationID != payload.ConfirmationID || envelope.Confirmation.TaskID != envelope.Task.ID ||
		stringParam(envelope.Run.Payload, "stage_id") != payload.StageID || stringParam(envelope.Run.Payload, "task_id") != envelope.Task.ID ||
		stringParam(envelope.Run.Payload, "confirmation_id") != payload.ConfirmationID || stringParam(envelope.Run.Payload, "plan_id") != payload.PlanID ||
		uintParam(envelope.Run.Payload, "plan_revision") != payload.PlanRevision || stringParam(envelope.Run.Payload, "plan_digest") != payload.PlanDigest ||
		uintParam(envelope.Run.Payload, "account_generation") != payload.AccountGeneration ||
		stringParam(envelope.Stage.Payload, "run_id") != payload.RunID || stringParam(envelope.Stage.Payload, "task_id") != envelope.Task.ID ||
		stringParam(envelope.Stage.Payload, "confirmation_id") != payload.ConfirmationID || stringParam(envelope.Stage.Payload, "plan_id") != payload.PlanID ||
		uintParam(envelope.Stage.Payload, "plan_revision") != payload.PlanRevision || stringParam(envelope.Stage.Payload, "plan_digest") != payload.PlanDigest ||
		uintParam(envelope.Stage.Payload, "account_generation") != payload.AccountGeneration ||
		stringParam(envelope.Run.Payload, "operation") != payload.Operation || stringParam(envelope.Stage.Payload, "operation") != payload.Operation {
		return ErrConflict
	}
	return nil
}

func genericRunSnapshot(envelope GenericRunEnvelope, payload *coretask.ExecutionV2RunTaskPayload) GenericRunAuthoritySnapshot {
	if payload == nil {
		return GenericRunAuthoritySnapshot{}
	}
	return GenericRunAuthoritySnapshot{
		OwnerID: payload.OwnerID, AccountGeneration: payload.AccountGeneration,
		RunID: payload.RunID, StageID: payload.StageID, TaskID: envelope.Task.ID,
		PlanID: payload.PlanID, PlanRevision: payload.PlanRevision, PlanDigest: payload.PlanDigest,
		ConfirmationID: payload.ConfirmationID, Operation: payload.Operation,
	}
}

func validGenericProjectionPayload(values map[string]any, envelope GenericRunEnvelope, payload *coretask.ExecutionV2RunTaskPayload) bool {
	if validateSafeInput(values) != nil || stringParam(values, "run_id") != "" && stringParam(values, "run_id") != payload.RunID {
		return false
	}
	for key, expected := range map[string]string{
		"plan_id": payload.PlanID, "plan_digest": payload.PlanDigest, "operation": payload.Operation,
		"confirmation_id": payload.ConfirmationID, "task_id": envelope.Task.ID,
	} {
		if actual := stringParam(values, key); actual != "" && actual != expected {
			return false
		}
	}
	return (uintParam(values, "plan_revision") == 0 || uintParam(values, "plan_revision") == payload.PlanRevision) &&
		(uintParam(values, "account_generation") == 0 || uintParam(values, "account_generation") == payload.AccountGeneration)
}

func validGenericProjectionStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "queued", "running", "uncertain", "succeeded", "failed", "canceled":
		return true
	default:
		return false
	}
}

func sameGenericTaskIdentity(left, right coretask.Task) bool {
	if left.ID != right.ID || left.Spec.Kind != coretask.TaskKindExecutionV2Run || right.Spec.Kind != coretask.TaskKindExecutionV2Run {
		return false
	}
	lp, rp := left.Spec.Payload.ExecutionV2Run, right.Spec.Payload.ExecutionV2Run
	if lp == nil || rp == nil {
		return false
	}
	leftRaw, _ := json.Marshal(lp)
	rightRaw, _ := json.Marshal(rp)
	return string(leftRaw) == string(rightRaw) && left.Spec.IdempotencyKey == right.Spec.IdempotencyKey
}

func sameGenericTaskFence(left, right coretask.Task) bool {
	if !sameGenericTaskIdentity(left, right) || left.Status != coretask.StatusRunning || right.Status != coretask.StatusRunning ||
		left.Attempt != right.Attempt || left.LeaseEpoch != right.LeaseEpoch || left.Revision != right.Revision ||
		left.Lease == nil || right.Lease == nil {
		return false
	}
	return left.Lease.TaskID == right.Lease.TaskID && left.Lease.Attempt == right.Lease.Attempt &&
		left.Lease.Epoch == right.Lease.Epoch && left.Lease.Holder == right.Lease.Holder && left.Lease.ExpiresAt.Equal(right.Lease.ExpiresAt)
}

func cloneGenericRunEnvelope(value GenericRunEnvelope) GenericRunEnvelope {
	value.Run = cloneRecord(value.Run)
	value.Stage = cloneRecord(value.Stage)
	value.Task = cloneGenericRunTask(value.Task)
	value.Confirmation = cloneGenericRunConfirmation(value.Confirmation)
	return value
}

func cloneGenericRunTask(value coretask.Task) coretask.Task {
	raw, _ := json.Marshal(value)
	var out coretask.Task
	_ = json.Unmarshal(raw, &out)
	return out
}

func cloneGenericRunConfirmation(value coreconfirmation.Confirmation) coreconfirmation.Confirmation {
	value.Binding.SelectedCommand = append([]string(nil), value.Binding.SelectedCommand...)
	value.Binding.NetworkGrants = append([]string(nil), value.Binding.NetworkGrants...)
	value.Binding.SecretGrants = append([]coreconfirmation.SecretGrant(nil), value.Binding.SecretGrants...)
	return value
}

func cloneGenericRunResult(value *coretask.Result) *coretask.Result {
	if value == nil {
		return nil
	}
	raw, _ := json.Marshal(value)
	var out coretask.Result
	_ = json.Unmarshal(raw, &out)
	return &out
}
