package coreextension

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/google/uuid"
)

func (r *MemoryRepository) RequestLifecycle(ctx context.Context, req LifecycleRequest) (MutationResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requestLifecycleLocked(ctx, req)
}

func (r *MemoryRepository) requestLifecycleLocked(ctx context.Context, req LifecycleRequest) (MutationResult, error) {
	if req.Operation != OperationInstall && req.Operation != OperationUpdate && req.Operation != OperationUninstall {
		return MutationResult{}, ErrInvalid
	}
	if req.Installation.Validate() != nil || !validUUID(req.Task.IdempotencyKey) || !validUUID(req.Task.TaskID) || req.Task.TargetID != req.Installation.ID || req.Task.ExpectedRevision != req.Installation.Revision || req.Confirmation.TaskID != req.Task.TaskID || req.Confirmation.Binding.TargetID != req.Installation.ID || req.Confirmation.Binding.TargetRevision != req.Installation.Revision || !req.Confirmation.Binding.Equal(req.Confirmation.Binding) || !req.Confirmation.RequestDigest.Valid() {
		return MutationResult{}, ErrInvalid
	}
	now := r.now().UTC()
	if req.Confirmation.ExpiresAt.IsZero() || req.Confirmation.ExpiresAt.Location() != time.UTC || !req.Confirmation.ExpiresAt.After(now) {
		return MutationResult{}, ErrInvalid
	}
	d := lifecycleRequestDigest(req)
	if prior, ok := r.lifecycleReplay[req.Task.IdempotencyKey]; ok {
		if prior.digest != d {
			return MutationResult{}, ErrIdempotencyConflict
		}
		return prior.result, nil
	}
	if r.requestFailpoint != nil {
		if err := r.requestFailpoint(); err != nil {
			return MutationResult{}, err
		}
	}
	for _, c := range r.confirmations {
		if c.Binding.OperationDomain == req.Confirmation.Binding.OperationDomain && c.Binding.TargetID == req.Confirmation.Binding.TargetID && (c.State == coreconfirmation.StatePending || c.State == coreconfirmation.StateConfirmed || c.State == coreconfirmation.StateConsumed) {
			if reservation, exists := r.reservations[c.ConfirmationID]; !exists || reservation.Active {
				return MutationResult{}, ErrConflict
			}
		}
	}
	task := Task{ID: req.Task.TaskID, State: "waiting_user", Revision: 1}
	confirmation := coreconfirmation.Confirmation{ConfirmationID: uuid.NewString(), Binding: req.Confirmation.Binding, TaskID: req.Task.TaskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: req.Confirmation.ExpiresAt}
	r.tasks[task.ID] = task
	r.confirmations[confirmation.ConfirmationID] = confirmation
	result := MutationResult{Installation: cloneInstallation(req.Installation), TaskID: task.ID, ConfirmationID: confirmation.ConfirmationID}
	if _, exists := r.items[req.Installation.ID]; !exists {
		r.order = append(r.order, req.Installation.ID)
	}
	r.items[req.Installation.ID] = cloneInstallation(req.Installation)
	r.lifecycles[req.Installation.ID] = lifecycleRecordFrom(req, result)
	r.lifecycleReplay[req.Task.IdempotencyKey] = lifecycleReplay{digest: d, result: result}
	return result, nil
}

func (r *MemoryRepository) ConfirmLifecycle(_ context.Context, c coreconfirmation.ConfirmCommand) (coreconfirmation.Confirmation, error) {
	if !validUUID(c.ConfirmationID) || !validUUID(c.IdempotencyKey) || c.ExpectedRevision < 1 {
		return coreconfirmation.Confirmation{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := "confirm:" + c.IdempotencyKey
	b, _ := json.Marshal(struct {
		ID      string
		Rev     int64
		Binding coreconfirmation.Binding
	}{c.ConfirmationID, c.ExpectedRevision, c.Binding})
	d := digestBytes(b)
	if prior, ok := r.lifecycleReplay[key]; ok {
		if prior.digest != d {
			return coreconfirmation.Confirmation{}, ErrIdempotencyConflict
		}
		return prior.confirmation, prior.err
	}
	value, ok := r.confirmations[c.ConfirmationID]
	if !ok {
		return coreconfirmation.Confirmation{}, ErrNotFound
	}
	if value.Revision != c.ExpectedRevision || value.State != coreconfirmation.StatePending {
		return coreconfirmation.Confirmation{}, ErrConflict
	}
	if !value.ExpiresAt.After(r.now().UTC()) {
		return coreconfirmation.Confirmation{}, ErrConflict
	}
	if !value.Binding.Equal(c.Binding) {
		return coreconfirmation.Confirmation{}, ErrConflict
	}
	task, ok := r.tasks[value.TaskID]
	if !ok || task.State != "waiting_user" {
		return coreconfirmation.Confirmation{}, ErrConflict
	}
	value.State = coreconfirmation.StateConfirmed
	value.Revision++
	value.UpdatedAt = r.now().UTC()
	r.confirmations[value.ConfirmationID] = value
	task.State = "queued"
	task.Revision++
	r.tasks[task.ID] = task
	r.lifecycleReplay[key] = lifecycleReplay{digest: d, result: MutationResult{ConfirmationID: value.ConfirmationID}, confirmation: value}
	return value, nil
}

func (r *MemoryRepository) ConsumeLifecycle(_ context.Context, c coreconfirmation.ConsumeCommand) (coreconfirmation.Confirmation, error) {
	if !validUUID(c.ConfirmationID) || !validUUID(c.TaskID) || !validUUID(c.IdempotencyKey) || c.Attempt == 0 || c.LeaseEpoch == 0 || c.ExpectedRevision < 1 || c.ExpectedTaskRevision < 1 {
		return coreconfirmation.Confirmation{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(struct {
		ID, Task     string
		Attempt      uint32
		Lease        uint64
		Rev, TaskRev int64
		Binding      coreconfirmation.Binding
	}{c.ConfirmationID, c.TaskID, c.Attempt, c.LeaseEpoch, c.ExpectedRevision, c.ExpectedTaskRevision, c.Binding})
	d := digestBytes(b)
	key := "consume:" + c.IdempotencyKey
	if prior, ok := r.lifecycleReplay[key]; ok {
		if prior.digest != d {
			return coreconfirmation.Confirmation{}, ErrIdempotencyConflict
		}
		return prior.confirmation, prior.err
	}
	value, ok := r.confirmations[c.ConfirmationID]
	if !ok {
		return coreconfirmation.Confirmation{}, ErrNotFound
	}
	if value.Revision != c.ExpectedRevision || value.TaskID != c.TaskID || value.State != coreconfirmation.StateConfirmed || !value.Binding.Equal(c.Binding) {
		return coreconfirmation.Confirmation{}, ErrConflict
	}
	if !value.ExpiresAt.After(r.now().UTC()) {
		value.State = coreconfirmation.StateExpired
		value.Revision++
		value.UpdatedAt = r.now().UTC()
		r.confirmations[value.ConfirmationID] = value
		if task, exists := r.tasks[value.TaskID]; exists {
			task.State = "failed"
			task.FailureCode = coreconfirmation.ReasonExpired
			task.Revision++
			r.tasks[task.ID] = task
			r.lifecycleReplay[key] = lifecycleReplay{digest: d, confirmation: cloneConfirmationValue(value), task: task, err: coreconfirmation.ErrExpired}
		} else {
			r.lifecycleReplay[key] = lifecycleReplay{digest: d, confirmation: cloneConfirmationValue(value), err: coreconfirmation.ErrExpired}
		}
		return value, coreconfirmation.ErrExpired
	}
	task, ok := r.tasks[c.TaskID]
	if !ok || task.State != "running" || task.Attempt != c.Attempt || task.LeaseEpoch != c.LeaseEpoch || task.Revision != c.ExpectedTaskRevision {
		return coreconfirmation.Confirmation{}, ErrConflict
	}
	value.State = coreconfirmation.StateConsumed
	value.Revision++
	value.UpdatedAt = r.now().UTC()
	r.confirmations[value.ConfirmationID] = value
	r.reservations[value.ConfirmationID] = coreconfirmation.Reservation{ConfirmationID: value.ConfirmationID, TaskID: c.TaskID, AcquiredAttempt: c.Attempt, AcquiredLeaseEpoch: c.LeaseEpoch, TaskRevision: task.Revision, Active: true}
	r.lifecycleReplay[key] = lifecycleReplay{digest: d, result: MutationResult{ConfirmationID: value.ConfirmationID}, confirmation: value}
	return value, nil
}

type memoryLifecycleCoordinator struct {
	mu            sync.Mutex
	tasks         map[string]Task
	confirmations map[string]coreconfirmation.Confirmation
	replays       map[string]struct {
		digest string
		result MutationResult
	}
	now func() time.Time
}

func (m *memoryLifecycleCoordinator) RequestLifecycle(_ context.Context, req LifecycleRequest) (MutationResult, error) {
	if req.Operation != OperationInstall && req.Operation != OperationUpdate && req.Operation != OperationUninstall {
		return MutationResult{}, ErrInvalid
	}
	if req.Installation.Validate() != nil || !validUUID(req.Task.TaskID) || req.Task.TargetID != req.Installation.ID || req.Task.ExpectedRevision != req.Installation.Revision || req.Confirmation.TaskID != req.Task.TaskID || req.Confirmation.Binding.TargetID != req.Installation.ID || req.Confirmation.Binding.TargetRevision != req.Installation.Revision || !req.Confirmation.Binding.Equal(req.Confirmation.Binding) || !req.Confirmation.RequestDigest.Valid() {
		return MutationResult{}, ErrInvalid
	}
	now := time.Now().UTC()
	if m.now != nil {
		now = m.now().UTC()
	}
	if req.Confirmation.ExpiresAt.IsZero() || req.Confirmation.ExpiresAt.Location() != time.UTC || !req.Confirmation.ExpiresAt.After(now) {
		return MutationResult{}, ErrInvalid
	}
	d := lifecycleRequestDigest(req)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.replays == nil {
		m.replays = map[string]struct {
			digest string
			result MutationResult
		}{}
	}
	if m.tasks == nil {
		m.tasks = map[string]Task{}
	}
	if m.confirmations == nil {
		m.confirmations = map[string]coreconfirmation.Confirmation{}
	}
	if prior, ok := m.replays[req.Task.IdempotencyKey]; ok {
		if prior.digest != d {
			return MutationResult{}, ErrIdempotencyConflict
		}
		return prior.result, nil
	}
	for _, c := range m.confirmations {
		if c.Binding.OperationDomain == req.Confirmation.Binding.OperationDomain && c.Binding.TargetID == req.Confirmation.Binding.TargetID && (c.State == coreconfirmation.StatePending || c.State == coreconfirmation.StateConfirmed) {
			return MutationResult{}, ErrConflict
		}
	}
	now = now.UTC()
	task := Task{ID: req.Task.TaskID, State: "waiting_user", Revision: 1}
	confirmation := coreconfirmation.Confirmation{ConfirmationID: uuid.NewString(), Binding: req.Confirmation.Binding, TaskID: req.Task.TaskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: req.Confirmation.ExpiresAt}
	m.tasks[task.ID], m.confirmations[confirmation.ConfirmationID] = task, confirmation
	result := MutationResult{Installation: cloneInstallation(req.Installation), TaskID: task.ID, ConfirmationID: confirmation.ConfirmationID}
	m.replays[req.Task.IdempotencyKey] = struct {
		digest string
		result MutationResult
	}{digest: d, result: result}
	return result, nil
}

type lifecycleFenceVerifier interface {
	ValidateLifecycleCompletion(context.Context, LifecycleRecord, Completion) error
}

func (m *memoryLifecycleCoordinator) ValidateLifecycleCompletion(_ context.Context, r LifecycleRecord, c Completion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[r.TaskID]
	if !ok {
		return ErrNotFound
	}
	if (r.AcquiredAttempt > 0 && c.Attempt != r.AcquiredAttempt) || (r.AcquiredLeaseEpoch > 0 && c.LeaseEpoch != r.AcquiredLeaseEpoch) || (t.Attempt > 0 && c.Attempt != t.Attempt) || (t.LeaseEpoch > 0 && c.LeaseEpoch != t.LeaseEpoch) || t.State != "running" || (c.AcquiredTaskRevision > 0 && t.Revision != c.AcquiredTaskRevision) {
		return ErrConflict
	}
	if c.TerminalAttempt == 0 || c.TerminalLeaseEpoch == 0 {
		return ErrConflict
	}
	if t.State != "running" {
		return ErrConflict
	}
	if c.Success {
		t.State = "succeeded"
	} else {
		t.State = "failed"
	}
	t.Revision++
	m.tasks[r.TaskID] = t
	if confirmation, exists := m.confirmations[r.ConfirmationID]; exists {
		confirmation.State = coreconfirmation.StateConsumed
		confirmation.Revision++
		confirmation.UpdatedAt = time.Now().UTC()
		m.confirmations[r.ConfirmationID] = confirmation
	}
	return nil
}

func (m *memoryLifecycleCoordinator) SetTaskFence(f coreconfirmation.TaskFence) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tasks == nil {
		m.tasks = map[string]Task{}
	}
	m.tasks[f.TaskID] = Task{ID: f.TaskID, State: f.State, Revision: f.Revision, Attempt: f.Attempt, LeaseEpoch: f.LeaseEpoch}
}
func (m *memoryLifecycleCoordinator) Task(id string) (Task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	return t, ok
}
func (m *memoryLifecycleCoordinator) Confirmation(id string) (coreconfirmation.Confirmation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.confirmations[id]
	return c, ok
}

func lifecycleRequestDigest(req LifecycleRequest) string {
	b, _ := json.Marshal(struct {
		Installation Installation
		Task         TaskRequest
		Confirmation coreconfirmation.RequestCommand
		Operation    string
	}{req.Installation, req.Task, req.Confirmation, req.Operation})
	return digestBytes(b)
}
func lifecycleFor(m Mutation, i Installation, op string) LifecycleRequest {
	parameter, network, secret := lifecycleDigests(m, op)
	taskID := uuid.NewString()
	sourceVersion := m.Candidate.Pin.RegistryVersion
	sourceCommit := m.Candidate.Pin.GitCommit
	b := coreconfirmation.Binding{OperationDomain: "extension", TargetID: i.ID, TargetRevision: i.Revision, SourceVersion: sourceVersion, SourceCommit: sourceCommit, ContentDigest: coreconfirmation.Digest(m.Inspection.ContentDigest), ParameterDigest: coreconfirmation.Digest(parameter), NetworkDigest: coreconfirmation.Digest(network), SecretGrantDigest: coreconfirmation.Digest(secret)}
	for _, g := range m.Inspection.NetworkGrants {
		b.NetworkGrants = append(b.NetworkGrants, g.Scheme+"://"+g.Host+":"+fmt.Sprint(g.Port)+g.PathPrefix+":"+g.Digest)
	}
	for _, g := range m.Inspection.SecretGrants {
		b.SecretGrants = append(b.SecretGrants, coreconfirmation.SecretGrant{ReferenceID: g.ReferenceID, Purpose: coreconfirmation.SecretPurpose(g.Purpose), BindingDigest: coreconfirmation.Digest(g.BindingDigest)})
	}
	expires := time.Now().UTC().Add(time.Hour)
	cmd := coreconfirmation.RequestCommand{IdempotencyKey: m.IdempotencyKey, TaskID: taskID, Binding: b, ExpiresAt: expires}
	cmd.RequestDigest = coreconfirmation.Digest(requestCommandDigest(cmd))
	return LifecycleRequest{Installation: cloneInstallation(i), Task: TaskRequest{IdempotencyKey: m.IdempotencyKey, TaskID: taskID, Goal: "extension " + op, TargetID: i.ID, ExpectedRevision: i.Revision}, Operation: op, Confirmation: cmd}
}

func requestCommandDigest(cmd coreconfirmation.RequestCommand) string {
	b, _ := json.Marshal(struct {
		Binding   coreconfirmation.Binding
		TaskID    string
		ExpiresAt time.Time
	}{cmd.Binding, cmd.TaskID, cmd.ExpiresAt.UTC()})
	return digestBytes(b)
}
