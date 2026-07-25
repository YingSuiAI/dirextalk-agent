package coreextension

import (
	"context"
	"encoding/json"
	"time"

	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/google/uuid"
)

func (r *MemoryRepository) replayLocked(key, d string) (MutationResult, error, bool) {
	if x, ok := r.replay[key]; ok {
		if x.digest != d && x.requestDigest != d {
			return MutationResult{}, ErrIdempotencyConflict, false
		}
		return x.result, nil, true
	}
	return MutationResult{}, nil, false
}

func (r *MemoryRepository) prepareMutation(ctx context.Context, m Mutation) (Mutation, error) {
	r.mu.Lock()
	reg, artifacts, secrets := r.registry, r.artifactStore, r.secretStore
	r.mu.Unlock()
	if reg == nil {
		return m, nil
	}
	if artifacts == nil {
		return Mutation{}, ErrInvalid
	}
	a, err := reg.Adapter(m.Candidate.Source)
	if err != nil {
		return Mutation{}, err
	}
	inspected, err := a.Inspect(ctx, InspectRequest{Kind: m.Candidate.Kind, Source: m.Candidate.Source, ID: m.Candidate.ID, Pin: m.Candidate.Pin})
	if err != nil {
		return Mutation{}, err
	}
	if !equalCandidate(m.Candidate, inspected.Candidate) {
		return Mutation{}, ErrConflict
	}
	fetched, err := a.Fetch(ctx, inspected.Candidate)
	if err != nil || fetched.Validate() != nil || !equalCandidate(m.Candidate, fetched.Candidate) || fetched.Inspection.ContentDigest != inspected.ContentDigest {
		return Mutation{}, ErrConflict
	}
	receipt, err := artifacts.Materialize(ctx, fetched)
	if err != nil {
		return Mutation{}, err
	}
	if !validDigest(receipt.Digest) || receipt.Digest != fetched.ContentDigest || receipt.RelativePath == "" {
		_ = artifacts.Remove(context.WithoutCancel(ctx), receipt)
		return Mutation{}, ErrInvalid
	}
	m.Inspection = fetched.Inspection
	m.ArtifactPath, m.ArtifactDigest = receipt.RelativePath, receipt.Digest
	if len(m.SecretInputs) > 0 {
		if secrets == nil {
			_ = artifacts.Remove(context.WithoutCancel(ctx), receipt)
			return Mutation{}, ErrInvalid
		}
		receipts, err := secrets.Bind(ctx, m.SecretInputs)
		if err != nil {
			_ = artifacts.Remove(context.WithoutCancel(ctx), receipt)
			return Mutation{}, err
		}
		if len(receipts) != len(m.SecretInputs) {
			_ = artifacts.Remove(context.WithoutCancel(ctx), receipt)
			return Mutation{}, ErrConflict
		}
		for _, input := range m.SecretInputs {
			matched := false
			for _, sr := range receipts {
				if sr.ReferenceID == input.ReferenceID && sr.Purpose == input.Purpose && sr.Fingerprint == input.Fingerprint() {
					matched = true
					break
				}
			}
			if !matched {
				_ = artifacts.Remove(context.WithoutCancel(ctx), receipt)
				return Mutation{}, ErrConflict
			}
		}
	}
	return m, nil
}
func (r *MemoryRepository) CreateMutation(ctx context.Context, m Mutation) (MutationResult, error) {
	rawDigest := mutationDigest(m)
	r.mu.Lock()
	if x, e, ok := r.replayLocked(m.IdempotencyKey, rawDigest); ok || e != nil {
		r.mu.Unlock()
		return x, e
	}
	r.mu.Unlock()
	var err error
	m, err = r.prepareMutation(ctx, m)
	if err != nil {
		return MutationResult{}, err
	}
	if !validUUID(m.IdempotencyKey) || m.Candidate.Validate() != nil || m.Inspection.Validate() != nil || !equalCandidate(m.Candidate, m.Inspection.Candidate) {
		return MutationResult{}, ErrInvalid
	}
	if err := validateSecretInputs(m); err != nil {
		return MutationResult{}, err
	}
	d := mutationDigest(m)
	r.mu.Lock()
	defer r.mu.Unlock()
	if x, e, ok := r.replayLocked(m.IdempotencyKey, d); ok || e != nil {
		return x, e
	}
	now := r.now().UTC()
	id := uuid.New().String()
	v := versionFromInspection(m.Inspection, now)
	v.ArtifactPath, v.ArtifactDigest = m.ArtifactPath, m.ArtifactDigest
	i := Installation{ID: id, Kind: m.Candidate.Kind, Source: m.Candidate.Source, CandidateID: m.Candidate.ID, Name: m.Candidate.Name, Description: m.Candidate.Description, Transport: m.Candidate.Transport, Revision: 1, State: StateInstalling, ProposedVersionID: v.VersionID, Versions: []VersionRecord{v}, CreatedAt: now, UpdatedAt: now}
	i.Candidate = m.Candidate
	req := lifecycleFor(m, i, OperationInstall)
	res, e := r.requestLifecycleLocked(context.Background(), req)
	if e != nil {
		return MutationResult{}, e
	}
	res.Installation = cloneInstallation(i)
	r.replay[m.IdempotencyKey] = replayMutation{digest: d, requestDigest: d, result: res}
	return res, nil
}
func (r *MemoryRepository) UpdateMutation(ctx context.Context, m Mutation, state State) (MutationResult, error) {
	if !validUUID(m.IdempotencyKey) || !validUUID(m.InstallationID) || m.ExpectedRevision < 1 {
		return MutationResult{}, ErrInvalid
	}
	if state != StateUpdating && state != StateUninstalling {
		return MutationResult{}, ErrInvalid
	}
	rawDigest := mutationDigest(m) + string(state)
	r.mu.Lock()
	if x, e, ok := r.replayLocked(m.IdempotencyKey, rawDigest); ok || e != nil {
		r.mu.Unlock()
		return x, e
	}
	r.mu.Unlock()
	if state == StateUpdating {
		var err error
		m, err = r.prepareMutation(ctx, m)
		if err != nil {
			return MutationResult{}, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if state == StateUpdating {
		if m.Candidate.Validate() != nil || m.Inspection.Validate() != nil || !equalCandidate(m.Candidate, m.Inspection.Candidate) {
			return MutationResult{}, ErrInvalid
		}
		if err := validateSecretInputs(m); err != nil {
			return MutationResult{}, err
		}
	}
	i, ok := r.items[m.InstallationID]
	if !ok {
		return MutationResult{}, ErrNotFound
	}
	if i.Revision != m.ExpectedRevision {
		return MutationResult{}, ErrRevisionConflict
	}
	if state == StateUpdating {
		if m.Candidate.Kind != i.Kind || m.Candidate.Source != i.Source || m.Candidate.ID != i.CandidateID || m.Candidate.Name != i.Name || m.Candidate.Description != i.Description || m.Candidate.Transport != i.Transport {
			return MutationResult{}, ErrInvalid
		}
	} else {
		m = mutationForUninstall(m, i)
	}
	d := mutationDigest(m) + string(state)
	if x, e, ok := r.replayLocked(m.IdempotencyKey, d); ok || e != nil {
		return x, e
	}
	staged := cloneInstallation(i)
	if state == StateUpdating {
		v := versionFromInspection(m.Inspection, r.now().UTC())
		v.ArtifactPath, v.ArtifactDigest = m.ArtifactPath, m.ArtifactDigest
		staged.Versions = append(staged.Versions, v)
		staged.ProposedVersionID = v.VersionID
		staged.Candidate = m.Candidate
	}
	staged.Revision++
	staged.State = state
	staged.UpdatedAt = r.now().UTC()
	req := lifecycleFor(m, staged, operationForState(state))
	res, e := r.requestLifecycleLocked(context.Background(), req)
	if e != nil {
		return MutationResult{}, e
	}
	res.Installation = cloneInstallation(staged)
	r.replay[m.IdempotencyKey] = replayMutation{digest: d, requestDigest: rawDigest, result: res}
	return res, nil
}
func (r *MemoryRepository) RemoveMutation(ctx context.Context, m Mutation) (MutationResult, error) {
	return r.UpdateMutation(ctx, m, StateUninstalling)
}

func operationForState(state State) string {
	if state == StateUpdating {
		return OperationUpdate
	}
	return OperationUninstall
}
func versionFromInspection(in Inspection, now time.Time) VersionRecord {
	return VersionRecord{VersionID: uuid.New().String(), Pin: in.Candidate.Pin, ContentDigest: in.ContentDigest, ManifestDigest: in.ManifestDigest, ExecutionDigest: in.ExecutionDigest, NetworkSchemaDigest: in.NetworkSchemaDigest, SecretSchemaDigest: in.SecretSchemaDigest, Execution: cloneExecution(in.Execution), NetworkGrants: append([]NetworkGrant(nil), in.NetworkGrants...), SecretGrants: redactedSecretGrants(in.SecretGrants), CreatedAt: now}
}
func redactedSecretGrants(in []SecretGrantDescriptor) []SecretGrantDescriptor {
	out := append([]SecretGrantDescriptor(nil), in...)
	for i := range out {
		out[i].Configured = true
	}
	return out
}
func validateSecretInputs(m Mutation) error {
	for _, input := range m.SecretInputs {
		if input.Validate() != nil {
			return ErrInvalid
		}
	}
	seenInputs := map[string]bool{}
	for _, input := range m.SecretInputs {
		if (m.Candidate.Kind == KindMCP && input.Purpose != SecretPurposeMCPCredential) || (m.Candidate.Kind == KindSkill && input.Purpose != SecretPurposeSkillSecret) {
			return ErrInvalid
		}
		key := input.ReferenceID + ":" + string(input.Purpose)
		if seenInputs[key] {
			return ErrInvalid
		}
		seenInputs[key] = true
	}
	seenGrants := map[string]bool{}
	for _, grant := range m.Inspection.SecretGrants {
		if (m.Candidate.Kind == KindMCP && grant.Purpose != SecretPurposeMCPCredential) || (m.Candidate.Kind == KindSkill && grant.Purpose != SecretPurposeSkillSecret) {
			return ErrInvalid
		}
		if !grant.Configured {
			return ErrInvalid
		}
		key := grant.ReferenceID + ":" + string(grant.Purpose)
		if seenGrants[key] {
			return ErrInvalid
		}
		seenGrants[key] = true
		matched := false
		for _, input := range m.SecretInputs {
			if input.ReferenceID == grant.ReferenceID && input.Purpose == grant.Purpose && grant.BindingDigest == input.Fingerprint() {
				matched = true
				break
			}
		}
		if !matched {
			return ErrInvalid
		}
		delete(seenInputs, key)
	}
	if len(seenInputs) > 0 {
		return ErrInvalid
	}
	if m.Inspection.Execution.Remote != nil {
		ref := m.Inspection.Execution.Remote.CredentialReferenceID
		found := false
		for _, g := range m.Inspection.SecretGrants {
			if g.ReferenceID == ref {
				if g.Purpose != SecretPurposeMCPCredential || !g.Configured {
					return ErrInvalid
				}
				for _, in := range m.SecretInputs {
					if in.ReferenceID == ref && in.Purpose == SecretPurposeMCPCredential && g.BindingDigest == in.Fingerprint() {
						found = true
					}
				}
				if !found {
					return ErrInvalid
				}
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}
func mutationForUninstall(m Mutation, i Installation) Mutation {
	if i.ActiveVersionID == "" {
		return m
	}
	for _, v := range i.Versions {
		if v.VersionID == i.ActiveVersionID {
			m.Candidate = Candidate{ID: i.CandidateID, Kind: i.Kind, Source: i.Source, Name: i.Name, Description: i.Description, Pin: v.Pin, Transport: i.Transport}
			m.Inspection = Inspection{Candidate: m.Candidate, ContentDigest: v.ContentDigest, ManifestDigest: v.ManifestDigest, ExecutionDigest: v.ExecutionDigest, NetworkSchemaDigest: v.NetworkSchemaDigest, SecretSchemaDigest: v.SecretSchemaDigest, Execution: cloneExecution(v.Execution), NetworkGrants: append([]NetworkGrant(nil), v.NetworkGrants...), SecretGrants: append([]SecretGrantDescriptor(nil), i.SecretGrants...)}
			return m
		}
	}
	return m
}
func lifecycleRecordFrom(req LifecycleRequest, res MutationResult) LifecycleRecord {
	return LifecycleRecord{InstallationID: req.Installation.ID, Operation: req.Operation, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Binding: req.Confirmation.Binding, State: "pending", RequestDigest: lifecycleRequestDigest(req), ExpectedRevision: req.Installation.Revision}
}

type Completion struct {
	InstallationID       string
	Operation            string
	ConfirmationID       string
	TaskID               string
	Attempt              uint32
	LeaseEpoch           uint64
	AcquiredTaskRevision int64
	TerminalAttempt      uint32
	TerminalLeaseEpoch   uint64
	TerminalTaskRevision int64
	ExpectedRevision     int64
	OutcomeDigest        string
	Success              bool
}

func (r *MemoryRepository) CompleteLifecycle(_ context.Context, c Completion) (Installation, error) {
	id := c.InstallationID
	expectedRevision := c.ExpectedRevision
	success := c.Success
	if !validUUID(id) || !validUUID(c.ConfirmationID) || !validUUID(c.TaskID) || expectedRevision < 1 || !validDigest(c.OutcomeDigest) || c.Attempt == 0 || c.LeaseEpoch == 0 || c.AcquiredTaskRevision < 1 || c.TerminalAttempt == 0 || c.TerminalLeaseEpoch == 0 || c.TerminalTaskRevision < 1 {
		return Installation{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := id + "/" + c.ConfirmationID + "/" + c.TaskID + "/" + c.Operation
	cd := completionDigest(c)
	if prior, ok := r.completionReplay[key]; ok {
		if prior.digest != cd {
			return Installation{}, ErrConflict
		}
		return cloneInstallation(prior.result), nil
	}
	record, ok := r.lifecycles[id]
	if !ok {
		return Installation{}, ErrNotFound
	}
	if record.Operation != c.Operation || record.ConfirmationID != c.ConfirmationID || record.TaskID != c.TaskID || record.ExpectedRevision != expectedRevision {
		return Installation{}, ErrConflict
	}
	i, ok := r.items[id]
	if !ok {
		return Installation{}, ErrNotFound
	}
	if i.Revision != expectedRevision {
		return Installation{}, ErrRevisionConflict
	}
	if c.Operation != OperationInstall && c.Operation != OperationUpdate && c.Operation != OperationUninstall {
		return Installation{}, ErrInvalid
	}
	if (c.Operation == OperationInstall && i.State != StateInstalling) || (c.Operation == OperationUpdate && i.State != StateUpdating) || (c.Operation == OperationUninstall && i.State != StateUninstalling) {
		return Installation{}, ErrConflict
	}
	confirmation, ok := r.confirmations[c.ConfirmationID]
	if !ok || confirmation.TaskID != c.TaskID || confirmation.State != coreconfirmation.StateConsumed {
		return Installation{}, ErrConflict
	}
	reservation, ok := r.reservations[c.ConfirmationID]
	if !ok || !reservation.Active || reservation.TaskID != c.TaskID || reservation.AcquiredAttempt != c.Attempt || reservation.AcquiredLeaseEpoch != c.LeaseEpoch {
		return Installation{}, ErrConflict
	}
	task, ok := r.tasks[c.TaskID]
	if !ok || task.State != "running" || task.Attempt != c.Attempt || task.LeaseEpoch != c.LeaseEpoch || (c.AcquiredTaskRevision > 0 && task.Revision != c.AcquiredTaskRevision) {
		return Installation{}, ErrConflict
	}
	if task.TerminalAttempt == 0 || task.TerminalLeaseEpoch == 0 || task.TerminalRevision == 0 || task.TerminalAttempt != c.TerminalAttempt || task.TerminalLeaseEpoch != c.TerminalLeaseEpoch {
		return Installation{}, ErrConflict
	}
	if task.TerminalRevision != c.TerminalTaskRevision {
		return Installation{}, ErrConflict
	}
	if success {
		if c.Operation == OperationUninstall {
			i.ActiveVersionID = ""
			i.ProposedVersionID = ""
			i.NetworkGrants = nil
			i.SecretGrants = nil
			i.State = StateRemoved
		} else if i.ProposedVersionID != "" {
			i.ActiveVersionID = i.ProposedVersionID
			i.ProposedVersionID = ""
			for _, v := range i.Versions {
				if v.VersionID == i.ActiveVersionID {
					i.SecretGrants = append([]SecretGrantDescriptor(nil), v.SecretGrants...)
					i.NetworkGrants = append([]NetworkGrant(nil), v.NetworkGrants...)
					break
				}
			}
			i.State = StateInstalled
		}
	} else {
		if r.artifactStore != nil && i.ProposedVersionID != "" {
			for _, v := range i.Versions {
				if v.VersionID == i.ProposedVersionID && v.ArtifactPath != "" {
					if err := r.artifactStore.Remove(context.Background(), ArtifactReceipt{RelativePath: v.ArtifactPath, Digest: v.ArtifactDigest}); err != nil {
						return Installation{}, err
					}
				}
			}
		}
		if i.ActiveVersionID != "" && c.Operation != OperationInstall {
			i.State = StateInstalled
		} else {
			i.State = StateFailed
		}
		i.ProposedVersionID = ""
	}
	i.Revision++
	i.UpdatedAt = r.now().UTC()
	r.items[id] = i
	task.State = map[bool]string{true: "succeeded", false: "failed"}[success]
	if c.TerminalTaskRevision > 0 {
		task.Revision = c.TerminalTaskRevision
	} else {
		task.Revision++
	}
	r.tasks[task.ID] = task
	reservation.Active = false
	r.reservations[reservation.ConfirmationID] = reservation
	record.State = map[bool]string{true: "succeeded", false: "failed"}[success]
	record.AcquiredAttempt = c.Attempt
	record.AcquiredLeaseEpoch = c.LeaseEpoch
	record.AcquiredTaskRevision = c.AcquiredTaskRevision
	record.TerminalAttempt = c.TerminalAttempt
	record.TerminalLeaseEpoch = c.TerminalLeaseEpoch
	record.TerminalTaskRevision = c.TerminalTaskRevision
	record.CompletionDigest = c.OutcomeDigest
	r.lifecycles[id] = record
	out := cloneInstallation(i)
	r.completionReplay[key] = completionReplay{digest: cd, result: out}
	return out, nil
}

func completionDigest(c Completion) string { b, _ := json.Marshal(c); return digestBytes(b) }
