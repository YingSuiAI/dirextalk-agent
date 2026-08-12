package coreextension

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

func cloneInstallation(i Installation) Installation {
	i.Versions = append([]VersionRecord(nil), i.Versions...)
	for n := range i.Versions {
		v := &i.Versions[n]
		if v.Execution.Stdio != nil {
			x := *v.Execution.Stdio
			x.Argv = append([]string(nil), x.Argv...)
			v.Execution.Stdio = &x
		}
		if v.Execution.Remote != nil {
			x := *v.Execution.Remote
			v.Execution.Remote = &x
		}
		if v.Execution.Skill != nil {
			x := *v.Execution.Skill
			x.Argv = append([]string(nil), x.Argv...)
			v.Execution.Skill = &x
		}
		v.NetworkGrants = append([]NetworkGrant(nil), v.NetworkGrants...)
		v.SecretGrants = append([]SecretGrantDescriptor(nil), v.SecretGrants...)
		v.NodeArtifact = cloneNodeArtifactReceipt(v.NodeArtifact)
		for j := range v.Tools {
			v.Tools[j].InputSchema = append([]byte(nil), v.Tools[j].InputSchema...)
		}
	}
	i.SecretGrants = append([]SecretGrantDescriptor(nil), i.SecretGrants...)
	i.NetworkGrants = append([]NetworkGrant(nil), i.NetworkGrants...)
	return i
}
func cloneExecution(e ExecutionDescriptor) ExecutionDescriptor {
	if e.Stdio != nil {
		x := *e.Stdio
		x.Argv = append([]string(nil), x.Argv...)
		e.Stdio = &x
	}
	if e.Remote != nil {
		x := *e.Remote
		e.Remote = &x
	}
	if e.Skill != nil {
		x := *e.Skill
		e.Skill = &x
	}
	return e
}
func (r *MemoryRepository) Get(_ context.Context, id string) (Installation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[id]
	if !ok {
		return Installation{}, ErrNotFound
	}
	return cloneInstallation(v), nil
}

// SetEnabled is a small transactional projection mutation in the in-memory
// repository used by contract tests. Production uses the PostgreSQL
// implementation with the same revision/idempotency semantics.
func (r *MemoryRepository) SetEnabled(_ context.Context, command ToggleCommand) (Installation, error) {
	if !validUUID(command.IdempotencyKey) || !validUUID(command.InstallationID) || command.ExpectedRevision < 1 {
		return Installation{}, ErrInvalid
	}
	digest := digestBytes(mustJSON(struct {
		ID      string
		Rev     int64
		Enabled bool
	}{command.InstallationID, command.ExpectedRevision, command.Enabled}))
	replayKey := map[bool]string{true: "enable:", false: "disable:"}[command.Enabled] + command.IdempotencyKey
	r.mu.Lock()
	defer r.mu.Unlock()
	if prior, ok := r.toggleReplay[replayKey]; ok {
		if prior.digest != digest {
			return Installation{}, ErrIdempotencyConflict
		}
		return cloneInstallation(prior.result), nil
	}
	i, ok := r.items[command.InstallationID]
	if !ok {
		return Installation{}, ErrNotFound
	}
	if i.Revision != command.ExpectedRevision {
		return Installation{}, ErrRevisionConflict
	}
	if i.State != StateInstalled || i.ActiveVersionID == "" {
		return Installation{}, ErrConflict
	}
	if i.Enabled != command.Enabled {
		i.Enabled = command.Enabled
		i.Revision++
		i.UpdatedAt = r.nowUTC()
		r.items[i.ID] = i
	}
	r.toggleReplay[replayKey] = toggleReplay{digest: digest, result: cloneInstallation(i)}
	return cloneInstallation(i), nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// GetLifecycleRecord exposes the immutable proposal fence for recovery and
// inspection tests without exposing mutable repository state.
func (r *MemoryRepository) GetLifecycleRecord(_ context.Context, id string) (LifecycleRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.lifecycles[id]
	if !ok {
		return LifecycleRecord{}, ErrNotFound
	}
	v.Binding.NetworkGrants = append([]string(nil), v.Binding.NetworkGrants...)
	v.Binding.SecretGrants = append([]coreconfirmation.SecretGrant(nil), v.Binding.SecretGrants...)
	return v, nil
}

func (r *MemoryRepository) SetTaskFence(f coreconfirmation.TaskFence) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tasks[f.TaskID] = Task{ID: f.TaskID, State: f.State, Revision: f.Revision, Attempt: f.Attempt, LeaseEpoch: f.LeaseEpoch}
}

func (r *MemoryRepository) SetTerminalTaskFence(taskID string, attempt uint32, lease uint64, revision int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	task := r.tasks[taskID]
	task.TerminalAttempt, task.TerminalLeaseEpoch, task.TerminalRevision = attempt, lease, revision
	r.tasks[taskID] = task
}

func (r *MemoryRepository) GetTask(id string) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, found := r.tasks[id]; found {
		return t, nil
	}
	return Task{}, ErrNotFound
}

func (r *MemoryRepository) GetConfirmation(id string) (coreconfirmation.Confirmation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, found := r.confirmations[id]; found {
		return c, nil
	}
	return coreconfirmation.Confirmation{}, ErrNotFound
}
func (r *MemoryRepository) List(_ context.Context, q ListQuery) (InstallationPage, error) {
	if q.PageSize < 0 || q.PageSize > 100 {
		return InstallationPage{}, ErrInvalid
	}
	n := q.PageSize
	if n == 0 {
		n = 50
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	vals := make([]Installation, 0)
	for _, id := range r.order {
		v := r.items[id]
		if q.Kind != "" && v.Kind != q.Kind || q.Source != "" && v.Source != q.Source || q.State != "" && v.State != q.State {
			continue
		}
		vals = append(vals, cloneInstallation(v))
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i].ID < vals[j].ID })
	start := 0
	if q.PageToken != "" {
		raw, e := base64.RawURLEncoding.DecodeString(q.PageToken)
		if e != nil {
			return InstallationPage{}, ErrInvalid
		}
		for start < len(vals) && vals[start].ID <= string(raw) {
			start++
		}
	}
	end := start + n
	if end > len(vals) {
		end = len(vals)
	}
	out := InstallationPage{Installations: vals[start:end]}
	if end < len(vals) {
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(vals[end-1].ID))
	}
	return out, nil
}
func mutationDigest(m Mutation) string {
	secrets := make([]string, len(m.SecretInputs))
	for n, s := range m.SecretInputs {
		secrets[n] = s.ReferenceID + ":" + string(s.Purpose) + ":" + s.Fingerprint()
	}
	sort.Strings(secrets)
	b, _ := json.Marshal(struct {
		Candidate            Candidate
		Inspection           Inspection
		InstallationID       string
		ExpectedRevision     int64
		Secrets              []string
		ArtifactPath         string
		ArtifactDigest       string
		ArtifactCleanupToken string
		NodeArtifact         *NodeArtifactReceipt
	}{m.Candidate, m.Inspection, m.InstallationID, m.ExpectedRevision, secrets, m.ArtifactPath, m.ArtifactDigest, m.ArtifactCleanupToken, m.NodeArtifact})
	return digestBytes(b)
}

func lifecycleDigests(m Mutation, op string) (parameter, network, secret string) {
	b, _ := json.Marshal(struct {
		Candidate Candidate
		Manifest  string
		Execution ExecutionDescriptor
		Operation string
	}{m.Candidate, m.Inspection.ManifestDigest, m.Inspection.Execution, op})
	parameter = digestBytes(b)
	grants := append([]NetworkGrant(nil), m.Inspection.NetworkGrants...)
	sort.Slice(grants, func(i, j int) bool {
		a, b := grants[i], grants[j]
		return a.Scheme+"\x00"+a.Host+fmt.Sprint(a.Port)+a.PathPrefix < b.Scheme+"\x00"+b.Host+fmt.Sprint(b.Port)+b.PathPrefix
	})
	var endpoint string
	if m.Inspection.Execution.Remote != nil {
		endpoint = m.Inspection.Execution.Remote.URL
	}
	nb, _ := json.Marshal(struct {
		Endpoint string
		Grants   []NetworkGrant
	}{endpoint, grants})
	network = digestBytes(nb)
	ss := make([]string, len(m.SecretInputs))
	for i, s := range m.SecretInputs {
		ss[i] = s.ReferenceID + ":" + string(s.Purpose) + ":" + s.Fingerprint()
	}
	sort.Strings(ss)
	sb, _ := json.Marshal(struct {
		Grants []SecretGrantDescriptor
		Inputs []string
	}{m.Inspection.SecretGrants, ss})
	secret = digestBytes(sb)
	return
}
