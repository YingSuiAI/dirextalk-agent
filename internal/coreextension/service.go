package coreextension

import (
	"context"
	"encoding/json"
)

// Service is the narrow lifecycle/use-case boundary consumed by RPC adapters.
type Service interface {
	Search(context.Context, SearchQuery) (Page, error)
	Inspect(context.Context, InspectRequest) (Inspection, error)
	RequestInstall(context.Context, Mutation) (MutationResult, error)
	RequestUpdate(context.Context, Mutation) (MutationResult, error)
	RequestUninstall(context.Context, Mutation) (MutationResult, error)
	Get(context.Context, string) (Installation, error)
	List(context.Context, ListQuery) (InstallationPage, error)
	ListTools(context.Context, string, int64) ([]Tool, error)
	Execute(context.Context, ExecuteRequest) (ExecuteResult, error)
}
type Tool struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	InputSchemaDigest string          `json:"input_schema_digest"`
	InputSchema       json.RawMessage `json:"input_schema,omitempty"`
}
type Coordinator interface {
	CreateTask(context.Context, ExecuteRequest) (string, error)
}
type ToolRuntime interface {
	ListTools(context.Context, Installation, VersionRecord) ([]Tool, error)
	CallTool(context.Context, Installation, VersionRecord, string, []byte) (string, error)
}
type service struct {
	repo        Repository
	registry    *Registry
	coordinator Coordinator
	artifacts   ArtifactStore
	secrets     SecretStore
	runtime     ToolRuntime
}

func (s *service) SetStores(a ArtifactStore, sec SecretStore) { s.artifacts = a; s.secrets = sec }
func ConfigureStores(svc Service, a ArtifactStore, sec SecretStore) bool {
	if s, ok := svc.(*service); ok {
		s.SetStores(a, sec)
		return true
	}
	return false
}

func NewService(repo Repository, registry *Registry, coordinator Coordinator) Service {
	return &service{repo: repo, registry: registry, coordinator: coordinator}
}
func NewServiceWithStores(repo Repository, registry *Registry, coordinator Coordinator, artifacts ArtifactStore, secrets SecretStore) Service {
	return &service{repo: repo, registry: registry, coordinator: coordinator, artifacts: artifacts, secrets: secrets}
}
func NewServiceWithRuntime(repo Repository, registry *Registry, coordinator Coordinator, runtime ToolRuntime) Service {
	return &service{repo: repo, registry: registry, coordinator: coordinator, runtime: runtime}
}

// NewProductionService is the single validated composition constructor. All
// durable and execution seams are explicit so a partially wired service
// cannot publish an install/execute surface.
func NewProductionService(repo Repository, registry *Registry, coordinator Coordinator, artifacts ArtifactStore, secrets SecretStore, runtime ToolRuntime) (Service, error) {
	if repo == nil || registry == nil || coordinator == nil || artifacts == nil || secrets == nil || runtime == nil {
		return nil, ErrInvalid
	}
	return &service{repo: repo, registry: registry, coordinator: coordinator, artifacts: artifacts, secrets: secrets, runtime: runtime}, nil
}

func NewServiceWithDependencies(repo Repository, registry *Registry, coordinator Coordinator, artifacts ArtifactStore, secrets SecretStore, runtime ToolRuntime) (Service, error) {
	return NewProductionService(repo, registry, coordinator, artifacts, secrets, runtime)
}
func (s *service) Search(ctx context.Context, q SearchQuery) (Page, error) {
	if s.registry == nil {
		return Page{}, ErrNotFound
	}
	a, e := s.registry.Adapter(q.Source)
	if e != nil {
		return Page{}, e
	}
	return a.Search(ctx, q)
}
func (s *service) Inspect(ctx context.Context, q InspectRequest) (Inspection, error) {
	if s.registry == nil {
		return Inspection{}, ErrNotFound
	}
	a, e := s.registry.Adapter(q.Source)
	if e != nil {
		return Inspection{}, e
	}
	return a.Inspect(ctx, q)
}
func (s *service) RequestInstall(ctx context.Context, m Mutation) (MutationResult, error) {
	m, receipt, err := s.prepareMutation(ctx, m)
	if err != nil {
		return MutationResult{}, err
	}
	res, err := s.repo.CreateMutation(ctx, m)
	if err != nil && receipt.RelativePath != "" && s.artifacts != nil {
		_ = s.artifacts.Remove(context.WithoutCancel(ctx), receipt)
	}
	if err != nil {
		return MutationResult{}, err
	}
	return res, nil
}
func (s *service) RequestUpdate(ctx context.Context, m Mutation) (MutationResult, error) {
	m, receipt, err := s.prepareMutation(ctx, m)
	if err != nil {
		return MutationResult{}, err
	}
	res, err := s.repo.UpdateMutation(ctx, m, StateUpdating)
	if err != nil && receipt.RelativePath != "" && s.artifacts != nil {
		_ = s.artifacts.Remove(context.WithoutCancel(ctx), receipt)
	}
	if err != nil {
		return MutationResult{}, err
	}
	return res, nil
}
func (s *service) prepareMutation(ctx context.Context, m Mutation) (Mutation, ArtifactReceipt, error) {
	if s.registry == nil || s.artifacts == nil || s.secrets == nil {
		return Mutation{}, ArtifactReceipt{}, ErrInvalid
	}
	a, e := s.registry.Adapter(m.Candidate.Source)
	if e != nil {
		return m, ArtifactReceipt{}, e
	}
	in, e := a.Inspect(ctx, InspectRequest{Kind: m.Candidate.Kind, Source: m.Candidate.Source, ID: m.Candidate.ID, Pin: m.Candidate.Pin})
	if e != nil {
		return m, ArtifactReceipt{}, e
	}
	if !equalCandidate(in.Candidate, m.Candidate) {
		return m, ArtifactReceipt{}, ErrConflict
	}
	m.Candidate = in.Candidate
	m.Inspection = in
	bound, e := bindSecretGrants(in.SecretGrants, m.SecretInputs)
	if e != nil {
		return m, ArtifactReceipt{}, e
	}
	m.Inspection.SecretGrants = bound
	f, e := a.Fetch(ctx, m.Candidate)
	if e != nil {
		return m, ArtifactReceipt{}, e
	}
	if e = f.Validate(); e != nil {
		return m, ArtifactReceipt{}, e
	}
	if f.ContentDigest != in.ContentDigest {
		return m, ArtifactReceipt{}, ErrConflict
	}
	receipt, e := s.artifacts.Materialize(ctx, f)
	if e != nil {
		return m, ArtifactReceipt{}, e
	}
	m.ArtifactPath, m.ArtifactDigest = receipt.RelativePath, receipt.Digest
	if _, e = s.secrets.Bind(ctx, m.SecretInputs); e != nil {
		_ = s.artifacts.Remove(context.WithoutCancel(ctx), receipt)
		return Mutation{}, ArtifactReceipt{}, e
	}
	return m, receipt, nil
}

func bindSecretGrants(grants []SecretGrantDescriptor, inputs []SecretInput) ([]SecretGrantDescriptor, error) {
	byKey := make(map[string]SecretInput, len(inputs))
	for _, input := range inputs {
		if err := input.Validate(); err != nil {
			return nil, ErrInvalid
		}
		key := input.ReferenceID + "\x00" + string(input.Purpose)
		if _, exists := byKey[key]; exists {
			return nil, ErrConflict
		}
		byKey[key] = input
	}
	out := make([]SecretGrantDescriptor, 0, len(grants))
	seen := make(map[string]bool, len(grants))
	for _, grant := range grants {
		key := grant.ReferenceID + "\x00" + string(grant.Purpose)
		input, ok := byKey[key]
		if !ok {
			return nil, ErrConflict
		}
		if seen[key] {
			return nil, ErrConflict
		}
		seen[key] = true
		grant.BindingDigest = input.Fingerprint()
		grant.Configured = true
		out = append(out, grant)
	}
	if len(seen) != len(byKey) {
		return nil, ErrConflict
	}
	return out, nil
}
func (s *service) RequestUninstall(ctx context.Context, m Mutation) (MutationResult, error) {
	return s.repo.RemoveMutation(ctx, m)
}
func (s *service) Get(ctx context.Context, id string) (Installation, error) {
	return s.repo.Get(ctx, id)
}
func (s *service) List(ctx context.Context, q ListQuery) (InstallationPage, error) {
	return s.repo.List(ctx, q)
}
func (s *service) ListTools(ctx context.Context, id string, rev int64) ([]Tool, error) {
	i, e := s.repo.Get(ctx, id)
	if e != nil {
		return nil, e
	}
	if rev > 0 && i.Revision != rev {
		return nil, ErrRevisionConflict
	}
	if i.ActiveVersionID == "" {
		return nil, ErrConflict
	}
	if s.runtime != nil {
		for _, v := range i.Versions {
			if v.VersionID == i.ActiveVersionID {
				return s.runtime.ListTools(ctx, i, v)
			}
		}
	}
	for _, v := range i.Versions {
		if v.VersionID == i.ActiveVersionID {
			return nil, ErrNotFound
		}
	}
	return nil, ErrNotFound
}
func (s *service) Execute(ctx context.Context, r ExecuteRequest) (ExecuteResult, error) {
	if !validUUID(r.IdempotencyKey) || !validUUID(r.InstallationID) || r.ExpectedRevision < 1 {
		return ExecuteResult{}, ErrInvalid
	}
	if s.coordinator == nil {
		return ExecuteResult{}, ErrNotFound
	}
	id, e := s.coordinator.CreateTask(ctx, r)
	return ExecuteResult{TaskID: id}, e
}
