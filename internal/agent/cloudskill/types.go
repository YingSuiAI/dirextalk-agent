// Package cloudskill exposes the model-callable, read/draft-only cloud
// dispatcher boundary. Trusted ownership and cloud scope are attached by the
// service composition layer; model arguments can never select them.
package cloudskill

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

var (
	ErrInvalidDependencies        = errors.New("invalid cloud dispatcher dependencies")
	ErrMissingCallScope           = errors.New("cloud dispatcher call scope is missing")
	ErrInvalidCallScope           = errors.New("cloud dispatcher call scope is invalid")
	ErrInvocationScopeMismatch    = errors.New("cloud dispatcher invocation does not match its trusted scope")
	ErrInvalidArguments           = errors.New("cloud dispatcher arguments are invalid")
	ErrResearchAlreadyStarted     = errors.New("a different research goal already exists for this request")
	ErrInvalidPortResponse        = errors.New("cloud dispatcher port returned an invalid response")
	ErrModelVisibleResultTooLarge = errors.New("cloud dispatcher result is too large")
	ErrPlanDraftNotReady          = errors.New("cloud dispatcher research task is not ready for a plan draft")
)

const (
	StepResearchOfficialSources   = "research_official_sources"
	StepDraftRecipe               = "draft_recipe"
	StepPrepareResourceCandidates = "prepare_resource_candidates"
	QuoteStateAwaitingConnection  = "awaiting_connection"
	QuoteStateAwaitingQuote       = "awaiting_quote"
)

// CallScope is authenticated application state. ConnectionID may be empty
// while research is waiting for an AWS connection; it is never decoded from
// model output.
type CallScope struct {
	OwnerID      string
	ConnectionID string
	RecipeID     string
	Retention    task.RetentionPolicy
}

// Binding is the durable lookup key passed to the three allowed application
// ports. RequestID is also the idempotency key for CreateResearch.
type Binding struct {
	RequestID      string
	OwnerID        string
	ConversationID string
	ConnectionID   string
	RecipeID       string
	Retention      task.RetentionPolicy
}

type ResearchRequest struct {
	Create         task.CreateCommand
	ConversationID string
	ConnectionID   string
	RecipeID       string
}

type StatusRequest struct {
	Binding Binding
}

type ResearchStatus struct {
	Task  task.Task
	Steps []task.Step
}

type RecipeDraftRequest struct {
	Binding Binding
}

type RecipeDraft struct {
	Ready  bool
	Recipe recipe.RecipeV1
}

// RecipeDraftInputV1 is the complete model-supplied part of RecipeV1. Trusted
// identity and lifecycle state are intentionally absent: the server always
// supplies schema_version, recipe_id, maturity=experimental and no managed
// acceptance.
type RecipeDraftInputV1 struct {
	Name         string                            `json:"name"`
	Sources      []recipe.SourceV1                 `json:"sources"`
	Requirements recipe.ResourceRequirementsV1     `json:"requirements"`
	Install      recipe.InstallContractV1          `json:"install"`
	Health       recipe.HealthContractV1           `json:"health"`
	Lifecycle    recipe.LifecycleContractV1        `json:"lifecycle"`
	VolumeSlots  []recipe.VolumeSlotRequirementV1  `json:"volume_slots,omitempty"`
	DataSlots    []recipe.DataSlotRequirementV1    `json:"data_slots,omitempty"`
	SecretSlots  []recipe.SecretSlotRequirementV1  `json:"secret_slots,omitempty"`
	Restart      *recipe.RestartContractV1         `json:"restart,omitempty"`
	Network      *recipe.NetworkContractV1         `json:"network,omitempty"`
	Pairing      *recipe.PairingContractV1         `json:"pairing,omitempty"`
	Integrations []recipe.IntegrationDeclarationV1 `json:"integrations,omitempty"`
}

func (input RecipeDraftInputV1) bind(recipeID string) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1,
		RecipeID:      recipeID,
		Name:          input.Name,
		Maturity:      recipe.MaturityExperimental,
		Sources:       input.Sources,
		Requirements:  input.Requirements,
		Install:       input.Install,
		Health:        input.Health,
		Lifecycle:     input.Lifecycle,
		VolumeSlots:   input.VolumeSlots,
		DataSlots:     input.DataSlots,
		SecretSlots:   input.SecretSlots,
		Restart:       input.Restart,
		Network:       input.Network,
		Pairing:       input.Pairing,
		Integrations:  input.Integrations,
	}
}

// ResourceCandidateDraftV1 deliberately contains no provider, Region,
// instance type, price, connection or approval field. Provider-backed quote
// selection happens later under a separately approved command.
type ResourceCandidateDraftV1 struct {
	Tier         string              `json:"tier"`
	Architecture recipe.Architecture `json:"architecture"`
	VCPU         uint32              `json:"vcpu"`
	MemoryMiB    uint64              `json:"memory_mib"`
	DiskGiB      uint64              `json:"disk_gib"`
	GPURequired  bool                `json:"gpu_required"`
	GPUMemoryMiB uint64              `json:"gpu_memory_mib,omitempty"`
	GPUFamily    string              `json:"gpu_family,omitempty"`
	Rationale    string              `json:"rationale"`
}

type SubmitPlanDraftRequest struct {
	Binding    Binding
	ToolCallID string
	Recipe     recipe.RecipeV1
	Candidates []ResourceCandidateDraftV1
}

type CandidateSummary struct {
	Tier         string              `json:"tier"`
	Architecture recipe.Architecture `json:"architecture"`
	VCPU         uint32              `json:"vcpu"`
	MemoryMiB    uint64              `json:"memory_mib"`
	DiskGiB      uint64              `json:"disk_gib"`
	GPURequired  bool                `json:"gpu_required"`
	GPUMemoryMiB uint64              `json:"gpu_memory_mib,omitempty"`
}

type SubmitPlanDraftResult struct {
	TaskID            string
	ExecutionStatus   task.ExecutionStatus
	OutcomeStatus     task.OutcomeStatus
	TaskRevision      int64
	RecipeDigest      string
	RecipeRevision    int64
	QuoteState        string
	CandidateRevision int64
	Candidates        []CandidateSummary
}

// ResearchPort can only create the durable planning/research task. Its
// implementation must honor Create.IdempotencyKey and may not provision cloud
// resources as part of this operation.
type ResearchPort interface {
	CreateResearch(context.Context, ResearchRequest) (task.Task, error)
}

type ResearchPortFunc func(context.Context, ResearchRequest) (task.Task, error)

func (f ResearchPortFunc) CreateResearch(ctx context.Context, request ResearchRequest) (task.Task, error) {
	return f(ctx, request)
}

// StatusPort is read-only and returns the research task projection.
type StatusPort interface {
	GetResearchStatus(context.Context, StatusRequest) (ResearchStatus, error)
}

type StatusPortFunc func(context.Context, StatusRequest) (ResearchStatus, error)

func (f StatusPortFunc) GetResearchStatus(ctx context.Context, request StatusRequest) (ResearchStatus, error) {
	return f(ctx, request)
}

// RecipeDraftPort is read-only. Recipe persistence and validation remain an
// application responsibility; this boundary validates again before exposing a
// draft to the model.
type RecipeDraftPort interface {
	GetRecipeDraft(context.Context, RecipeDraftRequest) (RecipeDraft, error)
}

type RecipeDraftPortFunc func(context.Context, RecipeDraftRequest) (RecipeDraft, error)

func (f RecipeDraftPortFunc) GetRecipeDraft(ctx context.Context, request RecipeDraftRequest) (RecipeDraft, error) {
	return f(ctx, request)
}

// PlanDraftPort persists one validated, experimental plan draft and advances
// only the fixed CONTROL_PLANE planning DAG. It has no provider mutation,
// approval, credential, network or shell capability.
type PlanDraftPort interface {
	SubmitPlanDraft(context.Context, SubmitPlanDraftRequest) (SubmitPlanDraftResult, error)
}

type PlanDraftPortFunc func(context.Context, SubmitPlanDraftRequest) (SubmitPlanDraftResult, error)

func (f PlanDraftPortFunc) SubmitPlanDraft(ctx context.Context, request SubmitPlanDraftRequest) (SubmitPlanDraftResult, error) {
	return f(ctx, request)
}

type Dependencies struct {
	Research    ResearchPort
	Status      StatusPort
	RecipeDraft RecipeDraftPort
	PlanDraft   PlanDraftPort
}
