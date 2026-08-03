// Package teamexecution materializes one approved Team Plan into a
// deterministic multi-Worker execution graph. It does not launch cloud
// resources, resolve secret bytes, or accept Worker configuration from a
// network caller.
package teamexecution

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const (
	SchemaV1 = "dirextalk.agent.team-execution/v1"
	SchemaV2 = "dirextalk.agent.team-execution/v2"
	SchemaV3 = "dirextalk.agent.team-execution/v3"
)

var (
	ErrInvalid          = errors.New("invalid Team execution request")
	ErrFactMismatch     = errors.New("Team execution fact mismatch")
	ErrNotReady         = errors.New("Team execution is not ready")
	ErrNotFound         = errors.New("Team execution was not found")
	ErrConcurrencyLimit = errors.New("Team execution concurrency limit reached")
)

type Status string

const (
	StatusMaterialized Status = "materialized"
	StatusDispatching  Status = "dispatching"
	StatusRunning      Status = "running"
	StatusVerifying    Status = "verifying"
	StatusCompleted    Status = "completed"
	StatusFailed       Status = "failed"
	StatusCanceled     Status = "canceled"
)

type DurationEstimateV1 struct {
	MinimumSeconds  uint64 `json:"minimum_seconds"`
	ExpectedSeconds uint64 `json:"expected_seconds"`
	MaximumSeconds  uint64 `json:"maximum_seconds"`
}

type ScheduleEstimateV1 struct {
	MinimumWallSeconds  uint64 `json:"minimum_wall_seconds"`
	ExpectedWallSeconds uint64 `json:"expected_wall_seconds"`
	MaximumWallSeconds  uint64 `json:"maximum_wall_seconds"`
}

// RoleV1 is an immutable launch intent. ModelCredentialSlot is a logical,
// deployment-scoped file slot; it is deliberately not the server-side
// credential reference and never contains secret material.
type RoleV1 struct {
	RoleID               string                               `json:"role_id"`
	Title                string                               `json:"title"`
	Objective            string                               `json:"objective"`
	WorkClass            teamplan.WorkClass                   `json:"work_class"`
	RequiredCapabilities []teamplan.Capability                `json:"required_capabilities"`
	Workspace            teamplan.WorkspaceMode               `json:"workspace"`
	DependsOnRoleIDs     []string                             `json:"depends_on_role_ids,omitempty"`
	StepDeclarationID    string                               `json:"step_declaration_id"`
	TaskStepID           string                               `json:"task_step_id"`
	DeploymentID         string                               `json:"deployment_id"`
	ExpectedWorkerID     string                               `json:"expected_worker_id"`
	RuntimeReleaseID     string                               `json:"runtime_release_id"`
	RuntimeFamily        teamplan.RuntimeFamily               `json:"runtime_family"`
	RuntimeVersion       string                               `json:"runtime_version"`
	RuntimeImageDigest   string                               `json:"runtime_image_digest"`
	RuntimeAdapter       teamplan.RuntimeAdapter              `json:"runtime_adapter"`
	Marketplace          *teamplan.WorkerMarketplaceBindingV1 `json:"marketplace,omitempty"`
	ModelProfileID       string                               `json:"model_profile_id"`
	ModelProvider        string                               `json:"model_provider"`
	Model                string                               `json:"model"`
	ModelInterface       teamplan.ModelInterface              `json:"model_interface"`
	ModelCredentialSlot  string                               `json:"model_credential_slot"`
	ComputeOfferID       string                               `json:"compute_offer_id"`
	InstanceType         string                               `json:"instance_type"`
	Resources            teamplan.ResourceEnvelope            `json:"resources"`
	Duration             DurationEstimateV1                   `json:"duration"`
	Tokens               teamplan.TokenEstimate               `json:"tokens"`
	ColdStartSeconds     uint64                               `json:"cold_start_seconds"`
}

// ExecutionV1 is the deterministic projection authorized by one device-signed
// Team Plan. Provider, budget, runtime, model, compute, and dependency facts
// remain bound to PlanDigest.
type ExecutionV1 struct {
	SchemaVersion         string                 `json:"schema_version"`
	ExecutionID           string                 `json:"execution_id"`
	OwnerID               string                 `json:"owner_id"`
	TaskID                string                 `json:"task_id"`
	PlanID                string                 `json:"plan_id"`
	PlanRevision          uint64                 `json:"plan_revision"`
	PlanDigest            string                 `json:"plan_digest"`
	ApprovalID            string                 `json:"approval_id"`
	ApprovalSignerKeyID   string                 `json:"approval_signer_key_id"`
	GoalDigest            string                 `json:"goal_digest"`
	InputSnapshot         taskinput.BindingV1    `json:"input_snapshot,omitempty"`
	TaskInput             taskinput.BindingV2    `json:"task_input,omitempty"`
	ProviderScope         teamplan.ProviderScope `json:"provider_scope"`
	Region                string                 `json:"region"`
	CatalogRevision       string                 `json:"catalog_revision"`
	PolicyRevision        string                 `json:"policy_revision"`
	PricingSnapshotID     string                 `json:"pricing_snapshot_id"`
	PricingSnapshotDigest string                 `json:"pricing_snapshot_digest"`
	WorkerCount           uint32                 `json:"worker_count"`
	MaxConcurrentWorkers  uint32                 `json:"max_concurrent_workers"`
	Currency              string                 `json:"currency"`
	MinimumCostMicros     uint64                 `json:"minimum_cost_micros"`
	ExpectedCostMicros    uint64                 `json:"expected_cost_micros"`
	MaximumCostMicros     uint64                 `json:"maximum_cost_micros"`
	HardBudgetMicros      uint64                 `json:"hard_budget_micros"`
	Schedule              ScheduleEstimateV1     `json:"schedule"`
	AuthorizedAt          time.Time              `json:"authorized_at"`
	Roles                 []RoleV1               `json:"roles"`
}

type Fact struct {
	Execution       ExecutionV1 `json:"execution"`
	ExecutionDigest string      `json:"execution_digest"`
	Status          Status      `json:"status"`
	RecordRevision  uint64      `json:"record_revision"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

type MaterializeRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	OwnerID        string `json:"owner_id"`
	PlanID         string `json:"plan_id"`
	PlanRevision   uint64 `json:"plan_revision"`
}

type BeginDispatchRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	OwnerID        string `json:"owner_id"`
	ExecutionID    string `json:"execution_id"`
}

type PendingMaterialization struct {
	OwnerID      string
	PlanID       string
	PlanRevision uint64
	UpdatedAt    time.Time
}

type PersistCommand struct {
	IdempotencyKey string
	Authorization  teamorchestration.ApprovedPlanFact
	Execution      ExecutionV1
}

type BeginDispatchCommand struct {
	IdempotencyKey string
	OwnerID        string
	ExecutionID    string
	// Authorization is required only for the first materialized -> dispatching
	// transition. Convergent replays after that transition validate the
	// permanently stored approval instead of requiring a still-live quote.
	Authorization *teamorchestration.ApprovedPlanFact
}

type Repository interface {
	FindMaterializedExecution(
		context.Context,
		task.MutationScope,
		MaterializeRequest,
	) (Fact, bool, error)
	ListPendingMaterializations(
		context.Context,
		*PendingMaterialization,
		uint32,
	) ([]PendingMaterialization, error)
	PersistExecution(
		context.Context,
		task.MutationScope,
		PersistCommand,
	) (Fact, error)
	GetTeamExecution(
		context.Context,
		string,
		string,
	) (Fact, error)
	FindDispatch(
		context.Context,
		task.MutationScope,
		BeginDispatchRequest,
	) (Fact, bool, error)
	BeginDispatch(
		context.Context,
		task.MutationScope,
		BeginDispatchCommand,
	) (Fact, error)
}

type ApprovedPlanVerifier interface {
	GetApprovedPlanForMaterialization(
		context.Context,
		string,
		string,
		uint64,
	) (teamorchestration.ApprovedPlanFact, error)
	VerifyApprovedPlanForExecution(
		context.Context,
		string,
		string,
		uint64,
	) (teamorchestration.ApprovedPlanFact, error)
}
