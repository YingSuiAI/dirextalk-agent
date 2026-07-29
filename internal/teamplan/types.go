// Package teamplan compiles a model-proposed Worker team into a deterministic,
// provider-neutral plan. It never receives model credentials, executes a
// runtime, selects an unqualified image, or creates cloud resources.
package teamplan

import (
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const SchemaV1 = "dirextalk.agent.team-plan/v1"

type RuntimeFamily string

const (
	RuntimeClaudeCode RuntimeFamily = "claude_code"
	RuntimeCodex      RuntimeFamily = "codex"
	RuntimeOpenClaw   RuntimeFamily = "openclaw"
	RuntimeHermes     RuntimeFamily = "hermes"
	RuntimeOpenCode   RuntimeFamily = "opencode"
)

type RuntimeAdapter string

const (
	AdapterClaudeCodeV1 RuntimeAdapter = "claude_code_task_v1"
	AdapterCodexV1      RuntimeAdapter = "codex_exec_task_v1"
	AdapterOpenClawV1   RuntimeAdapter = "openclaw_gateway_task_v1"
	AdapterHermesV1     RuntimeAdapter = "hermes_api_task_v1"
	AdapterOpenCodeV1   RuntimeAdapter = "opencode_server_task_v1"
)

type RuntimeTrust string

const (
	RuntimeTrustCandidate RuntimeTrust = "candidate"
	RuntimeTrustQualified RuntimeTrust = "qualified"
	RuntimeTrustDisabled  RuntimeTrust = "disabled"
)

type Capability string

const (
	CapabilityRepositoryRead    Capability = "repository.read"
	CapabilityRepositoryWrite   Capability = "repository.write"
	CapabilityCodeReview        Capability = "code.review"
	CapabilityShell             Capability = "shell"
	CapabilityGit               Capability = "git"
	CapabilityTest              Capability = "test"
	CapabilityWebResearch       Capability = "web.research"
	CapabilityBrowser           Capability = "browser"
	CapabilityMCPClient         Capability = "mcp.client"
	CapabilityACP               Capability = "acp"
	CapabilityLongMemory        Capability = "memory.long"
	CapabilitySubagents         Capability = "subagents"
	CapabilityMessaging         Capability = "messaging"
	CapabilityDocument          Capability = "document"
	CapabilityDataAnalysis      Capability = "data.analysis"
	CapabilityLongRunning       Capability = "long_running"
	CapabilityStructuredResults Capability = "result.structured"
)

type WorkClass string

const (
	WorkSoftwareImplementation WorkClass = "software.implementation"
	WorkSoftwareReview         WorkClass = "software.review"
	WorkSoftwareTest           WorkClass = "software.test"
	WorkResearch               WorkClass = "research"
	WorkBrowserAutomation      WorkClass = "browser.automation"
	WorkCommunication          WorkClass = "communication.automation"
	WorkGeneralTool            WorkClass = "general.tool"
	WorkLongRunningOperations  WorkClass = "operations.long_running"
)

type WorkspaceMode string

const (
	WorkspaceReadOnly WorkspaceMode = "read_only"
	// WorkspaceIsolated gives the role a private checkout or worktree. Its
	// output is returned as a patch/result bundle, never as shared mutation.
	WorkspaceIsolated WorkspaceMode = "isolated_workspace"
	// WorkspaceExclusive is reserved for a serial writer. Two exclusive roles
	// must have an explicit dependency path between them.
	WorkspaceExclusive WorkspaceMode = "exclusive_workspace"
)

type ModelInterface string

const (
	ModelAnthropicAPI     ModelInterface = "anthropic_api"
	ModelOpenAIResponses  ModelInterface = "openai_responses"
	ModelOpenAICompatible ModelInterface = "openai_compatible"
)

type QualityTier string

const (
	QualityEconomy  QualityTier = "economy"
	QualityBalanced QualityTier = "balanced"
	QualityPremium  QualityTier = "premium"
)

type Suitability struct {
	WorkClass WorkClass `json:"work_class"`
	Score     uint32    `json:"score"`
}

type ResourceEnvelope struct {
	VCPU      uint32              `json:"vcpu"`
	MemoryMiB uint64              `json:"memory_mib"`
	DiskGiB   uint64              `json:"disk_gib"`
	Arch      recipe.Architecture `json:"architecture"`
}

// RuntimeRelease is a qualified, content-addressed runtime artifact. ImageDigest
// identifies the runtime image; the provider adapter separately maps it to an
// approved Worker AMI or rootfs artifact.
type RuntimeRelease struct {
	ReleaseID       string           `json:"release_id"`
	Family          RuntimeFamily    `json:"family"`
	Version         string           `json:"version"`
	SourceURL       string           `json:"source_url"`
	SourceCommit    string           `json:"source_commit"`
	License         string           `json:"license"`
	ImageDigest     string           `json:"image_digest"`
	Adapter         RuntimeAdapter   `json:"adapter"`
	Capabilities    []Capability     `json:"capabilities"`
	ModelInterfaces []ModelInterface `json:"model_interfaces"`
	Suitability     []Suitability    `json:"suitability"`
	Minimum         ResourceEnvelope `json:"minimum"`
	Recommended     ResourceEnvelope `json:"recommended"`
	ColdStart       time.Duration    `json:"cold_start"`
	Trust           RuntimeTrust     `json:"trust"`
	QualifiedAt     time.Time        `json:"qualified_at"`
}

// ModelOffer is public catalog metadata plus a credential reference. It never
// contains model secret bytes. CredentialRef is resolved only by the existing
// encrypted, deployment-scoped secret-delivery path.
type ModelOffer struct {
	ProfileID              string         `json:"profile_id"`
	Provider               string         `json:"provider"`
	Model                  string         `json:"model"`
	Interface              ModelInterface `json:"interface"`
	Quality                QualityTier    `json:"quality"`
	ContextTokens          uint64         `json:"context_tokens"`
	Vision                 bool           `json:"vision"`
	InputMicrosPerMillion  uint64         `json:"input_micros_per_million"`
	OutputMicrosPerMillion uint64         `json:"output_micros_per_million"`
	CredentialRef          string         `json:"credential_ref"`
	Enabled                bool           `json:"enabled"`
	CredentialReady        bool           `json:"credential_ready"`
}

type ComputeOffer struct {
	OfferID        string              `json:"offer_id"`
	Region         string              `json:"region"`
	InstanceType   string              `json:"instance_type"`
	Architecture   recipe.Architecture `json:"architecture"`
	VCPU           uint32              `json:"vcpu"`
	MemoryMiB      uint64              `json:"memory_mib"`
	DiskGiB        uint64              `json:"disk_gib"`
	HourlyMicros   uint64              `json:"hourly_micros"`
	PurchaseOption string              `json:"purchase_option"`
	Available      bool                `json:"available"`
}

type DurationEstimate struct {
	Minimum  time.Duration `json:"minimum"`
	Expected time.Duration `json:"expected"`
	Maximum  time.Duration `json:"maximum"`
}

type TokenEstimate struct {
	InputMinimum   uint64 `json:"input_minimum"`
	InputExpected  uint64 `json:"input_expected"`
	InputMaximum   uint64 `json:"input_maximum"`
	OutputMinimum  uint64 `json:"output_minimum"`
	OutputExpected uint64 `json:"output_expected"`
	OutputMaximum  uint64 `json:"output_maximum"`
}

type ModelNeed struct {
	MinimumQuality       QualityTier `json:"minimum_quality"`
	MinimumContextTokens uint64      `json:"minimum_context_tokens"`
	Vision               bool        `json:"vision"`
}

// RoleProposal is bounded model output. It expresses intent and estimates, but
// cannot name an image, instance type, credential, command, or provider ID.
type RoleProposal struct {
	RoleID               string           `json:"role_id"`
	Title                string           `json:"title"`
	Objective            string           `json:"objective"`
	WorkClass            WorkClass        `json:"work_class"`
	RequiredCapabilities []Capability     `json:"required_capabilities"`
	PreferredFamilies    []RuntimeFamily  `json:"preferred_families,omitempty"`
	Workspace            WorkspaceMode    `json:"workspace"`
	DependsOnRoleIDs     []string         `json:"depends_on_role_ids,omitempty"`
	Duration             DurationEstimate `json:"duration"`
	Tokens               TokenEstimate    `json:"tokens"`
	ModelNeed            ModelNeed        `json:"model_need"`
	MinimumResources     ResourceEnvelope `json:"minimum_resources"`
}

type TeamProposal struct {
	Roles      []RoleProposal `json:"roles"`
	Confidence uint32         `json:"confidence"`
	Rationale  string         `json:"rationale"`
}

type Policy struct {
	MaxWorkers                uint32          `json:"max_workers"`
	MaxConcurrentWorkers      uint32          `json:"max_concurrent_workers"`
	MaxRoleDuration           time.Duration   `json:"max_role_duration"`
	MaxVCPUPerWorker          uint32          `json:"max_vcpu_per_worker"`
	MaxMemoryMiBPerWorker     uint64          `json:"max_memory_mib_per_worker"`
	MaxDiskGiBPerWorker       uint64          `json:"max_disk_gib_per_worker"`
	MaxPlanCostMicros         uint64          `json:"max_plan_cost_micros"`
	SafetyMarginBasisPoints   uint32          `json:"safety_margin_basis_points"`
	FixedWorkerOverheadMicros uint64          `json:"fixed_worker_overhead_micros"`
	AllowedRuntimeFamilies    []RuntimeFamily `json:"allowed_runtime_families"`
}

type CompileRequest struct {
	PlanID            string           `json:"plan_id"`
	Revision          uint64           `json:"revision"`
	OwnerID           string           `json:"owner_id"`
	GoalDigest        string           `json:"goal_digest"`
	Region            string           `json:"region"`
	CatalogRevision   string           `json:"catalog_revision"`
	PricingSnapshotID string           `json:"pricing_snapshot_id"`
	Currency          string           `json:"currency"`
	QuotedAt          time.Time        `json:"quoted_at"`
	ValidUntil        time.Time        `json:"valid_until"`
	Proposal          TeamProposal     `json:"proposal"`
	RuntimeReleases   []RuntimeRelease `json:"runtime_releases"`
	ModelOffers       []ModelOffer     `json:"model_offers"`
	ComputeOffers     []ComputeOffer   `json:"compute_offers"`
	Policy            Policy           `json:"policy"`
}

type WorkerAssignment struct {
	RoleID               string           `json:"role_id"`
	Title                string           `json:"title"`
	Objective            string           `json:"objective"`
	WorkClass            WorkClass        `json:"work_class"`
	RequiredCapabilities []Capability     `json:"required_capabilities"`
	Workspace            WorkspaceMode    `json:"workspace"`
	DependsOnRoleIDs     []string         `json:"depends_on_role_ids,omitempty"`
	RuntimeReleaseID     string           `json:"runtime_release_id"`
	RuntimeFamily        RuntimeFamily    `json:"runtime_family"`
	RuntimeVersion       string           `json:"runtime_version"`
	RuntimeImageDigest   string           `json:"runtime_image_digest"`
	RuntimeAdapter       RuntimeAdapter   `json:"runtime_adapter"`
	ModelProfileID       string           `json:"model_profile_id"`
	ModelProvider        string           `json:"model_provider"`
	Model                string           `json:"model"`
	ModelInterface       ModelInterface   `json:"model_interface"`
	ModelCredentialRef   string           `json:"model_credential_ref"`
	ComputeOfferID       string           `json:"compute_offer_id"`
	InstanceType         string           `json:"instance_type"`
	Resources            ResourceEnvelope `json:"resources"`
	Duration             DurationEstimate `json:"duration"`
	Tokens               TokenEstimate    `json:"tokens"`
	ColdStart            time.Duration    `json:"cold_start"`
}

type RoleCostEstimate struct {
	RoleID                string `json:"role_id"`
	ComputeMinimumMicros  uint64 `json:"compute_minimum_micros"`
	ComputeExpectedMicros uint64 `json:"compute_expected_micros"`
	ComputeMaximumMicros  uint64 `json:"compute_maximum_micros"`
	ModelMinimumMicros    uint64 `json:"model_minimum_micros"`
	ModelExpectedMicros   uint64 `json:"model_expected_micros"`
	ModelMaximumMicros    uint64 `json:"model_maximum_micros"`
	TotalMinimumMicros    uint64 `json:"total_minimum_micros"`
	TotalExpectedMicros   uint64 `json:"total_expected_micros"`
	TotalMaximumMicros    uint64 `json:"total_maximum_micros"`
}

type CostEstimate struct {
	Currency         string             `json:"currency"`
	MinimumMicros    uint64             `json:"minimum_micros"`
	ExpectedMicros   uint64             `json:"expected_micros"`
	MaximumMicros    uint64             `json:"maximum_micros"`
	HardBudgetMicros uint64             `json:"hard_budget_micros"`
	Roles            []RoleCostEstimate `json:"roles"`
	Assumptions      []string           `json:"assumptions"`
	Exclusions       []string           `json:"exclusions"`
}

type ScheduleEstimate struct {
	MinimumWallTime  time.Duration `json:"minimum_wall_time"`
	ExpectedWallTime time.Duration `json:"expected_wall_time"`
	MaximumWallTime  time.Duration `json:"maximum_wall_time"`
}

// Plan is the immutable approval input. Any runtime, model, resource, role,
// estimate, dependency, or budget change produces a different digest and must
// create a newer revision for user approval.
type Plan struct {
	SchemaVersion        string             `json:"schema_version"`
	PlanID               string             `json:"plan_id"`
	Revision             uint64             `json:"revision"`
	OwnerID              string             `json:"owner_id"`
	GoalDigest           string             `json:"goal_digest"`
	Region               string             `json:"region"`
	CatalogRevision      string             `json:"catalog_revision"`
	PricingSnapshotID    string             `json:"pricing_snapshot_id"`
	QuotedAt             time.Time          `json:"quoted_at"`
	ValidUntil           time.Time          `json:"valid_until"`
	ProposalConfidence   uint32             `json:"proposal_confidence"`
	ProposalRationale    string             `json:"proposal_rationale"`
	WorkerCount          uint32             `json:"worker_count"`
	MaxConcurrentWorkers uint32             `json:"max_concurrent_workers"`
	Assignments          []WorkerAssignment `json:"assignments"`
	Schedule             ScheduleEstimate   `json:"schedule"`
	Cost                 CostEstimate       `json:"cost"`
}
