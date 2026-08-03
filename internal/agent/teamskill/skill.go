package teamskill

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

const (
	ToolPrepare                = runtimeapi.CloudDialogueToolTeamPlanPrepare
	teamPlanSummarySchemaV1    = "dirextalk.agent.team-plan-summary/v1"
	teamProposalFeedbackV1     = "dirextalk.agent.team-proposal-feedback/v1"
	maxModelVisibleResultBytes = 64 << 10
	maxPrepareAttempts         = 2
)

type Skill struct {
	dependencies Dependencies
}

var _ runtimeapi.ToolProvider = (*Skill)(nil)

func New(dependencies Dependencies) (*Skill, error) {
	if dependencies.Policies == nil ||
		dependencies.Preparation == nil ||
		dependencies.TaskLifecycle == nil {
		return nil, ErrInvalidDependencies
	}
	return &Skill{dependencies: dependencies}, nil
}

func (skill *Skill) Tools(
	ctx context.Context,
	request runtimeapi.ToolRequest,
) ([]runtimeapi.Tool, error) {
	if skill == nil ||
		skill.dependencies.Policies == nil ||
		skill.dependencies.Preparation == nil ||
		skill.dependencies.TaskLifecycle == nil {
		return nil, ErrInvalidDependencies
	}
	scope, err := callScopeFromContext(ctx)
	if err != nil {
		return nil, err
	}
	requestID, parseErr := uuid.Parse(request.RequestID)
	if parseErr != nil ||
		requestID == uuid.Nil ||
		requestID.String() != request.RequestID ||
		request.OwnerID != scope.OwnerID ||
		request.LatestUserMessage != scope.Goal ||
		strings.TrimSpace(request.ConversationID) == "" {
		return nil, ErrInvocationScopeMismatch
	}
	policy, err := skill.dependencies.Policies.ResolveTeamPolicy(
		ctx,
		scope.OwnerID,
	)
	if err != nil {
		return nil, err
	}
	inputSchema, err := teamplan.ProposalInputSchema(policy)
	if err != nil {
		return nil, ErrInvalidDependencies
	}
	var runMu sync.Mutex
	prepareAttempts := 0
	taskAttempted := false
	planPrepared := false
	return []runtimeapi.Tool{{
		Definition: modelapi.Tool{
			Name:        ToolPrepare,
			Description: "Prepare one immutable, priced Team Plan for a substantial remote software implementation, review, or test task. Propose the smallest useful team. Current production execution supports one qualified Pi Worker. The server binds the user goal, AWS connection, runtime catalog, model credentials, compute offers, price, and policy. This operation creates no instance, starts no Worker, delivers no secret, and cannot approve spending.",
			InputSchema: inputSchema,
		},
		Run: func(
			runCtx context.Context,
			invocation runtimeapi.ToolInvocation,
		) (runtimeapi.ToolResult, error) {
			runMu.Lock()
			defer runMu.Unlock()
			if invocation.RequestID != request.RequestID ||
				invocation.OwnerID != request.OwnerID ||
				invocation.ConversationID != request.ConversationID ||
				invocation.Name != ToolPrepare ||
				strings.TrimSpace(invocation.ToolCallID) == "" {
				return runtimeapi.ToolResult{},
					ErrInvocationScopeMismatch
			}
			prepareAttempts++
			attempt := prepareAttempts
			if attempt > maxPrepareAttempts {
				if err := skill.closeUnplannedTask(
					runCtx,
					request,
					scope,
					"retry_exhausted",
					taskAttempted,
					planPrepared,
				); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				taskAttempted = false
				return newProposalFeedback(
					policy,
					"retry_exhausted",
					"Team planning already used its one bounded correction. Do not use cloud_dispatcher_research as a software-task fallback.",
					false,
				)
			}
			proposal, decodeErr := teamplan.DecodeProposalJSON(
				invocation.Arguments,
				policy,
			)
			if decodeErr != nil {
				retryAllowed := attempt < maxPrepareAttempts
				if !retryAllowed {
					if err := skill.closeUnplannedTask(
						runCtx,
						request,
						scope,
						"proposal_outside_policy",
						taskAttempted,
						planPrepared,
					); err != nil {
						return runtimeapi.ToolResult{}, err
					}
					taskAttempted = false
				}
				return newProposalFeedback(
					policy,
					"proposal_outside_policy",
					"The proposal shape or values violated the protected planning contract; this does not mean a Worker runtime is unavailable. Correct it to the trusted schema and limits: keep duration, token, and resource values within every maximum; preserve minimum <= expected <= maximum; use unique role IDs and an acyclic dependency graph; and use isolated_workspace or exclusive_workspace when repository.write is required. Do not use cloud_dispatcher_research as a software-task fallback.",
					retryAllowed,
				)
			}
			taskAttempted = true
			prepared, prepareErr :=
				skill.dependencies.Preparation.PrepareTeamPlan(
					runCtx,
					PrepareRequest{
						RequestID:    request.RequestID,
						OwnerID:      scope.OwnerID,
						ConnectionID: scope.ConnectionID,
						Goal:         scope.Goal,
						Proposal:     proposal,
					},
				)
			if prepareErr != nil {
				if reasonCode, guidance, retryable, safe := proposalFailureFeedback(
					prepareErr,
				); safe {
					retryAllowed := retryable && attempt < maxPrepareAttempts
					if !retryAllowed {
						if err := skill.closeUnplannedTask(
							runCtx,
							request,
							scope,
							reasonCode,
							taskAttempted,
							planPrepared,
						); err != nil {
							return runtimeapi.ToolResult{}, err
						}
						taskAttempted = false
					}
					return newProposalFeedback(
						policy,
						reasonCode,
						guidance,
						retryAllowed,
					)
				}
				if err := skill.closeUnplannedTask(
					runCtx,
					request,
					scope,
					"preparation_failed",
					taskAttempted,
					planPrepared,
				); err != nil {
					return runtimeapi.ToolResult{}, errors.Join(
						prepareErr,
						err,
					)
				}
				taskAttempted = false
				return runtimeapi.ToolResult{}, prepareErr
			}
			planPrepared = true
			view, viewErr := newPlanSummary(
				prepared,
				scope,
				request.RequestID,
				proposal,
			)
			if viewErr != nil {
				return runtimeapi.ToolResult{}, viewErr
			}
			encoded, encodeErr := json.Marshal(view)
			if encodeErr != nil ||
				len(encoded) > maxModelVisibleResultBytes ||
				security.ContainsLikelySecret(string(encoded)) {
				return runtimeapi.ToolResult{},
					ErrModelVisibleResultTooLarge
			}
			return runtimeapi.ToolResult{
				Content:        string(encoded),
				RelatedTaskIDs: []string{view.TaskID},
				RelatedPlanIDs: []string{view.PlanID},
			}, nil
		},
	}}, nil
}

func (skill *Skill) closeUnplannedTask(
	ctx context.Context,
	request runtimeapi.ToolRequest,
	scope CallScope,
	reasonCode string,
	taskAttempted,
	planPrepared bool,
) error {
	if !taskAttempted || planPrepared {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		5*time.Second,
	)
	defer cancel()
	return skill.dependencies.TaskLifecycle.CloseUnplannedTeamTask(
		cleanupCtx,
		PrepareRequest{
			RequestID:    request.RequestID,
			OwnerID:      scope.OwnerID,
			ConnectionID: scope.ConnectionID,
			Goal:         scope.Goal,
		},
		reasonCode,
	)
}

type proposalFeedbackV1 struct {
	SchemaVersion         string                   `json:"schema_version"`
	Status                string                   `json:"status"`
	ReasonCode            string                   `json:"reason_code"`
	Guidance              string                   `json:"guidance"`
	RetryAllowed          bool                     `json:"retry_allowed"`
	CloudResourcesStarted bool                     `json:"cloud_resources_started"`
	Limits                proposalFeedbackLimitsV1 `json:"limits"`
}

type proposalFeedbackLimitsV1 struct {
	MaxWorkers             uint32                   `json:"max_workers"`
	MaxConcurrentWorkers   uint32                   `json:"max_concurrent_workers"`
	MaxRoleDurationSeconds int64                    `json:"max_role_duration_seconds"`
	MaxVCPUPerWorker       uint32                   `json:"max_vcpu_per_worker"`
	MaxMemoryMiBPerWorker  uint64                   `json:"max_memory_mib_per_worker"`
	MaxDiskGiBPerWorker    uint64                   `json:"max_disk_gib_per_worker"`
	MaxPlanCostMicros      uint64                   `json:"max_plan_cost_micros"`
	AllowedRuntimeFamilies []teamplan.RuntimeFamily `json:"allowed_runtime_families"`
}

func newProposalFeedback(
	policy teamplan.Policy,
	reasonCode,
	guidance string,
	retryAllowed bool,
) (runtimeapi.ToolResult, error) {
	view := proposalFeedbackV1{
		SchemaVersion:         teamProposalFeedbackV1,
		Status:                "proposal_rejected",
		ReasonCode:            reasonCode,
		Guidance:              guidance,
		RetryAllowed:          retryAllowed,
		CloudResourcesStarted: false,
		Limits: proposalFeedbackLimitsV1{
			MaxWorkers:             policy.MaxWorkers,
			MaxConcurrentWorkers:   policy.MaxConcurrentWorkers,
			MaxRoleDurationSeconds: int64(policy.MaxRoleDuration / time.Second),
			MaxVCPUPerWorker:       policy.MaxVCPUPerWorker,
			MaxMemoryMiBPerWorker:  policy.MaxMemoryMiBPerWorker,
			MaxDiskGiBPerWorker:    policy.MaxDiskGiBPerWorker,
			MaxPlanCostMicros:      policy.MaxPlanCostMicros,
			AllowedRuntimeFamilies: append(
				[]teamplan.RuntimeFamily(nil),
				policy.AllowedRuntimeFamilies...,
			),
		},
	}
	encoded, err := json.Marshal(view)
	if err != nil ||
		len(encoded) > maxModelVisibleResultBytes ||
		security.ContainsLikelySecret(string(encoded)) {
		return runtimeapi.ToolResult{}, ErrModelVisibleResultTooLarge
	}
	return runtimeapi.ToolResult{
		Content: string(encoded),
		IsError: true,
	}, nil
}

func proposalFailureFeedback(err error) (string, string, bool, bool) {
	switch {
	case errors.Is(err, teamplan.ErrRuntimeRegistryUnavailable):
		return "runtime_registry_unavailable", "The trusted Worker Marketplace registry is unavailable or expired. This is not compute capacity exhaustion. Changing capabilities, runtime preferences, or resource values cannot fix this request. Report that no plan was created and do not retry this request.", false, true
	case errors.Is(err, teamplan.ErrNoRuntime):
		return "no_qualified_runtime", "No currently approved runtime matches the indispensable capabilities. This is a runtime eligibility mismatch, not compute capacity. Remove optional capabilities once without changing the user goal.", true, true
	case errors.Is(err, teamplan.ErrNoModel):
		return "no_qualified_model", "Reduce optional model quality or context requirements without changing the user goal.", true, true
	case errors.Is(err, teamplan.ErrNoCompute):
		return "no_qualified_compute", "No trusted compute offer matches the requested shape. Reduce optional compute requirements within the trusted limits without changing the user goal.", true, true
	case errors.Is(err, teamplan.ErrBudgetExceeded):
		return "budget_exceeded", "Reduce team size, duration, and token estimates while preserving the user goal.", true, true
	default:
		return "", "", false, false
	}
}

type planSummaryV1 struct {
	SchemaVersion          string            `json:"schema_version"`
	TaskID                 string            `json:"task_id"`
	PlanID                 string            `json:"plan_id"`
	PlanRevision           uint64            `json:"plan_revision"`
	Status                 string            `json:"status"`
	Region                 string            `json:"region"`
	WorkerCount            uint32            `json:"worker_count"`
	MaxConcurrentWorkers   uint32            `json:"max_concurrent_workers"`
	Rationale              string            `json:"rationale"`
	Roles                  []roleSummaryV1   `json:"roles"`
	Schedule               scheduleSummaryV1 `json:"schedule"`
	Cost                   costSummaryV1     `json:"cost"`
	ValidUntil             string            `json:"valid_until"`
	SignedApprovalRequired bool              `json:"signed_approval_required"`
	CloudResourcesStarted  bool              `json:"cloud_resources_started"`
}

type roleSummaryV1 struct {
	RoleID          string   `json:"role_id"`
	Title           string   `json:"title"`
	WorkClass       string   `json:"work_class"`
	DependsOn       []string `json:"depends_on_role_ids,omitempty"`
	Runtime         string   `json:"runtime"`
	Model           string   `json:"model"`
	InstanceType    string   `json:"instance_type"`
	ExpectedSeconds int64    `json:"expected_seconds"`
}

type scheduleSummaryV1 struct {
	MinimumSeconds  int64 `json:"minimum_seconds"`
	ExpectedSeconds int64 `json:"expected_seconds"`
	MaximumSeconds  int64 `json:"maximum_seconds"`
}

type costSummaryV1 struct {
	Currency         string `json:"currency"`
	MinimumMicros    uint64 `json:"minimum_micros"`
	ExpectedMicros   uint64 `json:"expected_micros"`
	MaximumMicros    uint64 `json:"maximum_micros"`
	HardBudgetMicros uint64 `json:"hard_budget_micros"`
}

func newPlanSummary(
	fact teamorchestration.PlanFact,
	scope CallScope,
	requestID string,
	proposal teamplan.TeamProposal,
) (planSummaryV1, error) {
	requestUUID, err := uuid.Parse(requestID)
	if err != nil || requestUUID == uuid.Nil {
		return planSummaryV1{}, ErrInvalidPortResponse
	}
	wantPlanID := uuid.NewSHA1(
		requestUUID,
		[]byte("team-plan\x00"+scope.OwnerID),
	).String()
	goalDigest := sha256.Sum256([]byte(strings.TrimSpace(scope.Goal)))
	wantGoalDigest := "sha256:" + hex.EncodeToString(goalDigest[:])
	planDigest, digestErr := fact.Plan.Digest()
	if digestErr != nil ||
		fact.Plan.Validate() != nil ||
		fact.PlanDigest != planDigest ||
		fact.TaskID == "" ||
		fact.Plan.PlanID != wantPlanID ||
		fact.Plan.Revision != 1 ||
		fact.Plan.OwnerID != scope.OwnerID ||
		fact.Plan.ProviderScope.ConnectionID != scope.ConnectionID ||
		fact.Plan.GoalDigest != wantGoalDigest ||
		fact.Status != teamorchestration.PlanReadyForConfirmation ||
		fact.RecordRevision != 1 ||
		!planMatchesProposal(fact.Plan, proposal) ||
		fact.Plan.ValidUntil.Before(time.Now().UTC()) {
		return planSummaryV1{}, ErrInvalidPortResponse
	}
	roles := make([]roleSummaryV1, 0, len(fact.Plan.Assignments))
	for _, assignment := range fact.Plan.Assignments {
		roles = append(roles, roleSummaryV1{
			RoleID:          assignment.RoleID,
			Title:           assignment.Title,
			WorkClass:       string(assignment.WorkClass),
			DependsOn:       append([]string(nil), assignment.DependsOnRoleIDs...),
			Runtime:         string(assignment.RuntimeFamily),
			Model:           assignment.Model,
			InstanceType:    assignment.InstanceType,
			ExpectedSeconds: durationSeconds(assignment.Duration.Expected),
		})
	}
	return planSummaryV1{
		SchemaVersion:        teamPlanSummarySchemaV1,
		TaskID:               fact.TaskID,
		PlanID:               fact.Plan.PlanID,
		PlanRevision:         fact.Plan.Revision,
		Status:               string(fact.Status),
		Region:               fact.Plan.Region,
		WorkerCount:          fact.Plan.WorkerCount,
		MaxConcurrentWorkers: fact.Plan.MaxConcurrentWorkers,
		Rationale:            fact.Plan.ProposalRationale,
		Roles:                roles,
		Schedule: scheduleSummaryV1{
			MinimumSeconds: durationSeconds(
				fact.Plan.Schedule.MinimumWallTime,
			),
			ExpectedSeconds: durationSeconds(
				fact.Plan.Schedule.ExpectedWallTime,
			),
			MaximumSeconds: durationSeconds(
				fact.Plan.Schedule.MaximumWallTime,
			),
		},
		Cost: costSummaryV1{
			Currency:         fact.Plan.Cost.Currency,
			MinimumMicros:    fact.Plan.Cost.MinimumMicros,
			ExpectedMicros:   fact.Plan.Cost.ExpectedMicros,
			MaximumMicros:    fact.Plan.Cost.MaximumMicros,
			HardBudgetMicros: fact.Plan.Cost.HardBudgetMicros,
		},
		ValidUntil:             fact.Plan.ValidUntil.UTC().Format(time.RFC3339),
		SignedApprovalRequired: true,
		CloudResourcesStarted:  false,
	}, nil
}

func planMatchesProposal(
	plan teamplan.Plan,
	proposal teamplan.TeamProposal,
) bool {
	if plan.ProposalConfidence != proposal.Confidence ||
		plan.ProposalRationale != proposal.Rationale ||
		plan.WorkerCount != uint32(len(proposal.Roles)) ||
		len(plan.Assignments) != len(proposal.Roles) {
		return false
	}
	roles := make(map[string]teamplan.RoleProposal, len(proposal.Roles))
	for _, role := range proposal.Roles {
		roles[role.RoleID] = role
	}
	for _, assignment := range plan.Assignments {
		role, ok := roles[assignment.RoleID]
		if !ok ||
			assignment.Title != role.Title ||
			assignment.Objective != role.Objective ||
			assignment.WorkClass != role.WorkClass ||
			assignment.Workspace != role.Workspace ||
			assignment.Duration != role.Duration ||
			assignment.Tokens != role.Tokens {
			return false
		}
		required := append(
			[]teamplan.Capability(nil),
			role.RequiredCapabilities...,
		)
		dependencies := append(
			[]string(nil),
			role.DependsOnRoleIDs...,
		)
		slices.Sort(required)
		slices.Sort(dependencies)
		if !slices.Equal(
			assignment.RequiredCapabilities,
			required,
		) || !slices.Equal(
			assignment.DependsOnRoleIDs,
			dependencies,
		) {
			return false
		}
	}
	return true
}

func durationSeconds(value time.Duration) int64 {
	return int64(value / time.Second)
}
