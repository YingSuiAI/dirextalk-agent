package teamplan

import (
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
)

const (
	PlanDigestPayloadV1 = "dirextalk.agent.team-plan-digest-payload/v1"
	PlanDigestPayloadV2 = "dirextalk.agent.team-plan-digest-payload/v2"
	PlanDigestPayloadV3 = "dirextalk.agent.team-plan-digest-payload/v3"
)

type durationDigestV1 struct {
	MinimumSeconds  uint64 `json:"minimum_seconds"`
	ExpectedSeconds uint64 `json:"expected_seconds"`
	MaximumSeconds  uint64 `json:"maximum_seconds"`
}

type assignmentDigestV1 struct {
	RoleID               string                      `json:"role_id"`
	Title                string                      `json:"title"`
	Objective            string                      `json:"objective"`
	WorkClass            WorkClass                   `json:"work_class"`
	RequiredCapabilities []Capability                `json:"required_capabilities"`
	Workspace            WorkspaceMode               `json:"workspace"`
	DependsOnRoleIDs     []string                    `json:"depends_on_role_ids,omitempty"`
	RuntimeReleaseID     string                      `json:"runtime_release_id"`
	RuntimeFamily        RuntimeFamily               `json:"runtime_family"`
	RuntimeVersion       string                      `json:"runtime_version"`
	RuntimeImageDigest   string                      `json:"runtime_image_digest"`
	RuntimeAdapter       RuntimeAdapter              `json:"runtime_adapter"`
	ModelProfileID       string                      `json:"model_profile_id"`
	ModelProvider        string                      `json:"model_provider"`
	Model                string                      `json:"model"`
	ModelInterface       ModelInterface              `json:"model_interface"`
	ModelCredentialRef   string                      `json:"model_credential_ref"`
	ComputeOfferID       string                      `json:"compute_offer_id"`
	InstanceType         string                      `json:"instance_type"`
	Resources            ResourceEnvelope            `json:"resources"`
	Duration             durationDigestV1            `json:"duration"`
	Tokens               TokenEstimate               `json:"tokens"`
	ColdStartSeconds     uint64                      `json:"cold_start_seconds"`
	Marketplace          *WorkerMarketplaceBindingV1 `json:"marketplace,omitempty"`
}

type scheduleDigestV1 struct {
	MinimumWallSeconds  uint64 `json:"minimum_wall_seconds"`
	ExpectedWallSeconds uint64 `json:"expected_wall_seconds"`
	MaximumWallSeconds  uint64 `json:"maximum_wall_seconds"`
}

type planDigestDocumentV1 struct {
	PayloadSchema         string               `json:"payload_schema"`
	HashAlgorithm         string               `json:"hash_algorithm"`
	SchemaVersion         string               `json:"schema_version"`
	PlanID                string               `json:"plan_id"`
	Revision              uint64               `json:"revision"`
	OwnerID               string               `json:"owner_id"`
	GoalDigest            string               `json:"goal_digest"`
	InputSnapshot         *taskinput.BindingV1 `json:"input_snapshot,omitempty"`
	TaskInput             *taskinput.BindingV2 `json:"task_input,omitempty"`
	ProviderScope         ProviderScope        `json:"provider_scope"`
	Region                string               `json:"region"`
	CatalogRevision       string               `json:"catalog_revision"`
	PolicyRevision        string               `json:"policy_revision"`
	PricingSnapshotID     string               `json:"pricing_snapshot_id"`
	PricingSnapshotDigest string               `json:"pricing_snapshot_digest"`
	QuotedAt              time.Time            `json:"quoted_at"`
	ValidUntil            time.Time            `json:"valid_until"`
	ProposalConfidence    uint32               `json:"proposal_confidence"`
	ProposalRationale     string               `json:"proposal_rationale"`
	WorkerCount           uint32               `json:"worker_count"`
	MaxConcurrentWorkers  uint32               `json:"max_concurrent_workers"`
	Assignments           []assignmentDigestV1 `json:"assignments"`
	Schedule              scheduleDigestV1     `json:"schedule"`
	Cost                  CostEstimate         `json:"cost"`
}

// Validate exposes the same closed validation used by compilation and signing.
func (plan Plan) Validate() error {
	return validatePlan(plan)
}

// CanonicalCBOR returns the exact cross-language approval projection. Duration
// values use integral seconds rather than Go nanoseconds.
func (plan Plan) CanonicalCBOR() ([]byte, error) {
	document, err := plan.digestDocument()
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(document)
}

// Digest is the stable deterministic-CBOR SHA-256 digest bound by Team Plan
// approval. Every selected runtime, model, resource, estimate, dependency and
// budget is included.
func (plan Plan) Digest() (string, error) {
	document, err := plan.digestDocument()
	if err != nil {
		return "", err
	}
	return canonical.Digest(document)
}

func (plan Plan) digestDocument() (planDigestDocumentV1, error) {
	if err := validatePlan(plan); err != nil {
		return planDigestDocumentV1{}, err
	}
	assignments := make([]assignmentDigestV1, 0, len(plan.Assignments))
	for _, assignment := range plan.Assignments {
		var marketplace *WorkerMarketplaceBindingV1
		if assignment.Marketplace != nil {
			value := assignment.Marketplace.Clone()
			marketplace = &value
		}
		assignments = append(assignments, assignmentDigestV1{
			RoleID: assignment.RoleID, Title: assignment.Title,
			Objective: assignment.Objective, WorkClass: assignment.WorkClass,
			RequiredCapabilities: append(
				[]Capability(nil),
				assignment.RequiredCapabilities...,
			),
			Workspace:          assignment.Workspace,
			DependsOnRoleIDs:   append([]string(nil), assignment.DependsOnRoleIDs...),
			RuntimeReleaseID:   assignment.RuntimeReleaseID,
			RuntimeFamily:      assignment.RuntimeFamily,
			RuntimeVersion:     assignment.RuntimeVersion,
			RuntimeImageDigest: assignment.RuntimeImageDigest,
			RuntimeAdapter:     assignment.RuntimeAdapter,
			ModelProfileID:     assignment.ModelProfileID,
			ModelProvider:      assignment.ModelProvider,
			Model:              assignment.Model,
			ModelInterface:     assignment.ModelInterface,
			ModelCredentialRef: assignment.ModelCredentialRef,
			ComputeOfferID:     assignment.ComputeOfferID,
			InstanceType:       assignment.InstanceType,
			Resources:          assignment.Resources,
			Duration:           durationDigest(assignment.Duration),
			Tokens:             assignment.Tokens,
			ColdStartSeconds:   seconds(assignment.ColdStart),
			Marketplace:        marketplace,
		})
	}
	cost := plan.Cost
	cost.Roles = append([]RoleCostEstimate(nil), cost.Roles...)
	cost.Assumptions = append([]string(nil), cost.Assumptions...)
	cost.Exclusions = append([]string(nil), cost.Exclusions...)
	slices.Sort(cost.Assumptions)
	slices.Sort(cost.Exclusions)
	payloadSchema := PlanDigestPayloadV1
	var inputSnapshot *taskinput.BindingV1
	var taskInput *taskinput.BindingV2
	switch plan.SchemaVersion {
	case SchemaV2:
		payloadSchema = PlanDigestPayloadV2
		value := plan.InputSnapshot
		inputSnapshot = &value
	case SchemaV3:
		payloadSchema = PlanDigestPayloadV3
		value := plan.TaskInput
		taskInput = &value
	}
	return planDigestDocumentV1{
		PayloadSchema: payloadSchema,
		HashAlgorithm: canonical.Algorithm,
		SchemaVersion: plan.SchemaVersion,
		PlanID:        plan.PlanID, Revision: plan.Revision, OwnerID: plan.OwnerID,
		GoalDigest:            plan.GoalDigest,
		InputSnapshot:         inputSnapshot,
		TaskInput:             taskInput,
		ProviderScope:         plan.ProviderScope,
		Region:                plan.Region,
		CatalogRevision:       plan.CatalogRevision,
		PolicyRevision:        plan.PolicyRevision,
		PricingSnapshotID:     plan.PricingSnapshotID,
		PricingSnapshotDigest: plan.PricingSnapshotDigest,
		QuotedAt:              plan.QuotedAt.UTC(), ValidUntil: plan.ValidUntil.UTC(),
		ProposalConfidence:   plan.ProposalConfidence,
		ProposalRationale:    plan.ProposalRationale,
		WorkerCount:          plan.WorkerCount,
		MaxConcurrentWorkers: plan.MaxConcurrentWorkers,
		Assignments:          assignments,
		Schedule: scheduleDigestV1{
			MinimumWallSeconds:  seconds(plan.Schedule.MinimumWallTime),
			ExpectedWallSeconds: seconds(plan.Schedule.ExpectedWallTime),
			MaximumWallSeconds:  seconds(plan.Schedule.MaximumWallTime),
		},
		Cost: cost,
	}, nil
}

func durationDigest(value DurationEstimate) durationDigestV1 {
	return durationDigestV1{
		MinimumSeconds:  seconds(value.Minimum),
		ExpectedSeconds: seconds(value.Expected),
		MaximumSeconds:  seconds(value.Maximum),
	}
}

func seconds(value time.Duration) uint64 {
	return uint64(value / time.Second)
}
