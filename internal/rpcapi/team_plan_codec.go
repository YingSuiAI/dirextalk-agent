package rpcapi

import (
	"encoding/base64"
	"math"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func teamProposalFromProto(
	value *agentv1.TeamProposalV3,
) (teamplan.TeamProposal, error) {
	if value == nil {
		return teamplan.TeamProposal{}, invalidTeamRequest(
			"proposal is required",
		)
	}
	proposal := teamplan.TeamProposal{
		Roles:      make([]teamplan.RoleProposal, 0, len(value.GetRoles())),
		Confidence: value.GetConfidence(),
		Rationale:  value.GetRationale(),
	}
	for _, roleValue := range value.GetRoles() {
		role, err := teamRoleProposalFromProto(roleValue)
		if err != nil {
			return teamplan.TeamProposal{}, err
		}
		proposal.Roles = append(proposal.Roles, role)
	}
	return proposal, nil
}

func teamRoleProposalFromProto(
	value *agentv1.TeamRoleProposalV3,
) (teamplan.RoleProposal, error) {
	if value == nil {
		return teamplan.RoleProposal{}, invalidTeamRequest(
			"every proposal role is required",
		)
	}
	workClass, err := teamWorkClassFromProto(value.GetWorkClass())
	if err != nil {
		return teamplan.RoleProposal{}, err
	}
	workspace, err := teamWorkspaceFromProto(value.GetWorkspaceMode())
	if err != nil {
		return teamplan.RoleProposal{}, err
	}
	duration, err := teamDurationFromProto(value.GetDuration())
	if err != nil {
		return teamplan.RoleProposal{}, err
	}
	modelNeed, err := teamModelNeedFromProto(value.GetModelNeed())
	if err != nil {
		return teamplan.RoleProposal{}, err
	}
	resources, err := teamResourcesFromProto(value.GetMinimumResources())
	if err != nil {
		return teamplan.RoleProposal{}, err
	}
	capabilities := make(
		[]teamplan.Capability,
		0,
		len(value.GetRequiredCapabilities()),
	)
	for _, capabilityValue := range value.GetRequiredCapabilities() {
		capability, mapErr := teamCapabilityFromProto(capabilityValue)
		if mapErr != nil {
			return teamplan.RoleProposal{}, mapErr
		}
		capabilities = append(capabilities, capability)
	}
	families := make(
		[]teamplan.RuntimeFamily,
		0,
		len(value.GetPreferredRuntimeFamilies()),
	)
	for _, familyValue := range value.GetPreferredRuntimeFamilies() {
		family, mapErr := teamRuntimeFamilyFromProto(familyValue)
		if mapErr != nil {
			return teamplan.RoleProposal{}, mapErr
		}
		families = append(families, family)
	}
	return teamplan.RoleProposal{
		RoleID:               value.GetRoleId(),
		Title:                value.GetTitle(),
		Objective:            value.GetObjective(),
		WorkClass:            workClass,
		RequiredCapabilities: capabilities,
		PreferredFamilies:    families,
		Workspace:            workspace,
		DependsOnRoleIDs: append(
			[]string(nil),
			value.GetDependsOnRoleIds()...,
		),
		Duration:         duration,
		Tokens:           teamTokensFromProto(value.GetTokens()),
		ModelNeed:        modelNeed,
		MinimumResources: resources,
	}, nil
}

func teamDurationFromProto(
	value *agentv1.TeamDurationEstimateV3,
) (teamplan.DurationEstimate, error) {
	if value == nil {
		return teamplan.DurationEstimate{}, invalidTeamRequest(
			"role duration is required",
		)
	}
	minimum, err := checkedTeamDuration(value.GetMinimumSeconds())
	if err != nil {
		return teamplan.DurationEstimate{}, err
	}
	expected, err := checkedTeamDuration(value.GetExpectedSeconds())
	if err != nil {
		return teamplan.DurationEstimate{}, err
	}
	maximum, err := checkedTeamDuration(value.GetMaximumSeconds())
	if err != nil {
		return teamplan.DurationEstimate{}, err
	}
	return teamplan.DurationEstimate{
		Minimum:  minimum,
		Expected: expected,
		Maximum:  maximum,
	}, nil
}

func checkedTeamDuration(seconds uint64) (time.Duration, error) {
	if seconds == 0 ||
		seconds > uint64(math.MaxInt64/int64(time.Second)) {
		return 0, invalidTeamRequest(
			"duration seconds must be positive and bounded",
		)
	}
	return time.Duration(seconds) * time.Second, nil
}

func teamTokensFromProto(
	value *agentv1.TeamTokenEstimateV3,
) teamplan.TokenEstimate {
	if value == nil {
		return teamplan.TokenEstimate{}
	}
	return teamplan.TokenEstimate{
		InputMinimum:   value.GetInputMinimum(),
		InputExpected:  value.GetInputExpected(),
		InputMaximum:   value.GetInputMaximum(),
		OutputMinimum:  value.GetOutputMinimum(),
		OutputExpected: value.GetOutputExpected(),
		OutputMaximum:  value.GetOutputMaximum(),
	}
}

func teamModelNeedFromProto(
	value *agentv1.TeamModelNeedV3,
) (teamplan.ModelNeed, error) {
	if value == nil {
		return teamplan.ModelNeed{}, invalidTeamRequest(
			"role model need is required",
		)
	}
	quality, err := teamQualityFromProto(value.GetMinimumQuality())
	if err != nil {
		return teamplan.ModelNeed{}, err
	}
	return teamplan.ModelNeed{
		MinimumQuality:       quality,
		MinimumContextTokens: value.GetMinimumContextTokens(),
		Vision:               value.GetVision(),
	}, nil
}

func teamResourcesFromProto(
	value *agentv1.TeamMinimumResourcesV3,
) (teamplan.ResourceEnvelope, error) {
	if value == nil {
		return teamplan.ResourceEnvelope{}, invalidTeamRequest(
			"role minimum resources are required",
		)
	}
	return teamplan.ResourceEnvelope{
		VCPU:      value.GetVcpu(),
		MemoryMiB: value.GetMemoryMib(),
		DiskGiB:   value.GetDiskGib(),
	}, nil
}

func teamPlanToProto(
	fact teamorchestration.PlanFact,
) (*agentv1.TeamPlanV3, error) {
	if err := fact.Plan.Validate(); err != nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	digest, err := fact.Plan.Digest()
	if err != nil || digest != fact.PlanDigest ||
		fact.Plan.Revision > math.MaxInt64 ||
		fact.RecordRevision == 0 ||
		fact.RecordRevision > math.MaxInt64 {
		return nil, teamorchestration.ErrFactMismatch
	}
	statusValue, err := teamPlanStatusToProto(fact.Status)
	if err != nil {
		return nil, err
	}
	provider, err := teamProviderScopeToProto(fact.Plan.ProviderScope)
	if err != nil {
		return nil, err
	}
	inputSnapshot, err := teamInputSnapshotToProto(
		fact.Plan.InputSnapshot,
	)
	if err != nil {
		return nil, err
	}
	taskInput, err := teamTaskInputToProto(fact.Plan.TaskInput)
	if err != nil {
		return nil, err
	}
	assignments := make(
		[]*agentv1.TeamWorkerAssignmentV3,
		0,
		len(fact.Plan.Assignments),
	)
	for _, assignment := range fact.Plan.Assignments {
		projected, mapErr := teamAssignmentToProto(assignment)
		if mapErr != nil {
			return nil, mapErr
		}
		assignments = append(assignments, projected)
	}
	quotedAt, err := checkedTeamTimestamp(fact.Plan.QuotedAt)
	if err != nil {
		return nil, err
	}
	validUntil, err := checkedTeamTimestamp(fact.Plan.ValidUntil)
	if err != nil {
		return nil, err
	}
	createdAt, err := checkedTeamTimestamp(fact.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := checkedTeamTimestamp(fact.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamPlanV3{
		SchemaVersion:          fact.Plan.SchemaVersion,
		TaskId:                 fact.TaskID,
		PlanId:                 fact.Plan.PlanID,
		PlanRevision:           int64(fact.Plan.Revision),
		OwnerId:                fact.Plan.OwnerID,
		GoalDigest:             fact.Plan.GoalDigest,
		InputSnapshot:          inputSnapshot,
		TaskInput:              taskInput,
		ProviderScope:          provider,
		Region:                 fact.Plan.Region,
		RuntimeCatalogRevision: fact.Plan.CatalogRevision,
		PolicyRevision:         fact.Plan.PolicyRevision,
		PricingSnapshotId:      fact.Plan.PricingSnapshotID,
		PricingSnapshotDigest:  fact.Plan.PricingSnapshotDigest,
		QuotedAt:               quotedAt,
		ValidUntil:             validUntil,
		ProposalConfidence:     fact.Plan.ProposalConfidence,
		ProposalRationale:      fact.Plan.ProposalRationale,
		WorkerCount:            fact.Plan.WorkerCount,
		MaxConcurrentWorkers:   fact.Plan.MaxConcurrentWorkers,
		Assignments:            assignments,
		Schedule:               teamScheduleToProto(fact.Plan.Schedule),
		Cost:                   teamCostToProto(fact.Plan.Cost),
		PlanDigest:             fact.PlanDigest,
		Status:                 statusValue,
		RecordRevision:         int64(fact.RecordRevision),
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}, nil
}

func teamTaskInputToProto(
	value taskinput.BindingV2,
) (*agentv1.TeamTaskInputBindingV3, error) {
	if value == (taskinput.BindingV2{}) {
		return nil, nil
	}
	if value.Validate() != nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	sourceKind, err := teamInputSourceKindToProto(value.SourceKind)
	if err != nil {
		return nil, err
	}
	var repository *agentv1.TeamGitRepositorySourceV3
	if value.SourceKind == taskinput.SourceGitHubRepository {
		repository = &agentv1.TeamGitRepositorySourceV3{
			Provider:      value.Repository.Provider,
			Host:          value.Repository.Host,
			ConnectionId:  value.Repository.ConnectionID,
			RepositoryId:  value.Repository.RepositoryID,
			Owner:         value.Repository.Owner,
			Name:          value.Repository.Name,
			BaseCommitSha: value.Repository.BaseCommitSHA,
			BaseRef:       value.Repository.BaseRef,
		}
	}
	workspace, err := teamInputSnapshotToProto(value.Workspace)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamTaskInputBindingV3{
		SchemaVersion: value.SchemaVersion,
		InputId:       value.InputID,
		InputDigest:   value.InputDigest,
		SourceDigest:  value.SourceDigest,
		SourceKind:    sourceKind,
		Repository:    repository,
		Workspace:     workspace,
	}, nil
}

func teamInputSourceKindToProto(
	value taskinput.SourceKind,
) (agentv1.TeamInputSourceKindV3, error) {
	switch value {
	case taskinput.SourceEmpty:
		return agentv1.TeamInputSourceKindV3_TEAM_INPUT_SOURCE_KIND_V3_EMPTY, nil
	case taskinput.SourceGitHubRepository:
		return agentv1.TeamInputSourceKindV3_TEAM_INPUT_SOURCE_KIND_V3_GITHUB_REPOSITORY, nil
	case taskinput.SourceWorkspaceArchive:
		return agentv1.TeamInputSourceKindV3_TEAM_INPUT_SOURCE_KIND_V3_WORKSPACE_ARCHIVE, nil
	default:
		return agentv1.TeamInputSourceKindV3_TEAM_INPUT_SOURCE_KIND_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamInputSnapshotToProto(
	value taskinput.BindingV1,
) (*agentv1.TeamInputSnapshotBindingV3, error) {
	if value == (taskinput.BindingV1{}) {
		return nil, nil
	}
	if value.Validate() != nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	return &agentv1.TeamInputSnapshotBindingV3{
		SnapshotId:         value.SnapshotID,
		SnapshotDigest:     value.SnapshotDigest,
		WorkspaceDigest:    value.WorkspaceDigest,
		WorkspaceSizeBytes: value.WorkspaceSizeBytes,
		WorkspaceMediaType: value.WorkspaceMediaType,
	}, nil
}

func teamAssignmentToProto(
	value teamplan.WorkerAssignment,
) (*agentv1.TeamWorkerAssignmentV3, error) {
	workClass, err := teamWorkClassToProto(value.WorkClass)
	if err != nil {
		return nil, err
	}
	marketplace, err := teamMarketplaceBindingToProto(
		value.Marketplace,
	)
	if err != nil {
		return nil, err
	}
	workspace, err := teamWorkspaceToProto(value.Workspace)
	if err != nil {
		return nil, err
	}
	family, err := teamRuntimeFamilyToProto(value.RuntimeFamily)
	if err != nil {
		return nil, err
	}
	adapter, err := teamRuntimeAdapterToProto(value.RuntimeAdapter)
	if err != nil {
		return nil, err
	}
	modelInterface, err := teamModelInterfaceToProto(value.ModelInterface)
	if err != nil {
		return nil, err
	}
	resources, err := teamResourcesToProto(value.Resources)
	if err != nil {
		return nil, err
	}
	duration, err := teamDurationToProto(value.Duration)
	if err != nil {
		return nil, err
	}
	coldStart, err := teamDurationSecondsAllowZero(value.ColdStart)
	if err != nil {
		return nil, err
	}
	capabilities := make(
		[]agentv1.TeamCapabilityV3,
		0,
		len(value.RequiredCapabilities),
	)
	for _, capabilityValue := range value.RequiredCapabilities {
		capability, mapErr := teamCapabilityToProto(capabilityValue)
		if mapErr != nil {
			return nil, mapErr
		}
		capabilities = append(capabilities, capability)
	}
	return &agentv1.TeamWorkerAssignmentV3{
		RoleId:               value.RoleID,
		Title:                value.Title,
		Objective:            value.Objective,
		WorkClass:            workClass,
		RequiredCapabilities: capabilities,
		WorkspaceMode:        workspace,
		DependsOnRoleIds: append(
			[]string(nil),
			value.DependsOnRoleIDs...,
		),
		RuntimeReleaseId:   value.RuntimeReleaseID,
		RuntimeFamily:      family,
		RuntimeVersion:     value.RuntimeVersion,
		RuntimeImageDigest: value.RuntimeImageDigest,
		RuntimeAdapter:     adapter,
		ModelProfileId:     value.ModelProfileID,
		ModelProvider:      value.ModelProvider,
		Model:              value.Model,
		ModelInterface:     modelInterface,
		ComputeOfferId:     value.ComputeOfferID,
		InstanceType:       value.InstanceType,
		Resources:          resources,
		Duration:           duration,
		Tokens:             teamTokensToProto(value.Tokens),
		ColdStartSeconds:   coldStart,
		Marketplace:        marketplace,
	}, nil
}

func teamMarketplaceBindingToProto(
	value *teamplan.WorkerMarketplaceBindingV1,
) (*agentv1.TeamWorkerMarketplaceBindingV3, error) {
	if value == nil {
		return nil, nil
	}
	var reviewValidUntil *timestamppb.Timestamp
	if value.ReviewValidUntil.IsZero() {
		if value.PublisherTier != "dirextalk_official" {
			return nil, teamplan.ErrInvalid
		}
	} else {
		var err error
		reviewValidUntil, err = checkedTeamTimestamp(
			value.ReviewValidUntil,
		)
		if err != nil {
			return nil, err
		}
	}
	networkServices := make(
		[]string,
		0,
		len(value.GrantedPermissions.NetworkServices),
	)
	for _, service := range value.GrantedPermissions.NetworkServices {
		networkServices = append(networkServices, string(service))
	}
	return &agentv1.TeamWorkerMarketplaceBindingV3{
		SchemaVersion:            value.SchemaVersion,
		RegistryId:               value.RegistryID,
		RegistryRevision:         value.RegistryRevision,
		ReleaseId:                value.ReleaseID,
		WorkerTypeId:             value.WorkerTypeID,
		PublisherId:              value.PublisherID,
		PublisherDisplayName:     value.PublisherDisplayName,
		PublisherTier:            value.PublisherTier,
		OrganizationId:           value.OrganizationID,
		ManifestDigest:           value.ManifestDigest,
		ImageRepository:          value.ImageRepository,
		ImageDigest:              value.ImageDigest,
		ImageSignatureDigest:     value.ImageSignatureDigest,
		SbomDigest:               value.SBOMDigest,
		ProvenanceEnvelopeDigest: value.ProvenanceEnvelopeDigest,
		ReviewId:                 value.ReviewID,
		ReviewPolicyRevision:     value.ReviewPolicyRevision,
		ReviewRiskClass:          value.ReviewRiskClass,
		ReviewValidUntil:         reviewValidUntil,
		GrantedPermissions: &agentv1.TeamWorkerPermissionSetV3{
			Workspace:       string(value.GrantedPermissions.Workspace),
			NetworkServices: networkServices,
			ToolScopes: append(
				[]string(nil),
				value.GrantedPermissions.ToolScopes...,
			),
			MaxTempDiskMib: value.GrantedPermissions.MaxTempDiskMiB,
		},
	}, nil
}

func teamResourcesToProto(
	value teamplan.ResourceEnvelope,
) (*agentv1.TeamResourceEnvelopeV3, error) {
	architecture, err := teamArchitectureToProto(value.Arch)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamResourceEnvelopeV3{
		Vcpu:         value.VCPU,
		MemoryMib:    value.MemoryMiB,
		DiskGib:      value.DiskGiB,
		Architecture: architecture,
	}, nil
}

func teamDurationToProto(
	value teamplan.DurationEstimate,
) (*agentv1.TeamDurationEstimateV3, error) {
	minimum, err := teamDurationSeconds(value.Minimum)
	if err != nil {
		return nil, err
	}
	expected, err := teamDurationSeconds(value.Expected)
	if err != nil {
		return nil, err
	}
	maximum, err := teamDurationSeconds(value.Maximum)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamDurationEstimateV3{
		MinimumSeconds:  minimum,
		ExpectedSeconds: expected,
		MaximumSeconds:  maximum,
	}, nil
}

func teamDurationSeconds(value time.Duration) (uint64, error) {
	if value <= 0 || value%time.Second != 0 {
		return 0, teamorchestration.ErrFactMismatch
	}
	return uint64(value / time.Second), nil
}

func teamDurationSecondsAllowZero(value time.Duration) (uint64, error) {
	if value < 0 || value%time.Second != 0 {
		return 0, teamorchestration.ErrFactMismatch
	}
	return uint64(value / time.Second), nil
}

func teamTokensToProto(
	value teamplan.TokenEstimate,
) *agentv1.TeamTokenEstimateV3 {
	return &agentv1.TeamTokenEstimateV3{
		InputMinimum:   value.InputMinimum,
		InputExpected:  value.InputExpected,
		InputMaximum:   value.InputMaximum,
		OutputMinimum:  value.OutputMinimum,
		OutputExpected: value.OutputExpected,
		OutputMaximum:  value.OutputMaximum,
	}
}

func teamScheduleToProto(
	value teamplan.ScheduleEstimate,
) *agentv1.TeamScheduleEstimateV3 {
	return &agentv1.TeamScheduleEstimateV3{
		MinimumWallSeconds:  uint64(value.MinimumWallTime / time.Second),
		ExpectedWallSeconds: uint64(value.ExpectedWallTime / time.Second),
		MaximumWallSeconds:  uint64(value.MaximumWallTime / time.Second),
	}
}

func teamCostToProto(
	value teamplan.CostEstimate,
) *agentv1.TeamCostEstimateV3 {
	roles := make(
		[]*agentv1.TeamRoleCostEstimateV3,
		0,
		len(value.Roles),
	)
	for _, role := range value.Roles {
		roles = append(roles, &agentv1.TeamRoleCostEstimateV3{
			RoleId:                role.RoleID,
			ComputeMinimumMicros:  role.ComputeMinimumMicros,
			ComputeExpectedMicros: role.ComputeExpectedMicros,
			ComputeMaximumMicros:  role.ComputeMaximumMicros,
			ModelMinimumMicros:    role.ModelMinimumMicros,
			ModelExpectedMicros:   role.ModelExpectedMicros,
			ModelMaximumMicros:    role.ModelMaximumMicros,
			TotalMinimumMicros:    role.TotalMinimumMicros,
			TotalExpectedMicros:   role.TotalExpectedMicros,
			TotalMaximumMicros:    role.TotalMaximumMicros,
		})
	}
	return &agentv1.TeamCostEstimateV3{
		Currency:         value.Currency,
		MinimumMicros:    value.MinimumMicros,
		ExpectedMicros:   value.ExpectedMicros,
		MaximumMicros:    value.MaximumMicros,
		HardBudgetMicros: value.HardBudgetMicros,
		Roles:            roles,
		Assumptions:      append([]string(nil), value.Assumptions...),
		Exclusions:       append([]string(nil), value.Exclusions...),
	}
}

func teamChallengeToProto(
	fact teamorchestration.ChallengeFact,
) (*agentv1.TeamApprovalChallengeV3, error) {
	if fact.Authorization == nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	authorizationDigest, authorizationDigestErr :=
		fact.Authorization.Digest()
	if err := fact.Challenge.Validate(); err != nil ||
		fact.Challenge.SchemaVersion !=
			teamapproval.ChallengeSchemaV2 ||
		fact.Authorization.Validate() != nil ||
		authorizationDigestErr != nil ||
		fact.Authorization.AuthorizationID !=
			fact.Challenge.LaunchAuthorizationID ||
		authorizationDigest !=
			fact.Challenge.LaunchAuthorizationDigest ||
		fact.Authorization.AgentInstanceID !=
			fact.Challenge.AgentInstanceID ||
		fact.Authorization.OwnerID != fact.Challenge.OwnerID ||
		fact.Authorization.PlanID != fact.Challenge.PlanID ||
		fact.Authorization.PlanRevision !=
			fact.Challenge.PlanRevision ||
		fact.Authorization.PlanDigest != fact.Challenge.PlanDigest ||
		fact.Authorization.ApprovalID !=
			fact.Challenge.ApprovalID ||
		fact.Authorization.ProviderScope !=
			fact.Challenge.ProviderScope ||
		fact.Authorization.WorkerCount !=
			fact.Challenge.WorkerCount ||
		fact.Authorization.MaxConcurrentBillableWorkers !=
			fact.Challenge.MaxConcurrentWorkers ||
		fact.Authorization.Currency != fact.Challenge.Currency ||
		fact.Authorization.HardBudgetMicros !=
			fact.Challenge.HardBudgetMicros ||
		fact.Challenge.PlanRevision > math.MaxInt64 ||
		fact.RecordRevision == 0 ||
		fact.RecordRevision > math.MaxInt64 {
		return nil, teamorchestration.ErrFactMismatch
	}
	signingPayload, err := fact.Challenge.SigningPayload()
	if err != nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	provider, err := teamProviderScopeToProto(
		fact.Challenge.ProviderScope,
	)
	if err != nil {
		return nil, err
	}
	quotedAt, err := checkedTeamTimestamp(fact.Challenge.QuotedAt)
	if err != nil {
		return nil, err
	}
	validUntil, err := checkedTeamTimestamp(
		fact.Challenge.QuoteValidUntil,
	)
	if err != nil {
		return nil, err
	}
	issuedAt, err := checkedTeamTimestamp(fact.Challenge.IssuedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := checkedTeamTimestamp(fact.Challenge.ExpiresAt)
	if err != nil {
		return nil, err
	}
	createdAt, err := checkedTeamTimestamp(fact.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := checkedTeamTimestamp(fact.UpdatedAt)
	if err != nil {
		return nil, err
	}
	var consumedAt *timestamppb.Timestamp
	if fact.ConsumedAt != nil {
		consumedAt, err = checkedTeamTimestamp(*fact.ConsumedAt)
		if err != nil {
			return nil, err
		}
	}
	return &agentv1.TeamApprovalChallengeV3{
		SchemaVersion:          fact.Challenge.SchemaVersion,
		ChallengeRevision:      int64(fact.Challenge.Revision),
		ApprovalId:             fact.Challenge.ApprovalID,
		ChallengeId:            fact.Challenge.ChallengeID,
		AgentInstanceId:        fact.Challenge.AgentInstanceID,
		OwnerId:                fact.Challenge.OwnerID,
		PlanId:                 fact.Challenge.PlanID,
		PlanRevision:           int64(fact.Challenge.PlanRevision),
		PlanDigest:             fact.Challenge.PlanDigest,
		GoalDigest:             fact.Challenge.GoalDigest,
		ProviderScope:          provider,
		RuntimeCatalogRevision: fact.Challenge.CatalogRevision,
		PolicyRevision:         fact.Challenge.PolicyRevision,
		PricingSnapshotId:      fact.Challenge.PricingSnapshotID,
		PricingSnapshotDigest:  fact.Challenge.PricingSnapshotDigest,
		QuotedAt:               quotedAt,
		QuoteValidUntil:        validUntil,
		WorkerCount:            fact.Challenge.WorkerCount,
		MaxConcurrentWorkers:   fact.Challenge.MaxConcurrentWorkers,
		Currency:               fact.Challenge.Currency,
		MinimumCostMicros:      fact.Challenge.MinimumCostMicros,
		ExpectedCostMicros:     fact.Challenge.ExpectedCostMicros,
		MaximumCostMicros:      fact.Challenge.MaximumCostMicros,
		HardBudgetMicros:       fact.Challenge.HardBudgetMicros,
		MinimumWallSeconds:     fact.Challenge.MinimumWallSeconds,
		ExpectedWallSeconds:    fact.Challenge.ExpectedWallSeconds,
		MaximumWallSeconds:     fact.Challenge.MaximumWallSeconds,
		SignerKeyId:            fact.Challenge.SignerKeyID,
		IssuedAt:               issuedAt,
		ExpiresAt:              expiresAt,
		SigningPayloadCbor:     signingPayload,
		RecordRevision:         int64(fact.RecordRevision),
		ConsumedAt:             consumedAt,
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
		LaunchAuthorizationId: fact.Challenge.
			LaunchAuthorizationID,
		LaunchAuthorizationDigest: fact.Challenge.
			LaunchAuthorizationDigest,
	}, nil
}

func teamLaunchAuthorizationToProto(
	value *teamlaunch.AuthorizationV1,
) (*agentv1.TeamLaunchAuthorizationV3, error) {
	if value == nil ||
		value.Validate() != nil ||
		value.PlanRevision > math.MaxInt64 {
		return nil, teamorchestration.ErrFactMismatch
	}
	provider, err := teamProviderScopeToProto(value.ProviderScope)
	if err != nil {
		return nil, err
	}
	notBefore, err := checkedTeamTimestamp(value.LaunchNotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := checkedTeamTimestamp(value.LaunchNotAfter)
	if err != nil {
		return nil, err
	}
	egress := make(
		[]*agentv1.TeamLaunchEgressRuleV3,
		0,
		len(value.Network.Egress),
	)
	for _, rule := range value.Network.Egress {
		egress = append(egress, &agentv1.TeamLaunchEgressRuleV3{
			Protocol: rule.Protocol,
			FromPort: uint32(rule.FromPort),
			ToPort:   uint32(rule.ToPort),
			CidrV4:   rule.CIDRv4,
		})
	}
	roles := make(
		[]*agentv1.TeamRoleLaunchAuthorizationV3,
		0,
		len(value.Roles),
	)
	for _, role := range value.Roles {
		architecture, err := teamArchitectureToProto(
			role.Architecture,
		)
		if err != nil {
			return nil, err
		}
		imageArchitecture, err := teamArchitectureToProto(
			role.WorkerImage.Architecture,
		)
		if err != nil {
			return nil, err
		}
		observedAt, err := checkedTeamTimestamp(
			role.WorkerImage.ObservedAt,
		)
		if err != nil {
			return nil, err
		}
		marketplace, err := teamMarketplaceBindingToProto(
			role.Marketplace,
		)
		if err != nil {
			return nil, err
		}
		roles = append(
			roles,
			&agentv1.TeamRoleLaunchAuthorizationV3{
				RoleId:                    role.RoleID,
				RuntimeReleaseId:          role.RuntimeReleaseID,
				RuntimeImageDigest:        role.RuntimeImageDigest,
				RuntimeInstallationDigest: role.RuntimeInstallationDigest,
				RuntimeExecutableDigest:   role.RuntimeExecutableDigest,
				ComputeOfferId:            role.ComputeOfferID,
				InstanceType:              role.InstanceType,
				Architecture:              architecture,
				Vcpu:                      role.VCPU,
				MemoryMib:                 role.MemoryMiB,
				PurchaseOption:            string(role.PurchaseOption),
				InstanceProfileName:       role.InstanceProfileName,
				EbsOptimized:              role.EBSOptimized,
				RequireImdsv2:             role.RequireIMDSv2,
				MetadataResponseHopLimit:  role.MetadataResponseHopLimit,
				ShutdownBehavior:          string(role.ShutdownBehavior),
				RootStorage: &agentv1.TeamLaunchRootStorageV3{
					DeviceName:          role.RootStorage.DeviceName,
					SizeGib:             role.RootStorage.SizeGiB,
					VolumeType:          role.RootStorage.VolumeType,
					Iops:                role.RootStorage.IOPS,
					ThroughputMibps:     role.RootStorage.ThroughputMiBPS,
					KmsKeyId:            role.RootStorage.KMSKeyID,
					Encrypted:           role.RootStorage.Encrypted,
					DeleteOnTermination: role.RootStorage.DeleteOnTermination,
				},
				WorkerImage: &agentv1.TeamLaunchWorkerImageV3{
					PublicationDigest:     role.WorkerImage.PublicationDigest,
					AgentInstanceId:       role.WorkerImage.AgentInstanceID,
					AccountId:             role.WorkerImage.AccountID,
					Region:                role.WorkerImage.Region,
					Architecture:          imageArchitecture,
					ImageId:               role.WorkerImage.ImageID,
					ImageDigest:           role.WorkerImage.ImageDigest,
					RootSnapshotId:        role.WorkerImage.RootSnapshotID,
					ReleaseManifestDigest: role.WorkerImage.ReleaseManifestDigest,
					WorkerRootfsDigest:    role.WorkerImage.WorkerRootFSDigest,
					WorkerBinaryDigest:    role.WorkerImage.WorkerBinaryDigest,
					ObservedAt:            observedAt,
				},
				MaximumApprovedCostMicros: role.MaximumApprovedCostMicros,
				Marketplace:               marketplace,
			},
		)
	}
	return &agentv1.TeamLaunchAuthorizationV3{
		SchemaVersion:   value.SchemaVersion,
		AuthorizationId: value.AuthorizationID,
		AgentInstanceId: value.AgentInstanceID,
		OwnerId:         value.OwnerID,
		PlanId:          value.PlanID,
		PlanRevision:    int64(value.PlanRevision),
		PlanDigest:      value.PlanDigest,
		ApprovalId:      value.ApprovalID,
		ProviderScope:   provider,
		Region:          value.Region,
		Network: &agentv1.TeamLaunchNetworkV3{
			ConnectivityMode:     string(value.Network.ConnectivityMode),
			VpcId:                value.Network.VPCID,
			SubnetId:             value.Network.SubnetID,
			AvailabilityZone:     value.Network.AvailabilityZone,
			SecurityGroupMode:    string(value.Network.SecurityGroupMode),
			PublicIpv4:           value.Network.PublicIPv4,
			PublicInbound:        value.Network.PublicInbound,
			ControlPlaneEndpoint: value.Network.ControlPlaneEndpoint,
			Egress:               egress,
		},
		Retention: &agentv1.TeamLaunchRetentionV3{
			RetentionClass: string(value.Retention.Class),
			AutoDestroy:    value.Retention.AutoDestroy,
			MaximumLifetimeSeconds: value.Retention.
				MaximumLifetimeSeconds,
			DestroyGraceSeconds: value.Retention.DestroyGraceSeconds,
		},
		WorkerCount:                  value.WorkerCount,
		MaxConcurrentBillableWorkers: value.MaxConcurrentBillableWorkers,
		Currency:                     value.Currency,
		HardBudgetMicros:             value.HardBudgetMicros,
		RequiresFreshQuote:           value.RequiresFreshQuote,
		MaximumQuoteAgeSeconds:       value.MaximumQuoteAgeSeconds,
		LaunchNotBefore:              notBefore,
		LaunchNotAfter:               notAfter,
		Roles:                        roles,
	}, nil
}

func teamApprovalFromProto(
	value *agentv1.TeamApprovalSignatureV3,
) (teamapproval.SignatureV1, error) {
	if value == nil ||
		value.GetSchemaVersion() !=
			teamapproval.SignatureSchemaV2 ||
		value.GetPlanRevision() < 1 ||
		len(value.GetSignature()) != 64 {
		return teamapproval.SignatureV1{}, invalidTeamRequest(
			"valid Team Plan device approval is required",
		)
	}
	signature := teamapproval.SignatureV1{
		SchemaVersion:             value.GetSchemaVersion(),
		ApprovalID:                value.GetApprovalId(),
		ChallengeID:               value.GetChallengeId(),
		PlanID:                    value.GetPlanId(),
		PlanRevision:              uint64(value.GetPlanRevision()),
		PlanDigest:                value.GetPlanDigest(),
		LaunchAuthorizationID:     value.GetLaunchAuthorizationId(),
		LaunchAuthorizationDigest: value.GetLaunchAuthorizationDigest(),
		SignerKeyID:               value.GetSignerKeyId(),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			append([]byte(nil), value.GetSignature()...),
		),
	}
	if signature.Validate() != nil {
		return teamapproval.SignatureV1{}, invalidTeamRequest(
			"valid Team Plan device approval is required",
		)
	}
	return signature, nil
}

func teamProviderScopeToProto(
	value teamplan.ProviderScope,
) (*agentv1.TeamProviderScopeV3, error) {
	if err := value.Validate(); err != nil ||
		value.ConnectionRevision > math.MaxInt64 {
		return nil, teamorchestration.ErrFactMismatch
	}
	provider, err := teamProviderToProto(value.Provider)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamProviderScopeV3{
		Provider:                provider,
		CloudConnectionId:       value.ConnectionID,
		CloudConnectionRevision: int64(value.ConnectionRevision),
		AccountId:               value.AccountID,
	}, nil
}

func checkedTeamTimestamp(
	value time.Time,
) (*timestamppb.Timestamp, error) {
	projected := timestamppb.New(value.UTC())
	if value.IsZero() || projected.CheckValid() != nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	return projected, nil
}

func teamProviderToProto(
	value teamplan.CloudProvider,
) (agentv1.TeamCloudProviderV3, error) {
	if value == teamplan.CloudProviderAWS {
		return agentv1.TeamCloudProviderV3_TEAM_CLOUD_PROVIDER_V3_AWS,
			nil
	}
	return agentv1.TeamCloudProviderV3_TEAM_CLOUD_PROVIDER_V3_UNSPECIFIED,
		teamorchestration.ErrFactMismatch
}

func teamPlanStatusToProto(
	value teamorchestration.PlanStatus,
) (agentv1.TeamPlanStatusV3, error) {
	switch value {
	case teamorchestration.PlanReadyForConfirmation:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_READY_FOR_CONFIRMATION, nil
	case teamorchestration.PlanApproved:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_APPROVED, nil
	case teamorchestration.PlanExpired:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_EXPIRED, nil
	case teamorchestration.PlanSuperseded:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_SUPERSEDED, nil
	case teamorchestration.PlanExecuting:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_EXECUTING, nil
	case teamorchestration.PlanCompleted:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_COMPLETED, nil
	case teamorchestration.PlanFailed:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_FAILED, nil
	case teamorchestration.PlanCanceled:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_CANCELED, nil
	default:
		return agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamRuntimeFamilyFromProto(
	value agentv1.TeamRuntimeFamilyV3,
) (teamplan.RuntimeFamily, error) {
	switch value {
	case agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_CLAUDE_CODE:
		return teamplan.RuntimeClaudeCode, nil
	case agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_CODEX:
		return teamplan.RuntimeCodex, nil
	case agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_OPENCLAW:
		return teamplan.RuntimeOpenClaw, nil
	case agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_HERMES:
		return teamplan.RuntimeHermes, nil
	case agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_OPENCODE:
		return teamplan.RuntimeOpenCode, nil
	case agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_PI:
		return teamplan.RuntimePi, nil
	default:
		return "", invalidTeamRequest("unknown preferred runtime family")
	}
}

func teamRuntimeFamilyToProto(
	value teamplan.RuntimeFamily,
) (agentv1.TeamRuntimeFamilyV3, error) {
	switch value {
	case teamplan.RuntimeClaudeCode:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_CLAUDE_CODE, nil
	case teamplan.RuntimeCodex:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_CODEX, nil
	case teamplan.RuntimeOpenClaw:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_OPENCLAW, nil
	case teamplan.RuntimeHermes:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_HERMES, nil
	case teamplan.RuntimeOpenCode:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_OPENCODE, nil
	case teamplan.RuntimePi:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_PI, nil
	default:
		return agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamRuntimeAdapterToProto(
	value teamplan.RuntimeAdapter,
) (agentv1.TeamRuntimeAdapterV3, error) {
	switch value {
	case teamplan.AdapterClaudeCodeV1:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_CLAUDE_CODE_TASK_V1, nil
	case teamplan.AdapterCodexV1:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_CODEX_EXEC_TASK_V1, nil
	case teamplan.AdapterOpenClawV1:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_OPENCLAW_GATEWAY_TASK_V1, nil
	case teamplan.AdapterHermesV1:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_HERMES_API_TASK_V1, nil
	case teamplan.AdapterOpenCodeV1:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_OPENCODE_SERVER_TASK_V1, nil
	case teamplan.AdapterPiV1:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_PI_JSON_TASK_V1, nil
	default:
		return agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamWorkClassFromProto(
	value agentv1.TeamWorkClassV3,
) (teamplan.WorkClass, error) {
	switch value {
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_IMPLEMENTATION:
		return teamplan.WorkSoftwareImplementation, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_REVIEW:
		return teamplan.WorkSoftwareReview, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_TEST:
		return teamplan.WorkSoftwareTest, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_RESEARCH:
		return teamplan.WorkResearch, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_BROWSER_AUTOMATION:
		return teamplan.WorkBrowserAutomation, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_COMMUNICATION_AUTOMATION:
		return teamplan.WorkCommunication, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_GENERAL_TOOL:
		return teamplan.WorkGeneralTool, nil
	case agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_LONG_RUNNING_OPERATIONS:
		return teamplan.WorkLongRunningOperations, nil
	default:
		return "", invalidTeamRequest("unknown work class")
	}
}

func teamWorkClassToProto(
	value teamplan.WorkClass,
) (agentv1.TeamWorkClassV3, error) {
	switch value {
	case teamplan.WorkSoftwareImplementation:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_IMPLEMENTATION, nil
	case teamplan.WorkSoftwareReview:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_REVIEW, nil
	case teamplan.WorkSoftwareTest:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_TEST, nil
	case teamplan.WorkResearch:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_RESEARCH, nil
	case teamplan.WorkBrowserAutomation:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_BROWSER_AUTOMATION, nil
	case teamplan.WorkCommunication:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_COMMUNICATION_AUTOMATION, nil
	case teamplan.WorkGeneralTool:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_GENERAL_TOOL, nil
	case teamplan.WorkLongRunningOperations:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_LONG_RUNNING_OPERATIONS, nil
	default:
		return agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamWorkspaceFromProto(
	value agentv1.TeamWorkspaceModeV3,
) (teamplan.WorkspaceMode, error) {
	switch value {
	case agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_READ_ONLY:
		return teamplan.WorkspaceReadOnly, nil
	case agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_ISOLATED:
		return teamplan.WorkspaceIsolated, nil
	case agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_EXCLUSIVE:
		return teamplan.WorkspaceExclusive, nil
	default:
		return "", invalidTeamRequest("unknown workspace mode")
	}
}

func teamWorkspaceToProto(
	value teamplan.WorkspaceMode,
) (agentv1.TeamWorkspaceModeV3, error) {
	switch value {
	case teamplan.WorkspaceReadOnly:
		return agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_READ_ONLY, nil
	case teamplan.WorkspaceIsolated:
		return agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_ISOLATED, nil
	case teamplan.WorkspaceExclusive:
		return agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_EXCLUSIVE, nil
	default:
		return agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamCapabilityFromProto(
	value agentv1.TeamCapabilityV3,
) (teamplan.Capability, error) {
	switch value {
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_REPOSITORY_READ:
		return teamplan.CapabilityRepositoryRead, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_REPOSITORY_WRITE:
		return teamplan.CapabilityRepositoryWrite, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_CODE_REVIEW:
		return teamplan.CapabilityCodeReview, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_SHELL:
		return teamplan.CapabilityShell, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_GIT:
		return teamplan.CapabilityGit, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_TEST:
		return teamplan.CapabilityTest, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_WEB_RESEARCH:
		return teamplan.CapabilityWebResearch, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_BROWSER:
		return teamplan.CapabilityBrowser, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_MCP_CLIENT:
		return teamplan.CapabilityMCPClient, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_ACP:
		return teamplan.CapabilityACP, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_LONG_MEMORY:
		return teamplan.CapabilityLongMemory, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_SUBAGENTS:
		return teamplan.CapabilitySubagents, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_MESSAGING:
		return teamplan.CapabilityMessaging, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_DOCUMENT:
		return teamplan.CapabilityDocument, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_DATA_ANALYSIS:
		return teamplan.CapabilityDataAnalysis, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_LONG_RUNNING:
		return teamplan.CapabilityLongRunning, nil
	case agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_STRUCTURED_RESULTS:
		return teamplan.CapabilityStructuredResults, nil
	default:
		return "", invalidTeamRequest("unknown required capability")
	}
}

func teamCapabilityToProto(
	value teamplan.Capability,
) (agentv1.TeamCapabilityV3, error) {
	switch value {
	case teamplan.CapabilityRepositoryRead:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_REPOSITORY_READ, nil
	case teamplan.CapabilityRepositoryWrite:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_REPOSITORY_WRITE, nil
	case teamplan.CapabilityCodeReview:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_CODE_REVIEW, nil
	case teamplan.CapabilityShell:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_SHELL, nil
	case teamplan.CapabilityGit:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_GIT, nil
	case teamplan.CapabilityTest:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_TEST, nil
	case teamplan.CapabilityWebResearch:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_WEB_RESEARCH, nil
	case teamplan.CapabilityBrowser:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_BROWSER, nil
	case teamplan.CapabilityMCPClient:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_MCP_CLIENT, nil
	case teamplan.CapabilityACP:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_ACP, nil
	case teamplan.CapabilityLongMemory:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_LONG_MEMORY, nil
	case teamplan.CapabilitySubagents:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_SUBAGENTS, nil
	case teamplan.CapabilityMessaging:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_MESSAGING, nil
	case teamplan.CapabilityDocument:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_DOCUMENT, nil
	case teamplan.CapabilityDataAnalysis:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_DATA_ANALYSIS, nil
	case teamplan.CapabilityLongRunning:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_LONG_RUNNING, nil
	case teamplan.CapabilityStructuredResults:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_STRUCTURED_RESULTS, nil
	default:
		return agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamModelInterfaceToProto(
	value teamplan.ModelInterface,
) (agentv1.TeamModelInterfaceV3, error) {
	switch value {
	case teamplan.ModelAnthropicAPI:
		return agentv1.TeamModelInterfaceV3_TEAM_MODEL_INTERFACE_V3_ANTHROPIC_API, nil
	case teamplan.ModelOpenAIResponses:
		return agentv1.TeamModelInterfaceV3_TEAM_MODEL_INTERFACE_V3_OPENAI_RESPONSES, nil
	case teamplan.ModelOpenAICompatible:
		return agentv1.TeamModelInterfaceV3_TEAM_MODEL_INTERFACE_V3_OPENAI_COMPATIBLE, nil
	default:
		return agentv1.TeamModelInterfaceV3_TEAM_MODEL_INTERFACE_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func teamQualityFromProto(
	value agentv1.TeamQualityTierV3,
) (teamplan.QualityTier, error) {
	switch value {
	case agentv1.TeamQualityTierV3_TEAM_QUALITY_TIER_V3_ECONOMY:
		return teamplan.QualityEconomy, nil
	case agentv1.TeamQualityTierV3_TEAM_QUALITY_TIER_V3_BALANCED:
		return teamplan.QualityBalanced, nil
	case agentv1.TeamQualityTierV3_TEAM_QUALITY_TIER_V3_PREMIUM:
		return teamplan.QualityPremium, nil
	default:
		return "", invalidTeamRequest("unknown minimum model quality")
	}
}

func teamArchitectureToProto(
	value recipe.Architecture,
) (agentv1.TeamArchitectureV3, error) {
	switch value {
	case recipe.ArchitectureAMD64:
		return agentv1.TeamArchitectureV3_TEAM_ARCHITECTURE_V3_AMD64, nil
	case recipe.ArchitectureARM64:
		return agentv1.TeamArchitectureV3_TEAM_ARCHITECTURE_V3_ARM64, nil
	default:
		return agentv1.TeamArchitectureV3_TEAM_ARCHITECTURE_V3_UNSPECIFIED,
			teamorchestration.ErrFactMismatch
	}
}

func invalidTeamRequest(message string) error {
	return status.Error(codes.InvalidArgument, message)
}
