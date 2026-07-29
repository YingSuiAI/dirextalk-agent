package teamexecution

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

var (
	executionDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	credentialSlotPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	currencyPattern        = regexp.MustCompile(`^[A-Z]{3}$`)
	roleIDPattern          = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

func Materialize(
	authorization teamorchestration.ApprovedPlanFact,
) (ExecutionV1, error) {
	planFact := authorization.Plan
	plan := planFact.Plan
	approval := authorization.Approval
	if err := validateAuthorization(authorization, true); err != nil {
		return ExecutionV1{}, err
	}
	planID, _ := uuid.Parse(plan.PlanID)
	executionID := uuid.NewSHA1(
		planID,
		[]byte(fmt.Sprintf(
			"team-execution:%d:%s",
			plan.Revision,
			approval.Signature.ApprovalID,
		)),
	)
	roles := make([]RoleV1, 0, len(plan.Assignments))
	for _, assignment := range plan.Assignments {
		declarationID := uuid.NewSHA1(
			executionID,
			[]byte("step-declaration:"+assignment.RoleID),
		).String()
		stepID, err := task.MaterializeStepID(
			planFact.TaskID,
			declarationID,
		)
		if err != nil {
			return ExecutionV1{}, ErrInvalid
		}
		deploymentID, expectedWorkerID, err :=
			deterministicWorkerIdentity(executionID, assignment.RoleID)
		if err != nil {
			return ExecutionV1{}, ErrInvalid
		}
		roles = append(roles, RoleV1{
			RoleID: assignment.RoleID, Title: assignment.Title,
			Objective: assignment.Objective, WorkClass: assignment.WorkClass,
			RequiredCapabilities: append(
				[]teamplan.Capability(nil),
				assignment.RequiredCapabilities...,
			),
			Workspace:          assignment.Workspace,
			DependsOnRoleIDs:   append([]string(nil), assignment.DependsOnRoleIDs...),
			StepDeclarationID:  declarationID,
			TaskStepID:         stepID,
			DeploymentID:       deploymentID,
			ExpectedWorkerID:   expectedWorkerID,
			RuntimeReleaseID:   assignment.RuntimeReleaseID,
			RuntimeFamily:      assignment.RuntimeFamily,
			RuntimeVersion:     assignment.RuntimeVersion,
			RuntimeImageDigest: assignment.RuntimeImageDigest,
			RuntimeAdapter:     assignment.RuntimeAdapter,
			ModelProfileID:     assignment.ModelProfileID,
			ModelProvider:      assignment.ModelProvider,
			Model:              assignment.Model,
			ModelInterface:     assignment.ModelInterface,
			ModelCredentialSlot: credentialSlot(
				executionID.String(),
				assignment.RoleID,
			),
			ComputeOfferID: assignment.ComputeOfferID,
			InstanceType:   assignment.InstanceType,
			Resources:      assignment.Resources,
			Duration:       durationEstimate(assignment.Duration),
			Tokens:         assignment.Tokens,
			ColdStartSeconds: uint64(
				assignment.ColdStart / time.Second,
			),
		})
	}
	execution := ExecutionV1{
		SchemaVersion:         SchemaV1,
		ExecutionID:           executionID.String(),
		OwnerID:               plan.OwnerID,
		TaskID:                planFact.TaskID,
		PlanID:                plan.PlanID,
		PlanRevision:          plan.Revision,
		PlanDigest:            planFact.PlanDigest,
		ApprovalID:            approval.Signature.ApprovalID,
		ApprovalSignerKeyID:   approval.Signature.SignerKeyID,
		GoalDigest:            plan.GoalDigest,
		ProviderScope:         plan.ProviderScope,
		Region:                plan.Region,
		CatalogRevision:       plan.CatalogRevision,
		PolicyRevision:        plan.PolicyRevision,
		PricingSnapshotID:     plan.PricingSnapshotID,
		PricingSnapshotDigest: plan.PricingSnapshotDigest,
		WorkerCount:           plan.WorkerCount,
		MaxConcurrentWorkers:  plan.MaxConcurrentWorkers,
		Currency:              plan.Cost.Currency,
		MinimumCostMicros:     plan.Cost.MinimumMicros,
		ExpectedCostMicros:    plan.Cost.ExpectedMicros,
		MaximumCostMicros:     plan.Cost.MaximumMicros,
		HardBudgetMicros:      plan.Cost.HardBudgetMicros,
		Schedule: ScheduleEstimateV1{
			MinimumWallSeconds: uint64(
				plan.Schedule.MinimumWallTime / time.Second,
			),
			ExpectedWallSeconds: uint64(
				plan.Schedule.ExpectedWallTime / time.Second,
			),
			MaximumWallSeconds: uint64(
				plan.Schedule.MaximumWallTime / time.Second,
			),
		},
		AuthorizedAt: approval.ApprovedAt.UTC(),
		Roles:        roles,
	}
	if err := execution.ValidateAgainst(authorization); err != nil {
		return ExecutionV1{}, err
	}
	return execution, nil
}

func (execution ExecutionV1) CanonicalCBOR() ([]byte, error) {
	if err := execution.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(execution)
}

func (execution ExecutionV1) Digest() (string, error) {
	if err := execution.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(execution)
}

func (role RoleV1) CanonicalCBOR() ([]byte, error) {
	if err := validateRole(role); err != nil {
		return nil, err
	}
	return canonical.Marshal(role)
}

func (role RoleV1) Digest() (string, error) {
	if err := validateRole(role); err != nil {
		return "", err
	}
	return canonical.Digest(role)
}

func (execution ExecutionV1) Validate() error {
	if execution.SchemaVersion != SchemaV1 ||
		!canonicalUUID(execution.ExecutionID) ||
		!validText(execution.OwnerID, 255) ||
		!canonicalUUID(execution.TaskID) ||
		!canonicalUUID(execution.PlanID) ||
		execution.PlanRevision == 0 ||
		execution.PlanRevision > uint64(math.MaxInt64) ||
		!executionDigestPattern.MatchString(execution.PlanDigest) ||
		!canonicalUUID(execution.ApprovalID) ||
		!validText(execution.ApprovalSignerKeyID, 128) ||
		!executionDigestPattern.MatchString(execution.GoalDigest) ||
		execution.ProviderScope.Validate() != nil ||
		!validText(execution.Region, 64) ||
		!executionDigestPattern.MatchString(execution.CatalogRevision) ||
		!executionDigestPattern.MatchString(execution.PolicyRevision) ||
		!canonicalUUID(execution.PricingSnapshotID) ||
		!executionDigestPattern.MatchString(execution.PricingSnapshotDigest) ||
		execution.WorkerCount == 0 ||
		execution.WorkerCount != uint32(len(execution.Roles)) ||
		execution.WorkerCount > 8 ||
		execution.MaxConcurrentWorkers == 0 ||
		execution.MaxConcurrentWorkers > execution.WorkerCount ||
		!currencyPattern.MatchString(execution.Currency) ||
		execution.MinimumCostMicros > execution.ExpectedCostMicros ||
		execution.ExpectedCostMicros > execution.MaximumCostMicros ||
		execution.HardBudgetMicros < execution.MaximumCostMicros ||
		execution.HardBudgetMicros == 0 ||
		execution.Schedule.MinimumWallSeconds == 0 ||
		execution.Schedule.MinimumWallSeconds >
			execution.Schedule.ExpectedWallSeconds ||
		execution.Schedule.ExpectedWallSeconds >
			execution.Schedule.MaximumWallSeconds ||
		!utcTimestamp(execution.AuthorizedAt) ||
		!slices.IsSortedFunc(
			execution.Roles,
			func(left, right RoleV1) int {
				return strings.Compare(left.RoleID, right.RoleID)
			},
		) {
		return ErrInvalid
	}
	roleIDs := make(map[string]struct{}, len(execution.Roles))
	declarationIDs := make(map[string]struct{}, len(execution.Roles))
	stepIDs := make(map[string]struct{}, len(execution.Roles))
	deploymentIDs := make(map[string]struct{}, len(execution.Roles))
	workerIDs := make(map[string]struct{}, len(execution.Roles))
	for _, role := range execution.Roles {
		if err := validateRole(role); err != nil ||
			duplicate(roleIDs, role.RoleID) ||
			duplicate(declarationIDs, role.StepDeclarationID) ||
			duplicate(stepIDs, role.TaskStepID) ||
			duplicate(deploymentIDs, role.DeploymentID) ||
			duplicate(workerIDs, role.ExpectedWorkerID) {
			return ErrInvalid
		}
		expectedStepID, err := task.MaterializeStepID(
			execution.TaskID,
			role.StepDeclarationID,
		)
		if err != nil || expectedStepID != role.TaskStepID {
			return ErrInvalid
		}
	}
	for _, role := range execution.Roles {
		for _, dependency := range role.DependsOnRoleIDs {
			if dependency == role.RoleID {
				return ErrInvalid
			}
			if _, found := roleIDs[dependency]; !found {
				return ErrInvalid
			}
		}
	}
	if hasRoleCycle(execution.Roles) {
		return ErrInvalid
	}
	return nil
}

func (execution ExecutionV1) ValidateAgainst(
	authorization teamorchestration.ApprovedPlanFact,
) error {
	if err := execution.Validate(); err != nil ||
		validateAuthorization(authorization, false) != nil {
		return ErrInvalid
	}
	planFact := authorization.Plan
	plan := planFact.Plan
	approval := authorization.Approval
	if execution.OwnerID != plan.OwnerID ||
		execution.TaskID != planFact.TaskID ||
		execution.PlanID != plan.PlanID ||
		execution.PlanRevision != plan.Revision ||
		execution.PlanDigest != planFact.PlanDigest ||
		execution.ApprovalID != approval.Signature.ApprovalID ||
		execution.ApprovalSignerKeyID != approval.Signature.SignerKeyID ||
		execution.GoalDigest != plan.GoalDigest ||
		execution.ProviderScope != plan.ProviderScope ||
		execution.Region != plan.Region ||
		execution.CatalogRevision != plan.CatalogRevision ||
		execution.PolicyRevision != plan.PolicyRevision ||
		execution.PricingSnapshotID != plan.PricingSnapshotID ||
		execution.PricingSnapshotDigest != plan.PricingSnapshotDigest ||
		execution.WorkerCount != plan.WorkerCount ||
		execution.MaxConcurrentWorkers != plan.MaxConcurrentWorkers ||
		execution.Currency != plan.Cost.Currency ||
		execution.MinimumCostMicros != plan.Cost.MinimumMicros ||
		execution.ExpectedCostMicros != plan.Cost.ExpectedMicros ||
		execution.MaximumCostMicros != plan.Cost.MaximumMicros ||
		execution.HardBudgetMicros != plan.Cost.HardBudgetMicros ||
		execution.Schedule.MinimumWallSeconds !=
			uint64(plan.Schedule.MinimumWallTime/time.Second) ||
		execution.Schedule.ExpectedWallSeconds !=
			uint64(plan.Schedule.ExpectedWallTime/time.Second) ||
		execution.Schedule.MaximumWallSeconds !=
			uint64(plan.Schedule.MaximumWallTime/time.Second) ||
		!execution.AuthorizedAt.Equal(approval.ApprovedAt.UTC()) ||
		len(execution.Roles) != len(plan.Assignments) {
		return ErrFactMismatch
	}
	for index, assignment := range plan.Assignments {
		role := execution.Roles[index]
		if !roleMatchesAssignment(role, assignment) {
			return ErrFactMismatch
		}
		expected, err := deterministicRole(
			execution.ExecutionID,
			execution.TaskID,
			assignment,
		)
		if err != nil ||
			role.StepDeclarationID != expected.StepDeclarationID ||
			role.TaskStepID != expected.TaskStepID ||
			role.DeploymentID != expected.DeploymentID ||
			role.ExpectedWorkerID != expected.ExpectedWorkerID ||
			role.ModelCredentialSlot != expected.ModelCredentialSlot {
			return ErrFactMismatch
		}
	}
	expectedExecutionID := uuid.NewSHA1(
		uuid.MustParse(plan.PlanID),
		[]byte(fmt.Sprintf(
			"team-execution:%d:%s",
			plan.Revision,
			approval.Signature.ApprovalID,
		)),
	).String()
	if execution.ExecutionID != expectedExecutionID {
		return ErrFactMismatch
	}
	return nil
}

func validateAuthorization(
	authorization teamorchestration.ApprovedPlanFact,
	requireApproved bool,
) error {
	planFact := authorization.Plan
	approval := authorization.Approval
	plan := planFact.Plan
	digest, err := plan.Digest()
	if err != nil ||
		!validAuthorizedPlanStatus(planFact.Status, requireApproved) ||
		!canonicalUUID(planFact.TaskID) ||
		planFact.PlanDigest != digest ||
		planFact.RecordRevision == 0 ||
		approval.Signature.Validate() != nil ||
		approval.Signature.PlanID != plan.PlanID ||
		approval.Signature.PlanRevision != plan.Revision ||
		approval.Signature.PlanDigest != digest ||
		approval.ApprovedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func validAuthorizedPlanStatus(
	status teamorchestration.PlanStatus,
	requireApproved bool,
) bool {
	if requireApproved {
		return status == teamorchestration.PlanApproved
	}
	switch status {
	case teamorchestration.PlanApproved,
		teamorchestration.PlanExecuting,
		teamorchestration.PlanCompleted,
		teamorchestration.PlanFailed,
		teamorchestration.PlanCanceled:
		return true
	default:
		return false
	}
}

func deterministicRole(
	executionID,
	taskID string,
	assignment teamplan.WorkerAssignment,
) (RoleV1, error) {
	parsedExecution, err := uuid.Parse(executionID)
	if err != nil || parsedExecution == uuid.Nil {
		return RoleV1{}, ErrInvalid
	}
	deploymentID, expectedWorkerID, err :=
		deterministicWorkerIdentity(parsedExecution, assignment.RoleID)
	if err != nil {
		return RoleV1{}, ErrInvalid
	}
	declarationID := uuid.NewSHA1(
		parsedExecution,
		[]byte("step-declaration:"+assignment.RoleID),
	).String()
	stepID, err := task.MaterializeStepID(taskID, declarationID)
	if err != nil {
		return RoleV1{}, ErrInvalid
	}
	return RoleV1{
		StepDeclarationID:   declarationID,
		TaskStepID:          stepID,
		DeploymentID:        deploymentID,
		ExpectedWorkerID:    expectedWorkerID,
		ModelCredentialSlot: credentialSlot(executionID, assignment.RoleID),
	}, nil
}

func deterministicWorkerIdentity(
	executionID uuid.UUID,
	roleID string,
) (string, string, error) {
	if executionID == uuid.Nil || !roleIDPattern.MatchString(roleID) {
		return "", "", ErrInvalid
	}
	deploymentID := uuid.NewSHA1(
		executionID,
		[]byte("deployment:"+roleID),
	).String()
	workerID, err := workeridentity.DeriveWorkerID(deploymentID)
	if err != nil {
		return "", "", ErrInvalid
	}
	return deploymentID, workerID, nil
}

func roleMatchesAssignment(
	role RoleV1,
	assignment teamplan.WorkerAssignment,
) bool {
	return role.RoleID == assignment.RoleID &&
		role.Title == assignment.Title &&
		role.Objective == assignment.Objective &&
		role.WorkClass == assignment.WorkClass &&
		slices.Equal(
			role.RequiredCapabilities,
			assignment.RequiredCapabilities,
		) &&
		role.Workspace == assignment.Workspace &&
		slices.Equal(role.DependsOnRoleIDs, assignment.DependsOnRoleIDs) &&
		role.RuntimeReleaseID == assignment.RuntimeReleaseID &&
		role.RuntimeFamily == assignment.RuntimeFamily &&
		role.RuntimeVersion == assignment.RuntimeVersion &&
		role.RuntimeImageDigest == assignment.RuntimeImageDigest &&
		role.RuntimeAdapter == assignment.RuntimeAdapter &&
		role.ModelProfileID == assignment.ModelProfileID &&
		role.ModelProvider == assignment.ModelProvider &&
		role.Model == assignment.Model &&
		role.ModelInterface == assignment.ModelInterface &&
		role.ComputeOfferID == assignment.ComputeOfferID &&
		role.InstanceType == assignment.InstanceType &&
		role.Resources == assignment.Resources &&
		role.Duration == durationEstimate(assignment.Duration) &&
		role.Tokens == assignment.Tokens &&
		role.ColdStartSeconds ==
			uint64(assignment.ColdStart/time.Second)
}

func validateRole(role RoleV1) error {
	if !roleIDPattern.MatchString(role.RoleID) ||
		!validSafeText(role.Title, 160) ||
		!validSafeText(role.Objective, 8192) ||
		!validWorkClass(role.WorkClass) ||
		len(role.RequiredCapabilities) == 0 ||
		!uniqueCapabilities(role.RequiredCapabilities) ||
		!slices.IsSorted(role.RequiredCapabilities) ||
		!validWorkspace(role.Workspace) ||
		!uniqueRoleIDs(role.DependsOnRoleIDs) ||
		!slices.IsSorted(role.DependsOnRoleIDs) ||
		!canonicalUUID(role.StepDeclarationID) ||
		!canonicalUUID(role.TaskStepID) ||
		!canonicalUUID(role.DeploymentID) ||
		!canonicalUUID(role.ExpectedWorkerID) ||
		!canonicalUUID(role.RuntimeReleaseID) ||
		!validRuntime(role.RuntimeFamily, role.RuntimeAdapter) ||
		!executionDigestPattern.MatchString(role.RuntimeImageDigest) ||
		!validText(role.RuntimeVersion, 128) ||
		!validText(role.ModelProfileID, 160) ||
		!validText(role.ModelProvider, 128) ||
		!validText(role.Model, 256) ||
		!validModelInterface(role.ModelInterface) ||
		!credentialSlotPattern.MatchString(role.ModelCredentialSlot) ||
		security.ContainsLikelySecret(role.ModelCredentialSlot) ||
		!canonicalUUID(role.ComputeOfferID) ||
		!validText(role.InstanceType, 64) ||
		role.Resources.VCPU == 0 ||
		role.Resources.MemoryMiB == 0 ||
		role.Resources.DiskGiB == 0 ||
		!recipe.ValidArchitecture(role.Resources.Arch) ||
		role.Duration.MinimumSeconds == 0 ||
		role.Duration.MinimumSeconds > role.Duration.ExpectedSeconds ||
		role.Duration.ExpectedSeconds > role.Duration.MaximumSeconds ||
		role.Duration.MaximumSeconds > 7*24*60*60 ||
		role.Tokens.InputMinimum == 0 ||
		role.Tokens.InputMinimum > role.Tokens.InputExpected ||
		role.Tokens.InputExpected > role.Tokens.InputMaximum ||
		role.Tokens.InputMaximum > 100_000_000 ||
		role.Tokens.OutputMinimum == 0 ||
		role.Tokens.OutputMinimum > role.Tokens.OutputExpected ||
		role.Tokens.OutputExpected > role.Tokens.OutputMaximum ||
		role.Tokens.OutputMaximum > 100_000_000 ||
		role.ColdStartSeconds > 30*60 ||
		slices.Contains(
			role.RequiredCapabilities,
			teamplan.CapabilityRepositoryWrite,
		) && role.Workspace == teamplan.WorkspaceReadOnly {
		return ErrInvalid
	}
	return nil
}

func validWorkClass(value teamplan.WorkClass) bool {
	switch value {
	case teamplan.WorkSoftwareImplementation,
		teamplan.WorkSoftwareReview,
		teamplan.WorkSoftwareTest,
		teamplan.WorkResearch,
		teamplan.WorkBrowserAutomation,
		teamplan.WorkCommunication,
		teamplan.WorkGeneralTool,
		teamplan.WorkLongRunningOperations:
		return true
	default:
		return false
	}
}

func validCapability(value teamplan.Capability) bool {
	switch value {
	case teamplan.CapabilityRepositoryRead,
		teamplan.CapabilityRepositoryWrite,
		teamplan.CapabilityCodeReview,
		teamplan.CapabilityShell,
		teamplan.CapabilityGit,
		teamplan.CapabilityTest,
		teamplan.CapabilityWebResearch,
		teamplan.CapabilityBrowser,
		teamplan.CapabilityMCPClient,
		teamplan.CapabilityACP,
		teamplan.CapabilityLongMemory,
		teamplan.CapabilitySubagents,
		teamplan.CapabilityMessaging,
		teamplan.CapabilityDocument,
		teamplan.CapabilityDataAnalysis,
		teamplan.CapabilityLongRunning,
		teamplan.CapabilityStructuredResults:
		return true
	default:
		return false
	}
}

func uniqueCapabilities(values []teamplan.Capability) bool {
	seen := make(map[teamplan.Capability]struct{}, len(values))
	for _, value := range values {
		if !validCapability(value) {
			return false
		}
		if _, found := seen[value]; found {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validWorkspace(value teamplan.WorkspaceMode) bool {
	return value == teamplan.WorkspaceReadOnly ||
		value == teamplan.WorkspaceIsolated ||
		value == teamplan.WorkspaceExclusive
}

func uniqueRoleIDs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !roleIDPattern.MatchString(value) {
			return false
		}
		if _, found := seen[value]; found {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validRuntime(
	family teamplan.RuntimeFamily,
	adapter teamplan.RuntimeAdapter,
) bool {
	switch family {
	case teamplan.RuntimeClaudeCode:
		return adapter == teamplan.AdapterClaudeCodeV1
	case teamplan.RuntimeCodex:
		return adapter == teamplan.AdapterCodexV1
	case teamplan.RuntimeOpenClaw:
		return adapter == teamplan.AdapterOpenClawV1
	case teamplan.RuntimeHermes:
		return adapter == teamplan.AdapterHermesV1
	case teamplan.RuntimeOpenCode:
		return adapter == teamplan.AdapterOpenCodeV1
	default:
		return false
	}
}

func validModelInterface(value teamplan.ModelInterface) bool {
	return value == teamplan.ModelAnthropicAPI ||
		value == teamplan.ModelOpenAIResponses ||
		value == teamplan.ModelOpenAICompatible
}

func hasRoleCycle(roles []RoleV1) bool {
	dependencies := make(map[string][]string, len(roles))
	for _, role := range roles {
		dependencies[role.RoleID] = role.DependsOnRoleIDs
	}
	state := make(map[string]uint8, len(roles))
	var visit func(string) bool
	visit = func(roleID string) bool {
		switch state[roleID] {
		case 1:
			return true
		case 2:
			return false
		}
		state[roleID] = 1
		for _, dependency := range dependencies[roleID] {
			if visit(dependency) {
				return true
			}
		}
		state[roleID] = 2
		return false
	}
	for roleID := range dependencies {
		if visit(roleID) {
			return true
		}
	}
	return false
}

func durationEstimate(value teamplan.DurationEstimate) DurationEstimateV1 {
	return DurationEstimateV1{
		MinimumSeconds:  uint64(value.Minimum / time.Second),
		ExpectedSeconds: uint64(value.Expected / time.Second),
		MaximumSeconds:  uint64(value.Maximum / time.Second),
	}
}

func credentialSlot(executionID, roleID string) string {
	digest := sha256.Sum256([]byte(executionID + "\x00" + roleID))
	return "model-" + hex.EncodeToString(digest[:8])
}

func duplicate(values map[string]struct{}, value string) bool {
	if _, found := values[value]; found {
		return true
	}
	values[value] = struct{}{}
	return false
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validText(value string, maximum int) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > maximum ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validSafeText(value string, maximum int) bool {
	return validText(value, maximum) &&
		!security.ContainsLikelySecret(value)
}

func utcTimestamp(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}
