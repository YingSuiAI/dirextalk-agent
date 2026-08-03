// Package teamdispatch schedules approved Team Execution roles without
// accepting provider, runtime, model, or Worker identity overrides.
package teamdispatch

import (
	"context"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/google/uuid"
)

const SchemaV1 = "dirextalk.agent.team-role-dispatch/v1"

var (
	ErrInvalid          = errors.New("invalid Team role dispatch")
	ErrFactMismatch     = errors.New("Team role dispatch fact mismatch")
	ErrNotReady         = errors.New("Team role dispatch is not ready")
	ErrNotFound         = errors.New("Team role dispatch was not found")
	ErrRevisionConflict = errors.New("Team role dispatch revision conflict")
	ErrConcurrencyLimit = errors.New("Team role dispatch concurrency limit reached")

	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	roleIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	credentialRefPattern = regexp.MustCompile(
		`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`,
	)
)

type Phase string

const (
	PhaseIntent           Phase = "intent"
	PhaseInputReady       Phase = "input_ready"
	PhaseArtifactsReady   Phase = "artifacts_ready"
	PhaseWorkerRegistered Phase = "worker_registered"
	PhaseBootstrapReady   Phase = "bootstrap_ready"
	PhaseProvisioning     Phase = "provisioning"
	PhaseActive           Phase = "active"
	PhaseResultReady      Phase = "result_ready"
	PhaseDestroying       Phase = "destroying"
	PhaseCompleted        Phase = "completed"
)

// AuthorizedExecution is reconstructed from PostgreSQL. The complete signed
// approval remains the authority; an Execution row alone cannot launch AWS
// resources.
type AuthorizedExecution struct {
	Approval  teamorchestration.ApprovedPlanFact
	Execution teamexecution.Fact
}

func (value AuthorizedExecution) Validate() error {
	if value.validateFacts() != nil {
		return ErrFactMismatch
	}
	switch value.Execution.Status {
	case teamexecution.StatusDispatching,
		teamexecution.StatusRunning:
		return nil
	default:
		return ErrNotReady
	}
}

func (value AuthorizedExecution) ValidateForCleanup() error {
	if value.validateFacts() != nil {
		return ErrFactMismatch
	}
	switch value.Execution.Status {
	case teamexecution.StatusDispatching,
		teamexecution.StatusRunning,
		teamexecution.StatusVerifying,
		teamexecution.StatusCompleted,
		teamexecution.StatusFailed,
		teamexecution.StatusCanceled:
		return nil
	default:
		return ErrNotReady
	}
}

func (value AuthorizedExecution) validateFacts() error {
	if value.Execution.Execution.ValidateAgainst(value.Approval) != nil ||
		value.Execution.ExecutionDigest == "" ||
		value.Execution.RecordRevision == 0 ||
		value.Execution.CreatedAt.IsZero() ||
		value.Execution.UpdatedAt.IsZero() ||
		value.Execution.UpdatedAt.Before(value.Execution.CreatedAt) ||
		value.Approval.Approval.Authorization == nil {
		return ErrFactMismatch
	}
	digest, err := value.Execution.Execution.Digest()
	if err != nil || digest != value.Execution.ExecutionDigest {
		return ErrFactMismatch
	}
	return nil
}

func (value AuthorizedExecution) ValidateForLaunch(now time.Time) error {
	if value.Validate() != nil || now.IsZero() {
		return ErrNotReady
	}
	if value.Approval.Approval.Authorization.ValidateAt(now.UTC()) != nil {
		return ErrNotReady
	}
	return nil
}

// IntentV1 is the immutable role reservation. It stores identities and
// digests, while the exact provider fields continue to live in the signed
// Team launch authorization.
type IntentV1 struct {
	SchemaVersion             string    `json:"schema_version"`
	OperationID               string    `json:"operation_id"`
	AgentInstanceID           string    `json:"agent_instance_id"`
	OwnerID                   string    `json:"owner_id"`
	ExecutionID               string    `json:"execution_id"`
	ExecutionDigest           string    `json:"execution_digest"`
	PlanID                    string    `json:"plan_id"`
	PlanRevision              uint64    `json:"plan_revision"`
	PlanDigest                string    `json:"plan_digest"`
	ApprovalID                string    `json:"approval_id"`
	LaunchAuthorizationID     string    `json:"launch_authorization_id"`
	LaunchAuthorizationDigest string    `json:"launch_authorization_digest"`
	RoleID                    string    `json:"role_id"`
	RoleDigest                string    `json:"role_digest"`
	TaskID                    string    `json:"task_id"`
	TaskStepID                string    `json:"task_step_id"`
	DeploymentID              string    `json:"deployment_id"`
	ExpectedWorkerID          string    `json:"expected_worker_id"`
	ModelCredentialRef        string    `json:"model_credential_ref"`
	MaximumApprovedCostMicros uint64    `json:"maximum_approved_cost_micros"`
	LaunchNotAfter            time.Time `json:"launch_not_after"`
}

func (value IntentV1) Validate() error {
	for _, candidate := range []string{
		value.OperationID,
		value.AgentInstanceID,
		value.ExecutionID,
		value.PlanID,
		value.ApprovalID,
		value.LaunchAuthorizationID,
		value.TaskID,
		value.TaskStepID,
		value.DeploymentID,
		value.ExpectedWorkerID,
	} {
		parsed, err := uuid.Parse(candidate)
		if err != nil || parsed == uuid.Nil || parsed.String() != candidate {
			return ErrInvalid
		}
	}
	if value.SchemaVersion != SchemaV1 ||
		value.OwnerID == "" ||
		value.OwnerID != strings.TrimSpace(value.OwnerID) ||
		len(value.OwnerID) > 255 ||
		value.PlanRevision == 0 ||
		value.PlanRevision > uint64(math.MaxInt64) ||
		!roleIDPattern.MatchString(value.RoleID) ||
		!credentialRefPattern.MatchString(value.ModelCredentialRef) ||
		!digestPattern.MatchString(value.ExecutionDigest) ||
		!digestPattern.MatchString(value.PlanDigest) ||
		!digestPattern.MatchString(value.LaunchAuthorizationDigest) ||
		!digestPattern.MatchString(value.RoleDigest) ||
		value.MaximumApprovedCostMicros == 0 ||
		!utcMicrosecond(value.LaunchNotAfter) {
		return ErrInvalid
	}
	return nil
}

func (value IntentV1) Digest() (string, error) {
	if value.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(value)
}

type Fact struct {
	Intent                        IntentV1                 `json:"intent"`
	IntentDigest                  string                   `json:"intent_digest"`
	Phase                         Phase                    `json:"phase"`
	Outcome                       task.OutcomeStatus       `json:"outcome"`
	Attempt                       uint32                   `json:"attempt"`
	RetryAfter                    *time.Time               `json:"retry_after,omitempty"`
	FailureCode                   string                   `json:"failure_code,omitempty"`
	PublishedEvidence             *PublishedEvidenceV1     `json:"published_evidence,omitempty"`
	PublishedEvidenceDigest       string                   `json:"published_evidence_digest,omitempty"`
	PublishedAt                   *time.Time               `json:"published_at,omitempty"`
	ProvisioningQuote             *teamlaunch.FreshQuoteV1 `json:"provisioning_quote,omitempty"`
	ProvisioningQuoteDigest       string                   `json:"provisioning_quote_digest,omitempty"`
	ProvisioningStartedAt         *time.Time               `json:"provisioning_started_at,omitempty"`
	ProvisioningWorkerRevision    uint64                   `json:"provisioning_worker_revision,omitempty"`
	ProvisioningEnrollmentExpires *time.Time               `json:"provisioning_enrollment_expires_at,omitempty"`
	ResultEvidence                *teamresult.EvidenceV1   `json:"result_evidence,omitempty"`
	ResultEvidenceDigest          string                   `json:"result_evidence_digest,omitempty"`
	ResultVerifiedAt              *time.Time               `json:"result_verified_at,omitempty"`
	RecordRevision                uint64                   `json:"record_revision"`
	CreatedAt                     time.Time                `json:"created_at"`
	UpdatedAt                     time.Time                `json:"updated_at"`
}

func (value Fact) Validate() error {
	digest, err := value.Intent.Digest()
	if err != nil ||
		value.IntentDigest != digest ||
		!validPhase(value.Phase) ||
		value.RecordRevision == 0 ||
		value.CreatedAt.IsZero() ||
		value.UpdatedAt.IsZero() ||
		value.UpdatedAt.Before(value.CreatedAt) ||
		value.Attempt > 100 ||
		!validFailureCode(value.FailureCode) {
		return ErrInvalid
	}
	if value.validateProvisioningQuote() != nil {
		return ErrInvalid
	}
	if value.validatePublishedEvidence() != nil {
		return ErrInvalid
	}
	if value.validateResultEvidence() != nil {
		return ErrInvalid
	}
	if value.RetryAfter != nil &&
		(!utcMicrosecond(*value.RetryAfter) ||
			value.RetryAfter.Before(value.UpdatedAt)) {
		return ErrInvalid
	}
	if value.Phase == PhaseCompleted {
		switch value.Outcome {
		case task.OutcomeSucceeded,
			task.OutcomeFailed,
			task.OutcomeCanceled,
			task.OutcomeTimedOut:
		default:
			return ErrInvalid
		}
		if value.RetryAfter != nil || value.FailureCode != "" {
			return ErrInvalid
		}
		return nil
	}
	if value.Outcome != task.OutcomePending {
		return ErrInvalid
	}
	if value.FailureCode == "" && value.RetryAfter != nil {
		return ErrInvalid
	}
	if value.FailureCode != "" && value.RetryAfter == nil {
		return ErrInvalid
	}
	return nil
}

func (value Fact) validateResultEvidence() error {
	required := value.Phase == PhaseResultReady ||
		(value.Phase == PhaseCompleted &&
			value.Outcome == task.OutcomeSucceeded)
	forbidden := value.Phase == PhaseIntent ||
		value.Phase == PhaseInputReady ||
		value.Phase == PhaseArtifactsReady ||
		value.Phase == PhaseWorkerRegistered ||
		value.Phase == PhaseBootstrapReady ||
		value.Phase == PhaseProvisioning ||
		value.Phase == PhaseActive
	if value.ResultEvidence == nil {
		if required ||
			value.ResultEvidenceDigest != "" ||
			value.ResultVerifiedAt != nil {
			return ErrInvalid
		}
		return nil
	}
	evidence := value.ResultEvidence
	if forbidden ||
		!digestPattern.MatchString(value.ResultEvidenceDigest) ||
		evidence.Validate() != nil ||
		evidence.OperationID != value.Intent.OperationID ||
		evidence.ExecutionID != value.Intent.ExecutionID ||
		evidence.RoleID != value.Intent.RoleID ||
		evidence.DeploymentID != value.Intent.DeploymentID ||
		evidence.ExpectedWorkerID != value.Intent.ExpectedWorkerID ||
		evidence.TaskID != value.Intent.TaskID ||
		evidence.TaskStepID != value.Intent.TaskStepID ||
		value.ResultVerifiedAt == nil ||
		!utcMicrosecond(*value.ResultVerifiedAt) ||
		value.ResultVerifiedAt.Before(value.CreatedAt) ||
		value.ResultVerifiedAt.After(value.UpdatedAt) {
		return ErrInvalid
	}
	digest, err := evidence.Digest()
	if err != nil || digest != value.ResultEvidenceDigest {
		return ErrInvalid
	}
	return nil
}

func (value Fact) validatePublishedEvidence() error {
	required := value.Phase == PhaseArtifactsReady ||
		value.Phase == PhaseWorkerRegistered ||
		value.Phase == PhaseBootstrapReady ||
		value.Phase == PhaseProvisioning ||
		value.Phase == PhaseActive ||
		value.Phase == PhaseResultReady
	forbidden := value.Phase == PhaseIntent ||
		value.Phase == PhaseInputReady
	if value.PublishedEvidence == nil {
		if required ||
			value.PublishedEvidenceDigest != "" ||
			value.PublishedAt != nil {
			return ErrInvalid
		}
		return nil
	}
	if forbidden ||
		!digestPattern.MatchString(value.PublishedEvidenceDigest) ||
		value.PublishedEvidence.ValidateAgainst(value.Intent) != nil ||
		value.PublishedAt == nil ||
		!utcMicrosecond(*value.PublishedAt) ||
		value.PublishedAt.Before(value.CreatedAt) ||
		value.PublishedAt.After(value.UpdatedAt) {
		return ErrInvalid
	}
	digest, err := value.PublishedEvidence.Digest()
	if err != nil || digest != value.PublishedEvidenceDigest {
		return ErrInvalid
	}
	if value.ProvisioningStartedAt != nil &&
		value.PublishedAt.After(*value.ProvisioningStartedAt) {
		return ErrInvalid
	}
	return nil
}

func (value Fact) validateProvisioningQuote() error {
	required := value.Phase == PhaseProvisioning ||
		value.Phase == PhaseActive ||
		value.Phase == PhaseResultReady
	forbidden := value.Phase == PhaseIntent ||
		value.Phase == PhaseInputReady ||
		value.Phase == PhaseArtifactsReady ||
		value.Phase == PhaseWorkerRegistered ||
		value.Phase == PhaseBootstrapReady
	if value.ProvisioningQuote == nil {
		if required ||
			value.ProvisioningQuoteDigest != "" ||
			value.ProvisioningStartedAt != nil ||
			value.ProvisioningWorkerRevision != 0 ||
			value.ProvisioningEnrollmentExpires != nil {
			return ErrInvalid
		}
		return nil
	}
	if forbidden ||
		!digestPattern.MatchString(value.ProvisioningQuoteDigest) ||
		value.ProvisioningQuote.Validate() != nil ||
		value.ProvisioningStartedAt == nil ||
		value.ProvisioningWorkerRevision == 0 ||
		value.ProvisioningWorkerRevision > uint64(math.MaxInt64) ||
		value.ProvisioningEnrollmentExpires == nil ||
		!utcMicrosecond(*value.ProvisioningStartedAt) ||
		!utcMicrosecond(*value.ProvisioningEnrollmentExpires) ||
		value.ProvisioningStartedAt.Before(value.CreatedAt) ||
		value.ProvisioningStartedAt.After(value.UpdatedAt) ||
		value.ProvisioningStartedAt.Before(
			value.ProvisioningQuote.CapturedAt,
		) ||
		!value.ProvisioningStartedAt.Before(
			value.ProvisioningQuote.ValidUntil,
		) ||
		!value.ProvisioningStartedAt.Before(
			value.Intent.LaunchNotAfter,
		) ||
		!value.ProvisioningStartedAt.Before(
			*value.ProvisioningEnrollmentExpires,
		) {
		return ErrInvalid
	}
	digest, err := value.ProvisioningQuote.Digest()
	if err != nil ||
		digest != value.ProvisioningQuoteDigest ||
		value.ProvisioningQuote.AuthorizationID !=
			value.Intent.LaunchAuthorizationID ||
		value.ProvisioningQuote.AuthorizationDigest !=
			value.Intent.LaunchAuthorizationDigest ||
		value.ProvisioningQuote.PlanID != value.Intent.PlanID ||
		value.ProvisioningQuote.PlanRevision !=
			value.Intent.PlanRevision ||
		value.ProvisioningQuote.PlanDigest !=
			value.Intent.PlanDigest {
		return ErrInvalid
	}
	for _, role := range value.ProvisioningQuote.Roles {
		if role.RoleID == value.Intent.RoleID {
			if role.TotalMaximumMicros >
				value.Intent.MaximumApprovedCostMicros {
				return ErrInvalid
			}
			return nil
		}
	}
	return ErrInvalid
}

type RoleProgress struct {
	RoleID          string
	ExecutionStatus task.ExecutionStatus
	OutcomeStatus   task.OutcomeStatus
}

type ClaimCommand struct {
	IdempotencyKey     string   `json:"idempotency_key"`
	Intent             IntentV1 `json:"intent"`
	MaxConcurrentRoles uint32   `json:"max_concurrent_roles"`
}

func (command ClaimCommand) Validate() error {
	key, err := uuid.Parse(command.IdempotencyKey)
	if err != nil ||
		key == uuid.Nil ||
		key.String() != command.IdempotencyKey ||
		command.Intent.Validate() != nil ||
		command.MaxConcurrentRoles == 0 ||
		command.MaxConcurrentRoles > 8 {
		return ErrInvalid
	}
	return nil
}

type RecoverableCursor struct {
	UpdatedAt   time.Time
	OperationID string
}

type ExecutionCursor struct {
	UpdatedAt   time.Time
	ExecutionID string
}

type DispatchableExecution struct {
	OwnerID     string
	ExecutionID string
	TaskID      string
	Status      teamexecution.Status
	UpdatedAt   time.Time
}

type AdvanceCommand struct {
	OwnerID          string
	OperationID      string
	ExpectedRevision uint64
	FromPhase        Phase
	ToPhase          Phase
	Outcome          task.OutcomeStatus
}

func (command AdvanceCommand) Validate() error {
	if !validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.OperationID) ||
		command.ExpectedRevision == 0 ||
		command.ExpectedRevision > uint64(math.MaxInt64) ||
		!validPhaseTransition(command.FromPhase, command.ToPhase) {
		return ErrInvalid
	}
	if command.ToPhase == PhaseCompleted {
		switch command.Outcome {
		case task.OutcomeSucceeded,
			task.OutcomeFailed,
			task.OutcomeCanceled,
			task.OutcomeTimedOut:
			return nil
		default:
			return ErrInvalid
		}
	}
	if command.Outcome != task.OutcomePending {
		return ErrInvalid
	}
	return nil
}

type RetryCommand struct {
	OwnerID          string
	OperationID      string
	ExpectedRevision uint64
	Phase            Phase
	FailureCode      string
	RetryAfter       time.Time
}

func (command RetryCommand) Validate() error {
	if !validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.OperationID) ||
		command.ExpectedRevision == 0 ||
		command.ExpectedRevision > uint64(math.MaxInt64) ||
		!validPhase(command.Phase) ||
		command.Phase == PhaseCompleted ||
		!validFailureCode(command.FailureCode) ||
		command.FailureCode == "" ||
		!utcMicrosecond(command.RetryAfter) {
		return ErrInvalid
	}
	return nil
}

type BeginProvisioningCommand struct {
	OwnerID                  string
	OperationID              string
	ExpectedRevision         uint64
	WorkerDeploymentRevision uint64
	Quote                    teamlaunch.FreshQuoteV1
}

type RefreshProvisioningQuoteCommand struct {
	OwnerID          string
	OperationID      string
	ExpectedRevision uint64
	Quote            teamlaunch.FreshQuoteV1
}

type PublishArtifactsCommand struct {
	OwnerID          string
	OperationID      string
	ExpectedRevision uint64
	Evidence         PublishedEvidenceV1
}

type RecordResultCommand struct {
	OwnerID          string
	OperationID      string
	ExpectedRevision uint64
	Evidence         teamresult.EvidenceV1
	Artifacts        []teamartifact.ArtifactV1
}

func (command PublishArtifactsCommand) Validate() error {
	if !validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.OperationID) ||
		command.ExpectedRevision == 0 ||
		command.ExpectedRevision > uint64(math.MaxInt64) ||
		command.Evidence.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (command RecordResultCommand) Validate() error {
	if !validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.OperationID) ||
		command.ExpectedRevision == 0 ||
		command.ExpectedRevision > uint64(math.MaxInt64) ||
		command.Evidence.Validate() != nil ||
		command.Evidence.OperationID != command.OperationID ||
		evidenceOwnerID(command.Artifacts) != command.OwnerID ||
		!artifactsMatchResult(command.Artifacts, command.Evidence) {
		return ErrInvalid
	}
	return nil
}

func artifactsMatchResult(
	artifacts []teamartifact.ArtifactV1,
	evidence teamresult.EvidenceV1,
) bool {
	if len(artifacts) == 0 ||
		len(artifacts) > teamartifact.MaximumArtifactsPerRole {
		return false
	}
	seen := make(map[string]struct{}, len(artifacts))
	finals := make(map[string]teamresult.FinalV1, len(evidence.Finals))
	for _, final := range evidence.Finals {
		finals[final.ActionID] = final
	}
	for _, artifact := range artifacts {
		if artifact.Validate() != nil ||
			artifact.OwnerID != evidenceOwnerID(artifacts) ||
			artifact.ExecutionID != evidence.ExecutionID ||
			artifact.OperationID != evidence.OperationID ||
			artifact.TaskID != evidence.TaskID ||
			artifact.RoleID != evidence.RoleID ||
			artifact.DeploymentID != evidence.DeploymentID {
			return false
		}
		if _, duplicate := seen[artifact.ArtifactID]; duplicate {
			return false
		}
		seen[artifact.ArtifactID] = struct{}{}
		if artifact.Name == "final.json" {
			final, found := finals[artifact.ActionID]
			if !found ||
				artifact.ObjectRef != final.ArtifactRef ||
				artifact.SHA256 != final.ArtifactSHA256 ||
				artifact.SizeBytes != final.ArtifactSizeBytes ||
				artifact.MediaType != final.ArtifactMediaType {
				return false
			}
		}
	}
	for actionID := range finals {
		found := false
		for _, artifact := range artifacts {
			if artifact.ActionID == actionID && artifact.Name == "final.json" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func evidenceOwnerID(artifacts []teamartifact.ArtifactV1) string {
	if len(artifacts) == 0 {
		return ""
	}
	return artifacts[0].OwnerID
}

func (command BeginProvisioningCommand) Validate() error {
	if !validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.OperationID) ||
		command.ExpectedRevision == 0 ||
		command.ExpectedRevision > uint64(math.MaxInt64) ||
		command.WorkerDeploymentRevision == 0 ||
		command.WorkerDeploymentRevision > uint64(math.MaxInt64) ||
		command.Quote.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (command RefreshProvisioningQuoteCommand) Validate() error {
	if !validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.OperationID) ||
		command.ExpectedRevision == 0 ||
		command.ExpectedRevision > uint64(math.MaxInt64) ||
		command.Quote.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type AuthorizationReader interface {
	LoadAuthorizedExecution(
		context.Context,
		string,
		string,
	) (AuthorizedExecution, error)
}

type ProgressReader interface {
	LoadRoleProgress(
		context.Context,
		string,
		string,
	) ([]RoleProgress, error)
}

type WorkerLaunch struct {
	Dispatch      Fact
	Authorization AuthorizedExecution
}

func (launch WorkerLaunch) ValidateForIdentity() error {
	if launch.Dispatch.Validate() != nil ||
		launch.Authorization.Validate() != nil ||
		launch.Dispatch.Intent.ValidateAgainst(
			launch.Authorization,
		) != nil ||
		launch.Dispatch.PublishedEvidence == nil ||
		launch.Dispatch.PublishedEvidence.ValidateAgainst(
			launch.Dispatch.Intent,
		) != nil ||
		launch.Authorization.Approval.Approval.Authorization == nil ||
		launch.Dispatch.PublishedEvidence.ConnectionID !=
			launch.Authorization.Approval.Approval.Authorization.
				ProviderScope.ConnectionID {
		return ErrFactMismatch
	}
	switch launch.Dispatch.Phase {
	case PhaseProvisioning, PhaseActive:
		return nil
	default:
		return ErrNotReady
	}
}

type WorkerLaunchReader interface {
	LoadWorkerLaunchByDeployment(
		context.Context,
		string,
		string,
	) (WorkerLaunch, error)
}

type ExecutionQueueReader interface {
	ListDispatchableExecutions(
		context.Context,
		*ExecutionCursor,
		uint32,
	) ([]DispatchableExecution, error)
}

// Repository must lock the parent Execution while ClaimRole counts
// non-terminal operations. That database fence is the final concurrency
// authority when multiple Central Agent processes recover simultaneously.
type Repository interface {
	ListExecutionOperations(
		context.Context,
		string,
		string,
	) ([]Fact, error)
	ClaimRole(
		context.Context,
		task.MutationScope,
		ClaimCommand,
	) (Fact, bool, error)
	GetRoleOperation(
		context.Context,
		string,
		string,
	) (Fact, error)
	AdvanceRole(
		context.Context,
		AdvanceCommand,
	) (Fact, error)
	PublishRoleArtifacts(
		context.Context,
		PublishArtifactsCommand,
	) (Fact, error)
	BeginProvisioning(
		context.Context,
		BeginProvisioningCommand,
	) (Fact, error)
	RefreshProvisioningQuote(
		context.Context,
		RefreshProvisioningQuoteCommand,
	) (Fact, error)
	RecordRoleResult(
		context.Context,
		RecordResultCommand,
	) (Fact, error)
	ScheduleRoleRetry(
		context.Context,
		RetryCommand,
	) (Fact, error)
	ListRecoverableRoleDispatches(
		context.Context,
		*RecoverableCursor,
		uint32,
		time.Time,
	) ([]Fact, error)
}

func validPhase(value Phase) bool {
	switch value {
	case PhaseIntent,
		PhaseInputReady,
		PhaseArtifactsReady,
		PhaseWorkerRegistered,
		PhaseBootstrapReady,
		PhaseProvisioning,
		PhaseActive,
		PhaseResultReady,
		PhaseDestroying,
		PhaseCompleted:
		return true
	default:
		return false
	}
}

func validPhaseTransition(from, to Phase) bool {
	if !validPhase(from) || !validPhase(to) || from == to ||
		from == PhaseCompleted {
		return false
	}
	if to == PhaseDestroying {
		return from != PhaseDestroying
	}
	switch from {
	case PhaseIntent:
		return to == PhaseInputReady
	case PhaseInputReady:
		return to == PhaseArtifactsReady
	case PhaseArtifactsReady:
		return to == PhaseWorkerRegistered
	case PhaseWorkerRegistered:
		return to == PhaseBootstrapReady
	case PhaseBootstrapReady:
		return false
	case PhaseProvisioning:
		return to == PhaseActive
	case PhaseActive:
		return to == PhaseResultReady
	case PhaseResultReady:
		return to == PhaseDestroying
	case PhaseDestroying:
		return to == PhaseCompleted
	default:
		return false
	}
}

func validOwnerID(value string) bool {
	return value != "" &&
		value == strings.TrimSpace(value) &&
		len(value) <= 255
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func validFailureCode(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 64 ||
		value != strings.TrimSpace(value) ||
		value[0] < 'a' ||
		value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character != '_' &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func utcMicrosecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Equal(value.Truncate(time.Microsecond))
}
