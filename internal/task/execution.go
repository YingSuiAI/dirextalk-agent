package task

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	maxTaskSteps     = 512
	minLeaseDuration = 5 * time.Second
	maxLeaseDuration = 30 * time.Minute
)

// MutationScope is supplied by the authenticated service boundary. It scopes
// every idempotency key by both the stable caller and the concrete credential
// used for this request.
type MutationScope struct {
	ClientID     string
	CredentialID string
}

func (scope MutationScope) Validate() error {
	clientID := strings.TrimSpace(scope.ClientID)
	if !validCallerID(clientID) || security.ContainsLikelySecret(clientID) {
		return ErrInvalidMutationScope
	}
	credentialID, err := uuid.Parse(scope.CredentialID)
	if err != nil || credentialID == uuid.Nil {
		return ErrInvalidMutationScope
	}
	return nil
}

func validCallerID(value string) bool {
	count := utf8.RuneCountInString(value)
	if count < 1 || count > 255 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type StepDefinition struct {
	StepID           string
	Name             string
	ExecutorKind     ExecutorKind
	DependsOnStepIDs []string
}

type Attempt struct {
	TaskID     string
	StepID     string
	Attempt    int32
	LeaseEpoch int64
	WorkerID   string
	// TaskRevision and StepRevision are the durable revisions observed when a
	// lease was acquired. They are deliberately carried in the acquire replay
	// snapshot so a later user-wait transition can fence all three aggregates
	// instead of relying on a best-effort lease timeout.
	TaskRevision    int64
	StepRevision    int64
	LeaseExpiresAt  time.Time
	ExecutionStatus ExecutionStatus
	OutcomeStatus   OutcomeStatus
	CheckpointRef   string
	ResultRef       string
	Revision        int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type AcquireReadyStepCommand struct {
	IdempotencyKey string
	TaskID         string
	StepID         string
	WorkerID       string
	ExecutorKind   ExecutorKind
	LeaseDuration  time.Duration
}

func (command AcquireReadyStepCommand) Validate() error {
	if err := validateMutationIDs(command.IdempotencyKey, command.TaskID, command.StepID, command.WorkerID); err != nil {
		return err
	}
	if command.ExecutorKind != ExecutorControlPlane && command.ExecutorKind != ExecutorCloudWorker {
		return fmt.Errorf("%w: executor kind is invalid", ErrInvalid)
	}
	return validateLeaseDuration(command.LeaseDuration)
}

func (command AcquireReadyStepCommand) Digest() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		TaskID        string       `json:"task_id"`
		StepID        string       `json:"step_id"`
		WorkerID      string       `json:"worker_id"`
		ExecutorKind  ExecutorKind `json:"executor_kind"`
		LeaseDuration int64        `json:"lease_duration_ns"`
	}{normalizedUUID(command.TaskID), normalizedUUID(command.StepID), normalizedUUID(command.WorkerID), command.ExecutorKind, int64(command.LeaseDuration)})
	return sha256.Sum256(encoded)
}

type RenewStepLeaseCommand struct {
	IdempotencyKey string
	TaskID         string
	StepID         string
	Attempt        int32
	LeaseEpoch     int64
	WorkerID       string
	LeaseDuration  time.Duration
}

func (command RenewStepLeaseCommand) Validate() error {
	if err := validateLeasedMutation(command.IdempotencyKey, command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch); err != nil {
		return err
	}
	return validateLeaseDuration(command.LeaseDuration)
}

func (command RenewStepLeaseCommand) Digest() [sha256.Size]byte {
	return leaseMutationDigest(command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch, int64(command.LeaseDuration), "", "", "")
}

type CheckpointStepCommand struct {
	IdempotencyKey string
	TaskID         string
	StepID         string
	Attempt        int32
	LeaseEpoch     int64
	WorkerID       string
	CheckpointRef  string
}

func (command CheckpointStepCommand) Validate() error {
	if err := validateLeasedMutation(command.IdempotencyKey, command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch); err != nil {
		return err
	}
	return validateEvidenceReference("checkpoint_ref", command.CheckpointRef, false)
}

func (command CheckpointStepCommand) Digest() [sha256.Size]byte {
	return leaseMutationDigest(command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch, 0, strings.TrimSpace(command.CheckpointRef), "", "")
}

type CompleteStepCommand struct {
	IdempotencyKey string
	TaskID         string
	StepID         string
	Attempt        int32
	LeaseEpoch     int64
	WorkerID       string
	Outcome        OutcomeStatus
	ResultRef      string
	// RelatedPlanID is set only by the trusted cloud planning controller when
	// the final planning Step has already persisted an exact ready Plan. It is
	// deliberately not part of the Worker RPC: the store verifies the owning
	// Cloud Goal session, owner, connection, final stage, and Plan before
	// projecting it into Task.ApprovedPlanID.
	RelatedPlanID string
}

// WaitingReasonServiceSecretsNotReady is the only reason persisted for a
// Cloud Goal that needs a user upload. It is a stable, non-sensitive code;
// secret references, bootstrap session IDs, and source error text are never
// written to Task events or the outbox.
const WaitingReasonServiceSecretsNotReady = "service_secrets_not_ready"

// SecretWaitRequirement is metadata-only. RecipeDigest becomes the
// SecretBootstrap target_id; no secret reference, session ID, plaintext, or
// delivery path crosses the Task boundary.
type SecretWaitRequirement struct {
	Purpose      string
	RecipeDigest string
}

// SuspendStepForSecretsCommand releases one live attempt and makes its Task
// visibly waiting_user until matching encrypted secret uploads exist. All
// revisions are the values returned by AcquireReadyStep, while Attempt and
// LeaseEpoch fence an older Worker/controller from completing afterwards.
type SuspendStepForSecretsCommand struct {
	IdempotencyKey          string
	TaskID                  string
	StepID                  string
	Attempt                 int32
	LeaseEpoch              int64
	WorkerID                string
	ExpectedTaskRevision    int64
	ExpectedStepRevision    int64
	ExpectedAttemptRevision int64
	AgentInstanceID         string
	Requirements            []SecretWaitRequirement
}

func (command SuspendStepForSecretsCommand) Validate() error {
	if err := validateLeasedMutation(command.IdempotencyKey, command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch); err != nil {
		return err
	}
	if command.ExpectedTaskRevision < 1 || command.ExpectedStepRevision < 1 || command.ExpectedAttemptRevision < 1 {
		return fmt.Errorf("%w: expected revisions must be positive", ErrInvalid)
	}
	agentID, err := uuid.Parse(command.AgentInstanceID)
	if err != nil || agentID == uuid.Nil || agentID.String() != command.AgentInstanceID {
		return fmt.Errorf("%w: agent_instance_id must be a UUID", ErrInvalid)
	}
	if len(command.Requirements) < 1 || len(command.Requirements) > 32 {
		return fmt.Errorf("%w: secret requirements length is invalid", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(command.Requirements))
	for _, requirement := range command.Requirements {
		purpose := strings.TrimSpace(requirement.Purpose)
		if purpose == "" || purpose != requirement.Purpose || len(purpose) > 256 || !utf8.ValidString(purpose) ||
			strings.IndexFunc(purpose, unicode.IsControl) >= 0 || security.ContainsLikelySecret(purpose) || !validRecipeDigest(requirement.RecipeDigest) {
			return fmt.Errorf("%w: secret requirement is invalid", ErrInvalid)
		}
		if _, duplicate := seen[purpose]; duplicate {
			return fmt.Errorf("%w: secret requirement purpose is duplicated", ErrInvalid)
		}
		seen[purpose] = struct{}{}
	}
	return nil
}

func (command SuspendStepForSecretsCommand) Digest() [sha256.Size]byte {
	requirements := append([]SecretWaitRequirement(nil), command.Requirements...)
	sort.Slice(requirements, func(i, j int) bool {
		if requirements[i].Purpose == requirements[j].Purpose {
			return requirements[i].RecipeDigest < requirements[j].RecipeDigest
		}
		return requirements[i].Purpose < requirements[j].Purpose
	})
	encoded, _ := json.Marshal(struct {
		TaskID                  string                  `json:"task_id"`
		StepID                  string                  `json:"step_id"`
		Attempt                 int32                   `json:"attempt"`
		LeaseEpoch              int64                   `json:"lease_epoch"`
		WorkerID                string                  `json:"worker_id"`
		ExpectedTaskRevision    int64                   `json:"expected_task_revision"`
		ExpectedStepRevision    int64                   `json:"expected_step_revision"`
		ExpectedAttemptRevision int64                   `json:"expected_attempt_revision"`
		AgentInstanceID         string                  `json:"agent_instance_id"`
		Requirements            []SecretWaitRequirement `json:"requirements"`
	}{
		TaskID: normalizedUUID(command.TaskID), StepID: normalizedUUID(command.StepID), Attempt: command.Attempt,
		LeaseEpoch: command.LeaseEpoch, WorkerID: normalizedUUID(command.WorkerID),
		ExpectedTaskRevision: command.ExpectedTaskRevision, ExpectedStepRevision: command.ExpectedStepRevision,
		ExpectedAttemptRevision: command.ExpectedAttemptRevision, AgentInstanceID: normalizedUUID(command.AgentInstanceID),
		Requirements: requirements,
	})
	return sha256.Sum256(encoded)
}

func (command CompleteStepCommand) Validate() error {
	if err := validateLeasedMutation(command.IdempotencyKey, command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch); err != nil {
		return err
	}
	switch command.Outcome {
	case OutcomeSucceeded, OutcomeFailed, OutcomeTimedOut, OutcomeInterrupted:
	default:
		return fmt.Errorf("%w: worker completion outcome is invalid", ErrInvalid)
	}
	if err := validateEvidenceReference("result_ref", command.ResultRef, command.Outcome != OutcomeSucceeded); err != nil {
		return err
	}
	if strings.TrimSpace(command.RelatedPlanID) == "" {
		return nil
	}
	planID, err := uuid.Parse(command.RelatedPlanID)
	if err != nil || planID == uuid.Nil || planID.String() != command.RelatedPlanID || command.Outcome != OutcomeSucceeded {
		return fmt.Errorf("%w: related_plan_id is invalid", ErrInvalid)
	}
	return nil
}

func (command CompleteStepCommand) Digest() [sha256.Size]byte {
	return leaseMutationDigest(
		command.TaskID, command.StepID, command.WorkerID, command.Attempt, command.LeaseEpoch, 0,
		strings.TrimSpace(command.ResultRef), string(command.Outcome), strings.TrimSpace(command.RelatedPlanID),
	)
}

func validateMutationIDs(idempotencyKey, taskID, stepID, workerID string) error {
	if _, err := uuid.Parse(idempotencyKey); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrInvalid)
	}
	if _, err := uuid.Parse(taskID); err != nil {
		return fmt.Errorf("%w: task_id must be a UUID", ErrInvalid)
	}
	if stepID != "" {
		if _, err := uuid.Parse(stepID); err != nil {
			return fmt.Errorf("%w: step_id must be a UUID", ErrInvalid)
		}
	}
	worker, err := uuid.Parse(workerID)
	if err != nil || worker == uuid.Nil {
		return fmt.Errorf("%w: worker_id must be a non-zero UUID", ErrInvalid)
	}
	return nil
}

func validateLeasedMutation(idempotencyKey, taskID, stepID, workerID string, attempt int32, leaseEpoch int64) error {
	if err := validateMutationIDs(idempotencyKey, taskID, stepID, workerID); err != nil {
		return err
	}
	if attempt < 1 || leaseEpoch < 1 {
		return fmt.Errorf("%w: attempt and lease_epoch must be positive", ErrInvalid)
	}
	return nil
}

func validateLeaseDuration(duration time.Duration) error {
	if duration < minLeaseDuration || duration > maxLeaseDuration {
		return fmt.Errorf("%w: lease duration must be between %s and %s", ErrInvalid, minLeaseDuration, maxLeaseDuration)
	}
	return nil
}

func validateEvidenceReference(name, value string, allowEmpty bool) error {
	value = strings.TrimSpace(value)
	if (!allowEmpty && value == "") || len(value) > 2048 {
		return fmt.Errorf("%w: %s length is invalid", ErrInvalid, name)
	}
	if security.ContainsLikelySecret(value) {
		return ErrRawSecret
	}
	return nil
}

func validRecipeDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func leaseMutationDigest(taskID, stepID, workerID string, attempt int32, leaseEpoch, duration int64, reference, outcome, relatedPlanID string) [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		TaskID     string `json:"task_id"`
		StepID     string `json:"step_id"`
		WorkerID   string `json:"worker_id"`
		Attempt    int32  `json:"attempt"`
		LeaseEpoch int64  `json:"lease_epoch"`
		Duration   int64  `json:"duration_ns,omitempty"`
		Reference  string `json:"reference,omitempty"`
		Outcome    string `json:"outcome,omitempty"`
		PlanID     string `json:"related_plan_id,omitempty"`
	}{normalizedUUID(taskID), normalizedUUID(stepID), normalizedUUID(workerID), attempt, leaseEpoch, duration, reference, outcome, relatedPlanID})
	return sha256.Sum256(encoded)
}

type normalizedStepDigest struct {
	StepID           string       `json:"step_id"`
	Name             string       `json:"name"`
	ExecutorKind     ExecutorKind `json:"executor_kind"`
	DependsOnStepIDs []string     `json:"depends_on_step_ids"`
}

func normalizedStepDigests(steps []StepDefinition) []normalizedStepDigest {
	result := make([]normalizedStepDigest, 0, len(steps))
	for _, step := range steps {
		dependencies := make([]string, 0, len(step.DependsOnStepIDs))
		for _, dependency := range step.DependsOnStepIDs {
			dependencies = append(dependencies, normalizedUUID(dependency))
		}
		sort.Strings(dependencies)
		result = append(result, normalizedStepDigest{
			StepID: normalizedUUID(step.StepID), Name: strings.TrimSpace(step.Name), ExecutorKind: step.ExecutorKind, DependsOnStepIDs: dependencies,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StepID < result[j].StepID })
	return result
}

func validateStepDAG(steps []StepDefinition) error {
	if len(steps) > maxTaskSteps {
		return fmt.Errorf("%w: task has more than %d steps", ErrInvalidDAG, maxTaskSteps)
	}
	byID := make(map[string]StepDefinition, len(steps))
	for _, step := range steps {
		parsed, err := uuid.Parse(step.StepID)
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: step_id must be a non-zero UUID", ErrInvalidDAG)
		}
		stepID := parsed.String()
		if _, duplicate := byID[stepID]; duplicate {
			return fmt.Errorf("%w: duplicate step_id", ErrInvalidDAG)
		}
		name := strings.TrimSpace(step.Name)
		if name == "" || len(name) > 512 || strings.IndexFunc(name, unicode.IsControl) >= 0 || security.ContainsLikelySecret(name) {
			return fmt.Errorf("%w: step name is invalid", ErrInvalidDAG)
		}
		if step.ExecutorKind != ExecutorControlPlane && step.ExecutorKind != ExecutorCloudWorker {
			return fmt.Errorf("%w: executor kind is invalid", ErrInvalidDAG)
		}
		byID[stepID] = step
	}

	dependencies := make(map[string][]string, len(steps))
	for stepID, step := range byID {
		seen := make(map[string]struct{}, len(step.DependsOnStepIDs))
		for _, rawDependency := range step.DependsOnStepIDs {
			parsed, err := uuid.Parse(rawDependency)
			if err != nil || parsed == uuid.Nil {
				return fmt.Errorf("%w: dependency must be a non-zero UUID", ErrInvalidDAG)
			}
			dependencyID := parsed.String()
			if dependencyID == stepID {
				return fmt.Errorf("%w: step depends on itself", ErrInvalidDAG)
			}
			if _, exists := byID[dependencyID]; !exists {
				return fmt.Errorf("%w: dependency is unknown", ErrInvalidDAG)
			}
			if _, duplicate := seen[dependencyID]; duplicate {
				return fmt.Errorf("%w: dependency is duplicated", ErrInvalidDAG)
			}
			seen[dependencyID] = struct{}{}
			dependencies[stepID] = append(dependencies[stepID], dependencyID)
		}
	}

	colors := make(map[string]uint8, len(steps))
	var visit func(string) bool
	visit = func(stepID string) bool {
		switch colors[stepID] {
		case 1:
			return false
		case 2:
			return true
		}
		colors[stepID] = 1
		for _, dependencyID := range dependencies[stepID] {
			if !visit(dependencyID) {
				return false
			}
		}
		colors[stepID] = 2
		return true
	}
	for stepID := range byID {
		if !visit(stepID) {
			return fmt.Errorf("%w: dependency cycle detected", ErrInvalidDAG)
		}
	}
	return nil
}

func normalizedUUID(value string) string {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return value
	}
	return parsed.String()
}
