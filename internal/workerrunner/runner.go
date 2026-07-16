package workerrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrCancellationRequested = errors.New("Worker cancellation was requested")

type ControlClient interface {
	Enroll(context.Context, []byte, *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)
	GetCurrentAssignment(context.Context, []byte, *agentv1.WorkerControlServiceGetCurrentAssignmentRequest) (*agentv1.WorkerControlServiceGetCurrentAssignmentResponse, error)
	Claim(context.Context, []byte, *agentv1.WorkerControlServiceClaimRequest) (*agentv1.WorkerControlServiceClaimResponse, error)
	Heartbeat(context.Context, []byte, *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error)
	RecordEvidence(context.Context, []byte, *agentv1.WorkerControlServiceRecordEvidenceRequest) (*agentv1.WorkerControlServiceRecordEvidenceResponse, error)
	Complete(context.Context, []byte, *agentv1.WorkerControlServiceCompleteRequest) (*agentv1.WorkerControlServiceCompleteResponse, error)
}

type ObjectStore interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, string, []byte) error
}

type Runner struct {
	Control           ControlClient
	Objects           ObjectStore
	Registry          *Registry
	HeartbeatInterval time.Duration
	RetryDelay        time.Duration
}

type Config struct {
	DeploymentID               string
	WorkerID                   string
	EnrollmentIdempotencyKey   string
	EnrollmentExpectedRevision int64
	EnrollmentToken            []byte
	// IdentitySessionToken and IdentityAssignment are supplied only after the
	// Worker has completed provider-verified enrollment. When present, Runner
	// skips the local/fake token enrollment path and starts with Claim.
	IdentitySessionToken []byte
	IdentityAssignment   *agentv1.WorkerAssignment
	LeaseDuration        time.Duration
}

type Result struct {
	Outcome          agentv1.WorkerOutcome
	ResultRef        string
	CompletedActions []string
}

func (runner Runner) Run(ctx context.Context, config Config) (Result, error) {
	if err := runner.validate(config); err != nil {
		return Result{}, err
	}
	var enrolledAssignment *agentv1.WorkerAssignment
	var sessionToken []byte
	if len(config.IdentitySessionToken) != 0 {
		sessionToken = bytes.Clone(config.IdentitySessionToken)
		enrolledAssignment = config.IdentityAssignment
	} else {
		enrollmentRequest := &agentv1.EnrollRequest{
			DeploymentId: config.DeploymentID, WorkerId: config.WorkerID,
			IdempotencyKey: config.EnrollmentIdempotencyKey, ExpectedRevision: config.EnrollmentExpectedRevision,
		}
		enrolled, err := retryCall(ctx, runner.retryDelay(), func() (*agentv1.EnrollResponse, error) {
			return runner.Control.Enroll(ctx, config.EnrollmentToken, enrollmentRequest)
		})
		if err != nil {
			return Result{}, fmt.Errorf("enroll Worker: %w", err)
		}
		sessionToken = enrolled.GetSessionToken()
		enrolledAssignment = enrolled.GetAssignment()
	}
	defer wipe(sessionToken)
	if len(sessionToken) < 32 {
		return Result{}, errors.New("Worker enrollment returned an invalid session")
	}
	if err := validateAssignment(enrolledAssignment, config, false); err != nil {
		return Result{}, err
	}

	currentAssignment, err := runner.waitForClaimableAssignment(ctx, config, sessionToken)
	if err != nil {
		return Result{}, fmt.Errorf("resume Worker assignment: %w", err)
	}
	claimRequest := &agentv1.WorkerControlServiceClaimRequest{
		DeploymentId: config.DeploymentID, WorkerId: config.WorkerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: currentAssignment.GetRevision(), LeaseDurationSeconds: int32(config.LeaseDuration / time.Second),
	}
	claimed, err := retryCall(ctx, runner.retryDelay(), func() (*agentv1.WorkerControlServiceClaimResponse, error) {
		return runner.Control.Claim(ctx, sessionToken, claimRequest)
	})
	if err != nil {
		return Result{}, fmt.Errorf("claim Worker execution: %w", err)
	}
	assignment := claimed.GetAssignment()
	if err := validateAssignment(assignment, config, true); err != nil {
		return Result{}, err
	}
	if assignment.GetCancellationRequested() {
		return Result{}, ErrCancellationRequested
	}

	executionContext, cancelExecution := context.WithTimeout(ctx, time.Duration(assignment.GetExecutionTimeoutSeconds())*time.Second)
	defer cancelExecution()
	lease := &leaseState{
		control: runner.Control, token: sessionToken, deploymentID: config.DeploymentID, workerID: config.WorkerID,
		epoch: assignment.GetLeaseEpoch(), revision: assignment.GetRevision(), leaseDuration: config.LeaseDuration,
		retryDelay: runner.retryDelay(),
	}
	heartbeatContext, stopHeartbeat := context.WithCancel(executionContext)
	heartbeatDone := make(chan error, 1)
	go func() {
		heartbeatErr := lease.heartbeatLoop(heartbeatContext, runner.heartbeatInterval(config.LeaseDuration))
		if heartbeatErr != nil && heartbeatContext.Err() == nil {
			cancelExecution()
		}
		heartbeatDone <- heartbeatErr
	}()

	completedActions, resultRef, executionErr := runner.execute(executionContext, assignment, lease)
	stopHeartbeat()
	heartbeatErr := <-heartbeatDone
	if errors.Is(heartbeatErr, context.Canceled) || errors.Is(heartbeatErr, context.DeadlineExceeded) {
		heartbeatErr = nil
	}
	if heartbeatErr != nil && !errors.Is(heartbeatErr, ErrCancellationRequested) {
		return Result{CompletedActions: completedActions}, fmt.Errorf("Worker heartbeat failed: %w", heartbeatErr)
	}

	outcome := agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED
	if heartbeatErr != nil && errors.Is(heartbeatErr, ErrCancellationRequested) {
		outcome = agentv1.WorkerOutcome_WORKER_OUTCOME_CANCELED
		resultRef = ""
		executionErr = ErrCancellationRequested
	} else if executionErr != nil {
		outcome = agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED
		resultRef = ""
		if errors.Is(executionContext.Err(), context.DeadlineExceeded) {
			outcome = agentv1.WorkerOutcome_WORKER_OUTCOME_TIMED_OUT
		} else if errors.Is(ctx.Err(), context.Canceled) {
			outcome = agentv1.WorkerOutcome_WORKER_OUTCOME_INTERRUPTED
		}
	}

	completeContext, cancelComplete := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancelComplete()
	if err := lease.complete(completeContext, outcome, resultRef); err != nil {
		return Result{Outcome: outcome, ResultRef: resultRef, CompletedActions: completedActions}, fmt.Errorf("complete Worker execution: %w", err)
	}
	result := Result{Outcome: outcome, ResultRef: resultRef, CompletedActions: completedActions}
	if executionErr != nil {
		return result, executionErr
	}
	return result, nil
}

func (runner Runner) waitForClaimableAssignment(ctx context.Context, config Config, sessionToken []byte) (*agentv1.WorkerAssignment, error) {
	request := &agentv1.WorkerControlServiceGetCurrentAssignmentRequest{DeploymentId: config.DeploymentID, WorkerId: config.WorkerID}
	for {
		response, err := retryCall(ctx, runner.retryDelay(), func() (*agentv1.WorkerControlServiceGetCurrentAssignmentResponse, error) {
			return runner.Control.GetCurrentAssignment(ctx, sessionToken, request)
		})
		if err != nil {
			return nil, err
		}
		assignment := response.GetAssignment()
		if err := validateAssignment(assignment, config, false); err != nil {
			return nil, err
		}
		if assignment.GetCancellationRequested() {
			return nil, ErrCancellationRequested
		}
		expiresAt := assignment.GetLeaseExpiresAt()
		if assignment.GetLeaseEpoch() < 1 || expiresAt == nil || !time.Now().UTC().Before(expiresAt.AsTime()) {
			return assignment, nil
		}
		wait := time.Until(expiresAt.AsTime())
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (runner Runner) execute(ctx context.Context, assignment *agentv1.WorkerAssignment, lease *leaseState) ([]string, string, error) {
	recipeBytes, err := runner.verifiedObject(ctx, assignment.GetRecipeBundle())
	if err != nil {
		return nil, "", err
	}
	wipe(recipeBytes)
	executionBytes, err := runner.verifiedObject(ctx, assignment.GetExecutionBundle())
	if err != nil {
		return nil, "", err
	}
	bundle, err := parseExecutionBundle(executionBytes, assignment.GetRecipeBundle().GetSha256(), time.Duration(assignment.GetExecutionTimeoutSeconds())*time.Second)
	wipe(executionBytes)
	if err != nil {
		return nil, "", err
	}
	if err := runner.Registry.Validate(bundle); err != nil {
		return nil, "", err
	}
	completed, startIndex, err := runner.resumeCheckpoint(ctx, assignment, bundle)
	if err != nil {
		return nil, "", err
	}
	for actionIndex := startIndex; actionIndex < len(bundle.Actions); actionIndex++ {
		action := bundle.Actions[actionIndex]
		actionContext, cancel := context.WithTimeout(ctx, time.Duration(action.TimeoutSeconds)*time.Second)
		_, actionErr := runner.Registry.Execute(actionContext, action)
		cancel()
		if actionErr != nil {
			return completed, "", fmt.Errorf("typed action %s failed: %w", action.ID, actionErr)
		}
		checkpoint := checkpointV1{
			SchemaVersion: checkpointSchemaV1, DeploymentID: assignment.GetDeploymentId(), WorkerID: assignment.GetWorkerId(),
			Attempt: assignment.GetAttempt(), LeaseEpoch: assignment.GetLeaseEpoch(),
			RecipeSHA256: hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()), ExecutionSHA256: hex.EncodeToString(assignment.GetExecutionBundle().GetSha256()),
			ActionIndex: actionIndex, ActionID: action.ID, Status: "succeeded",
		}
		checkpointBytes, err := json.Marshal(checkpoint)
		if err != nil {
			return completed, "", err
		}
		checkpointDigest := sha256.Sum256(checkpointBytes)
		checkpointRef, err := scopedCheckpointRef(assignment.GetAccess(), checkpoint, checkpointDigest)
		if err != nil {
			wipe(checkpointBytes)
			return completed, "", err
		}
		if err := runner.Objects.Put(ctx, checkpointRef, "application/json", checkpointBytes); err != nil {
			wipe(checkpointBytes)
			return completed, "", fmt.Errorf("store Worker checkpoint: %w", err)
		}
		wipe(checkpointBytes)
		if err := lease.recordCheckpoint(ctx, checkpointRef); err != nil {
			return completed, "", err
		}
		completed = append(completed, action.ID)
	}
	resultRef, err := scopedObjectRef(assignment.GetAccess(), false, "result.json")
	if err != nil {
		return completed, "", err
	}
	resultBody, _ := json.Marshal(struct {
		SchemaVersion    int      `json:"schema_version"`
		Status           string   `json:"status"`
		CompletedActions []string `json:"completed_actions"`
	}{SchemaVersion: 1, Status: "succeeded", CompletedActions: completed})
	if err := runner.Objects.Put(ctx, resultRef, "application/json", resultBody); err != nil {
		return completed, "", fmt.Errorf("store Worker result: %w", err)
	}
	return completed, resultRef, nil
}

type checkpointV1 struct {
	SchemaVersion   int    `json:"schema_version"`
	DeploymentID    string `json:"deployment_id"`
	WorkerID        string `json:"worker_id"`
	Attempt         int32  `json:"attempt"`
	LeaseEpoch      int64  `json:"lease_epoch"`
	RecipeSHA256    string `json:"recipe_sha256"`
	ExecutionSHA256 string `json:"execution_sha256"`
	ActionIndex     int    `json:"action_index"`
	ActionID        string `json:"action_id"`
	Status          string `json:"status"`
}

const checkpointSchemaV1 = 1

func (runner Runner) resumeCheckpoint(ctx context.Context, assignment *agentv1.WorkerAssignment, bundle ExecutionBundleV1) ([]string, int, error) {
	checkpointRef := strings.TrimSpace(assignment.GetCheckpointRef())
	if checkpointRef == "" {
		if assignment.GetCheckpointAttempt() != 0 || assignment.GetCheckpointLeaseEpoch() != 0 {
			return nil, 0, errors.New("Worker checkpoint fence exists without a checkpoint reference")
		}
		return make([]string, 0, len(bundle.Actions)), 0, nil
	}
	if assignment.GetCheckpointAttempt() < 1 || assignment.GetCheckpointLeaseEpoch() < 1 ||
		assignment.GetAttempt() <= assignment.GetCheckpointAttempt() || assignment.GetLeaseEpoch() <= assignment.GetCheckpointLeaseEpoch() ||
		!checkpointRefWithinScope(assignment.GetAccess(), checkpointRef) {
		return nil, 0, errors.New("Worker checkpoint fence is invalid")
	}
	raw, err := runner.Objects.Get(ctx, checkpointRef)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch Worker checkpoint: %w", err)
	}
	defer wipe(raw)
	if len(raw) == 0 || len(raw) > maxBundleBytes {
		return nil, 0, errors.New("Worker checkpoint is invalid")
	}
	var checkpoint checkpointV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return nil, 0, errors.New("Worker checkpoint is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("Worker checkpoint contains trailing data")
	}
	digest := sha256.Sum256(raw)
	expectedRef, err := scopedCheckpointRef(assignment.GetAccess(), checkpoint, digest)
	if err != nil || expectedRef != checkpointRef || checkpoint.SchemaVersion != checkpointSchemaV1 || checkpoint.Status != "succeeded" ||
		checkpoint.DeploymentID != assignment.GetDeploymentId() || checkpoint.WorkerID != assignment.GetWorkerId() ||
		checkpoint.Attempt != assignment.GetCheckpointAttempt() || checkpoint.LeaseEpoch != assignment.GetCheckpointLeaseEpoch() ||
		checkpoint.RecipeSHA256 != hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()) ||
		checkpoint.ExecutionSHA256 != hex.EncodeToString(assignment.GetExecutionBundle().GetSha256()) ||
		checkpoint.ActionIndex < 0 || checkpoint.ActionIndex >= len(bundle.Actions) || bundle.Actions[checkpoint.ActionIndex].ID != checkpoint.ActionID {
		return nil, 0, errors.New("Worker checkpoint does not match the current assignment")
	}
	completed := make([]string, checkpoint.ActionIndex+1)
	for index := range completed {
		completed[index] = bundle.Actions[index].ID
	}
	return completed, checkpoint.ActionIndex + 1, nil
}

func (runner Runner) verifiedObject(ctx context.Context, reference *agentv1.WorkerBundleReference) ([]byte, error) {
	if reference == nil || len(reference.GetSha256()) != sha256.Size || !validS3ObjectRef(reference.GetS3Ref()) {
		return nil, ErrInvalidBundle
	}
	raw, err := runner.Objects.Get(ctx, reference.GetS3Ref())
	if err != nil {
		return nil, fmt.Errorf("fetch locked Worker bundle: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxBundleBytes {
		wipe(raw)
		return nil, ErrInvalidBundle
	}
	digest := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(digest[:], reference.GetSha256()) != 1 {
		wipe(raw)
		return nil, ErrDigestMismatch
	}
	return raw, nil
}

func (runner Runner) validate(config Config) error {
	for _, value := range []string{config.DeploymentID, config.WorkerID} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil {
			return errors.New("Worker identifiers must be non-zero UUIDs")
		}
	}
	identityEnrollment := len(config.IdentitySessionToken) != 0 || config.IdentityAssignment != nil
	if identityEnrollment {
		if len(config.IdentitySessionToken) < 32 || config.IdentityAssignment == nil || len(config.EnrollmentToken) != 0 {
			return errors.New("Worker identity session configuration is invalid")
		}
	} else {
		key, err := uuid.Parse(config.EnrollmentIdempotencyKey)
		if err != nil || key == uuid.Nil || len(config.EnrollmentToken) < 32 {
			return errors.New("Worker token enrollment configuration is invalid")
		}
	}
	if runner.Control == nil || runner.Objects == nil || runner.Registry == nil ||
		config.EnrollmentExpectedRevision < 1 || config.LeaseDuration < 5*time.Second || config.LeaseDuration > 30*time.Minute || config.LeaseDuration%time.Second != 0 {
		return errors.New("Worker runner configuration is invalid")
	}
	return nil
}

func validateAssignment(assignment *agentv1.WorkerAssignment, config Config, leased bool) error {
	if assignment == nil || assignment.GetDeploymentId() != config.DeploymentID || assignment.GetWorkerId() != config.WorkerID || assignment.GetRevision() < 1 ||
		assignment.GetRecipeBundle() == nil || assignment.GetExecutionBundle() == nil || len(assignment.GetRecipeBundle().GetSha256()) != sha256.Size ||
		len(assignment.GetExecutionBundle().GetSha256()) != sha256.Size || !validS3ObjectRef(assignment.GetRecipeBundle().GetS3Ref()) ||
		!validS3ObjectRef(assignment.GetExecutionBundle().GetS3Ref()) || assignment.GetExecutionTimeoutSeconds() == 0 || assignment.GetExecutionTimeoutSeconds() > 604800 ||
		assignment.GetAccess() == nil {
		return errors.New("Worker assignment is invalid")
	}
	if leased && (assignment.GetLeaseEpoch() < 1 || assignment.GetLeaseExpiresAt() == nil || assignment.GetLeaseExpiresAt().AsTime().Before(time.Now().UTC())) {
		return errors.New("Worker lease assignment is invalid or expired")
	}
	return nil
}

func validS3ObjectRef(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.Scheme == "s3" && parsed.Host != "" && parsed.Path != "" && !strings.HasSuffix(parsed.Path, "/") &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func scopedObjectRef(access *agentv1.WorkerAccessScope, checkpoint bool, name string) (string, error) {
	if access == nil || access.GetArtifactBucket() == "" || !actionIDPattern.MatchString(strings.TrimSuffix(name, ".json")) {
		return "", errors.New("Worker output scope is invalid")
	}
	prefix := access.GetArtifactPrefix()
	if checkpoint {
		prefix = access.GetCheckpointPrefix()
	}
	if prefix == "" || strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "..") {
		return "", errors.New("Worker output prefix is invalid")
	}
	return "s3://" + access.GetArtifactBucket() + "/" + prefix + name, nil
}

func scopedCheckpointRef(access *agentv1.WorkerAccessScope, checkpoint checkpointV1, digest [sha256.Size]byte) (string, error) {
	if access == nil || access.GetArtifactBucket() == "" || checkpoint.Attempt < 1 || checkpoint.LeaseEpoch < 1 || checkpoint.ActionIndex < 0 ||
		!actionIDPattern.MatchString(checkpoint.ActionID) {
		return "", errors.New("Worker checkpoint scope is invalid")
	}
	prefix := access.GetCheckpointPrefix()
	if prefix == "" || strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "..") {
		return "", errors.New("Worker checkpoint prefix is invalid")
	}
	name := fmt.Sprintf("checkpoint-a%d-e%d-i%d-%s.json", checkpoint.Attempt, checkpoint.LeaseEpoch, checkpoint.ActionIndex, hex.EncodeToString(digest[:]))
	return "s3://" + access.GetArtifactBucket() + "/" + prefix + name, nil
}

func checkpointRefWithinScope(access *agentv1.WorkerAccessScope, reference string) bool {
	if access == nil || access.GetArtifactBucket() == "" {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil || parsed.Scheme != "s3" || parsed.Host != access.GetArtifactBucket() || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	prefix := access.GetCheckpointPrefix()
	if prefix == "" || strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "..") {
		return false
	}
	key := strings.TrimPrefix(parsed.Path, "/")
	name := strings.TrimPrefix(key, prefix)
	return key != name && name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..")
}

type leaseState struct {
	mu            sync.Mutex
	control       ControlClient
	token         []byte
	deploymentID  string
	workerID      string
	epoch         int64
	revision      int64
	leaseDuration time.Duration
	retryDelay    time.Duration
}

func (state *leaseState) heartbeatLoop(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := state.heartbeat(ctx); err != nil {
				return err
			}
		}
	}
}

func (state *leaseState) heartbeat(ctx context.Context) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	request := &agentv1.HeartbeatRequest{
		DeploymentId: state.deploymentID, WorkerId: state.workerID, LeaseEpoch: state.epoch,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: state.revision, LeaseDurationSeconds: int32(state.leaseDuration / time.Second),
	}
	response, err := retryCall(ctx, state.retryDelay, func() (*agentv1.HeartbeatResponse, error) {
		return state.control.Heartbeat(ctx, state.token, request)
	})
	if err != nil {
		return err
	}
	if response.GetLeaseEpoch() != state.epoch || response.GetRevision() <= state.revision {
		return errors.New("Worker heartbeat returned an invalid fence")
	}
	state.revision = response.GetRevision()
	if response.GetCancellationRequested() {
		return ErrCancellationRequested
	}
	return nil
}

func (state *leaseState) recordCheckpoint(ctx context.Context, ref string) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	request := &agentv1.WorkerControlServiceRecordEvidenceRequest{
		DeploymentId: state.deploymentID, WorkerId: state.workerID, LeaseEpoch: state.epoch,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: state.revision,
		Kind: agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_CHECKPOINT, Ref: ref,
	}
	response, err := retryCall(ctx, state.retryDelay, func() (*agentv1.WorkerControlServiceRecordEvidenceResponse, error) {
		return state.control.RecordEvidence(ctx, state.token, request)
	})
	if err != nil {
		return err
	}
	if response.GetRevision() <= state.revision {
		return errors.New("Worker checkpoint returned an invalid revision")
	}
	state.revision = response.GetRevision()
	return nil
}

func (state *leaseState) complete(ctx context.Context, outcome agentv1.WorkerOutcome, resultRef string) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	request := &agentv1.WorkerControlServiceCompleteRequest{
		DeploymentId: state.deploymentID, WorkerId: state.workerID, LeaseEpoch: state.epoch,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: state.revision, Outcome: outcome, ResultRef: resultRef,
	}
	response, err := retryCall(ctx, state.retryDelay, func() (*agentv1.WorkerControlServiceCompleteResponse, error) {
		return state.control.Complete(ctx, state.token, request)
	})
	if err != nil {
		return err
	}
	if response.GetRevision() <= state.revision {
		return errors.New("Worker completion returned an invalid revision")
	}
	state.revision = response.GetRevision()
	return nil
}

func retryCall[T any](ctx context.Context, delay time.Duration, call func() (T, error)) (T, error) {
	var zero T
	for attempt := 0; attempt < 3; attempt++ {
		result, err := call()
		if err == nil {
			return result, nil
		}
		code := status.Code(err)
		if ctx.Err() != nil || (code != codes.Unavailable && code != codes.DeadlineExceeded) || attempt == 2 {
			return zero, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, errors.New("Worker retry exhausted")
}

func (runner Runner) retryDelay() time.Duration {
	if runner.RetryDelay <= 0 {
		return 250 * time.Millisecond
	}
	return runner.RetryDelay
}

func (runner Runner) heartbeatInterval(leaseDuration time.Duration) time.Duration {
	if runner.HeartbeatInterval > 0 && runner.HeartbeatInterval < leaseDuration {
		return runner.HeartbeatInterval
	}
	return leaseDuration / 3
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
