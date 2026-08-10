package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/google/uuid"
)

const (
	defaultChallengeReadyTimeout        = 2 * time.Minute
	defaultChallengeReadyInitialBackoff = 250 * time.Millisecond
	defaultChallengeReadyMaximumBackoff = 5 * time.Second
)

type challengeRetryPolicy struct {
	timeout        time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
}

type WorkflowConfig struct {
	Bootstrap BootstrapBinding
	Identity  IdentitySource
	Proofs    ProofGenerator
	Control   ControlClient
	Executor  TaskExecutor
	Topology  RuntimeTopologySource
	Uploader  ResultUploader
	Now       func() time.Time
}

type Workflow struct {
	bootstrap             BootstrapBinding
	identity              IdentitySource
	proofs                ProofGenerator
	control               ControlClient
	executor              TaskExecutor
	topology              RuntimeTopologySource
	uploader              ResultUploader
	now                   func() time.Time
	challengeRetry        challengeRetryPolicy
	waitForChallengeRetry func(context.Context, time.Duration) error
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.Bootstrap.Validate() != nil || config.Identity == nil || config.Proofs == nil ||
		config.Control == nil || config.Executor == nil || config.Topology == nil || config.Uploader == nil {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Workflow{
		bootstrap: config.Bootstrap, identity: config.Identity, proofs: config.Proofs,
		control: config.Control, executor: config.Executor, topology: config.Topology, uploader: config.Uploader,
		now: config.Now,
		challengeRetry: challengeRetryPolicy{
			timeout:        defaultChallengeReadyTimeout,
			initialBackoff: defaultChallengeReadyInitialBackoff,
			maximumBackoff: defaultChallengeReadyMaximumBackoff,
		},
		waitForChallengeRetry: waitForChallengeRetry,
	}, nil
}

// Run performs one claim and one Pi task. It never retries a mutation whose
// external outcome is unknown and never falls back to local Agent execution.
func (workflow *Workflow) Run(ctx context.Context) error {
	if workflow == nil || ctx == nil {
		return ErrInvalid
	}
	challengeRequest := workflow.bootstrap.ChallengeRequest(uuid.NewString())
	challenge, err := workflow.issueIdentityChallenge(ctx, challengeRequest)
	if err != nil {
		return err
	}
	if !validChallenge(challenge, workflow.bootstrap, workflow.now()) {
		return ErrInvalid
	}
	binding, err := workflow.bootstrap.Bind(challenge.Fence)
	if err != nil {
		return err
	}
	identity, err := workflow.revalidateIdentity(ctx)
	if err != nil {
		return err
	}
	proof, err := workflow.proofs.Generate(ctx, challenge.Nonce, binding, identity)
	identity.Destroy()
	if err != nil {
		proof.Destroy()
		return ErrIdentityChanged
	}
	if !workflow.now().Before(challenge.ExpiresAt) {
		proof.Destroy()
		return ErrExpired
	}
	claimed, err := workflow.control.Claim(
		ctx, binding.Fence(), challenge.ChallengeID, &proof,
	)
	proof.Destroy()
	if err != nil {
		claimed.Destroy()
		return controlError(err)
	}
	defer claimed.Destroy()
	if err := validateClaimedTask(claimed, binding, workflow.now()); err != nil {
		return err
	}

	runCtx, cancelRun := context.WithDeadline(ctx, claimed.NotAfter)
	defer cancelRun()
	if heartbeatErr := workflow.heartbeatOnce(runCtx, claimed, 1); heartbeatErr != nil {
		return heartbeatTerminalError(heartbeatErr, runCtx.Err())
	}
	heartbeatCtx, stopHeartbeat := context.WithCancel(runCtx)
	heartbeatFailure := make(chan error, 1)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		heartbeatFailure <- workflow.heartbeatLoop(heartbeatCtx, cancelRun, claimed, 1)
	}()
	stopAndReadHeartbeat := func() error {
		stopHeartbeat()
		<-heartbeatDone
		return <-heartbeatFailure
	}

	result, runErr := workflow.executor.Run(runCtx, claimed)
	defer cloudruntime.DestroyResult(&result)
	if runErr != nil {
		if runCtx.Err() != nil {
			heartbeatErr := stopAndReadHeartbeat()
			return heartbeatTerminalError(heartbeatErr, runCtx.Err())
		}
		identityErr := workflow.checkIdentity(runCtx)
		heartbeatErr := stopAndReadHeartbeat()
		if heartbeatErr != nil && !errors.Is(heartbeatErr, context.Canceled) {
			return heartbeatTerminalError(heartbeatErr, runCtx.Err())
		}
		if identityErr != nil {
			return identityErr
		}
		if runCtx.Err() != nil {
			return heartbeatTerminalError(heartbeatErr, runCtx.Err())
		}
		failureCode := runtimeFailureCode(runErr)
		terminalCtx, cancelTerminal := context.WithTimeout(runCtx, claimed.HeartbeatInterval)
		failErr := workflow.control.Fail(terminalCtx, FailRequest{
			Fence: binding.Fence(), SessionID: claimed.SessionID,
			SessionToken: claimed.SessionToken, Code: failureCode,
			IdempotencyKey: uuid.NewString(),
		})
		cancelTerminal()
		if failErr != nil {
			return controlError(failErr)
		}
		return cloudruntime.ErrExecution
	}
	topology, topologyErr := workflow.topology.TerminalRuntimeTopology()
	if topologyErr != nil || topology.ValidateTerminal() != nil ||
		topology.ExecutionID != binding.ExecutionID || topology.TaskID != binding.TaskID ||
		topology.Attempt != binding.Attempt || topology.LeaseEpoch != binding.LeaseEpoch {
		_ = stopAndReadHeartbeat()
		return cloudruntime.ErrExecution
	}

	if err := workflow.checkIdentity(runCtx); err != nil {
		_ = stopAndReadHeartbeat()
		return err
	}
	manifestClaim, err := workflow.uploader.Upload(runCtx, claimed, result)
	if err != nil {
		heartbeatErr := stopAndReadHeartbeat()
		if heartbeatErr != nil && !errors.Is(heartbeatErr, context.Canceled) {
			return heartbeatTerminalError(heartbeatErr, runCtx.Err())
		}
		return err
	}
	if runCtx.Err() != nil {
		heartbeatErr := stopAndReadHeartbeat()
		return heartbeatTerminalError(heartbeatErr, runCtx.Err())
	}
	identityErr := workflow.checkIdentity(runCtx)
	heartbeatErr := stopAndReadHeartbeat()
	if heartbeatErr != nil && !errors.Is(heartbeatErr, context.Canceled) {
		return heartbeatTerminalError(heartbeatErr, runCtx.Err())
	}
	if identityErr != nil {
		return identityErr
	}
	if runCtx.Err() != nil {
		return heartbeatTerminalError(heartbeatErr, runCtx.Err())
	}
	terminalCtx, cancelTerminal := context.WithTimeout(runCtx, claimed.HeartbeatInterval)
	err = workflow.control.Complete(terminalCtx, CompleteRequest{
		Fence: binding.Fence(), SessionID: claimed.SessionID,
		SessionToken: claimed.SessionToken, ManifestClaim: manifestClaim, RuntimeTopology: topology,
		IdempotencyKey: uuid.NewString(),
	})
	cancelTerminal()
	if err != nil {
		return controlError(err)
	}
	return nil
}

// issueIdentityChallenge absorbs only the narrow EC2-started-before-dispatch-
// publication race. Every attempt revalidates the immutable instance identity
// and reuses the same idempotency key. Claim remains a separate single-shot
// mutation once a challenge is issued.
func (workflow *Workflow) issueIdentityChallenge(
	ctx context.Context,
	request ChallengeRequest,
) (Challenge, error) {
	policy := workflow.challengeRetry
	if request.Validate() != nil || policy.timeout <= 0 || policy.initialBackoff <= 0 ||
		policy.maximumBackoff < policy.initialBackoff || workflow.waitForChallengeRetry == nil {
		return Challenge{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Challenge{}, controlError(err)
	}

	retryCtx, cancel := context.WithTimeout(ctx, policy.timeout)
	defer cancel()
	deadline := workflow.now().Add(policy.timeout)
	backoff := policy.initialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return Challenge{}, controlError(err)
		}
		if !workflow.now().Before(deadline) {
			return Challenge{}, ErrNotReady
		}
		if err := workflow.checkIdentity(retryCtx); err != nil {
			if ctx.Err() != nil {
				return Challenge{}, controlError(ctx.Err())
			}
			if retryCtx.Err() != nil {
				return Challenge{}, ErrNotReady
			}
			return Challenge{}, err
		}
		if err := ctx.Err(); err != nil {
			return Challenge{}, controlError(err)
		}
		if retryCtx.Err() != nil {
			return Challenge{}, ErrNotReady
		}
		challenge, err := workflow.control.IssueIdentityChallenge(retryCtx, request)
		if err == nil {
			if ctx.Err() != nil {
				return Challenge{}, controlError(ctx.Err())
			}
			if retryCtx.Err() != nil {
				return Challenge{}, ErrNotReady
			}
			return challenge, nil
		}
		if err := ctx.Err(); err != nil {
			return Challenge{}, controlError(err)
		}
		if retryCtx.Err() != nil {
			return Challenge{}, ErrNotReady
		}
		if !errors.Is(err, ErrNotReady) {
			return Challenge{}, controlError(err)
		}

		remaining := deadline.Sub(workflow.now())
		if remaining <= 0 {
			return Challenge{}, ErrNotReady
		}
		delay := min(backoff, remaining)
		if err := workflow.waitForChallengeRetry(retryCtx, delay); err != nil {
			if ctx.Err() != nil {
				return Challenge{}, controlError(ctx.Err())
			}
			if retryCtx.Err() != nil {
				return Challenge{}, ErrNotReady
			}
			return Challenge{}, controlError(err)
		}
		if backoff < policy.maximumBackoff {
			backoff = min(backoff*2, policy.maximumBackoff)
		}
	}
}

func waitForChallengeRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (workflow *Workflow) heartbeatLoop(
	ctx context.Context,
	cancelRun context.CancelFunc,
	claimed ClaimedTask,
	sequence uint64,
) error {
	ticker := time.NewTicker(claimed.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sequence++
			if err := workflow.heartbeatOnce(ctx, claimed, sequence); err != nil {
				if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
					return err
				}
				cancelRun()
				return err
			}
		}
	}
}

func (workflow *Workflow) heartbeatOnce(
	ctx context.Context,
	claimed ClaimedTask,
	sequence uint64,
) error {
	heartbeatCtx, cancelHeartbeat := context.WithTimeout(ctx, claimed.HeartbeatInterval)
	defer cancelHeartbeat()
	if !workflow.now().Before(claimed.NotAfter) {
		return ErrExpired
	}
	if err := workflow.checkIdentity(heartbeatCtx); err != nil {
		return err
	}
	response, err := workflow.control.Heartbeat(
		heartbeatCtx, claimed.Binding.Fence(), claimed.SessionID,
		claimed.SessionToken, sequence, uuid.NewString(),
	)
	if err != nil {
		// A successful run stops the heartbeat context while an RPC may still
		// be in flight. Preserve that local stop; active failures stay authoritative.
		if ctx.Err() != nil && stoppedHeartbeatError(err) {
			return ctx.Err()
		}
		return controlError(err)
	}
	if response.Sequence != sequence || response.NotAfter.IsZero() ||
		response.NotAfter.After(claimed.NotAfter) {
		return ErrInvalid
	}
	switch response.State {
	case LeaseActive:
		if !workflow.now().Before(response.NotAfter) {
			return ErrExpired
		}
		return nil
	case LeaseCanceled:
		return ErrCanceled
	case LeaseExpired:
		return ErrExpired
	default:
		return ErrInvalid
	}
}

func stoppedHeartbeatError(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrCanceled) ||
		errors.Is(err, ErrExpired)
}

func (workflow *Workflow) revalidateIdentity(ctx context.Context) (InstanceIdentity, error) {
	identity, err := workflow.identity.ReadIdentity(ctx)
	if err != nil {
		identity.Destroy()
		if ctx.Err() != nil {
			return InstanceIdentity{}, ctx.Err()
		}
		return InstanceIdentity{}, ErrUnavailable
	}
	if identity.AccountID != workflow.bootstrap.AccountID ||
		identity.Region != workflow.bootstrap.Region ||
		identity.InstanceID != workflow.bootstrap.InstanceID ||
		len(identity.Document) == 0 || len(identity.PKCS7) == 0 {
		identity.Destroy()
		return InstanceIdentity{}, ErrIdentityChanged
	}
	return identity, nil
}

func (workflow *Workflow) checkIdentity(ctx context.Context) error {
	identity, err := workflow.revalidateIdentity(ctx)
	identity.Destroy()
	return err
}

func validChallenge(
	challenge Challenge,
	binding BootstrapBinding,
	now time.Time,
) bool {
	return canonicalUUID(challenge.ChallengeID) && challenge.Nonce != "" &&
		len(challenge.Nonce) >= 32 && len(challenge.Nonce) <= 1024 &&
		challenge.Nonce == strings.TrimSpace(challenge.Nonce) &&
		!challenge.ExpiresAt.IsZero() && now.Before(challenge.ExpiresAt) &&
		challenge.Fence.Validate() == nil &&
		challenge.Fence.ExecutionID == binding.ExecutionID &&
		challenge.Fence.TaskID == binding.TaskID &&
		challenge.Fence.AccountGeneration == binding.AccountGeneration
}

func validateClaimedTask(task ClaimedTask, binding Binding, now time.Time) error {
	if task.Binding != binding || !canonicalUUID(task.SessionID) ||
		len(task.SessionToken) < 32 || len(task.SessionToken) > 4096 ||
		task.Task.Validate() != nil || task.Task.ExecutionID != binding.ExecutionID ||
		task.Task.TaskID != binding.TaskID ||
		task.Task.InputManifestSHA256 != binding.InputManifestSHA256 ||
		task.Task.ModelBindingSHA256 != binding.ModelBindingSHA256 ||
		task.ModelGrant.ValidateFor(task.Task, now) != nil ||
		cloudruntime.ValidateInputManifestJSON(
			task.InputManifestJSON, task.Task.InputManifestSHA256,
		) != nil ||
		task.ArtifactScope.Validate() != nil ||
		task.HeartbeatInterval < 100*time.Millisecond || task.HeartbeatInterval > time.Minute ||
		task.NotAfter.IsZero() || !now.Before(task.NotAfter) ||
		task.NotAfter.After(time.Unix(task.ModelGrant.ExpiresAtUnix, 0).UTC()) {
		return ErrInvalid
	}
	digest, err := task.Task.Digest()
	if err != nil || digest != binding.TaskSHA256 {
		return ErrInvalid
	}
	return nil
}

func runtimeFailureCode(err error) string {
	if failure, ok := cloudruntime.FailureOf(err); ok {
		return string(failure.Stage) + "_" + string(failure.Code)
	}
	return "runtime_failed"
}

func heartbeatTerminalError(heartbeatErr, runErr error) error {
	switch {
	case errors.Is(heartbeatErr, ErrCanceled):
		return ErrCanceled
	case errors.Is(heartbeatErr, ErrExpired), errors.Is(runErr, context.DeadlineExceeded):
		return ErrExpired
	case heartbeatErr != nil && !errors.Is(heartbeatErr, context.Canceled):
		return heartbeatErr
	case errors.Is(runErr, context.Canceled):
		return ErrCanceled
	default:
		return ErrUnavailable
	}
}

func controlError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return ErrCanceled
	case errors.Is(err, ErrCanceled), errors.Is(err, ErrExpired),
		errors.Is(err, ErrStaleLease), errors.Is(err, ErrInvalid):
		return err
	default:
		return fmt.Errorf("%w", ErrUnavailable)
	}
}
