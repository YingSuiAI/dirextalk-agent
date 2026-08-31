// Package sshflow connects a confirmed Cloud Worker task to the small
// ephemeral-SSH provider. It deliberately knows nothing about S3, KMS,
// Worker Control, model relays, custom images, or deployment-time bindings.
package sshflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

var (
	ErrInvalid            = errors.New("invalid SSH Worker flow")
	ErrExecutionUncertain = errors.New("SSH Worker execution outcome is uncertain")
)

// Run is the exact durable authority loaded after confirmation consumption.
// ModelSnapshot is the secret-bearing snapshot sealed with the original turn;
// it must never be logged or serialized by an Executor.
type Run struct {
	Task              coretask.Task
	Plan              cloudworker.Plan
	Execution         cloudworker.Execution
	ConfirmationProof string
	ModelSnapshot     coremodel.ExecutionSnapshot
}

type Request struct {
	OwnerID           string
	AccountGeneration uint64
	TurnID            string
	ExecutionID       string
	ServerName        string
	Objective         string
	WorkloadKind      cloudworker.WorkloadKind
	Service           *cloudworker.ServiceSpec
	AWS               cloudworker.AWSBinding
	GitHubBinding     *cloudworker.GitHubBinding
	Compute           cloudworker.ComputeSpec
	Limits            cloudworker.Limits
	InputManifest     cloudworker.InputManifest
	WorkspaceMode     cloudworker.WorkspaceMode
	ConfirmationProof string
	ModelSnapshot     coremodel.ExecutionSnapshot
	ReuseOnly         bool
	ReuseWorkerID     string
	ReportProgress    func(context.Context, string, string) error
}

// Artifact is immutable metadata for bytes already collected under the
// Agent data root. RelativePath is never supplied by the model or Worker.
type Artifact struct {
	ArtifactID   string `json:"artifact_id"`
	ExecutionID  string `json:"execution_id"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	MediaType    string `json:"media_type"`
	RelativePath string `json:"relative_path"`
	SizeBytes    int64  `json:"size_bytes"`
	SHA256       string `json:"sha256"`
}

type Result struct {
	Summary         string
	ExitCode        int
	WorkerID        string
	Artifacts       []Artifact
	AppliedSteerIDs []string
}

type Executor interface {
	// Execute obtains or reuses one confirmed persistent Worker and returns after
	// the output has been copied back. Worker lifecycle is independent of this
	// task's terminal state; successful tasks intentionally retain the Worker.
	Execute(context.Context, Request) (Result, error)
}

type Store interface {
	Begin(context.Context, coretask.Task) (Run, error)
	Progress(context.Context, *Run, string, string) error
	Complete(context.Context, Run, Result) error
	Fail(context.Context, Run, Result, string, string) error
}

type Handler struct {
	store    Store
	executor Executor
}

func NewHandler(store Store, executor Executor) (*Handler, error) {
	if store == nil || executor == nil {
		return nil, ErrInvalid
	}
	return &Handler{store: store, executor: executor}, nil
}

func (handler *Handler) Handle(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
	if handler == nil || handler.store == nil || handler.executor == nil || ctx == nil ||
		task.Spec.Kind != coretask.TaskKindCloudWorker || task.Spec.Payload.CloudWorker == nil ||
		task.Status != coretask.StatusRunning || task.Lease == nil {
		return coreruntime.ManagedOutcome{Err: ErrInvalid}
	}
	run, err := handler.store.Begin(ctx, task)
	if err != nil {
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
	}
	if err = handler.store.Progress(ctx, &run, "preparing_environment", "Preparing Worker environment"); err != nil {
		result := Result{WorkerID: run.Plan.ExecutionID}
		return handler.fail(ctx, run, result, err, "ssh_worker_progress_failed", "Worker progress could not be persisted")
	}
	result, executeErr := handler.executor.Execute(ctx, Request{
		OwnerID: run.Plan.OwnerID, AccountGeneration: run.Plan.AccountGeneration,
		TurnID: run.Plan.TurnID, ExecutionID: run.Plan.ExecutionID, ServerName: run.Plan.ServerName, Objective: run.Plan.Objective,
		WorkloadKind: run.Plan.WorkloadKind, Service: run.Plan.Service,
		AWS: run.Plan.AWS, Compute: run.Plan.Compute,
		GitHubBinding: run.Plan.GitHubBinding,
		Limits:        run.Plan.Limits, InputManifest: run.Plan.InputManifest,
		WorkspaceMode:     run.Plan.WorkspaceMode,
		ConfirmationProof: run.ConfirmationProof, ModelSnapshot: run.ModelSnapshot,
		ReuseOnly: run.Plan.PersistentWorkerReuse, ReuseWorkerID: run.Plan.ReuseWorkerID,
		ReportProgress: func(progressCtx context.Context, phase, message string) error {
			progressErr := handler.store.Progress(progressCtx, &run, phase, message)
			if errors.Is(progressErr, cloudworker.ErrLeaseConflict) {
				return context.Canceled
			}
			return progressErr
		},
	})
	if executeErr != nil {
		// A detached remote process may still be running. Its durable task and
		// busy Worker lease must remain available for later observation instead
		// of being terminalized or automatically replayed.
		if errors.Is(executeErr, ErrExecutionUncertain) {
			progressCtx, cancel := detachedCommitContext(ctx)
			defer cancel()
			progressErr := handler.store.Progress(progressCtx, &run, "worker_outcome_uncertain", "Worker outcome is uncertain; reconciling safely")
			return coreruntime.ManagedOutcome{Err: errors.Join(executeErr, progressErr), TerminalOwned: true}
		}
		if strings.TrimSpace(result.WorkerID) == "" {
			result.WorkerID = run.Plan.ExecutionID
		}
		code := "ssh_worker_failed"
		summary := boundedSummary(executeErr.Error())
		var quotaFailure *sshworker.QuotaError
		if errors.As(executeErr, &quotaFailure) {
			code = quotaFailure.FailureCode()
			summary = boundedSummary(quotaFailure.UserSummary())
		}
		if summary == "" {
			summary = code
		}
		return handler.fail(ctx, run, result, executeErr, code, summary)
	}
	if strings.TrimSpace(result.Summary) == "" || strings.TrimSpace(result.WorkerID) == "" {
		if strings.TrimSpace(result.WorkerID) == "" {
			result.WorkerID = run.Plan.ExecutionID
		}
		const summary = "SSH Worker returned an invalid result"
		return handler.fail(ctx, run, result, ErrInvalid, "ssh_worker_invalid_result", summary)
	}
	commitCtx, cancel := detachedCommitContext(ctx)
	defer cancel()
	if err = handler.store.Complete(commitCtx, run, result); err != nil {
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
	}
	return coreruntime.ManagedOutcome{Result: coretask.Result{Text: result.Summary, Summary: result.Summary}, TerminalOwned: true}
}

func (handler *Handler) TaskHandler() coreruntime.TaskHandler { return handler.Handle }

func (handler *Handler) fail(ctx context.Context, run Run, result Result, cause error, code, summary string) coreruntime.ManagedOutcome {
	commitCtx, cancel := detachedCommitContext(ctx)
	defer cancel()
	if err := handler.store.Fail(commitCtx, run, result, code, summary); err != nil {
		// If terminal persistence lost a race or its response, leave a visible
		// recovery event when the same domain fence is still live. The task is
		// then reclaimed safely; provider/tool execution is not retried here.
		progressErr := handler.store.Progress(commitCtx, &run, "finalizing_failure", "Worker failed; finalizing the failure safely")
		return coreruntime.ManagedOutcome{Err: errors.Join(cause, err, progressErr), TerminalOwned: true}
	}
	return coreruntime.ManagedOutcome{Err: cause, TerminalOwned: true}
}

func detachedCommitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func boundedSummary(value string) string {
	value = strings.TrimSpace(value)
	if len([]byte(value)) <= coretask.MaxSummaryBytes {
		return value
	}
	var bounded strings.Builder
	bounded.Grow(coretask.MaxSummaryBytes)
	for _, current := range value {
		width := len(string(current))
		if bounded.Len()+width > coretask.MaxSummaryBytes {
			break
		}
		bounded.WriteRune(current)
	}
	return bounded.String()
}
