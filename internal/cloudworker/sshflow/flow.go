// Package sshflow connects a confirmed Cloud Worker task to the small
// ephemeral-SSH provider. It deliberately knows nothing about S3, KMS,
// Worker Control, model relays, custom images, or deployment-time bindings.
package sshflow

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

var ErrInvalid = errors.New("invalid SSH Worker flow")

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
	ExecutionID       string
	Objective         string
	AWS               cloudworker.AWSBinding
	Compute           cloudworker.ComputeSpec
	ConfirmationProof string
	ModelSnapshot     coremodel.ExecutionSnapshot
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
	Summary   string
	ExitCode  int
	WorkerID  string
	Artifacts []Artifact
}

type Executor interface {
	// Execute obtains or reuses one confirmed persistent Worker and returns after
	// the output has been copied back. Worker lifecycle is independent of this
	// task's terminal state; successful tasks intentionally retain the Worker.
	Execute(context.Context, Request) (Result, error)
}

type Store interface {
	Begin(context.Context, coretask.Task) (Run, error)
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
		return coreruntime.ManagedOutcome{Err: err}
	}
	result, executeErr := handler.executor.Execute(ctx, Request{
		OwnerID: run.Plan.OwnerID, AccountGeneration: run.Plan.AccountGeneration,
		ExecutionID: run.Plan.ExecutionID, Objective: run.Plan.Objective,
		AWS: run.Plan.AWS, Compute: run.Plan.Compute,
		ConfirmationProof: run.ConfirmationProof, ModelSnapshot: run.ModelSnapshot,
	})
	if executeErr != nil {
		code := "ssh_worker_failed"
		summary := strings.TrimSpace(executeErr.Error())
		if summary == "" {
			summary = code
		}
		if err = handler.store.Fail(ctx, run, result, code, summary); err != nil {
			return coreruntime.ManagedOutcome{Err: errors.Join(executeErr, err)}
		}
		return coreruntime.ManagedOutcome{Err: executeErr, TerminalOwned: true}
	}
	if strings.TrimSpace(result.Summary) == "" || strings.TrimSpace(result.WorkerID) == "" {
		return coreruntime.ManagedOutcome{Err: ErrInvalid}
	}
	if err = handler.store.Complete(ctx, run, result); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	return coreruntime.ManagedOutcome{Result: coretask.Result{Text: result.Summary, Summary: result.Summary}, TerminalOwned: true}
}

func (handler *Handler) TaskHandler() coreruntime.TaskHandler { return handler.Handle }
