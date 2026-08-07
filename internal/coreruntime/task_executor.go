package coreruntime

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
)

type TaskExecutor struct {
	profiles          ProfileResolver
	factory           ClientFactory
	ledger            coretask.AgentLedgerRepository
	tools             ToolDispatcher
	knowledge         PinnedKnowledgeResolver
	attachments       PinnedAttachmentResolver
	skillInstructions SkillInstructionResolver
	mu                sync.RWMutex
	handlers          map[coretask.TaskKind]TaskHandler
	workload          *coreworkload.Handler
}

// SnapshotProfileResolver reconstructs a provider client from an immutable
// task snapshot and a protected secret reference. Implementations must never
// expose the secret through task events or results.
type SnapshotProfileResolver interface {
	ResolveExecutionProfile(context.Context, coretask.ModelProfileSnapshot) (coremodel.Profile, error)
}

// ToolDispatcher is the narrow runtime boundary for already-installed MCP or
// Skill tools. It does not expose extension implementation details here.
type ToolDispatcher interface {
	DispatchTool(context.Context, ToolInvocation) (ToolResult, error)
}

type ToolInvocation struct {
	TaskID, CallID, Name string
	Attempt, Round       uint32
	Arguments            json.RawMessage
	ExtensionDigest      string
	ExtensionVersionID   string
	InstallationID       string
	ExtensionKind        coretask.ExtensionKind
	ArtifactDigest       string
	ToolSchemaDigest     string
}
type ToolResult struct {
	Content string
	JSON    json.RawMessage
}

type PinnedKnowledgeResolver interface {
	ResolvePinnedKnowledge(context.Context, []coretask.KnowledgeExecutionSnapshot) (string, error)
}

// GoalAwarePinnedKnowledgeResolver is the production form which receives the
// task goal so retrieval is bound to the exact queued task input.
type GoalAwarePinnedKnowledgeResolver interface {
	ResolvePinnedKnowledgeForGoal(context.Context, string, []coretask.KnowledgeExecutionSnapshot) (string, error)
}
type PinnedAttachmentResolver interface {
	ResolvePinnedAttachment(context.Context, coretask.AttachmentDescriptor) (string, error)
}
type SkillInstructionResolver interface {
	ResolveSkillInstructions(context.Context, coretask.ExtensionExecutionSnapshot) (string, error)
}

var ErrToolUncertain = errors.New("tool_uncertain")

type ManagedOutcome struct {
	Result        coretask.Result
	Err           error
	TerminalOwned bool
	Fence         *coretask.Fence
}

type TaskHandler func(context.Context, coretask.Task) ManagedOutcome

func NewTaskExecutor(profiles ProfileResolver, factory ClientFactory) (*TaskExecutor, error) {
	if profiles == nil {
		return nil, errors.New("profile resolver is required")
	}
	return &TaskExecutor{profiles: profiles, factory: adaptClientFactory(factory), handlers: make(map[coretask.TaskKind]TaskHandler)}, nil
}

func (e *TaskExecutor) SetAgentLedger(ledger coretask.AgentLedgerRepository) { e.ledger = ledger }
func (e *TaskExecutor) SetToolDispatcher(dispatcher ToolDispatcher)          { e.tools = dispatcher }
func (e *TaskExecutor) SetPinnedContextResolvers(k PinnedKnowledgeResolver, a PinnedAttachmentResolver) {
	e.knowledge, e.attachments = k, a
}
func (e *TaskExecutor) SetKnowledgeResolver(k PinnedKnowledgeResolver)   { e.knowledge = k }
func (e *TaskExecutor) SetAttachmentResolver(a PinnedAttachmentResolver) { e.attachments = a }
func (e *TaskExecutor) SetSkillInstructionResolver(s SkillInstructionResolver) {
	e.skillInstructions = s
}

// SetWorkloadHandler wires the fenced Core Runner/AWS workload domain
// handler. The handler owns the operation terminal transition; the generic
// task worker must not write a second terminal state.
func (e *TaskExecutor) SetWorkloadHandler(h *coreworkload.Handler) { e.workload = h }

func (e *TaskExecutor) RegisterHandler(kind coretask.TaskKind, handler TaskHandler) error {
	if (kind != coretask.TaskKindExtension && kind != coretask.TaskKindConversationTool && kind != coretask.TaskKindKnowledgeIndex && kind != coretask.TaskKindAWSChange && kind != coretask.TaskKindWorkload && kind != coretask.TaskKindCloudWorker && kind != coretask.TaskKindExecutionV2Run) || handler == nil {
		return errors.New("invalid task handler")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.handlers[kind]; exists {
		return errors.New("task handler already registered")
	}
	e.handlers[kind] = handler
	return nil
}

func (e *TaskExecutor) ExecuteManaged(ctx context.Context, task coretask.Task) (ManagedOutcome, error) {
	execCtx, cancel := taskExecutionContext(ctx, task)
	defer cancel()
	if err := execCtx.Err(); err != nil {
		return ManagedOutcome{Err: err}, nil
	}
	kind := task.Spec.Kind
	if kind == "" {
		kind = coretask.TaskKindAgent
	}
	if kind != coretask.TaskKindAgent {
		if kind == coretask.TaskKindWorkload && e.workload != nil {
			return e.executeWorkload(execCtx, task), nil
		}
		e.mu.RLock()
		h := e.handlers[kind]
		e.mu.RUnlock()
		if h == nil {
			return ManagedOutcome{}, errors.New("task handler is not registered")
		}
		outcome := h(execCtx, task)
		// A generic handler cannot win a deadline race merely by returning a
		// result after its context expired. Domain-owned terminal transitions
		// remain authoritative because they already fenced the task atomically.
		if !outcome.TerminalOwned {
			if err := execCtx.Err(); err != nil {
				outcome.Result = coretask.Result{}
				outcome.Err = err
			}
		}
		return outcome, nil
	}
	result, err, fence := e.executeAgentManaged(execCtx, task)
	return ManagedOutcome{Result: result, Err: err, Fence: fence}, nil
}

func (e *TaskExecutor) executeWorkload(ctx context.Context, task coretask.Task) ManagedOutcome {
	p := task.Spec.Payload.Workload
	if p == nil {
		return ManagedOutcome{Err: errors.New("workload task payload is missing"), TerminalOwned: true}
	}
	if task.Lease == nil || task.Lease.TaskID != task.ID || task.Attempt == 0 || task.LeaseEpoch == 0 || task.Revision == 0 || task.Lease.Attempt != task.Attempt || task.Lease.Epoch != task.LeaseEpoch || task.Lease.ExpiresAt.IsZero() || !task.Lease.ExpiresAt.After(time.Now().UTC()) {
		return ManagedOutcome{Err: coretask.ErrLeaseConflict, TerminalOwned: true}
	}
	fence := coreworkload.TaskFence{TaskID: task.ID, Holder: task.Lease.Holder, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, Revision: task.Revision, ExpiresAt: task.Lease.ExpiresAt}
	current, err := e.workload.GetOperation(ctx, p.OperationID)
	if err != nil || current.TaskID != fence.TaskID || current.WorkloadID != p.WorkloadID || current.PlanID != p.PlanID || current.PlanRevision != p.PlanRevision || current.PlanDigest != p.PlanDigest || current.TargetKind != coreworkload.TargetKind(p.TargetKind) || current.ConfirmationID != p.ConfirmationID {
		if err == nil {
			err = coreworkload.ErrStale
		}
		return ManagedOutcome{Err: err}
	}
	if current.Status == coreworkload.OperationRunning {
		op, recoverErr := e.workload.Recover(ctx, p.OperationID, fence)
		if recoverErr != nil {
			return ManagedOutcome{Err: recoverErr, TerminalOwned: true}
		}
		return ManagedOutcome{TerminalOwned: isWorkloadTerminal(op.Status)}
	}
	op, err := e.workload.Handle(ctx, p.OperationID, p.PlanDigest, current.Revision, fence)
	if err != nil {
		if current, getErr := e.workload.GetOperation(ctx, p.OperationID); getErr == nil {
			switch current.Status {
			case coreworkload.OperationSucceeded, coreworkload.OperationFailed, coreworkload.OperationRejected, coreworkload.OperationExpired, coreworkload.OperationCanceled, coreworkload.OperationUncertain:
				return ManagedOutcome{Err: err, TerminalOwned: true}
			}
		}
		return ManagedOutcome{Err: err}
	}
	return ManagedOutcome{TerminalOwned: isWorkloadTerminal(op.Status)}
}

func isWorkloadTerminal(status coreworkload.OperationStatus) bool {
	switch status {
	case coreworkload.OperationSucceeded, coreworkload.OperationFailed, coreworkload.OperationRejected, coreworkload.OperationExpired, coreworkload.OperationCanceled, coreworkload.OperationUncertain:
		return true
	default:
		return false
	}
}

func taskExecutionContext(ctx context.Context, task coretask.Task) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Cloud Worker runtime and cleanup deadlines belong to its durable domain
	// controller.  Applying the generic CoreTask deadline here can cancel the
	// controller after AWS mutation but before resource destruction, leaving no
	// handler able to finish cleanup, projection, or the completion outbox.
	// Parent cancellation and lease loss still cancel this context normally.
	if task.Spec.Kind == coretask.TaskKindCloudWorker {
		return context.WithCancel(ctx)
	}
	if task.ExecutionDeadlineAt != nil {
		return context.WithDeadline(ctx, task.ExecutionDeadlineAt.UTC())
	}
	if task.Spec.TimeoutSeconds > 0 {
		return context.WithTimeout(ctx, time.Duration(task.Spec.TimeoutSeconds)*time.Second)
	}
	return context.WithCancel(ctx)
}

func (e *TaskExecutor) Execute(ctx context.Context, task coretask.Task) (coretask.Result, error) {
	outcome, err := e.ExecuteManaged(ctx, task)
	if err != nil {
		return coretask.Result{}, err
	}
	return outcome.Result, outcome.Err
}

func (e *TaskExecutor) executeAgent(ctx context.Context, task coretask.Task) (coretask.Result, error) {
	execCtx, cancel := taskExecutionContext(ctx, task)
	defer cancel()
	result, err, _ := e.executeAgentManaged(execCtx, task)
	return result, err
}

func (e *TaskExecutor) executeAgentManaged(ctx context.Context, task coretask.Task) (coretask.Result, error, *coretask.Fence) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return coretask.Result{}, err, nil
	}
	result, err, fence := e.executeBoundedAgent(ctx, task)
	return result, err, fence
}
