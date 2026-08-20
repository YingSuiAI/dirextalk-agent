package coreconversation

// Durable conversation turns deliberately live beside the legacy Chat ledger.
// They use a separate request identity and lease so a caller can disconnect
// without transferring ownership of an accepted prompt to its gRPC context.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type TurnState string

const (
	TurnAccepted            TurnState = "accepted"
	TurnRunning             TurnState = "running"
	TurnWaitingConfirmation TurnState = "waiting_confirmation"
	TurnCompleted           TurnState = "completed"
	TurnCanceled            TurnState = "canceled"
	TurnFailed              TurnState = "failed"
)

type TurnEventKind string

const (
	TurnEventAccepted            TurnEventKind = "accepted"
	TurnEventStarted             TurnEventKind = "started"
	TurnEventDelta               TurnEventKind = "delta"
	TurnEventDone                TurnEventKind = "done"
	TurnEventError               TurnEventKind = "error"
	TurnEventCanceled            TurnEventKind = "canceled"
	TurnEventWaitingConfirmation TurnEventKind = "waiting_confirmation"
	TurnEventWorkerStatus        TurnEventKind = "worker_status"
	TurnEventWarning             TurnEventKind = "warning"
	TurnEventToolCall            TurnEventKind = "tool_call"
	TurnEventToolResult          TurnEventKind = "tool_result"
	TurnEventSteered             TurnEventKind = "steered"
)

const (
	MemoryRecallDegradedStatus = "memory_recall_degraded"
	MemoryRecallDegradedText   = "Long-term memory is temporarily unavailable; continuing this turn without it."
)

type Turn struct {
	ID                       string
	RequestID                string
	RequestFingerprint       string `json:"-"`
	OwnerID                  string `json:"-"`
	AccountGeneration        uint64 `json:"-"`
	ConversationID           string
	Prompt                   string
	ProfileID                string
	ExpectedRevision         *uint64
	Revision                 uint64
	State                    TurnState
	CancelRequested          bool
	CancelRequestID          string `json:"-"`
	CancelRequestFingerprint string `json:"-"`
	TerminalCode             string
	TerminalSummary          string
	Response                 *ChatResponse   `json:"-"`
	DispatchState            string          `json:"-"`
	DispatchEpoch            uint64          `json:"-"`
	DispatchResult           *ModelRunResult `json:"-"`
	ModelDispatchCount       uint32          `json:"-"`
	ModelActiveDuration      time.Duration   `json:"-"`
	ModelDispatchStartedAt   time.Time       `json:"-"`
	LastSequence             int64
	CreatedAt                time.Time
	UpdatedAt                time.Time
	ProfileSnapshot          coremodel.ExecutionSnapshot  `json:"-"`
	ProfileSnapshotDigest    string                       `json:"-"`
	ExtensionSnapshots       []ExtensionExecutionSnapshot `json:"-"`
	ExtensionSnapshotDigest  string                       `json:"-"`
	AttachmentSources        []TurnAttachment             `json:"-"`
	AttachmentSnapshotDigest string                       `json:"-"`
	RuntimeSnapshot          *TurnRuntimeSnapshot         `json:"-"`
}

type TurnEvent struct {
	TurnID            string
	Sequence          int64
	Revision          uint64
	Kind              TurnEventKind
	Text              string
	Message           *Message
	Response          *ChatResponse
	ToolCall          *ToolCall
	ToolResult        *ToolResult
	ConfirmationID    string
	ExecutionID       string
	Status            string
	Phase             string
	RelatedTaskIDs    []string
	RelatedPlanIDs    []string
	References        []Reference
	ErrorCode         string
	ErrorSummary      string
	FirstSequence     int64
	LastSequence      int64
	ReplayGap         bool
	MutationID        string
	ExpectedRevision  uint64
	AttachmentSources []TurnAttachment
	CreatedAt         time.Time
	Err               error `json:"-"`
}

// NewWaitingConfirmationTurnEvent is the sole content constructor for a
// durable confirmation wait. Quote/tool details live in their owning ledgers;
// this event carries only the common confirmation authority.
func NewWaitingConfirmationTurnEvent(confirmationID, executionID string) (TurnEvent, error) {
	event := TurnEvent{
		Kind:           TurnEventWaitingConfirmation,
		ConfirmationID: confirmationID,
		ExecutionID:    executionID,
		Status:         string(TurnWaitingConfirmation),
	}
	if err := event.ValidateWaitingConfirmationAuthority(); err != nil {
		return TurnEvent{}, err
	}
	return event, nil
}

// NewWorkerStatusTurnEvent projects one durable Cloud Worker lifecycle
// transition onto its originating turn. Worker details remain in Execution V2.
func NewWorkerStatusTurnEvent(executionID, status string) (TurnEvent, error) {
	event := TurnEvent{Kind: TurnEventWorkerStatus, ExecutionID: executionID, Status: status}
	if err := event.ValidateWorkerStatusAuthority(); err != nil {
		return TurnEvent{}, err
	}
	return event, nil
}

func NewWorkerProgressTurnEvent(executionID, phase string) (TurnEvent, error) {
	event := TurnEvent{Kind: TurnEventWorkerStatus, ExecutionID: executionID, Status: "running", Phase: strings.TrimSpace(phase)}
	if err := event.ValidateWorkerStatusAuthority(); err != nil {
		return TurnEvent{}, err
	}
	return event, nil
}

// NewMemoryRecallDegradedTurnEvent is the sole durable representation of an
// optional per-turn recall failure. The closed text is safe for clients and is
// never added to the model transcript or final response.
func NewMemoryRecallDegradedTurnEvent() TurnEvent {
	return TurnEvent{Kind: TurnEventWarning, Text: MemoryRecallDegradedText, Status: MemoryRecallDegradedStatus}
}

// ValidateWarningAuthority rejects arbitrary warning payloads. Turn identity,
// ordering, revision, and creation time are persistence metadata populated by
// the owning store and are intentionally allowed.
func (e TurnEvent) ValidateWarningAuthority() error {
	if e.Kind != TurnEventWarning || e.Text != MemoryRecallDegradedText || e.Status != MemoryRecallDegradedStatus ||
		e.Message != nil || e.Response != nil || e.ToolCall != nil || e.ToolResult != nil || e.ConfirmationID != "" ||
		e.ExecutionID != "" || e.Phase != "" || len(e.RelatedTaskIDs) != 0 || len(e.RelatedPlanIDs) != 0 ||
		len(e.References) != 0 || e.ErrorCode != "" || e.ErrorSummary != "" || e.FirstSequence != 0 ||
		e.LastSequence != 0 || e.ReplayGap || e.MutationID != "" || e.ExpectedRevision != 0 ||
		len(e.AttachmentSources) != 0 || e.Err != nil {
		return ErrInvalid
	}
	return nil
}

func (e TurnEvent) ValidateWorkerStatusAuthority() error {
	validStatus := false
	switch e.Status {
	case "queued", "provisioning", "running", "succeeded", "failed", "canceled", "rejected", "expired":
		validStatus = true
	}
	validPhase := e.Phase == ""
	if e.Status == "running" {
		switch e.Phase {
		case "", "preparing_environment", "provisioning_worker", "connecting_worker", "executing_remote_task", "collecting_result", "verifying_service":
			validPhase = true
		}
	}
	if e.Kind != TurnEventWorkerStatus || !validUUID(e.ExecutionID) || !validStatus ||
		!validPhase || e.Text != "" || e.Message != nil || e.Response != nil || e.ToolCall != nil || e.ToolResult != nil ||
		e.ConfirmationID != "" || len(e.RelatedTaskIDs) != 0 || len(e.RelatedPlanIDs) != 0 ||
		len(e.References) != 0 || e.ErrorCode != "" || e.ErrorSummary != "" || e.FirstSequence != 0 ||
		e.LastSequence != 0 || e.ReplayGap || e.MutationID != "" || e.ExpectedRevision != 0 || e.Err != nil {
		return ErrInvalid
	}
	return nil
}

// ValidateWaitingConfirmationAuthority rejects alternate or mixed event
// shapes. TurnID, Sequence, Revision, and CreatedAt are persistence metadata
// populated by the owning transaction and are intentionally allowed.
func (e TurnEvent) ValidateWaitingConfirmationAuthority() error {
	if e.Kind != TurnEventWaitingConfirmation || !validUUID(e.ConfirmationID) || !validUUID(e.ExecutionID) ||
		e.Status != string(TurnWaitingConfirmation) || e.Phase != "" || e.Text != "" || e.Message != nil || e.Response != nil ||
		e.ToolCall != nil || e.ToolResult != nil || len(e.RelatedTaskIDs) != 0 ||
		len(e.RelatedPlanIDs) != 0 || len(e.References) != 0 || e.ErrorCode != "" || e.ErrorSummary != "" ||
		e.FirstSequence != 0 || e.LastSequence != 0 || e.ReplayGap || e.MutationID != "" ||
		e.ExpectedRevision != 0 || len(e.AttachmentSources) != 0 || e.Err != nil {
		return ErrInvalid
	}
	return nil
}

type TurnStartCommand struct {
	// TurnID is set by adapters that already own a canonical public turn
	// identity. RequestID remains the independent business idempotency key.
	TurnID                    string
	RequestID                 string
	OwnerID                   string
	AccountGeneration         uint64
	ConversationID            string
	Prompt                    string
	ProfileID                 string
	ExpectedProfileRevision   int64
	ExpectedCredentialVersion int64
	ExpectedRevision          *uint64
	ProfileSnapshot           coremodel.ExecutionSnapshot
	Extensions                []ExtensionSelection
	ExtensionSnapshots        []ExtensionExecutionSnapshot
	// ExtensionSnapshotsPinned declares that ExtensionSnapshots is the complete
	// accepted set, including when it is empty. Internal background adapters use
	// this to prevent an empty pinned set from acquiring current automatic tools.
	ExtensionSnapshotsPinned bool
	// IntrinsicPolicy is persisted into the immutable runtime snapshot. Scheduled
	// background turns use "none" so they cannot create nested schedules or run
	// unrelated Core side effects.
	IntrinsicPolicy       TurnIntrinsicPolicy
	AcceptedAttachmentIDs []string
	AttachmentSources     []TurnAttachment
	// ExecutionMode selects one bounded admission preset. The admitted values,
	// not this selector or later binary defaults, become durable authority.
	ExecutionMode TurnExecutionMode
	// ConstrainedWorkflow is set only by trusted internal adapters. Owner RPC
	// surfaces cannot select the reserved scheduled execution mode.
	ConstrainedWorkflow TurnConstrainedWorkflow
}

type TurnCancelCommand struct {
	RequestID string
	TurnID    string
}

type TurnSteerCommand struct {
	RequestID             string
	TurnID                string
	ExpectedRevision      uint64
	Instruction           string
	AcceptedAttachmentIDs []string
	AttachmentSources     []TurnAttachment
}

type TurnSteer struct {
	RequestID         string
	Instruction       string
	ExpectedRevision  uint64
	Sequence          int64
	CreatedAt         time.Time
	Deferred          bool
	AttachmentSources []TurnAttachment
}

type TurnLease struct {
	Turn      Turn
	LeaseID   string
	Epoch     uint64
	ExpiresAt time.Time
}

// ToolAttempt is the non-secret projection of a durable extension invocation.
// Canonical arguments are deliberately absent: they remain in the Agent DB.
type ToolAttempt struct {
	ID, TurnID, TaskID, ConfirmationID string
	Round                              uint32
	CallID, ExecutionID                string
	ToolName                           string
	State                              string
	ArgumentsDigest                    string
	SafeSummary                        string
	Result                             json.RawMessage
}

// PrepareToolCommand is the one-way handoff from a fenced turn lease to the
// confirmation/task queue. The store must validate the snapshot against the
// accepted turn; callers cannot use it to pin arbitrary extension metadata.
type PrepareToolCommand struct {
	Lease              TurnLease
	Round              uint32
	Call               ToolCall
	Snapshot           ExtensionExecutionSnapshot
	CanonicalArguments json.RawMessage
	ArgumentsDigest    string
	SafeSummary        string
	IdempotencyKey     string
	ExpiresAt          time.Time
}

type ConversationToolStore interface {
	// PrepareConversationTool atomically persists the task, attempt,
	// confirmation, waiting turn transition, and waiting event.
	PrepareConversationTool(context.Context, PrepareToolCommand) (ToolAttempt, coretask.Task, coreconfirmation.Confirmation, error)
}

type ConversationToolRecoveryStore interface {
	ObserveConversationTool(context.Context, string) (ToolAttempt, error)
	ResumeConversationTurn(context.Context, string) error
}

// OrderedConversationToolStore persists model-authored tool calls in provider
// order. Recording a call/result never releases the turn lease; the round is
// released only after every call from the durable model result is complete.
// Local-sandbox serialization remains a Core Task scheduler concern.
type OrderedConversationToolStore interface {
	RecordConversationToolCall(context.Context, TurnLease, ToolCall) error
	// BeginConversationToolDispatch atomically changes a pending immediate
	// call to dispatched. execute is true only for the transaction that made
	// that change; a reclaimed dispatched call must fail uncertain, never run
	// the provider again.
	BeginConversationToolDispatch(context.Context, TurnLease, ToolCall) (execute bool, err error)
	RecordConversationToolResult(context.Context, TurnLease, ToolResult) error
	FailConversationToolDispatch(context.Context, TurnLease, ToolCall, string, string) (Turn, error)
	CompleteConversationToolRound(context.Context, TurnLease) (Turn, error)
}

type TurnStore interface {
	TurnRuntimeAdmissionStore
	StartTurn(context.Context, TurnStartCommand) (Turn, error)
	GetTurn(context.Context, string) (Turn, error)
	ListRecoverableTurns(context.Context) ([]Turn, error)
	ClaimTurn(context.Context, string, time.Time, time.Duration) (TurnLease, error)
	RenewTurn(context.Context, string, string, uint64, time.Time, time.Duration) (TurnLease, error)
	AppendTurnEvent(context.Context, string, TurnEvent) (TurnEvent, error)
	LoadTurnEvents(context.Context, string, int64, int) ([]TurnEvent, error)
	TurnEventBounds(context.Context, string) (int64, int64, error)
	CommitTurn(context.Context, TurnLease, ChatResponse) (Turn, error)
	RequestTurnCancel(context.Context, TurnCancelCommand) (Turn, error)
	MarkTurnCanceled(context.Context, TurnLease) (Turn, error)
	FailTurn(context.Context, TurnLease, string, string) (Turn, error)
}

// TurnUserMessageID is the transcript identity used when a durable intrinsic
// has already committed the current turn's user message before final response.
func TurnUserMessageID(requestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn-user:"+requestID)).String()
}

type TurnRequestLookup interface {
	GetTurnByRequestID(context.Context, string) (Turn, error)
}

// TurnRuntimeAdmissionStore reads an owner-fenced attachment candidate, lets
// the service build the runtime snapshot without holding storage locks, then
// atomically revalidates the candidate while accepting the Turn and its event.
type TurnRuntimeAdmissionStore interface {
	PrepareTurnRuntimeAdmission(context.Context, TurnStartCommand) (Turn, error)
	StartTurnWithRuntime(context.Context, TurnStartCommand, TurnRuntimeSnapshot) (Turn, error)
	ValidateTurnRuntime(context.Context, TurnLease, TurnRuntimeSnapshot) error
}

// TurnLister is the fresh Agent-owned history contract used by capability
// clients. It is optional on TurnStore to avoid making recovery-only stores
// implement a public listing surface.
type TurnLister interface {
	ListTurns(context.Context, string, string, int) ([]Turn, string, error)
}

type TurnDispatchStore interface {
	PrepareTurnModel(context.Context, TurnLease, TurnDispatchDirective) (Turn, error)
	LoadTurnModelDirective(context.Context, TurnLease) (TurnDispatchDirective, error)
	LoadTurnModelResult(context.Context, string) (ModelRunResult, bool, error)
	RecordTurnModelResult(context.Context, TurnLease, ModelRunResult) error
	MarkTurnModelUncertain(context.Context, TurnLease, string, string) error
}

const TurnFinalizationIntentVersion = 1

type TurnFinalizationReason string

const (
	TurnFinalizationToolLoop      TurnFinalizationReason = "tool_loop_no_progress"
	TurnFinalizationToolBudget    TurnFinalizationReason = "tool_budget_exhausted"
	TurnFinalizationModelBudget   TurnFinalizationReason = "model_budget_exhausted"
	TurnFinalizationProvider      TurnFinalizationReason = "provider_failure"
	TurnFinalizationInvalidOutput TurnFinalizationReason = "invalid_terminal_output"
	TurnFinalizationToolOutcome   TurnFinalizationReason = "terminal_tool_outcome"
	TurnFinalizationWorkflow      TurnFinalizationReason = "constrained_workflow"
)

// TurnFinalizationIntent is the durable decision that an ordinary accepted
// turn must stop autonomous work and converge on one useful terminal response.
// It does not expand the admitted runtime and is immutable once persisted.
type TurnFinalizationIntent struct {
	Version int                    `json:"version"`
	Reason  TurnFinalizationReason `json:"reason"`
}

func NewTurnFinalizationIntent(reason TurnFinalizationReason) TurnFinalizationIntent {
	return TurnFinalizationIntent{Version: TurnFinalizationIntentVersion, Reason: reason}
}

func (i TurnFinalizationIntent) Validate() error {
	if i.Version != TurnFinalizationIntentVersion {
		return ErrInvalid
	}
	switch i.Reason {
	case TurnFinalizationToolLoop, TurnFinalizationToolBudget, TurnFinalizationModelBudget,
		TurnFinalizationProvider, TurnFinalizationInvalidOutput, TurnFinalizationToolOutcome, TurnFinalizationWorkflow:
		return nil
	default:
		return ErrInvalid
	}
}

// TurnFinalizationStore persists finalization before a final provider dispatch
// or deterministic fallback. When failure is non-nil, the active provider
// attempt and the intent are classified in the same transaction.
type TurnFinalizationStore interface {
	PrepareTurnFinalization(context.Context, TurnLease, TurnFinalizationIntent, *ModelAttemptFailure) error
	LoadTurnFinalization(context.Context, string) (TurnFinalizationIntent, bool, error)
}

type ModelAttemptFailure struct {
	Code         string
	Summary      string
	RateLimited  bool
	RetryAfterMS int64
}

const TurnDispatchDirectiveVersion = 1

type TurnDispatchGuidance string

const (
	TurnDispatchGuidanceNone          TurnDispatchGuidance = "none"
	TurnDispatchGuidanceLoopNudge     TurnDispatchGuidance = "loop_nudge"
	TurnDispatchGuidanceLoopSynthesis TurnDispatchGuidance = "loop_synthesis"
)

type TurnDispatchToolMode string

const (
	TurnDispatchToolsAdmitted TurnDispatchToolMode = "admitted"
	TurnDispatchToolsNone     TurnDispatchToolMode = "none"
)

// TurnDispatchDirective is the durable, capability-reducing control applied
// to one physical model dispatch. The admitted TurnRuntimeSnapshot remains the
// immutable capability envelope; a directive can add bounded loop guidance,
// force one admitted tool, or remove every tool for final synthesis.
type TurnDispatchDirective struct {
	Version            int                    `json:"version"`
	Guidance           TurnDispatchGuidance   `json:"guidance"`
	ToolMode           TurnDispatchToolMode   `json:"tool_mode"`
	ForcedToolName     string                 `json:"forced_tool_name,omitempty"`
	FinalizationReason TurnFinalizationReason `json:"finalization_reason,omitempty"`
}

func NewTurnDispatchDirective(guidance TurnDispatchGuidance, toolMode TurnDispatchToolMode, forcedToolName string) TurnDispatchDirective {
	return TurnDispatchDirective{Version: TurnDispatchDirectiveVersion, Guidance: guidance, ToolMode: toolMode, ForcedToolName: strings.TrimSpace(forcedToolName)}
}

func DefaultTurnDispatchDirective() TurnDispatchDirective {
	return NewTurnDispatchDirective(TurnDispatchGuidanceNone, TurnDispatchToolsAdmitted, "")
}

func (d TurnDispatchDirective) ValidateFor(runtime TurnRuntimeSnapshot, extensions []ExtensionExecutionSnapshot) error {
	if d.Version != TurnDispatchDirectiveVersion || runtime.Validate() != nil {
		return ErrInvalid
	}
	switch d.Guidance {
	case TurnDispatchGuidanceNone, TurnDispatchGuidanceLoopNudge, TurnDispatchGuidanceLoopSynthesis:
	default:
		return ErrInvalid
	}
	if d.ToolMode != TurnDispatchToolsAdmitted && d.ToolMode != TurnDispatchToolsNone {
		return ErrInvalid
	}
	if d.Guidance == TurnDispatchGuidanceLoopSynthesis && d.ToolMode != TurnDispatchToolsNone {
		return ErrInvalid
	}
	if d.ToolMode == TurnDispatchToolsNone && (d.ForcedToolName != "" || d.Guidance != TurnDispatchGuidanceLoopSynthesis) {
		return ErrInvalid
	}
	if d.Guidance == TurnDispatchGuidanceLoopNudge && d.ForcedToolName != "" {
		return ErrInvalid
	}
	if d.FinalizationReason != "" {
		if NewTurnFinalizationIntent(d.FinalizationReason).Validate() != nil ||
			d.ToolMode != TurnDispatchToolsNone || d.Guidance != TurnDispatchGuidanceLoopSynthesis {
			return ErrInvalid
		}
	}
	if d.ForcedToolName == "" {
		return nil
	}
	if d.Guidance != TurnDispatchGuidanceNone || strings.TrimSpace(d.ForcedToolName) != d.ForcedToolName || len(d.ForcedToolName) > MaxToolNameBytes || !utf8.ValidString(d.ForcedToolName) {
		return ErrInvalid
	}
	for _, tool := range runtime.IntrinsicTools {
		if tool.Name == d.ForcedToolName {
			return nil
		}
	}
	for _, extension := range extensions {
		for _, name := range extension.ToolNames {
			if name == d.ForcedToolName {
				return nil
			}
		}
	}
	return ErrInvalid
}

func (d TurnDispatchDirective) Digest() string {
	raw, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return digest(string(raw))
}

const TurnRuntimeSnapshotVersion = 3

type TurnIntrinsicPolicy string

const TurnIntrinsicPolicyNone TurnIntrinsicPolicy = "none"

const TurnExecutionPolicyVersion = 1

type TurnExecutionMode string

const (
	TurnExecutionInteractive         TurnExecutionMode = "interactive"
	TurnExecutionDeep                TurnExecutionMode = "deep"
	TurnExecutionScheduled           TurnExecutionMode = "scheduled"
	TurnExecutionWorkerOrchestration TurnExecutionMode = "worker_orchestration"
)

const (
	interactiveTurnModelDispatches     = 8
	interactiveTurnModelActiveDuration = 5 * time.Minute
	interactiveTurnToolCalls           = 8
)

// TurnExecutionPolicy is the immutable ordinary ReAct budget admitted with a
// turn. Validation deliberately accepts every safe value in the supported
// version instead of comparing against the current preset for its mode.
type TurnExecutionPolicy struct {
	Version                    int               `json:"version"`
	Mode                       TurnExecutionMode `json:"mode"`
	MaxModelDispatches         uint32            `json:"max_model_dispatches"`
	MaxModelActiveMilliseconds uint64            `json:"max_model_active_milliseconds"`
	MaxToolCalls               uint32            `json:"max_tool_calls"`
	ToolLoopPolicyVersion      uint32            `json:"tool_loop_policy_version"`
	ProviderRetryPolicyVersion uint32            `json:"provider_retry_policy_version"`
}

func AdmittedTurnExecutionPolicy(mode TurnExecutionMode) (TurnExecutionPolicy, error) {
	policy := TurnExecutionPolicy{
		Version: TurnExecutionPolicyVersion, Mode: mode,
		ToolLoopPolicyVersion: 1, ProviderRetryPolicyVersion: 1,
	}
	switch mode {
	case TurnExecutionInteractive:
		policy.MaxModelDispatches = interactiveTurnModelDispatches
		policy.MaxModelActiveMilliseconds = uint64(interactiveTurnModelActiveDuration.Milliseconds())
		policy.MaxToolCalls = interactiveTurnToolCalls
	case TurnExecutionDeep, TurnExecutionScheduled, TurnExecutionWorkerOrchestration:
		policy.MaxModelDispatches = MaxAdmittedTurnModelDispatches
		policy.MaxModelActiveMilliseconds = uint64(MaxAdmittedTurnModelActiveDuration.Milliseconds())
		policy.MaxToolCalls = MaxAdmittedTurnToolCalls
	default:
		return TurnExecutionPolicy{}, ErrInvalid
	}
	return policy, nil
}

func (p TurnExecutionPolicy) Validate() error {
	switch p.Mode {
	case TurnExecutionInteractive, TurnExecutionDeep, TurnExecutionScheduled, TurnExecutionWorkerOrchestration:
	default:
		return ErrInvalid
	}
	if p.Version != TurnExecutionPolicyVersion || p.MaxModelDispatches == 0 || p.MaxModelDispatches > MaxAdmittedTurnModelDispatches ||
		p.MaxModelActiveMilliseconds == 0 || p.MaxModelActiveMilliseconds > uint64(MaxAdmittedTurnModelActiveDuration.Milliseconds()) ||
		p.MaxToolCalls == 0 || p.MaxToolCalls > MaxAdmittedTurnToolCalls ||
		p.ToolLoopPolicyVersion != 1 || p.ProviderRetryPolicyVersion != 1 {
		return ErrInvalid
	}
	return nil
}

func (p TurnExecutionPolicy) MaxModelActiveDuration() time.Duration {
	if p.Validate() != nil {
		return 0
	}
	return time.Duration(p.MaxModelActiveMilliseconds) * time.Millisecond
}

func normalizeTurnExecutionMode(mode TurnExecutionMode) TurnExecutionMode {
	if mode == "" {
		return TurnExecutionInteractive
	}
	return mode
}

// NormalizeClientTurnExecutionMode admits only owner-selected foreground
// modes. Scheduled is reserved for the trusted durable Task adapter.
func NormalizeClientTurnExecutionMode(mode TurnExecutionMode) (TurnExecutionMode, error) {
	mode = normalizeTurnExecutionMode(mode)
	switch mode {
	case TurnExecutionInteractive, TurnExecutionDeep, TurnExecutionWorkerOrchestration:
		return mode, nil
	default:
		return "", ErrInvalid
	}
}

type TurnRuntimeSnapshot struct {
	Version               int                     `json:"version"`
	CompiledSystemPrompt  string                  `json:"compiled_system_prompt"`
	SystemPromptDigest    string                  `json:"system_prompt_digest"`
	ProfileSnapshotDigest string                  `json:"profile_snapshot_digest"`
	RequestDialect        string                  `json:"request_dialect"`
	IntrinsicTools        []coremodel.Tool        `json:"intrinsic_tools"`
	IntrinsicDigest       string                  `json:"intrinsic_digest"`
	IntrinsicPolicy       TurnIntrinsicPolicy     `json:"intrinsic_policy,omitempty"`
	ExtensionDigest       string                  `json:"extension_digest"`
	AttachmentDigest      string                  `json:"attachment_digest"`
	ExecutionPolicy       TurnExecutionPolicy     `json:"execution_policy"`
	ExecutionPolicyDigest string                  `json:"execution_policy_digest"`
	ConstrainedWorkflow   TurnConstrainedWorkflow `json:"constrained_workflow,omitempty"`
}

func NewTurnRuntimeSnapshot(systemPrompt string, profile coremodel.ExecutionSnapshot, intrinsics []ResolvedIntrinsic, extensionDigest, attachmentDigest string) (TurnRuntimeSnapshot, error) {
	return NewTurnRuntimeSnapshotForMode(systemPrompt, profile, intrinsics, extensionDigest, attachmentDigest, TurnExecutionInteractive)
}

func NewTurnRuntimeSnapshotForMode(systemPrompt string, profile coremodel.ExecutionSnapshot, intrinsics []ResolvedIntrinsic, extensionDigest, attachmentDigest string, mode TurnExecutionMode) (TurnRuntimeSnapshot, error) {
	policy, err := AdmittedTurnExecutionPolicy(mode)
	if err != nil {
		return TurnRuntimeSnapshot{}, err
	}
	return newTurnRuntimeSnapshotWithPolicy(systemPrompt, profile, intrinsics, extensionDigest, attachmentDigest, "", policy, TurnConstrainedWorkflow{})
}

func newTurnRuntimeSnapshot(systemPrompt string, profile coremodel.ExecutionSnapshot, intrinsics []ResolvedIntrinsic, extensionDigest, attachmentDigest string, intrinsicPolicy TurnIntrinsicPolicy) (TurnRuntimeSnapshot, error) {
	policy, err := AdmittedTurnExecutionPolicy(TurnExecutionInteractive)
	if err != nil {
		return TurnRuntimeSnapshot{}, err
	}
	return newTurnRuntimeSnapshotWithPolicy(systemPrompt, profile, intrinsics, extensionDigest, attachmentDigest, intrinsicPolicy, policy, TurnConstrainedWorkflow{})
}

func newTurnRuntimeSnapshotWithPolicy(systemPrompt string, profile coremodel.ExecutionSnapshot, intrinsics []ResolvedIntrinsic, extensionDigest, attachmentDigest string, intrinsicPolicy TurnIntrinsicPolicy, policy TurnExecutionPolicy, workflow TurnConstrainedWorkflow) (TurnRuntimeSnapshot, error) {
	if intrinsicPolicy != "" && intrinsicPolicy != TurnIntrinsicPolicyNone {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	if intrinsicPolicy == TurnIntrinsicPolicyNone && len(intrinsics) != 0 {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	if policy.Validate() != nil {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	if (policy.Mode == TurnExecutionScheduled) != !workflow.IsZero() || (!workflow.IsZero() && workflow.Validate() != nil) {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	tools := make([]coremodel.Tool, 0, len(intrinsics))
	for _, intrinsic := range intrinsics {
		if intrinsic.Execute == nil || intrinsic.Tool.InputSchema == nil || !coremodel.IsIntrinsicToolName(intrinsic.Tool.Name) {
			return TurnRuntimeSnapshot{}, ErrInvalid
		}
		tools = append(tools, intrinsic.Tool)
	}
	intrinsicRaw, err := json.Marshal(tools)
	if err != nil {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	policyRaw, _ := json.Marshal(policy)
	snapshot := TurnRuntimeSnapshot{
		Version: TurnRuntimeSnapshotVersion, CompiledSystemPrompt: systemPrompt,
		SystemPromptDigest: digest(systemPrompt), ProfileSnapshotDigest: profile.Digest(),
		RequestDialect: string(profile.RequestDialect), IntrinsicTools: tools, IntrinsicPolicy: intrinsicPolicy,
		IntrinsicDigest: digest(string(intrinsicRaw)), ExtensionDigest: extensionDigest,
		AttachmentDigest: attachmentDigest,
		ExecutionPolicy:  policy, ExecutionPolicyDigest: digest(string(policyRaw)),
		ConstrainedWorkflow: workflow,
	}
	if snapshot.Validate() != nil {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	return snapshot, nil
}

func (s TurnRuntimeSnapshot) Validate() error {
	if s.Version != TurnRuntimeSnapshotVersion || s.SystemPromptDigest != digest(s.CompiledSystemPrompt) ||
		!validReferenceDigest(s.ProfileSnapshotDigest) || !validRuntimeRequestDialect(s.RequestDialect) ||
		(len(s.ExtensionDigest) != 0 && !validReferenceDigest(s.ExtensionDigest)) ||
		(len(s.AttachmentDigest) != 0 && !validReferenceDigest(s.AttachmentDigest)) ||
		(s.IntrinsicPolicy != "" && s.IntrinsicPolicy != TurnIntrinsicPolicyNone) ||
		(s.IntrinsicPolicy == TurnIntrinsicPolicyNone && len(s.IntrinsicTools) != 0) {
		return ErrInvalid
	}
	if (s.ExecutionPolicy.Mode == TurnExecutionScheduled) != !s.ConstrainedWorkflow.IsZero() ||
		(!s.ConstrainedWorkflow.IsZero() && s.ConstrainedWorkflow.Validate() != nil) {
		return ErrInvalid
	}
	intrinsicRaw, err := json.Marshal(s.IntrinsicTools)
	if err != nil || s.IntrinsicDigest != digest(string(intrinsicRaw)) {
		return ErrInvalid
	}
	for _, tool := range s.IntrinsicTools {
		if !coremodel.IsIntrinsicToolName(tool.Name) || tool.InputSchema == nil {
			return ErrInvalid
		}
	}
	policyRaw, err := json.Marshal(s.ExecutionPolicy)
	if err != nil || s.ExecutionPolicy.Validate() != nil || s.ExecutionPolicyDigest != digest(string(policyRaw)) {
		return ErrInvalid
	}
	return nil
}

func validRuntimeRequestDialect(value string) bool {
	switch coremodel.RequestDialect(value) {
	case coremodel.DialectOpenAICompatibleChatV1, coremodel.DialectOpenAIReasoningChatV1,
		coremodel.DialectAnthropicMessagesV1, coremodel.DialectGeminiGenerateV1Beta:
		return true
	default:
		return false
	}
}

func (s TurnRuntimeSnapshot) Digest() string {
	raw, _ := json.Marshal(s)
	return digest(string(raw))
}

func (f ModelAttemptFailure) Validate() error {
	if strings.TrimSpace(f.Code) != f.Code || f.Code == "" || len(f.Code) > 128 ||
		strings.TrimSpace(f.Summary) != f.Summary || f.Summary == "" || len(f.Summary) > 4096 ||
		f.RetryAfterMS < 0 || f.RetryAfterMS > 30_000 {
		return ErrInvalid
	}
	return nil
}

// TurnModelAttemptStore extends the logical model-round fence with one row per
// physical provider request. A retry is legal only after the active attempt
// was durably classified retryable without producing output.
type TurnModelAttemptStore interface {
	BindTurnModelRuntime(context.Context, TurnLease, TurnRuntimeSnapshot) error
	MarkTurnModelRetryable(context.Context, TurnLease, ModelAttemptFailure) error
	PrepareTurnModelRetry(context.Context, TurnLease) (Turn, error)
	MarkTurnModelAttemptUncertain(context.Context, TurnLease, ModelAttemptFailure) error
}

type TurnCancelStore interface {
	MarkTurnCanceledRequested(context.Context, string) (Turn, error)
}

// TurnSteerStore persists same-turn user guidance in the durable event ledger.
// The boolean result tells the service whether the current provider generation
// must be interrupted. Guidance received after a tool call is public or
// dispatched is deferred without changing that tool's active authority.
type TurnSteerStore interface {
	RequestTurnSteer(context.Context, TurnSteerCommand) (Turn, bool, error)
	ListTurnSteers(context.Context, string) ([]TurnSteer, error)
}

type TurnAttachmentContentResolver interface {
	ResolveTurnAttachment(context.Context, Turn, TurnAttachment) ([]byte, error)
}

type TurnUncertainStore interface {
	FailTurnUncertain(context.Context, string, string, string) (Turn, error)
}

func (c TurnStartCommand) Validate() error {
	if (c.TurnID != "" && !validUUID(c.TurnID)) || !validUUID(c.RequestID) || !validUUID(c.ProfileID) || (c.ConversationID != "" && !validUUID(c.ConversationID)) || c.ExpectedProfileRevision <= 0 || c.ExpectedCredentialVersion <= 0 {
		return ErrInvalid
	}
	c.OwnerID = strings.TrimSpace(c.OwnerID)
	if (c.OwnerID == "") != (c.AccountGeneration == 0) || len(c.OwnerID) > 512 || !utf8.ValidString(c.OwnerID) {
		return ErrInvalid
	}
	if err := validateText(c.Prompt, MaxContentBytes); err != nil {
		return err
	}
	if c.ExpectedRevision != nil && *c.ExpectedRevision == 0 {
		return ErrInvalid
	}
	if err := c.ProfileSnapshot.Validate(); err != nil {
		return ErrInvalid
	}
	if c.ProfileSnapshot.ProfileID != c.ProfileID || c.ProfileSnapshot.Revision != c.ExpectedProfileRevision || c.ProfileSnapshot.CredentialVersion != c.ExpectedCredentialVersion {
		return ErrConflict
	}
	for _, selection := range c.Extensions {
		if selection.Validate() != nil {
			return ErrInvalid
		}
	}
	for i := range c.ExtensionSnapshots {
		if err := c.ExtensionSnapshots[i].Validate(); err != nil {
			return err
		}
	}
	if c.ExtensionSnapshotsPinned && len(c.Extensions) != 0 {
		return ErrInvalid
	}
	if c.IntrinsicPolicy != "" && c.IntrinsicPolicy != TurnIntrinsicPolicyNone {
		return ErrInvalid
	}
	mode := normalizeTurnExecutionMode(c.ExecutionMode)
	if _, err := AdmittedTurnExecutionPolicy(mode); err != nil {
		return ErrInvalid
	}
	if (mode == TurnExecutionScheduled) != !c.ConstrainedWorkflow.IsZero() ||
		(!c.ConstrainedWorkflow.IsZero() && c.ConstrainedWorkflow.Validate() != nil) {
		return ErrInvalid
	}
	if len(c.Extensions) > 0 && len(c.ExtensionSnapshots) == 0 {
		return ErrInvalid
	}
	if len(c.AcceptedAttachmentIDs) > MaxTurnAttachments {
		return ErrInvalid
	}
	seenAttachments := make(map[string]struct{}, len(c.AcceptedAttachmentIDs))
	for _, id := range c.AcceptedAttachmentIDs {
		if !validUUID(id) {
			return ErrInvalid
		}
		if _, duplicate := seenAttachments[id]; duplicate {
			return ErrConflict
		}
		seenAttachments[id] = struct{}{}
	}
	if len(c.AttachmentSources) > 0 && ValidateAcceptedTurnAttachments(c.RequestID, c.AcceptedAttachmentIDs, c.AttachmentSources) != nil {
		return ErrInvalid
	}
	return nil
}

func (s ExtensionExecutionSnapshot) Validate() error {
	if s.Selection.Validate() != nil || s.InstallationID == "" || s.VersionID == "" || s.Source == "" || len(s.ContentDigest) != 64 || len(s.ArtifactDigest) != 64 {
		return ErrInvalid
	}
	if len([]byte(s.SkillInstructions)) > 64<<10 {
		return ErrInvalid
	}
	seen := map[string]struct{}{}
	for _, name := range s.ToolNames {
		if name == "" || len(name) > MaxToolNameBytes || coremodel.IsIntrinsicToolName(name) {
			return ErrInvalid
		}
		if _, ok := seen[name]; ok {
			return ErrConflict
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (c TurnStartCommand) Fingerprint() string {
	values := []any{
		c.TurnID,
		c.RequestID,
		strings.TrimSpace(c.OwnerID),
		c.AccountGeneration,
		c.ConversationID,
		c.Prompt,
		c.ProfileID,
		c.ExpectedProfileRevision,
		c.ExpectedCredentialVersion,
		c.ExpectedRevision,
		c.ProfileSnapshot.Digest(),
		c.ExtensionSnapshotDigest(),
		c.AcceptedAttachmentIDs,
		TurnAttachmentSnapshotDigest(c.AttachmentSources),
		"execution_mode",
		normalizeTurnExecutionMode(c.ExecutionMode),
	}
	if !c.ConstrainedWorkflow.IsZero() {
		values = append(values, "constrained_workflow", c.ConstrainedWorkflow)
	}
	// Keep the ordinary false form byte-for-byte compatible with already
	// accepted turns. The internal explicit-pin marker still has its own replay
	// identity, including for a deliberately empty snapshot set.
	if c.ExtensionSnapshotsPinned {
		values = append(values, "extension_snapshots_pinned")
	}
	if c.IntrinsicPolicy != "" {
		values = append(values, "intrinsic_policy", c.IntrinsicPolicy)
	}
	return digest(turnStructDigest(values...))
}

func (c TurnStartCommand) ExtensionSnapshotDigest() string {
	if len(c.ExtensionSnapshots) == 0 {
		return ""
	}
	items := append([]ExtensionExecutionSnapshot(nil), c.ExtensionSnapshots...)
	for i := range items {
		items[i].Selection.AllowedTools = append([]string(nil), items[i].Selection.AllowedTools...)
		sort.Strings(items[i].Selection.AllowedTools)
		items[i].ToolNames = append([]string(nil), items[i].ToolNames...)
		sort.Strings(items[i].ToolNames)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Selection.Kind != items[j].Selection.Kind {
			return items[i].Selection.Kind < items[j].Selection.Kind
		}
		if items[i].InstallationID != items[j].InstallationID {
			return items[i].InstallationID < items[j].InstallationID
		}
		return items[i].VersionID < items[j].VersionID
	})
	return digest(turnMustJSON(items))
}

func turnStructDigest(values ...any) string {
	// JSON encoding gives a deterministic representation for the primitive
	// fields used by request fingerprints, including an absent revision.
	return turnMustJSON(values)
}

func turnMustJSON(v any) string {
	b, _ := jsonMarshal(v)
	return string(b)
}

// indirection keeps this file's public surface small while allowing tests to
// replace encoding in fuzz builds if desired.
var jsonMarshal = func(v any) ([]byte, error) { return json.Marshal(v) }
