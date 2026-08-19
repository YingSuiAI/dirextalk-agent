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
	TurnEventToolCall            TurnEventKind = "tool_call"
	TurnEventToolResult          TurnEventKind = "tool_result"
	TurnEventSteered             TurnEventKind = "steered"
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
	ReasoningContent  string
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
	AcceptedAttachmentIDs    []string
	AttachmentSources        []TurnAttachment
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
	PrepareTurnModel(context.Context, TurnLease) (Turn, error)
	LoadTurnModelResult(context.Context, string) (ModelRunResult, bool, error)
	RecordTurnModelResult(context.Context, TurnLease, ModelRunResult) error
	MarkTurnModelUncertain(context.Context, TurnLease, string, string) error
}

type ModelAttemptFailure struct {
	Code         string
	Summary      string
	RateLimited  bool
	RetryAfterMS int64
}

const TurnRuntimeSnapshotVersion = 1

type TurnRuntimeSnapshot struct {
	Version               int               `json:"version"`
	CompiledSystemPrompt  string            `json:"compiled_system_prompt"`
	SystemPromptDigest    string            `json:"system_prompt_digest"`
	ProfileSnapshotDigest string            `json:"profile_snapshot_digest"`
	RequestDialect        string            `json:"request_dialect"`
	IntrinsicTools        []coremodel.Tool  `json:"intrinsic_tools"`
	IntrinsicDigest       string            `json:"intrinsic_digest"`
	ExtensionDigest       string            `json:"extension_digest"`
	AttachmentDigest      string            `json:"attachment_digest"`
	ExecutionPolicy       map[string]uint64 `json:"execution_policy"`
	ExecutionPolicyDigest string            `json:"execution_policy_digest"`
}

func NewTurnRuntimeSnapshot(systemPrompt string, profile coremodel.ExecutionSnapshot, intrinsics []ResolvedIntrinsic, extensionDigest, attachmentDigest string) (TurnRuntimeSnapshot, error) {
	tools := make([]coremodel.Tool, 0, len(intrinsics))
	for _, intrinsic := range intrinsics {
		if intrinsic.Execute == nil || intrinsic.Tool.InputSchema == nil || !coremodel.IsIntrinsicToolName(intrinsic.Tool.Name) {
			return TurnRuntimeSnapshot{}, ErrInvalid
		}
		tools = append(tools, intrinsic.Tool)
	}
	policy := map[string]uint64{
		"max_model_attempts":            MaxTurnModelDispatches,
		"max_model_active_millis":       uint64(MaxTurnModelActiveDuration.Milliseconds()),
		"max_tool_calls":                MaxTurnToolCalls,
		"tool_loop_policy_version":      1,
		"provider_retry_policy_version": 1,
	}
	intrinsicRaw, err := json.Marshal(tools)
	if err != nil {
		return TurnRuntimeSnapshot{}, ErrInvalid
	}
	policyRaw, _ := json.Marshal(policy)
	snapshot := TurnRuntimeSnapshot{
		Version: TurnRuntimeSnapshotVersion, CompiledSystemPrompt: systemPrompt,
		SystemPromptDigest: digest(systemPrompt), ProfileSnapshotDigest: profile.Digest(),
		RequestDialect: string(profile.RequestDialect), IntrinsicTools: tools,
		IntrinsicDigest: digest(string(intrinsicRaw)), ExtensionDigest: extensionDigest,
		AttachmentDigest: attachmentDigest,
		ExecutionPolicy:  policy, ExecutionPolicyDigest: digest(string(policyRaw)),
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
		(len(s.AttachmentDigest) != 0 && !validReferenceDigest(s.AttachmentDigest)) {
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
	if err != nil || len(s.ExecutionPolicy) != 5 || s.ExecutionPolicyDigest != digest(string(policyRaw)) ||
		s.ExecutionPolicy["max_model_attempts"] != MaxTurnModelDispatches ||
		s.ExecutionPolicy["max_model_active_millis"] != uint64(MaxTurnModelActiveDuration.Milliseconds()) ||
		s.ExecutionPolicy["max_tool_calls"] != MaxTurnToolCalls ||
		s.ExecutionPolicy["tool_loop_policy_version"] != 1 || s.ExecutionPolicy["provider_retry_policy_version"] != 1 {
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
	}
	// Keep the ordinary false form byte-for-byte compatible with already
	// accepted turns. The internal explicit-pin marker still has its own replay
	// identity, including for a deliberately empty snapshot set.
	if c.ExtensionSnapshotsPinned {
		values = append(values, "extension_snapshots_pinned")
	}
	return digest(turnStructDigest(values...))
}

func (c TurnStartCommand) ExtensionSnapshotDigest() string {
	if len(c.ExtensionSnapshots) == 0 {
		return ""
	}
	items := append([]ExtensionExecutionSnapshot(nil), c.ExtensionSnapshots...)
	for i := range items {
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
