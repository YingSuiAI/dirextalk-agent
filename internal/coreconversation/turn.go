package coreconversation

// Durable conversation turns deliberately live beside the legacy Chat ledger.
// They use a separate request identity and lease so a caller can disconnect
// without transferring ownership of an accepted prompt to its gRPC context.

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
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
	TurnEventToolCall            TurnEventKind = "tool_call"
	TurnEventToolResult          TurnEventKind = "tool_result"
)

type Turn struct {
	ID                       string
	RequestID                string
	RequestFingerprint       string `json:"-"`
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
	LastSequence             int64
	CreatedAt                time.Time
	UpdatedAt                time.Time
	ProfileSnapshot          coremodel.ExecutionSnapshot  `json:"-"`
	ProfileSnapshotDigest    string                       `json:"-"`
	ExtensionSnapshots       []ExtensionExecutionSnapshot `json:"-"`
	ExtensionSnapshotDigest  string                       `json:"-"`
}

type TurnEvent struct {
	TurnID         string
	Sequence       int64
	Kind           TurnEventKind
	Text           string
	Message        *Message
	Response       *ChatResponse
	ToolCall       *ToolCall
	ToolResult     *ToolResult
	ConfirmationID string
	AttemptID      string
	ExecutionID    string
	Status         string
	ErrorCode      string
	ErrorSummary   string
	FirstSequence  int64
	LastSequence   int64
	ReplayGap      bool
	CreatedAt      time.Time
	Err            error `json:"-"`
}

type TurnStartCommand struct {
	RequestID          string
	ConversationID     string
	Prompt             string
	ProfileID          string
	ExpectedRevision   *uint64
	ProfileSnapshot    coremodel.ExecutionSnapshot
	Extensions         []ExtensionSelection
	ExtensionSnapshots []ExtensionExecutionSnapshot
}

type TurnCancelCommand struct {
	RequestID        string
	TurnID           string
	ExpectedRevision uint64
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
	PrepareConversationTool(context.Context, PrepareToolCommand) (ToolAttempt, coretask.Task, coreconfirmation.Confirmation, error)
}

type ConversationToolRecoveryStore interface {
	ObserveConversationTool(context.Context, string) (ToolAttempt, error)
	ResumeConversationTurn(context.Context, string) error
}

type TurnStore interface {
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

type TurnRequestLookup interface {
	GetTurnByRequestID(context.Context, string) (Turn, error)
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

type TurnCancelStore interface {
	MarkTurnCanceledRequested(context.Context, string) (Turn, error)
}

type TurnUncertainStore interface {
	FailTurnUncertain(context.Context, string, string, string) (Turn, error)
}

func (c TurnStartCommand) Validate() error {
	if !validUUID(c.RequestID) || !validUUID(c.ProfileID) || (c.ConversationID != "" && !validUUID(c.ConversationID)) {
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
	if c.ProfileSnapshot.ProfileID != c.ProfileID {
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
	if len(c.Extensions) > 0 && len(c.ExtensionSnapshots) == 0 {
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
		if name == "" || len(name) > MaxToolNameBytes {
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
	return digest(turnStructDigest(c.RequestID, c.ConversationID, c.Prompt, c.ProfileID, c.ExpectedRevision, c.ProfileSnapshot.Digest(), c.ExtensionSnapshotDigest()))
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
