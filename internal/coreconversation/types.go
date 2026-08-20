// Package coreconversation contains the Core v1 conversation domain boundary.
package coreconversation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

const (
	MaxMessages              = 1000
	MaxContentBytes          = 1 << 20
	MaxToolArgumentsBytes    = 256 << 10
	MaxToolResultsBytes      = 1 << 20
	MaxToolCallIDBytes       = 256
	MaxToolNameBytes         = 256
	MaxToolCallsPerMessage   = 64
	MaxToolResultsPerMessage = 64
	MaxRelatedTaskIDs        = 32
	MaxRelatedPlanIDs        = 32
	MaxReferences            = 32
	MaxSummaryBytes          = 4096
)

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type ToolCall struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Arguments   string `json:"arguments"`
	ExecutionID string `json:"execution_id,omitempty"`
}
type ToolResult struct {
	CallID         string      `json:"call_id"`
	ToolName       string      `json:"tool_name,omitempty"`
	Content        string      `json:"content"`
	IsError        bool        `json:"is_error,omitempty"`
	RelatedTaskIDs []string    `json:"related_task_ids,omitempty"`
	RelatedPlanIDs []string    `json:"related_plan_ids,omitempty"`
	References     []Reference `json:"references,omitempty"`
	Summary        string      `json:"summary,omitempty"`
}

type Reference struct {
	Kind                 string  `json:"kind"`
	AccountGeneration    uint64  `json:"account_generation,omitempty"`
	TaskID               string  `json:"task_id,omitempty"`
	PlanID               string  `json:"plan_id,omitempty"`
	PlanRevision         uint64  `json:"plan_revision,omitempty"`
	PlanDigest           string  `json:"plan_digest,omitempty"`
	RunID                string  `json:"run_id,omitempty"`
	RunRevision          uint64  `json:"run_revision,omitempty"`
	RunDigest            string  `json:"run_digest,omitempty"`
	DeploymentID         string  `json:"deployment_id,omitempty"`
	ExecutionID          string  `json:"execution_id,omitempty"`
	WorkerID             string  `json:"worker_id,omitempty"`
	ConfirmationID       string  `json:"confirmation_id,omitempty"`
	ConfirmationRevision uint64  `json:"confirmation_revision,omitempty"`
	StageID              string  `json:"stage_id,omitempty"`
	StageRevision        uint64  `json:"stage_revision,omitempty"`
	StageDigest          string  `json:"stage_digest,omitempty"`
	TargetID             string  `json:"target_id,omitempty"`
	TargetRevision       uint64  `json:"target_revision,omitempty"`
	TargetDigest         string  `json:"target_digest,omitempty"`
	PreviewDigest        string  `json:"preview_digest,omitempty"`
	BindingDigest        string  `json:"binding_digest,omitempty"`
	QuoteDigest          string  `json:"quote_digest,omitempty"`
	ExecutionDigest      string  `json:"execution_digest,omitempty"`
	RiskLevel            string  `json:"risk_level,omitempty"`
	GateType             string  `json:"gate_type,omitempty"`
	BindingID            string  `json:"binding_id,omitempty"`
	BindingRevision      uint64  `json:"binding_revision,omitempty"`
	ProjectID            string  `json:"project_id,omitempty"`
	Status               string  `json:"status,omitempty"`
	State                string  `json:"state,omitempty"`
	RoomID               string  `json:"room_id,omitempty"`
	RoomType             string  `json:"room_type,omitempty"`
	ChannelID            string  `json:"channel_id,omitempty"`
	PostID               string  `json:"post_id,omitempty"`
	Title                string  `json:"title,omitempty"`
	Preview              string  `json:"preview,omitempty"`
	RecordKind           string  `json:"record_kind,omitempty"`
	ArtifactID           string  `json:"artifact_id,omitempty"`
	Name                 string  `json:"name,omitempty"`
	MediaType            string  `json:"media_type,omitempty"`
	SizeBytes            *uint64 `json:"size_bytes,omitempty"`
	SHA256               string  `json:"sha256,omitempty"`
}

type Message struct {
	ID     string `json:"id"`
	TurnID string `json:"turn_id,omitempty"`
	// Sequence is the durable transcript ordinal loaded from PostgreSQL. New
	// in-memory messages keep it at zero until the atomic conversation commit;
	// public history adapters use it without exposing Core-only payload fields.
	Sequence         int64                    `json:"-"`
	Role             Role                     `json:"role"`
	Content          string                   `json:"content,omitempty"`
	ReasoningContent string                   `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall               `json:"tool_calls,omitempty"`
	ToolResults      []ToolResult             `json:"tool_results,omitempty"`
	CreatedAt        time.Time                `json:"created_at"`
	ModelProfileID   string                   `json:"model_profile_id"`
	RelatedTaskIDs   []string                 `json:"related_task_ids,omitempty"`
	RelatedPlanIDs   []string                 `json:"related_plan_ids,omitempty"`
	References       []Reference              `json:"references,omitempty"`
	ToolSummaries    []string                 `json:"tool_summaries,omitempty"`
	Attachments      []AttachmentPresentation `json:"attachments,omitempty"`
	Status           string                   `json:"status,omitempty"`
}

type Conversation struct {
	ID                            string         `json:"id"`
	Title                         string         `json:"title,omitempty"`
	Revision                      uint64         `json:"revision"`
	CreatedAt                     time.Time      `json:"created_at"`
	UpdatedAt                     time.Time      `json:"updated_at"`
	DeletedAt                     *time.Time     `json:"deleted_at,omitempty"`
	Summary                       string         `json:"summary,omitempty"`
	WorkingContext                WorkingContext `json:"working_context,omitempty"`
	WorkingContextProtectedDigest string         `json:"-"`
	ContextMessageOffset          uint64         `json:"context_message_offset,omitempty"`
	Messages                      []Message      `json:"messages"`
}

// ContextCompressionResult is the Agent-owned result of a context compaction
// mutation.  The full transcript remains durable; Messages is the bounded
// model context window selected by the operation.
type ContextCompressionResult struct {
	ConversationID string         `json:"conversation_id"`
	Summary        string         `json:"summary"`
	WorkingContext WorkingContext `json:"working_context"`
	Messages       []Message      `json:"messages"`
	Revision       uint64         `json:"revision"`
	UpdatedAt      time.Time      `json:"updated_at"`
	Compression    string         `json:"compression"`
	Conversation   Conversation   `json:"conversation"`
}

type ExtensionSelection struct {
	Kind         ExtensionKind `json:"kind"`
	ID           string        `json:"id"`
	Version      string        `json:"version"`
	Digest       string        `json:"digest"`
	AllowedTools []string      `json:"allowed_tools,omitempty"`
}

// ExtensionExecutionSnapshot is the immutable, redacted binding captured at
// durable turn acceptance. It deliberately contains only identifiers and
// digests (plus bounded Skill instructions); executable closures and secret
// values never cross the persistence boundary.
type ExtensionExecutionSnapshot struct {
	Selection            ExtensionSelection `json:"selection"`
	InstallationID       string             `json:"installation_id"`
	VersionID            string             `json:"version_id"`
	InstallationRevision uint64             `json:"installation_revision"`
	Source               string             `json:"source"`
	ContentDigest        string             `json:"content_digest"`
	ArtifactDigest       string             `json:"artifact_digest"`
	ToolSchemaDigest     string             `json:"tool_schema_digest,omitempty"`
	NetworkBindingDigest string             `json:"network_binding_digest,omitempty"`
	SecretBindingDigest  string             `json:"secret_binding_digest,omitempty"`
	ToolNames            []string           `json:"tool_names,omitempty"`
	SkillInstructions    string             `json:"skill_instructions,omitempty"`
	RequiresConfirmation bool               `json:"requires_confirmation"`
	ReadOnly             bool               `json:"read_only"`
}

type ExtensionKind string

const (
	ExtensionMCP       ExtensionKind = "mcp"
	ExtensionSkill     ExtensionKind = "skill"
	ExtensionKnowledge ExtensionKind = "knowledge"
)

type ChatCommand struct {
	RequestID                 string               `json:"request_id"`
	ConversationID            string               `json:"conversation_id,omitempty"`
	Prompt                    string               `json:"prompt"`
	ProfileID                 string               `json:"profile_id"`
	ExpectedProfileRevision   int64                `json:"expected_profile_revision"`
	ExpectedCredentialVersion int64                `json:"expected_credential_version"`
	Extensions                []ExtensionSelection `json:"extensions,omitempty"`
	ExpectedRevision          *uint64              `json:"expected_revision,omitempty"`
	ExecutionMode             TurnExecutionMode    `json:"execution_mode,omitempty"`
}

type ChatResponse struct {
	RequestID      string       `json:"request_id"`
	ConversationID string       `json:"conversation_id"`
	Revision       uint64       `json:"revision"`
	Message        Message      `json:"message"`
	Done           bool         `json:"done"`
	ModelProfileID string       `json:"model_profile_id"`
	RelatedTaskIDs []string     `json:"related_task_ids,omitempty"`
	RelatedPlanIDs []string     `json:"related_plan_ids,omitempty"`
	References     []Reference  `json:"references,omitempty"`
	ToolSummaries  []string     `json:"tool_summaries,omitempty"`
	ToolResults    []ToolResult `json:"tool_results,omitempty"`
	// ConversationTitle and ConversationTitleSource are internal atomic-commit
	// projections, not part of the public chat or durable turn response contract.
	ConversationTitle       string `json:"-"`
	ConversationTitleSource string `json:"-"`
}

type StreamEventKind string

const (
	EventAccepted            StreamEventKind = "accepted"
	EventStarted             StreamEventKind = "started"
	EventDelta               StreamEventKind = "delta"
	EventToolCall            StreamEventKind = "tool_call"
	EventToolResult          StreamEventKind = "tool_result"
	EventWaitingConfirmation StreamEventKind = "waiting_confirmation"
	EventWorkerStatus        StreamEventKind = "worker_status"
	EventSteered             StreamEventKind = "steered"
	EventDone                StreamEventKind = "done"
	EventError               StreamEventKind = "error"
)

type StreamEvent struct {
	Kind             StreamEventKind `json:"kind"`
	TurnSequence     int64           `json:"turn_sequence,omitempty"`
	TurnID           string          `json:"turn_id,omitempty"`
	Revision         uint64          `json:"revision,omitempty"`
	RequestID        string          `json:"request_id"`
	ConversationID   string          `json:"conversation_id"`
	Text             string          `json:"text,omitempty"`
	ReasoningContent string          `json:"reasoning_content,omitempty"`
	ToolCall         *ToolCall       `json:"tool_call,omitempty"`
	ToolResult       *ToolResult     `json:"tool_result,omitempty"`
	Response         *ChatResponse   `json:"response,omitempty"`
	Err              string          `json:"error,omitempty"`
	ErrCode          string          `json:"error_code,omitempty"`
	ErrSummary       string          `json:"error_summary,omitempty"`
	ConfirmationID   string          `json:"confirmation_id,omitempty"`
	ExecutionID      string          `json:"execution_id,omitempty"`
	Status           string          `json:"status,omitempty"`
	Phase            string          `json:"phase,omitempty"`
}

type ClaimStatus string

const (
	ClaimNew       ClaimStatus = "new"
	ClaimInFlight  ClaimStatus = "in_flight"
	ClaimCompleted ClaimStatus = "completed"
	ClaimConflict  ClaimStatus = "conflict"
	ClaimReclaimed ClaimStatus = "reclaimed"
	ClaimFailed    ClaimStatus = "failed"
)

type ChatLease struct {
	RequestID, Fingerprint, ConversationID string
	LeaseID                                string
	ExpiresAt                              time.Time
	Status                                 ClaimStatus
	Epoch                                  uint64
	ProfileID                              string
	Extensions                             []ExtensionSelection
	Response                               *ChatResponse
	FailureCode                            string
	FailureSummary                         string
	ProfileSnapshot                        coremodel.ExecutionSnapshot `json:"-"`
	ProfileSnapshotDigest                  string                      `json:"-"`
}

func (l ChatLease) String() string {
	type redacted struct {
		RequestID, Fingerprint, ConversationID string
		LeaseID                                string
		ExpiresAt                              time.Time
		Status                                 ClaimStatus
		Epoch                                  uint64
		ProfileID                              string
		ProfileSnapshotDigest                  string
	}
	return fmt.Sprintf("%+v", redacted{l.RequestID, l.Fingerprint, l.ConversationID, l.LeaseID, l.ExpiresAt, l.Status, l.Epoch, l.ProfileID, l.ProfileSnapshotDigest})
}

func (l ChatLease) GoString() string { return l.String() }

type ChatStart struct {
	Command      ChatCommand
	Fingerprint  string
	Lease        ChatLease
	Conversation Conversation
}
type AtomicCompletion struct {
	RequestID, LeaseID, Fingerprint string
	ExpectedRevision                uint64
	Conversation                    Conversation
	Response                        ChatResponse
	Epoch                           uint64
}

type ModelRunRequest struct {
	Conversation          Conversation
	Profile               ResolvedProfile
	Snapshot              coremodel.ExecutionSnapshot
	ProfileSnapshot       coremodel.ExecutionSnapshot
	ForcedToolName        string
	Intrinsics            []ResolvedIntrinsic
	Extensions            []ResolvedExtension
	ExtensionSnapshots    []ExtensionExecutionSnapshot
	InputPartsByMessageID map[string][]coremodel.MessageInputPart
}
type ModelRunResult struct {
	Message        Message
	ToolCalls      []ToolCall
	Done           bool
	Continue       bool
	RelatedTaskIDs []string
	RelatedPlanIDs []string
	References     []Reference
	ToolSummaries  []string
}
type ResolvedProfile struct {
	ID           string
	DisplayName  string
	Provider     string
	Model        string
	SystemPrompt string
}
type ResolvedExtension struct {
	Selection ExtensionSelection
	Execute   func(context.Context, ToolExecutionRequest) (ToolResult, error)
	Snapshot  ExtensionExecutionSnapshot
	// Tools is the immutable model-facing tool catalog for this resolved
	// extension. A snapshot that names tools must resolve their exact schemas;
	// the runtime never synthesizes a permissive schema.
	Tools []coremodel.Tool
}

// ResolvedIntrinsic is a Core-owned model tool. It is deliberately separate
// from extension snapshots and never crosses MCP, Skills, or Extension Runner
// resolution. Read-only intrinsics return a ToolResult that Core persists
// before resuming the turn. All other intrinsics must atomically commit the
// durable turn before reporting success.
type ResolvedIntrinsic struct {
	Tool     coremodel.Tool
	ReadOnly bool
	Execute  func(context.Context, IntrinsicExecutionRequest) (IntrinsicExecutionResult, error)
}

type IntrinsicExecutionRequest struct {
	Lease              TurnLease
	Call               ToolCall
	CanonicalArguments json.RawMessage
	// ConversationRevision is the authoritative revision loaded for the model
	// round. Intrinsics that atomically append to the transcript must fence
	// their commit against this value instead of guessing from an optional
	// client CAS field.
	ConversationRevision uint64
}

type IntrinsicExecutionResult struct {
	TurnCommitted bool
	ToolResult    *ToolResult
}

// IntrinsicCorrectionError lets a Core-owned intrinsic return bounded,
// actionable guidance to the model without treating a correctable resource
// selection as a terminal turn failure.
type IntrinsicCorrectionError interface {
	error
	IntrinsicCorrection() string
}

type IntrinsicResolver interface {
	ResolveIntrinsicTools(context.Context, TurnLease) ([]ResolvedIntrinsic, error)
}

// ConversationScheduleCommand is the trusted, atomic boundary used by the
// Agent-owned schedule intrinsic. The model never supplies any identity or
// execution binding carried here.
type ConversationScheduleCommand struct {
	Lease    TurnLease
	Schedule coretask.Schedule
	Mutation coretask.MutationCommand
	Response ChatResponse
}

func (c ConversationScheduleCommand) Validate() error {
	turn := c.Lease.Turn
	if turn.ID == "" || turn.RequestID == "" || strings.TrimSpace(turn.OwnerID) == "" || turn.AccountGeneration == 0 ||
		c.Lease.LeaseID == "" || c.Lease.Epoch == 0 || c.Schedule.Validate() != nil || c.Mutation.Validate() != nil ||
		c.Mutation.ExpectedRevision != 0 || c.Response.RequestID != turn.RequestID ||
		c.Response.ConversationID != turn.ConversationID || c.Response.ModelProfileID != turn.ProfileID || !c.Response.Done ||
		c.Response.Message.ModelProfileID != turn.ProfileID || c.Response.Message.Validate() != nil {
		return ErrInvalid
	}
	template := c.Schedule.Spec
	if template.Kind != coretask.TaskKindAgent || template.ConversationID != turn.ConversationID || template.ModelProfileID != "" ||
		len(template.AttachmentRefs) != 0 || len(template.Extensions) != 0 || len(template.KnowledgeRefs) != 0 || template.Payload.Agent == nil ||
		template.Payload.Agent.OwnerID != strings.TrimSpace(turn.OwnerID) || template.Payload.Agent.AccountGeneration != turn.AccountGeneration ||
		template.Payload.ConversationTool != nil || template.Payload.Extension != nil || template.Payload.KnowledgeIndex != nil ||
		template.Payload.Workload != nil || template.Payload.CloudWorker != nil {
		return ErrInvalid
	}
	return nil
}

type ConversationScheduleStore interface {
	CommitConversationSchedule(context.Context, ConversationScheduleCommand) (coretask.Schedule, error)
}

const MaxStaticSiteHTMLBytes = 192 << 10

// StaticSitePublication contains only server-derived path authority. The
// model supplies HTML content but can never choose a filesystem path or URL.
type StaticSitePublication struct {
	SiteID    string
	ReleaseID string
	HTML      []byte
}

type StaticSiteReceipt struct {
	SiteID        string
	ReleaseID     string
	PublicPath    string
	SHA256        string
	SizeBytes     int64
	AlreadyExists bool
}

func (r StaticSiteReceipt) Validate() error {
	if !validUUID(r.SiteID) || !validUUID(r.ReleaseID) || r.PublicPath != "/.sites/"+r.SiteID+"/"+r.ReleaseID+"/" ||
		len(r.SHA256) != 64 || r.SizeBytes <= 0 || r.SizeBytes > MaxStaticSiteHTMLBytes {
		return ErrInvalid
	}
	for _, c := range r.SHA256 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalid
		}
	}
	return nil
}

type StaticSitePublisher interface {
	PublishSingleHTML(context.Context, StaticSitePublication) (StaticSiteReceipt, error)
}

// ConversationStaticSiteCommand commits the immutable publication receipt
// and terminal chat response under the exact turn lease. The filesystem
// publication is deliberately outside PostgreSQL and is idempotent by the
// server-derived site/release identity.
type ConversationStaticSiteCommand struct {
	Lease     TurnLease
	Receipt   StaticSiteReceipt
	PublicURL string
	Response  ChatResponse
}

func (c ConversationStaticSiteCommand) Validate() error {
	turn := c.Lease.Turn
	if turn.ID == "" || turn.RequestID == "" || strings.TrimSpace(turn.OwnerID) == "" || turn.AccountGeneration == 0 ||
		c.Lease.LeaseID == "" || c.Lease.Epoch == 0 || c.Receipt.Validate() != nil ||
		c.Response.RequestID != turn.RequestID || c.Response.ConversationID != turn.ConversationID ||
		c.Response.ModelProfileID != turn.ProfileID || !c.Response.Done || c.Response.Message.ModelProfileID != turn.ProfileID ||
		c.PublicURL == "" || !strings.HasSuffix(c.PublicURL, c.Receipt.PublicPath) ||
		c.Response.Message.Content != "Published the static page: "+c.PublicURL || c.Response.Message.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type ConversationStaticSiteStore interface {
	CommitConversationStaticSite(context.Context, ConversationStaticSiteCommand) (StaticSiteReceipt, error)
}

// ExtensionSnapshotResolver may resolve an already-pinned snapshot to an
// executable dispatcher without consulting mutable active installation state.
// It is intentionally optional so the basic conversation path remains usable.
type ExtensionSnapshotResolver interface {
	ResolveExtensionSnapshot(context.Context, ExtensionExecutionSnapshot) (ResolvedExtension, error)
}
type ToolExecutionRequest struct {
	RequestID       string
	ToolCallID      string
	ExecutionID     string
	ArgsDigest      string
	ExtensionDigest string
	Call            ToolCall
}

type ConversationStore interface {
	CreateConversation(context.Context, Conversation, string) error
	LoadConversation(context.Context, string) (Conversation, error)
	ListConversations(context.Context, string, int) ([]Conversation, string, error)
	SaveConversation(context.Context, Conversation, uint64) error
	DeleteConversation(context.Context, string, uint64) error
}
type CreateConversationCommand struct {
	RequestID    string
	Conversation Conversation
	Fingerprint  string
}
type DeleteConversationCommand struct {
	RequestID        string
	ConversationID   string
	ExpectedRevision uint64
	Fingerprint      string
}
type ConversationMutationResponse struct {
	Conversation Conversation
	RequestID    string
	Deleted      bool
	// Replayed is set only when the durable mutation response came from the
	// idempotency replay record. It is intentionally not persisted inside the
	// response JSON so a fresh execution never inherits a stale replay marker.
	Replayed bool `json:"-"`
}
type ConversationMutationStore interface {
	CreateConversationMutation(context.Context, CreateConversationCommand) (ConversationMutationResponse, error)
	DeleteConversationMutation(context.Context, DeleteConversationCommand) (ConversationMutationResponse, error)
}

// ConversationRenameStore is optional so legacy in-memory stores can keep the
// smaller conversation contract. Production PostgreSQL implements the
// idempotent revision-bound mutation.
type ConversationRenameStore interface {
	RenameConversationMutation(context.Context, string, string, uint64, string) (ConversationMutationResponse, error)
}

// ConversationContextStore is the production CAS/replay boundary for context
// compaction.  It updates only Agent-owned conversation state; transcript rows
// are intentionally retained for authoritative history and auditability.
type ConversationContextStore interface {
	CompressConversationContext(context.Context, string, string, WorkingContext, string, uint64, uint64, string) (Conversation, error)
}

func (c CreateConversationCommand) Validate() error {
	if !validUUID(c.RequestID) || !validUUID(c.Conversation.ID) || c.Conversation.Revision == 0 || len(c.Conversation.Messages) != 0 || len(c.Conversation.Title) > 512 || !utf8.ValidString(c.Conversation.Title) || c.Conversation.DeletedAt != nil || c.Fingerprint == "" || c.Fingerprint != digestConversation(c.Conversation) {
		return ErrInvalid
	}
	return nil
}
func (c DeleteConversationCommand) Validate() error {
	if !validUUID(c.RequestID) || !validUUID(c.ConversationID) || c.ExpectedRevision == 0 || c.Fingerprint == "" || c.Fingerprint != digest(fmt.Sprintf("%s:%d", c.ConversationID, c.ExpectedRevision)) {
		return ErrInvalid
	}
	return nil
}

type ChatLedger interface {
	ClaimChat(context.Context, string, string, string, string, []ExtensionSelection, time.Time, time.Duration) (ChatLease, error)
	RenewChat(context.Context, string, string, uint64, time.Time, time.Duration) (ChatLease, error)
	ReleaseChat(context.Context, string, string, uint64) error
	FailChat(context.Context, string, string, uint64, string, string) error
}
type ChatProfileSnapshotBinder interface {
	BindChatProfileSnapshot(context.Context, string, string, uint64, string, coremodel.ExecutionSnapshot) (ChatLease, error)
}
type ToolExecutionLedger interface {
	ClaimToolExecution(context.Context, string, string, string, string, time.Time, time.Duration) (ToolLease, error)
	MarkToolDispatched(context.Context, string, string, string, uint64) error
	CompleteToolExecution(context.Context, ToolCompletion) (ToolResult, error)
	TerminalizeToolUncertain(context.Context, string, string, string, uint64, string, uint64, string, string) error
	RenewToolExecution(context.Context, string, string, string, uint64, time.Time, time.Duration) (ToolLease, error)
	ReleaseToolExecution(context.Context, string, string, string, uint64) error
}
type Store interface {
	ConversationStore
	ConversationMutationStore
}
type ModelRunner interface {
	Run(context.Context, ModelRunRequest) (ModelRunResult, error)
}
type StreamingModelRunner interface {
	Stream(context.Context, ModelRunRequest, func(ModelDelta) error) (ModelRunResult, error)
}
type ModelDelta struct {
	Text             string
	ReasoningContent string
	ToolCall         *ToolCall
}
type ExtensionResolver interface {
	ResolveExtensions(context.Context, []ExtensionSelection) ([]ResolvedExtension, error)
}

// AutomaticExtensionSelector merges server-owned tools before a durable turn
// fingerprint is checked. Client selections remain exact inputs; the selector
// may only add its deterministic server-owned selection.
type AutomaticExtensionSelector interface {
	MergeAutomaticExtensions(context.Context, []ExtensionSelection) ([]ExtensionSelection, error)
}

// SnapshotProfileResolver is used only to bind a new request. Recovery uses
// the immutable snapshot persisted on its durable Turn.
type SnapshotProfileResolver interface {
	ResolveProfileSnapshot(context.Context, string) (coremodel.ExecutionSnapshot, error)
}

// CoreModelProfileResolver adapts the model domain resolver to the
// conversation snapshot boundary without exposing credentials in public
// conversation values.
type CoreModelProfileResolver struct {
	Resolver interface {
		ResolveProfile(context.Context, string) (coremodel.Profile, error)
	}
}

func AdaptProfileResolver(r interface {
	ResolveProfile(context.Context, string) (coremodel.Profile, error)
}) CoreModelProfileResolver {
	return CoreModelProfileResolver{Resolver: r}
}

func (a CoreModelProfileResolver) ResolveProfileSnapshot(ctx context.Context, id string) (coremodel.ExecutionSnapshot, error) {
	if a.Resolver == nil {
		return coremodel.ExecutionSnapshot{}, ErrInvalid
	}
	p, err := a.Resolver.ResolveProfile(ctx, id)
	if err != nil {
		return coremodel.ExecutionSnapshot{}, err
	}
	s := coremodel.SnapshotFromProfile(p)
	if err := s.Validate(); err != nil {
		return coremodel.ExecutionSnapshot{}, err
	}
	return s, nil
}

type ToolClaimStatus string

const (
	ToolClaimNew        ToolClaimStatus = "new"
	ToolClaimInFlight   ToolClaimStatus = "in_flight"
	ToolClaimCompleted  ToolClaimStatus = "completed"
	ToolClaimConflict   ToolClaimStatus = "conflict"
	ToolClaimReclaimed  ToolClaimStatus = "reclaimed"
	ToolClaimDispatched ToolClaimStatus = "dispatched"
	ToolClaimUncertain  ToolClaimStatus = "uncertain"
)

type ToolLease struct {
	RequestID, ToolCallID, LeaseID string
	Epoch                          uint64
	ExpiresAt                      time.Time
	Status                         ToolClaimStatus
	Result                         *ToolResult
	ExecutionID                    string
	ArgsDigest                     string
	ExtensionDigest                string
}
type ToolCompletion struct {
	RequestID, ToolCallID, LeaseID string
	Epoch                          uint64
	ArgsDigest, ExtensionDigest    string
	Result                         ToolResult
}

var (
	ErrInvalid                 = errors.New("invalid conversation request")
	ErrConflict                = errors.New("conversation conflict")
	ErrInFlight                = errors.New("chat request in flight")
	ErrCanceled                = errors.New("chat canceled")
	ErrLeaseExpired            = errors.New("chat lease expired")
	ErrDeleted                 = errors.New("conversation deleted")
	ErrChatFailed              = errors.New("chat failed")
	ErrToolDispatchStarted     = errors.New("conversation tool dispatch already started")
	ErrMemoryRecallUnavailable = errors.New("long-term memory recall is unavailable")
	ErrExtensionsUnsupported   = errors.New("conversation extensions require durable turn")
	ErrModelBudgetExhausted    = errors.New("conversation model budget exhausted")
	ErrTurnRuntimeIncompatible = errors.New("conversation turn runtime is incompatible")
)

func validUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && strings.ToLower(s) == id.String()
}

func validReferenceDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (r Reference) Validate() error {
	kind := strings.TrimSpace(r.Kind)
	if kind == "" || kind != r.Kind {
		return ErrInvalid
	}
	switch kind {
	case "execution_artifact":
		return validateExecutionArtifactReference(r)
	case "execution_plan", "execution_run", "execution_confirmation":
		if r.TaskID != "" {
			return validateCloudWorkerReference(r)
		}
		return validateGenericExecutionReference(r)
	case "service_binding":
		if hasCloudWorkerOnlyReferenceFields(r) || hasConversationReferenceFields(r) ||
			!validUUID(r.BindingID) || r.BindingRevision == 0 || !validReferenceDigest(r.BindingDigest) ||
			!validUUID(r.DeploymentID) || !validUUID(r.ProjectID) || !validUUID(r.RunID) ||
			!validUUID(r.TargetID) || r.TargetRevision == 0 || !validReferenceDigest(r.TargetDigest) ||
			r.PlanID != "" || r.PlanRevision != 0 || r.PlanDigest != "" || r.RunRevision != 0 || r.RunDigest != "" ||
			r.ConfirmationID != "" || r.ConfirmationRevision != 0 || r.StageID != "" || r.StageRevision != 0 ||
			r.StageDigest != "" || r.PreviewDigest != "" || r.RiskLevel != "" || r.GateType != "" || r.Status != "" || r.State != "" {
			return ErrInvalid
		}
		return nil
	case "room":
		if hasExecutionReferenceFields(r) || strings.TrimSpace(r.RoomID) == "" || r.RoomID != strings.TrimSpace(r.RoomID) || len(r.RoomID) > 512 || r.ChannelID != "" || r.PostID != "" || len(r.RoomType) > 128 || !utf8.ValidString(r.RoomType) || !validReferencePresentation(r) {
			return ErrInvalid
		}
		return nil
	case "channel_post":
		if hasExecutionReferenceFields(r) || strings.TrimSpace(r.RoomID) == "" || r.RoomID != strings.TrimSpace(r.RoomID) || strings.TrimSpace(r.ChannelID) == "" || r.ChannelID != strings.TrimSpace(r.ChannelID) || strings.TrimSpace(r.PostID) == "" || r.PostID != strings.TrimSpace(r.PostID) || len(r.RoomID) > 512 || len(r.ChannelID) > 512 || len(r.PostID) > 512 || r.RoomType != "" || !validReferencePresentation(r) {
			return ErrInvalid
		}
		return nil
	default:
		return ErrInvalid
	}
}

func validateExecutionArtifactReference(r Reference) error {
	if r.AccountGeneration == 0 || r.RecordKind != "local_sandbox" || !validUUID(r.ArtifactID) || !validUUID(r.ExecutionID) ||
		r.Name == "" || r.Name != strings.TrimSpace(r.Name) || len(r.Name) > 1024 || !utf8.ValidString(r.Name) ||
		path.IsAbs(r.Name) || path.Clean(r.Name) != r.Name || r.Name == "." || strings.HasPrefix(r.Name, "../") || strings.ContainsAny(r.Name, "\\\r\n\x00") ||
		r.MediaType == "" || r.MediaType != strings.TrimSpace(r.MediaType) || len(r.MediaType) > 255 || !utf8.ValidString(r.MediaType) || strings.ContainsAny(r.MediaType, "\r\n\x00") ||
		r.SizeBytes == nil || *r.SizeBytes > uint64(64<<20) || !validReferenceDigest(r.SHA256) {
		return ErrInvalid
	}
	copy := r
	copy.Kind, copy.RecordKind, copy.ArtifactID, copy.ExecutionID, copy.Name, copy.MediaType, copy.SHA256 = "", "", "", "", "", "", ""
	copy.AccountGeneration, copy.SizeBytes = 0, nil
	if copy != (Reference{}) {
		return ErrInvalid
	}
	return nil
}

func validateCloudWorkerReference(r Reference) error {
	if hasConversationReferenceFields(r) || r.AccountGeneration == 0 || !validUUID(r.TaskID) ||
		!validUUID(r.PlanID) || r.PlanRevision == 0 ||
		r.PlanDigest != "" || r.RunDigest != "" || r.BindingDigest != "" || r.QuoteDigest != "" || r.ExecutionDigest != "" ||
		r.DeploymentID != "" || r.StageID != "" || r.StageRevision != 0 || r.StageDigest != "" ||
		r.TargetID != "" || r.TargetRevision != 0 || r.TargetDigest != "" || r.PreviewDigest != "" ||
		r.RiskLevel != "" || r.GateType != "" || r.BindingID != "" || r.BindingRevision != 0 || r.ProjectID != "" {
		return ErrInvalid
	}
	switch r.Kind {
	case "execution_plan":
		if r.RunID != "" || r.RunRevision != 0 || r.ExecutionID != "" || r.WorkerID != "" ||
			r.ConfirmationID != "" || r.ConfirmationRevision != 0 || r.State != "" || !validExecutionReferenceStatus(r.Status) {
			return ErrInvalid
		}
	case "execution_run":
		if !validUUID(r.RunID) || r.RunRevision == 0 || !validUUID(r.ExecutionID) ||
			(r.WorkerID != "" && !validUUID(r.WorkerID)) || r.ConfirmationID != "" ||
			r.ConfirmationRevision != 0 || r.State != "" || !validExecutionReferenceStatus(r.Status) {
			return ErrInvalid
		}
	case "execution_confirmation":
		if r.RunID != "" || r.RunRevision != 0 || r.ExecutionID != "" || r.WorkerID != "" ||
			!validUUID(r.ConfirmationID) || r.ConfirmationRevision == 0 || r.Status != "" ||
			!validConfirmationReferenceState(r.State) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateGenericExecutionReference(r Reference) error {
	if hasConversationReferenceFields(r) || hasCloudWorkerOnlyReferenceFields(r) {
		return ErrInvalid
	}
	switch r.Kind {
	case "execution_plan":
		if !validUUID(r.PlanID) || r.PlanRevision == 0 || !validReferenceDigest(r.PlanDigest) ||
			r.RunID != "" || r.RunRevision != 0 || r.RunDigest != "" || r.DeploymentID != "" ||
			r.ConfirmationID != "" || r.ConfirmationRevision != 0 || r.StageID != "" || r.StageRevision != 0 ||
			r.StageDigest != "" || r.TargetID != "" || r.TargetRevision != 0 || r.TargetDigest != "" ||
			r.PreviewDigest != "" || r.BindingDigest != "" || r.RiskLevel != "" || r.GateType != "" ||
			r.BindingID != "" || r.BindingRevision != 0 || r.ProjectID != "" || r.Status != "" || r.State != "" {
			return ErrInvalid
		}
	case "execution_run":
		if !validUUID(r.RunID) || r.RunRevision == 0 || !validReferenceDigest(r.RunDigest) ||
			!validUUID(r.PlanID) || r.PlanRevision == 0 || !validReferenceDigest(r.PlanDigest) ||
			(r.DeploymentID != "" && !validUUID(r.DeploymentID)) || !validBoundedOptional(r.Status, 64) ||
			r.ConfirmationID != "" || r.ConfirmationRevision != 0 || r.StageID != "" || r.StageRevision != 0 ||
			r.StageDigest != "" || r.TargetID != "" || r.TargetRevision != 0 || r.TargetDigest != "" ||
			r.PreviewDigest != "" || r.BindingDigest != "" || r.RiskLevel != "" || r.GateType != "" ||
			r.BindingID != "" || r.BindingRevision != 0 || r.ProjectID != "" || r.State != "" {
			return ErrInvalid
		}
	case "execution_confirmation":
		if !validUUID(r.ConfirmationID) || !validUUID(r.PlanID) || r.PlanRevision == 0 || !validReferenceDigest(r.PlanDigest) ||
			!validUUID(r.RunID) || r.RunRevision == 0 || !validUUID(r.StageID) || r.StageRevision == 0 ||
			!validReferenceDigest(r.StageDigest) || !validUUID(r.TargetID) || r.TargetRevision == 0 ||
			!validReferenceDigest(r.TargetDigest) || r.DeploymentID != "" || r.BindingID != "" ||
			r.BindingRevision != 0 || r.ProjectID != "" || r.Status != "" {
			return ErrInvalid
		}
		full := r.ConfirmationRevision != 0 || r.BindingDigest != "" || r.PreviewDigest != ""
		if full {
			if r.ConfirmationRevision == 0 || !validReferenceDigest(r.BindingDigest) || !validReferenceDigest(r.PreviewDigest) ||
				r.RunDigest != "" || !validBoundedOptional(r.State, 64) || !validBoundedOptional(r.RiskLevel, 16) ||
				!validBoundedOptional(r.GateType, 128) {
				return ErrInvalid
			}
		} else if !validReferenceDigest(r.RunDigest) || r.State != "" || r.RiskLevel != "" || r.GateType != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validBoundedOptional(value string, limit int) bool {
	return value == strings.TrimSpace(value) && len(value) <= limit && utf8.ValidString(value)
}

func hasConversationReferenceFields(r Reference) bool {
	return r.RoomID != "" || r.RoomType != "" || r.ChannelID != "" || r.PostID != "" || r.Title != "" || r.Preview != ""
}

func hasCloudWorkerOnlyReferenceFields(r Reference) bool {
	return r.AccountGeneration != 0 || r.TaskID != "" || r.ExecutionID != "" || r.WorkerID != "" || r.QuoteDigest != "" || r.ExecutionDigest != ""
}

func hasExecutionReferenceFields(r Reference) bool {
	return hasCloudWorkerOnlyReferenceFields(r) || r.PlanID != "" || r.PlanRevision != 0 || r.PlanDigest != "" ||
		r.RunID != "" || r.RunRevision != 0 || r.RunDigest != "" || r.DeploymentID != "" ||
		r.ConfirmationID != "" || r.ConfirmationRevision != 0 || r.StageID != "" || r.StageRevision != 0 ||
		r.StageDigest != "" || r.TargetID != "" || r.TargetRevision != 0 || r.TargetDigest != "" ||
		r.PreviewDigest != "" || r.BindingDigest != "" || r.RiskLevel != "" || r.GateType != "" ||
		r.BindingID != "" || r.BindingRevision != 0 || r.ProjectID != "" || r.Status != "" || r.State != "" ||
		r.RecordKind != "" || r.ArtifactID != "" || r.Name != "" || r.MediaType != "" || r.SizeBytes != nil || r.SHA256 != ""
}

func validReferencePresentation(r Reference) bool {
	return len(r.Title) <= 512 && len(r.Preview) <= MaxSummaryBytes && utf8.ValidString(r.Title) && utf8.ValidString(r.Preview)
}

func referenceKey(value Reference) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func validateReferences(values []Reference) error {
	if len(values) > MaxReferences {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.Validate() != nil {
			return ErrInvalid
		}
		key := referenceKey(value)
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validExecutionReferenceStatus(value string) bool {
	switch value {
	case "waiting_user", "queued", "provisioning", "awaiting_worker", "running", "collecting", "validating", "cleaning", "succeeded", "failed", "canceled", "rejected", "expired":
		return true
	default:
		return false
	}
}

func validConfirmationReferenceState(value string) bool {
	switch value {
	case "pending", "confirmed", "consumed", "rejected", "expired":
		return true
	default:
		return false
	}
}

func cloneReferences(values []Reference) []Reference {
	out := append([]Reference(nil), values...)
	for index := range out {
		if out[index].SizeBytes != nil {
			value := *out[index].SizeBytes
			out[index].SizeBytes = &value
		}
	}
	return out
}
func validateText(s string, max int) error {
	if strings.TrimSpace(s) == "" || len(s) > max || !utf8.ValidString(s) {
		return ErrInvalid
	}
	return nil
}

func canonicalJSON(raw string, max int) ([]byte, error) {
	if len(raw) == 0 || len(raw) > max || !json.Valid([]byte(raw)) {
		return nil, ErrInvalid
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, ErrInvalid
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalid
	}
	out, err := json.Marshal(value)
	if err != nil || len(out) > max {
		return nil, ErrInvalid
	}
	return out, nil
}

func containsTool(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
func (c ToolCall) Validate() error {
	if err := c.validateIdentityAndBounds(); err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal([]byte(c.Arguments), &v); err != nil {
		return fmt.Errorf("%w: tool arguments", ErrInvalid)
	}
	if _, ok := v.(map[string]any); !ok {
		return fmt.Errorf("%w: tool arguments must be object", ErrInvalid)
	}
	return nil
}

func (c ToolCall) validateIdentityAndBounds() error {
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Name) == "" || len(c.ID) > MaxToolCallIDBytes || len(c.Name) > MaxToolNameBytes || len(c.ExecutionID) > MaxToolCallIDBytes || len(c.Arguments) > MaxToolArgumentsBytes || !utf8.ValidString(c.ID) || !utf8.ValidString(c.Name) || !utf8.ValidString(c.ExecutionID) || !utf8.ValidString(c.Arguments) {
		return ErrInvalid
	}
	return nil
}
func (r ToolResult) Validate() error {
	if strings.TrimSpace(r.CallID) == "" || !utf8.ValidString(r.CallID) {
		return ErrInvalid
	}
	if len(r.ToolName) > MaxToolNameBytes || !utf8.ValidString(r.ToolName) {
		return ErrInvalid
	}
	if err := validateText(r.Content, MaxToolResultsBytes); err != nil {
		return err
	}
	if len(r.RelatedTaskIDs) > MaxRelatedTaskIDs || len(r.RelatedPlanIDs) > MaxRelatedPlanIDs || len(r.Summary) > MaxSummaryBytes || !utf8.ValidString(r.Summary) || validateReferences(r.References) != nil {
		return ErrInvalid
	}
	for _, id := range r.RelatedTaskIDs {
		if !validUUID(id) {
			return ErrInvalid
		}
	}
	for _, id := range r.RelatedPlanIDs {
		if !validUUID(id) {
			return ErrInvalid
		}
	}
	return nil
}
func (m Message) Validate() error {
	if !validUUID(m.ID) || m.CreatedAt.IsZero() || m.CreatedAt.Location() != time.UTC || !validUUID(m.ModelProfileID) || len(m.ToolCalls) > MaxToolCallsPerMessage || len(m.ToolResults) > MaxToolResultsPerMessage {
		return ErrInvalid
	}
	if m.TurnID != "" && !validUUID(m.TurnID) {
		return ErrInvalid
	}
	if len(m.RelatedTaskIDs) > MaxRelatedTaskIDs || len(m.RelatedPlanIDs) > MaxRelatedPlanIDs || len(m.ToolSummaries) > MaxRelatedTaskIDs || validateReferences(m.References) != nil {
		return ErrInvalid
	}
	for _, id := range m.RelatedTaskIDs {
		if !validUUID(id) {
			return ErrInvalid
		}
	}
	for _, id := range m.RelatedPlanIDs {
		if !validUUID(id) {
			return ErrInvalid
		}
	}
	for _, s := range m.ToolSummaries {
		if len(s) > MaxSummaryBytes || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
			return ErrInvalid
		}
	}
	switch m.Role {
	case RoleSystem, RoleUser, RoleAssistant, RoleTool:
	default:
		return ErrInvalid
	}
	if len(m.Content) > MaxContentBytes || len(m.ReasoningContent) > MaxContentBytes || !utf8.ValidString(m.ReasoningContent) {
		return ErrInvalid
	}
	if m.Status != "" && m.Status != "done" && (m.Status != "failed" || m.Role != RoleAssistant) {
		return ErrInvalid
	}
	if m.Role != RoleTool && len(m.ToolResults) > 0 {
		return ErrInvalid
	}
	for _, c := range m.ToolCalls {
		if m.Role != RoleAssistant || c.Validate() != nil {
			return ErrInvalid
		}
	}
	for _, r := range m.ToolResults {
		if r.Validate() != nil {
			return ErrInvalid
		}
	}
	if m.Content == "" && len(m.ToolCalls) == 0 && len(m.ToolResults) == 0 {
		return ErrInvalid
	}
	return nil
}

func (c Conversation) ValidateForPersistence() error {
	if !validUUID(c.ID) || len(c.Title) > 512 || !utf8.ValidString(c.Title) || len(c.Summary) > MaxSummaryBytes || !utf8.ValidString(c.Summary) || c.Revision == 0 || len(c.Messages) > MaxMessages || c.ContextMessageOffset > uint64(len(c.Messages)) || c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() || c.CreatedAt.Location() != time.UTC || c.UpdatedAt.Location() != time.UTC || c.UpdatedAt.Before(c.CreatedAt) {
		return ErrInvalid
	}
	if c.WorkingContext.Version == "" {
		if c.WorkingContextProtectedDigest != "" {
			return ErrInvalid
		}
	} else if c.WorkingContext.Validate() != nil || c.WorkingContextProtectedDigest != "" && c.WorkingContextProtectedDigest != c.WorkingContext.ProtectedDigest() {
		return ErrInvalid
	}
	if c.DeletedAt != nil && (c.DeletedAt.IsZero() || c.DeletedAt.Location() != time.UTC || c.DeletedAt.Before(c.UpdatedAt)) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	knownCalls := map[string]bool{}
	var previous time.Time
	for _, m := range c.Messages {
		if m.Validate() != nil || seen[m.ID] {
			return ErrInvalid
		}
		seen[m.ID] = true
		if !previous.IsZero() && !m.CreatedAt.After(previous) {
			return ErrInvalid
		}
		previous = m.CreatedAt
		for _, call := range m.ToolCalls {
			knownCalls[call.ID] = true
		}
		for _, result := range m.ToolResults {
			if !knownCalls[result.CallID] {
				return ErrInvalid
			}
		}
	}
	return nil
}

func (c Conversation) Delete(expectedRevision uint64, now time.Time) (Conversation, error) {
	if err := c.ValidateForPersistence(); err != nil {
		return Conversation{}, err
	}
	if c.DeletedAt != nil || c.Revision != expectedRevision {
		return Conversation{}, ErrConflict
	}
	now = now.UTC()
	c.DeletedAt = &now
	c.Revision++
	c.UpdatedAt = now
	return c, nil
}
func (c Conversation) Validate() error {
	if c.DeletedAt != nil {
		return ErrDeleted
	}
	return c.ValidateForPersistence()
}
func (s ExtensionSelection) Validate() error {
	if !validUUID(s.ID) || (s.Kind != ExtensionMCP && s.Kind != ExtensionSkill && s.Kind != ExtensionKnowledge) || strings.TrimSpace(s.Version) == "" || strings.TrimSpace(s.Digest) == "" || !utf8.ValidString(s.Version) || !utf8.ValidString(s.Digest) {
		return ErrInvalid
	}
	for _, t := range s.AllowedTools {
		if strings.TrimSpace(t) == "" || coremodel.IsIntrinsicToolName(t) {
			return ErrInvalid
		}
	}
	return nil
}
func (c ChatCommand) Validate() error {
	if !validUUID(c.RequestID) || (c.ConversationID != "" && !validUUID(c.ConversationID)) || !validUUID(c.ProfileID) || c.ExpectedProfileRevision <= 0 || c.ExpectedCredentialVersion <= 0 {
		return ErrInvalid
	}
	if err := validateText(c.Prompt, MaxContentBytes); err != nil {
		return err
	}
	if _, err := NormalizeClientTurnExecutionMode(c.ExecutionMode); err != nil {
		return err
	}
	for _, e := range c.Extensions {
		if e.Validate() != nil {
			return ErrInvalid
		}
	}
	return nil
}

func (c ChatCommand) Fingerprint() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	type normalized struct {
		ConversationID, Prompt, ProfileID string
		ExpectedProfileRevision           int64
		ExpectedCredentialVersion         int64
		Extensions                        []ExtensionSelection
		ExpectedRevision                  *uint64
		ExecutionMode                     TurnExecutionMode
	}
	exts := append([]ExtensionSelection(nil), c.Extensions...)
	for i := range exts {
		exts[i].AllowedTools = append([]string(nil), exts[i].AllowedTools...)
		sort.Strings(exts[i].AllowedTools)
	}
	sort.Slice(exts, func(i, j int) bool {
		if exts[i].Kind != exts[j].Kind {
			return exts[i].Kind < exts[j].Kind
		}
		if exts[i].ID != exts[j].ID {
			return exts[i].ID < exts[j].ID
		}
		return exts[i].Version < exts[j].Version
	})
	uniq := exts[:0]
	for _, e := range exts {
		if len(uniq) == 0 || uniq[len(uniq)-1].Kind != e.Kind || uniq[len(uniq)-1].ID != e.ID || uniq[len(uniq)-1].Version != e.Version || uniq[len(uniq)-1].Digest != e.Digest {
			uniq = append(uniq, e)
		}
	}
	mode, _ := NormalizeClientTurnExecutionMode(c.ExecutionMode)
	n := normalized{c.ConversationID, c.Prompt, c.ProfileID, c.ExpectedProfileRevision, c.ExpectedCredentialVersion, uniq, c.ExpectedRevision, mode}
	b, err := json.Marshal(n)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (c ChatCommand) NormalizedExtensions() []ExtensionSelection {
	exts := append([]ExtensionSelection(nil), c.Extensions...)
	for i := range exts {
		exts[i].AllowedTools = append([]string(nil), exts[i].AllowedTools...)
		sort.Strings(exts[i].AllowedTools)
	}
	sort.Slice(exts, func(i, j int) bool {
		if exts[i].Kind != exts[j].Kind {
			return exts[i].Kind < exts[j].Kind
		}
		if exts[i].ID != exts[j].ID {
			return exts[i].ID < exts[j].ID
		}
		return exts[i].Version < exts[j].Version
	})
	uniq := exts[:0]
	for _, e := range exts {
		if len(uniq) == 0 || uniq[len(uniq)-1].Kind != e.Kind || uniq[len(uniq)-1].ID != e.ID || uniq[len(uniq)-1].Version != e.Version || uniq[len(uniq)-1].Digest != e.Digest {
			uniq = append(uniq, e)
		}
	}
	return uniq
}

func validateProfilePins(snapshot coremodel.ExecutionSnapshot, profileID string, revision, credentialVersion int64) error {
	if revision <= 0 || credentialVersion <= 0 || snapshot.ProfileID != profileID || snapshot.Revision != revision || snapshot.CredentialVersion != credentialVersion {
		return ErrConflict
	}
	return nil
}

func (c Conversation) Snapshot() Conversation {
	out := c
	out.WorkingContext = c.WorkingContext.Snapshot()
	out.Messages = append([]Message(nil), c.Messages...)
	for i := range out.Messages {
		out.Messages[i].ToolCalls = append([]ToolCall(nil), out.Messages[i].ToolCalls...)
		out.Messages[i].ToolResults = append([]ToolResult(nil), out.Messages[i].ToolResults...)
		for j := range out.Messages[i].ToolResults {
			out.Messages[i].ToolResults[j].RelatedTaskIDs = append([]string(nil), out.Messages[i].ToolResults[j].RelatedTaskIDs...)
			out.Messages[i].ToolResults[j].RelatedPlanIDs = append([]string(nil), out.Messages[i].ToolResults[j].RelatedPlanIDs...)
			out.Messages[i].ToolResults[j].References = cloneReferences(out.Messages[i].ToolResults[j].References)
		}
		out.Messages[i].RelatedTaskIDs = append([]string(nil), out.Messages[i].RelatedTaskIDs...)
		out.Messages[i].RelatedPlanIDs = append([]string(nil), out.Messages[i].RelatedPlanIDs...)
		out.Messages[i].References = cloneReferences(out.Messages[i].References)
		out.Messages[i].ToolSummaries = append([]string(nil), out.Messages[i].ToolSummaries...)
	}
	return out
}
