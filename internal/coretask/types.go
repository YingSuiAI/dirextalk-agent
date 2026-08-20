// Package coretask contains the Core v1 task and schedule domain contracts.
package coretask

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

type Status string

const (
	StatusQueued      Status = "queued"
	StatusRunning     Status = "running"
	StatusSucceeded   Status = "succeeded"
	StatusFailed      Status = "failed"
	StatusWaitingUser Status = "waiting_user"
	StatusCanceled    Status = "canceled"
)

// TaskKind is a closed discriminator for durable Core v1 task payloads.
type TaskKind string

const (
	TaskKindAgent            TaskKind = "agent"
	TaskKindExtension        TaskKind = "extension"
	TaskKindKnowledgeIndex   TaskKind = "knowledge_index"
	TaskKindWorkload         TaskKind = "workload"
	TaskKindConversationTool TaskKind = "conversation_tool"
	TaskKindCloudWorker      TaskKind = "cloud_worker"
)

// AgentTaskPayload is optional for direct Task creation and required for a
// schedule created from an authenticated conversation turn. It contains only
// immutable account authority, never credentials or arbitrary references.
type AgentTaskPayload struct {
	OwnerID               string                       `json:"owner_id"`
	AccountGeneration     uint64                       `json:"account_generation"`
	ScheduledConversation *ScheduledConversationOrigin `json:"scheduled_conversation,omitempty"`
}

// ScheduledCapability is the closed workflow contract selected when a Native
// conversation creates a durable schedule. It is not a generic permission to
// replay every extension that happened to be available on the creating turn.
type ScheduledCapability string

const (
	ScheduledCapabilityScheduledNote       ScheduledCapability = "scheduled_note"
	ScheduledCapabilityChatSummary         ScheduledCapability = "chat_summary"
	ScheduledCapabilityWebResearch         ScheduledCapability = "web_research"
	ScheduledCapabilityRoomMessage         ScheduledCapability = "room_message"
	ScheduledCapabilityContactReport       ScheduledCapability = "contact_report"
	ScheduledCapabilityRoomMemberReport    ScheduledCapability = "room_member_report"
	ScheduledCapabilityChannelDigest       ScheduledCapability = "channel_digest"
	ScheduledCapabilityChatSummaryDelivery ScheduledCapability = "chat_summary_delivery"
	ScheduledCapabilityWebDigestDelivery   ScheduledCapability = "web_digest_delivery"
)

// ScheduledCapabilityToolBinding names one model-facing provider tool and its
// human-readable logical name. Both names are immutable capability contract.
type ScheduledCapabilityToolBinding struct {
	LogicalName  string
	ProviderName string
}

// ScheduledCapabilityBinding is one ordered extension source in a scheduled
// workflow. A capability may require multiple sources; order is authoritative.
type ScheduledCapabilityBinding struct {
	Source string
	Tools  []ScheduledCapabilityToolBinding
}

func messageScheduledBinding(names ...string) ScheduledCapabilityBinding {
	tools := make([]ScheduledCapabilityToolBinding, 0, len(names))
	for _, name := range names {
		tools = append(tools, ScheduledCapabilityToolBinding{LogicalName: name, ProviderName: "mcp__message__" + name})
	}
	return ScheduledCapabilityBinding{Source: "message-mcp", Tools: tools}
}

func directScheduledBinding(source string, names ...string) ScheduledCapabilityBinding {
	tools := make([]ScheduledCapabilityToolBinding, 0, len(names))
	for _, name := range names {
		tools = append(tools, ScheduledCapabilityToolBinding{LogicalName: name, ProviderName: name})
	}
	return ScheduledCapabilityBinding{Source: source, Tools: tools}
}

// RequiredBindings returns the complete ordered multi-source capability
// closure. No caller may add a source or provider tool to this list.
func (c ScheduledCapability) RequiredBindings() ([]ScheduledCapabilityBinding, error) {
	switch c {
	case ScheduledCapabilityScheduledNote:
		return []ScheduledCapabilityBinding{}, nil
	case ScheduledCapabilityChatSummary:
		return []ScheduledCapabilityBinding{messageScheduledBinding("dirextalk_rooms_search", "dirextalk_messages_list")}, nil
	case ScheduledCapabilityWebResearch:
		return []ScheduledCapabilityBinding{directScheduledBinding("builtin:web_search:tavily", "web_search")}, nil
	case ScheduledCapabilityRoomMessage:
		return []ScheduledCapabilityBinding{messageScheduledBinding("dirextalk_rooms_search", "dirextalk_messages_send")}, nil
	case ScheduledCapabilityContactReport:
		return []ScheduledCapabilityBinding{messageScheduledBinding("dirextalk_contacts_list", "dirextalk_contacts_search")}, nil
	case ScheduledCapabilityRoomMemberReport:
		return []ScheduledCapabilityBinding{messageScheduledBinding("dirextalk_rooms_search", "dirextalk_room_members_list")}, nil
	case ScheduledCapabilityChannelDigest:
		return []ScheduledCapabilityBinding{messageScheduledBinding("dirextalk_rooms_search", "dirextalk_channel_posts_list", "dirextalk_channel_comments_list")}, nil
	case ScheduledCapabilityChatSummaryDelivery:
		return []ScheduledCapabilityBinding{messageScheduledBinding("dirextalk_rooms_search", "dirextalk_messages_list", "dirextalk_messages_send")}, nil
	case ScheduledCapabilityWebDigestDelivery:
		return []ScheduledCapabilityBinding{
			directScheduledBinding("builtin:web_search:tavily", "web_search"),
			messageScheduledBinding("dirextalk_rooms_search", "dirextalk_messages_send"),
		}, nil
	default:
		return nil, ErrInvalid
	}
}

// ScheduledConversationOrigin is the internal durable handoff from a Native
// conversation turn into a scheduled Agent Task. It is intentionally absent
// from ordinary user-created Agent Tasks. The snapshots are redacted execution
// bindings; credentials and executable closures remain behind the live Native
// resolver and must be revalidated before each scheduled turn starts.
type ScheduledConversationOrigin struct {
	Capability         ScheduledCapability          `json:"capability"`
	Timezone           string                       `json:"timezone"`
	ExtensionSnapshots []ScheduledExtensionSnapshot `json:"extension_snapshots"`
}

func (o ScheduledConversationOrigin) Validate() error {
	capability := ScheduledCapability(strings.TrimSpace(string(o.Capability)))
	timezone := strings.TrimSpace(o.Timezone)
	if capability != o.Capability || timezone != o.Timezone || timezone == "" || len([]byte(timezone)) > 128 || !utf8.ValidString(timezone) {
		return ErrInvalid
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return ErrInvalid
	}
	if _, err := capability.RequiredBindings(); err != nil {
		return err
	}
	if o.ExtensionSnapshots == nil {
		return ErrInvalid
	}
	snapshots, err := normalizeScheduledCapabilitySnapshots(capability, o.ExtensionSnapshots)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(snapshots, o.ExtensionSnapshots) {
		return ErrInvalid
	}
	return nil
}

// ScheduledExtensionSnapshot mirrors only the immutable, non-secret portion
// of a Native turn extension snapshot without introducing a coretask ->
// coreconversation package cycle.
type ScheduledExtensionSnapshot struct {
	Selection            ExtensionSelection `json:"selection"`
	InstallationID       string             `json:"installation_id"`
	VersionID            string             `json:"version_id"`
	InstallationRevision uint64             `json:"installation_revision,omitempty"`
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

// WorkloadTaskPayload is the immutable execution fence for a workload
// operation.  It deliberately contains identifiers and digests only; provider
// credentials and secret values remain behind their typed provider boundary.
type WorkloadTaskPayload struct {
	WorkloadID        string          `json:"workload_id"`
	PlanID            string          `json:"plan_id"`
	OperationID       string          `json:"operation_id"`
	PlanRevision      uint64          `json:"plan_revision"`
	PlanDigest        string          `json:"plan_digest"`
	TargetKind        string          `json:"target_kind"`
	ConfirmationID    string          `json:"confirmation_id"`
	ExecutionSnapshot json.RawMessage `json:"execution_snapshot,omitempty"`
}

// CloudWorkerTaskPayload is the complete scheduler handoff. It intentionally
// contains only stable identities and authorization digests; objective text,
// manifests, credentials and provider templates remain in their typed stores.
type CloudWorkerTaskPayload struct {
	ExecutionID       string `json:"execution_id"`
	AccountGeneration uint64 `json:"account_generation"`
	PlanID            string `json:"plan_id"`
	PlanRevision      uint64 `json:"plan_revision"`
	PlanDigest        string `json:"plan_digest"`
	ConfirmationID    string `json:"confirmation_id"`
	TurnID            string `json:"turn_id"`
	ConversationID    string `json:"conversation_id"`
	QuoteDigest       string `json:"quote_digest"`
	ExecutionDigest   string `json:"execution_digest"`
}

type ExtensionOperation string

const (
	ExtensionOperationInstall      ExtensionOperation = "install"
	ExtensionOperationUpdate       ExtensionOperation = "update"
	ExtensionOperationUninstall    ExtensionOperation = "uninstall"
	ExtensionOperationExecuteTool  ExtensionOperation = "execute_tool"
	ExtensionOperationExecuteSkill ExtensionOperation = "execute_skill"
)

// ExtensionExecutionTarget is the immutable scheduler lane selected when an
// extension work task is created. It is deliberately not inferred from
// the mutable installation projection while claiming work.
type ExtensionExecutionTarget string

const (
	ExtensionExecutionTargetLocalSandbox    ExtensionExecutionTarget = "local_sandbox"
	ExtensionExecutionTargetRemoteExtension ExtensionExecutionTarget = "remote_extension"
	ExtensionExecutionTargetStaticSkill     ExtensionExecutionTarget = "static_skill"
)

const (
	MaxCanonicalInputBytes = 64 << 10
	MaxSourceIDCount       = 128
)

type ExtensionTaskPayload struct {
	Operation          ExtensionOperation       `json:"operation"`
	ExecutionTarget    ExtensionExecutionTarget `json:"execution_target,omitempty"`
	InstallationID     string                   `json:"installation_id"`
	ExpectedRevision   uint64                   `json:"expected_revision,omitempty"`
	Version            string                   `json:"version"`
	Digest             string                   `json:"digest"`
	ArtifactDigest     string                   `json:"artifact_digest,omitempty"`
	ConfirmationID     string                   `json:"confirmation_id,omitempty"`
	ToolName           string                   `json:"tool_name,omitempty"`
	CanonicalInputJSON json.RawMessage          `json:"input_json,omitempty"`
}

// ConversationToolTaskPayload is the exact durable handoff from a turn to
// the common task/runner path. It contains only IDs and digests; arguments
// are represented by their digest and a bounded safe summary.
type ConversationToolTaskPayload struct {
	TurnID                  string                   `json:"turn_id"`
	AttemptID               string                   `json:"attempt_id"`
	Round                   uint32                   `json:"round"`
	CallID                  string                   `json:"call_id"`
	ExtensionSnapshotDigest string                   `json:"extension_snapshot_digest"`
	InstallationID          string                   `json:"installation_id"`
	VersionID               string                   `json:"version_id"`
	InstallationRevision    uint64                   `json:"installation_revision"`
	ToolName                string                   `json:"tool_name"`
	ToolSchemaDigest        string                   `json:"tool_schema_digest"`
	ArgumentsDigest         string                   `json:"arguments_digest"`
	ConfirmationID          string                   `json:"confirmation_id,omitempty"`
	SafeSummary             string                   `json:"safe_summary,omitempty"`
	ExecutionTarget         ExtensionExecutionTarget `json:"execution_target"`
	ReadOnly                bool                     `json:"read_only"`
}

type KnowledgeIndexTaskPayload struct {
	SourceIDs              []string `json:"source_ids"`
	ExpectedSourceRevision []uint64 `json:"expected_source_revisions"`
	CollectionConfigDigest string   `json:"collection_config_digest"`
}

// TaskPayload is a closed union; exactly one branch must match Kind.
type TaskPayload struct {
	Agent            *AgentTaskPayload            `json:"agent,omitempty"`
	ConversationTool *ConversationToolTaskPayload `json:"conversation_tool,omitempty"`
	Extension        *ExtensionTaskPayload        `json:"extension,omitempty"`
	KnowledgeIndex   *KnowledgeIndexTaskPayload   `json:"knowledge_index,omitempty"`
	Workload         *WorkloadTaskPayload         `json:"workload,omitempty"`
	CloudWorker      *CloudWorkerTaskPayload      `json:"cloud_worker,omitempty"`
}

var (
	ErrInvalid          = errors.New("coretask: invalid")
	ErrConflict         = errors.New("coretask: conflict")
	ErrRevisionConflict = errors.New("coretask: revision conflict")
	ErrLeaseConflict    = errors.New("coretask: lease conflict")
	ErrDispatchStarted  = errors.New("coretask: workload dispatch already started")
	ErrNotFound         = errors.New("coretask: not found")
	ErrTerminal         = errors.New("coretask: terminal task")
	ErrTimedOut         = errors.New("task_timed_out")
)

const (
	MaxGoalBytes        = 64 << 10
	MaxRefCount         = 128
	MaxRefBytes         = 512
	MaxProgressMessage  = 4 << 10
	MaxTimeoutSeconds   = int64((30 * 24 * time.Hour) / time.Second)
	MaxResultBytes      = 1 << 20
	MaxResultTextBytes  = 64 << 10
	MaxFileCount        = 128
	MaxFilePathBytes    = 1024
	MaxSummaryBytes     = 4 << 10
	MaxLeaseHolderBytes = 256
	MaxToolCallIDBytes  = 256
)

type TaskSpec struct {
	Kind           TaskKind             `json:"kind,omitempty"`
	Payload        TaskPayload          `json:"payload,omitempty"`
	Goal           string               `json:"goal"`
	ConversationID string               `json:"conversation_id,omitempty"`
	AttachmentRefs []string             `json:"attachment_refs,omitempty"`
	ModelProfileID string               `json:"model_profile_id"`
	Extensions     []ExtensionSelection `json:"extensions,omitempty"`
	KnowledgeRefs  []string             `json:"knowledge_refs,omitempty"`
	TimeoutSeconds int64                `json:"timeout_seconds,omitempty"`
	IdempotencyKey string               `json:"idempotency_key"`
	AvailableAt    time.Time            `json:"available_at,omitempty"`
}

type ExtensionKind string

const (
	ExtensionMCP   ExtensionKind = "mcp"
	ExtensionSkill ExtensionKind = "skill"
)

type ExtensionSelection struct {
	Kind         ExtensionKind `json:"kind"`
	ID           string        `json:"id"`
	Version      string        `json:"version"`
	Digest       string        `json:"digest"`
	AllowedTools []string      `json:"allowed_tools,omitempty"`
}

func normalizeExtensions(in []ExtensionSelection) ([]ExtensionSelection, error) {
	if len(in) > MaxRefCount {
		return nil, ErrInvalid
	}
	out := make([]ExtensionSelection, 0, len(in))
	for _, e := range in {
		e.ID = strings.TrimSpace(e.ID)
		e.Version = strings.TrimSpace(e.Version)
		e.Digest = strings.TrimSpace(e.Digest)
		if (e.Kind != ExtensionMCP && e.Kind != ExtensionSkill) || !ValidUUID(e.ID) || e.Version == "" || len([]byte(e.Version)) > 128 || !utf8.ValidString(e.Version) || len(e.Digest) != 64 || strings.ToLower(e.Digest) != e.Digest {
			return nil, ErrInvalid
		}
		if _, err := hex.DecodeString(e.Digest); err != nil {
			return nil, ErrInvalid
		}
		tools, err := normalizeRefs(e.AllowedTools)
		if err != nil {
			return nil, err
		}
		e.AllowedTools = tools
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Digest < out[j].Digest
	})
	for i := 1; i < len(out); i++ {
		if out[i].Kind == out[i-1].Kind && out[i].ID == out[i-1].ID && out[i].Version == out[i-1].Version && out[i].Digest == out[i-1].Digest {
			return nil, ErrConflict
		}
	}
	return out, nil
}

type TaskTemplate struct {
	Kind           TaskKind             `json:"kind,omitempty"`
	Payload        TaskPayload          `json:"payload,omitempty"`
	Goal           string               `json:"goal"`
	ConversationID string               `json:"conversation_id,omitempty"`
	AttachmentRefs []string             `json:"attachment_refs,omitempty"`
	ModelProfileID string               `json:"model_profile_id"`
	Extensions     []ExtensionSelection `json:"extensions,omitempty"`
	KnowledgeRefs  []string             `json:"knowledge_refs,omitempty"`
	TimeoutSeconds int64                `json:"timeout_seconds,omitempty"`
}

func (t TaskTemplate) Normalize() (TaskTemplate, error) {
	kind := t.Kind
	if kind == "" {
		kind = TaskKindAgent
	}
	dynamicScheduledProfile := kind == TaskKindAgent && strings.TrimSpace(t.ModelProfileID) == "" &&
		t.Payload.Agent != nil && t.Payload.Agent.ScheduledConversation != nil
	modelProfileID := t.ModelProfileID
	if dynamicScheduledProfile {
		// Native schedules intentionally do not freeze the model selected by the
		// creating turn. Materialization replaces this validation-only sentinel
		// with the then-current default before producing an ordinary TaskSpec.
		modelProfileID = "00000000-0000-4000-8000-000000000001"
	}
	s, err := (TaskSpec{Kind: t.Kind, Payload: t.Payload, Goal: t.Goal, ConversationID: t.ConversationID, AttachmentRefs: t.AttachmentRefs, ModelProfileID: modelProfileID, Extensions: t.Extensions, KnowledgeRefs: t.KnowledgeRefs, TimeoutSeconds: t.TimeoutSeconds, IdempotencyKey: "00000000-0000-4000-8000-000000000001"}).Normalize()
	if err != nil {
		return TaskTemplate{}, err
	}
	if dynamicScheduledProfile {
		s.ModelProfileID = ""
	}
	return TaskTemplate{Kind: s.Kind, Payload: s.Payload, Goal: s.Goal, ConversationID: s.ConversationID, AttachmentRefs: s.AttachmentRefs, ModelProfileID: s.ModelProfileID, Extensions: s.Extensions, KnowledgeRefs: s.KnowledgeRefs, TimeoutSeconds: s.TimeoutSeconds}, nil
}
func (t TaskTemplate) Validate() error { _, err := t.Normalize(); return err }
func (t TaskTemplate) Materialize(idempotencyKey string, availableAt time.Time) (TaskSpec, error) {
	n, err := t.Normalize()
	if err != nil {
		return TaskSpec{}, err
	}
	if !ValidUUID(idempotencyKey) || availableAt.IsZero() {
		return TaskSpec{}, ErrInvalid
	}
	return TaskSpec{Kind: n.Kind, Payload: n.Payload, Goal: n.Goal, ConversationID: n.ConversationID, AttachmentRefs: n.AttachmentRefs, ModelProfileID: n.ModelProfileID, Extensions: n.Extensions, KnowledgeRefs: n.KnowledgeRefs, TimeoutSeconds: n.TimeoutSeconds, IdempotencyKey: idempotencyKey, AvailableAt: availableAt.UTC()}.Normalize()
}

func (s TaskSpec) Normalize() (TaskSpec, error) {
	if s.Kind == "" {
		s.Kind = TaskKindAgent
	}
	goal := strings.TrimSpace(s.Goal)
	s.ModelProfileID = strings.TrimSpace(s.ModelProfileID)
	s.ConversationID = strings.TrimSpace(s.ConversationID)
	s.IdempotencyKey = strings.TrimSpace(s.IdempotencyKey)
	if goal == "" || !utf8.ValidString(s.Goal) || len([]byte(s.Goal)) > MaxGoalBytes || !ValidUUID(s.IdempotencyKey) {
		return TaskSpec{}, ErrInvalid
	}
	if err := normalizePayload(&s); err != nil {
		return TaskSpec{}, err
	}
	if (s.Kind == TaskKindAgent || s.Kind == TaskKindKnowledgeIndex) && !ValidUUID(s.ModelProfileID) {
		return TaskSpec{}, ErrInvalid
	}
	if s.Kind != TaskKindAgent && s.Kind != TaskKindKnowledgeIndex && s.ModelProfileID != "" && !ValidUUID(s.ModelProfileID) {
		return TaskSpec{}, ErrInvalid
	}
	if s.Kind != TaskKindAgent && s.Kind != TaskKindCloudWorker && s.Kind != TaskKindConversationTool && (s.ConversationID != "" || len(s.AttachmentRefs) != 0 || len(s.Extensions) != 0 || len(s.KnowledgeRefs) != 0) {
		return TaskSpec{}, ErrInvalid
	}
	if s.Kind == TaskKindConversationTool && (len(s.AttachmentRefs) != 0 || len(s.Extensions) != 0 || len(s.KnowledgeRefs) != 0) {
		return TaskSpec{}, ErrInvalid
	}
	if s.Kind == TaskKindCloudWorker && (len(s.AttachmentRefs) != 0 || len(s.Extensions) != 0 || len(s.KnowledgeRefs) != 0) {
		return TaskSpec{}, ErrInvalid
	}
	if s.ConversationID != "" && !ValidUUID(s.ConversationID) {
		return TaskSpec{}, ErrInvalid
	}
	if s.TimeoutSeconds < 0 || s.TimeoutSeconds > MaxTimeoutSeconds {
		return TaskSpec{}, ErrInvalid
	}
	var err error
	if s.AttachmentRefs, err = normalizeRefs(s.AttachmentRefs); err != nil {
		return TaskSpec{}, err
	}
	if s.Extensions, err = normalizeExtensions(s.Extensions); err != nil {
		return TaskSpec{}, err
	}
	if s.KnowledgeRefs, err = normalizeRefs(s.KnowledgeRefs); err != nil {
		return TaskSpec{}, err
	}
	if !s.AvailableAt.IsZero() {
		s.AvailableAt = s.AvailableAt.UTC()
	}
	return s, nil
}

func normalizePayload(s *TaskSpec) error {
	count := 0
	if s.Payload.Agent != nil {
		count++
	}
	if s.Payload.Extension != nil {
		count++
	}
	if s.Payload.KnowledgeIndex != nil {
		count++
	}
	if s.Payload.Workload != nil {
		count++
	}
	if s.Payload.ConversationTool != nil {
		count++
	}
	if s.Payload.CloudWorker != nil {
		count++
	}
	switch s.Kind {
	case TaskKindAgent:
		if count > 1 || (count == 1 && s.Payload.Agent == nil) {
			return ErrInvalid
		}
		if p := s.Payload.Agent; p != nil {
			p.OwnerID = strings.TrimSpace(p.OwnerID)
			if p.OwnerID == "" || len([]byte(p.OwnerID)) > 512 || !utf8.ValidString(p.OwnerID) || p.AccountGeneration == 0 {
				return ErrInvalid
			}
			if p.ScheduledConversation != nil {
				p.ScheduledConversation.Capability = ScheduledCapability(strings.TrimSpace(string(p.ScheduledConversation.Capability)))
				if strings.TrimSpace(p.ScheduledConversation.Timezone) != p.ScheduledConversation.Timezone || p.ScheduledConversation.Timezone == "" || len([]byte(p.ScheduledConversation.Timezone)) > 128 || !utf8.ValidString(p.ScheduledConversation.Timezone) {
					return ErrInvalid
				}
				if _, err := time.LoadLocation(p.ScheduledConversation.Timezone); err != nil {
					return ErrInvalid
				}
				snapshots, err := normalizeScheduledCapabilitySnapshots(p.ScheduledConversation.Capability, p.ScheduledConversation.ExtensionSnapshots)
				if err != nil {
					return err
				}
				p.ScheduledConversation.ExtensionSnapshots = snapshots
			}
		}
	case TaskKindExtension:
		if count != 1 || s.Payload.Extension == nil {
			return ErrInvalid
		}
		p := s.Payload.Extension
		if !ValidUUID(strings.TrimSpace(p.InstallationID)) || !validExtensionOperation(p.Operation) || strings.TrimSpace(p.Version) == "" || len([]byte(p.Version)) > 128 || len(p.Digest) != 64 || strings.ToLower(p.Digest) != p.Digest {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(p.Digest); err != nil {
			return ErrInvalid
		}
		p.InstallationID = strings.TrimSpace(p.InstallationID)
		p.Version = strings.TrimSpace(p.Version)
		p.Digest = strings.TrimSpace(p.Digest)
		lifecycle := p.Operation == ExtensionOperationInstall || p.Operation == ExtensionOperationUpdate || p.Operation == ExtensionOperationUninstall
		if lifecycle {
			if !ValidUUID(strings.TrimSpace(p.ConfirmationID)) || p.ExecutionTarget != "" || p.ToolName != "" || len(p.CanonicalInputJSON) != 0 {
				return ErrInvalid
			}
			p.ConfirmationID = strings.TrimSpace(p.ConfirmationID)
		} else {
			if p.ExpectedRevision == 0 || !validExtensionExecutionTarget(p.ExecutionTarget) || (p.ConfirmationID != "" && !ValidUUID(strings.TrimSpace(p.ConfirmationID))) || len(p.CanonicalInputJSON) == 0 || len(p.CanonicalInputJSON) > MaxCanonicalInputBytes || !json.Valid(p.CanonicalInputJSON) {
				return ErrInvalid
			}
			if (p.Operation == ExtensionOperationExecuteTool && p.ExecutionTarget == ExtensionExecutionTargetStaticSkill) ||
				(p.Operation == ExtensionOperationExecuteSkill && p.ExecutionTarget == ExtensionExecutionTargetRemoteExtension) {
				return ErrInvalid
			}
			var v any
			if err := json.Unmarshal(p.CanonicalInputJSON, &v); err != nil {
				return ErrInvalid
			}
			if containsForbiddenInput(v) {
				return ErrInvalid
			}
			canonical, _ := json.Marshal(v)
			p.CanonicalInputJSON = canonical
			p.ToolName = strings.TrimSpace(p.ToolName)
		}
	case TaskKindConversationTool:
		if count != 1 || s.Payload.ConversationTool == nil {
			return ErrInvalid
		}
		p := s.Payload.ConversationTool
		if !ValidUUID(p.TurnID) || !ValidUUID(p.AttemptID) || strings.TrimSpace(p.CallID) == "" || len([]byte(p.CallID)) > MaxToolCallIDBytes || !utf8.ValidString(p.CallID) || !ValidUUID(p.InstallationID) || !ValidUUID(p.VersionID) || p.InstallationRevision == 0 || strings.TrimSpace(p.ToolName) == "" || !ValidDigest(p.ExtensionSnapshotDigest) || !ValidDigest(p.ToolSchemaDigest) || !ValidDigest(p.ArgumentsDigest) || len([]byte(p.SafeSummary)) > MaxSummaryBytes || !validExtensionExecutionTarget(p.ExecutionTarget) {
			return ErrInvalid
		}
	case TaskKindKnowledgeIndex:
		if count != 1 || s.Payload.KnowledgeIndex == nil {
			return ErrInvalid
		}
		p := s.Payload.KnowledgeIndex
		if len(p.SourceIDs) == 0 || len(p.SourceIDs) > MaxSourceIDCount || len(p.SourceIDs) != len(p.ExpectedSourceRevision) || strings.TrimSpace(p.CollectionConfigDigest) == "" || len(p.CollectionConfigDigest) != 64 || strings.ToLower(p.CollectionConfigDigest) != p.CollectionConfigDigest {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(p.CollectionConfigDigest); err != nil {
			return ErrInvalid
		}
		for i := range p.SourceIDs {
			if strings.TrimSpace(p.SourceIDs[i]) == "" || p.ExpectedSourceRevision[i] == 0 {
				return ErrInvalid
			}
			p.SourceIDs[i] = strings.TrimSpace(p.SourceIDs[i])
		}
		for i := 1; i < len(p.SourceIDs); i++ {
			if p.SourceIDs[i] <= p.SourceIDs[i-1] {
				return ErrInvalid
			}
		}
	case TaskKindWorkload:
		if count != 1 || s.Payload.Workload == nil {
			return ErrInvalid
		}
		p := s.Payload.Workload
		if !ValidUUID(strings.TrimSpace(p.WorkloadID)) || !ValidUUID(strings.TrimSpace(p.PlanID)) || !ValidUUID(strings.TrimSpace(p.OperationID)) || !ValidUUID(strings.TrimSpace(p.ConfirmationID)) || p.PlanRevision == 0 || !ValidDigest(p.PlanDigest) || !validWorkloadTarget(p.TargetKind) || len(p.ExecutionSnapshot) > MaxResultBytes || (len(p.ExecutionSnapshot) > 0 && !json.Valid(p.ExecutionSnapshot)) {
			return ErrInvalid
		}
		p.WorkloadID = strings.TrimSpace(p.WorkloadID)
		p.PlanID = strings.TrimSpace(p.PlanID)
		p.OperationID = strings.TrimSpace(p.OperationID)
		p.ConfirmationID = strings.TrimSpace(p.ConfirmationID)
		p.PlanDigest = strings.TrimSpace(p.PlanDigest)
		if len(p.ExecutionSnapshot) > 0 {
			var v any
			if json.Unmarshal(p.ExecutionSnapshot, &v) != nil {
				return ErrInvalid
			}
			p.ExecutionSnapshot, _ = json.Marshal(v)
		}
	case TaskKindCloudWorker:
		if count != 1 || s.Payload.CloudWorker == nil {
			return ErrInvalid
		}
		p := s.Payload.CloudWorker
		if !ValidUUID(strings.TrimSpace(p.ExecutionID)) || p.AccountGeneration == 0 || !ValidUUID(strings.TrimSpace(p.PlanID)) || p.PlanRevision == 0 || !ValidDigest(strings.TrimSpace(p.PlanDigest)) || !ValidUUID(strings.TrimSpace(p.ConfirmationID)) || !ValidUUID(strings.TrimSpace(p.TurnID)) || !ValidUUID(strings.TrimSpace(p.ConversationID)) || !ValidDigest(strings.TrimSpace(p.QuoteDigest)) || !ValidDigest(strings.TrimSpace(p.ExecutionDigest)) || (s.ConversationID != "" && s.ConversationID != strings.TrimSpace(p.ConversationID)) {
			return ErrInvalid
		}
		p.ExecutionID = strings.TrimSpace(p.ExecutionID)
		p.PlanID = strings.TrimSpace(p.PlanID)
		p.PlanDigest = strings.TrimSpace(p.PlanDigest)
		p.ConfirmationID = strings.TrimSpace(p.ConfirmationID)
		p.TurnID = strings.TrimSpace(p.TurnID)
		p.ConversationID = strings.TrimSpace(p.ConversationID)
		p.QuoteDigest = strings.TrimSpace(p.QuoteDigest)
		p.ExecutionDigest = strings.TrimSpace(p.ExecutionDigest)
	default:
		return ErrInvalid
	}
	return nil
}

func normalizeScheduledExtensionSnapshots(in []ScheduledExtensionSnapshot) ([]ScheduledExtensionSnapshot, error) {
	if len(in) > MaxRefCount {
		return nil, ErrInvalid
	}
	out := make([]ScheduledExtensionSnapshot, 0, len(in))
	seenSelections := make(map[string]struct{}, len(in))
	seenTools := make(map[string]struct{})
	for _, snapshot := range in {
		normalizedSelections, err := normalizeExtensions([]ExtensionSelection{snapshot.Selection})
		if err != nil || len(normalizedSelections) != 1 {
			return nil, ErrInvalid
		}
		snapshot.Selection = normalizedSelections[0]
		snapshot.InstallationID = strings.TrimSpace(snapshot.InstallationID)
		snapshot.VersionID = strings.TrimSpace(snapshot.VersionID)
		snapshot.Source = strings.TrimSpace(snapshot.Source)
		snapshot.ContentDigest = strings.ToLower(strings.TrimSpace(snapshot.ContentDigest))
		snapshot.ArtifactDigest = strings.ToLower(strings.TrimSpace(snapshot.ArtifactDigest))
		snapshot.ToolSchemaDigest = strings.ToLower(strings.TrimSpace(snapshot.ToolSchemaDigest))
		snapshot.NetworkBindingDigest = strings.ToLower(strings.TrimSpace(snapshot.NetworkBindingDigest))
		snapshot.SecretBindingDigest = strings.ToLower(strings.TrimSpace(snapshot.SecretBindingDigest))
		if snapshot.InstallationID != snapshot.Selection.ID || snapshot.VersionID == "" || snapshot.Source == "" ||
			snapshot.ContentDigest != snapshot.Selection.Digest || !ValidDigest(snapshot.ContentDigest) || !ValidDigest(snapshot.ArtifactDigest) ||
			(snapshot.ToolSchemaDigest != "" && !ValidDigest(snapshot.ToolSchemaDigest)) ||
			(snapshot.NetworkBindingDigest != "" && !ValidDigest(snapshot.NetworkBindingDigest)) ||
			(snapshot.SecretBindingDigest != "" && !ValidDigest(snapshot.SecretBindingDigest)) ||
			len([]byte(snapshot.SkillInstructions)) > MaxGoalBytes || !utf8.ValidString(snapshot.SkillInstructions) {
			return nil, ErrInvalid
		}
		switch snapshot.Source {
		case "message-mcp", "builtin:web_search:tavily":
			if snapshot.InstallationRevision != 0 || snapshot.RequiresConfirmation || !snapshot.ReadOnly || snapshot.SkillInstructions != "" {
				return nil, ErrInvalid
			}
		case "product-capability", "builtin:knowledge:semantic":
			return nil, ErrInvalid
		default:
			if strings.HasPrefix(snapshot.Source, "builtin:") || snapshot.InstallationRevision == 0 || !ValidUUID(snapshot.VersionID) {
				return nil, ErrInvalid
			}
		}
		snapshot.ToolNames, err = normalizeRefs(snapshot.ToolNames)
		if err != nil || !equalStringSet(snapshot.ToolNames, snapshot.Selection.AllowedTools) {
			return nil, ErrInvalid
		}
		selectionKey := string(snapshot.Selection.Kind) + ":" + snapshot.Selection.ID
		if _, duplicate := seenSelections[selectionKey]; duplicate {
			return nil, ErrConflict
		}
		seenSelections[selectionKey] = struct{}{}
		for _, name := range snapshot.ToolNames {
			if _, duplicate := seenTools[name]; duplicate {
				return nil, ErrConflict
			}
			seenTools[name] = struct{}{}
		}
		out = append(out, snapshot)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Selection.Kind != out[j].Selection.Kind {
			return out[i].Selection.Kind < out[j].Selection.Kind
		}
		return out[i].Selection.ID < out[j].Selection.ID
	})
	return out, nil
}

func normalizeScheduledCapabilitySnapshots(capability ScheduledCapability, in []ScheduledExtensionSnapshot) ([]ScheduledExtensionSnapshot, error) {
	bindings, err := capability.RequiredBindings()
	if err != nil {
		return nil, err
	}
	snapshots, err := normalizeScheduledExtensionSnapshots(in)
	if err != nil {
		return nil, err
	}
	if len(snapshots) != len(bindings) {
		return nil, ErrInvalid
	}
	ordered := make([]ScheduledExtensionSnapshot, 0, len(bindings))
	used := make(map[int]struct{}, len(snapshots))
	for _, binding := range bindings {
		match := -1
		for index := range snapshots {
			if snapshots[index].Source != binding.Source {
				continue
			}
			if match != -1 {
				return nil, ErrInvalid
			}
			match = index
		}
		if match == -1 {
			return nil, ErrInvalid
		}
		if _, duplicate := used[match]; duplicate {
			return nil, ErrInvalid
		}
		wantTools := make([]string, 0, len(binding.Tools))
		for _, tool := range binding.Tools {
			wantTools = append(wantTools, tool.ProviderName)
		}
		sort.Strings(wantTools)
		if !equalStringSet(snapshots[match].ToolNames, wantTools) {
			return nil, ErrInvalid
		}
		used[match] = struct{}{}
		ordered = append(ordered, snapshots[match])
	}
	return ordered, nil
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ValidDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validWorkloadTarget(value string) bool {
	switch strings.TrimSpace(value) {
	case "CORE_RUNNER":
		return true
	default:
		return false
	}
}

func containsForbiddenInput(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x {
			lk := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
			for _, forbidden := range []string{"secret", "token", "password", "credential", "api_key", "apikey", "argv", "command", "endpoint"} {
				if strings.Contains(lk, forbidden) {
					return true
				}
			}
			if containsForbiddenInput(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if containsForbiddenInput(value) {
				return true
			}
		}
	}
	return false
}

func validExtensionOperation(op ExtensionOperation) bool {
	switch op {
	case ExtensionOperationInstall, ExtensionOperationUpdate, ExtensionOperationUninstall, ExtensionOperationExecuteTool, ExtensionOperationExecuteSkill:
		return true
	}
	return false
}

func validExtensionExecutionTarget(target ExtensionExecutionTarget) bool {
	switch target {
	case ExtensionExecutionTargetLocalSandbox, ExtensionExecutionTargetRemoteExtension, ExtensionExecutionTargetStaticSkill:
		return true
	default:
		return false
	}
}

func normalizeRefs(refs []string) ([]string, error) {
	if len(refs) > MaxRefCount {
		return nil, ErrInvalid
	}
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" || !utf8.ValidString(ref) || len([]byte(ref)) > MaxRefBytes {
			return nil, ErrInvalid
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	sort.Strings(out)
	return out, nil
}

func (s TaskSpec) Validate() error { _, err := s.Normalize(); return err }

func ValidUUID(value string) bool {
	v := strings.TrimSpace(value)
	u, err := uuid.Parse(v)
	return err == nil && u != uuid.Nil && strings.ToLower(v) == u.String()
}

type FileRef struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func (f FileRef) Validate() error {
	p := strings.TrimSpace(f.Path)
	if p == "" || len([]byte(p)) > MaxFilePathBytes || !utf8.ValidString(p) || path.IsAbs(p) || path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") || strings.Contains(p, `\`) || f.Size < 0 || len(f.Digest) != 64 {
		return ErrInvalid
	}
	for _, r := range f.Digest {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return ErrInvalid
		}
	}
	return nil
}

type Result struct {
	Text    string          `json:"text,omitempty"`
	JSON    json.RawMessage `json:"json,omitempty"`
	Files   []FileRef       `json:"files,omitempty"`
	Summary string          `json:"summary,omitempty"`
}

func (r Result) Validate() error {
	if len([]byte(r.Text)) > MaxResultTextBytes || !utf8.ValidString(r.Text) || len(r.JSON) > MaxResultBytes || len([]byte(r.Summary)) > MaxSummaryBytes || !utf8.ValidString(r.Summary) || len(r.Files) > MaxFileCount {
		return ErrInvalid
	}
	if len(r.JSON) > 0 && !json.Valid(r.JSON) {
		return ErrInvalid
	}
	for _, f := range r.Files {
		if err := f.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type Progress struct {
	EventID       string          `json:"event_id,omitempty"`
	TaskID        string          `json:"task_id"`
	Attempt       uint32          `json:"attempt"`
	Sequence      uint64          `json:"sequence"`
	At            time.Time       `json:"at"`
	Status        Status          `json:"status"`
	Phase         string          `json:"phase,omitempty"`
	Message       string          `json:"message,omitempty"`
	Percent       *float64        `json:"percent,omitempty"`
	ResultSummary string          `json:"result_summary,omitempty"`
	ResultJSON    json.RawMessage `json:"result_json,omitempty"`
	ErrorCode     string          `json:"error_code,omitempty"`
	ErrorSummary  string          `json:"error_summary,omitempty"`
}

type Lease struct {
	TaskID    string    `json:"task_id"`
	Attempt   uint32    `json:"attempt"`
	Epoch     uint64    `json:"epoch"`
	Holder    string    `json:"holder"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Task struct {
	ID                  string             `json:"id"`
	Spec                TaskSpec           `json:"spec"`
	Status              Status             `json:"status"`
	Attempt             uint32             `json:"attempt"`
	LeaseEpoch          uint64             `json:"lease_epoch"`
	Revision            uint64             `json:"revision"`
	ProgressSequence    uint64             `json:"progress_sequence"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
	AvailableAt         time.Time          `json:"available_at"`
	ExecutionStartedAt  *time.Time         `json:"execution_started_at,omitempty"`
	ExecutionDeadlineAt *time.Time         `json:"execution_deadline_at,omitempty"`
	DeletedAt           *time.Time         `json:"deleted_at,omitempty"`
	Lease               *Lease             `json:"lease,omitempty"`
	Result              *Result            `json:"result,omitempty"`
	FailureCode         string             `json:"failure_code,omitempty"`
	FailureSummary      string             `json:"failure_summary,omitempty"`
	RetryOfTaskID       string             `json:"retry_of_task_id,omitempty"`
	Snapshot            *ExecutionSnapshot `json:"snapshot,omitempty"`
}

func (t Task) Validate() error {
	if !ValidUUID(t.ID) || !validStatus(t.Status) || t.Revision == 0 || t.CreatedAt.IsZero() || t.UpdatedAt.IsZero() || t.AvailableAt.IsZero() || t.CreatedAt.Location() != time.UTC || t.UpdatedAt.Location() != time.UTC || t.AvailableAt.Location() != time.UTC || t.Attempt > 1 {
		return ErrInvalid
	}
	if err := t.Spec.Validate(); err != nil {
		return err
	}
	if t.Snapshot != nil {
		if err := t.Snapshot.Validate(); err != nil {
			return err
		}
	}
	if t.RetryOfTaskID != "" && (!ValidUUID(t.RetryOfTaskID) || t.RetryOfTaskID == t.ID) {
		return ErrInvalid
	}
	if t.DeletedAt != nil && (t.DeletedAt.IsZero() || t.DeletedAt.Location() != time.UTC) {
		return ErrInvalid
	}
	if t.Status == StatusWaitingUser && t.Attempt != 1 {
		return ErrInvalid
	}
	if t.Status == StatusSucceeded {
		if t.Attempt != 1 || t.Result == nil || t.FailureCode != "" || t.FailureSummary != "" {
			return ErrInvalid
		}
		if err := t.Result.Validate(); err != nil {
			return err
		}
	}
	if t.Status == StatusRunning || t.Status == StatusQueued || t.Status == StatusWaitingUser {
		if t.Result != nil || t.FailureCode != "" || t.FailureSummary != "" {
			return ErrInvalid
		}
	}
	if t.Status == StatusFailed {
		if t.Attempt != 1 || strings.TrimSpace(t.FailureCode) == "" || len([]byte(t.FailureCode)) > 128 || !utf8.ValidString(t.FailureCode) || strings.TrimSpace(t.FailureSummary) == "" || len([]byte(t.FailureSummary)) > MaxSummaryBytes || !utf8.ValidString(t.FailureSummary) {
			return ErrInvalid
		}
		if t.Result != nil {
			if err := t.Result.Validate(); err != nil {
				return err
			}
		}
	}
	if t.Status == StatusCanceled && t.Result != nil {
		if err := t.Result.Validate(); err != nil {
			return err
		}
	}
	if t.Status == StatusRunning {
		if t.Attempt != 1 || t.Lease == nil || t.Lease.TaskID != t.ID || t.Lease.Attempt != t.Attempt || t.Lease.Epoch != t.LeaseEpoch || t.Lease.Holder == "" || len([]byte(t.Lease.Holder)) > MaxLeaseHolderBytes || !utf8.ValidString(t.Lease.Holder) || t.Lease.ExpiresAt.IsZero() || t.Lease.ExpiresAt.Location() != time.UTC {
			return ErrInvalid
		}
	} else if t.Lease != nil {
		return ErrInvalid
	}
	return nil
}

func validStatus(s Status) bool {
	switch s {
	case StatusQueued, StatusRunning, StatusSucceeded, StatusFailed, StatusWaitingUser, StatusCanceled:
		return true
	}
	return false
}

func (s TaskSpec) MutationDigest() (string, error) {
	n, err := s.Normalize()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(n)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), nil
}

func CanonicalMutationDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	value = stripSecrets(value)
	b, err = json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), nil
}

func stripSecrets(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "password") || strings.Contains(lk, "api_key") || strings.Contains(lk, "apikey") {
				encoded, _ := json.Marshal(value)
				digest := sha256.Sum256(encoded)
				out[k] = "sha256:" + hex.EncodeToString(digest[:])
				continue
			}
			out[k] = stripSecrets(value)
		}
		return out
	case []any:
		for i := range x {
			x[i] = stripSecrets(x[i])
		}
	}
	return v
}
