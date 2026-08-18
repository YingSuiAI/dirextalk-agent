package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

var ErrCloudIntentRequired = errors.New("cloudworker: cloud proposal is not allowed for this turn")

const (
	englishCloudTarget = `(?:aws|ec2|cloud)`
	chineseCloudTarget = `(?:云端|云上|云|云\s*worker|cloud\s*worker|ec2|aws)`
)

var (
	cloudIntentClauseBoundary = regexp.MustCompile(`[.!?;\n。！？；,，]+`)
	englishCloudNegation      = regexp.MustCompile(
		`(?:\b(?:do\s+not|don't|never|without|no)\b[^.!?;\r\n]{0,120}\b` + englishCloudTarget + `\b|\b` + englishCloudTarget + `\b[^.!?;\r\n]{0,120}\b(?:not|never|without)\b)`)
	chineseCloudNegation = regexp.MustCompile(
		`(?:(?:不要|不用|不使用|禁止|别用|不可|不能|无需|不在)[^。！？；\r\n]{0,48}` + chineseCloudTarget + `|` +
			chineseCloudTarget + `[^。！？；\r\n]{0,48}(?:不要|不用|不使用|禁止|别用|不可|不能|无需执行))`)
)

// IntrinsicOwnerContext is resolved from Agent-owned account metadata. It is
// never accepted from model arguments or client request JSON.
type IntrinsicOwnerContext struct {
	OwnerID           string
	AccountGeneration uint64
}

type IntrinsicOwnerResolver interface {
	ResolveCloudWorkerOwner(context.Context, coreconversation.TurnLease) (IntrinsicOwnerContext, error)
}

// IntrinsicManifestResolver maps attachment IDs already accepted on the
// durable turn to exact Agent-owned source revisions. The model cannot name
// storage locations or arbitrary local paths.
type IntrinsicManifestResolver interface {
	ResolveCloudWorkerManifest(context.Context, coreconversation.TurnLease, WorkspaceMode, []string) (InputManifest, error)
}

// IntrinsicBudgetResolver is the sole authority for local-budget exhaustion.
// A model assertion and a failed local task are intentionally not inputs.
type IntrinsicBudgetResolver interface {
	ResolveCloudWorkerBudgetEvidence(context.Context, coreconversation.TurnLease) (*LocalBudgetEvidence, error)
}

// RetainedWorkerInventoryResolver returns a live owner-scoped view of
// persistent Workers. The inventory intrinsic bounds its model-facing result.
type RetainedWorkerInventoryResolver interface {
	ResolveRetainedWorkerInventory(context.Context, string, uint64) (RetainedWorkerInventory, error)
}

// RetainedWorkerManager exposes only the owner-scoped lifecycle operation the
// conversation intrinsic needs. The model never receives provider identities.
type RetainedWorkerManager interface {
	RetainedWorkerInventoryResolver
	DestroyRetainedWorker(context.Context, string, uint64, string, string) error
}

type IntrinsicTurnCommitter interface {
	CommitTurn(context.Context, coreconversation.TurnLease, coreconversation.ChatResponse) (coreconversation.Turn, error)
}

type RetainedWorkerInventory struct {
	ObservedAt time.Time                `json:"observed_at"`
	AtCapacity bool                     `json:"at_capacity"`
	Workers    []RetainedWorkerSnapshot `json:"workers"`
}

type RetainedWorkerSnapshot struct {
	WorkerID     string                   `json:"worker_id"`
	InstanceType string                   `json:"instance_type"`
	VCPU         uint32                   `json:"vcpu"`
	MemoryGiB    uint32                   `json:"memory_gib"`
	VolumeGiB    int32                    `json:"volume_gib"`
	Availability string                   `json:"availability"`
	EC2State     string                   `json:"ec2_state"`
	WorkerPhase  string                   `json:"worker_phase"`
	PublicIPv4   string                   `json:"public_ipv4,omitempty"`
	Error        string                   `json:"error,omitempty"`
	CurrentTask  *RetainedWorkerTask      `json:"current_task,omitempty"`
	Server       *RetainedWorkerServer    `json:"server,omitempty"`
	HourlyQuote  *RetainedWorkerQuote     `json:"hourly_quote,omitempty"`
	Workloads    []RetainedWorkerWorkload `json:"workloads,omitempty"`
}

type RetainedWorkerTask struct {
	ExecutionID string `json:"execution_id"`
	Phase       string `json:"phase"`
}

type RetainedWorkerServer struct {
	LastSeen time.Time `json:"last_seen"`
	Load1    float64   `json:"load_1"`
	Load5    float64   `json:"load_5"`
	Load15   float64   `json:"load_15"`
}

type RetainedWorkerQuote struct {
	Currency      string    `json:"currency"`
	MicrosPerHour uint64    `json:"micros_per_hour"`
	ObservedAt    time.Time `json:"observed_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type RetainedWorkerWorkload struct {
	WorkloadID  string `json:"workload_id"`
	Kind        string `json:"kind"`
	Phase       string `json:"phase"`
	ActiveState string `json:"active_state"`
	Health      string `json:"health"`
	Port        uint16 `json:"port,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

const maxModelInventoryBytes = 4096

func boundedWorkerInventoryJSON(inventory RetainedWorkerInventory) []byte {
	workers := append([]RetainedWorkerSnapshot(nil), inventory.Workers...)
	sort.Slice(workers, func(i, j int) bool {
		if workers[i].WorkerID == workers[j].WorkerID {
			return workers[i].InstanceType < workers[j].InstanceType
		}
		return workers[i].WorkerID < workers[j].WorkerID
	})
	projected := make([]any, 0, len(workers))
	encode := func(items []any, truncated bool) []byte {
		raw, err := json.Marshal(map[string]any{
			"schema": "cloud_worker_inventory/v1", "observed_at": inventory.ObservedAt, "at_capacity": inventory.AtCapacity,
			"worker_count": len(workers), "workers": items, "truncated": truncated,
		})
		if err != nil {
			return []byte(`{"schema":"cloud_worker_inventory/v1","truncated":true}`)
		}
		return raw
	}
	for _, worker := range workers {
		item := map[string]any{
			"worker_id": boundedInventoryText(worker.WorkerID), "instance_type": boundedInventoryText(worker.InstanceType),
			"vcpu": worker.VCPU, "memory_gib": worker.MemoryGiB, "volume_gib": worker.VolumeGiB,
			"availability": boundedInventoryText(worker.Availability), "ec2_state": boundedInventoryText(worker.EC2State),
			"worker_phase": boundedInventoryText(worker.WorkerPhase), "public_ipv4": boundedInventoryText(worker.PublicIPv4),
			"workload_count": len(worker.Workloads),
		}
		if worker.CurrentTask != nil {
			item["current_task"] = map[string]any{"execution_id": boundedInventoryText(worker.CurrentTask.ExecutionID), "phase": boundedInventoryText(worker.CurrentTask.Phase)}
		}
		if worker.Server != nil {
			item["server"] = worker.Server
		}
		if worker.HourlyQuote != nil {
			item["hourly_quote"] = map[string]any{
				"currency": boundedInventoryText(worker.HourlyQuote.Currency), "micros_per_hour": worker.HourlyQuote.MicrosPerHour,
				"observed_at": worker.HourlyQuote.ObservedAt, "expires_at": worker.HourlyQuote.ExpiresAt,
			}
		}
		candidate := append(append([]any(nil), projected...), item)
		if len(encode(candidate, true)) > maxModelInventoryBytes {
			break
		}
		projected = candidate
	}
	raw := encode(projected, len(projected) != len(workers))
	for len(raw) > maxModelInventoryBytes && len(projected) > 0 {
		projected = projected[:len(projected)-1]
		raw = encode(projected, true)
	}
	if len(raw) > maxModelInventoryBytes {
		raw = []byte(`{"schema":"cloud_worker_inventory/v1","truncated":true}`)
	}
	return raw
}

func boundedInventoryText(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if len(value) <= 128 {
		return value
	}
	for len(value) > 128 {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value
}

type ProposeIntrinsic struct {
	service     *Service
	owners      IntrinsicOwnerResolver
	manifests   IntrinsicManifestResolver
	budgets     IntrinsicBudgetResolver
	workers     RetainedWorkerInventoryResolver
	manager     RetainedWorkerManager
	turns       IntrinsicTurnCommitter
	domains     RetainedWorkerDomainManager
	domainTools coreconversation.IntrinsicToolStore
}

func NewProposeIntrinsic(service *Service, owners IntrinsicOwnerResolver, manifests IntrinsicManifestResolver, budgets IntrinsicBudgetResolver) (*ProposeIntrinsic, error) {
	if service == nil || owners == nil {
		return nil, ErrInvalid
	}
	return &ProposeIntrinsic{service: service, owners: owners, manifests: manifests, budgets: budgets}, nil
}

func (p *ProposeIntrinsic) EnableRetainedWorkerInventory(resolver RetainedWorkerInventoryResolver) error {
	if p == nil || resolver == nil {
		return ErrInvalid
	}
	p.workers = resolver
	return nil
}

func (p *ProposeIntrinsic) EnableRetainedWorkerManagement(manager RetainedWorkerManager, turns IntrinsicTurnCommitter) error {
	if p == nil || manager == nil || turns == nil {
		return ErrInvalid
	}
	p.workers, p.manager, p.turns = manager, manager, turns
	return nil
}

type proposeIntrinsicArguments struct {
	AttachmentIDs           []string `json:"attachment_ids,omitempty"`
	Intent                  string   `json:"intent"`
	Objective               string   `json:"objective"`
	WorkspaceMode           string   `json:"workspace_mode"`
	MinVCPU                 uint32   `json:"min_vcpu"`
	MinMemoryGiB            uint32   `json:"min_memory_gib"`
	DiskGiB                 uint64   `json:"disk_gib"`
	EstimatedRuntimeMinutes uint64   `json:"estimated_runtime_minutes"`
	WorkloadKind            string   `json:"workload_kind,omitempty"`
	Service                 *struct {
		WorkloadID string `json:"workload_id"`
		Port       uint16 `json:"port"`
		HealthPath string `json:"health_path"`
		Hostname   string `json:"hostname,omitempty"`
	} `json:"service,omitempty"`
}

func (p *ProposeIntrinsic) ResolveIntrinsicTools(ctx context.Context, lease coreconversation.TurnLease) ([]coreconversation.ResolvedIntrinsic, error) {
	if p == nil || p.service == nil || p.owners == nil || lease.Turn.ID == "" || lease.LeaseID == "" || lease.Epoch == 0 {
		return nil, ErrInvalid
	}
	if !p.service.ProposalReady(ctx) {
		return nil, nil
	}
	bound := lease
	attachmentSchema := frozenTurnAttachmentSchema(bound.Turn)
	workspaceModes := []any{string(WorkspaceNone), string(WorkspaceWrite)}
	if attachmentSchema != nil {
		workspaceModes = []any{string(WorkspaceNone), string(WorkspaceReadOnly), string(WorkspaceWrite)}
	}
	properties := map[string]any{
		"intent":                    map[string]any{"type": "string", "enum": []any{"execute", "proposal_only"}, "description": "Use execute only when the user wants the workload to run. Use proposal_only when the user explicitly asks for a plan without starting or authorizing Worker work; it returns a non-executing summary and creates no offer, task, confirmation, or execution."},
		"objective":                 map[string]any{"type": "string", "minLength": 1, "maxLength": coretask.MaxGoalBytes, "description": "Describe only the workload to run on the Worker."},
		"workspace_mode":            map[string]any{"type": "string", "enum": workspaceModes, "description": "Use none without attachment_ids, read_only with one or more attachment_ids, or write with optional attachment_ids."},
		"workload_kind":             map[string]any{"type": "string", "enum": []any{string(WorkloadJob), string(WorkloadService)}, "default": string(WorkloadJob), "description": "Use job only for finite execution. You MUST use service when the requested result is a persistent network service, website, API, daemon, or other endpoint that must remain available after this run."},
		"min_vcpu":                  map[string]any{"type": "integer", "minimum": 1, "maximum": 128, "description": "Minimum virtual CPU count needed for the task."},
		"min_memory_gib":            map[string]any{"type": "integer", "minimum": 1, "maximum": 1024, "description": "Minimum memory in GiB needed for the task."},
		"disk_gib":                  map[string]any{"type": "integer", "minimum": 8, "maximum": 16384, "description": "Working disk capacity in GiB needed for inputs, dependencies, and outputs."},
		"estimated_runtime_minutes": map[string]any{"type": "integer", "minimum": 1, "maximum": 1440, "description": "Sufficient task execution budget in minutes for environment setup, dependency installation, build, configuration, verification, result collection, and reasonable margin. This is not the lifetime of a retained Worker or deployed service."},
		"service": map[string]any{"type": "object", "description": "Required for workload_kind=service; omit for job.", "additionalProperties": false, "required": []any{"workload_id", "port", "health_path"}, "properties": map[string]any{
			"workload_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z0-9-]+$", "description": "Stable lowercase letters, digits, and hyphens only."},
			"port":        map[string]any{"type": "integer", "minimum": 1, "maximum": 65535, "description": "Internal HTTP port; not 80 or 443 when hostname is set."},
			"health_path": map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "pattern": `^/(?:$|[^/\s#][^\s#]*)$`, "description": "Absolute HTTP path beginning with one slash, without whitespace or fragments."},
			"hostname":    map[string]any{"type": "string", "minLength": 1, "maxLength": 253, "description": "Set when the user requests a hostname. Agent owns Caddy and DNS; do not instruct the Worker to configure them."},
		}},
	}
	if attachmentSchema != nil {
		properties["attachment_ids"] = attachmentSchema
	}
	description := "Run substantial project or shell work in a retained execution environment, or return a non-executing plan summary. Once workload_kind, actual minimum resources, and required service fields are known, invoke this tool immediately. Only creating a new Worker requires owner confirmation; retained Worker reuse executes directly, including persistent services and hostname publication."
	tool := coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerProposeToolName,
		Description: description,
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"intent", "objective", "workspace_mode", "min_vcpu", "min_memory_gib", "disk_gib", "estimated_runtime_minutes"},
			"properties":           properties,
		},
	}
	resolved := []coreconversation.ResolvedIntrinsic{{
		Tool: tool,
		Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
			return p.execute(ctx, bound, request)
		},
	}}
	if p.workers == nil || strings.TrimSpace(bound.Turn.OwnerID) == "" || bound.Turn.AccountGeneration == 0 {
		return resolved, nil
	}
	resolved = append(resolved, coreconversation.ResolvedIntrinsic{
		Tool: coremodel.Tool{
			Name:        coremodel.IntrinsicCloudWorkerInventoryToolName,
			Description: "Read the current owner-scoped retained Worker inventory. This is read-only and returns bounded status, capacity, load, task, address, pricing, and workload summary data.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false, "properties": map[string]any{},
			},
		},
		ReadOnly: true,
		Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
			return p.executeInventory(ctx, bound, request)
		},
	})
	if p.manager == nil {
		return resolved, nil
	}
	resolved = append(resolved, coreconversation.ResolvedIntrinsic{
		Tool: coremodel.Tool{
			Name:        coremodel.IntrinsicCloudWorkerDestroyToolName,
			Description: "Destroy one retained Worker only when the user explicitly asks to destroy it. A status question, completed task, or idle Worker is not authorization. First call cloud_worker_inventory, then pass the exact returned worker_id. This permanently removes the EC2 instance, key pair, security group, and any bound service state.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []any{"worker_id", "confirmation"},
				"properties": map[string]any{
					"worker_id":    map[string]any{"type": "string", "format": "uuid", "description": "Exact worker_id returned by cloud_worker_inventory."},
					"confirmation": map[string]any{"type": "string", "const": "destroy_worker"},
				},
			},
		},
		Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
			return p.executeDestroy(ctx, bound, request)
		},
	})
	resolved = append(resolved, cloudWorkerDomainTools(p, bound)...)
	return resolved, nil
}

func (p *ProposeIntrinsic) executeInventory(ctx context.Context, bound coreconversation.TurnLease, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
	if ctx == nil || p.workers == nil || strings.TrimSpace(bound.Turn.OwnerID) == "" ||
		bound.Turn.AccountGeneration == 0 || request.Lease.Turn.ID != bound.Turn.ID ||
		request.Lease.Turn.RequestID != bound.Turn.RequestID || request.Lease.LeaseID != bound.LeaseID ||
		request.Lease.Epoch < bound.Epoch || request.Call.Name != coremodel.IntrinsicCloudWorkerInventoryToolName ||
		request.Call.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(request.CanonicalArguments))
	decoder.DisallowUnknownFields()
	var arguments struct{}
	if decoder.Decode(&arguments) != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, request.Lease)
	if err != nil || strings.TrimSpace(owner.OwnerID) != strings.TrimSpace(bound.Turn.OwnerID) ||
		owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	inventory, err := p.workers.ResolveRetainedWorkerInventory(ctx, owner.OwnerID, owner.AccountGeneration)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	result := coreconversation.ToolResult{
		CallID: request.Call.ID, ToolName: coremodel.IntrinsicCloudWorkerInventoryToolName,
		Content: string(boundedWorkerInventoryJSON(inventory)), Summary: "Retained Worker inventory read",
	}
	if result.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	return coreconversation.IntrinsicExecutionResult{ToolResult: &result}, nil
}

type destroyIntrinsicArguments struct {
	WorkerID     string `json:"worker_id"`
	Confirmation string `json:"confirmation"`
}

func (p *ProposeIntrinsic) executeDestroy(ctx context.Context, bound coreconversation.TurnLease, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
	if ctx == nil || p.manager == nil || p.turns == nil || request.Lease.Turn.ID != bound.Turn.ID ||
		request.Lease.Turn.RequestID != bound.Turn.RequestID || request.Lease.LeaseID != bound.LeaseID ||
		request.Lease.Epoch < bound.Epoch || request.Call.Name != coremodel.IntrinsicCloudWorkerDestroyToolName ||
		request.Call.Validate() != nil || request.ConversationRevision == 0 || bound.Turn.CreatedAt.IsZero() {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	arguments, err := parseDestroyIntrinsicArguments(request.CanonicalArguments)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, request.Lease)
	if err != nil || owner.OwnerID != bound.Turn.OwnerID || owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	proof := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-destroy:"+bound.Turn.ID+":"+request.Call.ID)).String()
	if err = p.manager.DestroyRetainedWorker(ctx, owner.OwnerID, owner.AccountGeneration, arguments.WorkerID, proof); err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	message := coreconversation.Message{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-destroy-message:"+bound.Turn.ID+":"+request.Call.ID)).String(),
		Role: coreconversation.RoleAssistant, Content: fmt.Sprintf("Worker %s destroyed.", arguments.WorkerID),
		CreatedAt: bound.Turn.CreatedAt.UTC().Add(time.Microsecond), ModelProfileID: bound.Turn.ProfileID,
	}
	if message.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	response := coreconversation.ChatResponse{
		RequestID: bound.Turn.RequestID, ConversationID: bound.Turn.ConversationID,
		Revision: request.ConversationRevision + 1, Message: message, Done: true, ModelProfileID: bound.Turn.ProfileID,
	}
	if _, err = p.turns.CommitTurn(ctx, request.Lease, response); err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	return coreconversation.IntrinsicExecutionResult{TurnCommitted: true}, nil
}

func parseDestroyIntrinsicArguments(raw json.RawMessage) (destroyIntrinsicArguments, error) {
	if len(raw) == 0 || len(raw) > coreconversation.MaxToolArgumentsBytes {
		return destroyIntrinsicArguments{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var arguments destroyIntrinsicArguments
	if decoder.Decode(&arguments) != nil {
		return destroyIntrinsicArguments{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return destroyIntrinsicArguments{}, ErrInvalid
	}
	arguments.WorkerID = strings.TrimSpace(arguments.WorkerID)
	if !coretask.ValidUUID(arguments.WorkerID) || arguments.Confirmation != "destroy_worker" {
		return destroyIntrinsicArguments{}, ErrInvalid
	}
	return arguments, nil
}

// frozenTurnAttachmentSchema exposes only the sources already consumed and
// frozen on this durable turn. A generic UUID format would let the model name
// another turn's upload even though the execution boundary later rejected it.
func frozenTurnAttachmentSchema(turn coreconversation.Turn) map[string]any {
	if len(turn.AttachmentSources) == 0 || len(turn.AttachmentSources) > coreconversation.MaxTurnAttachments ||
		turn.AttachmentSnapshotDigest == "" ||
		turn.AttachmentSnapshotDigest != coreconversation.TurnAttachmentSnapshotDigest(turn.AttachmentSources) {
		return nil
	}
	accepted := make([]string, len(turn.AttachmentSources))
	choices := make([]any, 0, len(turn.AttachmentSources))
	for index, attachment := range turn.AttachmentSources {
		accepted[index] = attachment.SourceID
		choices = append(choices, map[string]any{
			"const":       attachment.SourceID,
			"title":       attachment.Name,
			"description": attachment.MediaType,
		})
	}
	if coreconversation.ValidateAcceptedTurnAttachments(turn.RequestID, accepted, turn.AttachmentSources) != nil {
		return nil
	}
	return map[string]any{
		"type": "array", "minItems": 1, "maxItems": len(choices), "uniqueItems": true,
		"description": "Omit with workspace_mode=none, provide one or more with read_only, and optionally provide with write.",
		"items":       map[string]any{"type": "string", "oneOf": choices},
	}
}

func (p *ProposeIntrinsic) execute(ctx context.Context, bound coreconversation.TurnLease, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
	if ctx == nil || request.Lease.Turn.ID != bound.Turn.ID || request.Lease.Turn.RequestID != bound.Turn.RequestID || request.Lease.LeaseID != bound.LeaseID || request.Lease.Epoch < bound.Epoch || request.Call.Name != coremodel.IntrinsicCloudWorkerProposeToolName || request.Call.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	arguments, err := parseProposeIntrinsicArguments(request.CanonicalArguments)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			return coreconversation.IntrinsicExecutionResult{}, coreconversation.ErrInvalid
		}
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	if arguments.Intent == "proposal_only" {
		return p.commitProposalOnly(ctx, bound, request, arguments)
	}
	mode := WorkspaceMode(arguments.WorkspaceMode)
	if hasCloudExecutionVeto(bound.Turn.Prompt) {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	if p.budgets == nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	budget, err := p.budgets.ResolveCloudWorkerBudgetEvidence(ctx, request.Lease)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	if budget == nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	reason := ProposalReasonLocalBudgetExceeded
	if strings.TrimSpace(bound.Turn.OwnerID) == "" || bound.Turn.AccountGeneration == 0 {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, request.Lease)
	if err != nil || strings.TrimSpace(owner.OwnerID) != strings.TrimSpace(bound.Turn.OwnerID) || owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	manifest := InputManifest{Schema: InputManifestSchema}
	if len(arguments.AttachmentIDs) > 0 {
		if p.manifests == nil || !turnAllowsAttachments(bound.Turn, arguments.AttachmentIDs) {
			return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
		}
		manifest, err = p.manifests.ResolveCloudWorkerManifest(ctx, request.Lease, mode, arguments.AttachmentIDs)
		if err != nil {
			return coreconversation.IntrinsicExecutionResult{}, err
		}
	}
	snapshot := bound.Turn.ProfileSnapshot
	if snapshot.Validate() != nil || snapshot.ProfileID != bound.Turn.ProfileID || snapshot.Revision <= 0 || snapshot.CredentialVersion <= 0 {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	modelAuthorization, err := ModelAuthorizationFromSnapshot(snapshot)
	if err != nil {
		// Reject providers without an approved remote Pi adapter before a paid
		// quote is created.
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	promptDigest := sha256.Sum256([]byte(bound.Turn.Prompt))
	idempotencyKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-propose:"+bound.Turn.ID+":"+request.Call.ID)).String()
	offer, err := p.service.Propose(ctx, ProposeCommand{
		OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration,
		IdempotencyKey: idempotencyKey, ConversationID: bound.Turn.ConversationID,
		TurnID: bound.Turn.ID, TurnLeaseID: request.Lease.LeaseID, TurnLeaseEpoch: request.Lease.Epoch,
		ExpectedTurnRevision: bound.Turn.Revision, Objective: arguments.Objective,
		ObjectiveSummary: arguments.Objective, UserPromptDigest: hex.EncodeToString(promptDigest[:]),
		WorkloadKind: WorkloadKind(arguments.WorkloadKind), Service: func() *ServiceSpec {
			if arguments.Service == nil {
				return nil
			}
			return &ServiceSpec{WorkloadID: arguments.Service.WorkloadID, Port: arguments.Service.Port, HealthPath: arguments.Service.HealthPath, Hostname: arguments.Service.Hostname}
		}(),
		ProposalReason: reason, LocalBudgetEvidence: budget, InputManifest: manifest,
		WorkspaceMode:      mode,
		ModelAuthorization: modelAuthorization,
		ComputeRequirements: ComputeRequirements{MinVCPU: arguments.MinVCPU, MinMemoryGiB: arguments.MinMemoryGiB,
			DiskGiB: arguments.DiskGiB, EstimatedRuntimeMinutes: arguments.EstimatedRuntimeMinutes},
	})
	if err != nil {
		slog.Warn("[cloud-worker.intrinsic] proposal_failed",
			"class", intrinsicProposalErrorClass(err),
			"turn_id", bound.Turn.ID,
			"workspace_mode", mode,
			"proposal_reason", reason)
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	if offer.Plan.TurnID != bound.Turn.ID || offer.Plan.ConversationID != bound.Turn.ConversationID || offer.Plan.AccountGeneration != owner.AccountGeneration || offer.Task.ID != offer.Plan.TaskID || offer.Confirmation.ConfirmationID != offer.Plan.ConfirmationID {
		return coreconversation.IntrinsicExecutionResult{}, ErrConflict
	}
	return coreconversation.IntrinsicExecutionResult{TurnCommitted: true}, nil
}

func (p *ProposeIntrinsic) commitProposalOnly(ctx context.Context, bound coreconversation.TurnLease, request coreconversation.IntrinsicExecutionRequest, arguments proposeIntrinsicArguments) (coreconversation.IntrinsicExecutionResult, error) {
	if p.turns == nil || request.ConversationRevision == 0 || bound.Turn.CreatedAt.IsZero() {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	detail := fmt.Sprintf("Plan only — no Worker was started.\n\nObjective: %s\nWorkload: %s\nMinimum resources: %d vCPU, %d GiB memory, %d GiB disk\nExecution budget: %d minutes",
		arguments.Objective, arguments.WorkloadKind, arguments.MinVCPU, arguments.MinMemoryGiB, arguments.DiskGiB, arguments.EstimatedRuntimeMinutes)
	if arguments.Service != nil {
		detail += fmt.Sprintf("\nService: %s on port %d (health %s)", arguments.Service.WorkloadID, arguments.Service.Port, arguments.Service.HealthPath)
		if arguments.Service.Hostname != "" {
			detail += " at " + arguments.Service.Hostname
		}
	}
	detail += "\n\nRequest execution separately when ready. A suitable retained Worker may then start immediately; creating a new Worker requires owner confirmation."
	message := coreconversation.Message{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-proposal-only-message:"+bound.Turn.ID+":"+request.Call.ID)).String(),
		Role: coreconversation.RoleAssistant, Content: detail,
		CreatedAt: bound.Turn.CreatedAt.UTC().Add(time.Microsecond), ModelProfileID: bound.Turn.ProfileID,
	}
	if message.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	titleSource := bound.Turn.Prompt
	if lister, ok := p.turns.(coreconversation.TurnLister); ok {
		if turns, _, err := lister.ListTurns(ctx, bound.Turn.ConversationID, "", 1); err == nil && len(turns) == 1 && strings.TrimSpace(turns[0].Prompt) != "" {
			titleSource = turns[0].Prompt
		}
	}
	response := coreconversation.ChatResponse{
		RequestID: bound.Turn.RequestID, ConversationID: bound.Turn.ConversationID,
		Revision: request.ConversationRevision + 1, Message: message, Done: true, ModelProfileID: bound.Turn.ProfileID,
		ConversationTitle: coreconversation.ProvisionalConversationTitle(titleSource), ConversationTitleSource: titleSource,
	}
	if _, err := p.turns.CommitTurn(ctx, request.Lease, response); err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	return coreconversation.IntrinsicExecutionResult{TurnCommitted: true}, nil
}

func turnAllowsSelectedWorkspaceArchive(turn coreconversation.Turn, selected []string) bool {
	if !turnAllowsAttachments(turn, selected) {
		return false
	}
	selectedSet := make(map[string]struct{}, len(selected))
	for _, id := range selected {
		selectedSet[id] = struct{}{}
	}
	for _, attachment := range turn.AttachmentSources {
		if attachment.Kind == coreconversation.TurnAttachmentKindWorkspaceArchive {
			_, selected := selectedSet[attachment.SourceID]
			return selected
		}
	}
	return false
}

func parseProposeIntrinsicArguments(raw json.RawMessage) (proposeIntrinsicArguments, error) {
	if len(raw) == 0 || len(raw) > coreconversation.MaxToolArgumentsBytes {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var arguments proposeIntrinsicArguments
	if decoder.Decode(&arguments) != nil {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	arguments.Objective = strings.TrimSpace(arguments.Objective)
	if arguments.Intent != "execute" && arguments.Intent != "proposal_only" {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	if arguments.WorkloadKind == "" {
		arguments.WorkloadKind = string(WorkloadJob)
	}
	if arguments.WorkloadKind == string(WorkloadJob) {
		arguments.Service = nil
	} else if arguments.Service != nil {
		arguments.Service.Hostname = remoteservice.CanonicalHostname(arguments.Service.Hostname)
	}
	if arguments.Objective == "" || len(arguments.Objective) > coretask.MaxGoalBytes || !utf8.ValidString(arguments.Objective) || !validateWorkspaceMode(WorkspaceMode(arguments.WorkspaceMode)) || len(arguments.AttachmentIDs) > coreconversation.MaxTurnAttachments {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	// Providers occasionally return a smaller positive disk estimate even
	// though the tool schema advertises the EC2/EBS floor. Treat that estimate
	// as a request for the supported minimum instead of failing the whole turn.
	if arguments.DiskGiB > 0 && arguments.DiskGiB < 8 {
		arguments.DiskGiB = 8
	}
	if (ComputeRequirements{MinVCPU: arguments.MinVCPU, MinMemoryGiB: arguments.MinMemoryGiB, DiskGiB: arguments.DiskGiB,
		EstimatedRuntimeMinutes: arguments.EstimatedRuntimeMinutes}).validate() != nil {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	if (arguments.WorkloadKind == string(WorkloadService) && (arguments.Service == nil || (ServiceSpec{WorkloadID: arguments.Service.WorkloadID, Port: arguments.Service.Port, HealthPath: arguments.Service.HealthPath, Hostname: arguments.Service.Hostname}).validate() != nil)) ||
		(arguments.WorkloadKind != string(WorkloadJob) && arguments.WorkloadKind != string(WorkloadService)) {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	seen := make(map[string]struct{}, len(arguments.AttachmentIDs))
	for _, id := range arguments.AttachmentIDs {
		if !coretask.ValidUUID(id) {
			return proposeIntrinsicArguments{}, ErrInvalid
		}
		if _, duplicate := seen[id]; duplicate {
			return proposeIntrinsicArguments{}, ErrInvalid
		}
		seen[id] = struct{}{}
	}
	if len(arguments.AttachmentIDs) == 0 && WorkspaceMode(arguments.WorkspaceMode) == WorkspaceReadOnly {
		arguments.WorkspaceMode = string(WorkspaceNone)
	}
	if !validWorkspaceInputCardinality(WorkspaceMode(arguments.WorkspaceMode), len(arguments.AttachmentIDs)) {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	// JSON whitespace and object-key order carry no authority. The semantic
	// fields above remain strict, and the trusted resolver receives a stable
	// attachment order so equivalent model output cannot fail spuriously.
	sort.Strings(arguments.AttachmentIDs)
	return arguments, nil
}

func intrinsicProposalErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrPricingCatalogStale):
		return "pricing_catalog_stale"
	case errors.Is(err, ErrProviderUnavailable):
		return "provider_unavailable"
	case errors.Is(err, ErrQuoteExpired):
		return "quote_expired"
	case errors.Is(err, ErrStaleAuthorization):
		return "stale_authorization"
	case errors.Is(err, ErrCloudIntentRequired):
		return "cloud_intent_required"
	case errors.Is(err, ErrLeaseConflict):
		return "lease_conflict"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	default:
		return "dependency_error"
	}
}

func turnAllowsAttachments(turn coreconversation.Turn, selected []string) bool {
	if len(selected) == 0 || len(selected) > coreconversation.MaxTurnAttachments || len(turn.AttachmentSources) == 0 ||
		turn.AttachmentSnapshotDigest == "" || turn.AttachmentSnapshotDigest != coreconversation.TurnAttachmentSnapshotDigest(turn.AttachmentSources) {
		return false
	}
	accepted := make([]string, len(turn.AttachmentSources))
	allowed := make(map[string]struct{}, len(turn.AttachmentSources))
	for index, attachment := range turn.AttachmentSources {
		accepted[index] = attachment.SourceID
		allowed[attachment.SourceID] = struct{}{}
	}
	if coreconversation.ValidateAcceptedTurnAttachments(turn.RequestID, accepted, turn.AttachmentSources) != nil {
		return false
	}
	for _, id := range selected {
		if _, ok := allowed[id]; !ok {
			return false
		}
	}
	return true
}

func hasCloudExecutionVeto(prompt string) bool {
	value := strings.ToLower(strings.TrimSpace(prompt))
	for _, clause := range cloudIntentClauseBoundary.Split(value, -1) {
		clause = strings.TrimSpace(clause)
		if englishCloudNegation.MatchString(clause) || chineseCloudNegation.MatchString(clause) {
			return true
		}
	}
	return false
}

var _ coreconversation.IntrinsicResolver = (*ProposeIntrinsic)(nil)
