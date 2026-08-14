package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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

// RetainedWorkerInventoryResolver projects a bounded, live, owner-scoped view
// of persistent Workers into the model's current round. It is read-only and
// never exposes lifecycle mutations.
type RetainedWorkerInventoryResolver interface {
	ResolveRetainedWorkerInventory(context.Context, string, uint64) (RetainedWorkerInventory, error)
}

type RetainedWorkerInventory struct {
	ObservedAt time.Time                `json:"observed_at"`
	AtCapacity bool                     `json:"at_capacity"`
	Workers    []RetainedWorkerSnapshot `json:"workers"`
}

type RetainedWorkerSnapshot struct {
	WorkerID     string                   `json:"worker_id"`
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

type ProposeIntrinsic struct {
	service   *Service
	owners    IntrinsicOwnerResolver
	manifests IntrinsicManifestResolver
	budgets   IntrinsicBudgetResolver
	workers   RetainedWorkerInventoryResolver
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

type proposeIntrinsicArguments struct {
	AttachmentIDs           []string `json:"attachment_ids,omitempty"`
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
	properties := map[string]any{
		"objective":                 map[string]any{"type": "string", "minLength": 1, "maxLength": coretask.MaxGoalBytes},
		"workspace_mode":            map[string]any{"type": "string", "enum": []any{string(WorkspaceNone), string(WorkspaceReadOnly), string(WorkspaceWrite)}},
		"workload_kind":             map[string]any{"type": "string", "enum": []any{string(WorkloadJob), string(WorkloadService)}, "default": string(WorkloadJob)},
		"min_vcpu":                  map[string]any{"type": "integer", "minimum": 1, "maximum": 128},
		"min_memory_gib":            map[string]any{"type": "integer", "minimum": 1, "maximum": 1024},
		"disk_gib":                  map[string]any{"type": "integer", "minimum": 8, "maximum": 16384},
		"estimated_runtime_minutes": map[string]any{"type": "integer", "minimum": 1, "maximum": 1440},
		"service": map[string]any{"type": "object", "additionalProperties": false, "required": []any{"workload_id", "port", "health_path"}, "properties": map[string]any{
			"workload_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}, "port": map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}, "health_path": map[string]any{"type": "string", "minLength": 1, "maxLength": 2048},
		}},
	}
	if attachmentSchema := frozenTurnAttachmentSchema(bound.Turn); attachmentSchema != nil {
		properties["attachment_ids"] = attachmentSchema
	}
	description := "Run work in a suitable retained execution environment, or propose a priced reusable environment when none is available. Use it for substantial project or shell execution, deployment, build, test, durable file delivery, long-running compute, and actual follow-up work in a retained environment. Do not call this tool only to inspect status; answer status questions from the live retained_worker_inventory below. The user does not need to mention cloud or remote execution. Do not use it for ordinary conversation or simple reasoning, or when the user requires local execution or forbids cloud use. Reuse needs no creation confirmation; new resources start only after the owner reviews and confirms the offer."
	inventory := `{"status":"unavailable"}`
	if p.workers != nil && strings.TrimSpace(bound.Turn.OwnerID) != "" && bound.Turn.AccountGeneration != 0 {
		if current, inventoryErr := p.workers.ResolveRetainedWorkerInventory(ctx, bound.Turn.OwnerID, bound.Turn.AccountGeneration); inventoryErr == nil {
			if raw, marshalErr := json.Marshal(current); marshalErr == nil && len(raw) <= 64<<10 {
				inventory = string(raw)
			}
		}
	}
	tool := coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerProposeToolName,
		Description: description + "\nretained_worker_inventory=" + inventory,
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"objective", "workspace_mode", "min_vcpu", "min_memory_gib", "disk_gib", "estimated_runtime_minutes"},
			"properties":           properties,
		},
	}
	return []coreconversation.ResolvedIntrinsic{{
		Tool: tool,
		Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
			return p.execute(ctx, bound, request)
		},
	}}, nil
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
		"items": map[string]any{"oneOf": choices},
	}
}

func (p *ProposeIntrinsic) execute(ctx context.Context, bound coreconversation.TurnLease, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
	if ctx == nil || request.Lease.Turn.ID != bound.Turn.ID || request.Lease.Turn.RequestID != bound.Turn.RequestID || request.Lease.LeaseID != bound.LeaseID || request.Lease.Epoch != bound.Epoch || request.Call.Name != coremodel.IntrinsicCloudWorkerProposeToolName || request.Call.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	arguments, err := parseProposeIntrinsicArguments(request.CanonicalArguments)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	mode := WorkspaceMode(arguments.WorkspaceMode)
	if hasCloudExecutionVeto(bound.Turn.Prompt) {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	if p.budgets == nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	budget, err := p.budgets.ResolveCloudWorkerBudgetEvidence(ctx, bound)
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
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, bound)
	if err != nil || strings.TrimSpace(owner.OwnerID) != strings.TrimSpace(bound.Turn.OwnerID) || owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	manifest := InputManifest{Schema: InputManifestSchema}
	if len(arguments.AttachmentIDs) > 0 {
		if p.manifests == nil || !turnAllowsAttachments(bound.Turn, arguments.AttachmentIDs) {
			return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
		}
		manifest, err = p.manifests.ResolveCloudWorkerManifest(ctx, bound, mode, arguments.AttachmentIDs)
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
		TurnID: bound.Turn.ID, TurnLeaseID: bound.LeaseID, TurnLeaseEpoch: bound.Epoch,
		ExpectedTurnRevision: bound.Turn.Revision, Objective: arguments.Objective,
		ObjectiveSummary: arguments.Objective, UserPromptDigest: hex.EncodeToString(promptDigest[:]),
		WorkloadKind: WorkloadKind(arguments.WorkloadKind), Service: func() *ServiceSpec {
			if arguments.Service == nil {
				return nil
			}
			return &ServiceSpec{WorkloadID: arguments.Service.WorkloadID, Port: arguments.Service.Port, HealthPath: arguments.Service.HealthPath}
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
	if arguments.WorkloadKind == "" {
		arguments.WorkloadKind = string(WorkloadJob)
	}
	if arguments.Objective == "" || len(arguments.Objective) > coretask.MaxGoalBytes || !utf8.ValidString(arguments.Objective) || !validateWorkspaceMode(WorkspaceMode(arguments.WorkspaceMode)) || len(arguments.AttachmentIDs) > coreconversation.MaxTurnAttachments {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	if (ComputeRequirements{MinVCPU: arguments.MinVCPU, MinMemoryGiB: arguments.MinMemoryGiB, DiskGiB: arguments.DiskGiB,
		EstimatedRuntimeMinutes: arguments.EstimatedRuntimeMinutes}).validate() != nil {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	if (arguments.WorkloadKind == string(WorkloadJob) && arguments.Service != nil) || (arguments.WorkloadKind == string(WorkloadService) && (arguments.Service == nil || (ServiceSpec{WorkloadID: arguments.Service.WorkloadID, Port: arguments.Service.Port, HealthPath: arguments.Service.HealthPath}).validate() != nil)) ||
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
