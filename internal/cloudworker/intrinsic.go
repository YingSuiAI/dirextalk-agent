package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

var ErrCloudIntentRequired = errors.New("cloudworker: explicit cloud intent or trusted local budget evidence is required")

const (
	englishCloudTarget = `(?:aws(?:\s+cloud)?(?:\s+worker)?|ec2|cloud\s+worker)`
	chineseCloudTarget = `(?:(?:aws\s*)?(?:云端|云上|云\s*worker|cloud\s*worker)|ec2|aws)`
)

var (
	// Authorization requires one complete command clause which binds the
	// execution verb to the Cloud target. Independent keywords elsewhere in the
	// prompt are deliberately insufficient.
	englishCloudExecutionCommand = regexp.MustCompile(
		`(?:^|[.!?;\n]\s*)(?:(?:please|kindly)\s+|(?:can|could)\s+you\s+(?:please\s+)?|i\s+(?:want|need)\s+you\s+to\s+)?(?:explicitly\s+)?(?:` +
			`(?:run|execute|process|offload|launch)\s+[^.!?;\r\n]{1,160}?\s+(?:on|in|using|with|to)\s+(?:an?\s+|the\s+)?` + englishCloudTarget + `\b|` +
			`(?:use|start|launch)\s+(?:an?\s+|the\s+)?` + englishCloudTarget + `\s+(?:to\s+)?(?:run|execute|process|edit|build|analy[sz]e|handle|explain)\b)`)
	chineseCloudExecutionCommand = regexp.MustCompile(
		`(?:^|[。！？；\n]\s*)(?:请(?:你)?|麻烦(?:你)?|我要你|需要你)?\s*(?:(?:明确|务必|必须)\s*)?(?:` +
			`(?:在|到|用|使用|通过|交给)\s*` + chineseCloudTarget + `(?:上|中)?\s*(?:执行|运行|处理|启动)|` +
			`(?:把|将)[^。！？；\r\n]{1,96}?(?:交给|放到|放在|提交到)\s*` + chineseCloudTarget + `(?:上|中)?\s*(?:执行|运行|处理)|` +
			`(?:让|启动)\s*` + chineseCloudTarget + `\s*(?:来|去)?\s*(?:执行|运行|处理))`)
	cloudIntentClauseBoundary = regexp.MustCompile(`[.!?;\n。！？；,，]+`)

	englishCloudNegation = regexp.MustCompile(
		`(?:\b(?:do\s+not|don't|never|without|no)\b[^.!?;\r\n]{0,120}\b(?:aws|ec2|cloud)\b|\b(?:aws|ec2|cloud)\b[^.!?;\r\n]{0,120}\b(?:not|never|without)\b)`)
	englishCloudConditional = regexp.MustCompile(`\b(?:if|unless|provided\s+that|in\s+case|when(?:ever)?)\b`)
	englishCloudComparison  = regexp.MustCompile(`\b(?:compare|comparison|versus|vs\.?)\b`)
	englishLocalExecution   = regexp.MustCompile(
		`(?:\b(?:run|execute|process|handle)\b[^.!?;\r\n]{0,80}\b(?:locally|on\s+(?:(?:my|this|the)\s+)?(?:machine|computer|device)|in\s+(?:the\s+)?local\s+sandbox)\b|` +
			`\b(?:locally|on\s+(?:(?:my|this|the)\s+)?(?:machine|computer|device)|in\s+(?:the\s+)?local\s+sandbox)\b[^.!?;\r\n]{0,80}\b(?:run|execute|process|handle)\b)`)
	chineseCloudNegation = regexp.MustCompile(
		`(?:(?:不要|不用|不使用|禁止|别用|不可|不能|无需|不在)[^。！？；\r\n]{0,48}` + chineseCloudTarget + `|` +
			chineseCloudTarget + `[^。！？；\r\n]{0,48}(?:不要|不用|不使用|禁止|别用|不可|不能|无需执行))`)
	chineseCloudConditional = regexp.MustCompile(`(?:如果|若是|假如|要是|倘若|一旦|否则|必要时|需要时|视情况)`)
	chineseCloudComparison  = regexp.MustCompile(`(?:比较|对比|相比|区别|差异|优缺点)`)
	chineseLocalExecution   = regexp.MustCompile(
		`(?:(?:在|用|使用)?(?:本机|本地|当前机器|当前电脑)(?:上|中)?[^。！？；，,\r\n]{0,16}(?:执行|运行|处理)|` +
			`(?:执行|运行|处理)[^。！？；，,\r\n]{0,16}(?:在|用|使用)(?:本机|本地|当前机器|当前电脑)(?:上|中)?)`)
	englishLocalExecutionNegation = regexp.MustCompile(
		`\b(?:do\s+not|don't|never)\s+(?:run|execute|process|handle)\s+(?:locally|on\s+(?:(?:my|this|the)\s+)?(?:machine|computer|device)|in\s+(?:the\s+)?local\s+sandbox)\b`)
	chineseLocalExecutionNegation = regexp.MustCompile(
		`(?:(?:不要|不用|禁止|别|不可|不能)\s*(?:在|用|使用)?\s*(?:本机|本地|当前机器|当前电脑)(?:上|中)?\s*(?:执行|运行|处理)|` +
			`(?:不要|不用|禁止|别|不可|不能)\s*(?:执行|运行|处理)\s*(?:在|用|使用)?\s*(?:本机|本地|当前机器|当前电脑)(?:上|中)?)`)
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
// durable turn to an exact-version private S3 manifest. The model cannot name
// buckets, keys, versions, grants, or arbitrary local paths.
type IntrinsicManifestResolver interface {
	ResolveCloudWorkerManifest(context.Context, coreconversation.TurnLease, WorkspaceMode, []string) (InputManifest, error)
}

// IntrinsicBudgetResolver is the sole authority for local-budget exhaustion.
// A model assertion and a failed local task are intentionally not inputs.
type IntrinsicBudgetResolver interface {
	ResolveCloudWorkerBudgetEvidence(context.Context, coreconversation.TurnLease) (*LocalBudgetEvidence, error)
}

type ProposeIntrinsic struct {
	service   *Service
	owners    IntrinsicOwnerResolver
	manifests IntrinsicManifestResolver
	budgets   IntrinsicBudgetResolver
}

func NewProposeIntrinsic(service *Service, owners IntrinsicOwnerResolver, manifests IntrinsicManifestResolver, budgets IntrinsicBudgetResolver) (*ProposeIntrinsic, error) {
	if service == nil || owners == nil {
		return nil, ErrInvalid
	}
	return &ProposeIntrinsic{service: service, owners: owners, manifests: manifests, budgets: budgets}, nil
}

type proposeIntrinsicArguments struct {
	AttachmentIDs []string `json:"attachment_ids,omitempty"`
	Objective     string   `json:"objective"`
	WorkspaceMode string   `json:"workspace_mode"`
}

func (p *ProposeIntrinsic) ResolveIntrinsicTools(_ context.Context, lease coreconversation.TurnLease) ([]coreconversation.ResolvedIntrinsic, error) {
	if p == nil || p.service == nil || p.owners == nil || lease.Turn.ID == "" || lease.LeaseID == "" || lease.Epoch == 0 {
		return nil, ErrInvalid
	}
	bound := lease
	properties := map[string]any{
		"objective":      map[string]any{"type": "string", "minLength": 1, "maxLength": coretask.MaxGoalBytes},
		"workspace_mode": map[string]any{"type": "string", "enum": []any{string(WorkspaceNone), string(WorkspaceReadOnly), string(WorkspaceWrite)}},
	}
	if attachmentSchema := frozenTurnAttachmentSchema(bound.Turn); attachmentSchema != nil {
		properties["attachment_ids"] = attachmentSchema
	}
	tool := coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerProposeToolName,
		Description: "Create a priced, owner-confirmed ephemeral AWS Pi Worker offer. Use only when the user explicitly requests cloud execution or Core reports an exhausted local runtime budget. This tool never runs a failed local task in the cloud automatically.",
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"objective", "workspace_mode"},
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
	explicit := hasExplicitCloudIntent(bound.Turn.Prompt)
	var budget *LocalBudgetEvidence
	reason := ProposalReasonExplicitUserCloud
	if !explicit {
		if hasCloudExecutionVeto(bound.Turn.Prompt) || mode == WorkspaceNone ||
			!turnAllowsSelectedWorkspaceArchive(bound.Turn, arguments.AttachmentIDs) {
			return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
		}
		if p.budgets == nil {
			return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
		}
		budget, err = p.budgets.ResolveCloudWorkerBudgetEvidence(ctx, bound)
		if err != nil || budget == nil {
			return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
		}
		reason = ProposalReasonLocalBudgetExceeded
	}
	if strings.TrimSpace(bound.Turn.OwnerID) == "" || bound.Turn.AccountGeneration == 0 {
		return coreconversation.IntrinsicExecutionResult{}, ErrCloudIntentRequired
	}
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, bound)
	if err != nil || strings.TrimSpace(owner.OwnerID) != strings.TrimSpace(bound.Turn.OwnerID) || owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	manifest := InputManifest{Schema: InputManifestSchema}
	if mode != WorkspaceNone {
		if p.manifests == nil || len(arguments.AttachmentIDs) == 0 || !turnAllowsAttachments(bound.Turn, arguments.AttachmentIDs) {
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
		// The relay has no approved Pi adapter for Anthropic, Gemini, voice,
		// or future providers. Reject before a paid quote is created.
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
		ProposalReason: reason, LocalBudgetEvidence: budget, InputManifest: manifest,
		WorkspaceMode:      mode,
		ModelAuthorization: modelAuthorization,
	})
	if err != nil {
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
	if arguments.Objective == "" || len(arguments.Objective) > coretask.MaxGoalBytes || !utf8.ValidString(arguments.Objective) || !validateWorkspaceMode(WorkspaceMode(arguments.WorkspaceMode)) || len(arguments.AttachmentIDs) > coreconversation.MaxTurnAttachments {
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
	if (WorkspaceMode(arguments.WorkspaceMode) == WorkspaceNone) != (len(arguments.AttachmentIDs) == 0) {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	canonical, _ := json.Marshal(arguments)
	if !bytes.Equal(canonical, raw) {
		return proposeIntrinsicArguments{}, ErrInvalid
	}
	// Attachment selection is a semantic set. Validate the caller's canonical
	// JSON before normalizing its order, then give the trusted resolver a stable
	// order so random UUID ordering cannot make an otherwise valid call flaky.
	sort.Strings(arguments.AttachmentIDs)
	return arguments, nil
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

func hasExplicitCloudIntent(prompt string) bool {
	explicit, veto := assessCloudIntent(prompt)
	return explicit && !veto
}

func hasCloudExecutionVeto(prompt string) bool {
	_, veto := assessCloudIntent(prompt)
	return veto
}

// assessCloudIntent keeps negation scope inside one punctuation-delimited
// clause. A directive such as "do not run locally; run this on AWS" is a
// positive cloud authorization, while any actual cloud negation, conditional,
// comparison, or conflicting positive local command still fails closed.
func assessCloudIntent(prompt string) (explicit bool, veto bool) {
	value := strings.ToLower(strings.TrimSpace(prompt))
	if value == "" {
		return false, true
	}
	if englishCloudConditional.MatchString(value) || englishCloudComparison.MatchString(value) ||
		chineseCloudConditional.MatchString(value) || chineseCloudComparison.MatchString(value) {
		return false, true
	}
	for _, clause := range cloudIntentClauseBoundary.Split(value, -1) {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		// A negative local directive is not itself paid-cloud authority, but it
		// must not be reinterpreted as either a positive local command or a
		// cloud negation spanning into the next clause.
		clause = englishLocalExecutionNegation.ReplaceAllString(clause, " ")
		clause = chineseLocalExecutionNegation.ReplaceAllString(clause, " ")
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		if englishCloudNegation.MatchString(clause) || chineseCloudNegation.MatchString(clause) ||
			englishLocalExecution.MatchString(clause) || chineseLocalExecution.MatchString(clause) {
			return false, true
		}
		if englishCloudExecutionCommand.MatchString(clause) || chineseCloudExecutionCommand.MatchString(clause) {
			explicit = true
		}
	}
	return explicit, false
}

var _ coreconversation.IntrinsicResolver = (*ProposeIntrinsic)(nil)
