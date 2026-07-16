package planning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

var (
	ErrCloudGoalPlanningModelFailed = errors.New("cloud Goal planning model failed")
	ErrCloudGoalMaterializerFailed  = errors.New("cloud Goal provider Plan materializer failed")
)

// CloudGoalPlanningRepository is the provider-neutral durable projection used
// by the production output coordinator. Every mutation remains scoped by the
// authenticated caller and the exact planning Binding.
type CloudGoalPlanningRepository interface {
	GetResearch(context.Context, task.MutationScope, Binding) (ResearchSession, error)
	GetOfficialSourceEvidence(context.Context, task.MutationScope, Binding, string) (OfficialSourceEvidenceSet, bool, error)
	BindOfficialSourceEvidence(context.Context, task.MutationScope, BindOfficialSourceEvidenceCommand) (OfficialSourceEvidenceSet, error)
	GetRecipeDraft(context.Context, task.MutationScope, Binding) (RecipeDraft, bool, error)
	SaveRecipeDraft(context.Context, task.MutationScope, SaveRecipeDraftCommand) (RecipeDraft, error)
	SaveResourceCandidates(context.Context, task.MutationScope, SaveCandidatesCommand) (ResourceCandidateSet, error)
}

// CloudGoalStageOutputRepository is the immutable replay journal. Attempt is
// checked when committing, but deliberately excluded from the stable identity
// so a newer fenced lease can replay an already committed stage output.
type CloudGoalStageOutputRepository interface {
	GetCloudGoalStageOutput(context.Context, task.MutationScope, CloudGoalStageIdentity, task.Attempt) (CloudGoalStageOutput, bool, error)
	SaveCloudGoalStageOutput(context.Context, task.MutationScope, SaveCloudGoalStageOutputCommand) (CloudGoalStageOutput, error)
}

// CloudGoalMaterializedFacts provides independent read-back of provider facts.
// A materializer result is never trusted until both records are found here.
type CloudGoalMaterializedFacts interface {
	FindCloudGoalQuote(context.Context, string, string) (cloudquote.QuoteV1, bool, error)
	FindCloudGoalPlan(context.Context, string, string) (cloudapproval.PlanV1, bool, error)
}

// CloudGoalPlanningModel is an injected reasoning boundary. Implementations
// may use a model and typed official-fetch tools, but this coordinator neither
// implements nor emulates those capabilities.
type CloudGoalPlanningModel interface {
	ResearchOfficialSources(context.Context, CloudGoalResearchInput) ([]recipe.SourceV1, error)
	DraftExperimentalRecipe(context.Context, CloudGoalRecipeInput) (recipe.RecipeV1, error)
	ProposeResourceCandidates(context.Context, CloudGoalCandidateInput) ([]ResourceCandidateV1, error)
}

type CloudGoalResearchInput struct {
	Request CloudGoalStageRequest
}

type CloudGoalRecipeInput struct {
	Request  CloudGoalStageRequest
	Evidence OfficialSourceEvidenceSet
}

type CloudGoalCandidateInput struct {
	Request CloudGoalStageRequest
	Draft   RecipeDraft
}

// ProviderPlanMaterializer is the only provider-specific seam. It receives no
// credential or bootstrap-session value. An implementation must use the
// already-active Connection, persist the deterministic Quote/Plan through
// typed fact commands using Stage.OutputIdempotencyKey unchanged for both
// operation-scoped mutations, and return their read-back values. AWS calls are
// restricted to placement and pricing; approval, provisioning and shell are
// outside this interface.
type ProviderPlanMaterializer interface {
	MaterializeProviderPlan(context.Context, ProviderPlanMaterializationRequest) (ProviderPlanMaterialization, error)
}

type ProviderPlanMaterializationRequest struct {
	AgentInstanceID string
	Stage           CloudGoalStageRequest
	Draft           RecipeDraft
	Candidates      []ResourceCandidateV1
	QuoteID         string
	PlanID          string
}

type ProviderPlanMaterialization struct {
	Quote cloudquote.QuoteV1
	Plan  cloudapproval.PlanV1
}

// ValidateProviderPlanMaterializationRequest closes the application boundary
// before provider reads. The provider implementation must not infer or repair
// a stale lease, Recipe digest, candidate set, or deterministic fact ID.
func ValidateProviderPlanMaterializationRequest(request ProviderPlanMaterializationRequest, now time.Time) error {
	agentInstanceID, agentErr := uuid.Parse(request.AgentInstanceID)
	if agentErr != nil || agentInstanceID == uuid.Nil || agentInstanceID.String() != request.AgentInstanceID ||
		request.Stage.Step.Name != cloudskill.StepPrepareResourceCandidates ||
		validateCloudGoalStageRequest(request.Stage, now.UTC()) != nil || request.Draft.Revision < 1 ||
		request.Draft.RecipeID != request.Stage.Binding.RecipeID || request.Draft.Recipe.RecipeID != request.Draft.RecipeID ||
		request.Draft.Recipe.Maturity != recipe.MaturityExperimental || request.Draft.Recipe.Validate() != nil ||
		ValidateCandidatesAgainstRecipe(request.Candidates, request.Draft.Recipe.Requirements) != nil {
		return ErrCloudGoalOutputInvalid
	}
	digest, err := request.Draft.Recipe.Digest()
	if err != nil || digest != request.Draft.Digest {
		return ErrCloudGoalOutputInvalid
	}
	quoteID, planID, err := ProviderFactIDs(request.Stage.OutputIdempotencyKey)
	if err != nil || request.QuoteID != quoteID || request.PlanID != planID {
		return ErrCloudGoalOutputInvalid
	}
	return nil
}

// ProviderFactIDs derives the operation-scoped Quote and Plan identities from
// the immutable stage output key. It is shared by the provider-neutral output
// coordinator and the provider materializer to prevent identity drift.
func ProviderFactIDs(outputKey string) (string, string, error) {
	namespace, err := uuid.Parse(outputKey)
	if err != nil || namespace == uuid.Nil || namespace.String() != outputKey {
		return "", "", ErrCloudGoalOutputInvalid
	}
	return uuid.NewSHA1(namespace, []byte("cloud-goal-provider-quote")).String(),
		uuid.NewSHA1(namespace, []byte("cloud-goal-provider-plan")).String(), nil
}

type CloudGoalStageIdentity struct {
	OutputIdempotencyKey string  `json:"output_idempotency_key"`
	Binding              Binding `json:"binding"`
	TaskID               string  `json:"task_id"`
	StepID               string  `json:"step_id"`
	StepName             string  `json:"step_name"`
	GoalDigest           string  `json:"goal_digest"`
}

func (identity CloudGoalStageIdentity) Validate() error {
	if _, err := uuid.Parse(identity.OutputIdempotencyKey); err != nil || identity.Binding.Validate() != nil || identity.Binding.ConnectionID == "" {
		return ErrCloudGoalOutputInvalid
	}
	if _, err := uuid.Parse(identity.TaskID); err != nil {
		return ErrCloudGoalOutputInvalid
	}
	if _, err := uuid.Parse(identity.StepID); err != nil || !validCloudGoalStageName(identity.StepName) {
		return ErrCloudGoalOutputInvalid
	}
	decoded, err := hex.DecodeString(identity.GoalDigest)
	if err != nil || len(decoded) != sha256.Size {
		return ErrCloudGoalOutputInvalid
	}
	return nil
}

func (identity CloudGoalStageIdentity) ValidateAttempt(attempt task.Attempt) error {
	return validateCloudGoalAttempt(identity, attempt, time.Time{})
}

type SaveCloudGoalStageOutputCommand struct {
	Identity CloudGoalStageIdentity
	Attempt  task.Attempt
	Output   CloudGoalStageOutput
}

func (command SaveCloudGoalStageOutputCommand) Validate() error {
	if command.Identity.Validate() != nil || validateCloudGoalAttempt(command.Identity, command.Attempt, time.Time{}) != nil ||
		validateStageOutput(command.Identity.StepName, command.Output) != nil {
		return ErrCloudGoalOutputInvalid
	}
	return nil
}

func (command SaveCloudGoalStageOutputCommand) Digest() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		Identity CloudGoalStageIdentity `json:"identity"`
		Output   CloudGoalStageOutput   `json:"output"`
	}{command.Identity, command.Output})
	return sha256.Sum256(encoded)
}

type PersistentCloudGoalOutputAdapter struct {
	agentInstanceID string
	planning        CloudGoalPlanningRepository
	outputs         CloudGoalStageOutputRepository
	model           CloudGoalPlanningModel
	materializer    ProviderPlanMaterializer
	facts           CloudGoalMaterializedFacts
	now             func() time.Time
}

var _ CloudGoalOutputAdapter = (*PersistentCloudGoalOutputAdapter)(nil)

func NewPersistentCloudGoalOutputAdapter(
	agentInstanceID string,
	planning CloudGoalPlanningRepository,
	outputs CloudGoalStageOutputRepository,
	model CloudGoalPlanningModel,
	materializer ProviderPlanMaterializer,
	facts CloudGoalMaterializedFacts,
	now func() time.Time,
) (*PersistentCloudGoalOutputAdapter, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || planning == nil || outputs == nil || model == nil || materializer == nil || facts == nil {
		return nil, ErrCloudGoalDispatchInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &PersistentCloudGoalOutputAdapter{
		agentInstanceID: agentInstanceID, planning: planning, outputs: outputs, model: model,
		materializer: materializer, facts: facts, now: now,
	}, nil
}

func (adapter *PersistentCloudGoalOutputAdapter) ExecuteCloudGoalStage(ctx context.Context, request CloudGoalStageRequest) (CloudGoalStageOutput, error) {
	if adapter == nil || ctx == nil {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	now := adapter.now().UTC()
	if now.IsZero() || validateCloudGoalStageRequest(request, now) != nil {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	identity := cloudGoalStageIdentity(request)
	replayed, found, err := adapter.outputs.GetCloudGoalStageOutput(ctx, request.Caller, identity, request.Attempt)
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	if found {
		if validateStageOutput(request.Step.Name, replayed) != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
		return replayed, nil
	}

	session, err := adapter.planning.GetResearch(ctx, request.Caller, request.Binding)
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	if session.Binding != request.Binding || session.TaskID != request.Attempt.TaskID {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}

	var output CloudGoalStageOutput
	switch request.Step.Name {
	case cloudskill.StepResearchOfficialSources:
		output, err = adapter.research(ctx, request)
	case cloudskill.StepDraftRecipe:
		output, err = adapter.recipe(ctx, request)
	case cloudskill.StepPrepareResourceCandidates:
		output, err = adapter.candidates(ctx, request, session)
	default:
		err = ErrCloudGoalOutputInvalid
	}
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	committed, err := adapter.outputs.SaveCloudGoalStageOutput(ctx, request.Caller, SaveCloudGoalStageOutputCommand{
		Identity: identity, Attempt: request.Attempt, Output: output,
	})
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	if committed != output {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	return committed, nil
}

func (adapter *PersistentCloudGoalOutputAdapter) research(ctx context.Context, request CloudGoalStageRequest) (CloudGoalStageOutput, error) {
	evidence, found, err := adapter.planning.GetOfficialSourceEvidence(ctx, request.Caller, request.Binding, request.Attempt.TaskID)
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	if !found {
		sources, modelErr := adapter.model.ResearchOfficialSources(ctx, CloudGoalResearchInput{Request: request})
		if modelErr != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalPlanningModelFailed
		}
		if validateOfficialSourceClaims(sources) != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
		evidence, err = adapter.planning.BindOfficialSourceEvidence(ctx, request.Caller, BindOfficialSourceEvidenceCommand{
			IdempotencyKey: request.OutputIdempotencyKey, Binding: request.Binding,
			TaskID: request.Attempt.TaskID, Sources: sources,
		})
		if err != nil {
			return CloudGoalStageOutput{}, err
		}
	}
	if validateEvidenceSet(request.Attempt.TaskID, evidence) != nil {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	return CloudGoalStageOutput{ResultRef: evidence.ResultRef()}, nil
}

func (adapter *PersistentCloudGoalOutputAdapter) recipe(ctx context.Context, request CloudGoalStageRequest) (CloudGoalStageOutput, error) {
	evidence, found, err := adapter.planning.GetOfficialSourceEvidence(ctx, request.Caller, request.Binding, request.Attempt.TaskID)
	if err != nil || !found {
		if err != nil {
			return CloudGoalStageOutput{}, err
		}
		return CloudGoalStageOutput{}, ErrResearchEvidenceMissing
	}
	draft, found, err := adapter.planning.GetRecipeDraft(ctx, request.Caller, request.Binding)
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	if !found {
		value, modelErr := adapter.model.DraftExperimentalRecipe(ctx, CloudGoalRecipeInput{Request: request, Evidence: evidence})
		if modelErr != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalPlanningModelFailed
		}
		if validateRecipeForEvidence(request.Binding, value, evidence) != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
		draft, err = adapter.planning.SaveRecipeDraft(ctx, request.Caller, SaveRecipeDraftCommand{
			IdempotencyKey: request.OutputIdempotencyKey, Binding: request.Binding, ExpectedRevision: 0, Recipe: value,
		})
		if err != nil {
			return CloudGoalStageOutput{}, err
		}
	}
	if validateRecipeForEvidence(request.Binding, draft.Recipe, evidence) != nil {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	digest, err := draft.Recipe.Digest()
	if err != nil || draft.Digest != digest || draft.Revision < 1 {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	return CloudGoalStageOutput{ResultRef: "planning://recipe/" + draft.Digest}, nil
}

func (adapter *PersistentCloudGoalOutputAdapter) candidates(ctx context.Context, request CloudGoalStageRequest, session ResearchSession) (CloudGoalStageOutput, error) {
	evidence, evidenceFound, err := adapter.planning.GetOfficialSourceEvidence(ctx, request.Caller, request.Binding, request.Attempt.TaskID)
	if err != nil || !evidenceFound {
		if err != nil {
			return CloudGoalStageOutput{}, err
		}
		return CloudGoalStageOutput{}, ErrResearchEvidenceMissing
	}
	draft, found, err := adapter.planning.GetRecipeDraft(ctx, request.Caller, request.Binding)
	if err != nil || !found {
		if err != nil {
			return CloudGoalStageOutput{}, err
		}
		return CloudGoalStageOutput{}, ErrResearchPending
	}
	if validateRecipeForEvidence(request.Binding, draft.Recipe, evidence) != nil {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	candidates := canonicalCandidates(session.Candidates)
	if session.CandidateRevision == 0 {
		proposed, modelErr := adapter.model.ProposeResourceCandidates(ctx, CloudGoalCandidateInput{Request: request, Draft: draft})
		if modelErr != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalPlanningModelFailed
		}
		if ValidateCandidatesAgainstRecipe(proposed, draft.Recipe.Requirements) != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
		saved, saveErr := adapter.planning.SaveResourceCandidates(ctx, request.Caller, SaveCandidatesCommand{
			IdempotencyKey: request.OutputIdempotencyKey, Binding: request.Binding, ExpectedRevision: 0,
			Candidates: proposed, QuoteState: QuoteAwaitingQuote,
		})
		if saveErr != nil {
			return CloudGoalStageOutput{}, saveErr
		}
		candidates = canonicalCandidates(saved.Candidates)
	} else if session.QuoteState != QuoteAwaitingQuote || ValidateCandidatesAgainstRecipe(candidates, draft.Recipe.Requirements) != nil {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
	if len(candidates) != 3 {
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}

	quoteID, planID := deterministicProviderFactIDs(request.OutputIdempotencyKey)
	materialized, found, err := adapter.readMaterialized(ctx, request, draft, candidates, quoteID, planID)
	if err != nil {
		return CloudGoalStageOutput{}, err
	}
	if !found {
		returned, materializeErr := adapter.materializer.MaterializeProviderPlan(ctx, ProviderPlanMaterializationRequest{
			AgentInstanceID: adapter.agentInstanceID, Stage: request, Draft: draft,
			Candidates: append([]ResourceCandidateV1(nil), candidates...), QuoteID: quoteID, PlanID: planID,
		})
		if materializeErr != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalMaterializerFailed
		}
		if validateMaterializedPlan(adapter.agentInstanceID, request, draft, candidates, quoteID, planID, returned, adapter.now().UTC()) != nil {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
		materialized, found, err = adapter.readMaterialized(ctx, request, draft, candidates, quoteID, planID)
		if err != nil {
			return CloudGoalStageOutput{}, err
		}
		if !found {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
		if !sameProviderMaterialization(returned, materialized) {
			return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
		}
	}
	return CloudGoalStageOutput{PlanID: materialized.Plan.PlanID}, nil
}

func sameProviderMaterialization(left, right ProviderPlanMaterialization) bool {
	leftQuote, leftQuoteErr := left.Quote.Digest()
	rightQuote, rightQuoteErr := right.Quote.Digest()
	leftPlan, leftPlanErr := left.Plan.Hash()
	rightPlan, rightPlanErr := right.Plan.Hash()
	return leftQuoteErr == nil && rightQuoteErr == nil && leftPlanErr == nil && rightPlanErr == nil &&
		leftQuote == rightQuote && leftPlan == rightPlan
}

func (adapter *PersistentCloudGoalOutputAdapter) readMaterialized(
	ctx context.Context,
	request CloudGoalStageRequest,
	draft RecipeDraft,
	candidates []ResourceCandidateV1,
	quoteID, planID string,
) (ProviderPlanMaterialization, bool, error) {
	plan, found, err := adapter.facts.FindCloudGoalPlan(ctx, request.Binding.OwnerID, planID)
	if err != nil || !found {
		return ProviderPlanMaterialization{}, false, err
	}
	quoted, quoteFound, err := adapter.facts.FindCloudGoalQuote(ctx, request.Binding.OwnerID, quoteID)
	if err != nil {
		return ProviderPlanMaterialization{}, false, err
	}
	if !quoteFound {
		return ProviderPlanMaterialization{}, false, ErrCloudGoalOutputInvalid
	}
	materialized := ProviderPlanMaterialization{Quote: quoted, Plan: plan}
	if validateMaterializedPlan(adapter.agentInstanceID, request, draft, candidates, quoteID, planID, materialized, adapter.now().UTC()) != nil {
		return ProviderPlanMaterialization{}, false, ErrCloudGoalOutputInvalid
	}
	return materialized, true, nil
}

func cloudGoalStageIdentity(request CloudGoalStageRequest) CloudGoalStageIdentity {
	digest := sha256.Sum256([]byte(strings.TrimSpace(request.Goal)))
	return CloudGoalStageIdentity{
		OutputIdempotencyKey: request.OutputIdempotencyKey, Binding: request.Binding,
		TaskID: request.Attempt.TaskID, StepID: request.Attempt.StepID, StepName: request.Step.Name,
		GoalDigest: hex.EncodeToString(digest[:]),
	}
}

func validateCloudGoalStageRequest(request CloudGoalStageRequest, now time.Time) error {
	identity := cloudGoalStageIdentity(request)
	if identity.Validate() != nil || request.Caller.Validate() != nil || request.Binding.ConnectionID == "" || strings.TrimSpace(request.Goal) == "" || len(request.Goal) > 64*1024 ||
		security.ContainsLikelySecret(request.Goal) || request.Step.TaskID != request.Attempt.TaskID || request.Step.StepID != request.Attempt.StepID ||
		request.Step.Name != identity.StepName || request.Step.ExecutorKind != task.ExecutorControlPlane ||
		request.Attempt.Attempt != request.Step.Attempt+1 || request.Attempt.LeaseEpoch != request.Step.LeaseEpoch+1 ||
		(request.Step.ExecutionStatus != task.ExecutionQueued && request.Step.ExecutionStatus != task.ExecutionRunning) || request.Step.OutcomeStatus != task.OutcomePending {
		return ErrCloudGoalOutputInvalid
	}
	return validateCloudGoalAttempt(identity, request.Attempt, now)
}

func validateCloudGoalAttempt(identity CloudGoalStageIdentity, attempt task.Attempt, now time.Time) error {
	if attempt.TaskID != identity.TaskID || attempt.StepID != identity.StepID || attempt.Attempt < 1 || attempt.LeaseEpoch < 1 ||
		attempt.WorkerID == "" || attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending {
		return ErrCloudGoalOutputInvalid
	}
	if _, err := uuid.Parse(attempt.WorkerID); err != nil {
		return ErrCloudGoalOutputInvalid
	}
	if !now.IsZero() && (attempt.LeaseExpiresAt.IsZero() || !now.Before(attempt.LeaseExpiresAt)) {
		return ErrCloudGoalOutputInvalid
	}
	return nil
}

func validCloudGoalStageName(value string) bool {
	return value == cloudskill.StepResearchOfficialSources || value == cloudskill.StepDraftRecipe || value == cloudskill.StepPrepareResourceCandidates
}

func validateStageOutput(stage string, output CloudGoalStageOutput) error {
	if security.ContainsLikelySecret(output.ResultRef) || security.ContainsLikelySecret(output.PlanID) {
		return ErrCloudGoalOutputInvalid
	}
	switch stage {
	case cloudskill.StepResearchOfficialSources:
		if output.PlanID != "" || !validPlanningDigestRef(output.ResultRef, "planning://official-source-evidence/") {
			return ErrCloudGoalOutputInvalid
		}
	case cloudskill.StepDraftRecipe:
		if output.PlanID != "" || !validPlanningDigestRef(output.ResultRef, "planning://recipe/") {
			return ErrCloudGoalOutputInvalid
		}
	case cloudskill.StepPrepareResourceCandidates:
		parsed, err := uuid.Parse(output.PlanID)
		if err != nil || parsed == uuid.Nil || parsed.String() != output.PlanID || output.ResultRef != "" {
			return ErrCloudGoalOutputInvalid
		}
	default:
		return ErrCloudGoalOutputInvalid
	}
	return nil
}

func (output CloudGoalStageOutput) ValidateForStage(stage string) error {
	return validateStageOutput(stage, output)
}

func validateOfficialSourceClaims(sources []recipe.SourceV1) error {
	if len(sources) < 1 || len(sources) > 16 {
		return ErrCloudGoalOutputInvalid
	}
	encoded, err := json.Marshal(sources)
	if err != nil || security.ContainsLikelySecret(string(encoded)) {
		return ErrCloudGoalOutputInvalid
	}
	command := BindOfficialSourceEvidenceCommand{IdempotencyKey: uuid.NewString(), Binding: Binding{
		RequestID: uuid.NewString(), OwnerID: "validation", ConversationID: "validation", RecipeID: "validation",
		Retention: task.RetentionEphemeralAutoDestroy,
	}, TaskID: uuid.NewString(), Sources: sources}
	if command.Validate() != nil {
		return ErrCloudGoalOutputInvalid
	}
	for _, source := range sources {
		if !source.Official {
			return ErrCloudGoalOutputInvalid
		}
	}
	return nil
}

func validateEvidenceSet(taskID string, set OfficialSourceEvidenceSet) error {
	built, err := BuildOfficialSourceEvidenceSet(taskID, set.Evidence)
	if err != nil || built.Digest != set.Digest || !slices.Equal(built.Evidence, set.Evidence) {
		return ErrCloudGoalOutputInvalid
	}
	return nil
}

func validateRecipeForEvidence(binding Binding, value recipe.RecipeV1, evidence OfficialSourceEvidenceSet) error {
	if value.SchemaVersion != recipe.SchemaV1 || value.RecipeID != binding.RecipeID || value.Maturity != recipe.MaturityExperimental ||
		value.ManagedAcceptance != nil || value.Validate() != nil || len(value.Sources) != len(evidence.Evidence) {
		return ErrCloudGoalOutputInvalid
	}
	byURL := make(map[string]OfficialSourceEvidence, len(evidence.Evidence))
	for _, item := range evidence.Evidence {
		byURL[item.URL] = item
	}
	for _, source := range value.Sources {
		item, found := byURL[source.URL]
		if !found || !source.Official || source.ContentDigest != item.ContentDigest || !source.RetrievedAt.Equal(item.RetrievedAt) {
			return ErrCloudGoalOutputInvalid
		}
	}
	return nil
}

func deterministicProviderFactIDs(outputKey string) (string, string) {
	quoteID, planID, err := ProviderFactIDs(outputKey)
	if err != nil {
		panic("validated cloud Goal output key became invalid")
	}
	return quoteID, planID
}

func validateMaterializedPlan(
	agentInstanceID string,
	request CloudGoalStageRequest,
	draft RecipeDraft,
	candidates []ResourceCandidateV1,
	quoteID, planID string,
	materialized ProviderPlanMaterialization,
	now time.Time,
) error {
	quoted, plan := materialized.Quote, materialized.Plan
	if quoted.QuoteID != quoteID || plan.PlanID != planID || quoted.Validate() != nil || plan.Validate() != nil ||
		plan.Status != cloudapproval.PlanReadyForConfirmation || plan.Revision != 1 || plan.AgentInstanceID != agentInstanceID ||
		plan.OwnerID != request.Binding.OwnerID || plan.ConnectionID != request.Binding.ConnectionID ||
		plan.Recipe.RecipeID != request.Binding.RecipeID || plan.Recipe.Digest != draft.Digest || plan.Recipe.Maturity != recipe.MaturityExperimental ||
		!now.Before(quoted.ValidUntil) || len(quoted.Candidates) != 3 || plan.ValidateQuote(quoted, now) != nil {
		return ErrCloudGoalOutputInvalid
	}
	profiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	ordered := canonicalCandidates(candidates)
	if len(ordered) != len(profiles) {
		return ErrCloudGoalOutputInvalid
	}
	for index, profile := range profiles {
		candidate, found := quoted.Candidate(profile)
		if !found || candidate.Scope.AgentInstanceID != agentInstanceID || candidate.Scope.OwnerID != request.Binding.OwnerID ||
			candidate.Scope.ConnectionID != request.Binding.ConnectionID || candidate.Scope.Recipe.RecipeID != request.Binding.RecipeID ||
			candidate.Scope.Recipe.Digest != draft.Digest || candidate.Scope.Recipe.Maturity != recipe.MaturityExperimental ||
			candidate.Scope.Resource.CandidateID != profile || candidate.Scope.Resource.Architecture != ordered[index].Architecture ||
			candidate.Scope.Resource.VCPU < ordered[index].VCPU || candidate.Scope.Resource.MemoryMiB < ordered[index].MemoryMiB ||
			candidate.Scope.Resource.DiskGiB < ordered[index].DiskGiB {
			return ErrCloudGoalOutputInvalid
		}
		if ordered[index].GPURequired && (candidate.Scope.Resource.GPUCount == 0 || candidate.Scope.Resource.GPUMemoryMiB < ordered[index].GPUMemoryMiB) {
			return ErrCloudGoalOutputInvalid
		}
	}
	return nil
}
