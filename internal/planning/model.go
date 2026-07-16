// Package planning owns the durable, provider-neutral planning projection used
// by the native cloud dispatcher. It never provisions resources or carries
// credentials.
package planning

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

var (
	ErrInvalid                 = errors.New("invalid planning input")
	ErrNotFound                = errors.New("planning session not found")
	ErrScopeMismatch           = errors.New("planning session caller scope does not match")
	ErrIdempotencyConflict     = idempotency.ErrConflict
	ErrRevisionConflict        = errors.New("planning revision does not match")
	ErrResearchPending         = errors.New("research task is not attached yet")
	ErrTaskOperation           = errors.New("durable task operation failed")
	ErrPersistence             = errors.New("planning persistence operation failed")
	ErrResearchEvidenceMissing = errors.New("official-source research evidence is missing")
	ErrRawSecret               = errors.New("raw secret is forbidden in planning data")
)

type QuoteRequestState string

const (
	QuoteAwaitingConnection QuoteRequestState = "awaiting_connection"
	QuoteAwaitingQuote      QuoteRequestState = "awaiting_quote"
)

func ValidQuoteRequestState(value QuoteRequestState) bool {
	return value == QuoteAwaitingConnection || value == QuoteAwaitingQuote
}

type CandidateTier string

const (
	TierEconomy     CandidateTier = "economy"
	TierRecommended CandidateTier = "recommended"
	TierPerformance CandidateTier = "performance"
)

var orderedCandidateTiers = []CandidateTier{TierEconomy, TierRecommended, TierPerformance}

// Binding is trusted application state. ConnectionID may be empty only while
// a plan is waiting for the user to connect an AWS account.
type Binding struct {
	RequestID      string
	OwnerID        string
	ConversationID string
	ConnectionID   string
	RecipeID       string
	Retention      task.RetentionPolicy
}

// SameSession reports whether two bindings address the same durable planning
// session. RequestID is deliberately excluded: each conversation turn has a
// fresh idempotency key, while status and Recipe reads must continue to address
// the plan created by an earlier turn.
func (binding Binding) SameSession(other Binding) bool {
	return binding.OwnerID == other.OwnerID &&
		binding.ConversationID == other.ConversationID &&
		binding.ConnectionID == other.ConnectionID &&
		binding.RecipeID == other.RecipeID &&
		binding.Retention == other.Retention
}

func (binding Binding) Validate() error {
	if _, err := uuid.Parse(binding.RequestID); err != nil {
		return fmt.Errorf("%w: request_id must be a UUID", ErrInvalid)
	}
	if !validOpaqueID(binding.OwnerID, 255) || !validOpaqueID(binding.ConversationID, 255) ||
		!validOpaqueID(binding.RecipeID, 128) || (binding.ConnectionID != "" && !validOpaqueID(binding.ConnectionID, 255)) {
		return fmt.Errorf("%w: binding identifiers are invalid", ErrInvalid)
	}
	if binding.Retention != task.RetentionEphemeralAutoDestroy && binding.Retention != task.RetentionManaged {
		return fmt.Errorf("%w: retention policy is invalid", ErrInvalid)
	}
	return nil
}

type ResearchCommand struct {
	Binding Binding
	Create  task.CreateCommand
}

func (command ResearchCommand) Validate() error {
	if err := command.Binding.Validate(); err != nil {
		return err
	}
	if err := command.Create.Validate(); err != nil {
		return err
	}
	if command.Create.IdempotencyKey != command.Binding.RequestID ||
		strings.TrimSpace(command.Create.OwnerID) != command.Binding.OwnerID ||
		command.Create.Retention != command.Binding.Retention {
		return fmt.Errorf("%w: task and planning bindings do not match", ErrInvalid)
	}
	if !validPlanningDAG(command.Create.Steps) {
		return fmt.Errorf("%w: planning task must use the fixed control-plane DAG", ErrInvalid)
	}
	return nil
}

func (command ResearchCommand) Digest() [sha256.Size]byte {
	taskDigest := command.Create.Digest()
	encoded, _ := json.Marshal(struct {
		Binding    Binding `json:"binding"`
		TaskDigest []byte  `json:"task_digest"`
	}{command.Binding, taskDigest[:]})
	return sha256.Sum256(encoded)
}

type ResearchSession struct {
	SessionID         string
	Binding           Binding
	TaskID            string
	QuoteState        QuoteRequestState
	Candidates        []ResourceCandidateV1
	CandidateRevision int64
	Revision          int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type ResourceCandidateV1 struct {
	Tier         CandidateTier       `json:"tier"`
	Architecture recipe.Architecture `json:"architecture"`
	VCPU         uint32              `json:"vcpu"`
	MemoryMiB    uint64              `json:"memory_mib"`
	DiskGiB      uint64              `json:"disk_gib"`
	GPURequired  bool                `json:"gpu_required"`
	GPUMemoryMiB uint64              `json:"gpu_memory_mib,omitempty"`
	GPUFamily    string              `json:"gpu_family,omitempty"`
	Rationale    string              `json:"rationale"`
}

type ResourceCandidateSet struct {
	Candidates []ResourceCandidateV1
	QuoteState QuoteRequestState
	Revision   int64
}

func ValidateResourceCandidates(candidates []ResourceCandidateV1, quoteState QuoteRequestState) error {
	if !ValidQuoteRequestState(quoteState) || len(candidates) != len(orderedCandidateTiers) {
		return fmt.Errorf("%w: exactly economy, recommended and performance candidates are required", ErrInvalid)
	}
	ordered := canonicalCandidates(candidates)
	for index, candidate := range ordered {
		if candidate.Tier != orderedCandidateTiers[index] || !recipe.ValidArchitecture(candidate.Architecture) ||
			candidate.VCPU == 0 || candidate.MemoryMiB == 0 || candidate.DiskGiB == 0 {
			return fmt.Errorf("%w: resource candidate is invalid", ErrInvalid)
		}
		if candidate.VCPU > 1024 || candidate.MemoryMiB > 64*1024*1024 || candidate.DiskGiB > 64*1024 {
			return fmt.Errorf("%w: resource candidate exceeds supported bounds", ErrInvalid)
		}
		if candidate.Rationale != strings.TrimSpace(candidate.Rationale) || candidate.Rationale == "" || len(candidate.Rationale) > 512 {
			return fmt.Errorf("%w: resource candidate rationale is invalid", ErrInvalid)
		}
		if security.ContainsLikelySecret(candidate.Rationale) || security.ContainsLikelySecret(candidate.GPUFamily) {
			return ErrRawSecret
		}
		if candidate.GPURequired {
			if candidate.GPUMemoryMiB == 0 || !validOptionalText(candidate.GPUFamily, 128) {
				return fmt.Errorf("%w: GPU candidate requirements are incomplete", ErrInvalid)
			}
		} else if candidate.GPUMemoryMiB != 0 || candidate.GPUFamily != "" {
			return fmt.Errorf("%w: GPU details require gpu_required", ErrInvalid)
		}
		if index > 0 {
			previous := ordered[index-1]
			if candidate.Architecture != previous.Architecture || candidate.VCPU < previous.VCPU ||
				candidate.MemoryMiB < previous.MemoryMiB || candidate.DiskGiB < previous.DiskGiB ||
				candidate.GPUMemoryMiB < previous.GPUMemoryMiB {
				return fmt.Errorf("%w: candidate tiers must be monotonic", ErrInvalid)
			}
		}
	}
	return nil
}

func ValidateCandidatesAgainstRecipe(candidates []ResourceCandidateV1, requirements recipe.ResourceRequirementsV1) error {
	if err := ValidateResourceCandidates(candidates, QuoteAwaitingQuote); err != nil {
		return err
	}
	for _, candidate := range candidates {
		if candidate.Architecture != requirements.Architecture || candidate.VCPU < requirements.MinVCPU ||
			candidate.MemoryMiB < requirements.MinMemoryMiB || candidate.DiskGiB < requirements.MinDiskGiB {
			return fmt.Errorf("%w: candidate does not satisfy recipe requirements", ErrInvalid)
		}
		if requirements.GPURequired && (!candidate.GPURequired || candidate.GPUMemoryMiB < requirements.MinGPUMemoryMiB) {
			return fmt.Errorf("%w: candidate does not satisfy recipe GPU requirements", ErrInvalid)
		}
	}
	return nil
}

type SaveCandidatesCommand struct {
	IdempotencyKey   string
	Binding          Binding
	ExpectedRevision int64
	Candidates       []ResourceCandidateV1
	QuoteState       QuoteRequestState
}

func (command SaveCandidatesCommand) Validate() error {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil || command.ExpectedRevision < 0 {
		return fmt.Errorf("%w: candidate mutation metadata is invalid", ErrInvalid)
	}
	if err := command.Binding.Validate(); err != nil {
		return err
	}
	if err := ValidateResourceCandidates(command.Candidates, command.QuoteState); err != nil {
		return err
	}
	if command.QuoteState == QuoteAwaitingConnection && command.Binding.ConnectionID != "" {
		return fmt.Errorf("%w: connected plans cannot await a connection", ErrInvalid)
	}
	if command.QuoteState == QuoteAwaitingQuote && command.Binding.ConnectionID == "" {
		return fmt.Errorf("%w: quote requests require a connection", ErrInvalid)
	}
	return nil
}

func (command SaveCandidatesCommand) Digest() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		Binding          Binding               `json:"binding"`
		ExpectedRevision int64                 `json:"expected_revision"`
		Candidates       []ResourceCandidateV1 `json:"candidates"`
		QuoteState       QuoteRequestState     `json:"quote_state"`
	}{command.Binding, command.ExpectedRevision, canonicalCandidates(command.Candidates), command.QuoteState})
	return sha256.Sum256(encoded)
}

type RecipeDraft struct {
	RecipeID  string
	Recipe    recipe.RecipeV1
	Digest    string
	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OfficialSourceEvidence is provenance derived exclusively from a completed
// official_source_fetch durable tool receipt. Content is deliberately omitted
// from the planning projection.
type OfficialSourceEvidence struct {
	TaskID        string    `json:"task_id"`
	ToolCallID    string    `json:"tool_call_id"`
	URL           string    `json:"url"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	ContentDigest string    `json:"content_digest"`
}

type OfficialSourceEvidenceSet struct {
	Evidence []OfficialSourceEvidence
	Digest   string
}

func (set OfficialSourceEvidenceSet) ResultRef() string {
	return "planning://official-source-evidence/" + set.Digest
}

type BindOfficialSourceEvidenceCommand struct {
	Binding Binding
	TaskID  string
	Sources []recipe.SourceV1
}

func (command BindOfficialSourceEvidenceCommand) Validate() error {
	if err := command.Binding.Validate(); err != nil {
		return err
	}
	if _, err := uuid.Parse(command.TaskID); err != nil || len(command.Sources) < 1 || len(command.Sources) > 16 {
		return fmt.Errorf("%w: official-source evidence binding is invalid", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(command.Sources))
	for _, source := range command.Sources {
		parsed, err := url.Parse(source.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
			source.URL != strings.TrimSpace(source.URL) || source.RetrievedAt.IsZero() || source.RetrievedAt != source.RetrievedAt.UTC() ||
			recipe.ValidateDigest(source.ContentDigest) != nil {
			return fmt.Errorf("%w: official-source evidence claim is invalid", ErrInvalid)
		}
		if _, exists := seen[source.URL]; exists {
			return fmt.Errorf("%w: official-source evidence URL is duplicated", ErrInvalid)
		}
		seen[source.URL] = struct{}{}
	}
	return nil
}

func BuildOfficialSourceEvidenceSet(taskID string, values []OfficialSourceEvidence) (OfficialSourceEvidenceSet, error) {
	if _, err := uuid.Parse(taskID); err != nil || len(values) < 1 || len(values) > 16 {
		return OfficialSourceEvidenceSet{}, ErrInvalid
	}
	canonical := append([]OfficialSourceEvidence(nil), values...)
	slices.SortFunc(canonical, func(left, right OfficialSourceEvidence) int {
		if compared := strings.Compare(left.URL, right.URL); compared != 0 {
			return compared
		}
		return strings.Compare(left.ContentDigest, right.ContentDigest)
	})
	seen := make(map[string]struct{}, len(canonical))
	for index, evidence := range canonical {
		canonical[index].RetrievedAt = evidence.RetrievedAt.UTC().Truncate(time.Microsecond)
		evidence = canonical[index]
		if evidence.TaskID != taskID || evidence.ToolCallID == "" || len(evidence.ToolCallID) > 255 ||
			evidence.URL == "" || evidence.RetrievedAt.IsZero() || evidence.RetrievedAt != evidence.RetrievedAt.UTC() ||
			recipe.ValidateDigest(evidence.ContentDigest) != nil {
			return OfficialSourceEvidenceSet{}, ErrInvalid
		}
		if _, exists := seen[evidence.URL]; exists {
			return OfficialSourceEvidenceSet{}, ErrInvalid
		}
		seen[evidence.URL] = struct{}{}
	}
	encoded, err := json.Marshal(struct {
		TaskID   string                   `json:"task_id"`
		Evidence []OfficialSourceEvidence `json:"evidence"`
	}{TaskID: taskID, Evidence: canonical})
	if err != nil {
		return OfficialSourceEvidenceSet{}, ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return OfficialSourceEvidenceSet{Evidence: canonical, Digest: fmt.Sprintf("sha256:%x", digest[:])}, nil
}

type SaveRecipeDraftCommand struct {
	IdempotencyKey   string
	Binding          Binding
	ExpectedRevision int64
	Recipe           recipe.RecipeV1
}

func (command SaveRecipeDraftCommand) Validate() error {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil || command.ExpectedRevision < 0 {
		return fmt.Errorf("%w: recipe mutation metadata is invalid", ErrInvalid)
	}
	if err := command.Binding.Validate(); err != nil {
		return err
	}
	if command.Recipe.RecipeID != command.Binding.RecipeID || command.Recipe.Maturity != recipe.MaturityExperimental {
		return fmt.Errorf("%w: only the bound experimental recipe may be saved", ErrInvalid)
	}
	if err := command.Recipe.Validate(); err != nil {
		return fmt.Errorf("%w: recipe validation failed", ErrInvalid)
	}
	return nil
}

func (command SaveRecipeDraftCommand) Digest() [sha256.Size]byte {
	recipeDigest, _ := command.Recipe.Digest()
	encoded, _ := json.Marshal(struct {
		Binding          Binding `json:"binding"`
		ExpectedRevision int64   `json:"expected_revision"`
		RecipeDigest     string  `json:"recipe_digest"`
	}{command.Binding, command.ExpectedRevision, recipeDigest})
	return sha256.Sum256(encoded)
}

type Repository interface {
	ClaimResearch(context.Context, task.MutationScope, ResearchCommand) (ResearchSession, error)
	AttachResearchTask(context.Context, task.MutationScope, Binding, string) (ResearchSession, error)
	GetResearch(context.Context, task.MutationScope, Binding) (ResearchSession, error)
	BindOfficialSourceEvidence(context.Context, task.MutationScope, BindOfficialSourceEvidenceCommand) (OfficialSourceEvidenceSet, error)
	SaveRecipeDraft(context.Context, task.MutationScope, SaveRecipeDraftCommand) (RecipeDraft, error)
	GetRecipeDraft(context.Context, task.MutationScope, Binding) (RecipeDraft, bool, error)
	SaveResourceCandidates(context.Context, task.MutationScope, SaveCandidatesCommand) (ResourceCandidateSet, error)
}

func canonicalCandidates(candidates []ResourceCandidateV1) []ResourceCandidateV1 {
	result := append([]ResourceCandidateV1(nil), candidates...)
	slices.SortFunc(result, func(left, right ResourceCandidateV1) int {
		return candidateTierRank(left.Tier) - candidateTierRank(right.Tier)
	})
	return result
}

func candidateTierRank(tier CandidateTier) int {
	switch tier {
	case TierEconomy:
		return 0
	case TierRecommended:
		return 1
	case TierPerformance:
		return 2
	default:
		return 100
	}
}

func validPlanningDAG(steps []task.StepDefinition) bool {
	if len(steps) != 3 {
		return false
	}
	wantNames := []string{"research_official_sources", "draft_recipe", "prepare_resource_candidates"}
	for index, step := range steps {
		if step.Name != wantNames[index] || step.ExecutorKind != task.ExecutorControlPlane {
			return false
		}
		if index == 0 && len(step.DependsOnStepIDs) != 0 {
			return false
		}
		if index > 0 && (len(step.DependsOnStepIDs) != 1 || step.DependsOnStepIDs[0] != steps[index-1].StepID) {
			return false
		}
	}
	return true
}

func validOpaqueID(value string, maxRunes int) bool {
	if value != strings.TrimSpace(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > maxRunes || security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOptionalText(value string, maximum int) bool {
	return value == strings.TrimSpace(value) && value != "" && len(value) <= maximum
}
