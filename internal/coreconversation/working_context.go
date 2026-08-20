package coreconversation

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const (
	WorkingContextVersion                           = "dirextalk.working-context/v1"
	WorkingContextProjectionAuthoritativeTranscript = "authoritative_transcript"
	MaxWorkingContextBytes                          = 4 << 20
)

// WorkingContext is the versioned, schema-constrained model memory. Protected
// fields are populated only from exact user transcript content or validated
// runtime references. Compressor-owned fields may summarize decisions and
// steps, but cannot replace those protected identities.
type WorkingContext struct {
	Version              string                    `json:"version"`
	OriginalGoal         string                    `json:"original_goal,omitempty"`
	ExactUserConstraints []string                  `json:"exact_user_constraints,omitempty"`
	Decisions            []string                  `json:"decisions,omitempty"`
	CompletedSteps       []string                  `json:"completed_steps,omitempty"`
	PendingSteps         []string                  `json:"pending_steps,omitempty"`
	Artifacts            []Reference               `json:"artifacts,omitempty"`
	ExternalResources    []Reference               `json:"external_resources,omitempty"`
	SideEffectIdentities []Reference               `json:"side_effect_identities,omitempty"`
	ToolReceipts         []Reference               `json:"tool_receipts,omitempty"`
	LastFailure          *WorkingContextFailure    `json:"last_failure,omitempty"`
	Projection           *WorkingContextProjection `json:"projection,omitempty"`
}

// WorkingContextProjection records the authoritative transcript prefix from
// which protected WorkingContext state was derived. It is protected metadata:
// compressor proposals cannot rewrite or erase its provenance.
type WorkingContextProjection struct {
	Source                    string                        `json:"source"`
	Scope                     WorkingContextProjectionScope `json:"scope"`
	SupersedesProtectedDigest string                        `json:"supersedes_protected_digest"`
}

type WorkingContextProjectionScope struct {
	FirstMessageID   string `json:"first_message_id"`
	ThroughMessageID string `json:"through_message_id"`
	MessageCount     uint64 `json:"message_count"`
}

type WorkingContextFailure struct {
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

func NewWorkingContext() WorkingContext {
	return WorkingContext{Version: WorkingContextVersion}
}

func (w WorkingContext) Validate() error {
	if w.Version != WorkingContextVersion || len(w.OriginalGoal) > MaxContentBytes || !utf8.ValidString(w.OriginalGoal) ||
		validateExactContextStrings(w.ExactUserConstraints) != nil || validateSummaryContextStrings(w.Decisions) != nil ||
		validateSummaryContextStrings(w.CompletedSteps) != nil || validateSummaryContextStrings(w.PendingSteps) != nil ||
		validateWorkingContextReferences(w.Artifacts) != nil || validateWorkingContextReferences(w.ExternalResources) != nil ||
		validateWorkingContextReferences(w.SideEffectIdentities) != nil || validateWorkingContextReferences(w.ToolReceipts) != nil {
		return ErrInvalid
	}
	if w.LastFailure != nil && (strings.TrimSpace(w.LastFailure.Code) != w.LastFailure.Code || w.LastFailure.Code == "" ||
		len(w.LastFailure.Code) > 128 || !utf8.ValidString(w.LastFailure.Code) ||
		strings.TrimSpace(w.LastFailure.Summary) != w.LastFailure.Summary || w.LastFailure.Summary == "" ||
		len(w.LastFailure.Summary) > MaxSummaryBytes || !utf8.ValidString(w.LastFailure.Summary)) {
		return ErrInvalid
	}
	if w.Projection != nil && (w.Projection.Source != WorkingContextProjectionAuthoritativeTranscript ||
		!validUUID(w.Projection.Scope.FirstMessageID) || !validUUID(w.Projection.Scope.ThroughMessageID) ||
		w.Projection.Scope.MessageCount == 0 || w.Projection.Scope.MessageCount > MaxMessages ||
		(w.Projection.Scope.MessageCount > 1 && w.Projection.Scope.FirstMessageID == w.Projection.Scope.ThroughMessageID) ||
		!validReferenceDigest(w.Projection.SupersedesProtectedDigest)) {
		return ErrInvalid
	}
	raw, err := json.Marshal(w)
	if err != nil || len(raw) > MaxWorkingContextBytes {
		return ErrInvalid
	}
	return nil
}

func validateExactContextStrings(values []string) error {
	if len(values) > MaxMessages {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > MaxContentBytes || !utf8.ValidString(value) {
			return ErrInvalid
		}
		if _, duplicate := seen[value]; duplicate {
			return ErrInvalid
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateSummaryContextStrings(values []string) error {
	if len(values) > MaxMessages {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != value || value == "" || len(value) > MaxSummaryBytes || !utf8.ValidString(value) {
			return ErrInvalid
		}
		if _, duplicate := seen[value]; duplicate {
			return ErrInvalid
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateWorkingContextReferences(values []Reference) error {
	if len(values) > MaxMessages {
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

func (w WorkingContext) ProtectedDigest() string {
	protected := struct {
		Version              string                    `json:"version"`
		OriginalGoal         string                    `json:"original_goal,omitempty"`
		ExactUserConstraints []string                  `json:"exact_user_constraints,omitempty"`
		Artifacts            []Reference               `json:"artifacts,omitempty"`
		ExternalResources    []Reference               `json:"external_resources,omitempty"`
		SideEffectIdentities []Reference               `json:"side_effect_identities,omitempty"`
		ToolReceipts         []Reference               `json:"tool_receipts,omitempty"`
		Projection           *WorkingContextProjection `json:"projection,omitempty"`
	}{
		Version: w.Version, OriginalGoal: w.OriginalGoal, ExactUserConstraints: w.ExactUserConstraints,
		Artifacts: w.Artifacts, ExternalResources: w.ExternalResources,
		SideEffectIdentities: w.SideEffectIdentities, ToolReceipts: w.ToolReceipts,
		Projection: cloneWorkingContextProjection(w.Projection),
	}
	raw, _ := json.Marshal(protected)
	return digest(string(raw))
}

// ApplyWorkingContextCompression accepts only compressor-owned fields from a
// proposal. Any attempted protected-field rewrite is rejected before merge.
func ApplyWorkingContextCompression(current, proposal WorkingContext) (WorkingContext, error) {
	if current.Validate() != nil || proposal.Validate() != nil || current.ProtectedDigest() != proposal.ProtectedDigest() {
		return WorkingContext{}, ErrConflict
	}
	out := current.Snapshot()
	out.Decisions = append([]string(nil), proposal.Decisions...)
	out.CompletedSteps = append([]string(nil), proposal.CompletedSteps...)
	out.PendingSteps = append([]string(nil), proposal.PendingSteps...)
	if proposal.LastFailure != nil {
		failure := *proposal.LastFailure
		out.LastFailure = &failure
	} else {
		out.LastFailure = nil
	}
	if out.Validate() != nil {
		return WorkingContext{}, ErrInvalid
	}
	return out, nil
}

// AdvanceWorkingContextFromTranscript is the trusted projection path. It may
// extend protected fields because its inputs are durable user messages and
// runtime-validated ToolResult references, never compressor output.
func AdvanceWorkingContextFromTranscript(current WorkingContext, messages []Message) (WorkingContext, error) {
	if current.Version == "" {
		current = NewWorkingContext()
	}
	if current.Validate() != nil {
		return WorkingContext{}, ErrInvalid
	}
	out := current.Snapshot()
	for _, message := range messages {
		switch message.Role {
		case RoleUser:
			if out.OriginalGoal == "" {
				out.OriginalGoal = message.Content
			} else if message.Content != "" && message.Content != out.OriginalGoal {
				out.ExactUserConstraints = appendUniqueExact(out.ExactUserConstraints, message.Content)
			}
		case RoleAssistant:
			if decision, _ := SummarizeText(message.Content); strings.TrimSpace(decision) != "" {
				out.Decisions = appendUniqueSummary(out.Decisions, decision)
			}
		case RoleTool:
			for _, result := range message.ToolResults {
				summary := strings.TrimSpace(result.Summary)
				if summary == "" {
					summary = strings.TrimSpace(result.Content)
				}
				summary, _ = SummarizeText(summary)
				if result.IsError {
					if summary != "" {
						out.LastFailure = &WorkingContextFailure{Code: "tool_error", Summary: summary}
					}
				} else if summary != "" {
					out.CompletedSteps = appendUniqueSummary(out.CompletedSteps, summary)
				}
				for _, reference := range result.References {
					out.ToolReceipts = appendUniqueReference(out.ToolReceipts, reference)
					switch reference.Kind {
					case "execution_artifact":
						out.Artifacts = appendUniqueReference(out.Artifacts, reference)
						out.SideEffectIdentities = appendUniqueReference(out.SideEffectIdentities, reference)
					case "room", "channel_post":
						out.ExternalResources = appendUniqueReference(out.ExternalResources, reference)
					default:
						out.ExternalResources = appendUniqueReference(out.ExternalResources, reference)
						out.SideEffectIdentities = appendUniqueReference(out.SideEffectIdentities, reference)
					}
				}
			}
		}
	}
	if out.Validate() != nil {
		return WorkingContext{}, ErrInvalid
	}
	return out, nil
}

func appendUniqueExact(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueSummary(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueReference(values []Reference, value Reference) []Reference {
	key := referenceKey(value)
	for _, existing := range values {
		if referenceKey(existing) == key {
			return values
		}
	}
	return append(values, value)
}

func (w WorkingContext) Snapshot() WorkingContext {
	out := w
	out.ExactUserConstraints = append([]string(nil), w.ExactUserConstraints...)
	out.Decisions = append([]string(nil), w.Decisions...)
	out.CompletedSteps = append([]string(nil), w.CompletedSteps...)
	out.PendingSteps = append([]string(nil), w.PendingSteps...)
	out.Artifacts = cloneReferences(w.Artifacts)
	out.ExternalResources = cloneReferences(w.ExternalResources)
	out.SideEffectIdentities = cloneReferences(w.SideEffectIdentities)
	out.ToolReceipts = cloneReferences(w.ToolReceipts)
	if w.LastFailure != nil {
		failure := *w.LastFailure
		out.LastFailure = &failure
	}
	out.Projection = cloneWorkingContextProjection(w.Projection)
	return out
}

func cloneWorkingContextProjection(value *WorkingContextProjection) *WorkingContextProjection {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func (w WorkingContext) ModelText() string {
	if w.Validate() != nil || w.Empty() {
		return ""
	}
	raw, _ := json.Marshal(w)
	return string(raw)
}

func (w WorkingContext) Empty() bool {
	return w.OriginalGoal == "" && len(w.ExactUserConstraints) == 0 && len(w.Decisions) == 0 &&
		len(w.CompletedSteps) == 0 && len(w.PendingSteps) == 0 && len(w.Artifacts) == 0 &&
		len(w.ExternalResources) == 0 && len(w.SideEffectIdentities) == 0 && len(w.ToolReceipts) == 0 && w.LastFailure == nil && w.Projection == nil
}

func (w WorkingContext) SummaryText() string {
	parts := append([]string(nil), w.Decisions...)
	parts = append(parts, w.CompletedSteps...)
	if w.LastFailure != nil {
		parts = append(parts, w.LastFailure.Code+": "+w.LastFailure.Summary)
	}
	return boundConversationSummary(strings.Join(parts, "\n"))
}
