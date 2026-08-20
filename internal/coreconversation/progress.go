package coreconversation

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"
)

const ProgressObservationVersion = "dirextalk.progress-observation/v1"

// ProgressObservation is a trusted runtime projection of one tool result. It
// deliberately excludes model-authored arguments and transport identities so
// semantically identical wrappers cannot disguise a lack of external progress.
// Resource and side-effect identities come only from validated runtime
// References attached to the ToolResult.
type ProgressObservation struct {
	Version                  string                 `json:"version"`
	NormalizedAction         string                 `json:"normalized_action"`
	ResultSummary            string                 `json:"result_summary,omitempty"`
	ArtifactWorkspaceChanges []Reference            `json:"artifact_workspace_changes,omitempty"`
	ExternalReceipts         []Reference            `json:"external_receipts,omitempty"`
	ExternalResourceState    []Reference            `json:"external_resource_state,omitempty"`
	Outcome                  ToolObservationOutcome `json:"outcome,omitempty"`
	MutationState            ToolMutationState      `json:"mutation_state,omitempty"`
	StateChanged             bool                   `json:"state_changed,omitempty"`
	CursorDigest             string                 `json:"cursor_digest,omitempty"`
	ErrorCategory            string                 `json:"error_category,omitempty"`
	CompletedSteps           []string               `json:"completed_steps,omitempty"`
	EffectiveDigest          string                 `json:"effective_digest"`
}

// ProgressObservationForToolResult returns structured progress only when the
// runtime supplied validated references. Results without that authority stay
// on the existing action/result-pair loop protection path.
func ProgressObservationForToolResult(result ToolResult) (ProgressObservation, bool, error) {
	if result.Validate() != nil {
		return ProgressObservation{}, false, ErrInvalid
	}
	if len(result.References) == 0 && result.Cursor == "" {
		return ProgressObservation{}, false, nil
	}
	observation := ProgressObservation{
		Version:          ProgressObservationVersion,
		NormalizedAction: strings.TrimSpace(result.ToolName),
		Outcome:          result.Outcome,
		MutationState:    result.MutationState,
		StateChanged:     result.StateChanged,
	}
	if result.Cursor != "" {
		observation.CursorDigest = digest(result.Cursor)
	}
	if observation.NormalizedAction == "" {
		return ProgressObservation{}, false, ErrInvalid
	}
	summary := strings.TrimSpace(result.Summary)
	if summary == "" {
		summary = strings.TrimSpace(result.Content)
	}
	observation.ResultSummary = boundConversationSummary(normalizeToolLoopPayload(summary))
	if result.IsError {
		observation.ErrorCategory = "tool_error"
	} else if observation.ResultSummary != "" {
		observation.CompletedSteps = []string{observation.ResultSummary}
	}
	for _, reference := range result.References {
		switch reference.Kind {
		case "execution_artifact":
			observation.ArtifactWorkspaceChanges = append(observation.ArtifactWorkspaceChanges, reference)
		case "room", "channel_post", "web_source", "knowledge_chunk":
			observation.ExternalResourceState = append(observation.ExternalResourceState, reference)
		default:
			observation.ExternalReceipts = append(observation.ExternalReceipts, reference)
		}
	}
	sortReferences := func(values []Reference) {
		sort.Slice(values, func(i, j int) bool { return referenceKey(values[i]) < referenceKey(values[j]) })
	}
	sortReferences(observation.ArtifactWorkspaceChanges)
	sortReferences(observation.ExternalReceipts)
	sortReferences(observation.ExternalResourceState)
	observation.EffectiveDigest = observation.effectiveDigest()
	if observation.Validate() != nil {
		return ProgressObservation{}, false, ErrInvalid
	}
	return observation, true, nil
}

func (o ProgressObservation) Validate() error {
	if o.Version != ProgressObservationVersion || strings.TrimSpace(o.NormalizedAction) != o.NormalizedAction ||
		o.NormalizedAction == "" || len(o.NormalizedAction) > MaxToolNameBytes || !utf8.ValidString(o.NormalizedAction) ||
		len(o.ResultSummary) > MaxSummaryBytes || !utf8.ValidString(o.ResultSummary) ||
		(o.ErrorCategory != "" && o.ErrorCategory != "tool_error") ||
		(o.Outcome != "" && !validProgressOutcome(o.Outcome)) ||
		(o.MutationState != "" && !validProgressMutationState(o.MutationState)) ||
		(o.CursorDigest != "" && !validReferenceDigest(o.CursorDigest)) ||
		len(o.CompletedSteps) > MaxRelatedTaskIDs || validateReferences(o.ArtifactWorkspaceChanges) != nil ||
		validateReferences(o.ExternalReceipts) != nil || validateReferences(o.ExternalResourceState) != nil {
		return ErrInvalid
	}
	for _, step := range o.CompletedSteps {
		if strings.TrimSpace(step) != step || step == "" || len(step) > MaxSummaryBytes || !utf8.ValidString(step) {
			return ErrInvalid
		}
	}
	if o.EffectiveDigest == "" || o.EffectiveDigest != o.effectiveDigest() {
		return ErrInvalid
	}
	return nil
}

func validProgressOutcome(outcome ToolObservationOutcome) bool {
	switch outcome {
	case ToolOutcomeSuccess, ToolOutcomePartial, ToolOutcomeNotFound, ToolOutcomeInvalid, ToolOutcomeAuth,
		ToolOutcomeUserInput, ToolOutcomeRetryable, ToolOutcomeFatal, ToolOutcomeUnknownMutation:
		return true
	default:
		return false
	}
}

func validProgressMutationState(state ToolMutationState) bool {
	switch state {
	case ToolMutationNone, ToolMutationUnchanged, ToolMutationChanged, ToolMutationUnknown:
		return true
	default:
		return false
	}
}

func (o ProgressObservation) effectiveDigest() string {
	o.EffectiveDigest = ""
	// Summary and completed steps are model-facing presentation. Canonical
	// progress comes from producer-owned evidence, cursor, mutation, outcome,
	// and resource state identities below.
	o.ResultSummary = ""
	o.CompletedSteps = nil
	o.ArtifactWorkspaceChanges = cloneReferences(o.ArtifactWorkspaceChanges)
	o.ExternalReceipts = cloneReferences(o.ExternalReceipts)
	o.ExternalResourceState = cloneReferences(o.ExternalResourceState)
	for _, references := range [][]Reference{o.ArtifactWorkspaceChanges, o.ExternalReceipts, o.ExternalResourceState} {
		for index := range references {
			// Title and Preview are presentation-only and can change without any
			// external identity, revision, digest, status, or state transition.
			references[index].Title = ""
			references[index].Preview = ""
		}
		sort.Slice(references, func(i, j int) bool { return referenceKey(references[i]) < referenceKey(references[j]) })
	}
	raw, _ := json.Marshal(o)
	return digest(string(raw))
}
