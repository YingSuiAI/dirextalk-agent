package runtimeapp

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
)

const (
	teamExecutionCompletedEvent    = "team.execution.completed"
	teamCompletionObservationV1    = "dirextalk.central.team-completion-observation/v1"
	teamCompletionRequestNamespace = "central-team-completion-synthesis/v1"
	maximumObservedArtifacts       = 64
	maximumObservedFinalsPerRole   = 4
	maximumObservedListItems       = 3
	maximumObservedSummaryBytes    = 1024
	maximumObservedListItemBytes   = 256
	maximumObservedArtifactBytes   = 128 << 10
	maximumObservedContentBytes    = 256 << 10
	maximumCompletionAttempts      = 4
)

var (
	ErrTeamCompletionInvalid  = errors.New("Team completion observation is invalid")
	ErrTeamCompletionNotFound = errors.New("Team completion observation was not found")
)

type teamCompletionStore interface {
	GetTaskEvent(context.Context, string) (task.Event, error)
	GetTeamExecution(context.Context, string, string) (teamexecution.Fact, error)
	GetTeamExecutionReport(context.Context, string, string) (teamreport.Fact, error)
	ListTeamArtifacts(context.Context, string, string) ([]teamartifact.ArtifactV1, error)
	LoadConversation(context.Context, string, string) (runtimeapi.Conversation, bool, error)
}

// TeamArtifactContentReader returns exact digest-bound bytes for a retained
// artifact after enforcing its owner, Connection, object, size, and digest.
type TeamArtifactContentReader interface {
	ReadTeamArtifactContent(
		context.Context,
		teamartifact.ArtifactV1,
		int64,
	) ([]byte, error)
}

type TeamCompletionResult struct {
	SourceEventID  string
	ConversationID string
	RequestID      string
	Chat           runtimeapi.ChatResult
}

type teamCompletionEventSummary struct {
	SchemaVersion   int                  `json:"schema_version"`
	ExecutionID     string               `json:"execution_id"`
	OwnerID         string               `json:"owner_id"`
	TaskID          string               `json:"task_id"`
	PlanID          string               `json:"plan_id"`
	PlanRevision    uint64               `json:"plan_revision"`
	PlanDigest      string               `json:"plan_digest"`
	Status          teamexecution.Status `json:"status"`
	RecordRevision  uint64               `json:"record_revision"`
	ConversationID  string               `json:"conversation_id"`
	ReportDigest    string               `json:"report_digest"`
	ReportGenerated time.Time            `json:"report_generated_at"`
	CleanupVerified bool                 `json:"cleanup_verified"`
}

type completionObservation struct {
	SchemaVersion             string               `json:"schema_version"`
	SourceEventID             string               `json:"source_event_id"`
	ExecutionID               string               `json:"execution_id"`
	TaskID                    string               `json:"task_id"`
	PlanID                    string               `json:"plan_id"`
	PlanRevision              uint64               `json:"plan_revision"`
	Status                    teamexecution.Status `json:"status"`
	CleanupVerified           bool                 `json:"cleanup_verified"`
	ReportDigest              string               `json:"report_digest"`
	ReportGeneratedAt         string               `json:"report_generated_at"`
	Roles                     []observedRole       `json:"roles"`
	ArtifactCount             int                  `json:"artifact_count"`
	ArtifactManifestTruncated bool                 `json:"artifact_manifest_truncated"`
	RetainedArtifacts         []observedArtifact   `json:"retained_artifacts"`
}

type observedRole struct {
	RoleID          string             `json:"role_id"`
	Title           string             `json:"title"`
	Outcome         task.OutcomeStatus `json:"outcome"`
	FinalCount      int                `json:"final_count"`
	FinalsTruncated bool               `json:"finals_truncated"`
	Finals          []observedFinal    `json:"finals"`
}

type observedFinal struct {
	ActionID     string   `json:"action_id"`
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Deliverables []string `json:"deliverables"`
	Tests        []string `json:"tests"`
	Risks        []string `json:"risks"`
}

type observedArtifact struct {
	ArtifactID       string                         `json:"artifact_id"`
	RoleID           string                         `json:"role_id"`
	ActionID         string                         `json:"action_id"`
	Name             string                         `json:"name"`
	Kind             teamartifact.Kind              `json:"kind"`
	MediaType        string                         `json:"media_type"`
	SizeBytes        int64                          `json:"size_bytes"`
	SHA256           string                         `json:"sha256"`
	Verification     teamartifact.VerificationState `json:"verification"`
	CreatedAt        string                         `json:"created_at"`
	RetentionExpires string                         `json:"retention_expires_at"`
	ContentState     string                         `json:"content_state"`
	Content          string                         `json:"content,omitempty"`
}

type observedArtifactContent struct {
	state   string
	content string
}

// SynthesizeTeamCompletion turns a server-owned completion event into a real
// Central reply. Worker narrative is model evidence only; the immutable event,
// report, artifact facts, and conversation are reloaded at this boundary.
func (service *Service) SynthesizeTeamCompletion(
	ctx context.Context,
	scope runtimeapi.MutationScope,
	ownerID string,
	sourceEventID string,
) (TeamCompletionResult, error) {
	if service == nil || service.store == nil || service.executor == nil ||
		scope.Validate() != nil {
		return TeamCompletionResult{}, ErrInvalidDependencies
	}
	ownerID = strings.TrimSpace(ownerID)
	sourceEventID = strings.TrimSpace(sourceEventID)
	eventUUID, err := uuid.Parse(sourceEventID)
	if ownerID == "" || len(ownerID) > 255 || err != nil ||
		eventUUID == uuid.Nil || eventUUID.String() != sourceEventID {
		return TeamCompletionResult{}, ErrTeamCompletionInvalid
	}
	store, ok := service.store.(teamCompletionStore)
	if !ok {
		return TeamCompletionResult{}, ErrInvalidDependencies
	}
	summary, observation, err := loadTeamCompletionObservation(
		ctx,
		store,
		service.teamArtifactContentReader,
		ownerID,
		sourceEventID,
	)
	if err != nil {
		return TeamCompletionResult{}, err
	}
	requestID := uuid.NewSHA1(
		eventUUID,
		[]byte(teamCompletionRequestNamespace),
	).String()
	for attempt := 0; attempt < maximumCompletionAttempts; attempt++ {
		conversation, found, loadErr := store.LoadConversation(
			ctx,
			ownerID,
			summary.ConversationID,
		)
		if loadErr != nil {
			return TeamCompletionResult{}, stableDurabilityError(loadErr)
		}
		if !found || conversation.OwnerID != ownerID ||
			conversation.ConversationID != summary.ConversationID ||
			conversation.Revision < 1 {
			return TeamCompletionResult{}, ErrTeamCompletionInvalid
		}
		expectedRevision := conversation.Revision
		request, requestErr := runtimeapi.NewTrustedTeamCompletionRequest(
			requestID,
			ownerID,
			summary.ConversationID,
			expectedRevision,
			string(observation),
		)
		if requestErr != nil {
			return TeamCompletionResult{}, ErrTeamCompletionInvalid
		}
		result, chatErr := service.Chat(ctx, scope, request)
		if chatErr == nil {
			return TeamCompletionResult{
				SourceEventID:  sourceEventID,
				ConversationID: summary.ConversationID,
				RequestID:      requestID,
				Chat:           result,
			}, nil
		}
		if !errors.Is(chatErr, runtimeapi.ErrRuntimeRevisionConflict) {
			return TeamCompletionResult{}, chatErr
		}
	}
	return TeamCompletionResult{}, runtimeapi.ErrRuntimeRevisionConflict
}

func (service *Service) ConversationState(
	ctx context.Context,
	ownerID string,
	conversationID string,
) (runtimeapi.Conversation, bool, error) {
	if service == nil || service.store == nil {
		return runtimeapi.Conversation{}, false, ErrInvalidDependencies
	}
	reader, ok := service.store.(interface {
		LoadConversation(context.Context, string, string) (runtimeapi.Conversation, bool, error)
	})
	if !ok {
		return runtimeapi.Conversation{}, false, ErrInvalidDependencies
	}
	ownerID = strings.TrimSpace(ownerID)
	conversationID = strings.TrimSpace(conversationID)
	if ownerID == "" || len(ownerID) > 255 || conversationID == "" ||
		len(conversationID) > 256 {
		return runtimeapi.Conversation{}, false, runtimeapi.ErrInvalidRequest
	}
	conversation, found, err := reader.LoadConversation(
		ctx,
		ownerID,
		conversationID,
	)
	if err != nil {
		return runtimeapi.Conversation{}, false, stableDurabilityError(err)
	}
	if found && (conversation.OwnerID != ownerID ||
		conversation.ConversationID != conversationID ||
		conversation.Revision < 0) {
		return runtimeapi.Conversation{}, false, runtimeapi.ErrInvalidConversation
	}
	return conversation, found, nil
}

func loadTeamCompletionObservation(
	ctx context.Context,
	store teamCompletionStore,
	contentReader TeamArtifactContentReader,
	ownerID string,
	sourceEventID string,
) (teamCompletionEventSummary, []byte, error) {
	event, err := store.GetTaskEvent(ctx, sourceEventID)
	if errors.Is(err, task.ErrNotFound) {
		return teamCompletionEventSummary{}, nil, ErrTeamCompletionNotFound
	}
	if err != nil {
		return teamCompletionEventSummary{}, nil, stableDurabilityError(err)
	}
	var summary teamCompletionEventSummary
	if event.EventID != sourceEventID ||
		event.EventType != teamExecutionCompletedEvent ||
		event.AggregateType != "team_execution" ||
		json.Unmarshal(event.SummaryJSON, &summary) != nil ||
		!validTeamCompletionEvent(event, summary, ownerID) {
		return teamCompletionEventSummary{}, nil, ErrTeamCompletionInvalid
	}
	execution, err := store.GetTeamExecution(ctx, ownerID, summary.ExecutionID)
	if err != nil {
		return teamCompletionEventSummary{}, nil, stableDurabilityError(err)
	}
	report, err := store.GetTeamExecutionReport(ctx, ownerID, summary.ExecutionID)
	if err != nil {
		return teamCompletionEventSummary{}, nil, stableDurabilityError(err)
	}
	artifacts, err := store.ListTeamArtifacts(ctx, ownerID, summary.ExecutionID)
	if err != nil {
		return teamCompletionEventSummary{}, nil, stableDurabilityError(err)
	}
	if !completionFactsMatch(summary, execution, report, artifacts) {
		return teamCompletionEventSummary{}, nil, ErrTeamCompletionInvalid
	}
	contents, err := readObservedArtifactContents(
		ctx,
		contentReader,
		artifacts,
	)
	if err != nil {
		return teamCompletionEventSummary{}, nil, err
	}
	observation := projectCompletionObservation(
		sourceEventID,
		summary,
		report,
		artifacts,
		contents,
	)
	encoded, err := json.Marshal(observation)
	if err != nil {
		return teamCompletionEventSummary{}, nil, ErrTeamCompletionInvalid
	}
	return summary, encoded, nil
}

func validTeamCompletionEvent(
	event task.Event,
	summary teamCompletionEventSummary,
	ownerID string,
) bool {
	return event.Seq > 0 &&
		event.Revision > 0 &&
		event.AggregateID == summary.ExecutionID &&
		summary.SchemaVersion == 1 &&
		summary.OwnerID == ownerID &&
		summary.Status == teamexecution.StatusCompleted &&
		summary.RecordRevision == uint64(event.Revision) &&
		summary.ConversationID != "" &&
		len(summary.ConversationID) <= 256 &&
		!summary.ReportGenerated.IsZero() &&
		summary.ReportGenerated.Equal(
			summary.ReportGenerated.UTC().Truncate(time.Microsecond),
		) &&
		summary.CleanupVerified
}

func completionFactsMatch(
	summary teamCompletionEventSummary,
	execution teamexecution.Fact,
	report teamreport.Fact,
	artifacts []teamartifact.ArtifactV1,
) bool {
	if execution.Status != teamexecution.StatusCompleted ||
		execution.RecordRevision != summary.RecordRevision ||
		execution.Execution.ExecutionID != summary.ExecutionID ||
		execution.Execution.OwnerID != summary.OwnerID ||
		execution.Execution.TaskID != summary.TaskID ||
		execution.Execution.PlanID != summary.PlanID ||
		execution.Execution.PlanRevision != summary.PlanRevision ||
		execution.Execution.PlanDigest != summary.PlanDigest ||
		report.Validate() != nil ||
		report.ReportDigest != summary.ReportDigest ||
		!report.GeneratedAt.Equal(summary.ReportGenerated) ||
		report.Report.ExecutionID != summary.ExecutionID ||
		report.Report.OwnerID != summary.OwnerID ||
		report.Report.TaskID != summary.TaskID ||
		report.Report.PlanID != summary.PlanID ||
		report.Report.PlanRevision != summary.PlanRevision ||
		report.Report.PlanDigest != summary.PlanDigest ||
		len(artifacts) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(artifacts))
	verifiedFinals := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Validate() != nil ||
			artifact.OwnerID != summary.OwnerID ||
			artifact.ExecutionID != summary.ExecutionID ||
			artifact.TaskID != summary.TaskID ||
			artifact.PlanID != summary.PlanID ||
			artifact.PlanRevision != summary.PlanRevision {
			return false
		}
		if _, duplicate := seen[artifact.ArtifactID]; duplicate {
			return false
		}
		seen[artifact.ArtifactID] = struct{}{}
		verifiedFinals[strings.Join([]string{
			artifact.RoleID,
			artifact.ActionID,
			artifact.SHA256,
		}, "\x00")] = struct{}{}
	}
	for _, role := range report.Report.Roles {
		for _, final := range role.Finals {
			key := strings.Join([]string{
				role.RoleID,
				final.ActionID,
				final.ArtifactSHA256,
			}, "\x00")
			if _, found := verifiedFinals[key]; !found {
				return false
			}
		}
	}
	return true
}

func projectCompletionObservation(
	sourceEventID string,
	summary teamCompletionEventSummary,
	report teamreport.Fact,
	artifacts []teamartifact.ArtifactV1,
	contents map[string]observedArtifactContent,
) completionObservation {
	roles := make([]observedRole, 0, len(report.Report.Roles))
	for _, role := range report.Report.Roles {
		finalLimit := len(role.Finals)
		if finalLimit > maximumObservedFinalsPerRole {
			finalLimit = maximumObservedFinalsPerRole
		}
		projected := observedRole{
			RoleID:          role.RoleID,
			Title:           boundedText(role.Title, maximumObservedSummaryBytes),
			Outcome:         role.Outcome,
			FinalCount:      len(role.Finals),
			FinalsTruncated: finalLimit != len(role.Finals),
			Finals:          make([]observedFinal, 0, finalLimit),
		}
		for _, final := range role.Finals[:finalLimit] {
			projected.Finals = append(projected.Finals, observedFinal{
				ActionID:     final.ActionID,
				Status:       final.Status,
				Summary:      boundedText(final.Summary, maximumObservedSummaryBytes),
				Deliverables: boundedList(final.Deliverables),
				Tests:        boundedList(final.Tests),
				Risks:        boundedList(final.Risks),
			})
		}
		roles = append(roles, projected)
	}
	sort.Slice(artifacts, func(left, right int) bool {
		leftPriority := artifactPriority(artifacts[left].Kind)
		rightPriority := artifactPriority(artifacts[right].Kind)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if artifacts[left].Name != artifacts[right].Name {
			return artifacts[left].Name < artifacts[right].Name
		}
		return artifacts[left].ArtifactID < artifacts[right].ArtifactID
	})
	artifactLimit := len(artifacts)
	if artifactLimit > maximumObservedArtifacts {
		artifactLimit = maximumObservedArtifacts
	}
	manifest := make([]observedArtifact, 0, artifactLimit)
	for _, artifact := range artifacts[:artifactLimit] {
		content := contents[artifact.ArtifactID]
		manifest = append(manifest, observedArtifact{
			ArtifactID:       artifact.ArtifactID,
			RoleID:           artifact.RoleID,
			ActionID:         artifact.ActionID,
			Name:             artifact.Name,
			Kind:             artifact.Kind,
			MediaType:        artifact.MediaType,
			SizeBytes:        artifact.SizeBytes,
			SHA256:           artifact.SHA256,
			Verification:     artifact.Verification,
			CreatedAt:        artifact.CreatedAt.Format(time.RFC3339Nano),
			RetentionExpires: artifact.RetentionExpires.Format(time.RFC3339Nano),
			ContentState:     content.state,
			Content:          content.content,
		})
	}
	return completionObservation{
		SchemaVersion:             teamCompletionObservationV1,
		SourceEventID:             sourceEventID,
		ExecutionID:               summary.ExecutionID,
		TaskID:                    summary.TaskID,
		PlanID:                    summary.PlanID,
		PlanRevision:              summary.PlanRevision,
		Status:                    summary.Status,
		CleanupVerified:           summary.CleanupVerified,
		ReportDigest:              summary.ReportDigest,
		ReportGeneratedAt:         summary.ReportGenerated.Format(time.RFC3339Nano),
		Roles:                     roles,
		ArtifactCount:             len(artifacts),
		ArtifactManifestTruncated: artifactLimit != len(artifacts),
		RetainedArtifacts:         manifest,
	}
}

func readObservedArtifactContents(
	ctx context.Context,
	reader TeamArtifactContentReader,
	artifacts []teamartifact.ArtifactV1,
) (map[string]observedArtifactContent, error) {
	result := make(map[string]observedArtifactContent, len(artifacts))
	remaining := int64(maximumObservedContentBytes)
	for _, artifact := range artifacts {
		if reader == nil {
			result[artifact.ArtifactID] = observedArtifactContent{
				state: "not_loaded",
			}
			continue
		}
		if artifact.SizeBytes > maximumObservedArtifactBytes {
			result[artifact.ArtifactID] = observedArtifactContent{
				state: "omitted_size",
			}
			continue
		}
		if artifact.SizeBytes > remaining {
			result[artifact.ArtifactID] = observedArtifactContent{
				state: "omitted_budget",
			}
			continue
		}
		content, err := reader.ReadTeamArtifactContent(
			ctx,
			artifact,
			artifact.SizeBytes,
		)
		if err != nil {
			clear(content)
			return nil, err
		}
		if int64(len(content)) != artifact.SizeBytes ||
			!utf8.Valid(content) ||
			strings.ContainsRune(string(content), '\x00') {
			clear(content)
			return nil, ErrTeamCompletionInvalid
		}
		text := string(content)
		clear(content)
		remaining -= artifact.SizeBytes
		if security.ContainsLikelySecret(text) {
			result[artifact.ArtifactID] = observedArtifactContent{
				state: "redacted",
			}
			continue
		}
		result[artifact.ArtifactID] = observedArtifactContent{
			state:   "included",
			content: text,
		}
	}
	return result, nil
}

func boundedList(values []string) []string {
	limit := len(values)
	if limit > maximumObservedListItems {
		limit = maximumObservedListItems
	}
	result := make([]string, 0, limit)
	for _, value := range values[:limit] {
		result = append(
			result,
			boundedText(value, maximumObservedListItemBytes),
		)
	}
	return result
}

func boundedText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func artifactPriority(kind teamartifact.Kind) int {
	switch kind {
	case teamartifact.KindResult:
		return 0
	case teamartifact.KindPatch:
		return 1
	default:
		return 2
	}
}
