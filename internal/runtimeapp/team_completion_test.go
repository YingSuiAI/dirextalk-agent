package runtimeapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestSynthesizeTeamCompletionUsesVerifiedFactsAndDurableConversation(t *testing.T) {
	t.Parallel()
	fixture := newTeamCompletionFixture(t)
	store := &teamCompletionStoreFake{
		runtimeStoreFake: newRuntimeStoreFake(),
		event:            fixture.event,
		execution:        fixture.execution,
		report:           fixture.report,
		artifacts:        fixture.artifacts,
		conversation: runtimeapi.Conversation{
			OwnerID:        fixture.ownerID,
			ConversationID: fixture.conversationID,
			Revision:       3,
			Messages: []modelapi.Message{
				{Role: modelapi.RoleUser, Content: "Prepare the analysis."},
				{Role: modelapi.RoleAssistant, Content: "I will return when the Team finishes."},
			},
		},
		conversationFound: true,
	}
	contentReader := &teamArtifactContentReaderFake{
		contents: map[string][]byte{
			fixture.artifacts[0].ArtifactID: []byte(strings.Repeat("x", 128)),
		},
	}
	executor := &executorFake{chat: func(
		_ context.Context,
		request runtimeapi.ChatRequest,
	) (runtimeapi.ChatResult, error) {
		if !request.TrustedObservation ||
			request.OwnerID != fixture.ownerID ||
			request.ConversationID != fixture.conversationID ||
			request.ExpectedConversationRevision != 3 ||
			len(request.Messages) != 3 {
			t.Fatalf("trusted completion request = %#v", request)
		}
		var observation map[string]any
		if json.Unmarshal(
			[]byte(request.Messages[1].Content),
			&observation,
		) != nil ||
			observation["source_event_id"] != fixture.event.EventID ||
			observation["artifact_count"] != float64(1) ||
			strings.Contains(request.Messages[1].Content, "s3://") ||
			strings.Contains(request.Messages[1].Content, fixture.ownerID) ||
			!strings.Contains(
				request.Messages[1].Content,
				`"content_state":"included"`,
			) ||
			!strings.Contains(
				request.Messages[1].Content,
				`"content":"`+strings.Repeat("x", 128)+`"`,
			) {
			t.Fatalf("completion observation = %s", request.Messages[1].Content)
		}
		message := modelapi.Message{
			Role:    modelapi.RoleAssistant,
			Content: "The Team finished the analysis. final.json is available.",
		}
		pending := runtimeapi.Conversation{
			OwnerID:        fixture.ownerID,
			ConversationID: fixture.conversationID,
			Revision:       3,
			Messages: append(
				append([]modelapi.Message(nil), request.Messages[:2]...),
				message,
			),
		}
		return runtimeapi.ChatResult{
			Message:                      message,
			PendingConversation:          &pending,
			ExpectedConversationRevision: 3,
		}, nil
	}}
	service, err := NewService(
		store,
		executor,
		WithTeamArtifactContentReader(contentReader),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SynthesizeTeamCompletion(
		context.Background(),
		validScope(),
		fixture.ownerID,
		fixture.event.EventID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceEventID != fixture.event.EventID ||
		result.ConversationID != fixture.conversationID ||
		result.Chat.Message.Content !=
			"The Team finished the analysis. final.json is available." ||
		result.Chat.ConversationRevision != 4 ||
		executor.chatCalls.Load() != 1 ||
		contentReader.calls != 1 {
		t.Fatalf("completion result = %#v", result)
	}
	replayed, err := service.SynthesizeTeamCompletion(
		context.Background(),
		validScope(),
		fixture.ownerID,
		fixture.event.EventID,
	)
	if err != nil ||
		replayed.Chat.Message.Content != result.Chat.Message.Content ||
		replayed.Chat.ConversationRevision != result.Chat.ConversationRevision ||
		executor.chatCalls.Load() != 1 ||
		contentReader.calls != 2 {
		t.Fatalf(
			"completion replay = %#v, error=%v, model_calls=%d",
			replayed,
			err,
			executor.chatCalls.Load(),
		)
	}
	store.mu.Lock()
	completed := store.lastCompletion
	store.mu.Unlock()
	if completed.ExpectedConversationRevision != 3 ||
		len(completed.Conversation.Messages) != 3 ||
		completed.Conversation.Messages[1].Role != modelapi.RoleTool ||
		completed.Conversation.Messages[2].Role != modelapi.RoleAssistant {
		t.Fatalf("durable completion = %#v", completed)
	}
}

func TestSynthesizeTeamCompletionRejectsArtifactNotBoundToReportFinal(t *testing.T) {
	t.Parallel()
	fixture := newTeamCompletionFixture(t)
	fixture.artifacts[0].SHA256 = digestOf("f")
	store := &teamCompletionStoreFake{
		runtimeStoreFake: newRuntimeStoreFake(),
		event:            fixture.event,
		execution:        fixture.execution,
		report:           fixture.report,
		artifacts:        fixture.artifacts,
		conversation: runtimeapi.Conversation{
			OwnerID:        fixture.ownerID,
			ConversationID: fixture.conversationID,
		},
		conversationFound: true,
	}
	service, err := NewService(store, &executorFake{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SynthesizeTeamCompletion(
		context.Background(),
		validScope(),
		fixture.ownerID,
		fixture.event.EventID,
	)
	if err != ErrTeamCompletionInvalid {
		t.Fatalf("unbound artifact error = %v", err)
	}
}

type teamCompletionFixture struct {
	ownerID        string
	conversationID string
	event          task.Event
	execution      teamexecution.Fact
	report         teamreport.Fact
	artifacts      []teamartifact.ArtifactV1
}

func newTeamCompletionFixture(t *testing.T) teamCompletionFixture {
	t.Helper()
	now := time.Date(2026, 8, 9, 1, 2, 3, 456000, time.UTC)
	ownerID := "owner-1"
	conversationID := "conversation-1"
	executionID := uuid.NewString()
	taskID := uuid.NewString()
	planID := uuid.NewString()
	planDigest := digestOf("b")
	artifactDigest := digestOf("a")
	reportValue := teamreport.ReportV1{
		SchemaVersion: teamreport.SchemaV1,
		ExecutionID:   executionID,
		OwnerID:       ownerID,
		TaskID:        taskID,
		PlanID:        planID,
		PlanRevision:  1,
		PlanDigest:    planDigest,
		Roles: []teamreport.RoleV1{{
			RoleID:               "researcher",
			Title:                "Researcher",
			RuntimeFamily:        teamplan.RuntimePi,
			RuntimeAdapter:       workerruntime.AdapterPiV1,
			Outcome:              task.OutcomeSucceeded,
			ResultEvidenceDigest: digestOf("c"),
			Finals: []teamreport.FinalV1{{
				ActionID:       "deliver",
				Adapter:        workerruntime.AdapterPiV1,
				Status:         "completed",
				Summary:        "Completed the requested analysis.",
				Deliverables:   []string{"final.json"},
				Tests:          []string{"validated JSON"},
				Risks:          []string{},
				ArtifactSHA256: artifactDigest,
			}},
		}},
	}
	reportDigest, err := reportValue.Digest()
	if err != nil {
		t.Fatal(err)
	}
	report := teamreport.Fact{
		Report:       reportValue,
		ReportDigest: reportDigest,
		GeneratedAt:  now,
	}
	artifact, err := teamartifact.NewVerified(teamartifact.BuildRequest{
		AgentInstanceID:  uuid.NewString(),
		OwnerID:          ownerID,
		ExecutionID:      executionID,
		OperationID:      uuid.NewString(),
		TaskID:           taskID,
		PlanID:           planID,
		PlanRevision:     1,
		ConnectionID:     uuid.NewString(),
		RoleID:           "researcher",
		ActionID:         "deliver",
		DeploymentID:     uuid.NewString(),
		Name:             "final.json",
		MediaType:        "application/json",
		SizeBytes:        128,
		SHA256:           artifactDigest,
		ObjectRef:        "s3://dirextalk-artifacts/team/final.json",
		CreatedAt:        now,
		RetentionExpires: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	execution := teamexecution.Fact{
		Execution: teamexecution.ExecutionV1{
			ExecutionID:  executionID,
			OwnerID:      ownerID,
			TaskID:       taskID,
			PlanID:       planID,
			PlanRevision: 1,
			PlanDigest:   planDigest,
		},
		Status:         teamexecution.StatusCompleted,
		RecordRevision: 2,
	}
	summary, err := json.Marshal(teamCompletionEventSummary{
		SchemaVersion:   1,
		ExecutionID:     executionID,
		OwnerID:         ownerID,
		TaskID:          taskID,
		PlanID:          planID,
		PlanRevision:    1,
		PlanDigest:      planDigest,
		Status:          teamexecution.StatusCompleted,
		RecordRevision:  2,
		ConversationID:  conversationID,
		ReportDigest:    reportDigest,
		ReportGenerated: now,
		CleanupVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return teamCompletionFixture{
		ownerID:        ownerID,
		conversationID: conversationID,
		event: task.Event{
			Seq:           9,
			EventID:       uuid.NewString(),
			EventType:     teamExecutionCompletedEvent,
			AggregateType: "team_execution",
			AggregateID:   executionID,
			Revision:      2,
			SummaryJSON:   summary,
			OccurredAt:    now,
		},
		execution: execution,
		report:    report,
		artifacts: []teamartifact.ArtifactV1{artifact},
	}
}

func digestOf(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

type teamCompletionStoreFake struct {
	*runtimeStoreFake
	event             task.Event
	execution         teamexecution.Fact
	report            teamreport.Fact
	artifacts         []teamartifact.ArtifactV1
	conversation      runtimeapi.Conversation
	conversationFound bool
}

type teamArtifactContentReaderFake struct {
	contents map[string][]byte
	calls    int
}

func (reader *teamArtifactContentReaderFake) ReadTeamArtifactContent(
	_ context.Context,
	artifact teamartifact.ArtifactV1,
	maximum int64,
) ([]byte, error) {
	reader.calls++
	content, found := reader.contents[artifact.ArtifactID]
	if !found || int64(len(content)) != maximum {
		return nil, errors.New("artifact content unavailable")
	}
	return append([]byte(nil), content...), nil
}

func (store *teamCompletionStoreFake) GetTaskEvent(
	context.Context,
	string,
) (task.Event, error) {
	return store.event, nil
}

func (store *teamCompletionStoreFake) GetTeamExecution(
	context.Context,
	string,
	string,
) (teamexecution.Fact, error) {
	return store.execution, nil
}

func (store *teamCompletionStoreFake) GetTeamExecutionReport(
	context.Context,
	string,
	string,
) (teamreport.Fact, error) {
	return store.report, nil
}

func (store *teamCompletionStoreFake) ListTeamArtifacts(
	context.Context,
	string,
	string,
) ([]teamartifact.ArtifactV1, error) {
	return append([]teamartifact.ArtifactV1(nil), store.artifacts...), nil
}

func (store *teamCompletionStoreFake) LoadConversation(
	context.Context,
	string,
	string,
) (runtimeapi.Conversation, bool, error) {
	return store.conversation, store.conversationFound, nil
}
