package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPlanningStoreRecoversResearchAndPersistsSecretFreeDraft(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	scope := task.MutationScope{ClientID: "planning-integration", CredentialID: uuid.NewString()}
	principalContext := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: scope.ClientID, CredentialID: scope.CredentialID})
	command := integrationResearchCommand()

	claimed, err := store.ClaimResearch(context.Background(), scope, command)
	if err != nil || claimed.TaskID != "" || claimed.Revision != 1 {
		t.Fatalf("claim pending research failed: task=%q revision=%d err=%T", claimed.TaskID, claimed.Revision, err)
	}
	createdBeforeCrash, err := store.Create(context.Background(), scope, command.Create)
	if err != nil {
		t.Fatalf("create research task before injected crash failed (%T)", err)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatalf("reopen planning store failed (%T)", err)
	}
	adapter, err := planning.NewCloudSkillAdapter(restarted, restarted)
	if err != nil {
		t.Fatalf("construct cloud skill adapter failed (%T)", err)
	}
	recovered, err := adapter.CreateResearch(principalContext, cloudskill.ResearchRequest{
		Create: command.Create, ConversationID: command.Binding.ConversationID,
		ConnectionID: command.Binding.ConnectionID, RecipeID: command.Binding.RecipeID,
	})
	if err != nil || recovered.TaskID != createdBeforeCrash.TaskID {
		t.Fatalf("recover research attachment failed: got=%q want=%q err=%T", recovered.TaskID, createdBeforeCrash.TaskID, err)
	}
	session, err := restarted.GetResearch(context.Background(), scope, command.Binding)
	if err != nil || session.TaskID != createdBeforeCrash.TaskID || session.QuoteState != planning.QuoteAwaitingQuote {
		t.Fatalf("recovered session mismatch: task=%q quote=%q err=%T", session.TaskID, session.QuoteState, err)
	}
	cloudBinding := cloudskill.Binding{
		RequestID: command.Binding.RequestID, OwnerID: command.Binding.OwnerID,
		ConversationID: command.Binding.ConversationID, ConnectionID: command.Binding.ConnectionID,
		RecipeID: command.Binding.RecipeID, Retention: command.Binding.Retention,
	}
	status, err := adapter.GetResearchStatus(principalContext, cloudskill.StatusRequest{Binding: cloudBinding})
	if err != nil || status.Task.TaskID != session.TaskID || len(status.Steps) != 3 || status.Steps[2].DependsOnStepIDs[0] != status.Steps[1].StepID {
		t.Fatalf("research status/DAG was not durable: steps=%d err=%T", len(status.Steps), err)
	}

	recipeValue := integrationRecipe(command.Binding.RecipeID)
	persistOfficialSourceReceipt(t, restarted, scope, command.Binding, recipeValue.Sources[0])
	wrongEvidence := planning.BindOfficialSourceEvidenceCommand{Binding: command.Binding, TaskID: session.TaskID, Sources: append([]recipe.SourceV1(nil), recipeValue.Sources...)}
	wrongEvidence.Sources[0].ContentDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := restarted.BindOfficialSourceEvidence(context.Background(), scope, wrongEvidence); !errors.Is(err, planning.ErrResearchEvidenceMissing) {
		t.Fatalf("unmatched official evidence error = %T, want evidence missing", err)
	}
	var evidenceRows int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM planning_official_source_evidence`).Scan(&evidenceRows); err != nil || evidenceRows != 0 {
		t.Fatalf("unmatched evidence persisted rows=%d err=%T", evidenceRows, err)
	}
	evidenceSet, err := restarted.BindOfficialSourceEvidence(context.Background(), scope, planning.BindOfficialSourceEvidenceCommand{
		Binding: command.Binding, TaskID: session.TaskID, Sources: recipeValue.Sources,
	})
	if err != nil || len(evidenceSet.Evidence) != 1 || !strings.HasPrefix(evidenceSet.ResultRef(), "planning://official-source-evidence/sha256:") {
		t.Fatalf("bind official evidence failed: count=%d ref=%q err=%T", len(evidenceSet.Evidence), evidenceSet.ResultRef(), err)
	}
	replayedEvidence, err := restarted.BindOfficialSourceEvidence(context.Background(), scope, planning.BindOfficialSourceEvidenceCommand{
		Binding: command.Binding, TaskID: session.TaskID, Sources: recipeValue.Sources,
	})
	if err != nil || !reflect.DeepEqual(evidenceSet, replayedEvidence) {
		t.Fatalf("official evidence replay changed result: err=%T", err)
	}

	recipeCommand := planning.SaveRecipeDraftCommand{
		IdempotencyKey: uuid.NewString(), Binding: command.Binding, Recipe: recipeValue,
	}
	draft, err := restarted.SaveRecipeDraft(context.Background(), scope, recipeCommand)
	if err != nil || draft.Revision != 1 || draft.Digest == "" {
		t.Fatalf("save recipe draft failed: revision=%d err=%T", draft.Revision, err)
	}
	resolvedRecipe, err := restarted.ResolveRecipe(context.Background(), recipeCommand.Binding.OwnerID, draft.RecipeID, draft.Digest)
	if err != nil || resolvedRecipe.RecipeID != draft.RecipeID {
		t.Fatalf("ResolveRecipe exact binding=%q err=%v", resolvedRecipe.RecipeID, err)
	}
	if _, err := restarted.ResolveRecipe(context.Background(), recipeCommand.Binding.OwnerID, draft.RecipeID, "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, planning.ErrNotFound) {
		t.Fatalf("ResolveRecipe wrong digest error=%v", err)
	}
	replayedDraft, err := restarted.SaveRecipeDraft(context.Background(), scope, recipeCommand)
	if err != nil || !reflect.DeepEqual(draft, replayedDraft) {
		t.Fatalf("recipe idempotent replay changed response: err=%T", err)
	}
	modelDraft, err := adapter.GetRecipeDraft(principalContext, cloudskill.RecipeDraftRequest{Binding: cloudBinding})
	if err != nil || !modelDraft.Ready || modelDraft.Recipe.RecipeID != command.Binding.RecipeID {
		t.Fatalf("cloud skill recipe projection was not ready: ready=%t err=%T", modelDraft.Ready, err)
	}

	candidateCommand := planning.SaveCandidatesCommand{
		IdempotencyKey: uuid.NewString(), Binding: command.Binding, ExpectedRevision: 0,
		Candidates: integrationCandidates(), QuoteState: planning.QuoteAwaitingQuote,
	}
	set, err := restarted.SaveResourceCandidates(context.Background(), scope, candidateCommand)
	if err != nil || set.Revision != 1 || len(set.Candidates) != 3 {
		t.Fatalf("save resource candidates failed: revision=%d count=%d err=%T", set.Revision, len(set.Candidates), err)
	}
	reloaded, err := restarted.GetResearch(context.Background(), scope, command.Binding)
	if err != nil || reloaded.CandidateRevision != 1 || !reflect.DeepEqual(set.Candidates, reloaded.Candidates) {
		t.Fatalf("resource candidates did not survive restart: revision=%d err=%T", reloaded.CandidateRevision, err)
	}

	followUp := command.Binding
	followUp.RequestID = uuid.NewString()
	rotatedScope := task.MutationScope{ClientID: scope.ClientID, CredentialID: uuid.NewString()}
	if continued, err := restarted.GetResearch(context.Background(), rotatedScope, followUp); err != nil || continued.SessionID != reloaded.SessionID {
		t.Fatalf("follow-up planning status did not survive request/key rotation: session=%q err=%T", continued.SessionID, err)
	}
	if continuedDraft, found, err := restarted.GetRecipeDraft(context.Background(), rotatedScope, followUp); err != nil || !found || continuedDraft.Digest != draft.Digest {
		t.Fatalf("follow-up Recipe read did not survive request/key rotation: found=%t err=%T", found, err)
	}
	otherScope := task.MutationScope{ClientID: "different-caller", CredentialID: uuid.NewString()}
	if _, err := restarted.GetResearch(context.Background(), otherScope, followUp); !errors.Is(err, planning.ErrScopeMismatch) {
		t.Fatalf("cross-caller planning read error = %T, want scope mismatch", err)
	}
	conflicting := command
	conflicting.Create.Goal = "A different planning goal."
	if _, err := restarted.ClaimResearch(context.Background(), scope, conflicting); !errors.Is(err, planning.ErrIdempotencyConflict) {
		t.Fatalf("research idempotency conflict error = %T", err)
	}

	canary := "sk-" + strings.Repeat("Z", 40)
	secretRecipe := recipeCommand
	secretRecipe.IdempotencyKey = uuid.NewString()
	secretRecipe.Recipe.Name = canary
	if _, err := restarted.SaveRecipeDraft(context.Background(), scope, secretRecipe); !errors.Is(err, planning.ErrInvalid) || strings.Contains(err.Error(), canary) {
		t.Fatalf("secret recipe rejection was not fail-closed and redacted: err=%T", err)
	}
	assertPlanningCanaryAbsent(t, pool, canary)
}

func persistOfficialSourceReceipt(t *testing.T, store *postgres.Store, scope task.MutationScope, binding planning.Binding, source recipe.SourceV1) {
	t.Helper()
	runtimeScope := runtimeapi.MutationScope{ClientID: scope.ClientID, CredentialID: scope.CredentialID}
	requestClaim, err := store.BeginRuntimeRequest(context.Background(), runtimeScope, runtimeapi.RuntimeRequestCommand{
		Request: runtimeapi.ChatRequest{
			RequestID: binding.RequestID, OwnerID: binding.OwnerID, ConversationID: binding.ConversationID,
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "Research the official source."}},
		},
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("begin evidence parent request failed (%T)", err)
	}
	if _, err := store.BindRuntimeRequestMemoryMode(context.Background(), runtimeScope, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: binding.RequestID, LeaseEpoch: requestClaim.LeaseEpoch, MemoryDisabled: false,
	}); err != nil {
		t.Fatalf("bind evidence parent memory mode failed (%T)", err)
	}
	failedCallID := "official-source-failed"
	failedClaim, err := store.BeginToolExecution(context.Background(), runtimeScope, runtimeapi.ToolExecutionCommand{
		RequestID: binding.RequestID, ParentLeaseEpoch: requestClaim.LeaseEpoch, OwnerID: binding.OwnerID,
		ConversationID: binding.ConversationID, ToolCallID: failedCallID, Name: publicweb.ToolName,
		Arguments: json.RawMessage(`{"url":"https://docs.example.com/unavailable"}`), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("begin failed official-source receipt failed (%T)", err)
	}
	if _, err := store.CompleteToolExecution(context.Background(), runtimeScope, runtimeapi.CompleteToolExecutionCommand{
		RequestID: binding.RequestID, ToolCallID: failedCallID, ParentLeaseEpoch: requestClaim.LeaseEpoch,
		LeaseEpoch: failedClaim.LeaseEpoch,
		Execution:  runtimeapi.ToolExecution{ToolCallID: failedCallID, Name: publicweb.ToolName, Content: `{"error":"tool_execution_failed"}`, IsError: true},
	}); err != nil {
		t.Fatalf("complete failed official-source receipt failed (%T)", err)
	}
	toolCallID := "official-source-integration"
	toolClaim, err := store.BeginToolExecution(context.Background(), runtimeScope, runtimeapi.ToolExecutionCommand{
		RequestID: binding.RequestID, ParentLeaseEpoch: requestClaim.LeaseEpoch, OwnerID: binding.OwnerID,
		ConversationID: binding.ConversationID, ToolCallID: toolCallID, Name: publicweb.ToolName,
		Arguments: json.RawMessage(`{"url":"` + source.URL + `"}`), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("begin official-source receipt failed (%T)", err)
	}
	result, err := json.Marshal(map[string]string{
		"url": source.URL, "retrieved_at": source.RetrievedAt.Format(time.RFC3339Nano),
		"content_digest": source.ContentDigest, "content": "official integration fixture",
	})
	if err != nil {
		t.Fatalf("encode official-source receipt failed (%T)", err)
	}
	if _, err := store.CompleteToolExecution(context.Background(), runtimeScope, runtimeapi.CompleteToolExecutionCommand{
		RequestID: binding.RequestID, ToolCallID: toolCallID, ParentLeaseEpoch: requestClaim.LeaseEpoch,
		LeaseEpoch: toolClaim.LeaseEpoch,
		Execution:  runtimeapi.ToolExecution{ToolCallID: toolCallID, Name: publicweb.ToolName, Content: string(result)},
	}); err != nil {
		t.Fatalf("complete official-source receipt failed (%T)", err)
	}
}

func newPlanningTestStore(t *testing.T) (*pgxpool.Pool, *postgres.Store, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	adminConfig.MaxConns = 2
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("open PostgreSQL administration pool failed (%T)", err)
	}
	schema := "dtx_agent_p1_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated PostgreSQL schema failed (%T)", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		adminPool.Close()
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-agent-p1-planning-test"
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		adminPool.Close()
		t.Fatalf("open isolated PostgreSQL pool failed (%T)", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, cleanupErr := adminPool.Exec(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE"); cleanupErr != nil {
			t.Errorf("drop isolated PostgreSQL schema failed (%T)", cleanupErr)
		}
		adminPool.Close()
	})
	instanceID := uuid.NewString()
	if err := postgres.ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("apply Agent migrations failed (%T)", err)
	}
	store, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatalf("construct PostgreSQL store failed (%T)", err)
	}
	return pool, store, instanceID
}

func integrationResearchCommand() planning.ResearchCommand {
	binding := planning.Binding{
		RequestID: uuid.NewString(), OwnerID: "owner-planning", ConversationID: "conversation-planning",
		ConnectionID: "connection-planning", RecipeID: "recipe-planning", Retention: task.RetentionEphemeralAutoDestroy,
	}
	first, second, third := uuid.NewString(), uuid.NewString(), uuid.NewString()
	return planning.ResearchCommand{
		Binding: binding,
		Create: task.CreateCommand{
			IdempotencyKey: binding.RequestID, OwnerID: binding.OwnerID, Goal: "Research and draft an official knowledge node.", Retention: binding.Retention,
			Steps: []task.StepDefinition{
				{StepID: first, Name: "research_official_sources", ExecutorKind: task.ExecutorControlPlane},
				{StepID: second, Name: "draft_recipe", ExecutorKind: task.ExecutorControlPlane, DependsOnStepIDs: []string{first}},
				{StepID: third, Name: "prepare_resource_candidates", ExecutorKind: task.ExecutorControlPlane, DependsOnStepIDs: []string{second}},
			},
		},
	}
}

func integrationRecipe(recipeID string) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: recipeID, Name: "Official knowledge node", Maturity: recipe.MaturityExperimental,
		Sources: []recipe.SourceV1{{
			URL: "https://example.com/official/knowledge-node", Version: "v1.0.0", Commit: "abcdef0123456789",
			ArtifactDigest: "sha256:" + strings.Repeat("a", 64), ContentDigest: "sha256:" + strings.Repeat("b", 64), License: "Apache-2.0", RetrievedAt: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC), Official: true,
		}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{RootRequired: true, TimeoutSeconds: 1800, CheckpointNames: []string{"installed"}, Steps: []recipe.InstallStepV1{{ID: "install", Summary: "Install the digest-locked artifact", TimeoutSeconds: 1200}}},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live", TimeoutSeconds: 5},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready", TimeoutSeconds: 5},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check", TimeoutSeconds: 30},
		},
		Lifecycle:   recipe.LifecycleContractV1{Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		VolumeSlots: []recipe.VolumeSlotRequirementV1{{SlotID: "data", Purpose: "Persistent index data"}},
	}
}

func integrationCandidates() []planning.ResourceCandidateV1 {
	return []planning.ResourceCandidateV1{
		{Tier: planning.TierPerformance, Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160, Rationale: "Extra query headroom."},
		{Tier: planning.TierEconomy, Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40, Rationale: "Minimum validated capacity."},
		{Tier: planning.TierRecommended, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80, Rationale: "Balanced steady-state capacity."},
	}
}

func assertPlanningCanaryAbsent(t *testing.T, pool *pgxpool.Pool, canary string) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM planning_recipe_drafts WHERE recipe_json::text LIKE '%' || $1 || '%') +
		  (SELECT count(*) FROM planning_resource_candidates WHERE candidate_json::text LIKE '%' || $1 || '%') +
		  (SELECT count(*) FROM task_events WHERE summary_json::text LIKE '%' || $1 || '%') +
		  (SELECT count(*) FROM outbox_events WHERE payload_json::text LIKE '%' || $1 || '%') +
		  (SELECT count(*) FROM idempotency_records WHERE COALESCE(response_json::text,'') LIKE '%' || $1 || '%')`, canary).Scan(&count); err != nil {
		t.Fatalf("query planning secret canary failed (%T)", err)
	}
	if count != 0 {
		t.Fatalf("planning secret canary reached %d durable rows", count)
	}
}
