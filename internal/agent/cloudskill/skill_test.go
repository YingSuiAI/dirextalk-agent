package cloudskill

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

const testRequestID = "61bf1ec0-2605-4d9a-a28c-84ec2f86b524"

func TestProviderExposesOnlyTypedResearchStatusAndRecipeDraftTools(t *testing.T) {
	t.Parallel()

	skill := mustSkill(t, Dependencies{
		Research: ResearchPortFunc(func(context.Context, ResearchRequest) (task.Task, error) { return task.Task{}, nil }),
		Status: StatusPortFunc(func(context.Context, StatusRequest) (ResearchStatus, error) {
			return ResearchStatus{}, nil
		}),
		RecipeDraft: RecipeDraftPortFunc(func(context.Context, RecipeDraftRequest) (RecipeDraft, error) {
			return RecipeDraft{}, nil
		}),
	})
	ctx := mustBind(t, testScope())
	tools, err := skill.Tools(ctx, toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Definition.Name)
		for _, forbidden := range []string{"approve", "credential", "secret", "provider", "ingress", "destroy", "shell"} {
			if strings.Contains(tool.Definition.Name, forbidden) {
				t.Fatalf("model-visible tool %q contains forbidden capability %q", tool.Definition.Name, forbidden)
			}
		}
	}
	sort.Strings(names)
	wantNames := []string{ToolRecipeDraft, ToolResearch, ToolStatus, ToolSubmitPlanDraft}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("tool names = %v, want %v", names, wantNames)
	}

	research := findTool(t, tools, ToolResearch)
	properties, ok := research.Definition.InputSchema["properties"].(map[string]any)
	if !ok || len(properties) != 1 || properties["goal"] == nil {
		t.Fatalf("research properties = %#v, want only goal", research.Definition.InputSchema["properties"])
	}
	if research.Definition.InputSchema["additionalProperties"] != false {
		t.Fatal("research schema must reject additional properties")
	}
	for _, name := range []string{ToolStatus, ToolRecipeDraft} {
		definition := findTool(t, tools, name).Definition
		properties, ok := definition.InputSchema["properties"].(map[string]any)
		if !ok || len(properties) != 0 || definition.InputSchema["additionalProperties"] != false {
			t.Fatalf("%s schema = %#v, want an empty strict object", name, definition.InputSchema)
		}
	}
	submit := findTool(t, tools, ToolSubmitPlanDraft)
	encodedSchema, err := json.Marshal(submit.Definition.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"owner_id", "connection_id", "task_id", "recipe_id", "retention", "approval", "provider", "schema_version", "maturity", "managed_acceptance"} {
		if strings.Contains(string(encodedSchema), `"`+forbidden+`"`) {
			t.Fatalf("submit schema exposed trusted field %q: %s", forbidden, encodedSchema)
		}
	}
	submitProperties, ok := submit.Definition.InputSchema["properties"].(map[string]any)
	if !ok || len(submitProperties) != 4 {
		t.Fatalf("submit schema properties = %#v, want recipe plus three fixed tiers", submit.Definition.InputSchema["properties"])
	}
	for _, name := range []string{"recipe", "economy", "recommended", "performance"} {
		if submitProperties[name] == nil {
			t.Fatalf("submit schema is missing %q", name)
		}
	}
}

func TestSubmitPlanDraftBindsExperimentalIdentityAndReturnsOnlySafeSummary(t *testing.T) {
	t.Parallel()

	var captured SubmitPlanDraftRequest
	draft := validRecipeDraft()
	digest, err := draft.Digest()
	if err != nil {
		t.Fatal(err)
	}
	skill := mustSkill(t, Dependencies{
		Research: inertResearchPort(), Status: inertStatusPort(), RecipeDraft: inertRecipeDraftPort(),
		PlanDraft: PlanDraftPortFunc(func(_ context.Context, request SubmitPlanDraftRequest) (SubmitPlanDraftResult, error) {
			captured = request
			return SubmitPlanDraftResult{
				TaskID: "99a88e43-ab03-48cb-a917-334f126a303e", ExecutionStatus: task.ExecutionFinished,
				OutcomeStatus: task.OutcomeSucceeded, TaskRevision: 9, RecipeDigest: digest, RecipeRevision: 1,
				QuoteState: QuoteStateAwaitingQuote, CandidateRevision: 1,
				Candidates: []CandidateSummary{
					{Tier: "economy", Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40},
					{Tier: "recommended", Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80},
					{Tier: "performance", Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160},
				},
			}, nil
		}),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatal(err)
	}
	result, err := findTool(t, tools, ToolSubmitPlanDraft).Run(context.Background(), invocation(ToolSubmitPlanDraft, validPlanDraftArguments(t)))
	if err != nil {
		t.Fatalf("submit plan draft: %v", err)
	}
	if captured.Binding != expectedBinding() || captured.ToolCallID != "tool-call-1" {
		t.Fatalf("trusted submission binding changed: %#v", captured)
	}
	if captured.Recipe.SchemaVersion != recipe.SchemaV1 || captured.Recipe.RecipeID != "recipe-1" ||
		captured.Recipe.Maturity != recipe.MaturityExperimental || captured.Recipe.ManagedAcceptance != nil {
		t.Fatalf("server-owned recipe fields were not enforced: %#v", captured.Recipe)
	}
	if len(captured.Candidates) != 3 || captured.Candidates[0].Tier != "economy" ||
		captured.Candidates[1].Tier != "recommended" || captured.Candidates[2].Tier != "performance" {
		t.Fatalf("candidate tiers were not server-owned: %#v", captured.Candidates)
	}
	for _, forbidden := range []string{"Official knowledge node", "Install the digest-pinned artifact", "sized for the official workload"} {
		if strings.Contains(result.Content, forbidden) {
			t.Fatalf("submit result leaked draft detail %q: %s", forbidden, result.Content)
		}
	}
	var output planDraftView
	if err := json.Unmarshal([]byte(result.Content), &output); err != nil {
		t.Fatal(err)
	}
	if output.TaskID == "" || output.RecipeDigest != digest || output.QuoteState != QuoteStateAwaitingQuote || len(output.Candidates) != 3 {
		t.Fatalf("submit output = %#v", output)
	}
	if len(result.RelatedTaskIDs) != 1 || result.RelatedTaskIDs[0] != output.TaskID || len(result.RelatedPlanIDs) != 0 {
		t.Fatalf("submit result lost structured Task reference: %#v", result)
	}
}

func TestSubmitPlanDraftRejectsSecretsAndTrustedScopeInjectionBeforePort(t *testing.T) {
	t.Parallel()

	called := 0
	skill := mustSkill(t, Dependencies{
		Research: inertResearchPort(), Status: inertStatusPort(), RecipeDraft: inertRecipeDraftPort(),
		PlanDraft: PlanDraftPortFunc(func(context.Context, SubmitPlanDraftRequest) (SubmitPlanDraftResult, error) {
			called++
			return SubmitPlanDraftResult{}, nil
		}),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatal(err)
	}
	submit := findTool(t, tools, ToolSubmitPlanDraft)
	secretInput := strings.Replace(validPlanDraftArguments(t), "Official knowledge node", "sk-abcdefghijklmnopqrstuvwxyz012345", 1)
	if _, err := submit.Run(context.Background(), invocation(ToolSubmitPlanDraft, secretInput)); !errors.Is(err, task.ErrRawSecret) {
		t.Fatalf("secret submission error = %v, want task.ErrRawSecret", err)
	}
	var injected map[string]any
	if err := json.Unmarshal([]byte(validPlanDraftArguments(t)), &injected); err != nil {
		t.Fatal(err)
	}
	injected["owner_id"] = "attacker"
	injected["connection_id"] = "other-connection"
	injected["approval"] = true
	encoded, _ := json.Marshal(injected)
	if _, err := submit.Run(context.Background(), invocation(ToolSubmitPlanDraft, string(encoded))); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("trusted scope injection error = %v, want ErrInvalidArguments", err)
	}
	delete(injected, "owner_id")
	delete(injected, "connection_id")
	delete(injected, "approval")
	recipeInput := injected["recipe"].(map[string]any)
	recipeInput["maturity"] = "managed"
	encoded, _ = json.Marshal(injected)
	if _, err := submit.Run(context.Background(), invocation(ToolSubmitPlanDraft, string(encoded))); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("managed recipe injection error = %v, want ErrInvalidArguments", err)
	}
	if called != 0 {
		t.Fatalf("plan draft port called %d times for rejected input", called)
	}
}

func TestResearchBindsTrustedScopeAndCreatesAtMostOneTask(t *testing.T) {
	t.Parallel()

	var requests []ResearchRequest
	skill := mustSkill(t, Dependencies{
		Research: ResearchPortFunc(func(_ context.Context, request ResearchRequest) (task.Task, error) {
			requests = append(requests, request)
			return task.Task{
				TaskID:          "99a88e43-ab03-48cb-a917-334f126a303e",
				OwnerID:         request.Create.OwnerID,
				Goal:            request.Create.Goal,
				ExecutionStatus: task.ExecutionPlanning,
				OutcomeStatus:   task.OutcomePending,
				RetentionPolicy: request.Create.Retention,
				Revision:        1,
			}, nil
		}),
		Status:      inertStatusPort(),
		RecipeDraft: inertRecipeDraftPort(),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}
	research := findTool(t, tools, ToolResearch)

	wrongScope := invocation(ToolResearch, `{"goal":"research an official knowledge node"}`)
	wrongScope.OwnerID = "other-owner"
	if _, err := research.Run(context.Background(), wrongScope); !errors.Is(err, ErrInvocationScopeMismatch) {
		t.Fatalf("wrong-owner error = %v, want ErrInvocationScopeMismatch", err)
	}

	first, err := research.Run(context.Background(), invocation(ToolResearch, `{"goal":"research an official knowledge node"}`))
	if err != nil {
		t.Fatalf("first research error = %v", err)
	}
	second, err := research.Run(context.Background(), invocation(ToolResearch, `{"goal":"research an official knowledge node"}`))
	if err != nil {
		t.Fatalf("same-goal research replay error = %v", err)
	}
	if first.Content != second.Content {
		t.Fatalf("research replay result changed: first=%s second=%s", first.Content, second.Content)
	}
	if !reflect.DeepEqual(first.RelatedTaskIDs, []string{"99a88e43-ab03-48cb-a917-334f126a303e"}) || !reflect.DeepEqual(first.RelatedTaskIDs, second.RelatedTaskIDs) {
		t.Fatalf("research result lost stable Task reference: first=%#v second=%#v", first, second)
	}
	if _, err := research.Run(context.Background(), invocation(ToolResearch, `{"goal":"a different goal"}`)); !errors.Is(err, ErrResearchAlreadyStarted) {
		t.Fatalf("different-goal error = %v, want ErrResearchAlreadyStarted", err)
	}
	if len(requests) != 1 {
		t.Fatalf("CreateResearch calls = %d, want 1", len(requests))
	}

	got := requests[0]
	if got.Create.IdempotencyKey != testRequestID || got.Create.OwnerID != "owner-1" || got.Create.Goal != "research an official knowledge node" {
		t.Fatalf("trusted task command was not bound correctly: %#v", got.Create)
	}
	if got.Create.Retention != task.RetentionEphemeralAutoDestroy || got.ConversationID != "conversation-1" || got.ConnectionID != "connection-1" || got.RecipeID != "recipe-1" {
		t.Fatalf("trusted cloud scope was not bound correctly: %#v", got)
	}
	if len(got.Create.Steps) != 3 || got.Create.Steps[0].Name != "research_official_sources" || got.Create.Steps[1].DependsOnStepIDs[0] != got.Create.Steps[0].StepID || got.Create.Steps[2].DependsOnStepIDs[0] != got.Create.Steps[1].StepID {
		t.Fatalf("planning DAG = %#v, want research -> recipe -> resource candidates", got.Create.Steps)
	}
	if got.Create.Steps[0].ExecutorKind != task.ExecutorControlPlane || got.Create.Steps[1].ExecutorKind != task.ExecutorControlPlane || got.Create.Steps[2].ExecutorKind != task.ExecutorControlPlane {
		t.Fatalf("planning DAG escaped the control plane: %#v", got.Create.Steps)
	}
}

func TestResearchRejectsRawCredentialsAndInjectedControlFieldsBeforePort(t *testing.T) {
	t.Parallel()

	called := 0
	skill := mustSkill(t, Dependencies{
		Research: ResearchPortFunc(func(context.Context, ResearchRequest) (task.Task, error) {
			called++
			return task.Task{}, nil
		}),
		Status:      inertStatusPort(),
		RecipeDraft: inertRecipeDraftPort(),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}
	research := findTool(t, tools, ToolResearch)

	secret := `{"goal":"deploy with sk-abcdefghijklmnopqrstuvwxyz012345"}`
	if _, err := research.Run(context.Background(), invocation(ToolResearch, secret)); !errors.Is(err, task.ErrRawSecret) {
		t.Fatalf("raw-secret error = %v, want task.ErrRawSecret", err)
	}
	injected := `{"goal":"research a service","connection_id":"attacker","retention":"managed_retained"}`
	if _, err := research.Run(context.Background(), invocation(ToolResearch, injected)); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("injected-control error = %v, want ErrInvalidArguments", err)
	}
	if called != 0 {
		t.Fatalf("research port called %d times for rejected input", called)
	}
}

func TestReadToolsRejectModelSelectedIdentifiersBeforePorts(t *testing.T) {
	t.Parallel()

	statusCalls, draftCalls := 0, 0
	skill := mustSkill(t, Dependencies{
		Research: inertResearchPort(),
		Status: StatusPortFunc(func(context.Context, StatusRequest) (ResearchStatus, error) {
			statusCalls++
			return ResearchStatus{}, nil
		}),
		RecipeDraft: RecipeDraftPortFunc(func(context.Context, RecipeDraftRequest) (RecipeDraft, error) {
			draftCalls++
			return RecipeDraft{}, nil
		}),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}

	for _, test := range []struct {
		name string
		args string
	}{
		{name: ToolStatus, args: `{"task_id":"attacker-selected"}`},
		{name: ToolRecipeDraft, args: `{"recipe_id":"attacker-selected"}`},
	} {
		if _, err := findTool(t, tools, test.name).Run(context.Background(), invocation(test.name, test.args)); !errors.Is(err, ErrInvalidArguments) {
			t.Fatalf("%s injected identifier error = %v, want ErrInvalidArguments", test.name, err)
		}
	}
	if statusCalls != 0 || draftCalls != 0 {
		t.Fatalf("read ports called for rejected arguments: status=%d draft=%d", statusCalls, draftCalls)
	}
}

func TestConcurrentResearchCallsCreateOnce(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	skill := mustSkill(t, Dependencies{
		Research: ResearchPortFunc(func(_ context.Context, request ResearchRequest) (task.Task, error) {
			calls.Add(1)
			return task.Task{
				TaskID:          "99a88e43-ab03-48cb-a917-334f126a303e",
				OwnerID:         request.Create.OwnerID,
				Goal:            request.Create.Goal,
				ExecutionStatus: task.ExecutionPlanning,
				OutcomeStatus:   task.OutcomePending,
				RetentionPolicy: request.Create.Retention,
				Revision:        1,
			}, nil
		}),
		Status:      inertStatusPort(),
		RecipeDraft: inertRecipeDraftPort(),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}
	research := findTool(t, tools, ToolResearch)

	const goroutines = 12
	var wait sync.WaitGroup
	errorsSeen := make(chan error, goroutines)
	for index := 0; index < goroutines; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			call := invocation(ToolResearch, `{"goal":"research an official knowledge node"}`)
			call.ToolCallID = "tool-call-" + string(rune('a'+index))
			_, err := research.Run(context.Background(), call)
			errorsSeen <- err
		}(index)
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent research error = %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("CreateResearch calls = %d, want 1", calls.Load())
	}
}

func TestStatusAndRecipeDraftReturnOnlyValidatedDeSecretedViews(t *testing.T) {
	t.Parallel()

	draft := validRecipeDraft()
	skill := mustSkill(t, Dependencies{
		Research: inertResearchPort(),
		Status: StatusPortFunc(func(_ context.Context, request StatusRequest) (ResearchStatus, error) {
			if request.Binding != expectedBinding() {
				t.Errorf("status binding = %#v, want %#v", request.Binding, expectedBinding())
			}
			return ResearchStatus{
				Task: task.Task{
					TaskID:          "99a88e43-ab03-48cb-a917-334f126a303e",
					OwnerID:         request.Binding.OwnerID,
					Goal:            "do not echo this goal",
					ExecutionStatus: task.ExecutionPlanning,
					OutcomeStatus:   task.OutcomePending,
					RetentionPolicy: request.Binding.Retention,
					CurrentStepID:   "research-sources",
					Revision:        3,
				},
				Steps: []task.Step{{
					StepID:          "research-sources",
					TaskID:          "99a88e43-ab03-48cb-a917-334f126a303e",
					ExecutionStatus: task.ExecutionRunning,
					OutcomeStatus:   task.OutcomePending,
					CheckpointRef:   "secret-checkpoint-reference",
					ResultRef:       "secret-result-reference",
					Revision:        2,
				}},
			}, nil
		}),
		RecipeDraft: RecipeDraftPortFunc(func(_ context.Context, request RecipeDraftRequest) (RecipeDraft, error) {
			if request.Binding != expectedBinding() {
				t.Errorf("recipe binding = %#v, want %#v", request.Binding, expectedBinding())
			}
			return RecipeDraft{Ready: true, Recipe: draft}, nil
		}),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}

	status, err := findTool(t, tools, ToolStatus).Run(context.Background(), invocation(ToolStatus, `{}`))
	if err != nil {
		t.Fatalf("status error = %v", err)
	}
	for _, forbidden := range []string{"do not echo this goal", "secret-checkpoint-reference", "secret-result-reference"} {
		if strings.Contains(status.Content, forbidden) {
			t.Fatalf("status leaked %q: %s", forbidden, status.Content)
		}
	}
	if !reflect.DeepEqual(status.RelatedTaskIDs, []string{"99a88e43-ab03-48cb-a917-334f126a303e"}) {
		t.Fatalf("status result lost Task reference: %#v", status)
	}

	result, err := findTool(t, tools, ToolRecipeDraft).Run(context.Background(), invocation(ToolRecipeDraft, `{}`))
	if err != nil {
		t.Fatalf("recipe draft error = %v", err)
	}
	var output struct {
		Ready  bool            `json:"ready"`
		Digest string          `json:"digest"`
		Recipe recipe.RecipeV1 `json:"recipe"`
	}
	if err := json.Unmarshal([]byte(result.Content), &output); err != nil {
		t.Fatalf("decode recipe result: %v", err)
	}
	wantDigest, err := draft.Digest()
	if err != nil {
		t.Fatalf("draft digest: %v", err)
	}
	if !output.Ready || output.Digest != wantDigest || output.Recipe.RecipeID != testScope().RecipeID {
		t.Fatalf("recipe output = %#v", output)
	}
}

func TestProviderFailsClosedWithoutMatchingTrustedScope(t *testing.T) {
	t.Parallel()

	skill := mustSkill(t, Dependencies{
		Research:    inertResearchPort(),
		Status:      inertStatusPort(),
		RecipeDraft: inertRecipeDraftPort(),
	})
	if _, err := skill.Tools(context.Background(), toolRequest()); !errors.Is(err, ErrMissingCallScope) {
		t.Fatalf("missing-scope error = %v, want ErrMissingCallScope", err)
	}

	scope := testScope()
	scope.OwnerID = "other-owner"
	if _, err := skill.Tools(mustBind(t, scope), toolRequest()); !errors.Is(err, ErrInvocationScopeMismatch) {
		t.Fatalf("mismatched-scope error = %v, want ErrInvocationScopeMismatch", err)
	}

	invalid := testScope()
	invalid.Retention = ""
	if _, err := BindCallScope(context.Background(), invalid); !errors.Is(err, ErrInvalidCallScope) {
		t.Fatalf("invalid-scope error = %v, want ErrInvalidCallScope", err)
	}
	waitingConnection := testScope()
	waitingConnection.ConnectionID = ""
	if _, err := BindCallScope(context.Background(), waitingConnection); err != nil {
		t.Fatalf("research without an AWS connection must remain available: %v", err)
	}
}

func TestRecipeDraftRejectsInvalidOrCredentialBearingPortOutput(t *testing.T) {
	t.Parallel()

	draft := validRecipeDraft()
	draft.Sources[0].URL += "?token=must-not-be-exposed"
	skill := mustSkill(t, Dependencies{
		Research: inertResearchPort(),
		Status:   inertStatusPort(),
		RecipeDraft: RecipeDraftPortFunc(func(context.Context, RecipeDraftRequest) (RecipeDraft, error) {
			return RecipeDraft{Ready: true, Recipe: draft}, nil
		}),
	})
	tools, err := skill.Tools(mustBind(t, testScope()), toolRequest())
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}
	if _, err := findTool(t, tools, ToolRecipeDraft).Run(context.Background(), invocation(ToolRecipeDraft, `{}`)); !errors.Is(err, ErrInvalidPortResponse) {
		t.Fatalf("credential-bearing draft error = %v, want ErrInvalidPortResponse", err)
	}
}

func mustSkill(t *testing.T, dependencies Dependencies) *Skill {
	t.Helper()
	if dependencies.PlanDraft == nil {
		dependencies.PlanDraft = inertPlanDraftPort()
	}
	skill, err := New(dependencies)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return skill
}

func mustBind(t *testing.T, scope CallScope) context.Context {
	t.Helper()
	ctx, err := BindCallScope(context.Background(), scope)
	if err != nil {
		t.Fatalf("BindCallScope() error = %v", err)
	}
	return ctx
}

func toolRequest() runtimeapi.ToolRequest {
	return runtimeapi.ToolRequest{RequestID: testRequestID, OwnerID: "owner-1", ConversationID: "conversation-1"}
}

func testScope() CallScope {
	return CallScope{
		OwnerID:      "owner-1",
		ConnectionID: "connection-1",
		RecipeID:     "recipe-1",
		Retention:    task.RetentionEphemeralAutoDestroy,
	}
}

func expectedBinding() Binding {
	return Binding{
		RequestID:      testRequestID,
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
		ConnectionID:   "connection-1",
		RecipeID:       "recipe-1",
		Retention:      task.RetentionEphemeralAutoDestroy,
	}
}

func invocation(name, arguments string) runtimeapi.ToolInvocation {
	return runtimeapi.ToolInvocation{
		RequestID:      testRequestID,
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
		ToolCallID:     "tool-call-1",
		Name:           name,
		Arguments:      json.RawMessage(arguments),
	}
}

func findTool(t *testing.T, tools []runtimeapi.Tool, name string) runtimeapi.Tool {
	t.Helper()
	for _, tool := range tools {
		if tool.Definition.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not found", name)
	return runtimeapi.Tool{}
}

func inertResearchPort() ResearchPort {
	return ResearchPortFunc(func(context.Context, ResearchRequest) (task.Task, error) { return task.Task{}, nil })
}

func inertStatusPort() StatusPort {
	return StatusPortFunc(func(context.Context, StatusRequest) (ResearchStatus, error) { return ResearchStatus{}, nil })
}

func inertRecipeDraftPort() RecipeDraftPort {
	return RecipeDraftPortFunc(func(context.Context, RecipeDraftRequest) (RecipeDraft, error) { return RecipeDraft{}, nil })
}

func inertPlanDraftPort() PlanDraftPort {
	return PlanDraftPortFunc(func(context.Context, SubmitPlanDraftRequest) (SubmitPlanDraftResult, error) {
		return SubmitPlanDraftResult{}, nil
	})
}

func validPlanDraftArguments(t *testing.T) string {
	t.Helper()
	draft := validRecipeDraft()
	input := planDraftInputV1{
		Recipe: RecipeDraftInputV1{
			Name: draft.Name, Sources: draft.Sources, Requirements: draft.Requirements,
			Install: draft.Install, Health: draft.Health, Lifecycle: draft.Lifecycle,
			VolumeSlots: draft.VolumeSlots, DataSlots: draft.DataSlots, SecretSlots: draft.SecretSlots,
			Restart: draft.Restart, Network: draft.Network, Pairing: draft.Pairing, Integrations: draft.Integrations,
		},
		Economy: candidateDraftInputV1{
			Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40,
			Rationale: "sized for the official workload economy profile",
		},
		Recommended: candidateDraftInputV1{
			Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80,
			Rationale: "sized for the official workload recommended profile",
		},
		Performance: candidateDraftInputV1{
			Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160,
			Rationale: "sized for the official workload performance profile",
		},
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func validRecipeDraft() recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1,
		RecipeID:      "recipe-1",
		Name:          "Official knowledge node",
		Maturity:      recipe.MaturityExperimental,
		Sources: []recipe.SourceV1{{
			URL:            "https://github.com/example/knowledge-node",
			Version:        "v1.0.0",
			Commit:         strings.Repeat("a", 40),
			ArtifactDigest: "sha256:" + strings.Repeat("b", 64), ContentDigest: "sha256:" + strings.Repeat("c", 64),
			License:     "Apache-2.0",
			RetrievedAt: time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC),
			Official:    true,
		}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install: recipe.InstallContractV1{
			TimeoutSeconds:  1800,
			CheckpointNames: []string{"installed"},
			Steps:           []recipe.InstallStepV1{{ID: "install", Summary: "Install the digest-pinned artifact", TimeoutSeconds: 1200}},
		},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live"},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready"},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check"},
		},
		Lifecycle: recipe.LifecycleContractV1{
			Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy",
		},
	}
}
