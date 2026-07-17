package planning

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestPersistentCloudGoalOutputAdapterPersistsEachStageAndReplaysAcrossLease(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for index, request := range requests {
		output, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request)
		if err != nil {
			t.Fatalf("stage %d: %v", index, err)
		}
		if output.ValidateForStage(request.Step.Name) != nil {
			t.Fatalf("stage %d output=%#v", index, output)
		}
	}
	if fixture.model.researchCalls != 1 || fixture.model.recipeCalls != 1 || fixture.model.candidateCalls != 1 || fixture.materializer.calls != 1 {
		t.Fatalf("port calls research=%d recipe=%d candidates=%d materializer=%d", fixture.model.researchCalls, fixture.model.recipeCalls, fixture.model.candidateCalls, fixture.materializer.calls)
	}
	assertCloudGoalPortRequest(t, fixture.model.researchInput.Request, requests[0])
	assertCloudGoalPortRequest(t, fixture.model.recipeInput.Request, requests[1])
	assertCloudGoalPortRequest(t, fixture.model.candidateInput.Request, requests[2])
	assertCloudGoalPortRequest(t, fixture.materializer.request.Stage, requests[2])
	if fixture.repository.evidenceKey != requests[0].OutputIdempotencyKey || fixture.repository.recipeKey != requests[1].OutputIdempotencyKey ||
		fixture.repository.candidateKey != requests[2].OutputIdempotencyKey {
		t.Fatalf("stage persistence keys evidence=%q recipe=%q candidates=%q", fixture.repository.evidenceKey, fixture.repository.recipeKey, fixture.repository.candidateKey)
	}

	replayed := requests[2]
	replayed.Step.ExecutionStatus = task.ExecutionRunning
	replayed.Step.Attempt = 1
	replayed.Step.LeaseEpoch = 1
	replayed.Attempt.Attempt = 2
	replayed.Attempt.LeaseEpoch = 2
	replayed.Attempt.LeaseExpiresAt = fixture.now.Add(2 * time.Minute)
	output, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), replayed)
	if err != nil || output.PlanID == "" || fixture.model.candidateCalls != 1 || fixture.materializer.calls != 1 {
		t.Fatalf("cross-lease replay output=%#v err=%v candidate_calls=%d materializer_calls=%d", output, err, fixture.model.candidateCalls, fixture.materializer.calls)
	}
}

func TestPersistentCloudGoalOutputAdapterRejectsScopeLeaseAndStageBeforePorts(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	base := fixture.stageRequests()[0]
	tests := []struct {
		name   string
		mutate func(*CloudGoalStageRequest)
	}{
		{"caller", func(request *CloudGoalStageRequest) { request.Caller.CredentialID = "not-a-uuid" }},
		{"expired lease", func(request *CloudGoalStageRequest) { request.Attempt.LeaseExpiresAt = fixture.now }},
		{"stage", func(request *CloudGoalStageRequest) { request.Step.Name = "provider.shell" }},
		{"step mismatch", func(request *CloudGoalStageRequest) { request.Attempt.StepID = uuid.NewString() }},
		{"epoch mismatch", func(request *CloudGoalStageRequest) { request.Attempt.LeaseEpoch = 9 }},
		{"output key", func(request *CloudGoalStageRequest) { request.OutputIdempotencyKey = "invalid" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.mutate(&request)
			if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); !errors.Is(err, ErrCloudGoalOutputInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if fixture.model.researchCalls != 0 || len(fixture.repository.outputs) != 0 {
		t.Fatalf("invalid request reached ports: research=%d outputs=%d", fixture.model.researchCalls, len(fixture.repository.outputs))
	}
}

func TestPersistentCloudGoalOutputAdapterRejectsSecretCanaryAndIncompleteCandidates(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	canary := "sk-" + strings.Repeat("Z", 40)
	fixture.model.sources[0].License = canary
	_, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), fixture.stageRequests()[0])
	if !errors.Is(err, ErrCloudGoalOutputInvalid) || strings.Contains(err.Error(), canary) || fixture.repository.evidenceFound {
		t.Fatalf("secret canary error=%q evidence_found=%t", err, fixture.repository.evidenceFound)
	}

	fixture = newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[1]); err != nil {
		t.Fatal(err)
	}
	fixture.model.candidates = fixture.model.candidates[:2]
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrCloudGoalOutputInvalid) {
		t.Fatalf("two-candidate error=%v", err)
	}
	if fixture.materializer.calls != 0 {
		t.Fatalf("invalid candidates reached provider: calls=%d", fixture.materializer.calls)
	}
}

func TestPersistentCloudGoalOutputAdapterPreservesServiceSecretNotReady(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for _, request := range requests[:2] {
		if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	fixture.materializer.err = ErrCloudGoalSecretsNotReady
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrCloudGoalSecretsNotReady) {
		t.Fatalf("error=%v", err)
	}
	if _, exists := fixture.repository.outputs[requests[2].OutputIdempotencyKey]; exists {
		t.Fatal("secret-not-ready stage was persisted as complete")
	}
}

func TestPersistentCloudGoalOutputAdapterRecoversProviderFactsAfterOutputJournalCrash(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for _, request := range requests[:2] {
		if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	fixture.repository.failOutputOnce = true
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrPersistence) {
		t.Fatalf("injected journal crash error=%v", err)
	}
	if fixture.materializer.calls != 1 || len(fixture.facts.plans) != 1 || len(fixture.repository.outputs) != 2 {
		t.Fatalf("partial materialization calls=%d plans=%d outputs=%d", fixture.materializer.calls, len(fixture.facts.plans), len(fixture.repository.outputs))
	}

	retry := requests[2]
	retry.Step.ExecutionStatus, retry.Step.Attempt, retry.Step.LeaseEpoch = task.ExecutionRunning, 1, 1
	retry.Attempt.Attempt, retry.Attempt.LeaseEpoch = 2, 2
	retry.Attempt.LeaseExpiresAt = fixture.now.Add(2 * time.Minute)
	output, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), retry)
	if err != nil || output.PlanID == "" || fixture.materializer.calls != 1 || fixture.model.candidateCalls != 1 {
		t.Fatalf("recovery output=%#v err=%v materializer=%d candidates=%d", output, err, fixture.materializer.calls, fixture.model.candidateCalls)
	}
}

func TestPersistentCloudGoalOutputAdapterRejectsUnpersistedProviderOutput(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for _, request := range requests[:2] {
		if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	fixture.materializer.persist = false
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrCloudGoalOutputInvalid) {
		t.Fatalf("unpersisted provider output error=%v", err)
	}
	if _, exists := fixture.repository.outputs[requests[2].OutputIdempotencyKey]; exists {
		t.Fatal("invalid provider output reached stage journal")
	}
}

func TestPersistentCloudGoalOutputAdapterRejectsProviderScopeDrift(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for _, request := range requests[:2] {
		if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	fixture.materializer.mutate = func(value *ProviderPlanMaterialization) {
		value.Plan.OwnerID = "different-owner"
	}
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrCloudGoalOutputInvalid) {
		t.Fatalf("provider scope drift error=%v", err)
	}
	if _, exists := fixture.repository.outputs[requests[2].OutputIdempotencyKey]; exists {
		t.Fatal("scope-drifted provider output reached stage journal")
	}
}

func TestPersistentCloudGoalOutputAdapterRejectsRecipeEvidenceDriftBeforeProvider(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for _, request := range requests[:2] {
		if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	fixture.repository.draft.Recipe.Sources[0].ContentDigest = outputTestDigest("c")
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrCloudGoalOutputInvalid) {
		t.Fatalf("recipe/evidence drift error=%v", err)
	}
	if fixture.model.candidateCalls != 0 || fixture.materializer.calls != 0 {
		t.Fatalf("drifted Recipe reached downstream ports: candidates=%d materializer=%d", fixture.model.candidateCalls, fixture.materializer.calls)
	}
}

func TestPersistentCloudGoalOutputAdapterRejectsProviderReadbackMismatch(t *testing.T) {
	fixture := newPersistentOutputFixture(t)
	requests := fixture.stageRequests()
	for _, request := range requests[:2] {
		if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	fixture.materializer.persistMutate = func(value *ProviderPlanMaterialization) {
		value.Quote.Assumptions = append(value.Quote.Assumptions, "different persisted assumption")
	}
	if _, err := fixture.adapter.ExecuteCloudGoalStage(context.Background(), requests[2]); !errors.Is(err, ErrCloudGoalOutputInvalid) {
		t.Fatalf("provider readback mismatch error=%v", err)
	}
}

type persistentOutputFixture struct {
	now          time.Time
	agentID      string
	binding      Binding
	caller       task.MutationScope
	taskID       string
	repository   *persistentOutputRepositoryFake
	model        *persistentOutputModelFake
	facts        *persistentOutputFactsFake
	materializer *persistentOutputMaterializerFake
	adapter      *PersistentCloudGoalOutputAdapter
}

func newPersistentOutputFixture(t *testing.T) *persistentOutputFixture {
	t.Helper()
	now := time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)
	requestID, taskID := uuid.NewString(), uuid.NewString()
	binding := Binding{
		RequestID: requestID, OwnerID: "owner-cloud-goal", ConversationID: "cloud-goal-" + strings.ReplaceAll(requestID, "-", ""),
		ConnectionID: uuid.NewString(), RecipeID: "recipe-cloud-goal", Retention: task.RetentionEphemeralAutoDestroy,
	}
	repository := &persistentOutputRepositoryFake{
		session: ResearchSession{SessionID: uuid.NewString(), Binding: binding, TaskID: taskID, QuoteState: QuoteAwaitingQuote, Revision: 1},
		outputs: make(map[string]cloudGoalOutputRecordFake),
	}
	value := persistentOutputRecipe(binding.RecipeID, now.Add(-time.Hour))
	model := &persistentOutputModelFake{sources: append([]recipe.SourceV1(nil), value.Sources...), recipe: value, candidates: persistentOutputCandidates()}
	facts := &persistentOutputFactsFake{quotes: make(map[string]cloudquote.QuoteV1), plans: make(map[string]cloudapproval.PlanV1)}
	materializer := &persistentOutputMaterializerFake{now: now, facts: facts, persist: true}
	agentID := uuid.NewString()
	adapter, err := NewPersistentCloudGoalOutputAdapter(agentID, repository, repository, model, materializer, facts, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return &persistentOutputFixture{
		now: now, agentID: agentID, binding: binding, caller: task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
		taskID: taskID, repository: repository, model: model, facts: facts, materializer: materializer, adapter: adapter,
	}
}

func (fixture *persistentOutputFixture) stageRequests() []CloudGoalStageRequest {
	names := []string{cloudskill.StepResearchOfficialSources, cloudskill.StepDraftRecipe, cloudskill.StepPrepareResourceCandidates}
	result := make([]CloudGoalStageRequest, 0, len(names))
	for _, name := range names {
		stepID := uuid.NewSHA1(uuid.MustParse(fixture.taskID), []byte(name)).String()
		result = append(result, CloudGoalStageRequest{
			Binding: fixture.binding, Caller: fixture.caller, Goal: "Research and plan an official knowledge service.",
			Step:                 task.Step{TaskID: fixture.taskID, StepID: stepID, Name: name, ExecutorKind: task.ExecutorControlPlane, ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending},
			Attempt:              task.Attempt{TaskID: fixture.taskID, StepID: stepID, Attempt: 1, LeaseEpoch: 1, WorkerID: uuid.NewString(), LeaseExpiresAt: fixture.now.Add(time.Minute), ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending},
			OutputIdempotencyKey: uuid.NewString(),
		})
	}
	return result
}

type cloudGoalOutputRecordFake struct {
	identity CloudGoalStageIdentity
	output   CloudGoalStageOutput
}

type persistentOutputRepositoryFake struct {
	session        ResearchSession
	evidence       OfficialSourceEvidenceSet
	evidenceFound  bool
	draft          RecipeDraft
	draftFound     bool
	outputs        map[string]cloudGoalOutputRecordFake
	failOutputOnce bool
	evidenceKey    string
	recipeKey      string
	candidateKey   string
}

func (fake *persistentOutputRepositoryFake) GetResearch(_ context.Context, _ task.MutationScope, binding Binding) (ResearchSession, error) {
	if binding != fake.session.Binding {
		return ResearchSession{}, ErrScopeMismatch
	}
	return fake.session, nil
}

func (fake *persistentOutputRepositoryFake) GetOfficialSourceEvidence(_ context.Context, _ task.MutationScope, binding Binding, taskID string) (OfficialSourceEvidenceSet, bool, error) {
	if binding != fake.session.Binding || taskID != fake.session.TaskID {
		return OfficialSourceEvidenceSet{}, false, ErrScopeMismatch
	}
	return fake.evidence, fake.evidenceFound, nil
}

func (fake *persistentOutputRepositoryFake) BindOfficialSourceEvidence(_ context.Context, _ task.MutationScope, command BindOfficialSourceEvidenceCommand) (OfficialSourceEvidenceSet, error) {
	if command.Validate() != nil || command.Binding != fake.session.Binding || command.TaskID != fake.session.TaskID {
		return OfficialSourceEvidenceSet{}, ErrInvalid
	}
	fake.evidenceKey = command.IdempotencyKey
	values := make([]OfficialSourceEvidence, 0, len(command.Sources))
	for index, source := range command.Sources {
		values = append(values, OfficialSourceEvidence{TaskID: command.TaskID, ToolCallID: "official-receipt-" + string(rune('a'+index)), URL: source.URL, RetrievedAt: source.RetrievedAt, ContentDigest: source.ContentDigest})
	}
	set, err := BuildOfficialSourceEvidenceSet(command.TaskID, values)
	if err != nil {
		return OfficialSourceEvidenceSet{}, err
	}
	if fake.evidenceFound && fake.evidence.Digest != set.Digest {
		return OfficialSourceEvidenceSet{}, ErrIdempotencyConflict
	}
	fake.evidence, fake.evidenceFound = set, true
	return set, nil
}

func (fake *persistentOutputRepositoryFake) GetRecipeDraft(_ context.Context, _ task.MutationScope, binding Binding) (RecipeDraft, bool, error) {
	if binding != fake.session.Binding {
		return RecipeDraft{}, false, ErrScopeMismatch
	}
	return fake.draft, fake.draftFound, nil
}

func (fake *persistentOutputRepositoryFake) SaveRecipeDraft(_ context.Context, _ task.MutationScope, command SaveRecipeDraftCommand) (RecipeDraft, error) {
	if command.Validate() != nil || command.Binding != fake.session.Binding || command.ExpectedRevision != 0 {
		return RecipeDraft{}, ErrInvalid
	}
	fake.recipeKey = command.IdempotencyKey
	digest, _ := command.Recipe.Digest()
	draft := RecipeDraft{RecipeID: command.Recipe.RecipeID, Recipe: command.Recipe, Digest: digest, Revision: 1}
	if fake.draftFound && fake.draft.Digest != draft.Digest {
		return RecipeDraft{}, ErrIdempotencyConflict
	}
	fake.draft, fake.draftFound = draft, true
	return draft, nil
}

func (fake *persistentOutputRepositoryFake) SaveResourceCandidates(_ context.Context, _ task.MutationScope, command SaveCandidatesCommand) (ResourceCandidateSet, error) {
	if command.Validate() != nil || command.Binding != fake.session.Binding || fake.session.CandidateRevision != command.ExpectedRevision {
		return ResourceCandidateSet{}, ErrInvalid
	}
	fake.candidateKey = command.IdempotencyKey
	fake.session.Candidates = canonicalCandidates(command.Candidates)
	fake.session.CandidateRevision++
	fake.session.QuoteState = command.QuoteState
	return ResourceCandidateSet{Candidates: fake.session.Candidates, QuoteState: command.QuoteState, Revision: fake.session.CandidateRevision}, nil
}

func (fake *persistentOutputRepositoryFake) GetCloudGoalStageOutput(_ context.Context, _ task.MutationScope, identity CloudGoalStageIdentity, attempt task.Attempt) (CloudGoalStageOutput, bool, error) {
	if identity.ValidateAttempt(attempt) != nil {
		return CloudGoalStageOutput{}, false, task.ErrStaleLease
	}
	record, found := fake.outputs[identity.OutputIdempotencyKey]
	if found && record.identity != identity {
		return CloudGoalStageOutput{}, false, ErrIdempotencyConflict
	}
	return record.output, found, nil
}

func (fake *persistentOutputRepositoryFake) SaveCloudGoalStageOutput(_ context.Context, _ task.MutationScope, command SaveCloudGoalStageOutputCommand) (CloudGoalStageOutput, error) {
	if command.Validate() != nil {
		return CloudGoalStageOutput{}, ErrInvalid
	}
	if fake.failOutputOnce {
		fake.failOutputOnce = false
		return CloudGoalStageOutput{}, ErrPersistence
	}
	if record, found := fake.outputs[command.Identity.OutputIdempotencyKey]; found {
		if record.identity != command.Identity || record.output != command.Output {
			return CloudGoalStageOutput{}, ErrIdempotencyConflict
		}
		return record.output, nil
	}
	fake.outputs[command.Identity.OutputIdempotencyKey] = cloudGoalOutputRecordFake{identity: command.Identity, output: command.Output}
	return command.Output, nil
}

type persistentOutputModelFake struct {
	sources        []recipe.SourceV1
	recipe         recipe.RecipeV1
	candidates     []ResourceCandidateV1
	researchCalls  int
	recipeCalls    int
	candidateCalls int
	researchInput  CloudGoalResearchInput
	recipeInput    CloudGoalRecipeInput
	candidateInput CloudGoalCandidateInput
}

func (fake *persistentOutputModelFake) ResearchOfficialSources(_ context.Context, input CloudGoalResearchInput) ([]recipe.SourceV1, error) {
	fake.researchCalls++
	fake.researchInput = input
	return append([]recipe.SourceV1(nil), fake.sources...), nil
}

func (fake *persistentOutputModelFake) DraftExperimentalRecipe(_ context.Context, input CloudGoalRecipeInput) (recipe.RecipeV1, error) {
	fake.recipeCalls++
	fake.recipeInput = input
	return fake.recipe, nil
}

func (fake *persistentOutputModelFake) ProposeResourceCandidates(_ context.Context, input CloudGoalCandidateInput) ([]ResourceCandidateV1, error) {
	fake.candidateCalls++
	fake.candidateInput = input
	return append([]ResourceCandidateV1(nil), fake.candidates...), nil
}

type persistentOutputFactsFake struct {
	quotes map[string]cloudquote.QuoteV1
	plans  map[string]cloudapproval.PlanV1
}

func (fake *persistentOutputFactsFake) FindCloudGoalQuote(_ context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, bool, error) {
	value, found := fake.quotes[quoteID]
	if found && value.Candidates[0].Scope.OwnerID != ownerID {
		return cloudquote.QuoteV1{}, false, ErrScopeMismatch
	}
	return value, found, nil
}

func (fake *persistentOutputFactsFake) FindCloudGoalPlan(_ context.Context, ownerID, planID string) (cloudapproval.PlanV1, bool, error) {
	value, found := fake.plans[planID]
	if found && value.OwnerID != ownerID {
		return cloudapproval.PlanV1{}, false, ErrScopeMismatch
	}
	return value, found, nil
}

type persistentOutputMaterializerFake struct {
	now           time.Time
	facts         *persistentOutputFactsFake
	persist       bool
	mutate        func(*ProviderPlanMaterialization)
	persistMutate func(*ProviderPlanMaterialization)
	calls         int
	request       ProviderPlanMaterializationRequest
	err           error
}

func (fake *persistentOutputMaterializerFake) MaterializeProviderPlan(ctx context.Context, request ProviderPlanMaterializationRequest) (ProviderPlanMaterialization, error) {
	fake.calls++
	fake.request = request
	if fake.err != nil {
		return ProviderPlanMaterialization{}, fake.err
	}
	quoted := persistentOutputQuote(ctx, request, fake.now)
	selected, _ := quoted.Candidate(cloudquote.CandidateRecommended)
	plan, err := cloudapp.BuildPlan(request.AgentInstanceID, request.PlanID, quoted, cloudquote.CandidateRecommended, selected.Scope, fake.now)
	if err != nil {
		return ProviderPlanMaterialization{}, err
	}
	materialized := ProviderPlanMaterialization{Quote: quoted, Plan: plan}
	if fake.mutate != nil {
		fake.mutate(&materialized)
	}
	if fake.persist {
		persisted := materialized
		if fake.persistMutate != nil {
			fake.persistMutate(&persisted)
		}
		fake.facts.quotes[persisted.Quote.QuoteID] = persisted.Quote
		fake.facts.plans[persisted.Plan.PlanID] = persisted.Plan
	}
	return materialized, nil
}

func persistentOutputQuote(ctx context.Context, request ProviderPlanMaterializationRequest, now time.Time) cloudquote.QuoteV1 {
	scopes := make([]cloudquote.ScopeV1, 0, len(request.Candidates))
	digest := request.Draft.Digest
	profiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	for index, candidate := range canonicalCandidates(request.Candidates) {
		scopes = append(scopes, cloudquote.ScopeV1{
			SchemaVersion: cloudquote.ScopeSchemaV1, AgentInstanceID: request.AgentInstanceID,
			OwnerID: request.Stage.Binding.OwnerID, ConnectionID: request.Stage.Binding.ConnectionID,
			Recipe: cloudquote.RecipeBindingV1{RecipeID: request.Stage.Binding.RecipeID, Digest: digest, Maturity: recipe.MaturityExperimental},
			Resource: cloudquote.ResourceScopeV1{
				CandidateID: profiles[index], Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"},
				InstanceType: []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index], InstanceCount: 1,
				Architecture: candidate.Architecture, VCPU: candidate.VCPU, MemoryMiB: candidate.MemoryMiB,
				DiskGiB: candidate.DiskGiB, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiBPS: 125,
				VolumeEncrypted: true, PurchaseOption: cloudquote.PurchaseOnDemand,
				WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: outputTestDigest("f"),
			},
			Network: cloudquote.NetworkScopeV1{
				VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
				SecurityGroupMode: cloudquote.SecurityGroupExisting, SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudquote.EntryPointNone,
			},
			Retention: cloudquote.RetentionScopeV1{Class: cloudquote.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
		})
	}
	service, _ := cloudquote.NewService(cloudquote.NewFakePricingPort(persistentOutputPricing(now)), func() time.Time { return now })
	quoted, err := service.Quote(ctx, cloudquote.RequestV1{
		QuoteID: request.QuoteID, Scopes: scopes, Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730, LogIngestMiB: 1024, LogStoredMiBMonths: 1024},
	}, request.Draft.Recipe)
	if err != nil {
		panic(err)
	}
	return quoted
}

func persistentOutputPricing(now time.Time) cloudquote.PricingSnapshotV1 {
	snapshot := cloudquote.PricingSnapshotV1{CapturedAt: now.Add(-time.Minute), Currency: "USD", Assumptions: []string{"one exclusive Worker"}, Exclusions: []string{"taxes"}}
	profiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	for index, profile := range profiles {
		instance := []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index]
		snapshot.Offerings = append(snapshot.Offerings, cloudquote.OfferingV1{CandidateID: profile, Region: "us-east-1", InstanceType: instance, Architecture: recipe.ArchitectureAMD64, PurchaseOption: cloudquote.PurchaseOnDemand, AvailabilityZones: []string{"us-east-1a"}})
		snapshot.Quotas = append(snapshot.Quotas, cloudquote.CandidateQuotaV1{CandidateID: profile, Quota: cloudquote.QuotaEvidenceV1{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 1, RequiredUnits: uint64(2 << index)}})
		items := []cloudquote.CostItemV1{}
		for _, category := range []cloudquote.CostCategory{cloudquote.CostComputeOnDemand, cloudquote.CostEBS, cloudquote.CostPublicIPv4, cloudquote.CostLogs, cloudquote.CostSnapshot, cloudquote.CostEntry, cloudquote.CostTraffic} {
			items = append(items, cloudquote.CostItemV1{Category: category, Description: string(category), SourceID: string(category) + "-" + string(profile), HourlyEstimateMicros: 1000, MonthlyEstimateMicros: 730000, MaximumLaunchAmountMicros: 1000})
		}
		snapshot.Prices = append(snapshot.Prices, cloudquote.CandidatePriceV1{CandidateID: profile, CostItems: items})
	}
	return snapshot
}

func persistentOutputRecipe(recipeID string, retrieved time.Time) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: recipeID, Name: "Official knowledge node", Maturity: recipe.MaturityExperimental,
		Sources: []recipe.SourceV1{{
			ID: "primary", URL: "https://github.com/example/knowledge-node", Version: "v1.0.0", Commit: strings.Repeat("a", 40),
			ArtifactDigest: outputTestDigest("a"), ContentDigest: outputTestDigest("b"), License: "Apache-2.0", RetrievedAt: retrieved,
			Official: true, Kind: recipe.SourceRepository, Repository: &recipe.RepositoryIdentityV1{Host: "github.com", Namespace: "example", Name: "knowledge-node"},
		}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install: recipe.InstallContractV1{RootRequired: true, TimeoutSeconds: 1800, CheckpointNames: []string{"installed"}, Steps: []recipe.InstallStepV1{{
			ID: "install", Summary: "Install the digest-locked artifact", TimeoutSeconds: 1200, Action: "artifact.install", Checkpoint: "installed",
			Inputs: []recipe.ActionInputV1{{Name: "artifact", Kind: recipe.ActionInputSource, Ref: "primary"}},
		}}},
		Health: recipe.HealthContractV1{
			Liveness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live"}, Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready"},
			Semantic: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check"},
		},
		Lifecycle: recipe.LifecycleContractV1{Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		Network:   &recipe.NetworkContractV1{DefaultDeny: true, PublicIngress: recipe.PublicIngressV1{Mode: recipe.PublicIngressNone}},
	}
}

func persistentOutputCandidates() []ResourceCandidateV1 {
	return []ResourceCandidateV1{
		{Tier: TierEconomy, Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40, Rationale: "Minimum validated capacity."},
		{Tier: TierRecommended, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80, Rationale: "Balanced steady-state capacity."},
		{Tier: TierPerformance, Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160, Rationale: "Extra workload headroom."},
	}
}

func outputTestDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

func assertCloudGoalPortRequest(t *testing.T, got, want CloudGoalStageRequest) {
	t.Helper()
	if got.Binding != want.Binding || got.Caller != want.Caller || got.Goal != want.Goal || got.OutputIdempotencyKey != want.OutputIdempotencyKey ||
		got.Step.TaskID != want.Step.TaskID || got.Step.StepID != want.Step.StepID || got.Step.Name != want.Step.Name ||
		got.Attempt.TaskID != want.Attempt.TaskID || got.Attempt.StepID != want.Attempt.StepID || got.Attempt.Attempt != want.Attempt.Attempt ||
		got.Attempt.LeaseEpoch != want.Attempt.LeaseEpoch || got.Attempt.WorkerID != want.Attempt.WorkerID {
		t.Fatalf("port request lost durable scope/lease:\n got=%#v\nwant=%#v", got, want)
	}
}
