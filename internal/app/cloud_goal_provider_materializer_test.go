package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type cloudGoalConnectionFake struct {
	connection cloudapp.Connection
	calls      int
}

func (fake *cloudGoalConnectionFake) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	fake.calls++
	return fake.connection, nil
}

type cloudGoalPlacementFake struct {
	placement    awsprovider.PlacementV1
	validateCall int
	resolveCalls int
	request      cloudapp.ActivePlacementRequestV1
}

func (fake *cloudGoalPlacementFake) ValidateConnection(connection cloudapp.Connection, ownerID, connectionID string) error {
	fake.validateCall++
	if connection.Status != "active" || connection.OwnerID != ownerID || connection.ConnectionID != connectionID {
		return cloudapp.ErrInvalid
	}
	return nil
}

func (fake *cloudGoalPlacementFake) Resolve(_ context.Context, _ cloudapp.Connection, request cloudapp.ActivePlacementRequestV1) (awsprovider.PlacementV1, error) {
	fake.resolveCalls++
	fake.request = request
	return fake.placement, nil
}

type cloudGoalQuoteFake struct {
	now   time.Time
	calls int
	err   error
	quote cloudquote.QuoteV1
}

func (fake *cloudGoalQuoteFake) Quote(ctx context.Context, _ cloudapp.Connection, request cloudquote.RequestV1, boundRecipe recipe.RecipeV1) (cloudquote.QuoteV1, error) {
	fake.calls++
	bound := request
	bound.Scopes = append([]cloudquote.ScopeV1(nil), request.Scopes...)
	for index := range bound.Scopes {
		bound.Scopes[index].Resource.WorkerImageID = "ami-0123456789abcdef0"
		bound.Scopes[index].Resource.WorkerImageDigest = cloudGoalTestDigest("f")
	}
	pricing, err := cloudquote.NewService(cloudquote.NewFakePricingPort(cloudGoalPricingSnapshot(fake.now, bound.Scopes)), func() time.Time { return fake.now })
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	quoted, err := pricing.Quote(ctx, bound, boundRecipe)
	fake.err = err
	fake.quote = quoted
	return quoted, err
}

type cloudGoalFactsFake struct {
	quotes                map[string]cloudquote.QuoteV1
	plans                 map[string]cloudapproval.PlanV1
	quoteKeys             []string
	planKeys              []string
	planTaskIDs           []string
	failQuoteResponseOnce bool
	quoteReadbackDrift    bool
	planReadbackDrift     bool
}

type cloudGoalSecretLocatorFake struct {
	session secretbootstrap.SessionV1
	err     error
	calls   int
	caller  string
	binding secretbootstrap.BindingV1
}

func (fake *cloudGoalSecretLocatorFake) FindUploaded(_ context.Context, caller string, binding secretbootstrap.BindingV1) (secretbootstrap.SessionV1, error) {
	fake.calls++
	fake.caller, fake.binding = caller, binding
	if fake.err != nil {
		return secretbootstrap.SessionV1{}, fake.err
	}
	return fake.session, nil
}

func newCloudGoalFactsFake() *cloudGoalFactsFake {
	return &cloudGoalFactsFake{quotes: make(map[string]cloudquote.QuoteV1), plans: make(map[string]cloudapproval.PlanV1)}
}

func (fake *cloudGoalFactsFake) PersistQuote(_ context.Context, _ cloudapp.MutationScope, key string, _ [32]byte, value cloudquote.QuoteV1) (cloudquote.QuoteV1, error) {
	fake.quoteKeys = append(fake.quoteKeys, key)
	fake.quotes[value.QuoteID] = value
	if fake.failQuoteResponseOnce {
		fake.failQuoteResponseOnce = false
		return cloudquote.QuoteV1{}, errors.New("synthetic response loss")
	}
	return value, nil
}

func (fake *cloudGoalFactsFake) LoadQuote(_ context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, error) {
	value, found := fake.quotes[quoteID]
	if !found || len(value.Candidates) == 0 || value.Candidates[0].Scope.OwnerID != ownerID {
		return cloudquote.QuoteV1{}, cloudapp.ErrNotFound
	}
	if fake.quoteReadbackDrift {
		value.Assumptions = []string{"different but syntactically valid assumption"}
	}
	return value, nil
}

func (fake *cloudGoalFactsFake) PersistCloudGoalPlan(_ context.Context, _ cloudapp.MutationScope, key, taskID string, value cloudapproval.PlanV1) (cloudapproval.PlanV1, error) {
	fake.planKeys = append(fake.planKeys, key)
	fake.planTaskIDs = append(fake.planTaskIDs, taskID)
	fake.plans[value.PlanID] = value
	return value, nil
}

func (fake *cloudGoalFactsFake) LoadPlan(_ context.Context, ownerID, planID string) (cloudapproval.PlanV1, error) {
	value, found := fake.plans[planID]
	if !found || value.OwnerID != ownerID {
		return cloudapproval.PlanV1{}, cloudapp.ErrNotFound
	}
	if fake.planReadbackDrift {
		value.ResourceScope.VCPU++
	}
	return value, nil
}

func TestCloudGoalProviderMaterializerUsesActiveConnectionAndPersistsThreeCandidateFacts(t *testing.T) {
	fixture := newCloudGoalProviderFixture(t)
	materialized, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("error=%v connection=%d validate=%d placement=%d quote=%d quote_error=%v quote=%#v", err, fixture.connections.calls, fixture.placements.validateCall, fixture.placements.resolveCalls, fixture.quotes.calls, fixture.quotes.err, fixture.quotes.quote)
	}
	if len(materialized.Quote.Candidates) != 3 || materialized.Plan.Status != cloudapproval.PlanReadyForConfirmation {
		t.Fatalf("materialized=%#v", materialized)
	}
	if fixture.connections.calls != 1 || fixture.placements.validateCall != 1 || fixture.placements.resolveCalls != 1 || fixture.quotes.calls != 1 {
		t.Fatalf("calls connection=%d validate=%d placement=%d quote=%d", fixture.connections.calls, fixture.placements.validateCall, fixture.placements.resolveCalls, fixture.quotes.calls)
	}
	if len(fixture.facts.quoteKeys) != 1 || len(fixture.facts.planKeys) != 1 || len(fixture.facts.planTaskIDs) != 1 ||
		fixture.facts.quoteKeys[0] != fixture.request.Stage.OutputIdempotencyKey || fixture.facts.planKeys[0] != fixture.request.Stage.OutputIdempotencyKey ||
		fixture.facts.planTaskIDs[0] != fixture.request.Stage.Attempt.TaskID {
		t.Fatalf("operation keys quote=%v plan=%v task=%v", fixture.facts.quoteKeys, fixture.facts.planKeys, fixture.facts.planTaskIDs)
	}
	if fixture.placements.request.Placement.PublicIPv4 || fixture.placements.request.Placement.RuntimeHoursPerMonth != cloudGoalRuntimeHours ||
		fixture.placements.request.Placement.PrivateConnectivity != cloudquote.PrivateConnectivityNoNATEndpointsV1 ||
		fixture.placements.request.Placement.ControlPlaneEndpoint != "grpcs://worker-control.y1.dirextalk.ai:443" ||
		fixture.placements.request.Placement.PrivateEndpointDataMiB != 2*cloudGoalEndpointDataMiB ||
		fixture.placements.request.Placement.Requirements.MinVCPU != 2 || fixture.placements.request.Placement.Requirements.MinMemoryMiB != 4096 ||
		fixture.placements.request.Placement.Requirements.MinDiskGiB != 40 {
		t.Fatalf("placement request=%#v", fixture.placements.request)
	}
	readQuote := fixture.facts.quotes[fixture.request.QuoteID]
	if !sameCloudGoalQuote(materialized.Quote, readQuote) {
		t.Fatal("returned Quote does not match independently persisted digest")
	}
	readPlan := fixture.facts.plans[fixture.request.PlanID]
	returnedHash, _ := materialized.Plan.Hash()
	readHash, _ := readPlan.Hash()
	if returnedHash != readHash {
		t.Fatal("returned Plan does not match independently persisted hash")
	}
	for _, candidate := range materialized.Quote.Candidates {
		if candidate.Scope.SchemaVersion != cloudquote.ScopeSchemaV2 || candidate.Scope.Network.RouteTableID != "rtb-0123456789abcdef0" ||
			candidate.Scope.Network.ControlPlaneEndpoint != "grpcs://worker-control.y1.dirextalk.ai:443" || candidate.Scope.ServiceOperations == nil ||
			!sameCloudGoalEndpointOperations(*candidate.Scope.ServiceOperations, "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0") {
			t.Fatalf("private endpoint scope=%#v", candidate.Scope)
		}
	}
}

func TestCloudGoalProviderMaterializerRecoversQuoteOnlyResponseLossWithoutRepricing(t *testing.T) {
	fixture := newCloudGoalProviderFixture(t)
	fixture.facts.failQuoteResponseOnce = true
	if _, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request); err == nil {
		t.Fatal("first response-loss attempt unexpectedly succeeded")
	}
	if _, found := fixture.facts.quotes[fixture.request.QuoteID]; !found {
		t.Fatal("simulated provider Quote was not durably persisted")
	}
	if _, found := fixture.facts.plans[fixture.request.PlanID]; found {
		t.Fatal("Plan should not be persisted after unknown Quote result")
	}
	materialized, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if materialized.Plan.PlanID != fixture.request.PlanID || fixture.placements.resolveCalls != 1 || fixture.quotes.calls != 1 {
		t.Fatalf("retry plan=%q placement_calls=%d quote_calls=%d", materialized.Plan.PlanID, fixture.placements.resolveCalls, fixture.quotes.calls)
	}
	if len(fixture.facts.quoteKeys) != 1 || len(fixture.facts.planKeys) != 1 || fixture.facts.planKeys[0] != fixture.request.Stage.OutputIdempotencyKey {
		t.Fatalf("retry mutation keys quote=%v plan=%v", fixture.facts.quoteKeys, fixture.facts.planKeys)
	}
}

func TestCloudGoalProviderMaterializerRejectsOwnerConnectionOrStatusDriftBeforeProviderRead(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*cloudGoalProviderFixture)
	}{
		{name: "owner", mutate: func(value *cloudGoalProviderFixture) { value.request.Stage.Binding.OwnerID = "other-owner" }},
		{name: "connection", mutate: func(value *cloudGoalProviderFixture) { value.request.Stage.Binding.ConnectionID = uuid.NewString() }},
		{name: "inactive", mutate: func(value *cloudGoalProviderFixture) { value.connections.connection.Status = "pending" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCloudGoalProviderFixture(t)
			test.mutate(fixture)
			if _, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request); !errors.Is(err, cloudapp.ErrUnavailable) {
				t.Fatalf("error=%v", err)
			}
			if fixture.placements.resolveCalls != 0 || fixture.quotes.calls != 0 || len(fixture.facts.quoteKeys) != 0 || len(fixture.facts.planKeys) != 0 {
				t.Fatalf("drift reached provider/persistence: placement=%d quote=%d quote_keys=%v plan_keys=%v", fixture.placements.resolveCalls, fixture.quotes.calls, fixture.facts.quoteKeys, fixture.facts.planKeys)
			}
		})
	}
}

func TestCloudGoalProviderMaterializerRejectsIndependentReadbackDrift(t *testing.T) {
	t.Run("quote_digest", func(t *testing.T) {
		fixture := newCloudGoalProviderFixture(t)
		fixture.facts.quoteReadbackDrift = true
		if _, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request); !errors.Is(err, cloudapp.ErrUnavailable) {
			t.Fatalf("error=%v", err)
		}
		if len(fixture.facts.planKeys) != 0 {
			t.Fatalf("drifted Quote reached Plan persistence: %v", fixture.facts.planKeys)
		}
	})
	t.Run("plan_hash", func(t *testing.T) {
		fixture := newCloudGoalProviderFixture(t)
		fixture.facts.planReadbackDrift = true
		if _, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request); !errors.Is(err, cloudapp.ErrUnavailable) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestCloudGoalProviderMaterializerRequiresUploadedRecipeBoundSecretBeforeProviderWork(t *testing.T) {
	fixture := newCloudGoalProviderFixture(t)
	fixture.request.Draft.Recipe.SecretSlots = []recipe.SecretSlotRequirementV1{{
		SlotID: "model-token", Purpose: "model token", Delivery: recipe.SecretDeliveryFile,
		TargetPath: "/etc/dirextalk-service-secrets/model-token", FileMode: 0o400,
	}}
	digest, err := fixture.request.Draft.Recipe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.request.Draft.Digest = digest
	fixture.secrets.err = secretbootstrap.ErrNotFound

	if _, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request); !errors.Is(err, ErrCloudGoalSecretsNotReady) {
		t.Fatalf("error=%v", err)
	}
	if fixture.connections.calls+fixture.placements.resolveCalls+fixture.quotes.calls+len(fixture.facts.quoteKeys)+len(fixture.facts.planKeys) != 0 {
		t.Fatal("an unresolved secret reached provider reads or fact mutations")
	}
	if fixture.secrets.caller != fixture.request.Stage.Caller.ClientID || fixture.secrets.binding.TargetID != digest ||
		fixture.secrets.binding.OwnerID != fixture.request.Stage.Binding.OwnerID || fixture.secrets.binding.Purpose != "model token" {
		t.Fatalf("lookup caller=%q binding=%#v", fixture.secrets.caller, fixture.secrets.binding)
	}
}

func TestCloudGoalProviderMaterializerBindsUploadedBootstrapRefIntoQuoteAndPlan(t *testing.T) {
	fixture := newCloudGoalProviderFixture(t)
	fixture.request.Draft.Recipe.SecretSlots = []recipe.SecretSlotRequirementV1{{
		SlotID: "model-token", Purpose: "model token", Delivery: recipe.SecretDeliveryFile,
		TargetPath: "/etc/dirextalk-service-secrets/model-token", FileMode: 0o400,
	}}
	digest, err := fixture.request.Draft.Recipe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.request.Draft.Digest = digest
	sessionID := uuid.NewString()
	fixture.secrets.session = secretbootstrap.SessionV1{
		SchemaVersion: secretbootstrap.SessionSchemaV1, SessionID: sessionID,
		AgentInstanceID: fixture.request.AgentInstanceID, OwnerID: fixture.request.Stage.Binding.OwnerID,
		Purpose: "model token", TargetID: digest, Status: secretbootstrap.StatusUploaded, Revision: 2,
	}

	materialized, err := fixture.materializer.MaterializeProviderPlan(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	wantRef := "secret_ref:bootstrap/" + sessionID
	if len(materialized.Plan.SecretScope) != 1 || materialized.Plan.SecretScope[0].SecretRef != wantRef ||
		materialized.Plan.SecretScope[0].Purpose != "model token" || materialized.Plan.SecretScope[0].Delivery != recipe.SecretDeliveryFile {
		t.Fatalf("plan secret scope=%#v", materialized.Plan.SecretScope)
	}
	for _, candidate := range materialized.Quote.Candidates {
		if len(candidate.Scope.SecretScope) != 1 || candidate.Scope.SecretScope[0].SecretRef != wantRef {
			t.Fatalf("quote secret scope=%#v", candidate.Scope.SecretScope)
		}
	}
}

type cloudGoalProviderFixture struct {
	request      planning.ProviderPlanMaterializationRequest
	connections  *cloudGoalConnectionFake
	placements   *cloudGoalPlacementFake
	quotes       *cloudGoalQuoteFake
	facts        *cloudGoalFactsFake
	secrets      *cloudGoalSecretLocatorFake
	materializer *cloudGoalProviderPlanMaterializer
}

func newCloudGoalProviderFixture(t *testing.T) *cloudGoalProviderFixture {
	t.Helper()
	now := time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)
	agentID := "019b2d57-b3c0-7e65-a1d2-10c43de26001"
	connectionID := "019b2d57-b3c0-7e65-a1d2-10c43de26002"
	recipeValue := cloudGoalProviderRecipe(now)
	digest, err := recipeValue.Digest()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := uuid.NewString()
	quoteID, planID, err := planning.ProviderFactIDs(outputKey)
	if err != nil {
		t.Fatal(err)
	}
	taskID, stepID := uuid.NewString(), uuid.NewString()
	request := planning.ProviderPlanMaterializationRequest{
		AgentInstanceID: agentID,
		Stage: planning.CloudGoalStageRequest{
			Binding: planning.Binding{RequestID: uuid.NewString(), OwnerID: "owner-1", ConversationID: "conversation-1", ConnectionID: connectionID, RecipeID: recipeValue.RecipeID, Retention: task.RetentionEphemeralAutoDestroy},
			Caller:  task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}, Goal: "Deploy the official knowledge service.",
			Step:                 task.Step{TaskID: taskID, StepID: stepID, Name: "prepare_resource_candidates", ExecutorKind: task.ExecutorControlPlane, ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending},
			Attempt:              task.Attempt{TaskID: taskID, StepID: stepID, Attempt: 1, LeaseEpoch: 1, WorkerID: uuid.NewString(), LeaseExpiresAt: now.Add(time.Minute), ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending},
			OutputIdempotencyKey: outputKey,
		},
		Draft:      planning.RecipeDraft{RecipeID: recipeValue.RecipeID, Recipe: recipeValue, Digest: digest, Revision: 1},
		Candidates: cloudGoalProviderCandidates(), QuoteID: quoteID, PlanID: planID,
	}
	connection := cloudapp.Connection{ConnectionID: connectionID, OwnerID: "owner-1", AccountID: "123456789012", Region: cloudquote.WorkerControlPrivateLinkRegion, Status: "active", Revision: 1}
	connections := &cloudGoalConnectionFake{connection: connection}
	placements := &cloudGoalPlacementFake{placement: cloudGoalProviderPlacement()}
	quotes := &cloudGoalQuoteFake{now: now}
	facts := newCloudGoalFactsFake()
	secrets := &cloudGoalSecretLocatorFake{}
	materializer, err := newCloudGoalProviderPlanMaterializer(agentID, connections, placements, quotes, facts, secrets, "grpcs://worker-control.y1.dirextalk.ai:443", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return &cloudGoalProviderFixture{request: request, connections: connections, placements: placements, quotes: quotes, facts: facts, secrets: secrets, materializer: materializer}
}

func cloudGoalProviderCandidates() []planning.ResourceCandidateV1 {
	return []planning.ResourceCandidateV1{
		{Tier: planning.TierEconomy, Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40, Rationale: "Minimum verified capacity."},
		{Tier: planning.TierRecommended, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80, Rationale: "Balanced steady-state capacity."},
		{Tier: planning.TierPerformance, Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160, Rationale: "Extra workload headroom."},
	}
}

func cloudGoalProviderPlacement() awsprovider.PlacementV1 {
	result := awsprovider.PlacementV1{
		Region: cloudquote.WorkerControlPrivateLinkRegion, AvailabilityZone: "ap-northeast-3a",
		Network: cloudquote.NetworkScopeV1{
			VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupMode: cloudquote.SecurityGroupCreateDedicated,
			PublicIPv4: false, EntryPoint: cloudquote.EntryPointNone, RouteTableID: "rtb-0123456789abcdef0",
			ControlPlaneEndpoint: "grpcs://worker-control.y1.dirextalk.ai:443", PrivateConnectivity: cloudquote.PrivateConnectivityNoNATEndpointsV1,
		},
		Usage: cloudGoalUsage(),
	}
	profiles := cloudGoalQuoteProfiles()
	for index, candidate := range cloudGoalProviderCandidates() {
		result.Candidates = append(result.Candidates, awsprovider.PlacementCandidateV1{
			Profile: profiles[index], InstanceType: []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index], Architecture: candidate.Architecture,
			VCPU: candidate.VCPU, MemoryMiB: candidate.MemoryMiB, DiskGiB: candidate.DiskGiB, AvailabilityZones: []string{"ap-northeast-3a"},
		})
	}
	return result
}

func cloudGoalProviderRecipe(now time.Time) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: "official-knowledge-node", Name: "Official knowledge node", Maturity: recipe.MaturityExperimental,
		Sources:      []recipe.SourceV1{{ID: "primary", URL: "https://github.com/example/knowledge-node", Version: "v1.0.0", Commit: strings.Repeat("a", 40), ArtifactDigest: cloudGoalTestDigest("a"), ContentDigest: cloudGoalTestDigest("b"), License: "Apache-2.0", RetrievedAt: now, Official: true, Kind: recipe.SourceRepository, Repository: &recipe.RepositoryIdentityV1{Host: "github.com", Namespace: "example", Name: "knowledge-node"}}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{RootRequired: true, TimeoutSeconds: 1800, CheckpointNames: []string{"installed"}, Steps: []recipe.InstallStepV1{{ID: "install", Summary: "Install the digest-locked artifact", TimeoutSeconds: 1200, Action: "artifact.install", Checkpoint: "installed", Inputs: []recipe.ActionInputV1{{Name: "artifact", Kind: recipe.ActionInputSource, Ref: "primary"}}}}},
		Health:       recipe.HealthContractV1{Liveness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live"}, Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready"}, Semantic: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check"}},
		Lifecycle:    recipe.LifecycleContractV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		Network:      &recipe.NetworkContractV1{DefaultDeny: true, PublicIngress: recipe.PublicIngressV1{Mode: recipe.PublicIngressNone}},
	}
}

func cloudGoalPricingSnapshot(now time.Time, scopes []cloudquote.ScopeV1) cloudquote.PricingSnapshotV1 {
	snapshot := cloudquote.PricingSnapshotV1{CapturedAt: now.Add(-time.Minute), Currency: "USD", Assumptions: []string{"one exclusive Worker"}, Exclusions: []string{"taxes"}}
	for index, scope := range scopes {
		profile := scope.Resource.CandidateID
		snapshot.Offerings = append(snapshot.Offerings, cloudquote.OfferingV1{CandidateID: profile, Region: scope.Resource.Region, InstanceType: scope.Resource.InstanceType, Architecture: scope.Resource.Architecture, PurchaseOption: scope.Resource.PurchaseOption, AvailabilityZones: append([]string(nil), scope.Resource.AvailabilityZones...)})
		snapshot.Quotas = append(snapshot.Quotas, cloudquote.CandidateQuotaV1{CandidateID: profile, Quota: cloudquote.QuotaEvidenceV1{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 1, RequiredUnits: uint64(2 << index)}})
		var items []cloudquote.CostItemV1
		for _, category := range []cloudquote.CostCategory{cloudquote.CostComputeOnDemand, cloudquote.CostEBS, cloudquote.CostPublicIPv4, cloudquote.CostLogs, cloudquote.CostSnapshot, cloudquote.CostEntry, cloudquote.CostTraffic, cloudquote.CostPrivateEndpoint} {
			items = append(items, cloudquote.CostItemV1{Category: category, Description: string(category), SourceID: string(profile) + "-" + string(category), HourlyEstimateMicros: uint64(index+1) * 1000, MonthlyEstimateMicros: uint64(index+1) * 730000, MaximumLaunchAmountMicros: uint64(index+1) * 1000})
		}
		snapshot.Prices = append(snapshot.Prices, cloudquote.CandidatePriceV1{CandidateID: profile, CostItems: items})
	}
	return snapshot
}

func cloudGoalTestDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
