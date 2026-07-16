package quote

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func TestServiceBuildsThreeExactCandidatesWithoutSecretProviderInput(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	boundRecipe := quoteRecipe(t)
	request := quoteRequest(t, boundRecipe, PurchaseOnDemand)
	port := NewFakePricingPort(pricingSnapshot(now, PurchaseOnDemand))
	service, err := NewService(port, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	got, err := service.Quote(context.Background(), request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	if got.ValidUntil.Sub(got.QuotedAt) != 15*time.Minute || len(got.Candidates) != 3 {
		t.Fatalf("unexpected quote validity/candidates: %#v", got)
	}
	if got.Currency != "USD" || got.Candidates[1].CandidateID != CandidateRecommended {
		t.Fatalf("unexpected currency/profile: %#v", got)
	}
	queries := port.Queries()
	if len(queries) != 1 {
		t.Fatalf("provider calls = %d, want 1", len(queries))
	}
	encoded, err := json.Marshal(queries[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret_ref") || strings.Contains(string(encoded), "owner-1") {
		t.Fatalf("pricing query leaked non-pricing scope: %s", encoded)
	}
	for _, candidate := range got.Candidates {
		if candidate.HourlyEstimateMicros == 0 || candidate.MonthlyEstimateMicros == 0 || candidate.MaximumLaunchAmountMicros == 0 {
			t.Fatalf("candidate has missing exact aggregate: %#v", candidate)
		}
	}
}

func TestServiceNormalizesAuthoritativeQuoteTimeToPostgresPrecision(t *testing.T) {
	clock := time.Date(2026, time.July, 16, 8, 0, 0, 123456789, time.UTC)
	boundRecipe := quoteRecipe(t)
	request := quoteRequest(t, boundRecipe, PurchaseOnDemand)
	service, err := NewService(NewFakePricingPort(pricingSnapshot(clock, PurchaseOnDemand)), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}

	got, err := service.Quote(context.Background(), request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	want := clock.Truncate(time.Microsecond)
	if !got.QuotedAt.Equal(want) || !got.ValidUntil.Equal(want.Add(Validity)) {
		t.Fatalf("quote times=(%s,%s), want PostgreSQL-stable (%s,%s)", got.QuotedAt, got.ValidUntil, want, want.Add(Validity))
	}
}

func TestQuoteRequiresRequoteForExpiryAndEveryCompleteScopeDrift(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	boundRecipe := quoteRecipe(t)
	request := quoteRequest(t, boundRecipe, PurchaseOnDemand)
	service, _ := NewService(NewFakePricingPort(pricingSnapshot(now, PurchaseOnDemand)), func() time.Time { return now })
	got, err := service.Quote(context.Background(), request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	selected, ok := got.Candidate(CandidateRecommended)
	if !ok {
		t.Fatal("recommended candidate missing")
	}
	if err := got.ValidateSelection(now, CandidateRecommended, selected.Scope); err != nil {
		t.Fatalf("unchanged current quote rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ScopeV1)
	}{
		{"owner", func(s *ScopeV1) { s.OwnerID = "owner-2" }},
		{"connection", func(s *ScopeV1) { s.ConnectionID = "connection-2" }},
		{"recipe", func(s *ScopeV1) { s.Recipe.Digest = testDigest("9") }},
		{"instance", func(s *ScopeV1) { s.Resource.InstanceType = "m7i.2xlarge" }},
		{"disk", func(s *ScopeV1) { s.Resource.DiskGiB++ }},
		{"image", func(s *ScopeV1) { s.Resource.WorkerImageDigest = testDigest("8") }},
		{"network", func(s *ScopeV1) { s.Network.SubnetID = "subnet-0bbbbbbbbbbbbbbbb" }},
		{"secret", func(s *ScopeV1) { s.SecretScope[0].Purpose = "changed purpose" }},
		{"integration", func(s *ScopeV1) { s.IntegrationScope[0].Scopes = []string{"read", "write"} }},
		{"retention", func(s *ScopeV1) { s.Retention.GracePeriodSeconds++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneTestScope(selected.Scope)
			test.mutate(&changed)
			requote, err := got.RequiresRequote(now, CandidateRecommended, changed)
			if err != nil {
				t.Fatal(err)
			}
			if !requote {
				t.Fatalf("%s drift did not require requote", test.name)
			}
		})
	}
	if err := got.ValidateSelection(got.ValidUntil, CandidateRecommended, selected.Scope); !errors.Is(err, ErrRequoteRequired) {
		t.Fatalf("expired quote error = %v, want ErrRequoteRequired", err)
	}
}

func TestSpotRequiresVerifiedCheckpointResumeAndInterruptionEvidence(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	boundRecipe := quoteRecipe(t)
	request := quoteRequest(t, boundRecipe, PurchaseSpot)
	port := NewFakePricingPort(pricingSnapshot(now, PurchaseSpot))
	service, _ := NewService(port, func() time.Time { return now })

	if _, err := service.Quote(context.Background(), request, boundRecipe); err == nil || !strings.Contains(err.Error(), "checkpoint/resume") {
		t.Fatalf("Spot without evidence error = %v", err)
	}
	digest, _ := boundRecipe.Digest()
	request.SpotQualification = &SpotQualificationV1{
		EvidenceID: "spot-evidence-1", RecipeDigest: digest, CheckpointName: "installed", ResumeAction: "restart", MaxRetries: 2,
		CheckpointVerifiedAt: now.Add(-2 * time.Hour), InterruptionTestedAt: now.Add(-time.Hour),
	}
	got, err := service.Quote(context.Background(), request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	if got.SpotEvidence == nil {
		t.Fatal("validated Spot evidence was not bound into quote")
	}

	request.SpotQualification.CheckpointName = "verified"
	request.SpotQualification.ResumeAction = "different"
	if _, err := service.Quote(context.Background(), request, boundRecipe); err == nil || !strings.Contains(err.Error(), "restart contract") {
		t.Fatalf("mismatched resume evidence error = %v", err)
	}
}

func TestServiceRejectsUnavailableQuotaBeforeReturningQuote(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	boundRecipe := quoteRecipe(t)
	request := quoteRequest(t, boundRecipe, PurchaseOnDemand)
	snapshot := pricingSnapshot(now, PurchaseOnDemand)
	snapshot.Quotas[1].Quota.LimitUnits = snapshot.Quotas[1].Quota.UsedUnits
	service, _ := NewService(NewFakePricingPort(snapshot), func() time.Time { return now })
	if _, err := service.Quote(context.Background(), request, boundRecipe); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("insufficient quota error = %v", err)
	}
}

func TestQuoteAndPricingContractsContainNoFloatingPointFields(t *testing.T) {
	for _, value := range []any{QuoteV1{}, ScopeV1{}, RequestV1{}, PricingQueryV1{}, PricingSnapshotV1{}} {
		assertNoFloatFields(t, reflect.TypeOf(value), make(map[reflect.Type]struct{}))
	}
}

func assertNoFloatFields(t *testing.T, value reflect.Type, seen map[reflect.Type]struct{}) {
	t.Helper()
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		value = value.Elem()
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	switch value.Kind() {
	case reflect.Float32, reflect.Float64:
		t.Fatalf("money contract contains floating-point type %s", value)
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			assertNoFloatFields(t, value.Field(index).Type, seen)
		}
	}
}

func quoteRequest(t *testing.T, boundRecipe recipe.RecipeV1, purchase PurchaseOption) RequestV1 {
	t.Helper()
	digest, err := boundRecipe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := RequestV1{QuoteID: "quote-1", Usage: UsageV1{RuntimeHoursPerMonth: 730, LogIngestMiB: 1024, LogStoredMiBMonths: 2048, SnapshotGiBMonths: 80}}
	for index, profile := range []CandidateProfile{CandidateEconomic, CandidateRecommended, CandidatePerformance} {
		factor := uint32(1 << index)
		request.Scopes = append(request.Scopes, ScopeV1{
			SchemaVersion: ScopeSchemaV1, AgentInstanceID: "agent-instance-1", OwnerID: "owner-1", ConnectionID: "connection-1",
			Recipe: RecipeBindingV1{RecipeID: boundRecipe.RecipeID, Digest: digest, Maturity: boundRecipe.Maturity},
			Resource: ResourceScopeV1{
				CandidateID: profile, Region: "us-east-1", AvailabilityZones: []string{"us-east-1a", "us-east-1b"}, InstanceType: []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index],
				InstanceCount: 1, Architecture: recipe.ArchitectureAMD64, VCPU: 2 * factor, MemoryMiB: 8192 * uint64(factor), DiskGiB: 80 * uint64(factor), VolumeType: "gp3", VolumeIOPS: 3000,
				VolumeThroughputMiBPS: 125, VolumeEncrypted: true, PurchaseOption: purchase, WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: testDigest("f"),
			},
			Network:          NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: EntryPointNone},
			SecretScope:      []SecretScopeV1{{SecretRef: "secret_ref:plan-1/model-token", Purpose: "model access", Delivery: recipe.SecretDeliveryFile}},
			IntegrationScope: []IntegrationScopeV1{{Kind: IntegrationMCP, Name: "knowledge tools", Scopes: []string{"read"}}},
			Retention:        RetentionScopeV1{Class: RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
		})
	}
	return request
}

func pricingSnapshot(now time.Time, purchase PurchaseOption) PricingSnapshotV1 {
	snapshot := PricingSnapshotV1{
		CapturedAt: now.Add(-time.Minute), Currency: "USD",
		Assumptions: []string{"730 runtime hours per month", "one exclusive Worker instance"},
		Exclusions:  []string{"taxes and unplanned internet transfer"},
	}
	compute := CostComputeOnDemand
	if purchase == PurchaseSpot {
		compute = CostComputeSpot
	}
	for index, profile := range []CandidateProfile{CandidateEconomic, CandidateRecommended, CandidatePerformance} {
		instance := []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index]
		snapshot.Offerings = append(snapshot.Offerings, OfferingV1{CandidateID: profile, Region: "us-east-1", InstanceType: instance, Architecture: recipe.ArchitectureAMD64, PurchaseOption: purchase, AvailabilityZones: []string{"us-east-1a", "us-east-1b"}})
		snapshot.Quotas = append(snapshot.Quotas, CandidateQuotaV1{CandidateID: profile, Quota: QuotaEvidenceV1{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 4, RequiredUnits: uint64(2 << index)}})
		multiplier := uint64(index + 1)
		snapshot.Prices = append(snapshot.Prices, CandidatePriceV1{CandidateID: profile, CostItems: []CostItemV1{
			costItem(compute, "EC2 compute", "price-compute-"+string(profile), 100000*multiplier, 73000000*multiplier, 200000*multiplier),
			costItem(CostEBS, "encrypted EBS", "price-ebs-"+string(profile), 10000*multiplier, 7300000*multiplier, 10000*multiplier),
			costItem(CostPublicIPv4, "public IPv4", "price-ipv4-"+string(profile), 0, 0, 0),
			costItem(CostLogs, "CloudWatch logs", "price-logs-"+string(profile), 1000, 730000, 1000),
			costItem(CostSnapshot, "EBS snapshots", "price-snapshot-"+string(profile), 1000, 730000, 1000),
			costItem(CostEntry, "public entry infrastructure", "price-entry-"+string(profile), 0, 0, 0),
			costItem(CostTraffic, "estimated data transfer", "price-traffic-"+string(profile), 1000, 730000, 1000),
		}})
	}
	return snapshot
}

func costItem(category CostCategory, description, source string, hourly, monthly, launch uint64) CostItemV1 {
	return CostItemV1{Category: category, Description: description, SourceID: source, HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: launch}
}

func cloneTestScope(value ScopeV1) ScopeV1 {
	value.Resource.AvailabilityZones = append([]string(nil), value.Resource.AvailabilityZones...)
	value.Network.IngressPorts = append([]uint32(nil), value.Network.IngressPorts...)
	value.SecretScope = append([]SecretScopeV1(nil), value.SecretScope...)
	value.IntegrationScope = append([]IntegrationScopeV1(nil), value.IntegrationScope...)
	for index := range value.IntegrationScope {
		value.IntegrationScope[index].Scopes = append([]string(nil), value.IntegrationScope[index].Scopes...)
	}
	return value
}

func quoteRecipe(t *testing.T) recipe.RecipeV1 {
	t.Helper()
	retrieved := time.Date(2026, time.July, 16, 6, 0, 0, 0, time.UTC)
	value := recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: "recipe-knowledge-node-1", Name: "Knowledge node", Maturity: recipe.MaturityExperimental,
		Sources:      []recipe.SourceV1{{ID: "primary", URL: "https://github.com/example/knowledge-node", Version: "v1.2.3", Commit: strings.Repeat("a", 40), ArtifactDigest: testDigest("a"), ContentDigest: testDigest("b"), License: "Apache-2.0", RetrievedAt: retrieved, Official: true, Kind: recipe.SourceRepository, Repository: &recipe.RepositoryIdentityV1{Host: "github.com", Namespace: "example", Name: "knowledge-node"}}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{RootRequired: true, TimeoutSeconds: 1800, CheckpointNames: []string{"installed", "verified"}, Steps: []recipe.InstallStepV1{{ID: "install", Summary: "Install digest-pinned service", TimeoutSeconds: 1200, Action: "artifact.install", Checkpoint: "installed", Inputs: []recipe.ActionInputV1{{Name: "artifact", Kind: recipe.ActionInputSource, Ref: "primary"}}}, {ID: "verify", Summary: "Verify service", TimeoutSeconds: 300, Action: "service.verify", Checkpoint: "verified"}}},
		Health:       recipe.HealthContractV1{Liveness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live"}, Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready"}, Semantic: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check"}},
		Lifecycle:    recipe.LifecycleContractV1{Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		Network:      &recipe.NetworkContractV1{DefaultDeny: true, PublicIngress: recipe.PublicIngressV1{Mode: recipe.PublicIngressNone}},
		Restart:      &recipe.RestartContractV1{Mode: recipe.RestartOnFailure, Action: "restart", MaxAttempts: 3, RecoveryCheckpoints: []string{"installed", "verified"}},
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("test Recipe invalid: %v", err)
	}
	return value
}

func testDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
