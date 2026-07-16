package cloudapp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

type activeQuoteCredentialOpener struct {
	credentials awsprovider.SourceCredentials
	binding     awsfoundation.SourceCredentialBinding
	calls       int
}

func (opener *activeQuoteCredentialOpener) Open(_ context.Context, binding awsfoundation.SourceCredentialBinding) (awsprovider.SourceCredentials, error) {
	opener.calls++
	opener.binding = binding
	return awsprovider.SourceCredentials{
		AccessKeyID:     append([]byte(nil), opener.credentials.AccessKeyID...),
		SecretAccessKey: append([]byte(nil), opener.credentials.SecretAccessKey...),
	}, nil
}

type activeQuotePricingFactory struct {
	port       cloudquote.PricingPort
	err        error
	region     string
	roleARN    string
	session    string
	sourceSeen bool
	source     *awsprovider.SourceCredentials
	calls      int
}

func (factory *activeQuotePricingFactory) NewPricingPort(region string, source *awsprovider.SourceCredentials, roleARN, roleSessionName string) (cloudquote.PricingPort, error) {
	factory.calls++
	factory.region = region
	factory.roleARN = roleARN
	factory.session = roleSessionName
	factory.sourceSeen = source != nil && len(source.AccessKeyID) > 0 && len(source.SecretAccessKey) > 0
	factory.source = source
	return factory.port, factory.err
}

func TestActiveQuoteUsesOnlyBoundControlRoleAndWipesSourceCredential(t *testing.T) {
	now := time.Date(2026, time.July, 16, 9, 0, 0, 0, time.UTC)
	connection, request, boundRecipe, release := activeQuoteFixture(t, now)
	opener := &activeQuoteCredentialOpener{credentials: awsprovider.SourceCredentials{
		AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("synthetic-secret-material-000000000000"),
	}}
	pricing := cloudquote.NewFakePricingPort(activeQuoteSnapshot(now))
	factory := &activeQuotePricingFactory{port: pricing}
	resolver := &quoteReleaseResolver{release: release}
	engine, err := NewAWSActiveQuoteEngine(testAgentID, opener, resolver, factory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	quoted, err := engine.Quote(context.Background(), connection, request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	if len(quoted.Candidates) != 3 || quoted.ValidUntil.Sub(quoted.QuotedAt) != 15*time.Minute {
		t.Fatalf("quote=%#v", quoted)
	}
	if opener.calls != 1 || factory.calls != 1 || resolver.calls != 1 || !factory.sourceSeen {
		t.Fatalf("calls opener=%d pricing=%d release=%d source_seen=%v", opener.calls, factory.calls, resolver.calls, factory.sourceSeen)
	}
	if factory.source == nil || len(factory.source.AccessKeyID) != 0 || len(factory.source.SecretAccessKey) != 0 {
		t.Fatal("source credential was not wiped after active quote")
	}
	if opener.binding.AgentInstanceID != testAgentID || opener.binding.AccountID != connection.AccountID || opener.binding.Region != connection.Region {
		t.Fatalf("credential binding=%#v", opener.binding)
	}
	if factory.region != connection.Region || factory.roleARN != connection.ControlRoleARN || !strings.HasPrefix(factory.session, "dtx-quote-") {
		t.Fatalf("pricing binding region=%q role=%q session=%q", factory.region, factory.roleARN, factory.session)
	}
	if len(pricing.Queries()) != 1 {
		t.Fatalf("pricing queries=%d", len(pricing.Queries()))
	}
}

func TestActiveQuoteRejectsConnectionOrScopeDriftBeforeCredentialUse(t *testing.T) {
	now := time.Date(2026, time.July, 16, 9, 0, 0, 0, time.UTC)
	connection, request, boundRecipe, release := activeQuoteFixture(t, now)
	tests := []struct {
		name   string
		mutate func(*Connection, *cloudquote.RequestV1)
	}{
		{name: "inactive", mutate: func(connection *Connection, _ *cloudquote.RequestV1) { connection.Status = "pending" }},
		{name: "owner", mutate: func(_ *Connection, request *cloudquote.RequestV1) { request.Scopes[1].OwnerID = "other-owner" }},
		{name: "connection", mutate: func(_ *Connection, request *cloudquote.RequestV1) {
			request.Scopes[2].ConnectionID = "019b2d57-b3c0-7e65-a1d2-10c43de26799"
		}},
		{name: "region", mutate: func(_ *Connection, request *cloudquote.RequestV1) { request.Scopes[0].Resource.Region = "us-west-2" }},
		{name: "role", mutate: func(connection *Connection, _ *cloudquote.RequestV1) {
			connection.ControlRoleARN = "arn:aws:iam::123456789012:role/Admin"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedConnection := connection
			changedRequest := request
			changedRequest.Scopes = append([]cloudquote.ScopeV1(nil), request.Scopes...)
			test.mutate(&changedConnection, &changedRequest)
			opener := &activeQuoteCredentialOpener{credentials: awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("synthetic-secret-material-000000000000")}}
			factory := &activeQuotePricingFactory{port: cloudquote.NewFakePricingPort(activeQuoteSnapshot(now))}
			engine, err := NewAWSActiveQuoteEngine(testAgentID, opener, &quoteReleaseResolver{release: release}, factory, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := engine.Quote(context.Background(), changedConnection, changedRequest, boundRecipe); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
			if opener.calls != 0 || factory.calls != 0 {
				t.Fatalf("invalid binding reached credentials/provider: opener=%d pricing=%d", opener.calls, factory.calls)
			}
		})
	}
}

func activeQuoteFixture(t *testing.T, now time.Time) (Connection, cloudquote.RequestV1, recipe.RecipeV1, workerrelease.ReleaseV1) {
	t.Helper()
	boundRecipe := activeQuoteRecipe(now)
	if err := boundRecipe.Validate(); err != nil {
		t.Fatal(err)
	}
	recipeDigest, err := boundRecipe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	connectionID := "019b2d57-b3c0-7e65-a1d2-10c43de26717"
	request := cloudquote.RequestV1{
		QuoteID: "019b2d57-b3c0-7e65-a1d2-10c43de26716",
		Usage:   cloudquote.UsageV1{RuntimeHoursPerMonth: 730},
	}
	for index, profile := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		factor := uint64(1 << index)
		request.Scopes = append(request.Scopes, cloudquote.ScopeV1{
			SchemaVersion: cloudquote.ScopeSchemaV1, AgentInstanceID: testAgentID, OwnerID: "owner-1", ConnectionID: connectionID,
			Recipe: cloudquote.RecipeBindingV1{RecipeID: boundRecipe.RecipeID, Digest: recipeDigest, Maturity: boundRecipe.Maturity},
			Resource: cloudquote.ResourceScopeV1{
				CandidateID: profile, Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index],
				InstanceCount: 1, Architecture: recipe.ArchitectureAMD64, VCPU: uint32(2 * factor), MemoryMiB: 8192 * factor, DiskGiB: 80 * factor,
				VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiBPS: 125, VolumeEncrypted: true, PurchaseOption: cloudquote.PurchaseOnDemand,
			},
			Network:   cloudquote.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudquote.EntryPointNone},
			Retention: cloudquote.RetentionScopeV1{Class: cloudquote.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
		})
	}
	connection := Connection{
		ConnectionID: connectionID, OwnerID: "owner-1", AccountID: "123456789012", Region: "us-east-1",
		FoundationStack: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-foundation/01234567-89ab-cdef-0123-456789abcdef",
		Status:          "active", Revision: 1,
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: testAgentID, Partition: "aws", AccountID: connection.AccountID, Region: connection.Region})
	if err != nil {
		t.Fatal(err)
	}
	connection.ControlRoleARN = "arn:aws:iam::" + connection.AccountID + ":role/" + spec.ControlRoleName
	release := workerrelease.ReleaseV1{
		AgentInstanceID: testAgentID, AccountID: connection.AccountID, Region: connection.Region, Architecture: recipe.ArchitectureAMD64,
		ImageID: "ami-0123456789abcdef0", ImageDigest: testCloudDigest("f"),
	}
	return connection, request, boundRecipe, release
}

func activeQuoteSnapshot(now time.Time) cloudquote.PricingSnapshotV1 {
	value := cloudquote.PricingSnapshotV1{CapturedAt: now.Add(-time.Minute), Currency: "USD", Assumptions: []string{"exclusive worker"}, Exclusions: []string{"tax"}}
	for index, profile := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		instance := []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index]
		value.Offerings = append(value.Offerings, cloudquote.OfferingV1{CandidateID: profile, Region: "us-east-1", InstanceType: instance, Architecture: recipe.ArchitectureAMD64, PurchaseOption: cloudquote.PurchaseOnDemand, AvailabilityZones: []string{"us-east-1a"}})
		value.Quotas = append(value.Quotas, cloudquote.CandidateQuotaV1{CandidateID: profile, Quota: cloudquote.QuotaEvidenceV1{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 1, RequiredUnits: uint64(2 << index)}})
		items := make([]cloudquote.CostItemV1, 0, 7)
		for _, category := range []cloudquote.CostCategory{cloudquote.CostComputeOnDemand, cloudquote.CostEBS, cloudquote.CostPublicIPv4, cloudquote.CostLogs, cloudquote.CostSnapshot, cloudquote.CostEntry, cloudquote.CostTraffic} {
			items = append(items, cloudquote.CostItemV1{Category: category, Description: string(category), SourceID: "source-" + string(profile) + "-" + string(category), HourlyEstimateMicros: uint64(index+1) * 1000, MonthlyEstimateMicros: uint64(index+1) * 730000, MaximumLaunchAmountMicros: uint64(index+1) * 1000})
		}
		value.Prices = append(value.Prices, cloudquote.CandidatePriceV1{CandidateID: profile, CostItems: items})
	}
	return value
}

func activeQuoteRecipe(now time.Time) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: "recipe-active-quote-1", Name: "Active quote service", Maturity: recipe.MaturityExperimental,
		Sources:      []recipe.SourceV1{{ID: "primary", URL: "https://github.com/example/service", Version: "v1.0.0", Commit: strings.Repeat("a", 40), ArtifactDigest: testCloudDigest("a"), ContentDigest: testCloudDigest("b"), License: "Apache-2.0", RetrievedAt: now, Official: true, Kind: recipe.SourceRepository, Repository: &recipe.RepositoryIdentityV1{Host: "github.com", Namespace: "example", Name: "service"}}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{RootRequired: true, TimeoutSeconds: 1800, CheckpointNames: []string{"installed"}, Steps: []recipe.InstallStepV1{{ID: "install", Summary: "Install", TimeoutSeconds: 1200, Action: "artifact.install", Checkpoint: "installed", Inputs: []recipe.ActionInputV1{{Name: "artifact", Kind: recipe.ActionInputSource, Ref: "primary"}}}}},
		Health:       recipe.HealthContractV1{Liveness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/live"}, Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/ready"}, Semantic: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "verify"}},
		Lifecycle:    recipe.LifecycleContractV1{Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		Network:      &recipe.NetworkContractV1{DefaultDeny: true, PublicIngress: recipe.PublicIngressV1{Mode: recipe.PublicIngressNone}},
		Restart:      &recipe.RestartContractV1{Mode: recipe.RestartOnFailure, Action: "restart", MaxAttempts: 3, RecoveryCheckpoints: []string{"installed"}},
	}
}
