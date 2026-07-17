package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestEntrypointScopeBuilderUsesDurableWorkerAndIndependentAWSFacts(t *testing.T) {
	fixture := newEntrypointScopeBuilderFixture(t)
	builder, err := newEntrypointScopeBuilder(fixture.agentID, fixture.facts, fixture.connections, fixture.statuses, fixture.providers, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	scope, err := builder.BuildEntryScope(context.Background(), entrypoint.ScopeBuildRequest{AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID,
		DeploymentID: fixture.deployment.Worker.DeploymentID, ExpectedDeploymentRevision: fixture.deployment.Worker.Revision, Draft: fixture.draft})
	if err != nil {
		t.Fatalf("BuildEntryScope() error = %v", err)
	}
	if scope.Worker.InstanceID != fixture.workerResource.ProviderID || scope.Worker.SecurityGroupID != fixture.groupResource.ProviderID ||
		scope.Worker.OriginalPlanHash != fixture.planHash || scope.Certificate.Hostname != fixture.draft.Hostname || len(scope.ALB.PublicSubnets) != 2 {
		t.Fatalf("scope did not bind durable facts: %#v", scope)
	}
	if fixture.reader.workerRequest.InstanceID != fixture.workerResource.ProviderID ||
		fixture.reader.workerRequest.ExpectedInstanceTags[resource.TagResourceID] != fixture.workerResource.ResourceID ||
		fixture.reader.workerRequest.ExpectedSecurityGroupTags[resource.TagResourceID] != fixture.groupResource.ResourceID {
		t.Fatalf("AWS worker request was not built from the durable ledger: %#v", fixture.reader.workerRequest)
	}
	if fixture.reader.certificateRequest.CertificateARN != fixture.draft.CertificateARN || fixture.reader.certificateRequest.Hostname != fixture.draft.Hostname ||
		fixture.reader.subnetsRequest.WorkerVPCID != scope.Worker.VPCID || len(fixture.reader.subnetsRequest.SubnetIDs) != 2 {
		t.Fatalf("AWS entry facts request = certificate=%#v subnets=%#v", fixture.reader.certificateRequest, fixture.reader.subnetsRequest)
	}
	if scope.ALB.WorkerPublicIPv4 || scope.ALB.EIPRequested || scope.ALB.TargetSource != entrypoint.TargetSourceApprovedWorkerReadBack || scope.Health.ExpectedStatusCode != 200 || !scope.Authentication.Required {
		t.Fatalf("unsafe public entry scope: %#v", scope)
	}
}

func TestEntrypointScopeBuilderFailsClosedOnAWSOwnershipDrift(t *testing.T) {
	fixture := newEntrypointScopeBuilderFixture(t)
	fixture.reader.worker.SecurityGroupID = "sg-0fedcba9876543210"
	builder, err := newEntrypointScopeBuilder(fixture.agentID, fixture.facts, fixture.connections, fixture.statuses, fixture.providers, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.BuildEntryScope(context.Background(), entrypoint.ScopeBuildRequest{AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID,
		DeploymentID: fixture.deployment.Worker.DeploymentID, ExpectedDeploymentRevision: fixture.deployment.Worker.Revision, Draft: fixture.draft})
	if !errors.Is(err, entrypoint.ErrReadBackRequired) {
		t.Fatalf("ownership drift error = %v, want read-back required", err)
	}
}

func TestEntrypointScopeBuilderRevalidatesFreshObservationNotChangedFacts(t *testing.T) {
	fixture := newEntrypointScopeBuilderFixture(t)
	builder, err := newEntrypointScopeBuilder(fixture.agentID, fixture.facts, fixture.connections, fixture.statuses, fixture.providers, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := builder.BuildEntryScope(context.Background(), entrypoint.ScopeBuildRequest{AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID,
		DeploymentID: fixture.deployment.Worker.DeploymentID, ExpectedDeploymentRevision: fixture.deployment.Worker.Revision, Draft: fixture.draft})
	if err != nil {
		t.Fatal(err)
	}
	fixture.reader.advance(fixture.now.Add(time.Minute))
	second, err := builder.RevalidateEntryScope(context.Background(), first)
	if err != nil {
		t.Fatalf("RevalidateEntryScope() error = %v", err)
	}
	firstFacts, err := entrypoint.ScopeFactDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondFacts, err := entrypoint.ScopeFactDigest(second)
	if err != nil || secondFacts != firstFacts || !second.Worker.ReadBack.ObservedAt.After(first.Worker.ReadBack.ObservedAt) {
		t.Fatalf("fresh read-back did not retain facts: first=%#v second=%#v digest=%q/%q err=%v", first, second, firstFacts, secondFacts, err)
	}
}

func TestEntrypointScopeBuilderRejectsClientEntryCostTampering(t *testing.T) {
	fixture := newEntrypointScopeBuilderFixture(t)
	fixture.draft.Cost.MaximumLaunchAmountMicros++
	builder, err := newEntrypointScopeBuilder(fixture.agentID, fixture.facts, fixture.connections, fixture.statuses, fixture.providers, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.BuildEntryScope(context.Background(), entrypoint.ScopeBuildRequest{AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID,
		DeploymentID: fixture.deployment.Worker.DeploymentID, ExpectedDeploymentRevision: fixture.deployment.Worker.Revision, Draft: fixture.draft})
	if !errors.Is(err, entrypoint.ErrInvalid) {
		t.Fatalf("tampered cost error = %v, want ErrInvalid", err)
	}
}

type entrypointScopeBuilderFixture struct {
	now            time.Time
	agentID        string
	ownerID        string
	planHash       string
	plan           cloudapproval.PlanV1
	approval       cloudapproval.ApprovalV1
	deployment     cloudstatus.Deployment
	workerResource resource.ResourceV1
	groupResource  resource.ResourceV1
	draft          entrypoint.DraftV1
	facts          *entryScopeFactsFake
	connections    *entryScopeConnectionFake
	statuses       *entryScopeStatusFake
	providers      *entryScopeProviderFactoryFake
	reader         *entryScopeReaderFake
}

func newEntrypointScopeBuilderFixture(t *testing.T) entrypointScopeBuilderFixture {
	t.Helper()
	now := time.Date(2026, time.July, 17, 12, 30, 0, 0, time.UTC)
	agentID, ownerID := uuid.NewString(), "owner-entry"
	planID, connectionID, deploymentID, taskID, approvalID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	plan := cloudapproval.PlanV1{SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID, Revision: 2,
		Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: connectionID,
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: "recipe-entry", Digest: entryTestDigest('a'), Maturity: recipe.MaturityExperimental},
		Quote:  cloudapproval.QuoteBindingV1{QuoteID: "quote-entry", Digest: entryTestDigest('b'), CandidateID: "recommended", ValidUntil: now.Add(15 * time.Minute)},
		ResourceScope: cloudapproval.ResourceScopeV1{Region: "us-east-1", AvailabilityZones: []string{"us-east-1a", "us-east-1b"}, InstanceType: "m7i.xlarge", Architecture: recipe.ArchitectureAMD64,
			InstanceCount: 1, VCPU: 4, MemoryMiB: 16384, DiskGiB: 80, VolumeType: "gp3", VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: entryTestDigest('c')},
		NetworkScope:   cloudapproval.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupMode: cloudapproval.SecurityGroupCreateDedicated, EntryPoint: cloudapproval.EntryPointNone},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400}}
	var err error
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := cloudapproval.NewApprovalV1(plan, approvalID, "challenge-entry", "device-entry", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status = cloudapproval.PlanApproved
	planHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	workerID, groupID := uuid.NewString(), uuid.NewString()
	deadline := now.Add(30 * time.Minute)
	workerTags := entryWorkerTags(agentID, ownerID, taskID, deploymentID, workerID, deadline)
	groupTags := entryWorkerTags(agentID, ownerID, taskID, deploymentID, groupID, deadline)
	workerResource := resource.ResourceV1{ResourceID: workerID, AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID, Type: resource.TypeEC2,
		LogicalName: "exclusive-cloud-worker", Region: "us-east-1", SpecDigest: entryTestDigest('d'), ApprovedPlanHash: planHash, ApprovalID: approvalID,
		ProviderID: "i-0123456789abcdef0", Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true, Tags: workerTags,
		State: resource.StateActive, ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "i-0123456789abcdef0", ObservedAt: now, TagDigest: entryTestDigest('e')}, Revision: 4}
	groupResource := resource.ResourceV1{ResourceID: groupID, AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID, Type: resource.TypeSG,
		LogicalName: "worker-security-group", Region: "us-east-1", SpecDigest: entryTestDigest('f'), ApprovedPlanHash: planHash, ApprovalID: approvalID,
		ProviderID: "sg-0123456789abcdef0", Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true, Tags: groupTags,
		State: resource.StateActive, ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "sg-0123456789abcdef0", ObservedAt: now, TagDigest: entryTestDigest('1')}, Revision: 5}
	deployment := cloudstatus.Deployment{Worker: worker.Deployment{DeploymentID: deploymentID, OwnerID: ownerID, TaskID: taskID, ProviderInstanceID: workerResource.ProviderID,
		State: worker.StateFinished, Outcome: worker.OutcomeSucceeded, Revision: 7, UpdatedAt: now}, PlanID: planID, ConnectionID: connectionID}
	draft := entrypoint.DraftV1{Hostname: "api.example.com", CertificateARN: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-4234-8234-1234567890ab",
		PublicSubnetIDs: []string{"subnet-11111111", "subnet-22222222"}, TargetPort: 8080, HealthPath: "/health/ready", ExpectedHealthStatusCode: 200,
		RecipeHealthContractDigest: entryTestDigest('2'), RecipeAuthenticationDigest: entryTestDigest('3')}
	quoted := entryPersistedQuoteFixture(t, now, plan, draft)
	quoteDigest, err := quoted.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate, found := quoted.Candidate(cloudquote.CandidateRecommended)
	if !found {
		t.Fatal("recommended entry quote candidate is missing")
	}
	draft.Cost, err = entryCostFromPersistedQuote(quoted, quoteDigest, candidate)
	if err != nil {
		t.Fatal(err)
	}
	reader := &entryScopeReaderFake{now: now, worker: awsprovider.EntryWorkerReadBackV1{InstanceID: workerResource.ProviderID, AccountID: "123456789012", Region: "us-east-1", VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: groupResource.ProviderID, OwnershipDigest: entryTestDigest('6'), ObservedAt: now.Add(time.Second)},
		certificate: awsprovider.EntryCertificateReadBackV1{CertificateARN: draft.CertificateARN, Region: "us-east-1", Hostname: draft.Hostname, SubjectAlternativeNames: []string{"*.example.com", "api.example.com"}, Status: awsprovider.EntryCertificateStatusIssued, ReadBackDigest: entryTestDigest('7'), ObservedAt: now.Add(time.Second)},
		subnets:     []awsprovider.EntryPublicSubnetReadBackV1{{SubnetID: "subnet-11111111", VPCID: "vpc-0123456789abcdef0", AvailabilityZone: "us-east-1a", Public: true, ReadBackDigest: entryTestDigest('8'), ObservedAt: now.Add(time.Second)}, {SubnetID: "subnet-22222222", VPCID: "vpc-0123456789abcdef0", AvailabilityZone: "us-east-1b", Public: true, ReadBackDigest: entryTestDigest('9'), ObservedAt: now.Add(time.Second)}}}
	return entrypointScopeBuilderFixture{now: now, agentID: agentID, ownerID: ownerID, planHash: planHash, plan: plan, approval: unsigned, deployment: deployment, workerResource: workerResource, groupResource: groupResource, draft: draft,
		facts: &entryScopeFactsFake{plan: plan, approval: unsigned, quote: quoted}, connections: &entryScopeConnectionFake{connection: cloudapp.Connection{ConnectionID: connectionID, OwnerID: ownerID, AccountID: "123456789012", Region: "us-east-1", Status: "active"}},
		statuses: &entryScopeStatusFake{deployment: deployment, resources: []resource.ResourceV1{workerResource, groupResource}}, providers: &entryScopeProviderFactoryFake{reader: reader}, reader: reader}
}

type entryScopeFactsFake struct {
	plan     cloudapproval.PlanV1
	approval cloudapproval.ApprovalV1
	quote    cloudquote.QuoteV1
}

func (fake *entryScopeFactsFake) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return fake.plan, nil
}
func (fake *entryScopeFactsFake) LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error) {
	return fake.approval, nil
}
func (fake *entryScopeFactsFake) LoadQuote(_ context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, error) {
	if fake.quote.QuoteID != quoteID || len(fake.quote.Candidates) == 0 || fake.quote.Candidates[0].Scope.OwnerID != ownerID {
		return cloudquote.QuoteV1{}, errors.New("quote not found")
	}
	return fake.quote, nil
}

type entryScopeConnectionFake struct{ connection cloudapp.Connection }

func (fake *entryScopeConnectionFake) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return fake.connection, nil
}

type entryScopeStatusFake struct {
	deployment cloudstatus.Deployment
	resources  []resource.ResourceV1
}

func (fake *entryScopeStatusFake) GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error) {
	return fake.deployment, nil
}
func (fake *entryScopeStatusFake) ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error) {
	return append([]resource.ResourceV1(nil), fake.resources...), nil
}

type entryScopeProviderFactoryFake struct {
	reader awsprovider.EntryScopeReadBackProvider
}

func (fake *entryScopeProviderFactoryFake) EntrypointReadBack(context.Context, cloudapp.Connection) (awsprovider.EntryScopeReadBackProvider, error) {
	return fake.reader, nil
}

type entryScopeReaderFake struct {
	now                time.Time
	worker             awsprovider.EntryWorkerReadBackV1
	certificate        awsprovider.EntryCertificateReadBackV1
	subnets            []awsprovider.EntryPublicSubnetReadBackV1
	workerRequest      awsprovider.EntryWorkerReadBackRequestV1
	certificateRequest awsprovider.EntryCertificateReadBackRequestV1
	subnetsRequest     awsprovider.EntryPublicSubnetsReadBackRequestV1
}

func (fake *entryScopeReaderFake) ReadBackEntryWorker(_ context.Context, request awsprovider.EntryWorkerReadBackRequestV1) (awsprovider.EntryWorkerReadBackV1, error) {
	fake.workerRequest = request
	return fake.worker, nil
}
func (fake *entryScopeReaderFake) ReadBackEntryCertificate(_ context.Context, request awsprovider.EntryCertificateReadBackRequestV1) (awsprovider.EntryCertificateReadBackV1, error) {
	fake.certificateRequest = request
	return fake.certificate, nil
}
func (fake *entryScopeReaderFake) ReadBackEntryPublicSubnets(_ context.Context, request awsprovider.EntryPublicSubnetsReadBackRequestV1) ([]awsprovider.EntryPublicSubnetReadBackV1, error) {
	fake.subnetsRequest = request
	return append([]awsprovider.EntryPublicSubnetReadBackV1(nil), fake.subnets...), nil
}
func (fake *entryScopeReaderFake) advance(now time.Time) {
	fake.worker.ObservedAt, fake.certificate.ObservedAt = now, now
	for index := range fake.subnets {
		fake.subnets[index].ObservedAt = now
	}
}

func entryPersistedQuoteFixture(t *testing.T, now time.Time, plan cloudapproval.PlanV1, draft entrypoint.DraftV1) cloudquote.QuoteV1 {
	t.Helper()
	base, err := expectedEntryQuoteScope(plan, entrypoint.NormalizeDraft(draft))
	if err != nil {
		t.Fatal(err)
	}
	quoted := cloudquote.QuoteV1{SchemaVersion: cloudquote.SchemaV1, QuoteID: uuid.NewString(), QuotedAt: now, ValidUntil: now.Add(15 * time.Minute), Currency: "USD",
		Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730, EntryHours: 730, InternetEgressMiB: 100}, Assumptions: []string{"one-LCU ALB estimate"}, Exclusions: []string{"taxes"}}
	for _, profile := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := base
		scope.Resource.CandidateID = profile
		scopeDigest, err := scope.Digest()
		if err != nil {
			t.Fatal(err)
		}
		items := []cloudquote.CostItemV1{
			entryQuoteCost(cloudquote.CostComputeOnDemand, "exclusive Worker compute", string(profile)+"-compute", 10_000),
			entryQuoteCost(cloudquote.CostEBS, "encrypted EBS", string(profile)+"-ebs", 2_000),
			entryQuoteCost(cloudquote.CostPublicIPv4, "no Worker public IPv4", string(profile)+"-ipv4", 0),
			entryQuoteCost(cloudquote.CostLogs, "CloudWatch logs", string(profile)+"-logs", 500),
			entryQuoteCost(cloudquote.CostSnapshot, "EBS snapshots", string(profile)+"-snapshots", 500),
			entryQuoteCost(cloudquote.CostEntry, "Application Load Balancer hours", string(profile)+"-alb", 1_000),
			entryQuoteCost(cloudquote.CostEntry, "Application Load Balancer one-LCU estimate", string(profile)+"-lcu", 700),
			entryQuoteCost(cloudquote.CostTraffic, "EC2 internet data transfer", string(profile)+"-traffic", 100),
		}
		candidate := cloudquote.CandidateV1{CandidateID: profile, Scope: scope, ScopeDigest: scopeDigest, OfferedAvailabilityZones: append([]string(nil), scope.Resource.AvailabilityZones...),
			Quotas: []cloudquote.QuotaEvidenceV1{{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 1, RequiredUnits: 1}}, CostItems: items}
		for _, item := range items {
			candidate.HourlyEstimateMicros += item.HourlyEstimateMicros
			candidate.MonthlyEstimateMicros += item.MonthlyEstimateMicros
			candidate.MaximumLaunchAmountMicros += item.MaximumLaunchAmountMicros
		}
		quoted.Candidates = append(quoted.Candidates, candidate)
	}
	if err := quoted.Validate(); err != nil {
		t.Fatal(err)
	}
	return quoted
}

func entryQuoteCost(category cloudquote.CostCategory, description, source string, hourly uint64) cloudquote.CostItemV1 {
	return cloudquote.CostItemV1{Category: category, Description: description, SourceID: source, HourlyEstimateMicros: hourly, MonthlyEstimateMicros: hourly * 730, MaximumLaunchAmountMicros: hourly}
}

func entryWorkerTags(agentID, ownerID, taskID, deploymentID, resourceID string, deadline time.Time) map[string]string {
	return map[string]string{resource.TagAgentInstanceID: agentID, resource.TagOwnerID: ownerID, resource.TagTaskID: taskID, resource.TagDeploymentID: deploymentID,
		resource.TagResourceID: resourceID, resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.UTC().Format(time.RFC3339)}
}

func entryTestDigest(fill byte) string { return "sha256:" + strings.Repeat(string(fill), 64) }
