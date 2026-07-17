package app

import (
	"context"
	"math/bits"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudcanonical "github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

// entryScopeFacts contains the immutable initial deployment plan/approval
// facts. It never exposes credentials or a mutable provider surface.
type entryScopeFacts interface {
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error)
	LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
}

type entryScopeConnections interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type entryScopeStatusReader interface {
	GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error)
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
}

// entryScopeProviderFactory is intentionally narrower than the normal
// resource runtime. A scope builder can only request independent entry facts;
// it cannot call Create, Delete, or any arbitrary AWS operation.
type entryScopeProviderFactory interface {
	EntrypointReadBack(context.Context, cloudapp.Connection) (awsprovider.EntryScopeReadBackProvider, error)
}

type entrypointScopeBuilder struct {
	agentInstanceID string
	facts           entryScopeFacts
	connections     entryScopeConnections
	statuses        entryScopeStatusReader
	providers       entryScopeProviderFactory
	now             func() time.Time
}

var _ entrypoint.ScopeBuilder = (*entrypointScopeBuilder)(nil)

func newEntrypointScopeBuilder(agentInstanceID string, facts entryScopeFacts, connections entryScopeConnections, statuses entryScopeStatusReader, providers entryScopeProviderFactory, now func() time.Time) (*entrypointScopeBuilder, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || facts == nil || connections == nil || statuses == nil || providers == nil || now == nil {
		return nil, entrypoint.ErrInvalid
	}
	return &entrypointScopeBuilder{agentInstanceID: parsed.String(), facts: facts, connections: connections, statuses: statuses, providers: providers, now: now}, nil
}

func (builder *entrypointScopeBuilder) BuildEntryScope(ctx context.Context, request entrypoint.ScopeBuildRequest) (entrypoint.ScopeV1, error) {
	if builder == nil || ctx == nil || request.AgentInstanceID != builder.agentInstanceID || request.Draft.Validate() != nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrInvalid
	}
	return builder.build(ctx, request.OwnerID, request.DeploymentID, request.ExpectedDeploymentRevision, entrypoint.NormalizeDraft(request.Draft))
}

func (builder *entrypointScopeBuilder) RevalidateEntryScope(ctx context.Context, signed entrypoint.ScopeV1) (entrypoint.ScopeV1, error) {
	if builder == nil || ctx == nil || signed.Validate() != nil || signed.AgentInstanceID != builder.agentInstanceID {
		return entrypoint.ScopeV1{}, entrypoint.ErrInvalid
	}
	// Rebuild only from the signed safe intent; the Worker/ALB target and
	// ownership tags are always re-read from PostgreSQL and AWS below.
	draft := entrypoint.DraftV1{Hostname: signed.Certificate.Hostname, CertificateARN: signed.Certificate.CertificateARN,
		TargetPort: signed.ALB.TargetPort, HealthPath: signed.Health.Path, ExpectedHealthStatusCode: signed.Health.ExpectedStatusCode,
		RecipeHealthContractDigest: signed.Recipe.HealthContractDigest, RecipeAuthenticationDigest: signed.Recipe.AuthenticationContractDigest, Cost: signed.Cost}
	for _, subnet := range signed.ALB.PublicSubnets {
		draft.PublicSubnetIDs = append(draft.PublicSubnetIDs, subnet.SubnetID)
	}
	return builder.build(ctx, signed.OwnerID, signed.Worker.DeploymentID, signed.Worker.DeploymentRevision, entrypoint.NormalizeDraft(draft))
}

func (builder *entrypointScopeBuilder) build(ctx context.Context, ownerID, deploymentID string, expectedRevision int64, draft entrypoint.DraftV1) (entrypoint.ScopeV1, error) {
	if strings.TrimSpace(ownerID) == "" || !validEntryUUID(deploymentID) || expectedRevision < 1 || draft.Validate() != nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrInvalid
	}
	now := builder.now().UTC()
	if !now.Before(draft.Cost.ValidUntil.UTC()) {
		return entrypoint.ScopeV1{}, entrypoint.ErrApprovalExpired
	}
	deployment, err := builder.statuses.GetDeployment(ctx, ownerID, deploymentID)
	if err != nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	if deployment.Worker.DeploymentID != deploymentID || deployment.Worker.OwnerID != ownerID || deployment.Worker.Revision != expectedRevision ||
		deployment.Worker.State != worker.StateFinished || deployment.Worker.Outcome != worker.OutcomeSucceeded || !deployment.Worker.UpdatedAt.UTC().After(time.Time{}) ||
		!validEntryUUID(deployment.PlanID) || !validEntryUUID(deployment.ConnectionID) {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	plan, err := builder.facts.LoadPlan(ctx, ownerID, deployment.PlanID)
	if err != nil || plan.Validate() != nil || plan.Status != cloudapproval.PlanApproved || plan.AgentInstanceID != builder.agentInstanceID ||
		plan.OwnerID != ownerID || plan.PlanID != deployment.PlanID || plan.ConnectionID != deployment.ConnectionID || plan.ResourceScope.Region == "" {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	planHash, err := plan.Hash()
	if err != nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	trustedCost, err := builder.readEntryCost(ctx, ownerID, plan, draft, now)
	if err != nil {
		return entrypoint.ScopeV1{}, err
	}
	resources, err := builder.statuses.ListDeploymentResources(ctx, ownerID, deploymentID)
	if err != nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	workerResource, groupResource, ok := entryWorkerResources(resources, builder.agentInstanceID, ownerID, deployment, planHash)
	if !ok {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	approval, err := builder.facts.LoadApproval(ctx, ownerID, workerResource.ApprovalID)
	if err != nil || approval.Validate() != nil || !entryApprovalMatchesPlan(approval, plan, planHash) ||
		groupResource.ApprovalID != approval.ApprovalID || groupResource.ApprovedPlanHash != planHash {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	connection, err := builder.connections.LoadConnection(ctx, ownerID, deployment.ConnectionID)
	if err != nil || connection.ConnectionID != deployment.ConnectionID || connection.OwnerID != ownerID || connection.Status != "active" ||
		connection.Region != plan.ResourceScope.Region || connection.AccountID == "" {
		return entrypoint.ScopeV1{}, entrypoint.ErrReadBackRequired
	}
	provider, err := builder.providers.EntrypointReadBack(ctx, connection)
	if err != nil || provider == nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrReadBackRequired
	}
	workerFact, err := provider.ReadBackEntryWorker(ctx, awsprovider.EntryWorkerReadBackRequestV1{
		InstanceID: workerResource.ProviderID, ExpectedInstanceTags: cloneEntryTags(workerResource.Tags), ExpectedSecurityGroupTags: cloneEntryTags(groupResource.Tags),
	})
	if err != nil || workerFact.InstanceID != workerResource.ProviderID || workerFact.Region != plan.ResourceScope.Region || workerFact.AccountID != connection.AccountID ||
		workerFact.VPCID != plan.NetworkScope.VPCID || workerFact.SubnetID != plan.NetworkScope.SubnetID || workerFact.SecurityGroupID != groupResource.ProviderID || workerFact.ObservedAt.IsZero() {
		return entrypoint.ScopeV1{}, entrypoint.ErrReadBackRequired
	}
	certificateFact, err := provider.ReadBackEntryCertificate(ctx, awsprovider.EntryCertificateReadBackRequestV1{CertificateARN: draft.CertificateARN, Hostname: draft.Hostname})
	if err != nil || certificateFact.Region != plan.ResourceScope.Region || certificateFact.Status != awsprovider.EntryCertificateStatusIssued || certificateFact.ObservedAt.IsZero() {
		return entrypoint.ScopeV1{}, entrypoint.ErrReadBackRequired
	}
	subnets, err := provider.ReadBackEntryPublicSubnets(ctx, awsprovider.EntryPublicSubnetsReadBackRequestV1{WorkerVPCID: workerFact.VPCID, SubnetIDs: append([]string(nil), draft.PublicSubnetIDs...)})
	if err != nil || len(subnets) != len(draft.PublicSubnetIDs) {
		return entrypoint.ScopeV1{}, entrypoint.ErrReadBackRequired
	}
	retention, ok := entryRetention(workerResource, groupResource)
	if !ok {
		return entrypoint.ScopeV1{}, entrypoint.ErrWorkerNotReady
	}
	result := entrypoint.ScopeV1{
		SchemaVersion: entrypoint.ScopeSchemaV1, Kind: entrypoint.EntryKindALB, AgentInstanceID: builder.agentInstanceID, OwnerID: ownerID,
		ConnectionID: deployment.ConnectionID, Region: plan.ResourceScope.Region,
		Worker: entrypoint.WorkerReadBackScopeV1{DeploymentID: deploymentID, DeploymentRevision: deployment.Worker.Revision, TaskID: deployment.Worker.TaskID,
			OriginalPlanID: plan.PlanID, OriginalPlanHash: planHash, OriginalApprovalID: approval.ApprovalID, WorkerResourceID: workerResource.ResourceID,
			WorkerResourceRevision: workerResource.Revision, WorkerSpecDigest: workerResource.SpecDigest, InstanceID: workerFact.InstanceID, VPCID: workerFact.VPCID,
			SubnetID: workerFact.SubnetID, SecurityGroupID: workerFact.SecurityGroupID, ExecutionOutcome: entrypoint.WorkerOutcomeSucceeded,
			SucceededAt: deployment.Worker.UpdatedAt.UTC(), ReadBack: entrypoint.AWSReadBackV1{Observed: true, Exists: true, State: entrypoint.EC2InstanceRunning,
				ObservedAt: workerFact.ObservedAt.UTC(), TagDigest: workerFact.OwnershipDigest}, Retention: retention},
		Recipe: entrypoint.RecipeHealthBindingV1{RecipeDigest: plan.Recipe.Digest, HealthContractDigest: draft.RecipeHealthContractDigest, AuthenticationContractDigest: draft.RecipeAuthenticationDigest},
		Certificate: entrypoint.CertificateScopeV1{CertificateARN: certificateFact.CertificateARN, Region: certificateFact.Region, Hostname: certificateFact.Hostname,
			SubjectAlternativeNames: append([]string(nil), certificateFact.SubjectAlternativeNames...), Status: entrypoint.CertificateStatusIssued,
			ReadBackDigest: certificateFact.ReadBackDigest, ObservedAt: certificateFact.ObservedAt.UTC()},
		ALB: entrypoint.ALBScopeV1{Scheme: entrypoint.ALBSchemeInternetFacing, ListenerPort: entrypoint.HTTPSPort, ListenerProtocol: entrypoint.ListenerProtocolHTTPS,
			TLSPolicy: entrypoint.TLSPolicyTLS13_2021_06, IngressCIDRs: []string{"0.0.0.0/0"}, TargetProtocol: entrypoint.TargetProtocolHTTP,
			TargetPort: draft.TargetPort, TargetSource: entrypoint.TargetSourceApprovedWorkerReadBack, WorkerPublicIPv4: false, EIPRequested: false,
			PublicSubnets: entryPublicSubnets(subnets)},
		Health:         entrypoint.HealthRouteScopeV1{Path: draft.HealthPath, ExpectedStatusCode: draft.ExpectedHealthStatusCode, EvidenceDigest: draft.RecipeHealthContractDigest, NoCredentialRoute: true},
		Authentication: entrypoint.AuthenticationScopeV1{Required: true, ContractDigest: draft.RecipeAuthenticationDigest}, Cost: trustedCost, Retention: retention,
	}
	if result.Validate() != nil {
		return entrypoint.ScopeV1{}, entrypoint.ErrReadBackRequired
	}
	return result, nil
}

func entryWorkerResources(resources []resource.ResourceV1, agentInstanceID, ownerID string, deployment cloudstatus.Deployment, planHash string) (resource.ResourceV1, resource.ResourceV1, bool) {
	var workerResource, groupResource resource.ResourceV1
	for _, item := range resources {
		switch {
		case item.Type == resource.TypeEC2 && item.LogicalName == "exclusive-cloud-worker":
			if workerResource.ResourceID != "" || !validEntryWorkerResource(item, agentInstanceID, ownerID, deployment, planHash) {
				return resource.ResourceV1{}, resource.ResourceV1{}, false
			}
			workerResource = item
		case item.Type == resource.TypeSG && item.LogicalName == "worker-security-group":
			if groupResource.ResourceID != "" || !validEntryWorkerResource(item, agentInstanceID, ownerID, deployment, planHash) {
				return resource.ResourceV1{}, resource.ResourceV1{}, false
			}
			groupResource = item
		}
	}
	if workerResource.ResourceID == "" || groupResource.ResourceID == "" || workerResource.ApprovalID == "" || workerResource.ApprovalID != groupResource.ApprovalID ||
		deployment.Worker.ProviderInstanceID != "" && deployment.Worker.ProviderInstanceID != workerResource.ProviderID {
		return resource.ResourceV1{}, resource.ResourceV1{}, false
	}
	return workerResource, groupResource, true
}

func validEntryWorkerResource(item resource.ResourceV1, agentInstanceID, ownerID string, deployment cloudstatus.Deployment, planHash string) bool {
	return item.AgentInstanceID == agentInstanceID && item.OwnerID == ownerID && item.DeploymentID == deployment.Worker.DeploymentID && item.TaskID == deployment.Worker.TaskID &&
		item.ApprovedPlanHash == planHash && item.ProviderID != "" && (item.State == resource.StateActive || item.State == resource.StateRetainedManaged) &&
		!item.ReadBack.ObservedAt.IsZero() && item.ReadBack.ProviderID == item.ProviderID
}

func entryApprovalMatchesPlan(approval cloudapproval.ApprovalV1, plan cloudapproval.PlanV1, planHash string) bool {
	return approval.AgentInstanceID == plan.AgentInstanceID && approval.OwnerID == plan.OwnerID && approval.PlanID == plan.PlanID &&
		approval.PlanRevision == plan.Revision && approval.PlanHash == planHash && approval.ConnectionID == plan.ConnectionID &&
		approval.RecipeDigest == plan.Recipe.Digest && approval.QuoteID == plan.Quote.QuoteID && approval.QuoteDigest == plan.Quote.Digest &&
		approval.QuoteScopeDigest == plan.Quote.ScopeDigest && approval.QuoteCandidateID == plan.Quote.CandidateID
}

func entryRetention(workerResource, groupResource resource.ResourceV1) (entrypoint.RetentionScopeV1, bool) {
	if workerResource.Retention != groupResource.Retention || workerResource.AutoDestroyApproved != groupResource.AutoDestroyApproved ||
		!workerResource.DestroyDeadline.UTC().Equal(groupResource.DestroyDeadline.UTC()) {
		return entrypoint.RetentionScopeV1{}, false
	}
	switch workerResource.Retention {
	case task.RetentionEphemeralAutoDestroy:
		if !workerResource.AutoDestroyApproved || workerResource.DestroyDeadline.IsZero() || workerResource.State != resource.StateActive || groupResource.State != resource.StateActive {
			return entrypoint.RetentionScopeV1{}, false
		}
		return entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: workerResource.DestroyDeadline.UTC()}, true
	case task.RetentionManaged:
		if workerResource.AutoDestroyApproved || !workerResource.DestroyDeadline.IsZero() || workerResource.State != resource.StateRetainedManaged || groupResource.State != resource.StateRetainedManaged {
			return entrypoint.RetentionScopeV1{}, false
		}
		return entrypoint.RetentionScopeV1{Class: entrypoint.RetentionManaged}, true
	default:
		return entrypoint.RetentionScopeV1{}, false
	}
}

func entryPublicSubnets(values []awsprovider.EntryPublicSubnetReadBackV1) []entrypoint.PublicSubnetScopeV1 {
	result := make([]entrypoint.PublicSubnetScopeV1, 0, len(values))
	for _, value := range values {
		result = append(result, entrypoint.PublicSubnetScopeV1{SubnetID: value.SubnetID, VPCID: value.VPCID, AvailabilityZone: value.AvailabilityZone,
			Public: value.Public, ReadBackDigest: value.ReadBackDigest, ObservedAt: value.ObservedAt.UTC()})
	}
	return result
}

func cloneEntryTags(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func validEntryUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil
}

// readEntryCost makes the persisted generic AWS quote the sole authority for
// ALB, LCU, and traffic estimates. The client only echoes that quote in the
// draft so stale or altered UI data cannot lower the device-approved scope.
func (builder *entrypointScopeBuilder) readEntryCost(ctx context.Context, ownerID string, plan cloudapproval.PlanV1, draft entrypoint.DraftV1, now time.Time) (entrypoint.EntryCostScopeV1, error) {
	quoted, err := builder.facts.LoadQuote(ctx, ownerID, draft.Cost.QuoteID)
	if err != nil || quoted.Validate() != nil || quoted.QuoteID != draft.Cost.QuoteID {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	if !now.Before(quoted.ValidUntil.UTC()) {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrApprovalExpired
	}
	quoteDigest, err := quoted.Digest()
	if err != nil || quoteDigest != draft.Cost.QuoteDigest {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	candidate, found := quoted.Candidate(cloudquote.CandidateProfile(plan.Quote.CandidateID))
	if !found {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	expectedScope, err := expectedEntryQuoteScope(plan, draft)
	if err != nil {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	expectedScopeDigest, err := expectedScope.Digest()
	if err != nil || candidate.ScopeDigest != expectedScopeDigest {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	cost, err := entryCostFromPersistedQuote(quoted, quoteDigest, candidate)
	if err != nil || !sameEntryCost(draft.Cost, cost) {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	return cost, nil
}

func expectedEntryQuoteScope(plan cloudapproval.PlanV1, draft entrypoint.DraftV1) (cloudquote.ScopeV1, error) {
	scope := plan.PricingScope()
	if scope.Network.VPCID == "" || scope.Network.SubnetID == "" || scope.Network.SecurityGroupMode != cloudquote.SecurityGroupCreateDedicated || scope.Network.SecurityGroupID != "" {
		return cloudquote.ScopeV1{}, entrypoint.ErrInvalid
	}
	scope.Network.PublicIPv4 = false
	scope.Network.EntryPoint = cloudquote.EntryPointALB
	scope.Network.PublicExposure = true
	scope.Network.IngressPorts = []uint32{entrypoint.HTTPSPort}
	scope.Network.Hostname = draft.Hostname
	scope.Network.TLSRequired = true
	scope.Network.AuthenticationRequired = true
	if scope.Validate() != nil {
		return cloudquote.ScopeV1{}, entrypoint.ErrInvalid
	}
	return scope, nil
}

type entryQuoteAssumptionsV1 struct {
	QuoteID         string                      `json:"quote_id"`
	QuoteDigest     string                      `json:"quote_digest"`
	CandidateID     cloudquote.CandidateProfile `json:"candidate_id"`
	ScopeDigest     string                      `json:"scope_digest"`
	Usage           cloudquote.UsageV1          `json:"usage"`
	Assumptions     []string                    `json:"assumptions"`
	Exclusions      []string                    `json:"exclusions"`
	CostSourceIDs   []string                    `json:"cost_source_ids"`
	LCUMilliUnits   uint32                      `json:"lcu_milli_units"`
	TrafficEstimate string                      `json:"traffic_estimate"`
}

func entryCostFromPersistedQuote(quoted cloudquote.QuoteV1, quoteDigest string, candidate cloudquote.CandidateV1) (entrypoint.EntryCostScopeV1, error) {
	const (
		albDescription = "Application Load Balancer hours"
		lcuDescription = "Application Load Balancer one-LCU estimate"
	)
	trafficDescription := "EC2 internet data transfer"
	if quoted.Usage.InternetEgressMiB == 0 {
		trafficDescription = "no internet egress requested"
	}
	var alb, lcu, traffic cloudquote.CostItemV1
	for _, item := range candidate.CostItems {
		switch {
		case item.Category == cloudquote.CostEntry && item.Description == albDescription:
			if alb.SourceID != "" {
				return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
			}
			alb = item
		case item.Category == cloudquote.CostEntry && item.Description == lcuDescription:
			if lcu.SourceID != "" {
				return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
			}
			lcu = item
		case item.Category == cloudquote.CostTraffic && item.Description == trafficDescription:
			if traffic.SourceID != "" {
				return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
			}
			traffic = item
		}
	}
	if alb.SourceID == "" || lcu.SourceID == "" || traffic.SourceID == "" || alb.HourlyEstimateMicros == 0 || lcu.HourlyEstimateMicros == 0 {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	maximum, carry := bits.Add64(alb.MaximumLaunchAmountMicros, lcu.MaximumLaunchAmountMicros, 0)
	if carry != 0 {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	maximum, carry = bits.Add64(maximum, traffic.MaximumLaunchAmountMicros, 0)
	if carry != 0 || maximum == 0 {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	sources := []string{alb.SourceID, lcu.SourceID, traffic.SourceID}
	slices.Sort(sources)
	assumptions := append([]string(nil), quoted.Assumptions...)
	exclusions := append([]string(nil), quoted.Exclusions...)
	slices.Sort(assumptions)
	slices.Sort(exclusions)
	assumptionsDigest, err := cloudcanonical.Digest(entryQuoteAssumptionsV1{
		QuoteID: quoted.QuoteID, QuoteDigest: quoteDigest, CandidateID: candidate.CandidateID, ScopeDigest: candidate.ScopeDigest,
		Usage: quoted.Usage, Assumptions: assumptions, Exclusions: exclusions, CostSourceIDs: sources, LCUMilliUnits: 1000, TrafficEstimate: traffic.Description,
	})
	if err != nil {
		return entrypoint.EntryCostScopeV1{}, entrypoint.ErrInvalid
	}
	return entrypoint.EntryCostScopeV1{
		QuoteID: quoted.QuoteID, QuoteDigest: quoteDigest, Currency: quoted.Currency, QuotedAt: quoted.QuotedAt.UTC(), ValidUntil: quoted.ValidUntil.UTC(),
		ALBHourlyEstimateMicros: alb.HourlyEstimateMicros, LCUHourlyEstimateMicros: lcu.HourlyEstimateMicros, EstimatedLCUMilliUnits: 1000,
		EstimatedEgressMiB: quoted.Usage.InternetEgressMiB, TrafficEstimateMicros: traffic.HourlyEstimateMicros,
		MaximumLaunchAmountMicros: maximum, AssumptionsDigest: assumptionsDigest,
	}, nil
}

func sameEntryCost(left, right entrypoint.EntryCostScopeV1) bool {
	return left.QuoteID == right.QuoteID && left.QuoteDigest == right.QuoteDigest && left.Currency == right.Currency &&
		left.QuotedAt.UTC().Equal(right.QuotedAt.UTC()) && left.ValidUntil.UTC().Equal(right.ValidUntil.UTC()) &&
		left.ALBHourlyEstimateMicros == right.ALBHourlyEstimateMicros && left.LCUHourlyEstimateMicros == right.LCUHourlyEstimateMicros &&
		left.EstimatedLCUMilliUnits == right.EstimatedLCUMilliUnits && left.EstimatedEgressMiB == right.EstimatedEgressMiB &&
		left.TrafficEstimateMicros == right.TrafficEstimateMicros && left.MaximumLaunchAmountMicros == right.MaximumLaunchAmountMicros &&
		left.AssumptionsDigest == right.AssumptionsDigest
}
