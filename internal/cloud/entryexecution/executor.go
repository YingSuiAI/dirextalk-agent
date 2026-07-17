// Package entryexecution reconciles separately device-approved public ALB
// entry operations.  It intentionally owns no AWS SDK client: the only cloud
// mutation port is the existing typed resource provisioner.
package entryexecution

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	defaultBatchSize    = 32
	defaultPollInterval = 10 * time.Second

	entrySecurityGroupLogicalName = "entry-alb-security-group"
	entryBridgeLogicalName        = "entry-worker-ingress-bridge"
	entryTargetGroupLogicalName   = "entry-target-group"
	entryLoadBalancerLogicalName  = "entry-application-load-balancer"
	entryListenerLogicalName      = "entry-https-listener"
)

// PlanResolver is deliberately operation-scoped.  Pending operations are a
// cross-owner recovery queue, while the public entrypoint repository correctly
// requires an owner for ordinary reads.  A control-plane-only adapter resolves
// the immutable approved plan without exposing an unscoped caller API.
type PlanResolver interface {
	ResolveApprovedPlan(context.Context, string) (entrypoint.PlanV1, error)
}

// OperationRepository is the durable, revision-fenced recovery queue.  It is
// a strict subset of entrypoint.Repository so the executor cannot prepare or
// approve a public entry operation.
type OperationRepository interface {
	ListPendingEntry(context.Context, int) ([]entrypoint.OperationV1, error)
	SaveEntryOperation(context.Context, entrypoint.OperationV1, int64) (entrypoint.OperationV1, error)
}

// ScopeRevalidator independently rebuilds the signed Worker, certificate and
// subnet facts immediately before a typed resource transition.
type ScopeRevalidator interface {
	RevalidateScope(context.Context, entrypoint.ScopeV1) error
}

// DeploymentResourceReader reads the durable resource ledger.  It supplies
// the exact existing Worker security-group resource identity required by the
// typed SG bridge; it is never a source of Worker URLs, logs or public IPs.
type DeploymentResourceReader interface {
	ListDeployment(context.Context, string) ([]resource.ResourceV1, error)
}

// ResourceProvisioner is deliberately the already-fenced typed provisioner.
// It has no general AWS API and no shell capability.
type ResourceProvisioner interface {
	Provision(context.Context, resource.ProvisionSpec, resource.ProviderCreateAuthorization) (resource.ResourceV1, error)
}

// Runner is the injectable controller surface used by application composition.
// NotifyEntrypoint satisfies entrypoint.Notifier and never blocks an approval
// request on an executor scan.
type Runner interface {
	entrypoint.Notifier
	Run(context.Context) error
	RunOnce(context.Context) error
}

// Config supplies only the narrow durable and typed ports required by an
// entrypoint reconciler.  No AWS SDK client is accepted here.
type Config struct {
	Operations OperationRepository
	Plans      PlanResolver
	Scopes     ScopeRevalidator
	Resources  DeploymentResourceReader
	Provision  ResourceProvisioner

	BatchSize    int
	PollInterval time.Duration
	Now          func() time.Time
}

// Executor restores progress after process restart.  The resource service
// records every mutation intent and uses deterministic ClientTokens, so
// repeating a provision request is reconciliation rather than a duplicate
// cloud purchase.
type Executor struct {
	operations OperationRepository
	plans      PlanResolver
	scopes     ScopeRevalidator
	resources  DeploymentResourceReader
	provision  ResourceProvisioner

	batchSize    int
	pollInterval time.Duration
	now          func() time.Time
	wake         chan struct{}
}

// NewExecutor creates a recoverable public-entry controller.
func NewExecutor(config Config) (*Executor, error) {
	if config.Operations == nil || config.Plans == nil || config.Scopes == nil || config.Resources == nil || config.Provision == nil {
		return nil, entrypoint.ErrInvalid
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaultBatchSize
	}
	if config.BatchSize < 1 || config.BatchSize > 256 {
		return nil, entrypoint.ErrInvalid
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.PollInterval < time.Second || config.PollInterval > time.Hour {
		return nil, entrypoint.ErrInvalid
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Executor{
		operations: config.Operations, plans: config.Plans, scopes: config.Scopes, resources: config.Resources, provision: config.Provision,
		batchSize: config.BatchSize, pollInterval: config.PollInterval, now: config.Now, wake: make(chan struct{}, 1),
	}, nil
}

// NotifyEntrypoint wakes a running controller after a successful approval. It
// is non-blocking so database/RPC approval never depends on background work.
func (executor *Executor) NotifyEntrypoint() {
	if executor == nil {
		return
	}
	select {
	case executor.wake <- struct{}{}:
	default:
	}
}

// Run continuously scans durable approved/provisioning/verifying operations.
// Per-operation permanent failures are persisted as de-sensitized public
// states. Transient repository or response-loss reconciliation failures wait
// for the next wake/poll rather than terminating the Agent process.
func (executor *Executor) Run(ctx context.Context) error {
	if executor == nil || ctx == nil {
		return entrypoint.ErrInvalid
	}
	ticker := time.NewTicker(executor.pollInterval)
	defer ticker.Stop()
	for {
		_ = executor.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-executor.wake:
		case <-ticker.C:
		}
	}
}

// RunOnce is the deterministic recovery seam used by startup and focused
// tests. It returns only a queue/system error; a permanent individual
// operation error is recorded in the operation and does not starve later work.
func (executor *Executor) RunOnce(ctx context.Context) error {
	if executor == nil || ctx == nil {
		return entrypoint.ErrInvalid
	}
	operations, err := executor.operations.ListPendingEntry(ctx, executor.batchSize)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := executor.reconcile(ctx, operation); err != nil {
			if errors.Is(err, entrypoint.ErrRevisionConflict) || errors.Is(err, entrypoint.ErrNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

func (executor *Executor) reconcile(ctx context.Context, operation entrypoint.OperationV1) error {
	if err := operation.Validate(); err != nil {
		return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
	}
	if operation.Status != entrypoint.StatusApproved && operation.Status != entrypoint.StatusProvisioning && operation.Status != entrypoint.StatusVerifying {
		return nil
	}
	plan, err := executor.plans.ResolveApprovedPlan(ctx, operation.Challenge.OperationID)
	if err != nil {
		if errors.Is(err, entrypoint.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
	}
	if err := validOperationPlan(operation, plan); err != nil {
		return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
	}

	if operation.Status == entrypoint.StatusApproved {
		if err := executor.scopes.RevalidateScope(ctx, plan.Scope); err != nil {
			return executor.failScope(ctx, operation, err)
		}
		operation, err = executor.transition(ctx, operation, entrypoint.StatusProvisioning)
		if err != nil {
			return err
		}
	}

	bindings, err := executor.bindWorkerResources(ctx, plan.Scope)
	if err != nil {
		if errors.Is(err, entrypoint.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return executor.failBinding(ctx, operation, err)
	}
	specs, err := resourceSpecs(operation, plan, bindings)
	if err != nil {
		return executor.fail(ctx, operation, entrypoint.ErrorCodeProvisioningFailed, summaryProvisioningFailed)
	}

	if operation.Status == entrypoint.StatusProvisioning {
		authorization := resource.ProviderCreateAuthorization{ApprovalExpiresAt: operation.Challenge.ExpiresAt, QuoteValidUntil: plan.Scope.Cost.ValidUntil}
		for _, spec := range specs {
			// Revalidation is intentionally immediately before every typed
			// provision call. The provisioner itself fences its durable intent
			// before the provider mutation.
			if err := executor.scopes.RevalidateScope(ctx, plan.Scope); err != nil {
				return executor.failScope(ctx, operation, err)
			}
			created, provisionErr := executor.provision.Provision(ctx, spec, authorization)
			if provisionErr != nil {
				if errors.Is(provisionErr, resource.ErrCreateAmbiguous) || errors.Is(provisionErr, resource.ErrRevisionConflict) ||
					errors.Is(provisionErr, context.Canceled) || errors.Is(provisionErr, context.DeadlineExceeded) {
					return provisionErr
				}
				if errors.Is(provisionErr, resource.ErrCreateAuthorizationExpired) {
					return executor.fail(ctx, operation, expiredCode(plan.Scope, executor.now()), summaryAuthorizationExpired)
				}
				return executor.fail(ctx, operation, entrypoint.ErrorCodeProvisioningFailed, summaryProvisioningFailed)
			}
			if !matchesProvisionedResource(created, spec) {
				return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
			}
		}
		operation, err = executor.transition(ctx, operation, entrypoint.StatusVerifying)
		if err != nil {
			return err
		}
	}

	if operation.Status == entrypoint.StatusVerifying {
		if err := executor.scopes.RevalidateScope(ctx, plan.Scope); err != nil {
			return executor.failScope(ctx, operation, err)
		}
		if err := executor.verifyDurableGraph(ctx, plan.Scope, specs); err != nil {
			if errors.Is(err, entrypoint.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return executor.fail(ctx, operation, entrypoint.ErrorCodeVerificationFailed, summaryVerificationFailed)
		}
		_, err = executor.transition(ctx, operation, entrypoint.StatusActive)
		return err
	}
	return nil
}

func validOperationPlan(operation entrypoint.OperationV1, plan entrypoint.PlanV1) error {
	if plan.Validate() != nil || plan.Status != entrypoint.PlanApproved || operation.Challenge.ValidateAgainstPlan(plan) != nil ||
		operation.Challenge.EntryPlanID != plan.EntryPlanID || operation.Challenge.ScopeDigest != plan.ScopeDigest {
		return entrypoint.ErrRevisionConflict
	}
	return nil
}

func (executor *Executor) bindWorkerResources(ctx context.Context, scope entrypoint.ScopeV1) (workerBindings, error) {
	resources, err := executor.resources.ListDeployment(ctx, scope.Worker.DeploymentID)
	if err != nil {
		return workerBindings{}, err
	}
	var worker resource.ResourceV1
	workerFound := false
	var securityGroup resource.ResourceV1
	securityGroupCount := 0
	for _, item := range resources {
		if item.ResourceID == scope.Worker.WorkerResourceID {
			if workerFound {
				return workerBindings{}, entrypoint.ErrReadBackRequired
			}
			worker, workerFound = item, true
		}
		if item.Type == resource.TypeSG && item.ProviderID == scope.Worker.SecurityGroupID && item.State != resource.StateVerifiedDestroyed {
			securityGroup, securityGroupCount = item, securityGroupCount+1
		}
		if item.Type == resource.TypeEIP && item.State != resource.StateVerifiedDestroyed {
			// Public entry scopes explicitly prohibit an EIP. Do not infer which
			// interface it might be attached to: a competing public address is
			// an unsafe deployment state until independently remediated.
			return workerBindings{}, entrypoint.ErrReadBackRequired
		}
	}
	if !workerFound || !matchesExistingWorker(worker, scope) {
		return workerBindings{}, entrypoint.ErrWorkerNotReady
	}
	if securityGroupCount != 1 || !matchesExistingWorkerSecurityGroup(securityGroup, scope) {
		return workerBindings{}, entrypoint.ErrReadBackRequired
	}
	return workerBindings{worker: worker, securityGroup: securityGroup}, nil
}

type workerBindings struct {
	worker        resource.ResourceV1
	securityGroup resource.ResourceV1
}

func matchesExistingWorker(item resource.ResourceV1, scope entrypoint.ScopeV1) bool {
	return item.ResourceID == scope.Worker.WorkerResourceID && item.AgentInstanceID == scope.AgentInstanceID && item.OwnerID == scope.OwnerID &&
		item.TaskID == scope.Worker.TaskID && item.DeploymentID == scope.Worker.DeploymentID && item.Type == resource.TypeEC2 &&
		item.Region == scope.Region && item.SpecDigest == scope.Worker.WorkerSpecDigest && item.ApprovedPlanHash == scope.Worker.OriginalPlanHash &&
		item.ApprovalID == scope.Worker.OriginalApprovalID && item.ProviderID == scope.Worker.InstanceID && item.ReadBack.Exists &&
		item.ReadBack.ProviderID == scope.Worker.InstanceID && item.ReadBack.TagDigest == scope.Worker.ReadBack.TagDigest && item.Revision == scope.Worker.WorkerResourceRevision &&
		activeState(item.State) && sameRetention(item, scope.Retention) && matchingTags(item, scope)
}

func matchesExistingWorkerSecurityGroup(item resource.ResourceV1, scope entrypoint.ScopeV1) bool {
	return item.AgentInstanceID == scope.AgentInstanceID && item.OwnerID == scope.OwnerID && item.TaskID == scope.Worker.TaskID &&
		item.DeploymentID == scope.Worker.DeploymentID && item.Type == resource.TypeSG && item.Region == scope.Region &&
		item.ApprovedPlanHash == scope.Worker.OriginalPlanHash && item.ApprovalID == scope.Worker.OriginalApprovalID &&
		item.ProviderID == scope.Worker.SecurityGroupID && item.ReadBack.Exists && item.ReadBack.ProviderID == scope.Worker.SecurityGroupID &&
		activeState(item.State) && sameRetention(item, scope.Retention) && matchingTags(item, scope)
}

func matchingTags(item resource.ResourceV1, scope entrypoint.ScopeV1) bool {
	deadline := "managed"
	if !scope.Retention.DestroyDeadline.IsZero() {
		deadline = scope.Retention.DestroyDeadline.UTC().Format(time.RFC3339)
	}
	return item.Tags[resource.TagAgentInstanceID] == scope.AgentInstanceID && item.Tags[resource.TagOwnerID] == scope.OwnerID &&
		item.Tags[resource.TagTaskID] == scope.Worker.TaskID && item.Tags[resource.TagDeploymentID] == scope.Worker.DeploymentID &&
		item.Tags[resource.TagResourceID] == item.ResourceID &&
		item.Tags[resource.TagRetention] == string(retentionPolicy(scope.Retention)) && item.Tags[resource.TagDestroyDeadline] == deadline
}

func activeState(value resource.State) bool {
	return value == resource.StateActive || value == resource.StateRetainedManaged
}

func sameRetention(item resource.ResourceV1, scope entrypoint.RetentionScopeV1) bool {
	want := retentionPolicy(scope)
	if item.Retention != want || item.AutoDestroyApproved != scope.AutoDestroy {
		return false
	}
	if want == task.RetentionEphemeralAutoDestroy {
		return item.DestroyDeadline.Equal(scope.DestroyDeadline.UTC())
	}
	return item.DestroyDeadline.IsZero()
}

func retentionPolicy(scope entrypoint.RetentionScopeV1) task.RetentionPolicy {
	if scope.Class == entrypoint.RetentionEphemeral {
		return task.RetentionEphemeralAutoDestroy
	}
	return task.RetentionManaged
}

func resourceSpecs(operation entrypoint.OperationV1, plan entrypoint.PlanV1, bindings workerBindings) ([]resource.ProvisionSpec, error) {
	scope := plan.Scope
	entryPlanHash, err := plan.Hash()
	if operation.Challenge.OperationID == "" || plan.Validate() != nil || plan.Status != entrypoint.PlanApproved ||
		err != nil || entryPlanHash != operation.Challenge.PlanHash || operation.Challenge.EntryPlanID != plan.EntryPlanID ||
		scope.Validate() != nil || !matchesExistingWorker(bindings.worker, scope) || !matchesExistingWorkerSecurityGroup(bindings.securityGroup, scope) {
		return nil, entrypoint.ErrInvalid
	}
	retention := retentionPolicy(scope.Retention)
	common := resource.ProvisionSpec{
		AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, TaskID: scope.Worker.TaskID, DeploymentID: scope.Worker.DeploymentID,
		// New public-entry resources are authorized by the separate entry plan
		// and device approval, not by the historical Worker purchase approval.
		// The latter remains solely an immutable check on bindings.worker above.
		Region: scope.Region, ApprovedPlanHash: entryPlanHash, ApprovalID: operation.Challenge.ApprovalID,
		Retention: retention, DestroyDeadline: scope.Retention.DestroyDeadline.UTC(), AutoDestroyApproved: scope.Retention.AutoDestroy,
	}

	albSecurityGroupID := entryResourceID(scope.AgentInstanceID, operation.Challenge.OperationID, entrySecurityGroupLogicalName)
	bridgeID := entryResourceID(scope.AgentInstanceID, operation.Challenge.OperationID, entryBridgeLogicalName)
	targetGroupID := entryResourceID(scope.AgentInstanceID, operation.Challenge.OperationID, entryTargetGroupLogicalName)
	loadBalancerID := entryResourceID(scope.AgentInstanceID, operation.Challenge.OperationID, entryLoadBalancerLogicalName)
	listenerID := entryResourceID(scope.AgentInstanceID, operation.Challenge.OperationID, entryListenerLogicalName)

	targetPort := uint16(scope.ALB.TargetPort)
	groupAWS := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, SecurityGroup: &resource.AWSSecurityGroupSpecV1{
		VPCID: scope.Worker.VPCID, Description: "Dirextalk approved public ALB entry",
		Ingress: []resource.AWSNetworkRuleV1{{Protocol: "tcp", FromPort: uint16(entrypoint.HTTPSPort), ToPort: uint16(entrypoint.HTTPSPort), CIDRv4: "0.0.0.0/0"}},
		// EC2 security-group egress rules cannot reference another security
		// group in this closed type. The fixed target port is device-signed and
		// the reciprocal Worker ingress bridge below accepts only this SG.
		Egress: []resource.AWSNetworkRuleV1{{Protocol: "tcp", FromPort: targetPort, ToPort: targetPort, CIDRv4: "0.0.0.0/0"}},
	}}
	bridgeAWS := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, SecurityGroupRule: &resource.AWSSecurityGroupRuleSpecV1{
		Direction: resource.AWSSecurityGroupRuleDirectionIngress, Protocol: "tcp", FromPort: targetPort, ToPort: targetPort,
		SourceSecurityGroupResourceID: albSecurityGroupID, TargetSecurityGroupResourceID: bindings.securityGroup.ResourceID,
	}}
	targetGroupAWS := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, TargetGroup: &resource.AWSTargetGroupSpecV1{
		VPCID: scope.Worker.VPCID, Protocol: resource.AWSTargetGroupProtocolHTTP, Port: targetPort,
		Registration: resource.AWSTargetRegistrationV1{InstanceID: scope.Worker.InstanceID}, HealthCheckPath: scope.Health.Path, HealthCheckMatcher: "200",
	}}
	loadBalancerAWS := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, ALB: &resource.AWSALBSpecV1{
		VPCID: scope.Worker.VPCID, SubnetIDs: subnetIDs(scope.ALB.PublicSubnets), SecurityGroupResourceID: albSecurityGroupID,
		Scheme: resource.AWSALBSchemeInternetFacing, IPAddressType: resource.AWSALBIPAddressTypeIPv4,
	}}
	listenerAWS := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Listener: &resource.AWSListenerSpecV1{
		LoadBalancerResourceID: loadBalancerID, TargetGroupResourceID: targetGroupID, Port: uint16(entrypoint.HTTPSPort), Protocol: resource.AWSListenerProtocolHTTPS,
		Hostname: scope.Certificate.Hostname, CertificateARN: scope.Certificate.CertificateARN, TLSPolicy: resource.AWSListenerTLSPolicyTLS13_12_2021_06,
	}}

	result := make([]resource.ProvisionSpec, 0, 5)
	for _, definition := range []struct {
		id           string
		kind         resource.Type
		logicalName  string
		dependencies []string
		aws          *resource.AWSResourceSpecV1
	}{
		{albSecurityGroupID, resource.TypeSG, entrySecurityGroupLogicalName, nil, groupAWS},
		{bridgeID, resource.TypeSecurityGroupRule, entryBridgeLogicalName, []string{albSecurityGroupID, bindings.securityGroup.ResourceID}, bridgeAWS},
		{targetGroupID, resource.TypeTargetGroup, entryTargetGroupLogicalName, []string{bindings.worker.ResourceID}, targetGroupAWS},
		{loadBalancerID, resource.TypeALB, entryLoadBalancerLogicalName, []string{albSecurityGroupID}, loadBalancerAWS},
		{listenerID, resource.TypeListener, entryListenerLogicalName, []string{loadBalancerID, targetGroupID}, listenerAWS},
	} {
		digest, err := definition.aws.Digest(definition.kind)
		if err != nil {
			return nil, err
		}
		spec := common
		spec.ResourceID, spec.Type, spec.LogicalName, spec.DependsOn, spec.SpecDigest, spec.AWS = definition.id, definition.kind, definition.logicalName, definition.dependencies, digest, definition.aws
		result = append(result, spec)
	}
	return result, nil
}

func subnetIDs(values []entrypoint.PublicSubnetScopeV1) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.SubnetID)
	}
	return result
}

func entryResourceID(agentInstanceID, operationID, logicalName string) string {
	return uuid.NewSHA1(uuid.MustParse(agentInstanceID), []byte("dirextalk.agent.cloud.entryexecution/v1\x00"+operationID+"\x00"+logicalName)).String()
}

func (executor *Executor) verifyDurableGraph(ctx context.Context, scope entrypoint.ScopeV1, specs []resource.ProvisionSpec) error {
	items, err := executor.resources.ListDeployment(ctx, scope.Worker.DeploymentID)
	if err != nil {
		return err
	}
	byID := make(map[string]resource.ResourceV1, len(items))
	for _, item := range items {
		if _, exists := byID[item.ResourceID]; exists {
			return entrypoint.ErrReadBackRequired
		}
		byID[item.ResourceID] = item
	}
	for _, spec := range specs {
		item, found := byID[spec.ResourceID]
		if !found || !matchesProvisionedResource(item, spec) || item.ProviderID == "" || !item.ReadBack.Exists || item.ReadBack.ProviderID != item.ProviderID {
			return entrypoint.ErrReadBackRequired
		}
	}
	return nil
}

func matchesProvisionedResource(item resource.ResourceV1, spec resource.ProvisionSpec) bool {
	return item.ResourceID == spec.ResourceID && item.AgentInstanceID == spec.AgentInstanceID && item.OwnerID == spec.OwnerID &&
		item.TaskID == spec.TaskID && item.DeploymentID == spec.DeploymentID && item.Type == spec.Type && item.LogicalName == spec.LogicalName &&
		item.Region == spec.Region && item.SpecDigest == spec.SpecDigest && item.ApprovedPlanHash == spec.ApprovedPlanHash &&
		item.ApprovalID == spec.ApprovalID && item.Retention == spec.Retention && item.AutoDestroyApproved == spec.AutoDestroyApproved &&
		item.DestroyDeadline.Equal(spec.DestroyDeadline) && item.State == resource.StateActive
}

func (executor *Executor) transition(ctx context.Context, operation entrypoint.OperationV1, status entrypoint.Status) (entrypoint.OperationV1, error) {
	next := operation
	next.Status, next.ErrorCode, next.ErrorSummary, next.UpdatedAt = status, entrypoint.ErrorCodeNone, "", executor.timestamp()
	saved, err := executor.operations.SaveEntryOperation(ctx, next, operation.Revision)
	if errors.Is(err, entrypoint.ErrRevisionConflict) || errors.Is(err, entrypoint.ErrNotFound) {
		return entrypoint.OperationV1{}, err
	}
	return saved, err
}

func (executor *Executor) failScope(ctx context.Context, operation entrypoint.OperationV1, err error) error {
	if errors.Is(err, entrypoint.ErrWorkerNotReady) {
		return executor.fail(ctx, operation, entrypoint.ErrorCodeWorkerNotReady, summaryWorkerNotReady)
	}
	if errors.Is(err, entrypoint.ErrReadBackRequired) || errors.Is(err, entrypoint.ErrRevisionConflict) || errors.Is(err, entrypoint.ErrUnsupportedEntry) || errors.Is(err, entrypoint.ErrInvalid) {
		return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, entrypoint.ErrUnavailable) {
		return err
	}
	return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
}

func (executor *Executor) failBinding(ctx context.Context, operation entrypoint.OperationV1, err error) error {
	if errors.Is(err, entrypoint.ErrWorkerNotReady) || errors.Is(err, resource.ErrNotFound) || errors.Is(err, resource.ErrDependency) {
		return executor.fail(ctx, operation, entrypoint.ErrorCodeWorkerNotReady, summaryWorkerNotReady)
	}
	return executor.fail(ctx, operation, entrypoint.ErrorCodeReadBackMismatch, summaryReadBackMismatch)
}

func (executor *Executor) fail(ctx context.Context, operation entrypoint.OperationV1, code entrypoint.ErrorCode, summary string) error {
	if operation.Status != entrypoint.StatusApproved && operation.Status != entrypoint.StatusProvisioning && operation.Status != entrypoint.StatusVerifying {
		return nil
	}
	next := operation
	next.Status, next.ErrorCode, next.ErrorSummary, next.UpdatedAt = entrypoint.StatusFailed, code, summary, executor.timestamp()
	_, err := executor.operations.SaveEntryOperation(ctx, next, operation.Revision)
	if errors.Is(err, entrypoint.ErrRevisionConflict) || errors.Is(err, entrypoint.ErrNotFound) {
		return nil
	}
	return err
}

func (executor *Executor) timestamp() time.Time {
	return executor.now().UTC().Truncate(time.Microsecond)
}

func expiredCode(scope entrypoint.ScopeV1, now time.Time) entrypoint.ErrorCode {
	if !now.UTC().Before(scope.Cost.ValidUntil.UTC()) {
		return entrypoint.ErrorCodeQuoteExpired
	}
	return entrypoint.ErrorCodeProvisioningFailed
}

const (
	summaryWorkerNotReady       = "The approved Worker is no longer ready for a public entry."
	summaryReadBackMismatch     = "The approved entry scope no longer matches independently verified cloud state."
	summaryAuthorizationExpired = "The approved entry authorization or quote expired before a new resource could be created."
	summaryProvisioningFailed   = "The approved public entry could not be provisioned."
	summaryVerificationFailed   = "The public entry resources could not be independently verified."
)

var _ Runner = (*Executor)(nil)
