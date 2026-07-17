package rpcapi

import (
	"context"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxCloudStatusRevision int64 = 1<<63 - 1

func (service *CloudControlService) ListCloudPlans(ctx context.Context, request *agentv1.ListCloudPlansRequest) (*agentv1.ListCloudPlansResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	page, err := service.statusReader.ListPlans(ctx, cloudstatus.ListQuery{
		OwnerID: request.GetOwnerId(), PageSize: int(request.GetPageSize()), PageToken: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListCloudPlansResponse{Plans: make([]*agentv1.CloudPlan, 0, len(page.Plans)), NextPageToken: page.NextPageToken}
	for _, item := range page.Plans {
		response.Plans = append(response.Plans, cloudPlanToProto(item))
	}
	return response, nil
}

func (service *CloudControlService) GetCloudConnection(ctx context.Context, request *agentv1.GetCloudConnectionRequest) (*agentv1.GetCloudConnectionResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	item, err := service.statusReader.GetConnection(ctx, request.GetOwnerId(), request.GetConnectionId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudConnectionResponse{Connection: cloudConnectionToProto(item)}, nil
}

func (service *CloudControlService) ListCloudConnections(ctx context.Context, request *agentv1.ListCloudConnectionsRequest) (*agentv1.ListCloudConnectionsResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	page, err := service.statusReader.ListConnections(ctx, cloudstatus.ListQuery{
		OwnerID: request.GetOwnerId(), PageSize: int(request.GetPageSize()), PageToken: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListCloudConnectionsResponse{
		Connections: make([]*agentv1.CloudConnection, 0, len(page.Connections)), NextPageToken: page.NextPageToken,
	}
	for _, item := range page.Connections {
		response.Connections = append(response.Connections, cloudConnectionToProto(item))
	}
	return response, nil
}

func (service *CloudControlService) GetCloudDeployment(ctx context.Context, request *agentv1.GetCloudDeploymentRequest) (*agentv1.GetCloudDeploymentResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	item, err := service.statusReader.GetDeployment(ctx, request.GetOwnerId(), request.GetDeploymentId())
	if err != nil {
		return nil, publicError(err)
	}
	resources, err := service.statusReader.ListDeploymentResources(ctx, request.GetOwnerId(), request.GetDeploymentId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudDeploymentResponse{Deployment: cloudDeploymentToProto(item, resources)}, nil
}

func (service *CloudControlService) ListCloudDeployments(ctx context.Context, request *agentv1.ListCloudDeploymentsRequest) (*agentv1.ListCloudDeploymentsResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	page, err := service.statusReader.ListDeployments(ctx, cloudstatus.ListQuery{
		OwnerID: request.GetOwnerId(), PageSize: int(request.GetPageSize()), PageToken: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListCloudDeploymentsResponse{
		Deployments: make([]*agentv1.CloudDeployment, 0, len(page.Deployments)), NextPageToken: page.NextPageToken,
	}
	for _, item := range page.Deployments {
		resources, listErr := service.statusReader.ListDeploymentResources(ctx, request.GetOwnerId(), item.Worker.DeploymentID)
		if listErr != nil {
			return nil, publicError(listErr)
		}
		response.Deployments = append(response.Deployments, cloudDeploymentToProto(item, resources))
	}
	return response, nil
}

func (service *CloudControlService) GetCloudResource(ctx context.Context, request *agentv1.GetCloudResourceRequest) (*agentv1.GetCloudResourceResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	item, err := service.statusReader.GetResource(ctx, request.GetOwnerId(), request.GetResourceId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudResourceResponse{Resource: cloudResourceToProto(item)}, nil
}

func (service *CloudControlService) ListCloudResources(ctx context.Context, request *agentv1.ListCloudResourcesRequest) (*agentv1.ListCloudResourcesResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	page, err := service.statusReader.ListResources(ctx, cloudstatus.ListQuery{
		OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(),
		PageSize: int(request.GetPageSize()), PageToken: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListCloudResourcesResponse{
		Resources: make([]*agentv1.CloudResource, 0, len(page.Resources)), NextPageToken: page.NextPageToken,
	}
	for _, item := range page.Resources {
		response.Resources = append(response.Resources, cloudResourceToProto(item))
	}
	return response, nil
}

func (service *CloudControlService) GetCloudWorker(ctx context.Context, request *agentv1.GetCloudWorkerRequest) (*agentv1.GetCloudWorkerResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	item, err := service.statusReader.GetWorker(ctx, request.GetOwnerId(), request.GetDeploymentId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudWorkerResponse{Worker: cloudWorkerToProto(item)}, nil
}

func (service *CloudControlService) ListCloudWorkers(ctx context.Context, request *agentv1.ListCloudWorkersRequest) (*agentv1.ListCloudWorkersResponse, error) {
	if service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	page, err := service.statusReader.ListWorkers(ctx, cloudstatus.ListQuery{
		OwnerID: request.GetOwnerId(), PageSize: int(request.GetPageSize()), PageToken: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListCloudWorkersResponse{
		Workers: make([]*agentv1.CloudWorker, 0, len(page.Workers)), NextPageToken: page.NextPageToken,
	}
	for _, item := range page.Workers {
		response.Workers = append(response.Workers, cloudWorkerToProto(item))
	}
	return response, nil
}

func cloudDeploymentToProto(item cloudstatus.Deployment, resources []resource.ResourceV1) *agentv1.CloudDeployment {
	workerItem := item.Worker
	resourceSummary := cloudResourceSummaryToProto(resources)
	updatedAt := workerItem.UpdatedAt
	for _, resourceItem := range resources {
		if resourceItem.UpdatedAt.After(updatedAt) {
			updatedAt = resourceItem.UpdatedAt
		}
	}
	return &agentv1.CloudDeployment{
		DeploymentId: workerItem.DeploymentID, OwnerId: workerItem.OwnerID, TaskId: workerItem.TaskID, StepId: workerItem.StepID, WorkerId: workerItem.WorkerID,
		ExecutionStatus: cloudWorkerExecutionToProto(workerItem.State), OutcomeStatus: cloudWorkerOutcomeToProto(workerItem.Outcome),
		Resources: resourceSummary, Revision: cloudStatusRevisionSum(workerItem.Revision, resourceSummary.GetRevision()),
		CreatedAt: cloudStatusTimestamp(workerItem.CreatedAt), UpdatedAt: cloudStatusTimestamp(updatedAt),
		PlanId: item.PlanID, ConnectionId: item.ConnectionID, Health: cloudHealthSummaryToProto(item.Health),
	}
}

func cloudHealthSummaryToProto(value cloudstatus.HealthSummary) *agentv1.CloudHealthSummary {
	counts := make([]*agentv1.CloudHealthProbeCount, 0, len(value.ProbeCounts))
	for _, count := range value.ProbeCounts {
		counts = append(counts, &agentv1.CloudHealthProbeCount{
			Kind:  cloudHealthProbeKindToProto(count.Kind),
			Count: count.Count,
		})
	}
	return &agentv1.CloudHealthSummary{
		Status:                 cloudHealthStatusToProto(value.Status),
		Revision:               value.Revision,
		ObservedAt:             cloudStatusTimestamp(value.ObservedAt),
		NextDueAt:              cloudStatusTimestamp(value.NextDueAt),
		ProbeCount:             value.ProbeCount,
		ProbeCounts:            counts,
		ExternalEvidenceDigest: value.EvidenceDigest,
		EvidenceType:           cloudHealthEvidenceTypeToProto(value.EvidenceType),
	}
}

func cloudHealthStatusToProto(value cloudstatus.HealthStatus) agentv1.CloudHealthStatus {
	switch value {
	case cloudstatus.HealthPending:
		return agentv1.CloudHealthStatus_CLOUD_HEALTH_STATUS_PENDING
	case cloudstatus.HealthHealthy:
		return agentv1.CloudHealthStatus_CLOUD_HEALTH_STATUS_HEALTHY
	case cloudstatus.HealthDegraded:
		return agentv1.CloudHealthStatus_CLOUD_HEALTH_STATUS_DEGRADED
	case cloudstatus.HealthUnhealthy:
		return agentv1.CloudHealthStatus_CLOUD_HEALTH_STATUS_UNHEALTHY
	case cloudstatus.HealthCanceled:
		return agentv1.CloudHealthStatus_CLOUD_HEALTH_STATUS_CANCELED
	default:
		return agentv1.CloudHealthStatus_CLOUD_HEALTH_STATUS_UNKNOWN
	}
}

func cloudHealthProbeKindToProto(value cloudstatus.HealthProbeKind) agentv1.CloudHealthProbeKind {
	switch value {
	case cloudstatus.HealthProbeLiveness:
		return agentv1.CloudHealthProbeKind_CLOUD_HEALTH_PROBE_KIND_LIVENESS
	case cloudstatus.HealthProbeReadiness:
		return agentv1.CloudHealthProbeKind_CLOUD_HEALTH_PROBE_KIND_READINESS
	case cloudstatus.HealthProbeSemantic:
		return agentv1.CloudHealthProbeKind_CLOUD_HEALTH_PROBE_KIND_SEMANTIC
	default:
		return agentv1.CloudHealthProbeKind_CLOUD_HEALTH_PROBE_KIND_UNSPECIFIED
	}
}

func cloudHealthEvidenceTypeToProto(value string) agentv1.CloudHealthEvidenceType {
	switch value {
	case cloudstatus.HealthEvidenceIndependent:
		return agentv1.CloudHealthEvidenceType_CLOUD_HEALTH_EVIDENCE_TYPE_INDEPENDENT_EXTERNAL
	case cloudstatus.HealthEvidenceNone, "":
		return agentv1.CloudHealthEvidenceType_CLOUD_HEALTH_EVIDENCE_TYPE_NONE
	default:
		return agentv1.CloudHealthEvidenceType_CLOUD_HEALTH_EVIDENCE_TYPE_UNSPECIFIED
	}
}

func cloudConnectionToProto(item cloudstatus.Connection) *agentv1.CloudConnection {
	return &agentv1.CloudConnection{
		ConnectionId: item.ConnectionID, OwnerId: item.OwnerID, AccountId: item.AccountID, Region: item.Region,
		ControlRoleArn: item.ControlRoleARN, FoundationStackId: item.FoundationStackID,
		Status: item.Status, Revision: item.Revision, CredentialGeneration: item.CredentialGeneration,
		CreatedAt: cloudStatusTimestamp(item.CreatedAt), UpdatedAt: cloudStatusTimestamp(item.UpdatedAt),
	}
}

func cloudWorkerToProto(item worker.Deployment) *agentv1.CloudWorker {
	evidenceCount := uint32(len(item.Evidence))
	if uint64(len(item.Evidence)) > uint64(^uint32(0)) {
		evidenceCount = ^uint32(0)
	}
	return &agentv1.CloudWorker{
		DeploymentId: item.DeploymentID, OwnerId: item.OwnerID, WorkerId: item.WorkerID,
		Status: cloudWorkerStateToProto(item.State), Attempt: item.Lease.Attempt, LeaseEpoch: item.Lease.Epoch,
		LeaseExpiresAt: cloudStatusTimestamp(item.Lease.ExpiresAt), LastHeartbeatAt: cloudStatusTimestamp(item.Lease.LastHeartbeatAt),
		CancellationRequested: item.State == worker.StateCancelRequested, CheckpointAvailable: item.Lease.CheckpointRef != "",
		ResultAvailable: item.ResultRef != "", EvidenceCount: evidenceCount, Revision: item.Revision,
		CreatedAt: cloudStatusTimestamp(item.CreatedAt), UpdatedAt: cloudStatusTimestamp(item.UpdatedAt),
	}
}

func cloudResourceToProto(item resource.ResourceV1) *agentv1.CloudResource {
	readBack := &agentv1.CloudResourceReadBack{
		Observed: !item.ReadBack.ObservedAt.IsZero(), Exists: item.ReadBack.Exists,
		ProviderId: item.ReadBack.ProviderID, TagDigest: item.ReadBack.TagDigest,
		ObservedAt: cloudStatusTimestamp(item.ReadBack.ObservedAt),
	}
	return &agentv1.CloudResource{
		ResourceId: item.ResourceID, OwnerId: item.OwnerID, TaskId: item.TaskID, DeploymentId: item.DeploymentID,
		Type: cloudResourceTypeToProto(item.Type), LogicalName: item.LogicalName, Region: item.Region, ProviderId: item.ProviderID,
		DependsOnResourceIds: append([]string(nil), item.DependsOn...), RetentionPolicy: retentionToProto(item.Retention),
		DestroyDeadline: cloudStatusTimestamp(item.DestroyDeadline), AutoDestroyApproved: item.AutoDestroyApproved,
		Status: cloudResourceStateToProto(item.State), ReadBack: readBack,
		BlockedReason: security.RedactText(strings.TrimSpace(item.BlockedReason)), Revision: item.Revision,
		CreatedAt: cloudStatusTimestamp(item.CreatedAt), UpdatedAt: cloudStatusTimestamp(item.UpdatedAt),
	}
}

func cloudResourceSummaryToProto(resources []resource.ResourceV1) *agentv1.CloudResourceSummary {
	summary := &agentv1.CloudResourceSummary{
		Status:   agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_NONE,
		ReadBack: &agentv1.CloudReadBackSummary{TotalResources: uint32(len(resources)), UnobservedResources: uint32(len(resources))},
	}
	counts := make(map[agentv1.CloudResourceStatus]uint32)
	for _, item := range resources {
		state := cloudResourceStateToProto(item.State)
		counts[state]++
		summary.Revision = cloudStatusRevisionSum(summary.Revision, item.Revision)
		if item.ReadBack.ObservedAt.IsZero() {
			continue
		}
		summary.ReadBack.ObservedResources++
		summary.ReadBack.UnobservedResources--
		if item.ReadBack.Exists {
			summary.ReadBack.ExistingResources++
		} else {
			summary.ReadBack.MissingResources++
		}
		if summary.ReadBack.LastObservedAt == nil || item.ReadBack.ObservedAt.After(summary.ReadBack.LastObservedAt.AsTime()) {
			summary.ReadBack.LastObservedAt = cloudStatusTimestamp(item.ReadBack.ObservedAt)
		}
	}
	states := make([]int, 0, len(counts))
	for state := range counts {
		states = append(states, int(state))
	}
	sort.Ints(states)
	for _, rawState := range states {
		state := agentv1.CloudResourceStatus(rawState)
		summary.StateCounts = append(summary.StateCounts, &agentv1.CloudResourceStateCount{Status: state, Count: counts[state]})
	}
	if len(counts) == 1 {
		for state := range counts {
			summary.Status = state
		}
	} else if len(counts) > 1 {
		summary.Status = agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_MIXED
	}
	return summary
}

// cloud_resources are retained through verified destruction and their
// revisions are monotonic. The saturating sum is therefore a monotonic
// revision for the composed Deployment read model. Introducing resource-fact
// deletion would require a separately persisted projection revision.
func cloudStatusRevisionSum(left, right int64) int64 {
	if left > maxCloudStatusRevision-right {
		return maxCloudStatusRevision
	}
	return left + right
}

func cloudWorkerExecutionToProto(value worker.State) agentv1.ExecutionStatus {
	switch value {
	case worker.StatePendingEnrollment, worker.StateReady:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_QUEUED
	case worker.StateLeased, worker.StateCancelRequested:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_RUNNING
	case worker.StateFinished:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_FINISHED
	default:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED
	}
}

func cloudWorkerOutcomeToProto(value worker.Outcome) agentv1.OutcomeStatus {
	switch value {
	case worker.OutcomePending:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_PENDING
	case worker.OutcomeSucceeded:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_SUCCEEDED
	case worker.OutcomeFailed:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_FAILED
	case worker.OutcomeCanceled:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_CANCELED
	case worker.OutcomeTimedOut:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_TIMED_OUT
	case worker.OutcomeInterrupted:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_INTERRUPTED
	default:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_UNSPECIFIED
	}
}

func cloudWorkerStateToProto(value worker.State) agentv1.CloudWorkerStatus {
	switch value {
	case worker.StatePendingEnrollment:
		return agentv1.CloudWorkerStatus_CLOUD_WORKER_STATUS_PENDING_ENROLLMENT
	case worker.StateReady:
		return agentv1.CloudWorkerStatus_CLOUD_WORKER_STATUS_READY
	case worker.StateLeased:
		return agentv1.CloudWorkerStatus_CLOUD_WORKER_STATUS_LEASED
	case worker.StateCancelRequested:
		return agentv1.CloudWorkerStatus_CLOUD_WORKER_STATUS_CANCEL_REQUESTED
	case worker.StateFinished:
		return agentv1.CloudWorkerStatus_CLOUD_WORKER_STATUS_FINISHED
	default:
		return agentv1.CloudWorkerStatus_CLOUD_WORKER_STATUS_UNSPECIFIED
	}
}

func cloudResourceStateToProto(value resource.State) agentv1.CloudResourceStatus {
	switch value {
	case resource.StateProvisioning:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_PROVISIONING
	case resource.StateActive:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_ACTIVE
	case resource.StateDestroyScheduled:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_DESTROY_SCHEDULED
	case resource.StateRetainedManaged:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_RETAINED_MANAGED
	case resource.StateDestroying:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_DESTROYING
	case resource.StateVerifiedDestroyed:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_VERIFIED_DESTROYED
	case resource.StateDestroyBlocked:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_DESTROY_BLOCKED
	case resource.StateOrphaned:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_ORPHANED
	default:
		return agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_UNSPECIFIED
	}
}

func cloudResourceTypeToProto(value resource.Type) agentv1.CloudResourceType {
	switch value {
	case resource.TypeEC2:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_EC2
	case resource.TypeEBS:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_EBS
	case resource.TypeENI:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_ENI
	case resource.TypeEIP:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_EIP
	case resource.TypeSG:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_SECURITY_GROUP
	case resource.TypeEndpoint:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_ENDPOINT
	case resource.TypeSnapshot:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_SNAPSHOT
	case resource.TypeALB:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_ALB
	case resource.TypeTargetGroup:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_TARGET_GROUP
	case resource.TypeListener:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_LISTENER
	case resource.TypeSecurityGroupRule:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_SECURITY_GROUP_RULE
	default:
		return agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_UNSPECIFIED
	}
}

func cloudStatusTimestamp(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}

func cloudStatusUnavailable() error {
	return status.Error(codes.Unavailable, "cloud status persistence is not configured")
}
