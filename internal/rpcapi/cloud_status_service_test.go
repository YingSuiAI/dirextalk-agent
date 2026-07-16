package rpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cloudStatusReaderStub struct {
	ownerID        string
	connection     cloudstatus.Connection
	deployment     cloudstatus.Deployment
	worker         worker.Deployment
	resources      []resource.ResourceV1
	deploymentPage cloudstatus.DeploymentPage
	connectionPage cloudstatus.ConnectionPage
	planPage       cloudstatus.PlanPage
	workerPage     cloudstatus.WorkerPage
	resourcePage   cloudstatus.ResourcePage
	lastQuery      cloudstatus.ListQuery
}

func (stub *cloudStatusReaderStub) ListPlans(_ context.Context, query cloudstatus.ListQuery) (cloudstatus.PlanPage, error) {
	stub.lastQuery = query
	if query.OwnerID != stub.ownerID {
		return cloudstatus.PlanPage{}, cloudstatus.ErrNotFound
	}
	return cloudstatus.PlanPage{Plans: append([]cloudapproval.PlanV1(nil), stub.planPage.Plans...), NextPageToken: stub.planPage.NextPageToken}, nil
}

func (stub *cloudStatusReaderStub) GetConnection(_ context.Context, ownerID, connectionID string) (cloudstatus.Connection, error) {
	if ownerID != stub.ownerID || connectionID != stub.connection.ConnectionID {
		return cloudstatus.Connection{}, cloudstatus.ErrNotFound
	}
	return stub.connection, nil
}

func (stub *cloudStatusReaderStub) ListConnections(_ context.Context, query cloudstatus.ListQuery) (cloudstatus.ConnectionPage, error) {
	stub.lastQuery = query
	if query.OwnerID != stub.ownerID {
		return cloudstatus.ConnectionPage{}, cloudstatus.ErrNotFound
	}
	return stub.connectionPage, nil
}

func (stub *cloudStatusReaderStub) GetDeployment(_ context.Context, ownerID, deploymentID string) (cloudstatus.Deployment, error) {
	if ownerID != stub.ownerID || deploymentID != stub.deployment.Worker.DeploymentID {
		return cloudstatus.Deployment{}, cloudstatus.ErrNotFound
	}
	return stub.deployment, nil
}

func (stub *cloudStatusReaderStub) ListDeployments(_ context.Context, query cloudstatus.ListQuery) (cloudstatus.DeploymentPage, error) {
	stub.lastQuery = query
	if query.OwnerID != stub.ownerID {
		return cloudstatus.DeploymentPage{}, cloudstatus.ErrNotFound
	}
	return stub.deploymentPage, nil
}

func (stub *cloudStatusReaderStub) GetWorker(_ context.Context, ownerID, deploymentID string) (worker.Deployment, error) {
	if ownerID != stub.ownerID || deploymentID != stub.worker.DeploymentID {
		return worker.Deployment{}, cloudstatus.ErrNotFound
	}
	return stub.worker, nil
}

func (stub *cloudStatusReaderStub) ListWorkers(_ context.Context, query cloudstatus.ListQuery) (cloudstatus.WorkerPage, error) {
	stub.lastQuery = query
	if query.OwnerID != stub.ownerID {
		return cloudstatus.WorkerPage{}, cloudstatus.ErrNotFound
	}
	return stub.workerPage, nil
}

func (stub *cloudStatusReaderStub) GetResource(_ context.Context, ownerID, resourceID string) (resource.ResourceV1, error) {
	if ownerID != stub.ownerID {
		return resource.ResourceV1{}, cloudstatus.ErrNotFound
	}
	for _, item := range stub.resources {
		if item.ResourceID == resourceID {
			return item, nil
		}
	}
	return resource.ResourceV1{}, cloudstatus.ErrNotFound
}

func (stub *cloudStatusReaderStub) ListResources(_ context.Context, query cloudstatus.ListQuery) (cloudstatus.ResourcePage, error) {
	stub.lastQuery = query
	if query.OwnerID != stub.ownerID {
		return cloudstatus.ResourcePage{}, cloudstatus.ErrNotFound
	}
	return stub.resourcePage, nil
}

func (stub *cloudStatusReaderStub) ListDeploymentResources(_ context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	expectedDeploymentID := stub.worker.DeploymentID
	if expectedDeploymentID == "" {
		expectedDeploymentID = stub.deployment.Worker.DeploymentID
	}
	if ownerID != stub.ownerID || deploymentID != expectedDeploymentID {
		return nil, cloudstatus.ErrNotFound
	}
	return append([]resource.ResourceV1(nil), stub.resources...), nil
}

func TestCloudDeploymentStatusKeepsExecutionOutcomeAndResourceAxesIndependent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deploymentID, planID, connectionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	stub := &cloudStatusReaderStub{
		ownerID: "owner-a",
		deployment: cloudstatus.Deployment{
			Worker: worker.Deployment{
				DeploymentID: deploymentID, OwnerID: "owner-a", TaskID: uuid.NewString(), StepID: uuid.NewString(), WorkerID: uuid.NewString(),
				State: worker.StateLeased, Outcome: worker.OutcomePending, Revision: 7, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
			},
			PlanID: planID, ConnectionID: connectionID,
		},
		resources: []resource.ResourceV1{
			{ResourceID: uuid.NewString(), OwnerID: "owner-a", DeploymentID: deploymentID, State: resource.StateActive, Revision: 2,
				ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "i-verified", ObservedAt: now.Add(-time.Second)}},
			{ResourceID: uuid.NewString(), OwnerID: "owner-a", DeploymentID: deploymentID, State: resource.StateDestroyBlocked, Revision: 3,
				ReadBack: resource.ReadBackEvidence{Exists: false, ProviderID: "vol-removed", ObservedAt: now}},
			{ResourceID: uuid.NewString(), OwnerID: "owner-a", DeploymentID: deploymentID, State: resource.StateProvisioning, Revision: 1},
		},
	}
	response, err := NewCloudControlService(nil, uuid.NewString(), stub).GetCloudDeployment(context.Background(), &agentv1.GetCloudDeploymentRequest{
		OwnerId: "owner-a", DeploymentId: deploymentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := response.GetDeployment()
	if got.GetPlanId() != planID || got.GetConnectionId() != connectionID {
		t.Fatalf("deployment relationships plan=%q connection=%q", got.GetPlanId(), got.GetConnectionId())
	}
	if got.GetExecutionStatus() != agentv1.ExecutionStatus_EXECUTION_STATUS_RUNNING || got.GetOutcomeStatus() != agentv1.OutcomeStatus_OUTCOME_STATUS_PENDING {
		t.Fatalf("execution=%s outcome=%s", got.GetExecutionStatus(), got.GetOutcomeStatus())
	}
	if got.GetRevision() != 13 || got.GetResources().GetRevision() != 6 || got.GetResources().GetStatus() != agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_MIXED {
		t.Fatalf("deployment revisions/status=%+v", got)
	}
	readBack := got.GetResources().GetReadBack()
	if readBack.GetTotalResources() != 3 || readBack.GetObservedResources() != 2 || readBack.GetExistingResources() != 1 ||
		readBack.GetMissingResources() != 1 || readBack.GetUnobservedResources() != 1 || !readBack.GetLastObservedAt().AsTime().Equal(now) {
		t.Fatalf("read-back summary=%+v", readBack)
	}
}

func TestCloudConnectionQueriesKeepPersistedStatusRevisionAndTimestamps(t *testing.T) {
	createdAt := time.Date(2026, 7, 16, 8, 0, 0, 123000000, time.UTC)
	updatedAt := createdAt.Add(3 * time.Minute)
	item := cloudstatus.Connection{
		ConnectionID: uuid.NewString(), OwnerID: "owner-a", AccountID: "123456789012", Region: "us-east-1",
		ControlRoleARN: "arn:aws:iam::123456789012:role/dirextalk-control", FoundationStackID: "foundation-stack",
		CredentialGeneration: 7, Status: "degraded", Revision: 4, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	stub := &cloudStatusReaderStub{
		ownerID: "owner-a", connection: item,
		connectionPage: cloudstatus.ConnectionPage{Connections: []cloudstatus.Connection{item}, NextPageToken: "next-connection-page"},
	}
	service := NewCloudControlService(nil, uuid.NewString(), stub)
	response, err := service.GetCloudConnection(context.Background(), &agentv1.GetCloudConnectionRequest{
		OwnerId: "owner-a", ConnectionId: item.ConnectionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := response.GetConnection()
	if got.GetStatus() != "degraded" || got.GetRevision() != 4 || got.GetCredentialGeneration() != 7 ||
		!got.GetCreatedAt().AsTime().Equal(createdAt) || !got.GetUpdatedAt().AsTime().Equal(updatedAt) {
		t.Fatalf("connection read model drifted: %+v", got)
	}
	if _, err := service.GetCloudConnection(context.Background(), &agentv1.GetCloudConnectionRequest{
		OwnerId: "owner-b", ConnectionId: item.ConnectionID,
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-owner connection status code=%s err=%v", status.Code(err), err)
	}
	page, err := service.ListCloudConnections(context.Background(), &agentv1.ListCloudConnectionsRequest{
		OwnerId: "owner-a", PageSize: 13, PageToken: "connection-page",
	})
	if err != nil || len(page.GetConnections()) != 1 || page.GetNextPageToken() != "next-connection-page" ||
		stub.lastQuery.OwnerID != "owner-a" || stub.lastQuery.PageSize != 13 || stub.lastQuery.PageToken != "connection-page" {
		t.Fatalf("connection list response=%+v query=%+v err=%v", page, stub.lastQuery, err)
	}
}

func TestCloudPlanListKeepsOwnerAndCursorScope(t *testing.T) {
	instanceID := uuid.NewString()
	plan := rpcApprovalPlan(t, instanceID)
	stub := &cloudStatusReaderStub{
		ownerID:  plan.OwnerID,
		planPage: cloudstatus.PlanPage{Plans: []cloudapproval.PlanV1{plan}, NextPageToken: "next-plan-page"},
	}
	service := NewCloudControlService(nil, instanceID, stub)
	page, err := service.ListCloudPlans(context.Background(), &agentv1.ListCloudPlansRequest{
		OwnerId: plan.OwnerID, PageSize: 11, PageToken: "plan-page",
	})
	if err != nil || len(page.GetPlans()) != 1 || page.GetPlans()[0].GetPlanId() != plan.PlanID || page.GetNextPageToken() != "next-plan-page" ||
		stub.lastQuery.OwnerID != plan.OwnerID || stub.lastQuery.PageSize != 11 || stub.lastQuery.PageToken != "plan-page" {
		t.Fatalf("plan list response=%+v query=%+v err=%v", page, stub.lastQuery, err)
	}
	if _, err := service.ListCloudPlans(context.Background(), &agentv1.ListCloudPlansRequest{OwnerId: "owner-b"}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-owner plan list code=%s err=%v", status.Code(err), err)
	}
}

func TestCloudDeploymentReadModelAdvancesWhenOnlyResourceChanges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	item := cloudstatus.Deployment{
		Worker: worker.Deployment{
			DeploymentID: uuid.NewString(), OwnerID: "owner-a", TaskID: uuid.NewString(), StepID: uuid.NewString(),
			Revision: 7, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		},
		PlanID: uuid.NewString(), ConnectionID: uuid.NewString(),
	}
	resourceItem := resource.ResourceV1{
		ResourceID: uuid.NewString(), DeploymentID: item.Worker.DeploymentID,
		Revision: 2, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	before := cloudDeploymentToProto(item, []resource.ResourceV1{resourceItem})
	resourceItem.Revision++
	resourceItem.UpdatedAt = now.Add(time.Minute)
	after := cloudDeploymentToProto(item, []resource.ResourceV1{resourceItem})
	if before.GetRevision() != 9 || after.GetRevision() != 10 || !before.GetUpdatedAt().AsTime().Equal(now) ||
		!after.GetUpdatedAt().AsTime().Equal(resourceItem.UpdatedAt) {
		t.Fatalf("resource-only read-model transition before=%+v after=%+v", before, after)
	}
}

func TestCloudStatusQueriesFailClosedAcrossOwnersAndRedactStoredErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deploymentID, resourceID := uuid.NewString(), uuid.NewString()
	canary := "sk-abcdefghijklmnopqrstuvwxyz123456"
	stub := &cloudStatusReaderStub{
		ownerID: "owner-a",
		worker:  worker.Deployment{DeploymentID: deploymentID, OwnerID: "owner-a"},
		resources: []resource.ResourceV1{{
			ResourceID: resourceID, OwnerID: "owner-a", TaskID: uuid.NewString(), DeploymentID: deploymentID,
			Type: resource.TypeEC2, LogicalName: "worker", Region: "us-east-1", Retention: task.RetentionEphemeralAutoDestroy,
			State: resource.StateDestroyBlocked, BlockedReason: "provider failed with " + canary, Revision: 4, CreatedAt: now, UpdatedAt: now,
		}},
	}
	service := NewCloudControlService(nil, uuid.NewString(), stub)
	if _, err := service.GetCloudWorker(context.Background(), &agentv1.GetCloudWorkerRequest{OwnerId: "owner-b", DeploymentId: deploymentID}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-owner Worker status code=%s err=%v", status.Code(err), err)
	}
	response, err := service.GetCloudResource(context.Background(), &agentv1.GetCloudResourceRequest{OwnerId: "owner-a", ResourceId: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response.GetResource().GetBlockedReason(), canary) || !strings.Contains(response.GetResource().GetBlockedReason(), "[redacted]") {
		t.Fatalf("blocked reason was not redacted: %q", response.GetResource().GetBlockedReason())
	}
}

func TestCloudStatusListsPropagateOwnerFilterAndCursor(t *testing.T) {
	item := worker.Deployment{DeploymentID: uuid.NewString(), OwnerID: "owner-a", State: worker.StateReady, Outcome: worker.OutcomePending}
	planID, connectionID := uuid.NewString(), uuid.NewString()
	deployment := cloudstatus.Deployment{Worker: item, PlanID: planID, ConnectionID: connectionID}
	stub := &cloudStatusReaderStub{
		ownerID: "owner-a", worker: item, deployment: deployment,
		workerPage:     cloudstatus.WorkerPage{Workers: []worker.Deployment{item}, NextPageToken: "next-worker-page"},
		deploymentPage: cloudstatus.DeploymentPage{Deployments: []cloudstatus.Deployment{deployment}, NextPageToken: "next-deployment-page"},
	}
	response, err := NewCloudControlService(nil, uuid.NewString(), stub).ListCloudWorkers(context.Background(), &agentv1.ListCloudWorkersRequest{
		OwnerId: "owner-a", PageSize: 23, PageToken: "worker-page",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.GetWorkers()) != 1 || response.GetNextPageToken() != "next-worker-page" ||
		stub.lastQuery.OwnerID != "owner-a" || stub.lastQuery.PageSize != 23 || stub.lastQuery.PageToken != "worker-page" {
		t.Fatalf("list response=%+v query=%+v", response, stub.lastQuery)
	}
	deployments, err := NewCloudControlService(nil, uuid.NewString(), stub).ListCloudDeployments(context.Background(), &agentv1.ListCloudDeploymentsRequest{
		OwnerId: "owner-a", PageSize: 17, PageToken: "deployment-page",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deployments.GetDeployments()) != 1 || deployments.GetNextPageToken() != "next-deployment-page" ||
		deployments.GetDeployments()[0].GetPlanId() != planID || deployments.GetDeployments()[0].GetConnectionId() != connectionID ||
		stub.lastQuery.OwnerID != "owner-a" || stub.lastQuery.PageSize != 17 || stub.lastQuery.PageToken != "deployment-page" {
		t.Fatalf("deployment list response=%+v query=%+v", deployments, stub.lastQuery)
	}
}
