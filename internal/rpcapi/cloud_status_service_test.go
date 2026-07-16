package rpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cloudStatusReaderStub struct {
	ownerID      string
	worker       worker.Deployment
	resources    []resource.ResourceV1
	workerPage   cloudstatus.WorkerPage
	resourcePage cloudstatus.ResourcePage
	lastQuery    cloudstatus.ListQuery
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
	if ownerID != stub.ownerID || deploymentID != stub.worker.DeploymentID {
		return nil, cloudstatus.ErrNotFound
	}
	return append([]resource.ResourceV1(nil), stub.resources...), nil
}

func TestCloudDeploymentStatusKeepsExecutionOutcomeAndResourceAxesIndependent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deploymentID := uuid.NewString()
	stub := &cloudStatusReaderStub{
		ownerID: "owner-a",
		worker: worker.Deployment{
			DeploymentID: deploymentID, OwnerID: "owner-a", TaskID: uuid.NewString(), StepID: uuid.NewString(), WorkerID: uuid.NewString(),
			State: worker.StateLeased, Outcome: worker.OutcomePending, Revision: 7, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
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
	if got.GetExecutionStatus() != agentv1.ExecutionStatus_EXECUTION_STATUS_RUNNING || got.GetOutcomeStatus() != agentv1.OutcomeStatus_OUTCOME_STATUS_PENDING {
		t.Fatalf("execution=%s outcome=%s", got.GetExecutionStatus(), got.GetOutcomeStatus())
	}
	if got.GetRevision() != 7 || got.GetResources().GetRevision() != 6 || got.GetResources().GetStatus() != agentv1.CloudResourceStatus_CLOUD_RESOURCE_STATUS_MIXED {
		t.Fatalf("deployment revisions/status=%+v", got)
	}
	readBack := got.GetResources().GetReadBack()
	if readBack.GetTotalResources() != 3 || readBack.GetObservedResources() != 2 || readBack.GetExistingResources() != 1 ||
		readBack.GetMissingResources() != 1 || readBack.GetUnobservedResources() != 1 || !readBack.GetLastObservedAt().AsTime().Equal(now) {
		t.Fatalf("read-back summary=%+v", readBack)
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
	stub := &cloudStatusReaderStub{ownerID: "owner-a", worker: item, workerPage: cloudstatus.WorkerPage{
		Workers: []worker.Deployment{item}, NextPageToken: "next-worker-page",
	}}
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
}
