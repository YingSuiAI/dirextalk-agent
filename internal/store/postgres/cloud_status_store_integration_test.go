package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestCloudStatusPostgresOwnerIsolationPaginationAndReadBack(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	taskID, stepID := createWorkerTask(t, baseStore)
	workerStore, err := baseStore.NewWorkerStore(bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	workerService, err := worker.NewService(workerStore, bytes.Repeat([]byte{0x66}, 32))
	if err != nil {
		t.Fatal(err)
	}
	createDeployment := func(ownerID string, sequence int) worker.Deployment {
		t.Helper()
		deploymentID := uuid.NewString()
		prefix := fmt.Sprintf("s3://status-fixture/%s/%d/", deploymentID, sequence)
		created, enrollment, createErr := workerService.CreateDeployment(ctx, worker.ControlMutation{
			ClientID: "cloud-status-integration", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		}, worker.CreateDeploymentRequest{
			DeploymentID: deploymentID, OwnerID: ownerID, TaskID: taskID, StepID: stepID,
			ControlPlaneEndpoint: "grpcs://agent.example.internal:9443", EnrollmentTTL: 10 * time.Minute,
			RecipeBundle:     worker.BundleRef{S3Ref: prefix + "recipe.json", SHA256: [32]byte{byte(sequence + 1)}},
			ExecutionBundle:  worker.BundleRef{S3Ref: prefix + "execution.json", SHA256: [32]byte{byte(sequence + 11)}},
			ExecutionTimeout: 10 * time.Minute,
			Access: worker.AccessScope{
				ArtifactPrefix: prefix + "artifacts/", CheckpointPrefix: prefix + "checkpoints/", EvidencePrefix: prefix + "evidence/",
				LogPrefix: "cloudwatch://status-fixture/" + deploymentID,
			},
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		enrollment.Destroy()
		return created
	}
	first := createDeployment("owner-a", 1)
	second := createDeployment("owner-a", 2)
	foreign := createDeployment("owner-b", 3)
	seedWorkerIdentityBinding(t, pool, instanceID, first.OwnerID, first.TaskID, first.DeploymentID, "i-00000001", "123456789012")
	seedWorkerIdentityBinding(t, pool, instanceID, second.OwnerID, second.TaskID, second.DeploymentID, "i-00000002", "123456789013")
	seedWorkerIdentityBinding(t, pool, instanceID, foreign.OwnerID, foreign.TaskID, foreign.DeploymentID, "i-00000003", "123456789014")
	if _, err := pool.Exec(ctx, `DELETE FROM cloud_resources WHERE agent_instance_id=$1`, instanceID); err != nil {
		t.Fatalf("remove fixture-only Worker resources: %v", err)
	}

	resourceStore, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	deadline := now.Add(time.Hour).Truncate(time.Second)
	createResource := func(ownerID, deploymentID, taskID string, sequence int) resource.ResourceV1 {
		t.Helper()
		resourceID := uuid.NewString()
		var approvedPlanHash string
		var approvalID uuid.UUID
		if err := pool.QueryRow(ctx, `
			SELECT plan.plan_hash, launch.approval_id
			FROM cloud_launch_operations AS launch
			JOIN cloud_plans AS plan ON plan.plan_id=launch.plan_id
			WHERE launch.agent_instance_id=$1 AND launch.owner_id=$2 AND launch.deployment_id=$3 AND launch.task_id=$4`,
			instanceID, ownerID, deploymentID, taskID,
		).Scan(&approvedPlanHash, &approvalID); err != nil {
			t.Fatalf("load orphan approval origin: %v", err)
		}
		item := resource.ResourceV1{
			ResourceID: resourceID, AgentInstanceID: instanceID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID,
			Type: resource.TypeEC2, LogicalName: fmt.Sprintf("worker-%d", sequence), Region: "us-east-1",
			ApprovedPlanHash: approvedPlanHash, ApprovalID: approvalID.String(),
			Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline,
			AutoDestroyApproved: true, State: resource.StateOrphaned,
			ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: fmt.Sprintf("i-status-%d", sequence), ObservedAt: now, TagDigest: "sha256:" + strings.Repeat("c", 64)},
			Revision: 1, CreatedAt: now.Add(time.Duration(sequence) * time.Millisecond), UpdatedAt: now.Add(time.Duration(sequence) * time.Millisecond),
		}
		item.ProviderID = item.ReadBack.ProviderID
		item.Tags = map[string]string{
			resource.TagAgentInstanceID: instanceID, resource.TagOwnerID: ownerID, resource.TagTaskID: taskID,
			resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
			resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.Format(time.RFC3339),
			resource.TagApprovedPlanHash: approvedPlanHash, resource.TagApprovalID: approvalID.String(),
		}
		created, createErr := resourceStore.ImportOrphan(ctx, item)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return created
	}
	ownedResource := createResource("owner-a", first.DeploymentID, first.TaskID, 1)
	_ = createResource("owner-b", foreign.DeploymentID, foreign.TaskID, 2)

	statuses, err := postgres.NewCloudStatusStore(baseStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statuses.GetWorker(ctx, "owner-b", first.DeploymentID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("cross-owner Worker read error=%v", err)
	}
	if _, err := statuses.GetResource(ctx, "owner-b", ownedResource.ResourceID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("cross-owner resource read error=%v", err)
	}

	firstPage, err := statuses.ListWorkers(ctx, cloudstatus.ListQuery{OwnerID: "owner-a", PageSize: 1})
	if err != nil || len(firstPage.Workers) != 1 || firstPage.NextPageToken == "" {
		t.Fatalf("first Worker page=%+v err=%v", firstPage, err)
	}
	secondPage, err := statuses.ListWorkers(ctx, cloudstatus.ListQuery{OwnerID: "owner-a", PageSize: 1, PageToken: firstPage.NextPageToken})
	if err != nil || len(secondPage.Workers) != 1 || secondPage.NextPageToken != "" || secondPage.Workers[0].DeploymentID == firstPage.Workers[0].DeploymentID {
		t.Fatalf("second Worker page=%+v err=%v", secondPage, err)
	}
	seen := map[string]bool{firstPage.Workers[0].DeploymentID: true, secondPage.Workers[0].DeploymentID: true}
	if !seen[first.DeploymentID] || !seen[second.DeploymentID] || seen[foreign.DeploymentID] {
		t.Fatalf("owner-filtered Worker IDs=%v", seen)
	}

	resources, err := statuses.ListResources(ctx, cloudstatus.ListQuery{OwnerID: "owner-a", DeploymentID: first.DeploymentID, PageSize: 10})
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].ResourceID != ownedResource.ResourceID ||
		resources.Resources[0].ReadBack.ProviderID != ownedResource.ProviderID || resources.Resources[0].Revision != ownedResource.Revision {
		t.Fatalf("owner-filtered resources=%+v err=%v", resources, err)
	}
	// A CloudDeployment exists only after the immutable launch record binds its
	// Worker to an approved Plan and CloudConnection. The orphan import above
	// uses that same durable origin instead of creating an unowned ledger fact.
	var expectedPlanID, expectedConnectionID string
	if err := pool.QueryRow(ctx, `
		SELECT plan_id::text, connection_id::text
		FROM cloud_launch_operations
		WHERE agent_instance_id=$1 AND deployment_id=$2`, instanceID, first.DeploymentID).Scan(&expectedPlanID, &expectedConnectionID); err != nil {
		t.Fatal(err)
	}

	linked, err := statuses.GetDeployment(ctx, first.OwnerID, first.DeploymentID)
	if err != nil || linked.Worker.DeploymentID != first.DeploymentID || linked.PlanID != expectedPlanID || linked.ConnectionID != expectedConnectionID {
		t.Fatalf("durable cloud deployment=%+v err=%v", linked, err)
	}
	if _, err := statuses.GetDeployment(ctx, "owner-b", first.DeploymentID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("cross-owner cloud deployment read error=%v", err)
	}
	deploymentFirstPage, err := statuses.ListDeployments(ctx, cloudstatus.ListQuery{OwnerID: "owner-a", PageSize: 1})
	if err != nil || len(deploymentFirstPage.Deployments) != 1 || deploymentFirstPage.NextPageToken == "" {
		t.Fatalf("first CloudDeployment page=%+v err=%v", deploymentFirstPage, err)
	}
	if _, err := statuses.ListDeployments(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-a", PageSize: 1, PageToken: firstPage.NextPageToken,
	}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("Worker cursor was accepted by CloudDeployment pagination: %v", err)
	}
	if _, err := statuses.ListWorkers(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-a", PageSize: 1, PageToken: deploymentFirstPage.NextPageToken,
	}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("CloudDeployment cursor was accepted by Worker pagination: %v", err)
	}
	deploymentSecondPage, err := statuses.ListDeployments(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-a", PageSize: 1, PageToken: deploymentFirstPage.NextPageToken,
	})
	if err != nil || len(deploymentSecondPage.Deployments) != 1 || deploymentSecondPage.NextPageToken != "" ||
		deploymentSecondPage.Deployments[0].Worker.DeploymentID == deploymentFirstPage.Deployments[0].Worker.DeploymentID {
		t.Fatalf("second CloudDeployment page=%+v err=%v", deploymentSecondPage, err)
	}
	for _, deployment := range append(deploymentFirstPage.Deployments, deploymentSecondPage.Deployments...) {
		if deployment.PlanID == "" || deployment.ConnectionID == "" || deployment.Worker.OwnerID != "owner-a" {
			t.Fatalf("incomplete CloudDeployment relation=%+v", deployment)
		}
	}

	restartedBaseStore, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	restartedStatuses, err := postgres.NewCloudStatusStore(restartedBaseStore)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := restartedStatuses.GetDeployment(ctx, first.OwnerID, first.DeploymentID)
	if err != nil || reloaded.PlanID != expectedPlanID || reloaded.ConnectionID != expectedConnectionID || reloaded.Worker.Revision != first.Revision {
		t.Fatalf("restarted CloudDeployment=%+v err=%v", reloaded, err)
	}
}
