package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

type identityLaunchFake struct{ operation cloudexecution.Operation }

func (fake identityLaunchFake) GetByDeployment(context.Context, string) (cloudexecution.Operation, error) {
	return fake.operation, nil
}

type identityConnectionFake struct{ connection cloudapp.Connection }

func (fake identityConnectionFake) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return fake.connection, nil
}

type identityResourceFake struct{ resources []resource.ResourceV1 }

func (fake identityResourceFake) ListDeployment(context.Context, string) ([]resource.ResourceV1, error) {
	return append([]resource.ResourceV1(nil), fake.resources...), nil
}

type identityDeploymentFake struct{ deployment worker.Deployment }

func (fake identityDeploymentFake) Get(context.Context, string) (worker.Deployment, error) {
	return fake.deployment, nil
}

type identityProviderFake struct {
	evidence awsprovider.WorkerInstanceIdentityEvidence
	request  awsprovider.WorkerInstanceIdentityRequest
	calls    int
}

func (fake *identityProviderFake) VerifyWorkerInstanceIdentity(_ context.Context, request awsprovider.WorkerInstanceIdentityRequest) (awsprovider.WorkerInstanceIdentityEvidence, error) {
	fake.calls++
	fake.request = request
	return fake.evidence, nil
}

type identityProviderFactoryFake struct{ provider *identityProviderFake }

func (fake identityProviderFactoryFake) WorkerIdentityVerifier(context.Context, cloudapp.Connection) (awsprovider.WorkerInstanceIdentityVerifier, error) {
	return fake.provider, nil
}

func TestWorkerIdentityAuthorizerJoinsDurableFactsBeforeExactEC2ReadBack(t *testing.T) {
	fixture := newWorkerIdentityAuthorizerFixture(t)
	evidence, err := fixture.authorizer.AuthorizeDeployment(context.Background(), fixture.claim)
	if err != nil {
		t.Fatalf("AuthorizeDeployment() error = %v", err)
	}
	if !evidence.Authorized || !evidence.Exists || !evidence.TagsVerified || evidence.InstanceID != fixture.claim.InstanceID || fixture.provider.calls != 1 {
		t.Fatalf("evidence=%+v calls=%d", evidence, fixture.provider.calls)
	}
	if fixture.provider.request.InstanceID != fixture.claim.InstanceID || fixture.provider.request.WorkerProfileName != fixture.claim.WorkerRoleName || len(fixture.provider.request.ExpectedOwnershipTags) != 7 {
		t.Fatalf("typed provider request = %+v", fixture.provider.request)
	}
	for _, key := range []string{resource.TagAgentInstanceID, resource.TagOwnerID, resource.TagTaskID, resource.TagDeploymentID, resource.TagResourceID, resource.TagRetention, resource.TagDestroyDeadline} {
		if fixture.provider.request.ExpectedOwnershipTags[key] == "" {
			t.Fatalf("ownership tag %s was not independently supplied", key)
		}
	}
}

func TestWorkerIdentityAuthorizerFailsClosedBeforeProviderOnFactMismatch(t *testing.T) {
	tests := map[string]func(*workerIdentityAuthorizerFixture){
		"claim owner": func(fixture *workerIdentityAuthorizerFixture) { fixture.claim.OwnerID = "other-owner" },
		"provider instance": func(fixture *workerIdentityAuthorizerFixture) {
			fixture.resources.resources[0].ProviderID = "i-0fedcba9876543210"
		},
		"approval": func(fixture *workerIdentityAuthorizerFixture) {
			fixture.resources.resources[0].ApprovalID = uuid.NewString()
		},
		"worker already bound": func(fixture *workerIdentityAuthorizerFixture) {
			fixture.deployments.deployment.ProviderInstanceID = fixture.claim.InstanceID
		},
		"duplicate instance": func(fixture *workerIdentityAuthorizerFixture) {
			fixture.resources.resources = append(fixture.resources.resources, fixture.resources.resources[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkerIdentityAuthorizerFixture(t)
			mutate(&fixture)
			_, err := fixture.authorizer.AuthorizeDeployment(context.Background(), fixture.claim)
			if !errors.Is(err, workeridentity.ErrIdentityRejected) || fixture.provider.calls != 0 {
				t.Fatalf("error=%v provider calls=%d", err, fixture.provider.calls)
			}
		})
	}
}

type workerIdentityAuthorizerFixture struct {
	authorizer  *workerIdentityAuthorizer
	claim       workeridentity.DeploymentClaim
	resources   *identityResourceFake
	deployments *identityDeploymentFake
	provider    *identityProviderFake
}

func newWorkerIdentityAuthorizerFixture(t *testing.T) workerIdentityAuthorizerFixture {
	t.Helper()
	now := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	agentID, deploymentID, taskID, resourceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	approvalID, connectionID := uuid.NewString(), uuid.NewString()
	accountID, region, ownerID, instanceID := "123456789012", "us-east-1", "owner-1", "i-0123456789abcdef0"
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: agentID, Partition: "aws", AccountID: accountID, Region: region})
	if err != nil {
		t.Fatal(err)
	}
	connection := cloudapp.Connection{
		ConnectionID: connectionID, OwnerID: ownerID, AccountID: accountID, Region: region,
		ControlRoleARN:  "arn:aws:iam::" + accountID + ":role/" + foundation.ControlRoleName,
		FoundationStack: foundation.StackName, Status: "active", Revision: 1,
	}
	operation := cloudexecution.Operation{
		Intent: cloudexecution.Intent{
			Launch: cloudexecution.LaunchRequest{OwnerID: ownerID, ApprovalID: approvalID}, ConnectionID: connectionID,
			ApprovedPlanHash: "sha256:" + strings.Repeat("a", 64), DeploymentID: deploymentID,
		},
		State: cloudexecution.StateProvisioning, TaskID: taskID, Revision: 6,
	}
	tags := map[string]string{
		resource.TagAgentInstanceID: agentID, resource.TagOwnerID: ownerID, resource.TagTaskID: taskID,
		resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
		resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: now.Add(time.Hour).Format(time.RFC3339),
	}
	resources := &identityResourceFake{resources: []resource.ResourceV1{{
		ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID,
		Type: resource.TypeEC2, Region: region, ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: approvalID,
		ProviderID: instanceID, Tags: tags, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: instanceID, ObservedAt: now, TagDigest: "sha256:" + strings.Repeat("b", 64)},
	}}}
	deployments := &identityDeploymentFake{deployment: worker.Deployment{
		DeploymentID: deploymentID, OwnerID: ownerID, TaskID: taskID, State: worker.StatePendingEnrollment, Revision: 1,
	}}
	provider := &identityProviderFake{evidence: awsprovider.WorkerInstanceIdentityEvidence{
		InstanceID: instanceID, AccountID: accountID, Region: region, WorkerProfileName: foundation.WorkerRoleName,
		PrimaryNetworkInterfaceID: "eni-0123456789abcdef0", TagDigest: "sha256:" + strings.Repeat("c", 64), ObservedAt: now,
	}}
	authorizer, err := newWorkerIdentityAuthorizer(agentID, identityLaunchFake{operation}, identityConnectionFake{connection}, resources, deployments, identityProviderFactoryFake{provider})
	if err != nil {
		t.Fatal(err)
	}
	return workerIdentityAuthorizerFixture{
		authorizer: authorizer, resources: resources, deployments: deployments, provider: provider,
		claim: workeridentity.DeploymentClaim{
			AgentInstanceID: agentID, OwnerID: ownerID, DeploymentID: deploymentID, Partition: "aws", AccountID: accountID,
			Region: region, WorkerRoleName: foundation.WorkerRoleName, InstanceID: instanceID, PrincipalID: "AROAABCDEFGHIJKLMNOP:" + instanceID,
		},
	}
}
