package app

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

type workerPrincipalBinderFake struct {
	request awsartifact.PrincipalBindRequest
	result  awsartifact.PrincipalBinding
	calls   int
}

func (fake *workerPrincipalBinderFake) Bind(_ context.Context, request awsartifact.PrincipalBindRequest) (awsartifact.PrincipalBinding, error) {
	fake.calls++
	fake.request = request
	return fake.result, nil
}

func TestWorkerIdentityMaterializerBindsOnlyDurableSourceToVerifiedPrincipal(t *testing.T) {
	fixture := newWorkerIdentityMaterializerFixture(t)
	materialized, err := fixture.materializer.MaterializeWorkerIdentity(context.Background(), fixture.challenge, fixture.identity)
	if err != nil {
		t.Fatalf("MaterializeWorkerIdentity() error = %v", err)
	}
	if fixture.binder.calls != 1 || fixture.binder.request.STSUserID != fixture.identity.PrincipalID || fixture.binder.request.InstanceID != fixture.identity.InstanceID ||
		fixture.binder.request.Published.Recipe != fixture.deployments.deployment.RecipeBundle || fixture.binder.request.Published.Execution != fixture.deployments.deployment.ExecutionBundle {
		t.Fatalf("binder request = %+v calls=%d", fixture.binder.request, fixture.binder.calls)
	}
	if err := materialized.Validate(fixture.identity.PrincipalID, fixture.challenge.DeploymentID); err != nil {
		t.Fatalf("materialized scope is invalid: %v", err)
	}
}

func TestWorkerIdentityMaterializerRejectsFactDriftBeforeS3(t *testing.T) {
	tests := map[string]func(*workerIdentityMaterializerFixture){
		"identity instance": func(fixture *workerIdentityMaterializerFixture) { fixture.identity.InstanceID = "i-0fedcba9876543210" },
		"source recipe": func(fixture *workerIdentityMaterializerFixture) {
			fixture.deployments.deployment.RecipeBundle.S3Ref += ".changed"
		},
		"connection account": func(fixture *workerIdentityMaterializerFixture) {
			fixture.connection.connection.AccountID = "999999999999"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkerIdentityMaterializerFixture(t)
			mutate(&fixture)
			_, err := fixture.materializer.MaterializeWorkerIdentity(context.Background(), fixture.challenge, fixture.identity)
			if !errors.Is(err, worker.ErrIdentityRejected) || fixture.binder.calls != 0 {
				t.Fatalf("error=%v binder calls=%d", err, fixture.binder.calls)
			}
		})
	}
}

type workerIdentityMaterializerFixture struct {
	materializer *workerIdentityMaterializer
	challenge    worker.IdentityChallenge
	identity     workeridentity.VerifiedIdentity
	deployments  *identityDeploymentFake
	connection   *identityConnectionFake
	binder       *workerPrincipalBinderFake
}

func newWorkerIdentityMaterializerFixture(t *testing.T) workerIdentityMaterializerFixture {
	t.Helper()
	deploymentID, workerID, taskID, connectionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	principalID, instanceID := "AROAABCDEFGHIJKLMNOP:i-0123456789abcdef0", "i-0123456789abcdef0"
	sourceBase := "s3://foundation/deployments/" + deploymentID + "/"
	targetBase := "s3://foundation/workers/" + principalID + "/" + deploymentID + "/"
	deployment := worker.Deployment{
		DeploymentID: deploymentID, OwnerID: "owner-1", TaskID: taskID, State: worker.StatePendingEnrollment,
		RecipeBundle:    worker.BundleRef{S3Ref: sourceBase + "bundles/recipe.cbor", SHA256: [32]byte{1}},
		ExecutionBundle: worker.BundleRef{S3Ref: sourceBase + "bundles/execution.json", SHA256: [32]byte{2}},
		Access: worker.AccessScope{
			ArtifactPrefix: sourceBase + "artifacts/", CheckpointPrefix: sourceBase + "checkpoints/", EvidencePrefix: sourceBase + "evidence/",
			LogPrefix: "cloudwatch://stack/deployment", SecretRefs: []string{},
		},
		Revision: 1,
	}
	operation := cloudexecution.Operation{
		Intent: cloudexecution.Intent{
			Launch: cloudexecution.LaunchRequest{OwnerID: deployment.OwnerID}, ConnectionID: connectionID, DeploymentID: deploymentID,
		},
		State: cloudexecution.StateProvisioning, TaskID: taskID, RecipeBundle: deployment.RecipeBundle, ExecutionBundle: deployment.ExecutionBundle,
	}
	connection := &identityConnectionFake{connection: cloudapp.Connection{
		ConnectionID: connectionID, OwnerID: deployment.OwnerID, AccountID: "123456789012", Region: "us-east-1",
		FoundationStack: "dtx-agent-test", Status: "active", Revision: 1,
	}}
	binder := &workerPrincipalBinderFake{result: awsartifact.PrincipalBinding{
		Recipe:         worker.BundleRef{S3Ref: targetBase + "bundles/recipe.cbor", SHA256: deployment.RecipeBundle.SHA256},
		Execution:      worker.BundleRef{S3Ref: targetBase + "bundles/execution.json", SHA256: deployment.ExecutionBundle.SHA256},
		ArtifactPrefix: targetBase + "artifacts/", CheckpointPrefix: targetBase + "checkpoints/", EvidencePrefix: targetBase + "evidence/",
		CloudWatchLogGroup: "/dirextalk/agent/test/worker", CloudWatchLogStream: "AROAABCDEFGHIJKLMNOP/" + instanceID,
		LogPrefix: "cloudwatch://dtx-agent-test/AROAABCDEFGHIJKLMNOP/" + instanceID,
	}}
	deployments := &identityDeploymentFake{deployment: deployment}
	materializer, err := newWorkerIdentityMaterializer(identityLaunchFake{operation}, connection, deployments, binder)
	if err != nil {
		t.Fatal(err)
	}
	challenge := worker.IdentityChallenge{
		ChallengeID: uuid.NewString(), DeploymentID: deploymentID, WorkerID: workerID, OwnerID: deployment.OwnerID,
		AccountID: connection.connection.AccountID, Region: connection.connection.Region, ExpectedProviderInstanceID: instanceID, ExpectedRevision: 1,
	}
	identity := workeridentity.VerifiedIdentity{
		Partition: "aws", AccountID: challenge.AccountID, Region: challenge.Region, WorkerRoleName: "worker-role",
		InstanceID: instanceID, PrincipalID: principalID, DeploymentID: deploymentID, OwnerID: deployment.OwnerID,
		Trust: workeridentity.TrustSTSAndEC2ReadBack,
	}
	return workerIdentityMaterializerFixture{
		materializer: materializer, challenge: challenge, identity: identity, deployments: deployments, connection: connection, binder: binder,
	}
}
