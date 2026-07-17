package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
)

type workerPrincipalBinder interface {
	Bind(context.Context, awsartifact.PrincipalBindRequest) (awsartifact.PrincipalBinding, error)
}

type workerIdentityMaterializer struct {
	launches    workerIdentityLaunchReader
	connections workerIdentityConnectionReader
	deployments workerIdentityDeploymentReader
	binder      workerPrincipalBinder
}

func newWorkerIdentityMaterializer(
	launches workerIdentityLaunchReader,
	connections workerIdentityConnectionReader,
	deployments workerIdentityDeploymentReader,
	binder workerPrincipalBinder,
) (*workerIdentityMaterializer, error) {
	if launches == nil || connections == nil || deployments == nil || binder == nil {
		return nil, cloudapp.ErrInvalid
	}
	return &workerIdentityMaterializer{launches: launches, connections: connections, deployments: deployments, binder: binder}, nil
}

func (materializer *workerIdentityMaterializer) MaterializeWorkerIdentity(
	ctx context.Context,
	challenge worker.IdentityChallenge,
	identity workeridentity.VerifiedIdentity,
) (worker.IdentityMaterialization, error) {
	if materializer == nil || ctx == nil || identity.Trust != workeridentity.TrustSTSAndEC2ReadBack ||
		challenge.DeploymentID == "" || challenge.WorkerID == "" || challenge.OwnerID == "" || challenge.AccountID == "" || challenge.Region == "" ||
		identity.DeploymentID != challenge.DeploymentID || identity.OwnerID != challenge.OwnerID || identity.AccountID != challenge.AccountID || identity.Region != challenge.Region ||
		identity.InstanceID != challenge.ExpectedProviderInstanceID || identity.PrincipalID == "" {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	operation, err := materializer.launches.GetByDeployment(ctx, challenge.DeploymentID)
	if err != nil || operation.DeploymentID != challenge.DeploymentID || operation.Launch.OwnerID != challenge.OwnerID || operation.ConnectionID == "" ||
		(operation.State != cloudexecution.StateProvisioning && operation.State != cloudexecution.StateActive) {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	deployment, err := materializer.deployments.Get(ctx, challenge.DeploymentID)
	if err != nil || deployment.DeploymentID != challenge.DeploymentID || deployment.OwnerID != challenge.OwnerID || deployment.TaskID != operation.TaskID ||
		deployment.State != worker.StatePendingEnrollment || deployment.ProviderInstanceID != "" ||
		(deployment.WorkerID != "" && deployment.WorkerID != challenge.WorkerID) ||
		operation.RecipeBundle != deployment.RecipeBundle || operation.ExecutionBundle != deployment.ExecutionBundle {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	connection, err := materializer.connections.LoadConnection(ctx, challenge.OwnerID, operation.ConnectionID)
	if err != nil || connection.Status != "active" || connection.OwnerID != challenge.OwnerID || connection.AccountID != challenge.AccountID || connection.Region != challenge.Region ||
		strings.TrimSpace(connection.FoundationStack) == "" {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	published := cloudexecution.PublishedBundles{
		Recipe: operation.RecipeBundle, Execution: operation.ExecutionBundle, Access: deployment.Access,
		SecretBindings: installerSecretBindings(operation), InstallerRootTrust: operation.InstallerRootTrust,
		InstallerSecrets: append([]installerbootstrap.SecretSourceV1(nil), operation.InstallerSecrets...),
	}
	bound, err := materializer.binder.Bind(ctx, awsartifact.PrincipalBindRequest{
		Connection: connection, DeploymentID: challenge.DeploymentID, InstanceID: identity.InstanceID,
		STSUserID: identity.PrincipalID, Published: published,
	})
	if err != nil {
		return worker.IdentityMaterialization{}, worker.ErrIdentityUnavailable
	}
	result := worker.IdentityMaterialization{
		RecipeBundle: bound.Recipe, ExecutionBundle: bound.Execution,
		Access: worker.AccessScope{
			ArtifactPrefix: bound.ArtifactPrefix, CheckpointPrefix: bound.CheckpointPrefix, EvidencePrefix: bound.EvidencePrefix,
			LogPrefix:  bound.LogPrefix,
			SecretRefs: append([]string(nil), deployment.Access.SecretRefs...),
		},
	}
	if err := result.Validate(identity.PrincipalID, challenge.DeploymentID); err != nil {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	return result, nil
}

func installerSecretBindings(operation cloudexecution.Operation) map[string]string {
	result := make(map[string]string, len(operation.InstallerSecrets))
	for _, source := range operation.InstallerSecrets {
		result[source.SecretRef] = "secret://aws/deployments/" + operation.DeploymentID + "/" + source.SlotID + "/" + source.VersionID
	}
	return result
}
