package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
)

type workerPrincipalBinder interface {
	Bind(context.Context, awsartifact.PrincipalBindRequest) (awsartifact.PrincipalBinding, error)
}

type workerIdentityMaterializer struct {
	launches    *workerIdentityLaunchResolver
	connections workerIdentityConnectionReader
	deployments workerIdentityDeploymentReader
	binder      workerPrincipalBinder
}

func newWorkerIdentityMaterializer(
	launches workerIdentityLaunchReader,
	connections workerIdentityConnectionReader,
	deployments workerIdentityDeploymentReader,
	binder workerPrincipalBinder,
	teamLaunches ...teamdispatch.WorkerLaunchReader,
) (*workerIdentityMaterializer, error) {
	if launches == nil || connections == nil || deployments == nil || binder == nil {
		return nil, cloudapp.ErrInvalid
	}
	resolver, err := newWorkerIdentityLaunchResolver(
		launches,
		teamLaunches,
	)
	if err != nil {
		return nil, cloudapp.ErrInvalid
	}
	return &workerIdentityMaterializer{
		launches: resolver, connections: connections,
		deployments: deployments, binder: binder,
	}, nil
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
	deployment, err := materializer.deployments.Get(ctx, challenge.DeploymentID)
	if err != nil || deployment.DeploymentID != challenge.DeploymentID || deployment.OwnerID != challenge.OwnerID {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	if replay, ok := replayedWorkerIdentityMaterialization(
		deployment,
		challenge,
		identity,
	); ok {
		return replay, nil
	}
	if deployment.State != worker.StatePendingEnrollment ||
		deployment.ProviderInstanceID != "" ||
		(deployment.WorkerID != "" && deployment.WorkerID != challenge.WorkerID) {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	launch, err := materializer.launches.Resolve(
		ctx,
		challenge.OwnerID,
		deployment,
	)
	if err != nil {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	connection, err := materializer.connections.LoadConnection(ctx, challenge.OwnerID, launch.ConnectionID)
	if err != nil || connection.Status != "active" || connection.OwnerID != challenge.OwnerID || connection.AccountID != challenge.AccountID || connection.Region != challenge.Region ||
		strings.TrimSpace(connection.FoundationStack) == "" {
		return worker.IdentityMaterialization{}, worker.ErrIdentityRejected
	}
	bound, err := materializer.binder.Bind(ctx, awsartifact.PrincipalBindRequest{
		Connection: connection, DeploymentID: challenge.DeploymentID, InstanceID: identity.InstanceID,
		STSUserID: identity.PrincipalID, Published: launch.Published,
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

func replayedWorkerIdentityMaterialization(
	deployment worker.Deployment,
	challenge worker.IdentityChallenge,
	identity workeridentity.VerifiedIdentity,
) (worker.IdentityMaterialization, bool) {
	switch deployment.State {
	case worker.StateReady, worker.StateLeased, worker.StateCancelRequested:
	default:
		return worker.IdentityMaterialization{}, false
	}
	if deployment.WorkerID != challenge.WorkerID ||
		deployment.ProviderInstanceID != identity.InstanceID ||
		deployment.Enrollment.ConsumedAt.IsZero() {
		return worker.IdentityMaterialization{}, false
	}
	result := worker.IdentityMaterialization{
		RecipeBundle:    deployment.RecipeBundle,
		ExecutionBundle: deployment.ExecutionBundle,
		Access: worker.AccessScope{
			ArtifactPrefix:   deployment.Access.ArtifactPrefix,
			CheckpointPrefix: deployment.Access.CheckpointPrefix,
			EvidencePrefix:   deployment.Access.EvidencePrefix,
			LogPrefix:        deployment.Access.LogPrefix,
			SecretRefs:       append([]string(nil), deployment.Access.SecretRefs...),
		},
	}
	if result.Validate(identity.PrincipalID, challenge.DeploymentID) != nil {
		return worker.IdentityMaterialization{}, false
	}
	return result, true
}
