package app

import (
	"context"
	"reflect"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

type workerIdentityLaunchEvidence struct {
	OwnerID          string
	ConnectionID     string
	TaskID           string
	DeploymentID     string
	ApprovedPlanHash string
	ApprovalID       string
	Published        cloudexecution.PublishedBundles
}

type workerIdentityLaunchResolver struct {
	classic workerIdentityLaunchReader
	team    teamdispatch.WorkerLaunchReader
}

func newWorkerIdentityLaunchResolver(
	classic workerIdentityLaunchReader,
	team []teamdispatch.WorkerLaunchReader,
) (*workerIdentityLaunchResolver, error) {
	if classic == nil || len(team) > 1 || (len(team) == 1 && team[0] == nil) {
		return nil, worker.ErrInvalid
	}
	resolver := &workerIdentityLaunchResolver{classic: classic}
	if len(team) == 1 {
		resolver.team = team[0]
	}
	return resolver, nil
}

func (resolver *workerIdentityLaunchResolver) Resolve(
	ctx context.Context,
	ownerID string,
	deployment worker.Deployment,
) (workerIdentityLaunchEvidence, error) {
	if resolver == nil ||
		resolver.classic == nil ||
		ctx == nil ||
		deployment.DeploymentID == "" ||
		deployment.OwnerID != ownerID {
		return workerIdentityLaunchEvidence{}, worker.ErrIdentityRejected
	}
	operation, classicErr := resolver.classic.GetByDeployment(
		ctx,
		deployment.DeploymentID,
	)
	if classicErr == nil {
		evidence := workerIdentityLaunchEvidence{
			OwnerID:          operation.Launch.OwnerID,
			ConnectionID:     operation.ConnectionID,
			TaskID:           operation.TaskID,
			DeploymentID:     operation.DeploymentID,
			ApprovedPlanHash: operation.ApprovedPlanHash,
			ApprovalID:       operation.Launch.ApprovalID,
			Published: cloudexecution.PublishedBundles{
				Recipe:    operation.RecipeBundle,
				Execution: operation.ExecutionBundle,
				Access:    deployment.Access,
				SecretBindings: installerSecretBindingsFromSources(
					operation.DeploymentID,
					operation.InstallerSecrets,
				),
				InstallerRootTrust: operation.InstallerRootTrust,
				InstallerSecrets: append(
					[]installerbootstrap.SecretSourceV1{},
					operation.InstallerSecrets...,
				),
			},
		}
		if (operation.State != cloudexecution.StateProvisioning &&
			operation.State != cloudexecution.StateActive) ||
			evidence.validate(deployment) != nil {
			return workerIdentityLaunchEvidence{},
				worker.ErrIdentityRejected
		}
		return evidence, nil
	}
	if resolver.team == nil {
		return workerIdentityLaunchEvidence{}, worker.ErrIdentityRejected
	}
	teamLaunch, teamErr := resolver.team.LoadWorkerLaunchByDeployment(
		ctx,
		ownerID,
		deployment.DeploymentID,
	)
	if teamErr != nil || teamLaunch.ValidateForIdentity() != nil {
		return workerIdentityLaunchEvidence{}, worker.ErrIdentityRejected
	}
	published, err := teamLaunch.Dispatch.PublishedEvidence.
		PublishedBundles()
	if err != nil {
		return workerIdentityLaunchEvidence{}, worker.ErrIdentityRejected
	}
	evidence := workerIdentityLaunchEvidence{
		OwnerID:          teamLaunch.Dispatch.Intent.OwnerID,
		ConnectionID:     teamLaunch.Dispatch.PublishedEvidence.ConnectionID,
		TaskID:           teamLaunch.Dispatch.Intent.TaskID,
		DeploymentID:     teamLaunch.Dispatch.Intent.DeploymentID,
		ApprovedPlanHash: teamLaunch.Dispatch.Intent.PlanDigest,
		ApprovalID:       teamLaunch.Dispatch.Intent.ApprovalID,
		Published:        published,
	}
	if evidence.validate(deployment) != nil {
		return workerIdentityLaunchEvidence{}, worker.ErrIdentityRejected
	}
	return evidence, nil
}

func (evidence workerIdentityLaunchEvidence) validate(
	deployment worker.Deployment,
) error {
	connectionID, connectionErr := uuid.Parse(evidence.ConnectionID)
	taskID, taskErr := uuid.Parse(evidence.TaskID)
	deploymentID, deploymentErr := uuid.Parse(evidence.DeploymentID)
	approvalID, approvalErr := uuid.Parse(evidence.ApprovalID)
	if evidence.OwnerID == "" ||
		evidence.OwnerID != deployment.OwnerID ||
		connectionErr != nil ||
		connectionID == uuid.Nil ||
		taskErr != nil ||
		taskID == uuid.Nil ||
		deploymentErr != nil ||
		deploymentID == uuid.Nil ||
		approvalErr != nil ||
		approvalID == uuid.Nil ||
		evidence.TaskID != deployment.TaskID ||
		evidence.DeploymentID != deployment.DeploymentID ||
		!strings.HasPrefix(evidence.ApprovedPlanHash, "sha256:") ||
		len(evidence.ApprovedPlanHash) != 71 ||
		evidence.Published.Recipe != deployment.RecipeBundle ||
		evidence.Published.Execution != deployment.ExecutionBundle ||
		!reflect.DeepEqual(evidence.Published.Access, deployment.Access) ||
		len(evidence.Published.SecretBindings) !=
			len(deployment.Access.SecretRefs) ||
		len(evidence.Published.InstallerSecrets) !=
			len(deployment.Access.SecretRefs) {
		return worker.ErrIdentityRejected
	}
	if len(evidence.Published.InstallerSecrets) != 0 &&
		evidence.Published.InstallerRootTrust == nil {
		return worker.ErrIdentityRejected
	}
	for _, source := range evidence.Published.InstallerSecrets {
		bound, found := evidence.Published.SecretBindings[source.SecretRef]
		if !found || !containsString(deployment.Access.SecretRefs, bound) {
			return worker.ErrIdentityRejected
		}
	}
	return nil
}

func installerSecretBindingsFromSources(
	deploymentID string,
	sources []installerbootstrap.SecretSourceV1,
) map[string]string {
	result := make(map[string]string, len(sources))
	for _, source := range sources {
		result[source.SecretRef] = "secret://aws/deployments/" +
			deploymentID + "/" + source.SlotID + "/" + source.VersionID
	}
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
