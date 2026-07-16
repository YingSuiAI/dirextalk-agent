package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

type workerIdentityLaunchReader interface {
	GetByDeployment(context.Context, string) (cloudexecution.Operation, error)
}

type workerIdentityConnectionReader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type workerIdentityResourceReader interface {
	ListDeployment(context.Context, string) ([]resource.ResourceV1, error)
}

type workerIdentityDeploymentReader interface {
	Get(context.Context, string) (worker.Deployment, error)
}

type workerIdentityProviderFactory interface {
	WorkerIdentityVerifier(context.Context, cloudapp.Connection) (awsprovider.WorkerInstanceIdentityVerifier, error)
}

// workerIdentityAuthorizer independently joins the durable launch, Worker,
// connection, and resource ledgers before asking the typed EC2 provider for a
// fresh read-back. No identity coordinate supplied by the enrolling VM is
// accepted as an ownership fact by itself.
type workerIdentityAuthorizer struct {
	agentInstanceID string
	launches        workerIdentityLaunchReader
	connections     workerIdentityConnectionReader
	resources       workerIdentityResourceReader
	deployments     workerIdentityDeploymentReader
	providers       workerIdentityProviderFactory
}

func newWorkerIdentityAuthorizer(
	agentInstanceID string,
	launches workerIdentityLaunchReader,
	connections workerIdentityConnectionReader,
	resources workerIdentityResourceReader,
	deployments workerIdentityDeploymentReader,
	providers workerIdentityProviderFactory,
) (*workerIdentityAuthorizer, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || launches == nil || connections == nil || resources == nil || deployments == nil || providers == nil {
		return nil, cloudapp.ErrInvalid
	}
	return &workerIdentityAuthorizer{
		agentInstanceID: parsed.String(), launches: launches, connections: connections,
		resources: resources, deployments: deployments, providers: providers,
	}, nil
}

func (authorizer *workerIdentityAuthorizer) AuthorizeDeployment(ctx context.Context, claim workeridentity.DeploymentClaim) (workeridentity.DeploymentEvidence, error) {
	if authorizer == nil || ctx == nil || claim.AgentInstanceID != authorizer.agentInstanceID || claim.OwnerID == "" || claim.DeploymentID == "" || claim.InstanceID == "" {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	operation, err := authorizer.launches.GetByDeployment(ctx, claim.DeploymentID)
	if err != nil || operation.DeploymentID != claim.DeploymentID || operation.Launch.OwnerID != claim.OwnerID || operation.ConnectionID == "" || operation.ApprovedPlanHash == "" ||
		(operation.State != cloudexecution.StateProvisioning && operation.State != cloudexecution.StateActive) {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	deployment, err := authorizer.deployments.Get(ctx, claim.DeploymentID)
	if err != nil || deployment.DeploymentID != claim.DeploymentID || deployment.OwnerID != claim.OwnerID || deployment.TaskID != operation.TaskID ||
		deployment.State != worker.StatePendingEnrollment || deployment.ProviderInstanceID != "" {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	connection, err := authorizer.connections.LoadConnection(ctx, claim.OwnerID, operation.ConnectionID)
	if err != nil || connection.Status != "active" || connection.OwnerID != claim.OwnerID || connection.AccountID != claim.AccountID || connection.Region != claim.Region {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	role, err := arn.Parse(connection.ControlRoleARN)
	if err != nil || role.Partition != claim.Partition || role.AccountID != claim.AccountID {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: authorizer.agentInstanceID, Partition: claim.Partition, AccountID: claim.AccountID, Region: claim.Region,
	})
	if err != nil || role.Resource != "role/"+foundation.ControlRoleName || foundation.WorkerRoleName != claim.WorkerRoleName {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}

	ledger, err := authorizer.resources.ListDeployment(ctx, claim.DeploymentID)
	if err != nil {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	var instance *resource.ResourceV1
	for index := range ledger {
		candidate := &ledger[index]
		if candidate.Type != resource.TypeEC2 {
			continue
		}
		if instance != nil {
			return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
		}
		instance = candidate
	}
	if instance == nil || instance.State != resource.StateActive || !instance.ReadBack.Exists || instance.ProviderID != claim.InstanceID || instance.ReadBack.ProviderID != claim.InstanceID ||
		instance.AgentInstanceID != authorizer.agentInstanceID || instance.OwnerID != claim.OwnerID || instance.DeploymentID != claim.DeploymentID || instance.TaskID != operation.TaskID ||
		instance.Region != claim.Region || instance.ApprovedPlanHash != operation.ApprovedPlanHash || instance.ApprovalID != operation.Launch.ApprovalID {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}

	expectedTags := map[string]string{
		resource.TagAgentInstanceID: instance.Tags[resource.TagAgentInstanceID],
		resource.TagOwnerID:         instance.Tags[resource.TagOwnerID],
		resource.TagTaskID:          instance.Tags[resource.TagTaskID],
		resource.TagDeploymentID:    instance.Tags[resource.TagDeploymentID],
		resource.TagResourceID:      instance.Tags[resource.TagResourceID],
		resource.TagRetention:       instance.Tags[resource.TagRetention],
		resource.TagDestroyDeadline: instance.Tags[resource.TagDestroyDeadline],
	}
	for _, value := range expectedTags {
		if strings.TrimSpace(value) == "" {
			return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
		}
	}
	provider, err := authorizer.providers.WorkerIdentityVerifier(ctx, connection)
	if err != nil || provider == nil {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	observed, err := provider.VerifyWorkerInstanceIdentity(ctx, awsprovider.WorkerInstanceIdentityRequest{
		InstanceID: claim.InstanceID, Region: claim.Region, WorkerProfileName: foundation.WorkerProfileName,
		ExpectedOwnershipTags: expectedTags,
	})
	if err != nil || observed.InstanceID != claim.InstanceID || observed.AccountID != claim.AccountID || observed.Region != claim.Region || observed.WorkerProfileName != claim.WorkerRoleName {
		return workeridentity.DeploymentEvidence{}, workeridentity.ErrIdentityRejected
	}
	return workeridentity.DeploymentEvidence{
		Authorized: true, Exists: true, TagsVerified: true,
		AgentInstanceID: authorizer.agentInstanceID, OwnerID: claim.OwnerID, DeploymentID: claim.DeploymentID,
		AccountID: observed.AccountID, Region: observed.Region, WorkerRoleName: observed.WorkerProfileName,
		InstanceID: observed.InstanceID, TagDigest: observed.TagDigest, ObservedAt: observed.ObservedAt,
	}, nil
}

var _ workeridentity.DeploymentResourceAuthorizer = (*workerIdentityAuthorizer)(nil)
