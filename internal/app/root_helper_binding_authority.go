package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

type rootHelperWorkerIdentityReader interface {
	GetCurrentVerifiedWorkerPrincipal(context.Context, string, string) (postgres.VerifiedWorkerPrincipal, error)
}

type rootHelperCloudFormationAPI interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

type rootHelperCloudFormationFactory interface {
	NewCloudFormation(aws.Config) rootHelperCloudFormationAPI
}

type sdkRootHelperCloudFormationFactory struct{}

func (sdkRootHelperCloudFormationFactory) NewCloudFormation(config aws.Config) rootHelperCloudFormationAPI {
	return cloudformation.NewFromConfig(config)
}

type productionRootHelperBindingAuthority struct {
	agentInstanceID string
	current         cloudstatus.Reader
	identities      rootHelperWorkerIdentityReader
	vault           *awsfoundation.CredentialVault
	factory         rootHelperCloudFormationFactory
}

func (authority *productionRootHelperBindingAuthority) ResolveRootHelperBinding(ctx context.Context, ownerID, deploymentID string,
	expectedRevision int64) (rootHelperBindingFacts, error) {
	if authority == nil || authority.current == nil || authority.identities == nil || authority.vault == nil || authority.factory == nil {
		return rootHelperBindingFacts{}, helperkey.ErrUnavailable
	}
	deployment, err := authority.current.GetDeployment(ctx, ownerID, deploymentID)
	if err != nil || deployment.Worker.OwnerID != ownerID || deployment.Worker.DeploymentID != deploymentID ||
		deployment.Worker.Revision != expectedRevision || deployment.Worker.ProviderInstanceID == "" {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	connection, err := authority.current.GetConnection(ctx, ownerID, deployment.ConnectionID)
	if err != nil || connection.OwnerID != ownerID || connection.ConnectionID != deployment.ConnectionID ||
		connection.Status != "active" || connection.Revision < 1 {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	identity, err := authority.identities.GetCurrentVerifiedWorkerPrincipal(ctx, ownerID, deploymentID)
	if err != nil || identity.InstanceID != deployment.Worker.ProviderInstanceID ||
		identity.AccountID != connection.AccountID || identity.Region != connection.Region {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	role, err := arn.Parse(connection.ControlRoleARN)
	if err != nil || role.Service != "iam" || role.AccountID != connection.AccountID || !strings.HasPrefix(role.Resource, "role/") {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: authority.agentInstanceID, Partition: role.Partition,
		AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	source, err := authority.vault.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: authority.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return rootHelperBindingFacts{}, helperkey.ErrUnavailable
	}
	config, configErr := awsprovider.AssumedControlAWSConfig(connection.Region, &source, connection.ControlRoleARN,
		"dtx-helper-"+strings.ReplaceAll(deploymentID, "-", "")[:12])
	source.Wipe()
	if configErr != nil {
		return rootHelperBindingFacts{}, helperkey.ErrUnavailable
	}
	client := authority.factory.NewCloudFormation(config)
	if client == nil {
		return rootHelperBindingFacts{}, helperkey.ErrUnavailable
	}
	output, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(connection.FoundationStackID)})
	if err != nil || output == nil || len(output.Stacks) != 1 || aws.ToString(output.Stacks[0].StackId) != connection.FoundationStackID {
		return rootHelperBindingFacts{}, helperkey.ErrUnavailable
	}
	kmsARN := ""
	for _, item := range output.Stacks[0].Outputs {
		if aws.ToString(item.OutputKey) == "FoundationKeyArn" {
			kmsARN = aws.ToString(item.OutputValue)
		}
	}
	parsedKMS, err := arn.Parse(kmsARN)
	if err != nil || parsedKMS.Partition != role.Partition || parsedKMS.Service != "kms" ||
		parsedKMS.Region != connection.Region || parsedKMS.AccountID != connection.AccountID ||
		!strings.HasPrefix(parsedKMS.Resource, "key/") {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	return rootHelperBindingFacts{
		AgentInstanceID: authority.agentInstanceID, OwnerID: ownerID, DeploymentID: deploymentID,
		DeploymentRevision: deployment.Worker.Revision, InstanceID: identity.InstanceID,
		WorkerRoleARN:     "arn:" + role.Partition + ":iam::" + connection.AccountID + ":role/" + spec.WorkerRoleName,
		WorkerPrincipalID: identity.PrincipalID, Partition: role.Partition, AccountID: connection.AccountID,
		Region: connection.Region, FoundationKMSKeyARN: kmsARN,
	}, nil
}
