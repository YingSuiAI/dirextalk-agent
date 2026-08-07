package sdkclient

import (
	"context"
	"errors"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

const (
	maximumStackEventPages = 100
	maximumStackEvents     = 10000
)

func (client *Client) referenceForStack(
	ctx context.Context,
	identity cloudaws.ExecutionIdentity,
	intent cloudaws.DispatchIntent,
	stack cftypes.Stack,
	expectedTags map[string]string,
	mutationDispatchedAt time.Time,
	mutationDeadline time.Time,
) (cloudaws.StackReference, error) {
	stackID := awssdk.ToString(stack.StackId)
	if err := client.validateStack(stack, intent.StackName, stackID, expectedTags); err != nil {
		return cloudaws.StackReference{}, err
	}
	creation, err := client.readStackCreationIdentity(ctx, identity, intent, stack, mutationDispatchedAt, mutationDeadline)
	if err != nil {
		return cloudaws.StackReference{}, err
	}
	return cloudaws.StackReference{
		ProviderID: stackID, InfrastructureDigest: intent.InfrastructureDigest,
		IntentDigest: intent.IntentDigest, ClientToken: intent.ClientToken,
		CreationIdentity: creation, Tags: cfnTagMap(stack.Tags),
	}, nil
}

func (client *Client) readStackCreationIdentity(
	ctx context.Context,
	identity cloudaws.ExecutionIdentity,
	intent cloudaws.DispatchIntent,
	stack cftypes.Stack,
	mutationDispatchedAt time.Time,
	mutationDeadline time.Time,
) (cloudaws.StackCreationIdentity, error) {
	stackID := awssdk.ToString(stack.StackId)
	stackName := awssdk.ToString(stack.StackName)
	if stack.CreationTime == nil || stack.CreationTime.IsZero() || stackID == "" || stackName != intent.StackName ||
		validateCreateMutationWindow(intent, mutationDispatchedAt, mutationDeadline) != nil {
		return cloudaws.StackCreationIdentity{}, cloudaws.ErrCloudReadback
	}
	creationTime := stack.CreationTime.UTC()
	if creationTime.Before(mutationDispatchedAt) || creationTime.After(mutationDeadline) {
		return cloudaws.StackCreationIdentity{}, cloudaws.ErrOwnershipMismatch
	}
	seenTokens := make(map[string]struct{})
	seenEventIDs := make(map[string]struct{})
	var nextToken *string
	var creation cloudaws.StackCreationIdentity
	eventsRead := 0
	for page := 0; ; page++ {
		if page >= maximumStackEventPages {
			return cloudaws.StackCreationIdentity{}, cloudaws.ErrCloudReadback
		}
		if err := client.verify(ctx, identity); err != nil {
			return cloudaws.StackCreationIdentity{}, err
		}
		output, err := client.cfn.DescribeStackEvents(ctx, &cloudformation.DescribeStackEventsInput{
			StackName: awssdk.String(stackID), NextToken: nextToken,
		})
		if err != nil || output == nil {
			return cloudaws.StackCreationIdentity{}, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, event := range output.StackEvents {
			eventsRead++
			if eventsRead > maximumStackEvents || awssdk.ToString(event.StackId) != stackID ||
				awssdk.ToString(event.StackName) != stackName || event.Timestamp == nil || event.Timestamp.IsZero() ||
				awssdk.ToString(event.EventId) == "" {
				return cloudaws.StackCreationIdentity{}, cloudaws.ErrOwnershipMismatch
			}
			eventID := awssdk.ToString(event.EventId)
			if _, duplicate := seenEventIDs[eventID]; duplicate {
				return cloudaws.StackCreationIdentity{}, cloudaws.ErrCloudReadback
			}
			seenEventIDs[eventID] = struct{}{}
			if awssdk.ToString(event.ResourceType) != "AWS::CloudFormation::Stack" ||
				awssdk.ToString(event.LogicalResourceId) != stackName || awssdk.ToString(event.PhysicalResourceId) != stackID ||
				event.ResourceStatus != cftypes.ResourceStatusCreateInProgress {
				continue
			}
			if awssdk.ToString(event.ClientRequestToken) != intent.ClientToken || !event.Timestamp.Equal(creationTime) ||
				creation.StackID != "" {
				return cloudaws.StackCreationIdentity{}, cloudaws.ErrOwnershipMismatch
			}
			creation = cloudaws.StackCreationIdentity{
				StackID: stackID, StackName: stackName, ClientRequestToken: intent.ClientToken,
				CreationEventID: eventID, CreationTime: creationTime, ObservedAt: client.now().UTC(),
			}
		}
		token := awssdk.ToString(output.NextToken)
		if token == "" {
			break
		}
		if _, duplicate := seenTokens[token]; duplicate {
			return cloudaws.StackCreationIdentity{}, cloudaws.ErrCloudReadback
		}
		seenTokens[token] = struct{}{}
		nextToken = awssdk.String(token)
	}
	if creation.StackID == "" {
		// Stack event visibility is eventually consistent. A visible stack with
		// no creation event is pending read-back, never an adoptable name match.
		return cloudaws.StackCreationIdentity{}, cloudaws.ErrCloudReadback
	}
	if creation.ObservedAt.IsZero() || creation.ObservedAt != creation.ObservedAt.UTC() ||
		creation.CreationTime != creation.CreationTime.UTC() || creation.CreationTime.Before(time.Unix(0, 0).UTC()) {
		return cloudaws.StackCreationIdentity{}, cloudaws.ErrCloudReadback
	}
	return creation, nil
}

func validateCreateMutationWindow(intent cloudaws.DispatchIntent, dispatchedAt, deadline time.Time) error {
	if dispatchedAt.IsZero() || deadline.IsZero() || dispatchedAt != dispatchedAt.UTC() || deadline != deadline.UTC() ||
		dispatchedAt.Before(intent.RecordedAt) || !deadline.After(dispatchedAt) || deadline.After(intent.Authorization.QuoteExpiresAt) {
		return cloudaws.ErrInvalid
	}
	return nil
}
