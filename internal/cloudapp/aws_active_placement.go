package cloudapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

// PlacementPort is the one read-only provider seam exposed to the application
// coordinator. It cannot price, approve, or mutate resources.
type PlacementPort interface {
	Resolve(context.Context, awsprovider.PlacementRequestV1) (awsprovider.PlacementV1, error)
}

type ActivePlacementFactory interface {
	NewPlacementPort(string, *awsprovider.SourceCredentials, string, string) (PlacementPort, error)
}

type SDKActivePlacementFactory struct{}

func (SDKActivePlacementFactory) NewPlacementPort(region string, source *awsprovider.SourceCredentials, controlRoleARN, roleSessionName string) (PlacementPort, error) {
	return awsprovider.NewPlacementResolverFromSource(region, source, controlRoleARN, roleSessionName)
}

type ActivePlacementRequestV1 struct {
	OwnerID      string
	ConnectionID string
	Placement    awsprovider.PlacementRequestV1
}

// AWSActivePlacementResolver permits discovery only after an owner-bound
// Connection is active. It opens the encrypted minimal source key, assumes the
// deterministic Control Role for 15 minutes, and wipes the key after the read.
// Uploaded bootstrap/root credentials have no path into this type.
type AWSActivePlacementResolver struct {
	agentInstanceID string
	credentials     SourceCredentialOpener
	factory         ActivePlacementFactory
}

func NewAWSActivePlacementResolver(agentInstanceID string, credentials SourceCredentialOpener, factory ActivePlacementFactory) (*AWSActivePlacementResolver, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || credentials == nil || factory == nil {
		return nil, ErrInvalid
	}
	return &AWSActivePlacementResolver{agentInstanceID: agentInstanceID, credentials: credentials, factory: factory}, nil
}

func (resolver *AWSActivePlacementResolver) Resolve(ctx context.Context, connection Connection, request ActivePlacementRequestV1) (awsprovider.PlacementV1, error) {
	if resolver == nil || ctx == nil || resolver.ValidateConnection(connection, request.OwnerID, request.ConnectionID) != nil || request.Placement.Validate() != nil {
		return awsprovider.PlacementV1{}, ErrInvalid
	}
	credentials, err := resolver.credentials.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: resolver.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return awsprovider.PlacementV1{}, ErrUnavailable
	}
	defer credentials.Wipe()
	port, err := resolver.factory.NewPlacementPort(connection.Region, &credentials, connection.ControlRoleARN, activePlacementRoleSession(connection.ConnectionID))
	if err != nil {
		return awsprovider.PlacementV1{}, ErrUnavailable
	}
	placement, err := port.Resolve(ctx, request.Placement)
	if err != nil {
		return awsprovider.PlacementV1{}, ErrUnavailable
	}
	if placement.Region != connection.Region {
		return awsprovider.PlacementV1{}, ErrUnavailable
	}
	return placement, nil
}

// ValidateConnection performs the complete owner/Role/Foundation binding
// check without opening credentials or contacting AWS. Quote-only crash
// recovery uses it before trusting a persisted provider fact.
func (resolver *AWSActivePlacementResolver) ValidateConnection(connection Connection, ownerID, connectionID string) error {
	if resolver == nil {
		return ErrInvalid
	}
	return validateActivePlacementConnection(resolver.agentInstanceID, connection, ownerID, connectionID)
}

func validateActivePlacementConnection(agentInstanceID string, connection Connection, ownerID, wantedConnectionID string) error {
	connectionID, connectionErr := uuid.Parse(strings.TrimSpace(connection.ConnectionID))
	role, roleErr := arn.Parse(strings.TrimSpace(connection.ControlRoleARN))
	stack, stackErr := arn.Parse(strings.TrimSpace(connection.FoundationStack))
	if connectionErr != nil || connectionID == uuid.Nil || connectionID.String() != connection.ConnectionID ||
		connection.OwnerID == "" || ownerID != connection.OwnerID || wantedConnectionID != connection.ConnectionID ||
		connection.AccountID == "" || connection.Region == "" || connection.Status != "active" || connection.Revision < 1 ||
		roleErr != nil || role.Service != "iam" || role.AccountID != connection.AccountID ||
		stackErr != nil || stack.Service != "cloudformation" || stack.Partition != role.Partition || stack.Region != connection.Region || stack.AccountID != connection.AccountID {
		return ErrInvalid
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: agentInstanceID, Partition: role.Partition, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil || role.Resource != "role/"+spec.ControlRoleName || !strings.HasPrefix(stack.Resource, "stack/"+spec.StackName+"/") {
		return ErrInvalid
	}
	stackID := strings.TrimPrefix(stack.Resource, "stack/"+spec.StackName+"/")
	parsedStackID, parseErr := uuid.Parse(stackID)
	if parseErr != nil || parsedStackID == uuid.Nil || parsedStackID.String() != stackID {
		return ErrInvalid
	}
	return nil
}

func activePlacementRoleSession(connectionID string) string {
	digest := sha256.Sum256([]byte(connectionID))
	return "dtx-place-" + hex.EncodeToString(digest[:])[:20]
}
