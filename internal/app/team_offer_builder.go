package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
)

type teamOfferConnectionReader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type teamPricingConfigProvider interface {
	teamPricingConfig(
		context.Context,
		cloudapp.Connection,
	) (aws.Config, error)
}

type teamComputePortFactory interface {
	NewComputePort(
		aws.Config,
		teamplan.ProviderScope,
		string,
		[]string,
		[]awsprovider.TeamComputeShape,
	) (teampricing.ComputeOfferPort, error)
}

type teamSnapshotAssembler interface {
	Build(
		context.Context,
		teamplan.ProviderScope,
		string,
		teampricing.ComputeOfferPort,
	) (*teamplan.OfferSnapshot, error)
}

type teamOfferConfigurationVerifier interface {
	VerifyCurrent(
		context.Context,
		*teamplan.OfferSnapshot,
	) error
}

type awsTeamOfferBuilder struct {
	connections teamOfferConnectionReader
	configs     teamPricingConfigProvider
	compute     *awsprovider.TeamComputeCatalog
	ports       teamComputePortFactory
	snapshots   teamSnapshotAssembler
	policy      teamOfferConfigurationVerifier
}

func newAWSTeamOfferBuilder(
	connections teamOfferConnectionReader,
	configs teamPricingConfigProvider,
	compute *awsprovider.TeamComputeCatalog,
	ports teamComputePortFactory,
	snapshots teamSnapshotAssembler,
	policy teamOfferConfigurationVerifier,
) (*awsTeamOfferBuilder, error) {
	if connections == nil || configs == nil || compute == nil ||
		ports == nil || snapshots == nil || policy == nil {
		return nil, teamorchestration.ErrInvalid
	}
	return &awsTeamOfferBuilder{
		connections: connections,
		configs:     configs,
		compute:     compute,
		ports:       ports,
		snapshots:   snapshots,
		policy:      policy,
	}, nil
}

func (builder *awsTeamOfferBuilder) BuildForConnection(
	ctx context.Context,
	ownerID,
	connectionID string,
) (*teamplan.OfferSnapshot, error) {
	parsed, err := uuid.Parse(connectionID)
	if builder == nil || builder.connections == nil ||
		builder.configs == nil || builder.compute == nil ||
		builder.ports == nil || builder.snapshots == nil ||
		builder.policy == nil ||
		ctx == nil ||
		strings.TrimSpace(ownerID) != ownerID || ownerID == "" ||
		err != nil || parsed == uuid.Nil || parsed.String() != connectionID {
		return nil, teamorchestration.ErrInvalid
	}
	connection, scope, err := builder.loadConnection(
		ctx,
		ownerID,
		connectionID,
	)
	if err != nil {
		return nil, err
	}
	zones, shapes, err := builder.compute.Resolve(connection.Region)
	if err != nil {
		return nil, err
	}
	configuration, err := builder.configs.teamPricingConfig(
		ctx,
		connection,
	)
	if err != nil {
		return nil, err
	}
	compute, err := builder.ports.NewComputePort(
		configuration,
		scope,
		connection.Region,
		zones,
		shapes,
	)
	if err != nil {
		return nil, err
	}
	snapshot, err := builder.snapshots.Build(
		ctx,
		scope,
		connection.Region,
		compute,
	)
	if err != nil {
		return nil, err
	}
	if snapshot == nil ||
		snapshot.ProviderScope() != scope ||
		snapshot.Region() != connection.Region {
		return nil, teamorchestration.ErrFactMismatch
	}
	if err := builder.policy.VerifyCurrent(ctx, snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (builder *awsTeamOfferBuilder) VerifyCurrentOffer(
	ctx context.Context,
	ownerID string,
	snapshot *teamplan.OfferSnapshot,
) error {
	if builder == nil || builder.policy == nil ||
		ctx == nil || snapshot == nil {
		return teamorchestration.ErrInvalid
	}
	scope := snapshot.ProviderScope()
	connection, currentScope, err := builder.loadConnection(
		ctx,
		ownerID,
		scope.ConnectionID,
	)
	if err != nil {
		return err
	}
	if currentScope != scope || connection.Region != snapshot.Region() {
		return teamplan.ErrPricingChanged
	}
	return builder.policy.VerifyCurrent(ctx, snapshot)
}

func (builder *awsTeamOfferBuilder) loadConnection(
	ctx context.Context,
	ownerID,
	connectionID string,
) (cloudapp.Connection, teamplan.ProviderScope, error) {
	parsed, err := uuid.Parse(connectionID)
	if builder == nil || builder.connections == nil ||
		ctx == nil ||
		strings.TrimSpace(ownerID) != ownerID || ownerID == "" ||
		err != nil || parsed == uuid.Nil || parsed.String() != connectionID {
		return cloudapp.Connection{}, teamplan.ProviderScope{},
			teamorchestration.ErrInvalid
	}
	connection, err := builder.connections.LoadConnection(
		ctx,
		ownerID,
		connectionID,
	)
	if err != nil {
		return cloudapp.Connection{}, teamplan.ProviderScope{}, err
	}
	if connection.ConnectionID != connectionID ||
		connection.OwnerID != ownerID ||
		connection.Status != "active" ||
		connection.Revision <= 0 {
		return cloudapp.Connection{}, teamplan.ProviderScope{},
			teamorchestration.ErrFactMismatch
	}
	scope := teamplan.ProviderScope{
		Provider:           teamplan.CloudProviderAWS,
		ConnectionID:       connection.ConnectionID,
		ConnectionRevision: uint64(connection.Revision),
		AccountID:          connection.AccountID,
	}
	if err := scope.Validate(); err != nil {
		return cloudapp.Connection{}, teamplan.ProviderScope{},
			teamorchestration.ErrFactMismatch
	}
	return connection, scope, nil
}

type sdkTeamComputePortFactory struct{}

func (sdkTeamComputePortFactory) NewComputePort(
	configuration aws.Config,
	scope teamplan.ProviderScope,
	region string,
	zones []string,
	shapes []awsprovider.TeamComputeShape,
) (teampricing.ComputeOfferPort, error) {
	pricing, err := awsprovider.NewPricingProviderFromConfig(configuration)
	if err != nil {
		return nil, err
	}
	return awsprovider.NewTeamComputePricingProvider(
		pricing,
		scope,
		region,
		zones,
		shapes,
	)
}

type trustedTeamSnapshotAssembler struct {
	models      *teampricing.ModelOfferCatalog
	credentials teampricing.CredentialReadinessPort
}

type trustedTeamOfferPolicy struct {
	models      *teampricing.ModelOfferCatalog
	credentials teampricing.CredentialReadinessPort
	compute     *awsprovider.TeamComputeCatalog
}

func (policy trustedTeamOfferPolicy) VerifyCurrent(
	ctx context.Context,
	snapshot *teamplan.OfferSnapshot,
) error {
	if policy.models == nil || policy.credentials == nil ||
		policy.compute == nil || ctx == nil || snapshot == nil {
		return teamorchestration.ErrInvalid
	}
	if err := policy.models.VerifyCurrentModels(
		ctx,
		snapshot,
		policy.credentials,
	); err != nil {
		return err
	}
	sourceID, digest, err := policy.compute.ConfigurationBinding(
		snapshot.Region(),
	)
	if err != nil {
		return teamplan.ErrPricingChanged
	}
	document := snapshot.Document()
	matched := 0
	for _, source := range document.Sources {
		if source.Kind == teamplan.OfferSourceComputeConfig {
			matched++
			if source.SourceID != sourceID ||
				source.Digest != digest {
				return teamplan.ErrPricingChanged
			}
		}
	}
	if matched != 1 {
		return teamplan.ErrPricingChanged
	}
	_, shapes, err := policy.compute.Resolve(snapshot.Region())
	if err != nil {
		return teamplan.ErrPricingChanged
	}
	for _, offer := range document.ComputeOffers {
		if !teamComputeOfferAllowed(offer, shapes) {
			return teamplan.ErrPricingChanged
		}
	}
	return nil
}

func teamComputeOfferAllowed(
	offer teamplan.ComputeOffer,
	shapes []awsprovider.TeamComputeShape,
) bool {
	for _, shape := range shapes {
		if offer.InstanceType == shape.InstanceType &&
			offer.Architecture == shape.Architecture &&
			offer.DiskGiB == shape.DiskGiB {
			return true
		}
	}
	return false
}

func (assembler trustedTeamSnapshotAssembler) Build(
	ctx context.Context,
	scope teamplan.ProviderScope,
	region string,
	compute teampricing.ComputeOfferPort,
) (*teamplan.OfferSnapshot, error) {
	service, err := teampricing.NewSnapshotService(
		assembler.models,
		assembler.credentials,
		compute,
	)
	if err != nil {
		return nil, err
	}
	return service.Build(ctx, scope, region)
}

func (factory *awsResourceRuntimeFactory) teamPricingConfig(
	ctx context.Context,
	connection cloudapp.Connection,
) (aws.Config, error) {
	configuration, _, err := factory.controlConfig(ctx, connection)
	return configuration, err
}

func (composition *CloudComposition) NewTeamOfferBuilder(
	models *teampricing.ModelOfferCatalog,
	credentials teampricing.CredentialReadinessPort,
	compute *awsprovider.TeamComputeCatalog,
) (teamorchestration.TrustedOfferSource, error) {
	if composition == nil || composition.cloudGoalStore == nil ||
		composition.resourceRuntime == nil ||
		models == nil || credentials == nil || compute == nil {
		return nil, teamorchestration.ErrInvalid
	}
	return newAWSTeamOfferBuilder(
		composition.cloudGoalStore,
		composition.resourceRuntime,
		compute,
		sdkTeamComputePortFactory{},
		trustedTeamSnapshotAssembler{
			models:      models,
			credentials: credentials,
		},
		trustedTeamOfferPolicy{
			models:      models,
			credentials: credentials,
			compute:     compute,
		},
	)
}

var _ teamorchestration.TrustedOfferSource = (*awsTeamOfferBuilder)(nil)
