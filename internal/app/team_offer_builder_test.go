package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
)

func TestAWSTeamOfferBuilderDerivesCloudIdentityFromConnection(t *testing.T) {
	t.Parallel()
	connection := teamOfferConnectionFixture()
	catalog := teamOfferComputeCatalogFixture(t)
	connections := &teamOfferConnectionReaderFixture{
		connection: connection,
	}
	configs := &teamPricingConfigFixture{
		configuration: aws.Config{Region: connection.Region},
	}
	ports := &teamComputePortFactoryFixture{
		port: teamComputeOfferPortFixture{},
	}
	snapshots := &teamSnapshotAssemblerFixture{}
	builder, err := newAWSTeamOfferBuilder(
		connections,
		configs,
		catalog,
		ports,
		snapshots,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := builder.BuildForConnection(
		context.Background(),
		connection.OwnerID,
		connection.ConnectionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantScope := teamplan.ProviderScope{
		Provider:           teamplan.CloudProviderAWS,
		ConnectionID:       connection.ConnectionID,
		ConnectionRevision: uint64(connection.Revision),
		AccountID:          connection.AccountID,
	}
	if connections.calls != 1 ||
		connections.ownerID != connection.OwnerID ||
		connections.connectionID != connection.ConnectionID ||
		configs.calls != 1 ||
		configs.connection != connection ||
		ports.calls != 1 ||
		ports.scope != wantScope ||
		ports.region != connection.Region ||
		len(ports.zones) != 2 ||
		ports.zones[0] != "us-east-1a" ||
		len(ports.shapes) != 1 ||
		ports.shapes[0].InstanceType != "m7i.large" ||
		snapshots.calls != 1 ||
		snapshots.scope != wantScope ||
		snapshots.region != connection.Region ||
		snapshot.ProviderScope() != wantScope {
		t.Fatalf(
			"connection=%#v config=%#v ports=%#v snapshots=%#v snapshot=%#v",
			connections,
			configs,
			ports,
			snapshots,
			snapshot.Document(),
		)
	}
}

func TestAWSTeamOfferBuilderRejectsConnectionFactSubstitution(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*cloudapp.Connection){
		"owner": func(value *cloudapp.Connection) {
			value.OwnerID = "other-owner"
		},
		"connection": func(value *cloudapp.Connection) {
			value.ConnectionID = uuid.NewString()
		},
		"account": func(value *cloudapp.Connection) {
			value.AccountID = "not-an-account"
		},
		"inactive": func(value *cloudapp.Connection) {
			value.Status = "destroyed"
		},
		"revision": func(value *cloudapp.Connection) {
			value.Revision = 0
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			connection := teamOfferConnectionFixture()
			requestedOwner := connection.OwnerID
			requestedConnection := connection.ConnectionID
			mutate(&connection)
			configs := &teamPricingConfigFixture{}
			builder, err := newAWSTeamOfferBuilder(
				&teamOfferConnectionReaderFixture{
					connection: connection,
				},
				configs,
				teamOfferComputeCatalogFixture(t),
				&teamComputePortFactoryFixture{},
				&teamSnapshotAssemblerFixture{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := builder.BuildForConnection(
				context.Background(),
				requestedOwner,
				requestedConnection,
			); !errors.Is(err, teamorchestration.ErrFactMismatch) ||
				configs.calls != 0 {
				t.Fatalf(
					"BuildForConnection() error=%v config calls=%d",
					err,
					configs.calls,
				)
			}
		})
	}
}

func TestAWSTeamOfferBuilderRejectsSnapshotScopeSubstitution(t *testing.T) {
	t.Parallel()
	connection := teamOfferConnectionFixture()
	assembler := &teamSnapshotAssemblerFixture{
		mutateScope: func(scope *teamplan.ProviderScope) {
			scope.ConnectionID = uuid.NewString()
		},
	}
	builder, err := newAWSTeamOfferBuilder(
		&teamOfferConnectionReaderFixture{connection: connection},
		&teamPricingConfigFixture{
			configuration: aws.Config{Region: connection.Region},
		},
		teamOfferComputeCatalogFixture(t),
		&teamComputePortFactoryFixture{
			port: teamComputeOfferPortFixture{},
		},
		assembler,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.BuildForConnection(
		context.Background(),
		connection.OwnerID,
		connection.ConnectionID,
	); !errors.Is(err, teamorchestration.ErrFactMismatch) {
		t.Fatalf("substituted Snapshot error=%v", err)
	}
}

type teamOfferConnectionReaderFixture struct {
	connection   cloudapp.Connection
	err          error
	calls        int
	ownerID      string
	connectionID string
}

func (fixture *teamOfferConnectionReaderFixture) LoadConnection(
	_ context.Context,
	ownerID,
	connectionID string,
) (cloudapp.Connection, error) {
	fixture.calls++
	fixture.ownerID = ownerID
	fixture.connectionID = connectionID
	return fixture.connection, fixture.err
}

type teamPricingConfigFixture struct {
	configuration aws.Config
	err           error
	calls         int
	connection    cloudapp.Connection
}

func (fixture *teamPricingConfigFixture) teamPricingConfig(
	_ context.Context,
	connection cloudapp.Connection,
) (aws.Config, error) {
	fixture.calls++
	fixture.connection = connection
	return fixture.configuration, fixture.err
}

type teamComputePortFactoryFixture struct {
	port   teampricing.ComputeOfferPort
	err    error
	calls  int
	scope  teamplan.ProviderScope
	region string
	zones  []string
	shapes []awsprovider.TeamComputeShape
}

func (fixture *teamComputePortFactoryFixture) NewComputePort(
	_ aws.Config,
	scope teamplan.ProviderScope,
	region string,
	zones []string,
	shapes []awsprovider.TeamComputeShape,
) (teampricing.ComputeOfferPort, error) {
	fixture.calls++
	fixture.scope = scope
	fixture.region = region
	fixture.zones = append([]string(nil), zones...)
	fixture.shapes = append(
		[]awsprovider.TeamComputeShape(nil),
		shapes...,
	)
	return fixture.port, fixture.err
}

type teamSnapshotAssemblerFixture struct {
	mutateScope func(*teamplan.ProviderScope)
	calls       int
	scope       teamplan.ProviderScope
	region      string
	compute     teampricing.ComputeOfferPort
}

func (fixture *teamSnapshotAssemblerFixture) Build(
	_ context.Context,
	scope teamplan.ProviderScope,
	region string,
	compute teampricing.ComputeOfferPort,
) (*teamplan.OfferSnapshot, error) {
	fixture.calls++
	fixture.scope = scope
	fixture.region = region
	fixture.compute = compute
	if fixture.mutateScope != nil {
		fixture.mutateScope(&scope)
	}
	return teamOfferSnapshotFixture(scope, region)
}

type teamComputeOfferPortFixture struct{}

func (teamComputeOfferPortFixture) ReadComputeOffers(
	context.Context,
	teamplan.ProviderScope,
	string,
) (teampricing.ComputeEvidence, error) {
	return teampricing.ComputeEvidence{}, nil
}

func teamOfferConnectionFixture() cloudapp.Connection {
	return cloudapp.Connection{
		ConnectionID:    uuid.NewString(),
		OwnerID:         "owner-team-offer",
		AccountID:       "123456789012",
		Region:          "us-east-1",
		ControlRoleARN:  "arn:aws:iam::123456789012:role/test-control",
		FoundationStack: "test-foundation",
		Status:          "active",
		Revision:        3,
	}
}

func teamOfferComputeCatalogFixture(
	t *testing.T,
) *awsprovider.TeamComputeCatalog {
	t.Helper()
	catalog, err := awsprovider.NewTeamComputeCatalog(
		awsprovider.TeamComputeCatalogDocument{
			SchemaVersion: awsprovider.TeamComputeCatalogSchemaV1,
			Regions: []awsprovider.TeamComputeRegion{{
				Region: "us-east-1",
				AvailabilityZones: []string{
					"us-east-1a",
					"us-east-1b",
				},
				Shapes: []awsprovider.TeamComputeShape{{
					InstanceType: "m7i.large",
					Architecture: recipe.ArchitectureAMD64,
					DiskGiB:      40,
				}},
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func teamOfferSnapshotFixture(
	scope teamplan.ProviderScope,
	region string,
) (*teamplan.OfferSnapshot, error) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	return teamplan.NewOfferSnapshot(teamplan.OfferSnapshotDocument{
		SchemaVersion: teamplan.OfferSnapshotSchemaV1,
		SnapshotID:    uuid.NewString(),
		ProviderScope: scope,
		Region:        region,
		Currency:      "USD",
		CapturedAt:    now,
		ValidUntil:    now.Add(teamplan.OfferSnapshotValidity),
		Sources: []teamplan.OfferSourceReceipt{
			{
				Kind:       teamplan.OfferSourceModelPricing,
				SourceID:   "model-pricing-test",
				Digest:     "sha256:" + strings.Repeat("1", 64),
				CapturedAt: now.Add(-time.Hour),
			},
			{
				Kind:       teamplan.OfferSourceComputePricing,
				SourceID:   "compute-pricing-test",
				Digest:     "sha256:" + strings.Repeat("2", 64),
				CapturedAt: now,
			},
			{
				Kind:       teamplan.OfferSourceComputeCapacity,
				SourceID:   "compute-capacity-test",
				Digest:     "sha256:" + strings.Repeat("3", 64),
				CapturedAt: now,
			},
		},
		ModelOffers: []teamplan.ModelOffer{{
			ProfileID:              "model-balanced",
			Provider:               "openai",
			Model:                  "code-model",
			Interface:              teamplan.ModelOpenAIResponses,
			Quality:                teamplan.QualityBalanced,
			ContextTokens:          128_000,
			InputMicrosPerMillion:  1_000_000,
			OutputMicrosPerMillion: 2_000_000,
			CredentialRef:          "secret_ref:model/test",
			Enabled:                true,
			CredentialReady:        true,
		}},
		ComputeOffers: []teamplan.ComputeOffer{{
			OfferID:        uuid.NewString(),
			Region:         region,
			InstanceType:   "m7i.large",
			Architecture:   recipe.ArchitectureAMD64,
			VCPU:           2,
			MemoryMiB:      8192,
			DiskGiB:        40,
			HourlyMicros:   3_600_000,
			PurchaseOption: "on_demand",
			CapacityPool:   "aws:ec2-quota:L-1216C47A",
			CapacityUnits:  2,
			AvailableUnits: 64,
			Available:      true,
		}},
	})
}

var _ teamOfferConnectionReader = (*teamOfferConnectionReaderFixture)(nil)
var _ teamPricingConfigProvider = (*teamPricingConfigFixture)(nil)
var _ teamComputePortFactory = (*teamComputePortFactoryFixture)(nil)
var _ teamSnapshotAssembler = (*teamSnapshotAssemblerFixture)(nil)
var _ teampricing.ComputeOfferPort = teamComputeOfferPortFixture{}
