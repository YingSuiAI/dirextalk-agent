package app

import (
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/google/uuid"
)

const (
	teamLaunchDestroyGrace        = 5 * time.Minute
	teamLaunchOperationalBuffer   = 30 * time.Minute
	teamLaunchMaximumWorkerLife   = 7 * 24 * time.Hour
	teamLaunchMinimumUsableWindow = 15 * time.Second
)

type teamExactPlacementResolver interface {
	ResolveExact(
		context.Context,
		cloudapp.Connection,
		cloudapp.ActiveExactPlacementRequestV1,
	) (awsprovider.ExactPlacementV1, error)
}

type teamWorkerReleaseResolver interface {
	ResolveActiveWorkerRelease(
		context.Context,
		string,
		string,
		string,
		recipe.Architecture,
	) (workerrelease.ReleaseV1, error)
}

type teamRuntimeLaunchEvidenceResolver interface {
	ResolveAssignmentLaunchEvidence(
		teamplan.WorkerAssignment,
	) (teamplan.RuntimeLaunchEvidence, error)
}

type awsTeamLaunchAuthorizationBuilder struct {
	agentInstanceID string
	endpoint        string
	connections     teamOfferConnectionReader
	placements      teamExactPlacementResolver
	workerReleases  teamWorkerReleaseResolver
	runtimes        teamRuntimeLaunchEvidenceResolver
}

// NewTeamLaunchAuthorizationBuilder composes the read-only launch-evidence
// path from the same owner-bound AWS connection used for pricing. Provider
// mutation remains outside this builder and requires the later signed
// authorization.
func (composition *CloudComposition) NewTeamLaunchAuthorizationBuilder(
	compiler *teamplan.CatalogCompiler,
) (teamorchestration.TrustedLaunchAuthorizationBuilder, error) {
	if composition == nil ||
		composition.agentInstanceID == "" ||
		composition.workerControlTarget == "" ||
		composition.workerConnectivityMode !=
			cloudquote.PrivateConnectivityDirectPublicTLSV1 ||
		composition.cloudGoalStore == nil ||
		composition.ActivePlacements == nil ||
		compiler == nil {
		return nil, teamorchestration.ErrInvalid
	}
	return newAWSTeamLaunchAuthorizationBuilder(
		composition.agentInstanceID,
		composition.workerControlTarget,
		composition.cloudGoalStore,
		composition.ActivePlacements,
		composition.cloudGoalStore,
		compiler,
	)
}

func newAWSTeamLaunchAuthorizationBuilder(
	agentInstanceID,
	endpoint string,
	connections teamOfferConnectionReader,
	placements teamExactPlacementResolver,
	workerReleases teamWorkerReleaseResolver,
	runtimes teamRuntimeLaunchEvidenceResolver,
) (*awsTeamLaunchAuthorizationBuilder, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != agentInstanceID ||
		cloudquote.ValidateDirectPublicControlPlaneEndpoint(endpoint) != nil ||
		connections == nil ||
		placements == nil ||
		workerReleases == nil ||
		runtimes == nil {
		return nil, teamorchestration.ErrInvalid
	}
	return &awsTeamLaunchAuthorizationBuilder{
		agentInstanceID: agentInstanceID,
		endpoint:        endpoint,
		connections:     connections,
		placements:      placements,
		workerReleases:  workerReleases,
		runtimes:        runtimes,
	}, nil
}

func (builder *awsTeamLaunchAuthorizationBuilder) BuildForPlan(
	ctx context.Context,
	plan teamplan.Plan,
	approvalID string,
	issuedAt time.Time,
) (teamlaunch.AuthorizationV1, error) {
	if builder == nil ||
		ctx == nil ||
		plan.Validate() != nil ||
		plan.ProviderScope.Provider != teamplan.CloudProviderAWS ||
		issuedAt.IsZero() ||
		issuedAt.Location() != time.UTC ||
		issuedAt.Nanosecond()%1000 != 0 {
		return teamlaunch.AuthorizationV1{},
			teamorchestration.ErrInvalid
	}
	connection, err := builder.connections.LoadConnection(
		ctx,
		plan.OwnerID,
		plan.ProviderScope.ConnectionID,
	)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	if !teamConnectionMatchesPlan(connection, plan) {
		return teamlaunch.AuthorizationV1{},
			teamorchestration.ErrFactMismatch
	}
	shapes, err := exactTeamPlacementShapes(plan)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	lifetime, err := teamWorkerLifetime(plan)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	hours := uint32((lifetime + time.Hour - 1) / time.Hour)
	if hours == 0 || hours > 744 {
		return teamlaunch.AuthorizationV1{},
			teamorchestration.ErrFactMismatch
	}
	placementRequest := cloudapp.ActiveExactPlacementRequestV1{
		OwnerID:      plan.OwnerID,
		ConnectionID: plan.ProviderScope.ConnectionID,
		Placement: awsprovider.ExactPlacementRequestV1{
			Shapes:                 shapes,
			PublicIPv4:             true,
			RuntimeHoursPerMonth:   hours,
			PrivateConnectivity:    cloudquote.PrivateConnectivityDirectPublicTLSV1,
			ControlPlaneEndpoint:   builder.endpoint,
			PrivateEndpointDataMiB: 0,
		},
	}
	if placementRequest.Placement.Validate() != nil {
		return teamlaunch.AuthorizationV1{},
			teamorchestration.ErrFactMismatch
	}
	placement, err := builder.placements.ResolveExact(
		ctx,
		connection,
		placementRequest,
	)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	if !teamPlacementMatchesPlan(
		placement,
		plan.Region,
		builder.endpoint,
	) {
		return teamlaunch.AuthorizationV1{},
			teamorchestration.ErrFactMismatch
	}
	if !issuedAt.Before(plan.ValidUntil) ||
		plan.ValidUntil.Sub(issuedAt) <
			teamLaunchMinimumUsableWindow {
		return teamlaunch.AuthorizationV1{},
			teamplan.ErrPricingExpired
	}
	// The approval remains valid for the bounded Team lifetime. Every actual
	// provider create is independently fenced by a fresh short-lived quote.
	launchNotAfter := issuedAt.Add(lifetime)
	selections, err := builder.roleSelections(ctx, plan)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	egress, err := teamLaunchEgress(builder.endpoint)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	return teamlaunch.NewAuthorizationV1(teamlaunch.BuildRequest{
		Plan:            plan,
		AgentInstanceID: builder.agentInstanceID,
		ApprovalID:      approvalID,
		Network: teamlaunch.NetworkV1{
			ConnectivityMode:     teamlaunch.ConnectivityDirectPublicTLSV1,
			VPCID:                placement.Network.VPCID,
			SubnetID:             placement.Network.SubnetID,
			AvailabilityZone:     placement.AvailabilityZone,
			SecurityGroupMode:    teamlaunch.SecurityGroupDedicatedNoIngress,
			PublicIPv4:           true,
			PublicInbound:        false,
			ControlPlaneEndpoint: builder.endpoint,
			Egress:               egress,
		},
		Retention: teamlaunch.RetentionV1{
			Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
			AutoDestroy:            true,
			MaximumLifetimeSeconds: uint64(lifetime / time.Second),
			DestroyGraceSeconds:    uint64(teamLaunchDestroyGrace / time.Second),
		},
		LaunchNotBefore: issuedAt,
		LaunchNotAfter:  launchNotAfter,
		RoleSelections:  selections,
	})
}

func (builder *awsTeamLaunchAuthorizationBuilder) roleSelections(
	ctx context.Context,
	plan teamplan.Plan,
) ([]teamlaunch.RoleSelection, error) {
	releases := make(
		map[recipe.Architecture]workerrelease.ReleaseV1,
	)
	result := make(
		[]teamlaunch.RoleSelection,
		0,
		len(plan.Assignments),
	)
	for _, assignment := range plan.Assignments {
		release, found := releases[assignment.Resources.Arch]
		if !found {
			var err error
			release, err = builder.workerReleases.
				ResolveActiveWorkerRelease(
					ctx,
					builder.agentInstanceID,
					plan.ProviderScope.AccountID,
					plan.Region,
					assignment.Resources.Arch,
				)
			if err != nil {
				return nil,
					teamorchestration.ErrLaunchAuthorizationUnavailable
			}
			release, err = workerrelease.ValidateStored(release)
			if err != nil {
				return nil,
					teamorchestration.ErrLaunchAuthorizationUnavailable
			}
			releases[assignment.Resources.Arch] = release
		}
		evidence, err := builder.runtimes.
			ResolveAssignmentLaunchEvidence(
				assignment,
			)
		if err != nil {
			return nil,
				teamorchestration.ErrLaunchAuthorizationUnavailable
		}
		result = append(result, teamlaunch.RoleSelection{
			RoleID:                    assignment.RoleID,
			RuntimeInstallationDigest: evidence.InstallationManifestDigest,
			RuntimeExecutableDigest:   evidence.ExecutableDigest,
			WorkerRelease:             release,
		})
	}
	return result, nil
}

func teamConnectionMatchesPlan(
	connection cloudapp.Connection,
	plan teamplan.Plan,
) bool {
	return connection.ConnectionID ==
		plan.ProviderScope.ConnectionID &&
		connection.OwnerID == plan.OwnerID &&
		connection.AccountID == plan.ProviderScope.AccountID &&
		connection.Region == plan.Region &&
		connection.Status == "active" &&
		connection.Revision > 0 &&
		uint64(connection.Revision) ==
			plan.ProviderScope.ConnectionRevision
}

func exactTeamPlacementShapes(
	plan teamplan.Plan,
) ([]awsprovider.ExactPlacementShapeV1, error) {
	byInstance := make(
		map[string]awsprovider.ExactPlacementShapeV1,
		len(plan.Assignments),
	)
	for _, assignment := range plan.Assignments {
		shape := awsprovider.ExactPlacementShapeV1{
			InstanceType: assignment.InstanceType,
			Architecture: assignment.Resources.Arch,
			VCPU:         assignment.Resources.VCPU,
			MemoryMiB:    assignment.Resources.MemoryMiB,
			DiskGiB:      assignment.Resources.DiskGiB,
		}
		if existing, found := byInstance[shape.InstanceType]; found &&
			existing != shape {
			return nil, teamorchestration.ErrFactMismatch
		}
		byInstance[shape.InstanceType] = shape
	}
	shapes := make(
		[]awsprovider.ExactPlacementShapeV1,
		0,
		len(byInstance),
	)
	for _, shape := range byInstance {
		shapes = append(shapes, shape)
	}
	slices.SortFunc(
		shapes,
		func(left, right awsprovider.ExactPlacementShapeV1) int {
			return strings.Compare(
				left.InstanceType,
				right.InstanceType,
			)
		},
	)
	return shapes, nil
}

func teamWorkerLifetime(plan teamplan.Plan) (time.Duration, error) {
	if plan.Schedule.MaximumWallTime <= 0 ||
		plan.Schedule.MaximumWallTime >
			teamLaunchMaximumWorkerLife {
		return 0, teamorchestration.ErrFactMismatch
	}
	lifetime := plan.Schedule.MaximumWallTime +
		teamLaunchOperationalBuffer
	if lifetime > teamLaunchMaximumWorkerLife ||
		lifetime <= teamLaunchDestroyGrace {
		return 0, teamorchestration.ErrFactMismatch
	}
	return lifetime.Truncate(time.Second), nil
}

func teamPlacementMatchesPlan(
	placement awsprovider.ExactPlacementV1,
	region,
	endpoint string,
) bool {
	network := placement.Network
	return placement.Region == region &&
		placement.AvailabilityZone != "" &&
		network.VPCID != "" &&
		network.SubnetID != "" &&
		network.SecurityGroupMode ==
			cloudquote.SecurityGroupCreateDedicated &&
		network.PublicIPv4 &&
		network.EntryPoint == cloudquote.EntryPointNone &&
		network.ControlPlaneEndpoint == endpoint &&
		network.PrivateConnectivity ==
			cloudquote.PrivateConnectivityDirectPublicTLSV1
}

func teamLaunchEgress(
	endpoint string,
) ([]teamlaunch.EgressRuleV1, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, teamorchestration.ErrFactMismatch
	}
	portText := parsed.Port()
	if portText == "" {
		portText = "443"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, teamorchestration.ErrFactMismatch
	}
	rules := []teamlaunch.EgressRuleV1{{
		Protocol: "tcp",
		FromPort: 443,
		ToPort:   443,
		CIDRv4:   "0.0.0.0/0",
	}}
	if port != 443 {
		rules = append(rules, teamlaunch.EgressRuleV1{
			Protocol: "tcp",
			FromPort: uint16(port),
			ToPort:   uint16(port),
			CIDRv4:   "0.0.0.0/0",
		})
	}
	rules = append(rules, teamlaunch.EgressRuleV1{
		Protocol: "udp",
		FromPort: 53,
		ToPort:   53,
		CIDRv4:   "169.254.169.253/32",
	})
	slices.SortFunc(
		rules,
		func(left, right teamlaunch.EgressRuleV1) int {
			leftKey := left.Protocol + ":" +
				strconv.FormatUint(uint64(left.FromPort), 10)
			rightKey := right.Protocol + ":" +
				strconv.FormatUint(uint64(right.FromPort), 10)
			return strings.Compare(leftKey, rightKey)
		},
	)
	return rules, nil
}

var _ teamorchestration.TrustedLaunchAuthorizationBuilder = (*awsTeamLaunchAuthorizationBuilder)(nil)
