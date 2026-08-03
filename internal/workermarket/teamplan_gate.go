package workermarket

import (
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

type TeamPlanGate struct {
	registry       *Registry
	organizationID string
}

func NewTeamPlanGate(
	registry *Registry,
	organizationID string,
) (*TeamPlanGate, error) {
	if registry == nil ||
		!digestPattern.MatchString(registry.Revision()) ||
		!validOptionalOrganizationID(organizationID) {
		return nil, ErrInvalid
	}
	return &TeamPlanGate{
		registry:       registry,
		organizationID: organizationID,
	}, nil
}

func (gate *TeamPlanGate) Revision() string {
	if gate == nil || gate.registry == nil {
		return ""
	}
	return gate.registry.Revision()
}

func (gate *TeamPlanGate) VerifyRuntime(
	runtime teamplan.RuntimeRelease,
	at time.Time,
) error {
	if gate == nil || gate.registry == nil || at.IsZero() ||
		gate.registry.ValidateAt(at.UTC().Truncate(time.Second)) != nil {
		return teamplan.ErrRuntimeRegistryUnavailable
	}
	release, err := gate.resolve(runtime, at)
	if err != nil {
		return err
	}
	manifest := release.Manifest
	if string(manifest.MinimumResources.Architecture) !=
		string(runtime.Minimum.Arch) ||
		string(manifest.RecommendedResources.Architecture) !=
			string(runtime.Recommended.Arch) ||
		manifest.MinimumResources.VCPU != runtime.Minimum.VCPU ||
		manifest.MinimumResources.MemoryMiB !=
			runtime.Minimum.MemoryMiB ||
		manifest.MinimumResources.DiskGiB != runtime.Minimum.DiskGiB ||
		manifest.RecommendedResources.VCPU !=
			runtime.Recommended.VCPU ||
		manifest.RecommendedResources.MemoryMiB !=
			runtime.Recommended.MemoryMiB ||
		manifest.RecommendedResources.DiskGiB !=
			runtime.Recommended.DiskGiB {
		return ErrNotApproved
	}
	for _, capability := range runtime.Capabilities {
		if !slices.Contains(
			manifest.Capabilities,
			string(capability),
		) {
			return ErrNotApproved
		}
	}
	for _, modelInterface := range runtime.ModelInterfaces {
		if !slices.Contains(
			manifest.ModelInterfaces,
			string(modelInterface),
		) {
			return ErrNotApproved
		}
	}
	return nil
}

func (gate *TeamPlanGate) VerifyAssignment(
	runtime teamplan.RuntimeRelease,
	assignment teamplan.WorkerAssignment,
	at time.Time,
) error {
	expected, err := gate.BindAssignment(runtime, assignment, at)
	if err != nil ||
		assignment.Marketplace == nil ||
		!expected.Equal(*assignment.Marketplace) {
		return ErrNotApproved
	}
	return nil
}

func (gate *TeamPlanGate) BindAssignment(
	runtime teamplan.RuntimeRelease,
	assignment teamplan.WorkerAssignment,
	at time.Time,
) (teamplan.WorkerMarketplaceBindingV1, error) {
	release, err := gate.resolve(runtime, at)
	if err != nil {
		return teamplan.WorkerMarketplaceBindingV1{}, err
	}
	if assignment.RuntimeReleaseID != runtime.ReleaseID ||
		assignment.RuntimeFamily != runtime.Family ||
		assignment.RuntimeVersion != runtime.Version ||
		assignment.RuntimeImageDigest != runtime.ImageDigest ||
		assignment.RuntimeAdapter != runtime.Adapter {
		return teamplan.WorkerMarketplaceBindingV1{}, ErrNotApproved
	}
	mode, ok := protocolWorkspaceMode(assignment.Workspace)
	if !ok ||
		!slices.Contains(release.Manifest.WorkspaceModes, mode) ||
		!slices.Contains(
			release.Manifest.ModelInterfaces,
			string(assignment.ModelInterface),
		) {
		return teamplan.WorkerMarketplaceBindingV1{}, ErrNotApproved
	}
	for _, capability := range assignment.RequiredCapabilities {
		if !slices.Contains(
			release.Manifest.Capabilities,
			string(capability),
		) {
			return teamplan.WorkerMarketplaceBindingV1{}, ErrNotApproved
		}
	}
	permissions, err := grantedPermissions(
		release.Manifest.RequestedPermissions,
		mode,
		assignment,
	)
	if err != nil {
		return teamplan.WorkerMarketplaceBindingV1{}, err
	}
	publisher, found := gate.registry.publisher[release.PublisherID]
	if !found {
		return teamplan.WorkerMarketplaceBindingV1{}, ErrNotApproved
	}
	return teamplan.WorkerMarketplaceBindingV1{
		SchemaVersion:            teamplan.WorkerMarketplaceBindingSchemaV1,
		RegistryID:               gate.registry.RegistryID(),
		RegistryRevision:         gate.registry.Revision(),
		ReleaseID:                release.ReleaseID,
		WorkerTypeID:             release.WorkerTypeID,
		PublisherID:              publisher.PublisherID,
		PublisherDisplayName:     publisher.DisplayName,
		PublisherTier:            string(publisher.Tier),
		OrganizationID:           release.OrganizationID,
		ManifestDigest:           release.ManifestDigest,
		ImageRepository:          release.OCI.Repository,
		ImageDigest:              release.OCI.ImageDigest,
		ImageSignatureDigest:     release.OCI.SignatureBundleDigest,
		SBOMDigest:               release.OCI.SBOMDigest,
		ProvenanceEnvelopeDigest: release.OCI.ProvenanceEnvelopeDigest,
		ReviewID:                 release.Review.ReviewID,
		ReviewPolicyRevision:     release.Review.PolicyRevision,
		ReviewRiskClass:          release.Review.RiskClass,
		ReviewValidUntil:         release.Review.ValidUntil,
		GrantedPermissions:       permissions,
	}, nil
}

func (gate *TeamPlanGate) resolve(
	runtime teamplan.RuntimeRelease,
	at time.Time,
) (ReleaseV1, error) {
	if gate == nil ||
		gate.registry == nil ||
		at.IsZero() {
		return ReleaseV1{}, ErrNotApproved
	}
	if gate.registry.ValidateAt(
		at.UTC().Truncate(time.Second),
	) != nil {
		return ReleaseV1{}, teamplan.ErrRuntimeRegistryUnavailable
	}
	release, found := gate.registry.release[runtime.ReleaseID]
	if !found {
		return ReleaseV1{}, ErrNotApproved
	}
	if release.Status == ReleaseRevoked {
		return ReleaseV1{}, ErrRevoked
	}
	if !gate.registry.releaseSelectable(
		release,
		gate.organizationID,
		at.UTC().Truncate(time.Second),
	) ||
		release.Version != runtime.Version ||
		release.OCI.ImageDigest != runtime.ImageDigest {
		return ReleaseV1{}, ErrNotApproved
	}
	return release, nil
}

func grantedPermissions(
	requested workerprotocol.PermissionSetV1,
	workspace workerprotocol.WorkspaceMode,
	assignment teamplan.WorkerAssignment,
) (workerprotocol.PermissionSetV1, error) {
	if requested.Validate() != nil {
		return workerprotocol.PermissionSetV1{}, ErrNotApproved
	}
	keepMCP := slices.Contains(
		assignment.RequiredCapabilities,
		teamplan.CapabilityMCPClient,
	)
	keepPublicWeb := slices.Contains(
		assignment.RequiredCapabilities,
		teamplan.CapabilityWebResearch,
	) || slices.Contains(
		assignment.RequiredCapabilities,
		teamplan.CapabilityBrowser,
	)
	network := make(
		[]workerprotocol.NetworkService,
		0,
		len(requested.NetworkServices),
	)
	for _, service := range requested.NetworkServices {
		switch service {
		case workerprotocol.NetworkControlPlane,
			workerprotocol.NetworkArtifactStore,
			workerprotocol.NetworkModelGateway:
			network = append(network, service)
		case workerprotocol.NetworkMCPGateway:
			if keepMCP {
				network = append(network, service)
			}
		case workerprotocol.NetworkPublicWeb:
			if keepPublicWeb {
				network = append(network, service)
			}
		}
	}
	if !slices.Contains(
		network,
		workerprotocol.NetworkModelGateway,
	) ||
		(keepMCP && !slices.Contains(
			network,
			workerprotocol.NetworkMCPGateway,
		)) {
		return workerprotocol.PermissionSetV1{}, ErrNotApproved
	}
	maxTempDiskMiB := assignment.Resources.DiskGiB * 1024
	if requested.MaxTempDiskMiB < maxTempDiskMiB {
		maxTempDiskMiB = requested.MaxTempDiskMiB
	}
	granted := workerprotocol.PermissionSetV1{
		Workspace:       workspace,
		NetworkServices: network,
		ToolScopes: append(
			[]string(nil),
			requested.ToolScopes...,
		),
		MaxTempDiskMiB: maxTempDiskMiB,
	}
	if granted.Validate() != nil ||
		!permissionSubset(granted, requested) {
		return workerprotocol.PermissionSetV1{}, ErrNotApproved
	}
	return granted, nil
}

func protocolWorkspaceMode(
	mode teamplan.WorkspaceMode,
) (workerprotocol.WorkspaceMode, bool) {
	switch mode {
	case teamplan.WorkspaceReadOnly:
		return workerprotocol.WorkspaceReadOnly, true
	case teamplan.WorkspaceIsolated,
		teamplan.WorkspaceExclusive:
		return workerprotocol.WorkspaceIsolated, true
	default:
		return "", false
	}
}

var _ teamplan.WorkerReleaseApprovalGate = (*TeamPlanGate)(nil)
