package teamplan

import "slices"

func (value WorkerMarketplaceBindingV1) Validate(
	runtimeReleaseID,
	runtimeImageDigest string,
) error {
	return validateMarketplaceBinding(
		value,
		runtimeReleaseID,
		runtimeImageDigest,
	)
}

func (value WorkerMarketplaceBindingV1) Clone() WorkerMarketplaceBindingV1 {
	value.GrantedPermissions.NetworkServices = append(
		value.GrantedPermissions.NetworkServices[:0:0],
		value.GrantedPermissions.NetworkServices...,
	)
	value.GrantedPermissions.ToolScopes = append(
		value.GrantedPermissions.ToolScopes[:0:0],
		value.GrantedPermissions.ToolScopes...,
	)
	return value
}

func (value WorkerMarketplaceBindingV1) Equal(
	other WorkerMarketplaceBindingV1,
) bool {
	return value.SchemaVersion == other.SchemaVersion &&
		value.RegistryID == other.RegistryID &&
		value.RegistryRevision == other.RegistryRevision &&
		value.ReleaseID == other.ReleaseID &&
		value.WorkerTypeID == other.WorkerTypeID &&
		value.PublisherID == other.PublisherID &&
		value.PublisherDisplayName == other.PublisherDisplayName &&
		value.PublisherTier == other.PublisherTier &&
		value.OrganizationID == other.OrganizationID &&
		value.ManifestDigest == other.ManifestDigest &&
		value.ImageRepository == other.ImageRepository &&
		value.ImageDigest == other.ImageDigest &&
		value.ImageSignatureDigest == other.ImageSignatureDigest &&
		value.SBOMDigest == other.SBOMDigest &&
		value.ProvenanceEnvelopeDigest ==
			other.ProvenanceEnvelopeDigest &&
		value.ReviewID == other.ReviewID &&
		value.ReviewPolicyRevision == other.ReviewPolicyRevision &&
		value.ReviewRiskClass == other.ReviewRiskClass &&
		value.ReviewValidUntil.Equal(other.ReviewValidUntil) &&
		value.GrantedPermissions.Workspace ==
			other.GrantedPermissions.Workspace &&
		slices.Equal(
			value.GrantedPermissions.NetworkServices,
			other.GrantedPermissions.NetworkServices,
		) &&
		slices.Equal(
			value.GrantedPermissions.ToolScopes,
			other.GrantedPermissions.ToolScopes,
		) &&
		value.GrantedPermissions.MaxTempDiskMiB ==
			other.GrantedPermissions.MaxTempDiskMiB
}
