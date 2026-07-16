package approval

import cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"

// PricingScope projects the exact selected Plan fields covered by a Quote
// candidate. QuoteBinding itself is excluded so no caller-provided digest can
// influence the computed value.
func (p PlanV1) PricingScope() cloudquote.ScopeV1 {
	scope := cloudquote.ScopeV1{
		SchemaVersion:   cloudquote.ScopeSchemaV1,
		AgentInstanceID: p.AgentInstanceID,
		OwnerID:         p.OwnerID,
		ConnectionID:    p.ConnectionID,
		Recipe: cloudquote.RecipeBindingV1{
			RecipeID: p.Recipe.RecipeID,
			Digest:   p.Recipe.Digest,
			Maturity: p.Recipe.Maturity,
		},
		Resource: cloudquote.ResourceScopeV1{
			CandidateID:           cloudquote.CandidateProfile(p.Quote.CandidateID),
			Region:                p.ResourceScope.Region,
			AvailabilityZones:     append([]string(nil), p.ResourceScope.AvailabilityZones...),
			InstanceType:          p.ResourceScope.InstanceType,
			InstanceCount:         p.ResourceScope.InstanceCount,
			Architecture:          p.ResourceScope.Architecture,
			VCPU:                  p.ResourceScope.VCPU,
			MemoryMiB:             p.ResourceScope.MemoryMiB,
			GPUType:               p.ResourceScope.GPUType,
			GPUCount:              p.ResourceScope.GPUCount,
			GPUMemoryMiB:          p.ResourceScope.GPUMemoryMiB,
			DiskGiB:               p.ResourceScope.DiskGiB,
			VolumeType:            p.ResourceScope.VolumeType,
			VolumeIOPS:            p.ResourceScope.VolumeIOPS,
			VolumeThroughputMiBPS: p.ResourceScope.VolumeThroughputMiBPS,
			VolumeEncrypted:       p.ResourceScope.VolumeEncrypted,
			PurchaseOption:        cloudquote.PurchaseOption(p.ResourceScope.PurchaseOption),
			WorkerImageID:         p.ResourceScope.WorkerImageID,
			WorkerImageDigest:     p.ResourceScope.WorkerImageDigest,
		},
		Network: cloudquote.NetworkScopeV1{
			VPCID:                  p.NetworkScope.VPCID,
			SubnetID:               p.NetworkScope.SubnetID,
			SecurityGroupMode:      cloudquote.SecurityGroupMode(normalizedSecurityGroupMode(p.NetworkScope)),
			SecurityGroupID:        p.NetworkScope.SecurityGroupID,
			PublicIPv4:             p.NetworkScope.PublicIPv4,
			EntryPoint:             cloudquote.EntryPointKind(p.NetworkScope.EntryPoint),
			PublicExposure:         p.NetworkScope.PublicExposure,
			IngressPorts:           append([]uint32(nil), p.NetworkScope.IngressPorts...),
			Hostname:               p.NetworkScope.Hostname,
			TLSRequired:            p.NetworkScope.TLSRequired,
			AuthenticationRequired: p.NetworkScope.AuthenticationRequired,
		},
		Retention: cloudquote.RetentionScopeV1{
			Class:              cloudquote.RetentionClass(p.RetentionScope.Class),
			AutoDestroy:        p.RetentionScope.AutoDestroy,
			GracePeriodSeconds: p.RetentionScope.GracePeriodSeconds,
			MaxLifetimeSeconds: p.RetentionScope.MaxLifetimeSeconds,
		},
	}
	for _, secret := range p.SecretScope {
		scope.SecretScope = append(scope.SecretScope, cloudquote.SecretScopeV1{
			SecretRef: secret.SecretRef,
			Purpose:   secret.Purpose,
			Delivery:  secret.Delivery,
		})
	}
	for _, integration := range p.IntegrationScope {
		scope.IntegrationScope = append(scope.IntegrationScope, cloudquote.IntegrationScopeV1{
			Kind:   cloudquote.IntegrationKind(integration.Kind),
			Name:   integration.Name,
			Scopes: append([]string(nil), integration.Scopes...),
		})
	}
	return scope
}

func (p PlanV1) PricingScopeDigest() (string, error) {
	return p.PricingScope().Digest()
}
