package cloudapp

import (
	"fmt"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/google/uuid"
)

func BuildPlan(agentInstanceID, planID string, priced cloudquote.QuoteV1, candidateID cloudquote.CandidateProfile, current cloudquote.ScopeV1, now time.Time) (cloudapproval.PlanV1, error) {
	if parsed, err := uuid.Parse(agentInstanceID); err != nil || parsed == uuid.Nil {
		return cloudapproval.PlanV1{}, ErrInvalid
	}
	if parsed, err := uuid.Parse(planID); err != nil || parsed == uuid.Nil || now.IsZero() {
		return cloudapproval.PlanV1{}, ErrInvalid
	}
	if err := priced.ValidateSelection(now.UTC(), candidateID, current); err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("%w: %v", ErrQuoteExpired, err)
	}
	candidate, found := priced.Candidate(candidateID)
	if !found {
		return cloudapproval.PlanV1{}, ErrInvalid
	}
	quoteDigest, err := priced.Digest()
	if err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("%w: quote digest", ErrInvalid)
	}
	planSchema := cloudapproval.PlanSchemaV1
	if candidate.Scope.SchemaVersion == cloudquote.ScopeSchemaV2 {
		planSchema = cloudapproval.PlanSchemaV2
	}
	plan := cloudapproval.PlanV1{
		SchemaVersion: planSchema, AgentInstanceID: agentInstanceID,
		OwnerID: candidate.Scope.OwnerID, PlanID: planID, Revision: 1,
		Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: candidate.Scope.ConnectionID,
		Recipe: cloudapproval.RecipeBindingV1{
			RecipeID: candidate.Scope.Recipe.RecipeID, Digest: candidate.Scope.Recipe.Digest, Maturity: candidate.Scope.Recipe.Maturity,
		},
		Quote: cloudapproval.QuoteBindingV1{
			QuoteID: priced.QuoteID, Digest: quoteDigest, ScopeDigest: candidate.ScopeDigest,
			CandidateID: string(candidateID), ValidUntil: priced.ValidUntil,
		},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: candidate.Scope.Resource.Region, AvailabilityZones: candidate.Scope.Resource.AvailabilityZones,
			InstanceType: candidate.Scope.Resource.InstanceType, InstanceCount: candidate.Scope.Resource.InstanceCount,
			Architecture: candidate.Scope.Resource.Architecture, VCPU: candidate.Scope.Resource.VCPU,
			MemoryMiB: candidate.Scope.Resource.MemoryMiB, GPUType: candidate.Scope.Resource.GPUType,
			GPUCount: candidate.Scope.Resource.GPUCount, GPUMemoryMiB: candidate.Scope.Resource.GPUMemoryMiB,
			DiskGiB: candidate.Scope.Resource.DiskGiB, VolumeType: candidate.Scope.Resource.VolumeType,
			VolumeIOPS: candidate.Scope.Resource.VolumeIOPS, VolumeThroughputMiBPS: candidate.Scope.Resource.VolumeThroughputMiBPS,
			VolumeEncrypted: candidate.Scope.Resource.VolumeEncrypted,
			PurchaseOption:  cloudapproval.PurchaseOption(candidate.Scope.Resource.PurchaseOption),
			WorkerImageID:   candidate.Scope.Resource.WorkerImageID, WorkerImageDigest: candidate.Scope.Resource.WorkerImageDigest,
			VolumeScopes: append([]cloudapproval.VolumeScopeV1(nil), candidate.Scope.Resource.VolumeScopes...),
		},
		NetworkScope: cloudapproval.NetworkScopeV1{
			VPCID: candidate.Scope.Network.VPCID, SubnetID: candidate.Scope.Network.SubnetID,
			SecurityGroupMode: cloudapproval.SecurityGroupMode(candidate.Scope.Network.SecurityGroupMode),
			SecurityGroupID:   candidate.Scope.Network.SecurityGroupID, PublicIPv4: candidate.Scope.Network.PublicIPv4,
			EntryPoint:     cloudapproval.EntryPointKind(candidate.Scope.Network.EntryPoint),
			PublicExposure: candidate.Scope.Network.PublicExposure, IngressPorts: candidate.Scope.Network.IngressPorts,
			Hostname: candidate.Scope.Network.Hostname, TLSRequired: candidate.Scope.Network.TLSRequired,
			AuthenticationRequired: candidate.Scope.Network.AuthenticationRequired,
		},
		RetentionScope: cloudapproval.RetentionScopeV1{
			Class: cloudapproval.RetentionClass(candidate.Scope.Retention.Class), AutoDestroy: candidate.Scope.Retention.AutoDestroy,
			GracePeriodSeconds: candidate.Scope.Retention.GracePeriodSeconds,
			MaxLifetimeSeconds: candidate.Scope.Retention.MaxLifetimeSeconds,
		},
		// The quote is immutable input. Detach the V2 template slices before the
		// Plan is persisted or projected for device signing.
		ServiceOperations: cloudquote.NormalizeServiceOperations(candidate.Scope.ServiceOperations),
	}
	for _, secret := range candidate.Scope.SecretScope {
		plan.SecretScope = append(plan.SecretScope, cloudapproval.SecretReferenceV1{
			SecretRef: secret.SecretRef, Purpose: secret.Purpose, Delivery: secret.Delivery,
		})
	}
	for _, integration := range candidate.Scope.IntegrationScope {
		plan.IntegrationScope = append(plan.IntegrationScope, cloudapproval.IntegrationScopeV1{
			Kind: cloudapproval.IntegrationKind(integration.Kind), Name: integration.Name, Scopes: integration.Scopes,
		})
	}
	if err := plan.Validate(); err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return plan, nil
}
