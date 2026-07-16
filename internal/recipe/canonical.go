package recipe

import (
	"sort"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

func (r RecipeV1) CanonicalCBOR() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(r.normalized())
}

func (r RecipeV1) Digest() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(r.normalized())
}

func (r RecipeV1) normalized() RecipeV1 {
	normalized := r
	normalized.Sources = append([]SourceV1(nil), r.Sources...)
	for index := range normalized.Sources {
		normalized.Sources[index].RetrievedAt = normalized.Sources[index].RetrievedAt.UTC()
	}
	sort.Slice(normalized.Sources, func(i, j int) bool {
		left, right := normalized.Sources[i], normalized.Sources[j]
		if left.URL != right.URL {
			return left.URL < right.URL
		}
		if left.Commit != right.Commit {
			return left.Commit < right.Commit
		}
		if left.ArtifactDigest != right.ArtifactDigest {
			return left.ArtifactDigest < right.ArtifactDigest
		}
		return left.Version < right.Version
	})

	normalized.Install.CheckpointNames = sortedStrings(r.Install.CheckpointNames)
	normalized.Install.AllowedAdaptations = sortedStrings(r.Install.AllowedAdaptations)
	normalized.Install.Adaptations = append([]AdaptationRuleV1(nil), r.Install.Adaptations...)
	sort.Slice(normalized.Install.Adaptations, func(i, j int) bool {
		return normalized.Install.Adaptations[i].Action < normalized.Install.Adaptations[j].Action
	})
	normalized.Install.Steps = append([]InstallStepV1(nil), r.Install.Steps...)
	for index := range normalized.Install.Steps {
		normalized.Install.Steps[index].Inputs = append([]ActionInputV1(nil), r.Install.Steps[index].Inputs...)
		sort.Slice(normalized.Install.Steps[index].Inputs, func(i, j int) bool {
			return normalized.Install.Steps[index].Inputs[i].Name < normalized.Install.Steps[index].Inputs[j].Name
		})
	}
	normalized.Requirements.DataLocations = append([]DataLocationRequirementV1(nil), r.Requirements.DataLocations...)
	for index := range normalized.Requirements.DataLocations {
		normalized.Requirements.DataLocations[index].Residency = sortedStrings(r.Requirements.DataLocations[index].Residency)
	}
	sort.Slice(normalized.Requirements.DataLocations, func(i, j int) bool {
		return normalized.Requirements.DataLocations[i].DataSlotID < normalized.Requirements.DataLocations[j].DataSlotID
	})
	normalized.VolumeSlots = append([]VolumeSlotRequirementV1(nil), r.VolumeSlots...)
	sort.Slice(normalized.VolumeSlots, func(i, j int) bool {
		return normalized.VolumeSlots[i].SlotID < normalized.VolumeSlots[j].SlotID
	})
	normalized.DataSlots = append([]DataSlotRequirementV1(nil), r.DataSlots...)
	sort.Slice(normalized.DataSlots, func(i, j int) bool {
		return normalized.DataSlots[i].SlotID < normalized.DataSlots[j].SlotID
	})
	normalized.SecretSlots = append([]SecretSlotRequirementV1(nil), r.SecretSlots...)
	sort.Slice(normalized.SecretSlots, func(i, j int) bool {
		return normalized.SecretSlots[i].SlotID < normalized.SecretSlots[j].SlotID
	})
	normalized.Integrations = append([]IntegrationDeclarationV1(nil), r.Integrations...)
	sort.Slice(normalized.Integrations, func(i, j int) bool {
		return normalized.Integrations[i].ID < normalized.Integrations[j].ID
	})
	if r.Network != nil {
		network := *r.Network
		network.Outbound = append([]OutboundRuleV1(nil), r.Network.Outbound...)
		sort.Slice(network.Outbound, func(i, j int) bool {
			return network.Outbound[i].ID < network.Outbound[j].ID
		})
		network.Listeners = append([]ListenerV1(nil), r.Network.Listeners...)
		sort.Slice(network.Listeners, func(i, j int) bool {
			return network.Listeners[i].ID < network.Listeners[j].ID
		})
		normalized.Network = &network
	}
	if r.Restart != nil {
		restart := *r.Restart
		restart.RecoveryCheckpoints = sortedStrings(r.Restart.RecoveryCheckpoints)
		normalized.Restart = &restart
	}
	if r.Pairing != nil {
		pairing := *r.Pairing
		normalized.Pairing = &pairing
	}
	if r.ManagedAcceptance != nil {
		acceptance := *r.ManagedAcceptance
		acceptance.AcceptedAt = acceptance.AcceptedAt.UTC()
		normalized.ManagedAcceptance = &acceptance
	}
	return normalized
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
