package quote

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

var ErrRequoteRequired = errors.New("quote expired or approved scope changed")

func (s ScopeV1) CanonicalCBOR() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(normalizeScope(s))
}

func (s ScopeV1) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(normalizeScope(s))
}

func (q QuoteV1) CanonicalCBOR() ([]byte, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(normalizeQuote(q))
}

func (q QuoteV1) Digest() (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(normalizeQuote(q))
}

func (q QuoteV1) Candidate(candidateID CandidateProfile) (CandidateV1, bool) {
	for _, candidate := range q.Candidates {
		if candidate.CandidateID == candidateID {
			return cloneCandidate(candidate), true
		}
	}
	return CandidateV1{}, false
}

// RequiresRequote returns true when time or any complete candidate scope has
// drifted. Callers must never compare a selected subset of the plan instead.
func (q QuoteV1) RequiresRequote(now time.Time, candidateID CandidateProfile, current ScopeV1) (bool, error) {
	if now.IsZero() {
		return false, fmt.Errorf("current time is required")
	}
	if err := q.Validate(); err != nil {
		return false, err
	}
	candidate, ok := q.Candidate(candidateID)
	if !ok {
		return false, fmt.Errorf("candidate %q is not present in quote", candidateID)
	}
	if !now.Before(q.ValidUntil) {
		return true, nil
	}
	digest, err := current.Digest()
	if err != nil {
		return false, err
	}
	return digest != candidate.ScopeDigest, nil
}

func (q QuoteV1) ValidateSelection(now time.Time, candidateID CandidateProfile, current ScopeV1) error {
	requote, err := q.RequiresRequote(now, candidateID, current)
	if err != nil {
		return err
	}
	if requote {
		return ErrRequoteRequired
	}
	return nil
}

func normalizeScope(value ScopeV1) ScopeV1 {
	value.Resource.AvailabilityZones = sortedStrings(value.Resource.AvailabilityZones)
	value.Resource.VolumeScopes = append([]VolumeScopeV1(nil), value.Resource.VolumeScopes...)
	sort.Slice(value.Resource.VolumeScopes, func(i, j int) bool {
		return value.Resource.VolumeScopes[i].SlotID < value.Resource.VolumeScopes[j].SlotID
	})
	value.Network.SecurityGroupMode = normalizedSecurityGroupMode(value.Network)
	value.Network.IngressPorts = append([]uint32(nil), value.Network.IngressPorts...)
	sort.Slice(value.Network.IngressPorts, func(i, j int) bool {
		return value.Network.IngressPorts[i] < value.Network.IngressPorts[j]
	})
	value.SecretScope = append([]SecretScopeV1(nil), value.SecretScope...)
	sort.Slice(value.SecretScope, func(i, j int) bool {
		if value.SecretScope[i].SecretRef != value.SecretScope[j].SecretRef {
			return value.SecretScope[i].SecretRef < value.SecretScope[j].SecretRef
		}
		if value.SecretScope[i].Delivery != value.SecretScope[j].Delivery {
			return value.SecretScope[i].Delivery < value.SecretScope[j].Delivery
		}
		return value.SecretScope[i].Purpose < value.SecretScope[j].Purpose
	})
	value.IntegrationScope = append([]IntegrationScopeV1(nil), value.IntegrationScope...)
	for index := range value.IntegrationScope {
		value.IntegrationScope[index].Scopes = sortedStrings(value.IntegrationScope[index].Scopes)
	}
	sort.Slice(value.IntegrationScope, func(i, j int) bool {
		if value.IntegrationScope[i].Kind != value.IntegrationScope[j].Kind {
			return value.IntegrationScope[i].Kind < value.IntegrationScope[j].Kind
		}
		return value.IntegrationScope[i].Name < value.IntegrationScope[j].Name
	})
	return value
}

func normalizeQuote(value QuoteV1) QuoteV1 {
	value.QuotedAt = value.QuotedAt.UTC()
	value.ValidUntil = value.ValidUntil.UTC()
	value.Candidates = append([]CandidateV1(nil), value.Candidates...)
	for index := range value.Candidates {
		candidate := cloneCandidate(value.Candidates[index])
		candidate.Scope = normalizeScope(candidate.Scope)
		candidate.OfferedAvailabilityZones = sortedStrings(candidate.OfferedAvailabilityZones)
		sort.Slice(candidate.Quotas, func(i, j int) bool {
			if candidate.Quotas[i].ServiceCode != candidate.Quotas[j].ServiceCode {
				return candidate.Quotas[i].ServiceCode < candidate.Quotas[j].ServiceCode
			}
			return candidate.Quotas[i].QuotaCode < candidate.Quotas[j].QuotaCode
		})
		sort.Slice(candidate.CostItems, func(i, j int) bool {
			if candidate.CostItems[i].Category != candidate.CostItems[j].Category {
				return candidate.CostItems[i].Category < candidate.CostItems[j].Category
			}
			return candidate.CostItems[i].SourceID < candidate.CostItems[j].SourceID
		})
		value.Candidates[index] = candidate
	}
	sort.Slice(value.Candidates, func(i, j int) bool {
		return candidateRank(value.Candidates[i].CandidateID) < candidateRank(value.Candidates[j].CandidateID)
	})
	value.Assumptions = sortedStrings(value.Assumptions)
	value.Exclusions = sortedStrings(value.Exclusions)
	if value.SpotEvidence != nil {
		copy := *value.SpotEvidence
		copy.CheckpointVerifiedAt = copy.CheckpointVerifiedAt.UTC()
		copy.InterruptionTestedAt = copy.InterruptionTestedAt.UTC()
		value.SpotEvidence = &copy
	}
	return value
}

func cloneCandidate(value CandidateV1) CandidateV1 {
	value.Scope = normalizeScope(value.Scope)
	value.OfferedAvailabilityZones = append([]string(nil), value.OfferedAvailabilityZones...)
	value.Quotas = append([]QuotaEvidenceV1(nil), value.Quotas...)
	value.CostItems = append([]CostItemV1(nil), value.CostItems...)
	return value
}

func sortedStrings(values []string) []string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return values
}

func candidateRank(value CandidateProfile) int {
	switch value {
	case CandidateEconomic:
		return 0
	case CandidateRecommended:
		return 1
	case CandidatePerformance:
		return 2
	default:
		return 3
	}
}
