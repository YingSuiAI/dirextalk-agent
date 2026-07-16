package quote

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const maximumPricingEvidenceAge = 5 * time.Minute

type Service struct {
	pricing PricingPort
	now     func() time.Time
}

func NewService(pricing PricingPort, now func() time.Time) (*Service, error) {
	if pricing == nil {
		return nil, fmt.Errorf("pricing port is required")
	}
	if now == nil {
		return nil, fmt.Errorf("clock is required")
	}
	return &Service{pricing: pricing, now: now}, nil
}

func (s *Service) Quote(ctx context.Context, request RequestV1, boundRecipe recipe.RecipeV1) (QuoteV1, error) {
	if ctx == nil {
		return QuoteV1{}, fmt.Errorf("context is required")
	}
	if err := request.Validate(); err != nil {
		return QuoteV1{}, err
	}
	if err := boundRecipe.Validate(); err != nil {
		return QuoteV1{}, fmt.Errorf("validate Recipe: %w", err)
	}
	recipeDigest, err := boundRecipe.Digest()
	if err != nil {
		return QuoteV1{}, fmt.Errorf("digest Recipe: %w", err)
	}
	request = normalizeRequest(request)
	for index, scope := range request.Scopes {
		if scope.Recipe.RecipeID != boundRecipe.RecipeID || scope.Recipe.Digest != recipeDigest || scope.Recipe.Maturity != boundRecipe.Maturity {
			return QuoteV1{}, fmt.Errorf("scopes[%d] does not bind the supplied Recipe", index)
		}
		if err := validateMeetsRecipe(scope.Resource, boundRecipe.Requirements); err != nil {
			return QuoteV1{}, fmt.Errorf("scopes[%d]: %w", index, err)
		}
	}
	if err := validateSpotQualification(request, boundRecipe, recipeDigest); err != nil {
		return QuoteV1{}, err
	}

	now := s.now().UTC()
	if now.IsZero() {
		return QuoteV1{}, fmt.Errorf("clock returned zero time")
	}
	query := pricingQuery(request)
	snapshot, err := s.pricing.Price(ctx, query)
	if err != nil {
		return QuoteV1{}, fmt.Errorf("read provider pricing: %w", err)
	}
	if err := validateSnapshot(snapshot, query, now); err != nil {
		return QuoteV1{}, err
	}

	quote := QuoteV1{
		SchemaVersion: SchemaV1,
		QuoteID:       request.QuoteID,
		QuotedAt:      now,
		ValidUntil:    now.Add(Validity),
		Currency:      snapshot.Currency,
		Usage:         request.Usage,
		Assumptions:   append([]string(nil), snapshot.Assumptions...),
		Exclusions:    append([]string(nil), snapshot.Exclusions...),
	}
	if request.SpotQualification != nil {
		copy := *request.SpotQualification
		quote.SpotEvidence = &copy
	}
	for _, scope := range request.Scopes {
		offering := findOffering(snapshot.Offerings, scope.Resource.CandidateID)
		price := findPrice(snapshot.Prices, scope.Resource.CandidateID)
		candidate := CandidateV1{
			CandidateID:              scope.Resource.CandidateID,
			Scope:                    scope,
			OfferedAvailabilityZones: append([]string(nil), offering.AvailabilityZones...),
			CostItems:                append([]CostItemV1(nil), price.CostItems...),
		}
		for _, evidence := range snapshot.Quotas {
			if evidence.CandidateID == candidate.CandidateID {
				candidate.Quotas = append(candidate.Quotas, evidence.Quota)
			}
		}
		candidate.ScopeDigest, err = scope.Digest()
		if err != nil {
			return QuoteV1{}, err
		}
		for _, item := range candidate.CostItems {
			candidate.HourlyEstimateMicros, _ = checkedAdd(candidate.HourlyEstimateMicros, item.HourlyEstimateMicros)
			candidate.MonthlyEstimateMicros, _ = checkedAdd(candidate.MonthlyEstimateMicros, item.MonthlyEstimateMicros)
			candidate.MaximumLaunchAmountMicros, _ = checkedAdd(candidate.MaximumLaunchAmountMicros, item.MaximumLaunchAmountMicros)
		}
		quote.Candidates = append(quote.Candidates, candidate)
	}
	quote = normalizeQuote(quote)
	if err := quote.Validate(); err != nil {
		return QuoteV1{}, fmt.Errorf("provider produced invalid quote: %w", err)
	}
	return quote, nil
}

func pricingQuery(request RequestV1) PricingQueryV1 {
	first := request.Scopes[0]
	query := PricingQueryV1{
		Region: first.Resource.Region,
		Zones:  append([]string(nil), first.Resource.AvailabilityZones...),
		Usage:  request.Usage,
	}
	for _, scope := range request.Scopes {
		resource := scope.Resource
		query.Candidates = append(query.Candidates, PricingCandidateQueryV1{
			CandidateID:           resource.CandidateID,
			InstanceType:          resource.InstanceType,
			InstanceCount:         resource.InstanceCount,
			Architecture:          resource.Architecture,
			DiskGiB:               resource.DiskGiB,
			VolumeType:            resource.VolumeType,
			VolumeIOPS:            resource.VolumeIOPS,
			VolumeThroughputMiBPS: resource.VolumeThroughputMiBPS,
			PurchaseOption:        resource.PurchaseOption,
			EntryPoint:            scope.Network.EntryPoint,
			PublicExposure:        scope.Network.PublicExposure,
		})
	}
	query.Zones = sortedStrings(query.Zones)
	sort.Slice(query.Candidates, func(i, j int) bool {
		return candidateRank(query.Candidates[i].CandidateID) < candidateRank(query.Candidates[j].CandidateID)
	})
	return query
}

func validateMeetsRecipe(resource ResourceScopeV1, requirements recipe.ResourceRequirementsV1) error {
	if resource.Architecture != requirements.Architecture || resource.VCPU < requirements.MinVCPU || resource.MemoryMiB < requirements.MinMemoryMiB || resource.DiskGiB < requirements.MinDiskGiB {
		return fmt.Errorf("candidate does not meet Recipe CPU, memory, disk, or architecture requirements")
	}
	if requirements.GPURequired {
		if resource.GPUCount == 0 || resource.GPUMemoryMiB < requirements.MinGPUMemoryMiB || !stringsEqualFoldNonEmpty(resource.GPUType, requirements.GPUFamily) {
			return fmt.Errorf("candidate does not meet Recipe GPU requirements")
		}
	}
	return nil
}

func validateSpotQualification(request RequestV1, boundRecipe recipe.RecipeV1, digest string) error {
	hasSpot := false
	for _, scope := range request.Scopes {
		if scope.Resource.PurchaseOption == PurchaseSpot {
			hasSpot = true
			if scope.Retention.Class != RetentionEphemeral || !scope.Retention.AutoDestroy {
				return fmt.Errorf("Spot is restricted to ephemeral auto-destroy workloads")
			}
		}
	}
	if !hasSpot {
		if request.SpotQualification != nil {
			return fmt.Errorf("Spot qualification is not allowed without a Spot candidate")
		}
		return nil
	}
	if request.SpotQualification == nil {
		return fmt.Errorf("Spot requires checkpoint/resume and interruption-test evidence")
	}
	evidence := *request.SpotQualification
	if err := validateSpotEvidence(evidence); err != nil {
		return err
	}
	if evidence.RecipeDigest != digest || boundRecipe.Restart == nil || evidence.ResumeAction != boundRecipe.Restart.Action || evidence.MaxRetries > boundRecipe.Restart.MaxAttempts {
		return fmt.Errorf("Spot evidence does not match the Recipe restart contract")
	}
	if !contains(boundRecipe.Install.CheckpointNames, evidence.CheckpointName) || !contains(boundRecipe.Restart.RecoveryCheckpoints, evidence.CheckpointName) {
		return fmt.Errorf("Spot evidence checkpoint is not recoverable by the Recipe")
	}
	return nil
}

func validateSnapshot(snapshot PricingSnapshotV1, query PricingQueryV1, now time.Time) error {
	if snapshot.CapturedAt.IsZero() || snapshot.CapturedAt.After(now.Add(30*time.Second)) || now.Sub(snapshot.CapturedAt) > maximumPricingEvidenceAge {
		return fmt.Errorf("provider pricing evidence is stale or from the future")
	}
	if !currencyPattern.MatchString(snapshot.Currency) {
		return fmt.Errorf("provider currency is invalid")
	}
	if err := validateTextSetRequired("provider assumptions", snapshot.Assumptions, 32); err != nil {
		return err
	}
	if err := validateTextSetRequired("provider exclusions", snapshot.Exclusions, 32); err != nil {
		return err
	}
	if len(snapshot.Offerings) != 3 || len(snapshot.Prices) != 3 || len(snapshot.Quotas) < 3 {
		return fmt.Errorf("provider must return offering, price, and quota evidence for all three candidates")
	}
	seenOfferings := make(map[CandidateProfile]struct{}, 3)
	seenPrices := make(map[CandidateProfile]struct{}, 3)
	quotaCounts := make(map[CandidateProfile]int, 3)
	for _, candidate := range query.Candidates {
		offering, ok := lookupOffering(snapshot.Offerings, candidate.CandidateID)
		if !ok {
			return fmt.Errorf("provider omitted offering for %q", candidate.CandidateID)
		}
		if _, duplicate := seenOfferings[candidate.CandidateID]; duplicate {
			return fmt.Errorf("provider returned duplicate offering")
		}
		seenOfferings[candidate.CandidateID] = struct{}{}
		if offering.Region != query.Region || offering.InstanceType != candidate.InstanceType || offering.Architecture != candidate.Architecture || offering.PurchaseOption != candidate.PurchaseOption {
			return fmt.Errorf("provider offering does not match typed pricing query")
		}
		if err := validateZones(query.Region, offering.AvailabilityZones); err != nil || !hasIntersection(query.Zones, offering.AvailabilityZones) {
			return fmt.Errorf("provider offering is unavailable in requested zones")
		}
		price, ok := lookupPrice(snapshot.Prices, candidate.CandidateID)
		if !ok {
			return fmt.Errorf("provider omitted price for %q", candidate.CandidateID)
		}
		if _, duplicate := seenPrices[candidate.CandidateID]; duplicate {
			return fmt.Errorf("provider returned duplicate price")
		}
		seenPrices[candidate.CandidateID] = struct{}{}
		if len(price.CostItems) == 0 {
			return fmt.Errorf("provider returned empty cost items")
		}
	}
	for _, evidence := range snapshot.Quotas {
		if candidateRank(evidence.CandidateID) > 2 {
			return fmt.Errorf("provider quota references unknown candidate")
		}
		quotaCounts[evidence.CandidateID]++
	}
	for _, candidate := range query.Candidates {
		if quotaCounts[candidate.CandidateID] == 0 {
			return fmt.Errorf("provider omitted quota for %q", candidate.CandidateID)
		}
	}
	return nil
}

func lookupOffering(values []OfferingV1, id CandidateProfile) (OfferingV1, bool) {
	var result OfferingV1
	count := 0
	for _, value := range values {
		if value.CandidateID == id {
			result = value
			count++
		}
	}
	return result, count == 1
}

func findOffering(values []OfferingV1, id CandidateProfile) OfferingV1 {
	value, _ := lookupOffering(values, id)
	return value
}

func lookupPrice(values []CandidatePriceV1, id CandidateProfile) (CandidatePriceV1, bool) {
	var result CandidatePriceV1
	count := 0
	for _, value := range values {
		if value.CandidateID == id {
			result = value
			count++
		}
	}
	return result, count == 1
}

func findPrice(values []CandidatePriceV1, id CandidateProfile) CandidatePriceV1 {
	value, _ := lookupPrice(values, id)
	return value
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringsEqualFoldNonEmpty(left, right string) bool {
	return left != "" && right != "" && strings.EqualFold(left, right)
}
