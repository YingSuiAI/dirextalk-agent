package awsprovider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/google/uuid"
)

const (
	teamComputeEvidenceSchemaV1 = "dirextalk.agent.aws-team-compute-evidence/v1"
	teamComputeConfigSchemaV1   = "dirextalk.agent.aws-team-compute-configuration/v1"
	maximumTeamComputeShapes    = 32
)

var (
	ErrInvalidTeamComputePricing = errors.New("invalid AWS Team Compute pricing configuration")
	instanceTypePattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	availabilityZonePattern      = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d+[a-z]$`)
)

// TeamComputeShape is an operator-owned allowlist item. The Agent model cannot
// provide an instance type, Region, zone, disk size, or purchase option.
type TeamComputeShape struct {
	InstanceType string              `json:"instance_type"`
	Architecture recipe.Architecture `json:"architecture"`
	DiskGiB      uint64              `json:"disk_gib"`
}

// TeamComputePricingProvider combines only AWS read APIs. Its client surface
// contains no RunInstances, Create*, Delete*, Stop*, or Terminate* operation.
type TeamComputePricingProvider struct {
	pricing *PricingProvider
	scope   teamplan.ProviderScope
	region  string
	zones   []string
	shapes  []TeamComputeShape
	config  teamComputeConfigurationBinding
}

func NewTeamComputePricingProvider(
	pricing *PricingProvider,
	scope teamplan.ProviderScope,
	region string,
	zones []string,
	shapes []TeamComputeShape,
) (*TeamComputePricingProvider, error) {
	if pricing == nil || pricing.factory == nil || pricing.now == nil ||
		scope.Validate() != nil ||
		scope.Provider != teamplan.CloudProviderAWS {
		return nil, ErrInvalidTeamComputePricing
	}
	normalizedRegion, normalizedZones, normalizedShapes, err :=
		normalizeTeamComputeRegion(region, zones, shapes)
	if err != nil {
		return nil, err
	}
	binding, err := newTeamComputeConfigurationBinding(
		normalizedRegion,
		normalizedZones,
		normalizedShapes,
	)
	if err != nil {
		return nil, err
	}
	return &TeamComputePricingProvider{
		pricing: pricing,
		scope:   scope,
		region:  normalizedRegion,
		zones:   normalizedZones,
		shapes:  normalizedShapes,
		config:  binding,
	}, nil
}

func normalizeTeamComputeRegion(
	region string,
	zones []string,
	shapes []TeamComputeShape,
) (string, []string, []TeamComputeShape, error) {
	if strings.TrimSpace(region) != region ||
		!sdkRegionPattern.MatchString(region) ||
		len(zones) == 0 || len(zones) > 16 ||
		len(shapes) == 0 || len(shapes) > maximumTeamComputeShapes {
		return "", nil, nil, ErrInvalidTeamComputePricing
	}
	normalizedZones := append([]string(nil), zones...)
	slices.Sort(normalizedZones)
	for index, zone := range normalizedZones {
		if strings.TrimSpace(zone) != zone ||
			!availabilityZonePattern.MatchString(zone) ||
			len(zone) != len(region)+1 ||
			!strings.HasPrefix(zone, region) ||
			(index > 0 && normalizedZones[index-1] == zone) {
			return "", nil, nil, ErrInvalidTeamComputePricing
		}
	}

	normalizedShapes := append([]TeamComputeShape(nil), shapes...)
	slices.SortFunc(normalizedShapes, compareTeamComputeShapes)
	for index, shape := range normalizedShapes {
		if !instanceTypePattern.MatchString(shape.InstanceType) ||
			!recipe.ValidArchitecture(shape.Architecture) ||
			shape.DiskGiB < 8 || shape.DiskGiB > 64*1024 ||
			(index > 0 &&
				compareTeamComputeShapes(normalizedShapes[index-1], shape) == 0) {
			return "", nil, nil, ErrInvalidTeamComputePricing
		}
	}
	return region, normalizedZones, normalizedShapes, nil
}

func (provider *TeamComputePricingProvider) ReadComputeOffers(
	ctx context.Context,
	scope teamplan.ProviderScope,
	region string,
) (teampricing.ComputeEvidence, error) {
	if provider == nil || provider.pricing == nil || ctx == nil ||
		scope != provider.scope ||
		region != provider.region {
		return teampricing.ComputeEvidence{}, ErrInvalidTeamComputePricing
	}
	if err := ctx.Err(); err != nil {
		return teampricing.ComputeEvidence{}, err
	}
	clients := provider.pricing.factory.ClientsForRegion(region)
	if clients.EC2 == nil || clients.PriceList == nil ||
		clients.ServiceQuotas == nil || clients.CloudWatch == nil {
		return teampricing.ComputeEvidence{}, errors.New(
			"AWS Team Compute pricing read clients are incomplete",
		)
	}
	capturedAt := provider.pricing.now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() {
		return teampricing.ComputeEvidence{}, ErrInvalidTeamComputePricing
	}

	catalog := newPriceCatalog(clients.PriceList)
	quotaCache := make(map[string]quotaSnapshot)
	offers := make([]teamplan.ComputeOffer, 0, len(provider.shapes))
	prices := make([]teamComputePriceObservation, 0, len(provider.shapes))
	capacity := make([]teamComputeCapacityObservation, 0, len(provider.shapes))
	for _, shape := range provider.shapes {
		candidate := cloudquote.PricingCandidateQueryV1{
			CandidateID:    cloudquote.CandidateRecommended,
			InstanceType:   shape.InstanceType,
			InstanceCount:  1,
			Architecture:   shape.Architecture,
			DiskGiB:        shape.DiskGiB,
			VolumeType:     "gp3",
			PurchaseOption: cloudquote.PurchaseOnDemand,
			EntryPoint:     cloudquote.EntryPointNone,
		}
		query := cloudquote.PricingQueryV1{
			Region: region,
			Zones:  provider.zones,
			Usage: cloudquote.UsageV1{
				RuntimeHoursPerMonth: 730,
			},
		}
		offering, err := readOffering(ctx, clients.EC2, query, candidate)
		if err != nil {
			return teampricing.ComputeEvidence{}, fmt.Errorf(
				"Team Compute offering evidence: %w",
				err,
			)
		}
		spec, err := readInstanceSpec(
			ctx,
			clients.EC2,
			shape.InstanceType,
			shape.Architecture,
		)
		if err != nil || spec.memoryMiB == 0 || spec.vcpu > uint64(^uint32(0)) {
			return teampricing.ComputeEvidence{}, errors.New(
				"Team Compute instance evidence is unavailable",
			)
		}
		quota, err := readQuota(
			ctx,
			clients,
			candidate,
			spec.vcpu,
			capturedAt,
			quotaCache,
		)
		if err != nil {
			return teampricing.ComputeEvidence{}, fmt.Errorf(
				"Team Compute quota evidence: %w",
				err,
			)
		}
		availableUnits := quota.LimitUnits - quota.UsedUnits
		if availableUnits < spec.vcpu {
			return teampricing.ComputeEvidence{}, errors.New(
				"Team Compute account capacity is unavailable",
			)
		}
		computeCost, err := readComputeCost(
			ctx,
			clients.EC2,
			catalog,
			region,
			candidate,
			offering.AvailabilityZones,
			query.Usage,
			capturedAt,
		)
		if err != nil {
			return teampricing.ComputeEvidence{}, fmt.Errorf(
				"Team Compute instance price evidence: %w",
				err,
			)
		}
		ebsCosts, err := readEBSCosts(ctx, catalog, region, candidate)
		if err != nil {
			return teampricing.ComputeEvidence{}, fmt.Errorf(
				"Team Compute disk price evidence: %w",
				err,
			)
		}
		costItems := append(
			[]cloudquote.CostItemV1{computeCost},
			ebsCosts...,
		)
		slices.SortFunc(costItems, compareCostItems)
		hourlyMicros := uint64(0)
		for _, item := range costItems {
			hourlyMicros, err = checkedSum(
				hourlyMicros,
				item.HourlyEstimateMicros,
			)
			if err != nil {
				return teampricing.ComputeEvidence{}, err
			}
		}
		offerID := teamComputeOfferID(region, shape)
		offer := teamplan.ComputeOffer{
			OfferID:        offerID,
			Region:         region,
			InstanceType:   shape.InstanceType,
			Architecture:   shape.Architecture,
			VCPU:           uint32(spec.vcpu),
			MemoryMiB:      spec.memoryMiB,
			DiskGiB:        shape.DiskGiB,
			HourlyMicros:   hourlyMicros,
			PurchaseOption: "on_demand",
			CapacityPool:   "aws:ec2-quota:" + quota.QuotaCode,
			CapacityUnits:  spec.vcpu,
			AvailableUnits: availableUnits,
			Available:      true,
		}
		offers = append(offers, offer)
		prices = append(prices, teamComputePriceObservation{
			OfferID:      offerID,
			InstanceType: shape.InstanceType,
			DiskGiB:      shape.DiskGiB,
			HourlyMicros: hourlyMicros,
			CostItems:    costItems,
		})
		capacity = append(capacity, teamComputeCapacityObservation{
			OfferID:           offerID,
			InstanceType:      shape.InstanceType,
			Architecture:      shape.Architecture,
			VCPU:              uint32(spec.vcpu),
			MemoryMiB:         spec.memoryMiB,
			AvailabilityZones: offering.AvailabilityZones,
			Quota:             quota,
			CapacityPool:      offer.CapacityPool,
			CapacityUnits:     offer.CapacityUnits,
			AvailableUnits:    offer.AvailableUnits,
		})
	}

	priceDigest, err := canonical.Digest(teamComputePriceEvidence{
		SchemaVersion: teamComputeEvidenceSchemaV1,
		ProviderScope: scope,
		Region:        region,
		Currency:      "USD",
		CapturedAt:    capturedAt,
		Offers:        prices,
	})
	if err != nil {
		return teampricing.ComputeEvidence{}, err
	}
	capacityDigest, err := canonical.Digest(teamComputeCapacityEvidence{
		SchemaVersion: teamComputeEvidenceSchemaV1,
		ProviderScope: scope,
		Region:        region,
		CapturedAt:    capturedAt,
		Offers:        capacity,
	})
	if err != nil {
		return teampricing.ComputeEvidence{}, err
	}
	return teampricing.ComputeEvidence{
		ProviderScope: scope,
		Region:        region,
		Currency:      "USD",
		Sources: []teamplan.OfferSourceReceipt{
			{
				Kind:       teamplan.OfferSourceComputeConfig,
				SourceID:   provider.config.SourceID,
				Digest:     provider.config.Digest,
				CapturedAt: capturedAt,
			},
			{
				Kind:       teamplan.OfferSourceComputePricing,
				SourceID:   "aws-price-list:" + region + ":team-compute/v1",
				Digest:     priceDigest,
				CapturedAt: capturedAt,
			},
			{
				Kind:       teamplan.OfferSourceComputeCapacity,
				SourceID:   "aws-ec2-capacity:" + region + ":team-compute/v1",
				Digest:     capacityDigest,
				CapturedAt: capturedAt,
			},
		},
		Offers: offers,
	}, nil
}

type teamComputeConfigurationBinding struct {
	SourceID string
	Digest   string
}

type teamComputeConfigurationDocument struct {
	SchemaVersion     string             `json:"schema_version"`
	Region            string             `json:"region"`
	AvailabilityZones []string           `json:"availability_zones"`
	Shapes            []TeamComputeShape `json:"shapes"`
}

func newTeamComputeConfigurationBinding(
	region string,
	zones []string,
	shapes []TeamComputeShape,
) (teamComputeConfigurationBinding, error) {
	normalizedRegion, normalizedZones, normalizedShapes, err :=
		normalizeTeamComputeRegion(region, zones, shapes)
	if err != nil {
		return teamComputeConfigurationBinding{}, err
	}
	digest, err := canonical.Digest(teamComputeConfigurationDocument{
		SchemaVersion:     teamComputeConfigSchemaV1,
		Region:            normalizedRegion,
		AvailabilityZones: normalizedZones,
		Shapes:            normalizedShapes,
	})
	if err != nil {
		return teamComputeConfigurationBinding{}, err
	}
	return teamComputeConfigurationBinding{
		SourceID: "agent-team-compute-catalog:" + normalizedRegion + ":v1",
		Digest:   digest,
	}, nil
}

type teamComputePriceEvidence struct {
	SchemaVersion string                        `json:"schema_version"`
	ProviderScope teamplan.ProviderScope        `json:"provider_scope"`
	Region        string                        `json:"region"`
	Currency      string                        `json:"currency"`
	CapturedAt    time.Time                     `json:"captured_at"`
	Offers        []teamComputePriceObservation `json:"offers"`
}

type teamComputePriceObservation struct {
	OfferID      string                  `json:"offer_id"`
	InstanceType string                  `json:"instance_type"`
	DiskGiB      uint64                  `json:"disk_gib"`
	HourlyMicros uint64                  `json:"hourly_micros"`
	CostItems    []cloudquote.CostItemV1 `json:"cost_items"`
}

type teamComputeCapacityEvidence struct {
	SchemaVersion string                           `json:"schema_version"`
	ProviderScope teamplan.ProviderScope           `json:"provider_scope"`
	Region        string                           `json:"region"`
	CapturedAt    time.Time                        `json:"captured_at"`
	Offers        []teamComputeCapacityObservation `json:"offers"`
}

type teamComputeCapacityObservation struct {
	OfferID           string                     `json:"offer_id"`
	InstanceType      string                     `json:"instance_type"`
	Architecture      recipe.Architecture        `json:"architecture"`
	VCPU              uint32                     `json:"vcpu"`
	MemoryMiB         uint64                     `json:"memory_mib"`
	AvailabilityZones []string                   `json:"availability_zones"`
	Quota             cloudquote.QuotaEvidenceV1 `json:"quota"`
	CapacityPool      string                     `json:"capacity_pool"`
	CapacityUnits     uint64                     `json:"capacity_units"`
	AvailableUnits    uint64                     `json:"available_units"`
}

func compareTeamComputeShapes(left, right TeamComputeShape) int {
	if left.InstanceType != right.InstanceType {
		return strings.Compare(left.InstanceType, right.InstanceType)
	}
	if left.Architecture != right.Architecture {
		return strings.Compare(string(left.Architecture), string(right.Architecture))
	}
	switch {
	case left.DiskGiB < right.DiskGiB:
		return -1
	case left.DiskGiB > right.DiskGiB:
		return 1
	default:
		return 0
	}
}

func compareCostItems(left, right cloudquote.CostItemV1) int {
	if left.Category != right.Category {
		return strings.Compare(string(left.Category), string(right.Category))
	}
	return strings.Compare(left.SourceID, right.SourceID)
}

func teamComputeOfferID(region string, shape TeamComputeShape) string {
	return uuid.NewSHA1(
		uuid.NameSpaceURL,
		[]byte(
			"dirextalk.agent.team-compute-offer/v1\x00"+
				region+"\x00"+
				shape.InstanceType+"\x00"+
				string(shape.Architecture)+"\x00"+
				fmt.Sprint(shape.DiskGiB),
		),
	).String()
}

var _ teampricing.ComputeOfferPort = (*TeamComputePricingProvider)(nil)
