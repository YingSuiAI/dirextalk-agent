package teamplan

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	OfferSnapshotSchemaV1 = "dirextalk.agent.team-offer-snapshot/v1"
	// Plans remain approvable for one day. Provider creation still requires
	// a fresh quote no older than teamlaunch.maximumQuoteAgeSeconds and may
	// never exceed the approved role or Team hard-budget boundaries.
	OfferSnapshotValidity          = 24 * time.Hour
	ComputePricingEvidenceValidity = 15 * time.Minute
	ModelPricingEvidenceValidity   = 7 * 24 * time.Hour
	maximumOfferSources            = 8
)

type OfferSourceKind string

const (
	OfferSourceModelPricing    OfferSourceKind = "model_pricing"
	OfferSourceComputePricing  OfferSourceKind = "compute_pricing"
	OfferSourceComputeCapacity OfferSourceKind = "compute_capacity"
	OfferSourceComputeConfig   OfferSourceKind = "compute_configuration"
)

var offerSourceIDPattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`,
)

type OfferSourceReceipt struct {
	Kind       OfferSourceKind `json:"kind"`
	SourceID   string          `json:"source_id"`
	Digest     string          `json:"digest"`
	CapturedAt time.Time       `json:"captured_at"`
}

type OfferSnapshotDocument struct {
	SchemaVersion string               `json:"schema_version"`
	SnapshotID    string               `json:"snapshot_id"`
	ProviderScope ProviderScope        `json:"provider_scope"`
	Region        string               `json:"region"`
	Currency      string               `json:"currency"`
	CapturedAt    time.Time            `json:"captured_at"`
	ValidUntil    time.Time            `json:"valid_until"`
	Sources       []OfferSourceReceipt `json:"sources"`
	ModelOffers   []ModelOffer         `json:"model_offers"`
	ComputeOffers []ComputeOffer       `json:"compute_offers"`
}

// OfferSnapshot is an immutable, digest-addressed combination of server-owned
// model-pricing metadata and read-only compute price/capacity evidence.
type OfferSnapshot struct {
	document OfferSnapshotDocument
	digest   string
}

func NewOfferSnapshot(
	document OfferSnapshotDocument,
) (*OfferSnapshot, error) {
	normalized, err := normalizeOfferSnapshot(document)
	if err != nil {
		return nil, err
	}
	digest, err := canonical.Digest(normalized)
	if err != nil {
		return nil, ErrInvalid
	}
	return &OfferSnapshot{document: normalized, digest: digest}, nil
}

func (snapshot *OfferSnapshot) SnapshotID() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.document.SnapshotID
}

func (snapshot *OfferSnapshot) Digest() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.digest
}

func (snapshot *OfferSnapshot) CanonicalCBOR() ([]byte, error) {
	if snapshot == nil || snapshot.digest == "" {
		return nil, ErrInvalid
	}
	return canonical.Marshal(snapshot.document)
}

func (snapshot *OfferSnapshot) Region() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.document.Region
}

func (snapshot *OfferSnapshot) ProviderScope() ProviderScope {
	if snapshot == nil {
		return ProviderScope{}
	}
	return snapshot.document.ProviderScope
}

func (snapshot *OfferSnapshot) Currency() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.document.Currency
}

func (snapshot *OfferSnapshot) CapturedAt() time.Time {
	if snapshot == nil {
		return time.Time{}
	}
	return snapshot.document.CapturedAt
}

func (snapshot *OfferSnapshot) ValidUntil() time.Time {
	if snapshot == nil {
		return time.Time{}
	}
	return snapshot.document.ValidUntil
}

func (snapshot *OfferSnapshot) ModelOffers() []ModelOffer {
	if snapshot == nil {
		return nil
	}
	return append([]ModelOffer(nil), snapshot.document.ModelOffers...)
}

func (snapshot *OfferSnapshot) ComputeOffers() []ComputeOffer {
	if snapshot == nil {
		return nil
	}
	return append([]ComputeOffer(nil), snapshot.document.ComputeOffers...)
}

func (snapshot *OfferSnapshot) Document() OfferSnapshotDocument {
	if snapshot == nil {
		return OfferSnapshotDocument{}
	}
	return cloneOfferSnapshotDocument(snapshot.document)
}

func (snapshot *OfferSnapshot) ValidateAt(now time.Time) error {
	if snapshot == nil || snapshot.digest == "" || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	if now.Before(snapshot.document.CapturedAt.Add(-30*time.Second)) ||
		!now.Before(snapshot.document.ValidUntil) {
		return ErrPricingExpired
	}
	return nil
}

// VerifyPlanPricing proves that a signed Plan still resolves to this exact,
// unexpired price/capacity snapshot. Runtime-catalog verification remains a
// separate CatalogCompiler responsibility.
func (snapshot *OfferSnapshot) VerifyPlanPricing(
	plan Plan,
	now time.Time,
) error {
	if snapshot == nil {
		return ErrInvalid
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	if err := snapshot.ValidateAt(now); err != nil {
		return err
	}
	if plan.PricingSnapshotID != snapshot.SnapshotID() ||
		plan.PricingSnapshotDigest != snapshot.Digest() ||
		plan.ProviderScope != snapshot.ProviderScope() ||
		plan.Region != snapshot.Region() ||
		plan.Cost.Currency != snapshot.Currency() ||
		!plan.QuotedAt.Equal(snapshot.CapturedAt()) ||
		!plan.ValidUntil.Equal(snapshot.ValidUntil()) {
		return ErrPricingChanged
	}
	models := make(map[string]ModelOffer, len(snapshot.document.ModelOffers))
	for _, offer := range snapshot.document.ModelOffers {
		models[offer.ProfileID] = offer
	}
	compute := make(
		map[string]ComputeOffer,
		len(snapshot.document.ComputeOffers),
	)
	for _, offer := range snapshot.document.ComputeOffers {
		compute[offer.OfferID] = offer
	}
	computeUsage := make(map[string]uint64, len(compute))
	var fixedOverhead uint64
	for index, assignment := range plan.Assignments {
		model, modelExists := models[assignment.ModelProfileID]
		machine, computeExists := compute[assignment.ComputeOfferID]
		if !modelExists || !model.Enabled || !model.CredentialReady ||
			assignment.ModelProvider != model.Provider ||
			assignment.Model != model.Model ||
			assignment.ModelInterface != model.Interface ||
			assignment.ModelCredentialRef != model.CredentialRef ||
			!computeExists || !machine.Available ||
			assignment.InstanceType != machine.InstanceType ||
			assignment.Resources.Arch != machine.Architecture ||
			assignment.Resources.VCPU != machine.VCPU ||
			assignment.Resources.MemoryMiB != machine.MemoryMiB ||
			assignment.Resources.DiskGiB != machine.DiskGiB {
			return ErrPricingChanged
		}
		computeUsage[machine.CapacityPool] += machine.CapacityUnits
		if computeUsage[machine.CapacityPool] > machine.AvailableUnits {
			return ErrPricingChanged
		}
		calculated, err := estimateRoleCost(
			assignment,
			machine.HourlyMicros,
			model.InputMicrosPerMillion,
			model.OutputMicrosPerMillion,
			0,
		)
		if err != nil {
			return err
		}
		quoted := plan.Cost.Roles[index]
		if quoted.ComputeMinimumMicros != calculated.ComputeMinimumMicros ||
			quoted.ComputeExpectedMicros != calculated.ComputeExpectedMicros ||
			quoted.ComputeMaximumMicros != calculated.ComputeMaximumMicros ||
			quoted.ModelMinimumMicros != calculated.ModelMinimumMicros ||
			quoted.ModelExpectedMicros != calculated.ModelExpectedMicros ||
			quoted.ModelMaximumMicros != calculated.ModelMaximumMicros ||
			quoted.TotalMinimumMicros < calculated.TotalMinimumMicros ||
			quoted.TotalExpectedMicros < calculated.TotalExpectedMicros ||
			quoted.TotalMaximumMicros < calculated.TotalMaximumMicros {
			return ErrPricingChanged
		}
		minimumOverhead := quoted.TotalMinimumMicros -
			calculated.TotalMinimumMicros
		expectedOverhead := quoted.TotalExpectedMicros -
			calculated.TotalExpectedMicros
		maximumOverhead := quoted.TotalMaximumMicros -
			calculated.TotalMaximumMicros
		if minimumOverhead != expectedOverhead ||
			expectedOverhead != maximumOverhead ||
			minimumOverhead > absoluteMaxRateMicros ||
			index > 0 && minimumOverhead != fixedOverhead {
			return ErrPricingChanged
		}
		fixedOverhead = minimumOverhead
	}
	schedule, peak, err := estimateSchedule(
		plan.Assignments,
		plan.MaxConcurrentWorkers,
	)
	if err != nil {
		return err
	}
	if schedule != plan.Schedule ||
		peak != plan.MaxConcurrentWorkers ||
		!slices.Equal(plan.Cost.Assumptions, []string{
			"on_demand_compute",
			"remote_model_token_range",
			"workers_start_when_roles_are_ready",
		}) ||
		!slices.Equal(plan.Cost.Exclusions, []string{
			"excess_network_egress",
			"third_party_paid_tools",
			"unapproved_retries",
		}) {
		return ErrPricingChanged
	}
	maximumHardBudget, err := checkedMul(
		plan.Cost.MaximumMicros,
		15_000,
	)
	if err != nil {
		return err
	}
	maximumHardBudget = ceilDiv(maximumHardBudget, 10_000)
	if plan.Cost.HardBudgetMicros > maximumHardBudget {
		return ErrPricingChanged
	}
	return nil
}

func normalizeOfferSnapshot(
	document OfferSnapshotDocument,
) (OfferSnapshotDocument, error) {
	document = cloneOfferSnapshotDocument(document)
	if document.SchemaVersion != OfferSnapshotSchemaV1 ||
		!canonicalUUID(document.SnapshotID) ||
		validateProviderScope(document.ProviderScope) != nil ||
		!regionPattern.MatchString(document.Region) ||
		!currencyPattern.MatchString(document.Currency) ||
		!utcTimestamp(document.CapturedAt) ||
		!utcTimestamp(document.ValidUntil) ||
		!document.CapturedAt.Before(document.ValidUntil) ||
		document.ValidUntil.Sub(document.CapturedAt) > OfferSnapshotValidity ||
		len(document.Sources) < 3 ||
		len(document.Sources) > maximumOfferSources ||
		len(document.ModelOffers) == 0 ||
		len(document.ModelOffers) > 64 ||
		len(document.ComputeOffers) == 0 ||
		len(document.ComputeOffers) > 128 {
		return OfferSnapshotDocument{}, ErrInvalid
	}
	requiredSources := map[OfferSourceKind]bool{
		OfferSourceModelPricing:    false,
		OfferSourceComputePricing:  false,
		OfferSourceComputeCapacity: false,
		OfferSourceComputeConfig:   false,
	}
	sourceKeys := make(map[string]struct{}, len(document.Sources))
	for _, source := range document.Sources {
		if _, known := requiredSources[source.Kind]; !known ||
			!offerSourceIDPattern.MatchString(source.SourceID) ||
			security.ContainsLikelySecret(source.SourceID) ||
			!sha256Pattern.MatchString(source.Digest) ||
			!utcTimestamp(source.CapturedAt) ||
			source.CapturedAt.After(document.CapturedAt) {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		maximumAge := ComputePricingEvidenceValidity
		if source.Kind == OfferSourceModelPricing {
			maximumAge = ModelPricingEvidenceValidity
		}
		if document.CapturedAt.Sub(source.CapturedAt) > maximumAge {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		key := string(source.Kind) + "\x00" + source.SourceID
		if _, exists := sourceKeys[key]; exists {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		sourceKeys[key] = struct{}{}
		requiredSources[source.Kind] = true
	}
	for _, present := range requiredSources {
		if !present {
			return OfferSnapshotDocument{}, ErrInvalid
		}
	}
	modelIDs := make(map[string]struct{}, len(document.ModelOffers))
	for _, offer := range document.ModelOffers {
		if validateModelOffer(offer) != nil {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		if _, exists := modelIDs[offer.ProfileID]; exists {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		modelIDs[offer.ProfileID] = struct{}{}
	}
	computeIDs := make(map[string]struct{}, len(document.ComputeOffers))
	capacityPools := make(map[string]uint64, len(document.ComputeOffers))
	for _, offer := range document.ComputeOffers {
		if validateComputeOffer(offer) != nil ||
			offer.Region != document.Region {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		if _, exists := computeIDs[offer.OfferID]; exists {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		computeIDs[offer.OfferID] = struct{}{}
		if available, exists := capacityPools[offer.CapacityPool]; exists &&
			available != offer.AvailableUnits {
			return OfferSnapshotDocument{}, ErrInvalid
		}
		capacityPools[offer.CapacityPool] = offer.AvailableUnits
	}
	slices.SortFunc(document.Sources, func(left, right OfferSourceReceipt) int {
		if left.Kind != right.Kind {
			return strings.Compare(string(left.Kind), string(right.Kind))
		}
		return strings.Compare(left.SourceID, right.SourceID)
	})
	slices.SortFunc(document.ModelOffers, func(left, right ModelOffer) int {
		return strings.Compare(left.ProfileID, right.ProfileID)
	})
	slices.SortFunc(document.ComputeOffers, func(left, right ComputeOffer) int {
		return strings.Compare(left.OfferID, right.OfferID)
	})
	return document, nil
}

func cloneOfferSnapshotDocument(
	document OfferSnapshotDocument,
) OfferSnapshotDocument {
	document.Sources = append([]OfferSourceReceipt(nil), document.Sources...)
	document.ModelOffers = append([]ModelOffer(nil), document.ModelOffers...)
	document.ComputeOffers = append([]ComputeOffer(nil), document.ComputeOffers...)
	return document
}
