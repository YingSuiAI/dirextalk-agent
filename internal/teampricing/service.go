package teampricing

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

var (
	ErrInvalidSnapshotRequest         = errors.New("invalid team pricing snapshot request")
	ErrPricingEvidenceExpired         = errors.New("team pricing evidence expired")
	ErrComputeEvidenceUnavailable     = errors.New("team compute pricing evidence unavailable")
	ErrCredentialReadinessUnavailable = errors.New("team model credential readiness unavailable")
	regionPattern                     = regexp.MustCompile(
		`^[a-z]{2}(?:-gov)?-[a-z]+-\d+$`,
	)
)

// CredentialReadinessPort performs an existence/readiness check only. Its
// contract has no method that can return credential bytes.
type CredentialReadinessPort interface {
	Ready(context.Context, string) (bool, error)
}

// ComputeEvidence contains only read-only public AWS price, instance-shape,
// quota, and availability evidence.
type ComputeEvidence struct {
	ProviderScope teamplan.ProviderScope
	Region        string
	Currency      string
	Sources       []teamplan.OfferSourceReceipt
	Offers        []teamplan.ComputeOffer
}

type ComputeOfferPort interface {
	ReadComputeOffers(
		context.Context,
		teamplan.ProviderScope,
		string,
	) (ComputeEvidence, error)
}

type SnapshotService struct {
	models      *ModelOfferCatalog
	credentials CredentialReadinessPort
	compute     ComputeOfferPort
	now         func() time.Time
	newID       func() (string, error)
}

func NewSnapshotService(
	models *ModelOfferCatalog,
	credentials CredentialReadinessPort,
	compute ComputeOfferPort,
) (*SnapshotService, error) {
	return newSnapshotService(
		models,
		credentials,
		compute,
		time.Now,
		func() (string, error) {
			value, err := uuid.NewV7()
			return value.String(), err
		},
	)
}

func newSnapshotService(
	models *ModelOfferCatalog,
	credentials CredentialReadinessPort,
	compute ComputeOfferPort,
	now func() time.Time,
	newID func() (string, error),
) (*SnapshotService, error) {
	if models == nil || credentials == nil || compute == nil ||
		now == nil || newID == nil {
		return nil, ErrInvalidSnapshotRequest
	}
	return &SnapshotService{
		models:      models,
		credentials: credentials,
		compute:     compute,
		now:         now,
		newID:       newID,
	}, nil
}

// Build obtains fresh compute evidence and credential readiness, then freezes
// them with model pricing into one content-addressed Offer Snapshot.
func (service *SnapshotService) Build(
	ctx context.Context,
	scope teamplan.ProviderScope,
	region string,
) (*teamplan.OfferSnapshot, error) {
	if service == nil || ctx == nil ||
		scope.Validate() != nil ||
		strings.TrimSpace(region) != region ||
		!regionPattern.MatchString(region) {
		return nil, ErrInvalidSnapshotRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	capturedAt := service.now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() {
		return nil, ErrInvalidSnapshotRequest
	}

	compute, err := service.compute.ReadComputeOffers(ctx, scope, region)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrComputeEvidenceUnavailable
	}
	if compute.Currency != service.models.Currency() {
		return nil, ErrInvalidSnapshotRequest
	}
	if err := validateComputeEvidence(compute, scope, region); err != nil {
		return nil, err
	}

	modelOffers := make([]teamplan.ModelOffer, 0, len(service.models.offers))
	for _, configured := range service.models.catalogOffers() {
		offer := configured.offer
		if offer.Enabled {
			offer.CredentialReady, err = service.credentials.Ready(
				ctx,
				offer.CredentialRef,
			)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, ErrCredentialReadinessUnavailable
			}
		}
		modelOffers = append(modelOffers, offer)
	}

	sources := append(service.models.sourceReceipts(), compute.Sources...)
	validUntil := capturedAt.Add(teamplan.OfferSnapshotValidity)
	for _, source := range sources {
		validity := teamplan.OfferSnapshotValidity
		if source.Kind == teamplan.OfferSourceModelPricing {
			validity = teamplan.ModelPricingEvidenceValidity
		}
		sourceExpiry := source.CapturedAt.Add(validity)
		if sourceExpiry.Before(validUntil) {
			validUntil = sourceExpiry
		}
	}
	if !capturedAt.Before(validUntil) {
		return nil, ErrPricingEvidenceExpired
	}

	snapshotID, err := service.newID()
	if err != nil {
		return nil, ErrInvalidSnapshotRequest
	}
	return teamplan.NewOfferSnapshot(teamplan.OfferSnapshotDocument{
		SchemaVersion: teamplan.OfferSnapshotSchemaV1,
		SnapshotID:    snapshotID,
		ProviderScope: scope,
		Region:        region,
		Currency:      compute.Currency,
		CapturedAt:    capturedAt,
		ValidUntil:    validUntil,
		Sources:       sources,
		ModelOffers:   modelOffers,
		ComputeOffers: compute.Offers,
	})
}

func validateComputeEvidence(
	evidence ComputeEvidence,
	scope teamplan.ProviderScope,
	region string,
) error {
	if !currencyPattern.MatchString(evidence.Currency) ||
		evidence.ProviderScope != scope ||
		evidence.Region != region ||
		len(evidence.Sources) != 3 ||
		len(evidence.Offers) == 0 ||
		len(evidence.Offers) > 128 {
		return ErrInvalidSnapshotRequest
	}
	sources := append([]teamplan.OfferSourceReceipt(nil), evidence.Sources...)
	slices.SortFunc(sources, compareSources)
	if sources[0].Kind != teamplan.OfferSourceComputeCapacity ||
		sources[1].Kind != teamplan.OfferSourceComputeConfig ||
		sources[2].Kind != teamplan.OfferSourceComputePricing ||
		sources[0].SourceID == sources[1].SourceID ||
		sources[0].SourceID == sources[2].SourceID ||
		sources[1].SourceID == sources[2].SourceID {
		return ErrInvalidSnapshotRequest
	}
	for _, offer := range evidence.Offers {
		if offer.Region != region {
			return ErrInvalidSnapshotRequest
		}
	}
	return nil
}
