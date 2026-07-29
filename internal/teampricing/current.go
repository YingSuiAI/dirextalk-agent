package teampricing

import (
	"context"
	"slices"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

// VerifyCurrentModels compares a frozen Snapshot with the current protected
// model offer catalog and mounted credential readiness. It returns a requote
// error for any catalog, pricing-source, or readiness drift.
func (catalog *ModelOfferCatalog) VerifyCurrentModels(
	ctx context.Context,
	snapshot *teamplan.OfferSnapshot,
	credentials CredentialReadinessPort,
) error {
	if catalog == nil || ctx == nil || snapshot == nil ||
		credentials == nil {
		return ErrInvalidSnapshotRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	document := snapshot.Document()
	if document.Currency != catalog.Currency() {
		return teamplan.ErrPricingChanged
	}
	actualSources := make([]teamplan.OfferSourceReceipt, 0)
	for _, source := range document.Sources {
		if source.Kind == teamplan.OfferSourceModelPricing {
			actualSources = append(actualSources, source)
		}
	}
	expectedSources := catalog.sourceReceipts()
	if !slices.Equal(actualSources, expectedSources) {
		return teamplan.ErrPricingChanged
	}

	expectedOffers := make([]teamplan.ModelOffer, 0, len(catalog.offers))
	for _, configured := range catalog.catalogOffers() {
		offer := configured.offer
		if offer.Enabled {
			ready, err := credentials.Ready(
				ctx,
				offer.CredentialRef,
			)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return ErrCredentialReadinessUnavailable
			}
			offer.CredentialReady = ready
		}
		expectedOffers = append(expectedOffers, offer)
	}
	if !slices.Equal(document.ModelOffers, expectedOffers) {
		return teamplan.ErrPricingChanged
	}
	return nil
}
