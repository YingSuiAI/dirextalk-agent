package teampricing

import (
	"context"
	"errors"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

// CatalogCredentialReadiness maps a logical Worker credential reference to
// the mounted Central Agent source credential selected by the same immutable
// model Profile. It returns readiness only and clears resolved bytes before
// returning.
type CatalogCredentialReadiness struct {
	sources  map[string]string
	resolver modelapi.SecretResolver
}

func NewCatalogCredentialReadiness(
	catalog *ModelOfferCatalog,
	resolver modelapi.SecretResolver,
) (*CatalogCredentialReadiness, error) {
	if catalog == nil || resolver == nil || len(catalog.offers) == 0 {
		return nil, ErrCredentialReadinessUnavailable
	}
	sources := make(map[string]string, len(catalog.offers))
	for _, configured := range catalog.catalogOffers() {
		workerRef := strings.TrimSpace(configured.offer.CredentialRef)
		sourceRef := strings.TrimSpace(configured.sourceCredentialRef)
		if !credentialRefPattern.MatchString(workerRef) ||
			sourceRef == "" {
			return nil, ErrCredentialReadinessUnavailable
		}
		if existing, duplicate := sources[workerRef]; duplicate && existing != sourceRef {
			return nil, ErrCredentialReadinessUnavailable
		}
		sources[workerRef] = sourceRef
	}
	return &CatalogCredentialReadiness{
		sources:  sources,
		resolver: resolver,
	}, nil
}

func (readiness *CatalogCredentialReadiness) Ready(
	ctx context.Context,
	workerCredentialRef string,
) (bool, error) {
	if readiness == nil || readiness.resolver == nil || ctx == nil {
		return false, ErrCredentialReadinessUnavailable
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	sourceRef, ok := readiness.sources[workerCredentialRef]
	if !ok {
		return false, nil
	}
	secret, err := readiness.resolver.ResolveSecret(ctx, sourceRef)
	if err != nil {
		clear(secret)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if errors.Is(err, modelapi.ErrSecretUnavailable) {
			return false, nil
		}
		return false, ErrCredentialReadinessUnavailable
	}
	ready := len(secret) != 0
	clear(secret)
	return ready, nil
}

var _ CredentialReadinessPort = (*CatalogCredentialReadiness)(nil)
