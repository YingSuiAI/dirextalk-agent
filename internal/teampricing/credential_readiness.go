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
	sources    map[string]string
	selections map[string]credentialSelection
	resolver   modelapi.SecretResolver
}

type credentialSelection struct {
	workerCredentialRef string
	sourceCredentialRef string
	provider            string
	model               string
	modelInterface      string
}

// CredentialMaterializationRequest binds secret access to the same immutable
// catalog selection that was priced and approved for the Worker role.
type CredentialMaterializationRequest struct {
	ProfileID           string
	Provider            string
	Model               string
	ModelInterface      string
	WorkerCredentialRef string
}

func NewCatalogCredentialReadiness(
	catalog *ModelOfferCatalog,
	resolver modelapi.SecretResolver,
) (*CatalogCredentialReadiness, error) {
	if catalog == nil || resolver == nil || len(catalog.offers) == 0 {
		return nil, ErrCredentialReadinessUnavailable
	}
	sources := make(map[string]string, len(catalog.offers))
	selections := make(map[string]credentialSelection, len(catalog.offers))
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
		selections[configured.offer.ProfileID] = credentialSelection{
			workerCredentialRef: workerRef,
			sourceCredentialRef: sourceRef,
			provider:            configured.offer.Provider,
			model:               configured.offer.Model,
			modelInterface:      string(configured.offer.Interface),
		}
	}
	return &CatalogCredentialReadiness{
		sources:    sources,
		selections: selections,
		resolver:   resolver,
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

// Materialize resolves the mounted source only inside a caller-supplied write
// callback. The returned buffer is always cleared before this method returns.
func (readiness *CatalogCredentialReadiness) Materialize(
	ctx context.Context,
	request CredentialMaterializationRequest,
	write func([]byte) error,
) error {
	if readiness == nil || readiness.resolver == nil ||
		ctx == nil || write == nil {
		return ErrCredentialReadinessUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	expected, err := readiness.validateMaterializationRequest(request)
	if err != nil {
		return ErrCredentialReadinessUnavailable
	}
	secret, err := readiness.resolver.ResolveSecret(
		ctx,
		expected.sourceCredentialRef,
	)
	if err != nil || len(secret) == 0 {
		clear(secret)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrCredentialReadinessUnavailable
	}
	defer clear(secret)
	if err := write(secret); err != nil {
		return err
	}
	return nil
}

// ValidateMaterializationRequest checks immutable catalog binding without
// reading the mounted secret.
func (readiness *CatalogCredentialReadiness) ValidateMaterializationRequest(
	request CredentialMaterializationRequest,
) error {
	if readiness == nil || readiness.resolver == nil {
		return ErrCredentialReadinessUnavailable
	}
	_, err := readiness.validateMaterializationRequest(request)
	return err
}

func (readiness *CatalogCredentialReadiness) validateMaterializationRequest(
	request CredentialMaterializationRequest,
) (credentialSelection, error) {
	expected, ok := readiness.selections[strings.ToLower(strings.TrimSpace(request.ProfileID))]
	if !ok ||
		strings.TrimSpace(request.Provider) != expected.provider ||
		strings.TrimSpace(request.Model) != expected.model ||
		strings.TrimSpace(request.ModelInterface) !=
			expected.modelInterface ||
		strings.TrimSpace(request.WorkerCredentialRef) !=
			expected.workerCredentialRef {
		return credentialSelection{}, ErrCredentialReadinessUnavailable
	}
	return expected, nil
}

var _ CredentialReadinessPort = (*CatalogCredentialReadiness)(nil)
