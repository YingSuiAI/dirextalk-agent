// Package teampricing assembles trusted, short-lived pricing evidence for
// multi-Worker Team Plans. It never receives model output or secret bytes.
package teampricing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const (
	ModelOfferCatalogSchemaV1 = "dirextalk.agent.model-offer-catalog/v1"
	maximumModelCatalogSize   = int64(1 << 20)
	maximumModelSources       = 6
)

var (
	ErrInvalidModelCatalog = errors.New("invalid model offer catalog")
	currencyPattern        = regexp.MustCompile(`^[A-Z]{3}$`)
	sourceIDPattern        = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`,
	)
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	credentialRefPattern = regexp.MustCompile(
		`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`,
	)
)

// ModelPriceSource identifies public pricing evidence captured by an operator
// process. Digest is the SHA-256 receipt for that evidence, not a credential.
type ModelPriceSource struct {
	SourceID   string    `json:"source_id"`
	Digest     string    `json:"digest"`
	CapturedAt time.Time `json:"captured_at"`
}

// ModelOfferEntry augments an immutable model Profile with Worker-facing
// capability, pricing, and a deployment-scoped credential reference.
type ModelOfferEntry struct {
	ProfileID              string                  `json:"profile_id"`
	WorkerProvider         string                  `json:"worker_provider"`
	Interface              teamplan.ModelInterface `json:"interface"`
	Quality                teamplan.QualityTier    `json:"quality"`
	Vision                 bool                    `json:"vision"`
	InputMicrosPerMillion  uint64                  `json:"input_micros_per_million"`
	OutputMicrosPerMillion uint64                  `json:"output_micros_per_million"`
	WorkerCredentialRef    string                  `json:"worker_credential_ref"`
	Enabled                bool                    `json:"enabled"`
	SourceID               string                  `json:"source_id"`
}

type ModelOfferCatalogDocument struct {
	SchemaVersion string             `json:"schema_version"`
	Currency      string             `json:"currency"`
	Sources       []ModelPriceSource `json:"sources"`
	Offers        []ModelOfferEntry  `json:"offers"`
}

type catalogOffer struct {
	offer               teamplan.ModelOffer
	sourceCredentialRef string
}

// ModelOfferCatalog is immutable after construction.
type ModelOfferCatalog struct {
	currency string
	sources  []teamplan.OfferSourceReceipt
	offers   []catalogOffer
}

// LoadModelOfferCatalog opens trusted metadata with no-follow semantics and
// rejects group/world-writable files before parsing strict JSON.
func LoadModelOfferCatalog(
	path string,
	profiles *modelapi.ProfileCatalog,
) (*ModelOfferCatalog, error) {
	raw, err := readProtectedCatalog(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ModelOfferCatalogDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode", ErrInvalidModelCatalog)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON value", ErrInvalidModelCatalog)
	}
	return NewModelOfferCatalog(document, profiles)
}

// NewModelOfferCatalog is the explicit construction seam for tests and
// operator tooling. Runtime startup should use LoadModelOfferCatalog.
func NewModelOfferCatalog(
	document ModelOfferCatalogDocument,
	profiles *modelapi.ProfileCatalog,
) (*ModelOfferCatalog, error) {
	if profiles == nil ||
		document.SchemaVersion != ModelOfferCatalogSchemaV1 ||
		!currencyPattern.MatchString(document.Currency) ||
		len(document.Sources) == 0 ||
		len(document.Sources) > maximumModelSources ||
		len(document.Offers) == 0 ||
		len(document.Offers) > 64 {
		return nil, ErrInvalidModelCatalog
	}

	sources := make(map[string]teamplan.OfferSourceReceipt, len(document.Sources))
	for _, source := range document.Sources {
		source.SourceID = strings.TrimSpace(source.SourceID)
		if !sourceIDPattern.MatchString(source.SourceID) ||
			security.ContainsLikelySecret(source.SourceID) ||
			!digestPattern.MatchString(source.Digest) ||
			!canonicalTime(source.CapturedAt) {
			return nil, ErrInvalidModelCatalog
		}
		if _, exists := sources[source.SourceID]; exists {
			return nil, ErrInvalidModelCatalog
		}
		sources[source.SourceID] = teamplan.OfferSourceReceipt{
			Kind:       teamplan.OfferSourceModelPricing,
			SourceID:   source.SourceID,
			Digest:     source.Digest,
			CapturedAt: source.CapturedAt,
		}
	}

	usedSources := make(map[string]struct{}, len(sources))
	seenProfiles := make(map[string]struct{}, len(document.Offers))
	credentialSources := make(map[string]string, len(document.Offers))
	offers := make([]catalogOffer, 0, len(document.Offers))
	for _, entry := range document.Offers {
		entry.ProfileID = strings.ToLower(strings.TrimSpace(entry.ProfileID))
		entry.WorkerProvider = strings.ToLower(
			strings.TrimSpace(entry.WorkerProvider),
		)
		entry.WorkerCredentialRef = strings.TrimSpace(entry.WorkerCredentialRef)
		entry.SourceID = strings.TrimSpace(entry.SourceID)
		if _, exists := seenProfiles[entry.ProfileID]; exists ||
			!validWorkerProvider(
				entry.WorkerProvider,
				entry.Interface,
				profiles,
				entry.ProfileID,
			) ||
			!credentialRefPattern.MatchString(entry.WorkerCredentialRef) ||
			security.ContainsLikelySecret(entry.WorkerCredentialRef) ||
			entry.InputMicrosPerMillion > 10_000_000_000 ||
			entry.OutputMicrosPerMillion > 10_000_000_000 {
			return nil, ErrInvalidModelCatalog
		}
		if _, exists := sources[entry.SourceID]; !exists {
			return nil, ErrInvalidModelCatalog
		}
		profile, err := profiles.ResolveSelection(modelapi.Profile{
			ProfileID: entry.ProfileID,
		})
		if err != nil || !compatibleInterface(profile.Provider, entry.Interface) ||
			profile.ContextWindow < 1024 {
			return nil, ErrInvalidModelCatalog
		}
		if source, exists := credentialSources[entry.WorkerCredentialRef]; exists && source != profile.SecretRef {
			return nil, ErrInvalidModelCatalog
		}
		if entry.Quality != teamplan.QualityEconomy &&
			entry.Quality != teamplan.QualityBalanced &&
			entry.Quality != teamplan.QualityPremium {
			return nil, ErrInvalidModelCatalog
		}
		offer := teamplan.ModelOffer{
			ProfileID:              profile.ProfileID,
			Provider:               entry.WorkerProvider,
			Model:                  profile.Model,
			Interface:              entry.Interface,
			Quality:                entry.Quality,
			ContextTokens:          uint64(profile.ContextWindow),
			Vision:                 entry.Vision,
			InputMicrosPerMillion:  entry.InputMicrosPerMillion,
			OutputMicrosPerMillion: entry.OutputMicrosPerMillion,
			CredentialRef:          entry.WorkerCredentialRef,
			Enabled:                entry.Enabled,
		}
		for _, value := range []string{
			offer.ProfileID,
			offer.Provider,
			offer.Model,
			offer.CredentialRef,
		} {
			if security.ContainsLikelySecret(value) {
				return nil, ErrInvalidModelCatalog
			}
		}
		seenProfiles[entry.ProfileID] = struct{}{}
		credentialSources[entry.WorkerCredentialRef] = profile.SecretRef
		usedSources[entry.SourceID] = struct{}{}
		offers = append(offers, catalogOffer{
			offer:               offer,
			sourceCredentialRef: profile.SecretRef,
		})
	}
	if len(usedSources) != len(sources) {
		return nil, ErrInvalidModelCatalog
	}

	receipts := make([]teamplan.OfferSourceReceipt, 0, len(sources))
	for _, source := range sources {
		receipts = append(receipts, source)
	}
	slices.SortFunc(receipts, compareSources)
	slices.SortFunc(offers, func(left, right catalogOffer) int {
		return strings.Compare(left.offer.ProfileID, right.offer.ProfileID)
	})
	return &ModelOfferCatalog{
		currency: document.Currency,
		sources:  receipts,
		offers:   offers,
	}, nil
}

func (catalog *ModelOfferCatalog) Currency() string {
	if catalog == nil {
		return ""
	}
	return catalog.currency
}

// Offers returns de-secreted Worker-facing model metadata for release-bundle
// verification. The mounted source credential reference remains private.
func (catalog *ModelOfferCatalog) Offers() []teamplan.ModelOffer {
	if catalog == nil {
		return nil
	}
	result := make([]teamplan.ModelOffer, 0, len(catalog.offers))
	for _, configured := range catalog.offers {
		result = append(result, configured.offer)
	}
	return result
}

func (catalog *ModelOfferCatalog) sourceReceipts() []teamplan.OfferSourceReceipt {
	if catalog == nil {
		return nil
	}
	return append([]teamplan.OfferSourceReceipt(nil), catalog.sources...)
}

func (catalog *ModelOfferCatalog) catalogOffers() []catalogOffer {
	if catalog == nil {
		return nil
	}
	return append([]catalogOffer(nil), catalog.offers...)
}

func compatibleInterface(
	provider modelapi.Provider,
	modelInterface teamplan.ModelInterface,
) bool {
	switch provider {
	case modelapi.ProviderAnthropic:
		return modelInterface == teamplan.ModelAnthropicAPI
	case modelapi.ProviderDeepSeek:
		return modelInterface == teamplan.ModelOpenAICompatible
	case modelapi.ProviderOpenAICompatible:
		return modelInterface == teamplan.ModelOpenAICompatible ||
			modelInterface == teamplan.ModelOpenAIResponses
	default:
		return false
	}
}

func validWorkerProvider(
	workerProvider string,
	modelInterface teamplan.ModelInterface,
	profiles *modelapi.ProfileCatalog,
	profileID string,
) bool {
	if !sourceIDPattern.MatchString(workerProvider) ||
		strings.ContainsAny(workerProvider, "/:") ||
		security.ContainsLikelySecret(workerProvider) {
		return false
	}
	profile, err := profiles.ResolveSelection(modelapi.Profile{
		ProfileID: profileID,
	})
	if err != nil {
		return false
	}
	switch profile.Provider {
	case modelapi.ProviderOpenAICompatible:
		return workerProvider == "openai" &&
			(modelInterface == teamplan.ModelOpenAIResponses ||
				modelInterface == teamplan.ModelOpenAICompatible)
	case modelapi.ProviderDeepSeek:
		return workerProvider == "deepseek" &&
			modelInterface == teamplan.ModelOpenAICompatible
	case modelapi.ProviderAnthropic:
		return workerProvider == "anthropic" &&
			modelInterface == teamplan.ModelAnthropicAPI
	default:
		return false
	}
}

func compareSources(
	left teamplan.OfferSourceReceipt,
	right teamplan.OfferSourceReceipt,
) int {
	if left.Kind != right.Kind {
		return strings.Compare(string(left.Kind), string(right.Kind))
	}
	return strings.Compare(left.SourceID, right.SourceID)
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}

func readProtectedCatalog(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalidModelCatalog
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidModelCatalog
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 ||
		info.Size() > maximumModelCatalogSize {
		return nil, ErrInvalidModelCatalog
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumModelCatalogSize+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInvalidModelCatalog
	}
	return raw, nil
}
