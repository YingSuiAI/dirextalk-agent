package awsprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
)

type rateSpec struct {
	serviceCode string
	filters     map[string]string
	unit        string
}

type catalogRate struct {
	unitMicros uint64
	sourceID   string
}

type priceCatalog struct {
	client PriceListReadAPI
	cache  map[string]catalogRate
}

func newPriceCatalog(client PriceListReadAPI) *priceCatalog {
	return &priceCatalog{client: client, cache: make(map[string]catalogRate)}
}

func (catalog *priceCatalog) rate(ctx context.Context, spec rateSpec) (catalogRate, error) {
	key := rateSpecKey(spec)
	if value, ok := catalog.cache[key]; ok {
		return value, nil
	}
	filters := make([]pricingtypes.Filter, 0, len(spec.filters))
	names := make([]string, 0, len(spec.filters))
	for name := range spec.filters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		filters = append(filters, pricingtypes.Filter{Field: aws.String(name), Type: pricingtypes.FilterTypeTermMatch, Value: aws.String(spec.filters[name])})
	}
	input := &pricing.GetProductsInput{
		ServiceCode: aws.String(spec.serviceCode), FormatVersion: aws.String("aws_v1"), Filters: filters, MaxResults: aws.Int32(100),
	}
	var selected *catalogRate
	for page := 0; page < 100; page++ {
		output, err := catalog.client.GetProducts(ctx, input)
		if err != nil {
			return catalogRate{}, fmt.Errorf("AWS Price List GetProducts: %w", err)
		}
		for _, document := range output.PriceList {
			rates, err := parseCatalogDocument(document, spec.unit)
			if err != nil {
				return catalogRate{}, fmt.Errorf("AWS price list document: %w", err)
			}
			for _, value := range rates {
				if selected == nil || value.unitMicros > selected.unitMicros || (value.unitMicros == selected.unitMicros && value.sourceID < selected.sourceID) {
					candidate := value
					selected = &candidate
				}
			}
		}
		if aws.ToString(output.NextToken) == "" {
			break
		}
		input.NextToken = output.NextToken
		if page == 99 {
			return catalogRate{}, errors.New("AWS price list pagination limit exceeded")
		}
	}
	if selected == nil {
		return catalogRate{}, fmt.Errorf("AWS price list has no USD %s first-tier rate", spec.unit)
	}
	catalog.cache[key] = *selected
	return *selected, nil
}

func rateSpecKey(spec rateSpec) string {
	keys := make([]string, 0, len(spec.filters))
	for key := range spec.filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	result.WriteString(spec.serviceCode)
	result.WriteByte('|')
	result.WriteString(spec.unit)
	for _, key := range keys {
		result.WriteByte('|')
		result.WriteString(key)
		result.WriteByte('=')
		result.WriteString(spec.filters[key])
	}
	return result.String()
}

type priceListDocument struct {
	Product struct {
		SKU string `json:"sku"`
	} `json:"product"`
	Terms struct {
		OnDemand map[string]struct {
			PriceDimensions map[string]struct {
				Unit         string            `json:"unit"`
				BeginRange   string            `json:"beginRange"`
				PricePerUnit map[string]string `json:"pricePerUnit"`
			} `json:"priceDimensions"`
		} `json:"OnDemand"`
	} `json:"terms"`
}

func parseCatalogDocument(raw, wantedUnit string) ([]catalogRate, error) {
	var document priceListDocument
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil, err
	}
	if document.Product.SKU == "" || len(document.Terms.OnDemand) == 0 {
		return nil, errors.New("product SKU or OnDemand terms are missing")
	}
	termCodes := make([]string, 0, len(document.Terms.OnDemand))
	for termCode := range document.Terms.OnDemand {
		termCodes = append(termCodes, termCode)
	}
	sort.Strings(termCodes)
	result := make([]catalogRate, 0)
	for _, termCode := range termCodes {
		term := document.Terms.OnDemand[termCode]
		dimensionCodes := make([]string, 0, len(term.PriceDimensions))
		for dimensionCode := range term.PriceDimensions {
			dimensionCodes = append(dimensionCodes, dimensionCode)
		}
		sort.Strings(dimensionCodes)
		for _, dimensionCode := range dimensionCodes {
			dimension := term.PriceDimensions[dimensionCode]
			if !strings.EqualFold(strings.TrimSpace(dimension.Unit), wantedUnit) || !decimalZero(dimension.BeginRange) {
				continue
			}
			price, exists := dimension.PricePerUnit["USD"]
			if !exists {
				continue
			}
			micros, err := decimalMicros(price)
			if err != nil {
				return nil, fmt.Errorf("invalid USD decimal: %w", err)
			}
			result = append(result, catalogRate{unitMicros: micros, sourceID: sourceIdentifier("awspl", document.Product.SKU, termCode, dimensionCode)})
		}
	}
	return result, nil
}

func decimalZero(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	for _, character := range value {
		if character != '0' && character != '.' {
			return false
		}
	}
	return true
}

func sourceIdentifier(parts ...string) string {
	raw := strings.Join(parts, ":")
	var sanitized strings.Builder
	for _, character := range raw {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || strings.ContainsRune("._:-", character) {
			sanitized.WriteRune(character)
		} else {
			sanitized.WriteByte('_')
		}
	}
	value := strings.TrimLeftFunc(sanitized.String(), func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character)
	})
	if value == "" {
		value = "aws-price"
	}
	if len(value) <= 128 {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return value[:103] + ":sha256:" + hex.EncodeToString(digest[:8])
}
