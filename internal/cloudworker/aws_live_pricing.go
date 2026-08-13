package cloudworker

import (
	"context"
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
)

// AWSPriceListAPI is deliberately read-only. A quote cannot cross an AWS
// mutation boundary.
type AWSPriceListAPI interface {
	GetProducts(context.Context, *pricing.GetProductsInput, ...func(*pricing.Options)) (*pricing.GetProductsOutput, error)
}

type AWSPriceListFactory interface {
	New(workaws.CredentialHandle) (AWSPriceListAPI, error)
}

type SDKAWSPriceListFactory struct{}

func (SDKAWSPriceListFactory) New(credential workaws.CredentialHandle) (AWSPriceListAPI, error) {
	if credential.Validate() != nil {
		return nil, ErrStaleAuthorization
	}
	config := aws.Config{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken,
		),
		Retryer: func() aws.Retryer { return aws.NopRetryer{} },
	}
	return pricing.NewFromConfig(config), nil
}

// AWSLivePricingCatalog performs a new AWS Price List query for every
// proposal and requote. It holds no price catalog or cross-request cache.
type AWSLivePricingCatalog struct {
	credentials workaws.ExactCredentialResolver
	factory     AWSPriceListFactory
	now         func() time.Time
	ttl         time.Duration
}

func NewAWSLivePricingCatalog(credentials workaws.ExactCredentialResolver, factory AWSPriceListFactory, ttl time.Duration, clocks ...func() time.Time) (*AWSLivePricingCatalog, error) {
	if credentials == nil || factory == nil || ttl <= 0 || ttl > 15*time.Minute {
		return nil, ErrInvalid
	}
	now := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		now = clocks[0]
	}
	return &AWSLivePricingCatalog{credentials: credentials, factory: factory, now: now, ttl: ttl}, nil
}

func (catalog *AWSLivePricingCatalog) Snapshot(ctx context.Context, request PricingCatalogRequest) (PricingCatalogSnapshot, error) {
	if catalog == nil || ctx == nil || request.CredentialRevision == 0 || request.CredentialID == "" ||
		request.Region == "" || request.InstanceType == "" || request.VolumeGiB == 0 {
		return PricingCatalogSnapshot{}, ErrInvalid
	}
	credential, err := catalog.credentials.ResolveCredentialRevision(ctx, request.CredentialID, request.CredentialRevision)
	if err != nil || credential.Validate() != nil || credential.ReferenceID != request.CredentialID ||
		credential.Region != request.Region || credential.AccountID != request.AccountID {
		return PricingCatalogSnapshot{}, ErrStaleAuthorization
	}
	client, err := catalog.factory.New(credential)
	if err != nil || client == nil {
		return PricingCatalogSnapshot{}, ErrProviderUnavailable
	}
	compute, err := liveAWSPriceMicros(ctx, client, "AmazonEC2", map[string]string{
		"instanceType": request.InstanceType, "operatingSystem": "Linux", "tenancy": "Shared",
		"preInstalledSw": "NA", "capacitystatus": "Used", "regionCode": request.Region,
	}, "Hrs")
	if err != nil {
		return PricingCatalogSnapshot{}, err
	}
	storage, err := liveAWSPriceMicros(ctx, client, "AmazonEC2", map[string]string{
		"volumeApiName": "gp3", "productFamily": "Storage", "regionCode": request.Region,
	}, "GB-Mo")
	if err != nil {
		return PricingCatalogSnapshot{}, err
	}
	publicIPv4, err := liveAWSPriceMicros(ctx, client, "AmazonVPC", map[string]string{
		"group": "VPCPublicIPv4Address", "groupDescription": "Hourly charge for In-use Public IPv4 Addresses", "regionCode": request.Region,
	}, "Hrs")
	if err != nil {
		return PricingCatalogSnapshot{}, err
	}
	now := catalog.now().UTC()
	return SealPricingCatalogSnapshot(PricingCatalogSnapshot{
		RequestDigest: request.digest(), SourceTime: now, ExpiresAt: now.Add(catalog.ttl),
		Rates: PricingCatalogRates{ComputeMicrosPerHour: compute, EBSStorageMicrosPerGiBMonth: storage, PublicIPv4MicrosPerHour: publicIPv4},
	})
}

type awsPriceDocument struct {
	Product struct {
		ProductFamily string            `json:"productFamily"`
		Attributes    map[string]string `json:"attributes"`
	} `json:"product"`
	Terms struct {
		OnDemand map[string]struct {
			PriceDimensions map[string]struct {
				Unit         string            `json:"unit"`
				PricePerUnit map[string]string `json:"pricePerUnit"`
			} `json:"priceDimensions"`
		} `json:"OnDemand"`
	} `json:"terms"`
}

func liveAWSPriceMicros(ctx context.Context, client AWSPriceListAPI, serviceCode string, attributes map[string]string, unit string) (uint64, error) {
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	filters := make([]pricingtypes.Filter, 0, len(keys))
	for _, key := range keys {
		filters = append(filters, pricingtypes.Filter{Field: aws.String(key), Type: pricingtypes.FilterTypeTermMatch, Value: aws.String(attributes[key])})
	}
	output, err := client.GetProducts(ctx, &pricing.GetProductsInput{
		ServiceCode: aws.String(serviceCode), Filters: filters, FormatVersion: aws.String("aws_v1"), MaxResults: aws.Int32(100),
	})
	if err != nil || output == nil || strings.TrimSpace(aws.ToString(output.NextToken)) != "" {
		return 0, ErrProviderUnavailable
	}
	prices := map[string]*big.Rat{}
	for _, raw := range output.PriceList {
		var document awsPriceDocument
		if json.Unmarshal([]byte(raw), &document) != nil {
			return 0, ErrProviderUnavailable
		}
		for key, expected := range attributes {
			actual := document.Product.Attributes[key]
			if key == "productFamily" {
				actual = document.Product.ProductFamily
			}
			if actual != expected {
				return 0, ErrProviderUnavailable
			}
		}
		for _, term := range document.Terms.OnDemand {
			for _, dimension := range term.PriceDimensions {
				if dimension.Unit != unit {
					continue
				}
				price, ok := new(big.Rat).SetString(strings.TrimSpace(dimension.PricePerUnit["USD"]))
				if !ok || price.Sign() <= 0 {
					return 0, ErrProviderUnavailable
				}
				prices[price.RatString()] = price
			}
		}
	}
	if len(prices) != 1 {
		return 0, ErrProviderUnavailable
	}
	for _, price := range prices {
		price.Mul(price, big.NewRat(1_000_000, 1))
		quotient := new(big.Int).Quo(price.Num(), price.Denom())
		if new(big.Int).Mod(price.Num(), price.Denom()).Sign() != 0 {
			quotient.Add(quotient, big.NewInt(1))
		}
		if !quotient.IsUint64() || quotient.Uint64() == 0 || quotient.Uint64() > math.MaxInt64 {
			return 0, ErrProviderUnavailable
		}
		return quotient.Uint64(), nil
	}
	return 0, ErrProviderUnavailable
}

var _ PricingCatalog = (*AWSLivePricingCatalog)(nil)
