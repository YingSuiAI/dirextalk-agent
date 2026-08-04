package production

// This file ports the Message Server's read-only EC2 reservation catalog into
// Agent ownership. It verifies regional offerings, instance architecture and
// a single signed AWS Price List result; no EC2/CloudFormation mutation client
// is part of the interface.

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
)

var reservationInstanceTypeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}\.[a-z0-9][a-z0-9-]{0,31}$`)

var ErrReservationCatalogUnavailable = errors.New("execution.v2 production: reservation catalog unavailable")

type EC2ReservationClient interface {
	DescribeInstanceTypeOfferings(context.Context, *ec2.DescribeInstanceTypeOfferingsInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error)
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
}
type PricingClient interface {
	GetProducts(context.Context, *pricing.GetProductsInput, ...func(*pricing.Options)) (*pricing.GetProductsOutput, error)
}
type ReservationFactory interface {
	NewEC2Reservation(workaws.CredentialHandle) (EC2ReservationClient, error)
	NewPricing(workaws.CredentialHandle) (PricingClient, error)
}

// SDKReservationFactory is the production AWS SDK constructor. It only
// exposes Describe* and Price List clients; callers cannot use it to mutate
// compute resources.
type SDKReservationFactory struct{}

func (SDKReservationFactory) NewEC2Reservation(h workaws.CredentialHandle) (EC2ReservationClient, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	cfg := aws.Config{Region: h.Region, Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(h.AccessKeyID, h.SecretAccessKey, h.SessionToken))}
	return ec2.NewFromConfig(cfg), nil
}
func (SDKReservationFactory) NewPricing(h workaws.CredentialHandle) (PricingClient, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	// AWS Price List Query is served from us-east-1 for commercial regions.
	cfg := aws.Config{Region: "us-east-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(h.AccessKeyID, h.SecretAccessKey, h.SessionToken))}
	return pricing.NewFromConfig(cfg), nil
}

type AWSReservationCatalog struct {
	factory ReservationFactory
	now     func() time.Time
	ttl     time.Duration
	timeout time.Duration
}

func NewAWSReservationCatalog(factory ReservationFactory, now func() time.Time) *AWSReservationCatalog {
	if factory == nil {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &AWSReservationCatalog{factory: factory, now: now, ttl: 15 * time.Minute, timeout: 30 * time.Second}
}
func (c *AWSReservationCatalog) Ready() bool {
	return c != nil && c.factory != nil && c.now != nil && c.ttl > 0 && c.ttl <= time.Hour && c.timeout > 0
}

func (c *AWSReservationCatalog) ResolveReservation(ctx context.Context, credential workaws.CredentialHandle, instanceType string, volumeGiB uint64) (ReservationOffer, error) {
	var zero ReservationOffer
	instanceType = strings.TrimSpace(instanceType)
	if !c.Ready() || credential.Validate() != nil || !reservationInstanceTypeRE.MatchString(instanceType) || volumeGiB < 8 || volumeGiB > 16384 || !pricingSupportsRegion(credential.Region) {
		return zero, ErrReservationCatalogUnavailable
	}
	ec2c, err := c.factory.NewEC2Reservation(credential)
	if err != nil || ec2c == nil {
		return zero, ErrReservationCatalogUnavailable
	}
	pricingClient, err := c.factory.NewPricing(credential)
	if err != nil || pricingClient == nil {
		return zero, ErrReservationCatalogUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var next *string
	availabilityZones := map[string]struct{}{}
	for page := 0; page < 5; page++ {
		out, callErr := ec2c.DescribeInstanceTypeOfferings(callCtx, &ec2.DescribeInstanceTypeOfferingsInput{LocationType: ec2types.LocationTypeAvailabilityZone, Filters: []ec2types.Filter{{Name: aws.String("instance-type"), Values: []string{instanceType}}}, NextToken: next})
		if callErr != nil || out == nil {
			return zero, ErrReservationCatalogUnavailable
		}
		for _, offering := range out.InstanceTypeOfferings {
			if string(offering.InstanceType) != instanceType || !validAvailabilityZone(credential.Region, aws.ToString(offering.Location)) {
				return zero, ErrReservationCatalogUnavailable
			}
			availabilityZones[aws.ToString(offering.Location)] = struct{}{}
		}
		next = out.NextToken
		if strings.TrimSpace(aws.ToString(next)) == "" {
			break
		}
		if page == 4 {
			return zero, ErrReservationCatalogUnavailable
		}
	}
	if len(availabilityZones) == 0 {
		return zero, ErrReservationCatalogUnavailable
	}
	locations := make([]string, 0, len(availabilityZones))
	for location := range availabilityZones {
		locations = append(locations, location)
	}
	sort.Strings(locations)
	typesOut, err := ec2c.DescribeInstanceTypes(callCtx, &ec2.DescribeInstanceTypesInput{InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(instanceType)}})
	if err != nil || typesOut == nil || len(typesOut.InstanceTypes) != 1 || string(typesOut.InstanceTypes[0].InstanceType) != instanceType || typesOut.InstanceTypes[0].ProcessorInfo == nil || !containsArchitecture(typesOut.InstanceTypes[0].ProcessorInfo.SupportedArchitectures, ec2types.ArchitectureTypeX8664) || typesOut.InstanceTypes[0].VCpuInfo == nil || aws.ToInt32(typesOut.InstanceTypes[0].VCpuInfo.DefaultVCpus) <= 0 || typesOut.InstanceTypes[0].MemoryInfo == nil || aws.ToInt64(typesOut.InstanceTypes[0].MemoryInfo.SizeInMiB) <= 0 {
		return zero, ErrReservationCatalogUnavailable
	}
	compute, err := queryUniquePrice(callCtx, pricingClient, map[string]string{"instanceType": instanceType, "operatingSystem": "Linux", "tenancy": "Shared", "preInstalledSw": "NA", "capacitystatus": "Used", "regionCode": credential.Region}, "Hrs")
	if err != nil {
		return zero, ErrReservationCatalogUnavailable
	}
	storage, err := queryUniquePrice(callCtx, pricingClient, map[string]string{"volumeApiName": "gp3", "productFamily": "Storage", "regionCode": credential.Region}, "GB-Mo")
	if err != nil {
		return zero, ErrReservationCatalogUnavailable
	}
	storage.Mul(storage, new(big.Rat).SetInt64(int64(volumeGiB)))
	storage.Quo(storage, new(big.Rat).SetInt64(730))
	total := new(big.Rat).Add(compute, storage)
	amount := decimalAmount(total)
	if amount == "" {
		return zero, ErrReservationCatalogUnavailable
	}
	now := c.now().UTC().Truncate(time.Microsecond)
	return ReservationOffer{InfrastructureProfileID: "aws-ec2-general-linux-ssm-v1", AMIParameter: "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", InstanceType: instanceType, AvailabilityZone: locations[0], VolumeGiB: volumeGiB, Architecture: "x86_64", ManagementTransport: "aws_ssm", PublicIP: true, PublicInbound: false, CostAmount: amount, CostCurrency: "USD", CostExpiresAt: now.Add(c.ttl)}, nil
}

func pricingSupportsRegion(region string) bool {
	region = strings.TrimSpace(region)
	return region != "" && !strings.HasPrefix(region, "cn-") && !strings.HasPrefix(region, "us-gov-") && !strings.HasPrefix(region, "us-iso-") && !strings.HasPrefix(region, "us-isob-")
}
func validAvailabilityZone(region, value string) bool {
	region = strings.TrimSpace(region)
	value = strings.TrimSpace(value)
	if region == "" || value == "" || len(value) != len(region)+1 || !strings.HasPrefix(value, region) {
		return false
	}
	suffix := value[len(value)-1]
	return suffix >= 'a' && suffix <= 'z'
}
func containsArchitecture(values []ec2types.ArchitectureType, want ec2types.ArchitectureType) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type priceDocument struct {
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

func queryUniquePrice(ctx context.Context, client PricingClient, attributes map[string]string, unit string) (*big.Rat, error) {
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	filters := make([]pricingtypes.Filter, 0, len(keys))
	for _, key := range keys {
		filters = append(filters, pricingtypes.Filter{Field: aws.String(key), Type: pricingtypes.FilterTypeTermMatch, Value: aws.String(attributes[key])})
	}
	var next *string
	prices := map[string]*big.Rat{}
	for page := 0; page < 5; page++ {
		out, err := client.GetProducts(ctx, &pricing.GetProductsInput{ServiceCode: aws.String("AmazonEC2"), Filters: filters, FormatVersion: aws.String("aws_v1"), MaxResults: aws.Int32(100), NextToken: next})
		if err != nil || out == nil {
			return nil, ErrReservationCatalogUnavailable
		}
		for _, raw := range out.PriceList {
			var doc priceDocument
			if json.Unmarshal([]byte(raw), &doc) != nil {
				return nil, ErrReservationCatalogUnavailable
			}
			for key, want := range attributes {
				actual := doc.Product.Attributes[key]
				if key == "productFamily" {
					actual = doc.Product.ProductFamily
				}
				if actual != want {
					return nil, ErrReservationCatalogUnavailable
				}
			}
			for _, term := range doc.Terms.OnDemand {
				for _, dimension := range term.PriceDimensions {
					if dimension.Unit != unit {
						continue
					}
					value := strings.TrimSpace(dimension.PricePerUnit["USD"])
					rat, ok := new(big.Rat).SetString(value)
					if !ok || rat.Sign() <= 0 {
						return nil, ErrReservationCatalogUnavailable
					}
					prices[rat.RatString()] = rat
				}
			}
		}
		if strings.TrimSpace(aws.ToString(out.NextToken)) == "" {
			break
		}
		next = out.NextToken
		if page == 4 {
			return nil, ErrReservationCatalogUnavailable
		}
	}
	if len(prices) != 1 {
		return nil, ErrReservationCatalogUnavailable
	}
	for _, price := range prices {
		return new(big.Rat).Set(price), nil
	}
	return nil, ErrReservationCatalogUnavailable
}
func decimalAmount(value *big.Rat) string {
	if value == nil || value.Sign() <= 0 {
		return ""
	}
	result := strings.TrimRight(strings.TrimRight(value.FloatString(10), "0"), ".")
	if result == "" || result == "0" {
		return ""
	}
	return result
}
