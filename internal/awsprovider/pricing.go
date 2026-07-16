package awsprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	quotatypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"
)

const (
	pricingEvidenceWindow = 15 * time.Minute
	spotHistoryWindow     = 3 * time.Hour
	hoursPerMonth         = uint64(730)
)

// PricingEC2ReadAPI is intentionally read-only. It contains no EC2 mutation,
// launch, stop, or terminate operation.
type PricingEC2ReadAPI interface {
	DescribeInstanceTypeOfferings(context.Context, *ec2.DescribeInstanceTypeOfferingsInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error)
	DescribeSpotPriceHistory(context.Context, *ec2.DescribeSpotPriceHistoryInput, ...func(*ec2.Options)) (*ec2.DescribeSpotPriceHistoryOutput, error)
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
}

type PriceListReadAPI interface {
	GetProducts(context.Context, *pricing.GetProductsInput, ...func(*pricing.Options)) (*pricing.GetProductsOutput, error)
}

type ServiceQuotasReadAPI interface {
	GetServiceQuota(context.Context, *servicequotas.GetServiceQuotaInput, ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error)
}

type QuotaCloudWatchReadAPI interface {
	GetMetricStatistics(context.Context, *cloudwatch.GetMetricStatisticsInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

type PricingReadClients struct {
	EC2           PricingEC2ReadAPI
	PriceList     PriceListReadAPI
	ServiceQuotas ServiceQuotasReadAPI
	CloudWatch    QuotaCloudWatchReadAPI
}

type PricingReadClientFactory interface {
	ClientsForRegion(region string) PricingReadClients
}

// AWSPricingReadClientFactory constructs region-bound read-only SDK clients.
// Price List has a separate regional endpoint, while EC2, Service Quotas, and
// CloudWatch must observe the candidate Region.
type AWSPricingReadClientFactory struct {
	Config aws.Config
}

func (factory AWSPricingReadClientFactory) ClientsForRegion(region string) PricingReadClients {
	regional := factory.Config
	regional.Region = region
	priceListConfig := factory.Config
	priceListConfig.Region = priceListRegion(region)
	return PricingReadClients{
		EC2: ec2.NewFromConfig(regional), PriceList: pricing.NewFromConfig(priceListConfig),
		ServiceQuotas: servicequotas.NewFromConfig(regional), CloudWatch: cloudwatch.NewFromConfig(regional),
	}
}

func priceListRegion(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "cn-northwest-1"
	}
	if strings.HasPrefix(region, "us-gov-") {
		return "us-gov-west-1"
	}
	return "us-east-1"
}

type PricingProvider struct {
	factory PricingReadClientFactory
	now     func() time.Time
}

func NewPricingProvider(factory PricingReadClientFactory, now func() time.Time) (*PricingProvider, error) {
	if factory == nil || now == nil {
		return nil, errors.New("pricing provider requires a client factory and clock")
	}
	return &PricingProvider{factory: factory, now: now}, nil
}

func NewPricingProviderFromConfig(config aws.Config) (*PricingProvider, error) {
	return NewPricingProvider(AWSPricingReadClientFactory{Config: config}, time.Now)
}

var _ cloudquote.PricingPort = (*PricingProvider)(nil)

func (provider *PricingProvider) Price(ctx context.Context, query cloudquote.PricingQueryV1) (cloudquote.PricingSnapshotV1, error) {
	if provider == nil || provider.factory == nil || provider.now == nil {
		return cloudquote.PricingSnapshotV1{}, errors.New("pricing provider is not initialized")
	}
	if ctx == nil {
		return cloudquote.PricingSnapshotV1{}, errors.New("pricing context is required")
	}
	if err := validatePricingQuery(query); err != nil {
		return cloudquote.PricingSnapshotV1{}, err
	}
	clients := provider.factory.ClientsForRegion(query.Region)
	if clients.EC2 == nil || clients.PriceList == nil || clients.ServiceQuotas == nil || clients.CloudWatch == nil {
		return cloudquote.PricingSnapshotV1{}, errors.New("pricing read clients are incomplete")
	}

	capturedAt := provider.now().UTC()
	snapshot := cloudquote.PricingSnapshotV1{
		CapturedAt: capturedAt,
		Currency:   "USD",
		Assumptions: []string{
			"monthly normalization uses 730 hours",
			"AWS Price List first public tier is applied conservatively to all requested usage",
			"query usage quantities and one exclusive Worker per candidate are treated as authoritative",
			"ALB estimates assume one Application Load Balancer and one LCU per entry hour",
			"CloudFront request estimates assume one HTTPS request per MiB of requested egress",
			"CloudFront uses the highest public first-tier edge geography rate as a conservative estimate",
			"a missing AWS quota usage metric datapoint is treated as zero current usage",
			"pricing and quota evidence was captured at " + capturedAt.Format(time.RFC3339),
		},
		Exclusions: []string{
			"taxes, support plans, Savings Plans, Reserved Instances, and Marketplace charges",
			"NAT Gateway, Route 53, WAF, certificate, and request usage not represented by the typed query",
			"unexpected cross-Region transfer, burst traffic, and ALB usage above one LCU",
			"actual AWS billing adjustments and tier discounts after the evidence timestamp",
		},
	}
	catalog := newPriceCatalog(clients.PriceList)
	quotaCache := make(map[string]quotaSnapshot)

	for _, candidate := range query.Candidates {
		offering, err := readOffering(ctx, clients.EC2, query, candidate)
		if err != nil {
			return cloudquote.PricingSnapshotV1{}, fmt.Errorf("candidate %s offering evidence: %w", candidate.CandidateID, err)
		}
		vcpu, err := readInstanceVCPU(ctx, clients.EC2, candidate.InstanceType, candidate.Architecture)
		if err != nil {
			return cloudquote.PricingSnapshotV1{}, fmt.Errorf("candidate %s instance evidence: %w", candidate.CandidateID, err)
		}
		quota, err := readQuota(ctx, clients, candidate, vcpu, capturedAt, quotaCache)
		if err != nil {
			return cloudquote.PricingSnapshotV1{}, fmt.Errorf("candidate %s Service Quotas evidence: %w", candidate.CandidateID, err)
		}
		costs, err := provider.readCosts(ctx, clients.EC2, catalog, query, candidate, offering.AvailabilityZones, capturedAt)
		if err != nil {
			return cloudquote.PricingSnapshotV1{}, fmt.Errorf("candidate %s price evidence: %w", candidate.CandidateID, err)
		}
		snapshot.Offerings = append(snapshot.Offerings, offering)
		snapshot.Quotas = append(snapshot.Quotas, cloudquote.CandidateQuotaV1{CandidateID: candidate.CandidateID, Quota: quota})
		snapshot.Prices = append(snapshot.Prices, cloudquote.CandidatePriceV1{CandidateID: candidate.CandidateID, CostItems: costs})
	}
	return snapshot, nil
}

func validatePricingQuery(query cloudquote.PricingQueryV1) error {
	if !sdkRegionPattern.MatchString(query.Region) {
		return errors.New("pricing Region is invalid")
	}
	if len(query.Zones) == 0 || len(query.Candidates) == 0 {
		return errors.New("pricing query requires zones and candidates")
	}
	seen := make(map[cloudquote.CandidateProfile]struct{}, len(query.Candidates))
	for _, candidate := range query.Candidates {
		if candidate.CandidateID == "" || candidate.InstanceType == "" || candidate.InstanceCount == 0 || candidate.DiskGiB == 0 || candidate.VolumeType == "" {
			return errors.New("pricing candidate is incomplete")
		}
		if _, exists := seen[candidate.CandidateID]; exists {
			return errors.New("pricing candidate IDs must be unique")
		}
		seen[candidate.CandidateID] = struct{}{}
		if candidate.PurchaseOption != cloudquote.PurchaseOnDemand && candidate.PurchaseOption != cloudquote.PurchaseSpot {
			return errors.New("pricing purchase option is unsupported")
		}
		if candidate.EntryPoint != cloudquote.EntryPointNone && candidate.EntryPoint != cloudquote.EntryPointALB && candidate.EntryPoint != cloudquote.EntryPointCloudFront {
			return errors.New("pricing entry point is unsupported")
		}
	}
	return nil
}

func readOffering(ctx context.Context, client PricingEC2ReadAPI, query cloudquote.PricingQueryV1, candidate cloudquote.PricingCandidateQueryV1) (cloudquote.OfferingV1, error) {
	input := &ec2.DescribeInstanceTypeOfferingsInput{
		LocationType: ec2types.LocationTypeAvailabilityZone,
		Filters: []ec2types.Filter{
			{Name: aws.String("instance-type"), Values: []string{candidate.InstanceType}},
			{Name: aws.String("location"), Values: append([]string(nil), query.Zones...)},
		},
		MaxResults: aws.Int32(100),
	}
	zones := make(map[string]struct{})
	for page := 0; page < 100; page++ {
		output, err := client.DescribeInstanceTypeOfferings(ctx, input)
		if err != nil {
			return cloudquote.OfferingV1{}, fmt.Errorf("DescribeInstanceTypeOfferings: %w", err)
		}
		for _, item := range output.InstanceTypeOfferings {
			zone := aws.ToString(item.Location)
			if string(item.InstanceType) == candidate.InstanceType && containsString(query.Zones, zone) {
				zones[zone] = struct{}{}
			}
		}
		if aws.ToString(output.NextToken) == "" {
			break
		}
		input.NextToken = output.NextToken
		if page == 99 {
			return cloudquote.OfferingV1{}, errors.New("DescribeInstanceTypeOfferings pagination limit exceeded")
		}
	}
	values := make([]string, 0, len(zones))
	for zone := range zones {
		values = append(values, zone)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return cloudquote.OfferingV1{}, errors.New("instance type is unavailable in requested zones")
	}
	return cloudquote.OfferingV1{
		CandidateID: candidate.CandidateID, Region: query.Region, InstanceType: candidate.InstanceType,
		Architecture: candidate.Architecture, PurchaseOption: candidate.PurchaseOption, AvailabilityZones: values,
	}, nil
}

func readInstanceVCPU(ctx context.Context, client PricingEC2ReadAPI, instanceType string, architecture recipe.Architecture) (uint64, error) {
	output, err := client.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(instanceType)}, MaxResults: aws.Int32(100),
	})
	if err != nil {
		return 0, fmt.Errorf("DescribeInstanceTypes: %w", err)
	}
	for _, item := range output.InstanceTypes {
		if string(item.InstanceType) != instanceType || item.VCpuInfo == nil || aws.ToInt32(item.VCpuInfo.DefaultVCpus) <= 0 || item.ProcessorInfo == nil {
			continue
		}
		wanted := ec2types.ArchitectureTypeX8664
		if architecture == recipe.ArchitectureARM64 {
			wanted = ec2types.ArchitectureTypeArm64
		}
		for _, supported := range item.ProcessorInfo.SupportedArchitectures {
			if supported == wanted {
				return uint64(aws.ToInt32(item.VCpuInfo.DefaultVCpus)), nil
			}
		}
		return 0, errors.New("instance type does not support the requested architecture")
	}
	return 0, errors.New("instance type vCPU count is unavailable")
}

type quotaSnapshot struct {
	limit uint64
	used  uint64
}

func readQuota(ctx context.Context, clients PricingReadClients, candidate cloudquote.PricingCandidateQueryV1, vcpu uint64, now time.Time, cache map[string]quotaSnapshot) (cloudquote.QuotaEvidenceV1, error) {
	quotaCode, err := quotaCodeFor(candidate.InstanceType, candidate.PurchaseOption)
	if err != nil {
		return cloudquote.QuotaEvidenceV1{}, err
	}
	cacheKey := "ec2:" + quotaCode
	evidence, exists := cache[cacheKey]
	if !exists {
		output, err := clients.ServiceQuotas.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{ServiceCode: aws.String("ec2"), QuotaCode: aws.String(quotaCode)})
		if err != nil {
			return cloudquote.QuotaEvidenceV1{}, fmt.Errorf("GetServiceQuota: %w", err)
		}
		if output.Quota == nil || aws.ToString(output.Quota.ServiceCode) != "ec2" || aws.ToString(output.Quota.QuotaCode) != quotaCode || output.Quota.Value == nil {
			return cloudquote.QuotaEvidenceV1{}, errors.New("GetServiceQuota returned mismatched evidence")
		}
		limit, err := sdkNumberCeil(output.Quota.Value)
		if err != nil || limit == 0 {
			return cloudquote.QuotaEvidenceV1{}, errors.New("GetServiceQuota returned an invalid limit")
		}
		used, err := readQuotaUsage(ctx, clients.CloudWatch, output.Quota.UsageMetric, now)
		if err != nil {
			return cloudquote.QuotaEvidenceV1{}, err
		}
		evidence = quotaSnapshot{limit: limit, used: used}
		cache[cacheKey] = evidence
	}
	if vcpu != 0 && uint64(candidate.InstanceCount) > ^uint64(0)/vcpu {
		return cloudquote.QuotaEvidenceV1{}, errors.New("required vCPU count overflows")
	}
	required := vcpu * uint64(candidate.InstanceCount)
	if evidence.used > evidence.limit || required > evidence.limit-evidence.used {
		return cloudquote.QuotaEvidenceV1{}, errors.New("candidate exceeds current account quota")
	}
	return cloudquote.QuotaEvidenceV1{ServiceCode: "ec2", QuotaCode: quotaCode, LimitUnits: evidence.limit, UsedUnits: evidence.used, RequiredUnits: required}, nil
}

func quotaCodeFor(instanceType string, purchase cloudquote.PurchaseOption) (string, error) {
	family := strings.ToLower(strings.SplitN(instanceType, ".", 2)[0])
	class := "standard"
	switch {
	case strings.HasPrefix(family, "g"), strings.HasPrefix(family, "vt"):
		class = "g-vt"
	case strings.HasPrefix(family, "p"):
		class = "p"
	case strings.HasPrefix(family, "f"):
		class = "f"
	case strings.HasPrefix(family, "inf"):
		class = "inf"
	case strings.HasPrefix(family, "x"):
		class = "x"
	case strings.HasPrefix(family, "dl"):
		class = "dl"
	case strings.HasPrefix(family, "trn"):
		class = "trn"
	case strings.HasPrefix(family, "hpc"):
		class = "hpc"
	case strings.HasPrefix(family, "u-"):
		class = "high-memory"
	}
	onDemand := map[string]string{
		"standard": "L-1216C47A", "f": "L-74FC7D96", "g-vt": "L-DB2E81BA", "p": "L-417A185B",
		"inf": "L-1945791B", "x": "L-7295265B", "dl": "L-6E869C2A", "trn": "L-2C3B7624",
		"hpc": "L-F7808C92", "high-memory": "L-43DA4232",
	}
	spot := map[string]string{
		"standard": "L-34B43A08", "f": "L-88CF9481", "g-vt": "L-3819A6DF", "p": "L-7212CCBC",
		"inf": "L-B5D1601B", "x": "L-E3A00192", "dl": "L-85EED4F7", "trn": "L-6B0D517C",
	}
	var code string
	if purchase == cloudquote.PurchaseSpot {
		code = spot[class]
	} else {
		code = onDemand[class]
	}
	if code == "" {
		return "", errors.New("instance class has no supported quota for the purchase option")
	}
	return code, nil
}

func readQuotaUsage(ctx context.Context, client QuotaCloudWatchReadAPI, metric *quotatypes.MetricInfo, now time.Time) (uint64, error) {
	if metric == nil {
		return 0, nil
	}
	namespace, name := aws.ToString(metric.MetricNamespace), aws.ToString(metric.MetricName)
	if namespace == "" || name == "" {
		return 0, errors.New("Service Quotas usage metric is incomplete")
	}
	statistic, selector, err := quotaStatistic(metric.MetricStatisticRecommendation)
	if err != nil {
		return 0, err
	}
	dimensionNames := make([]string, 0, len(metric.MetricDimensions))
	for dimension := range metric.MetricDimensions {
		dimensionNames = append(dimensionNames, dimension)
	}
	sort.Strings(dimensionNames)
	dimensions := make([]cloudwatchtypes.Dimension, 0, len(dimensionNames))
	for _, dimension := range dimensionNames {
		dimensions = append(dimensions, cloudwatchtypes.Dimension{Name: aws.String(dimension), Value: aws.String(metric.MetricDimensions[dimension])})
	}
	start := now.Add(-pricingEvidenceWindow)
	output, err := client.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace: aws.String(namespace), MetricName: aws.String(name), Dimensions: dimensions,
		StartTime: aws.Time(start), EndTime: aws.Time(now), Period: aws.Int32(60), Statistics: []cloudwatchtypes.Statistic{statistic},
	})
	if err != nil {
		return 0, fmt.Errorf("GetMetricStatistics: %w", err)
	}
	var selected *cloudwatchtypes.Datapoint
	for index := range output.Datapoints {
		point := &output.Datapoints[index]
		if selector(point) == nil {
			continue
		}
		if selected == nil || (point.Timestamp != nil && (selected.Timestamp == nil || point.Timestamp.After(*selected.Timestamp))) {
			selected = point
		}
	}
	if selected == nil {
		return 0, nil
	}
	return sdkNumberCeil(selector(selected))
}

func quotaStatistic(recommendation *string) (cloudwatchtypes.Statistic, func(*cloudwatchtypes.Datapoint) any, error) {
	switch strings.ToLower(strings.TrimSpace(aws.ToString(recommendation))) {
	case "", "maximum", "max":
		return cloudwatchtypes.StatisticMaximum, func(value *cloudwatchtypes.Datapoint) any { return value.Maximum }, nil
	case "average", "avg":
		return cloudwatchtypes.StatisticAverage, func(value *cloudwatchtypes.Datapoint) any { return value.Average }, nil
	case "sum":
		return cloudwatchtypes.StatisticSum, func(value *cloudwatchtypes.Datapoint) any { return value.Sum }, nil
	case "minimum", "min":
		return cloudwatchtypes.StatisticMinimum, func(value *cloudwatchtypes.Datapoint) any { return value.Minimum }, nil
	case "samplecount", "sample count":
		return cloudwatchtypes.StatisticSampleCount, func(value *cloudwatchtypes.Datapoint) any { return value.SampleCount }, nil
	default:
		return "", nil, errors.New("Service Quotas recommends an unsupported CloudWatch statistic")
	}
}

func sdkNumberCeil(value any) (uint64, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(encoded))
	if text == "null" || text == "" {
		return 0, errors.New("numeric evidence is missing")
	}
	return decimalCeilUnits(text)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
