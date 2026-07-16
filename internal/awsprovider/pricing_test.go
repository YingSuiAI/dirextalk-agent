package awsprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	quotatypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"
)

func TestPricingProviderBuildsCompleteReadOnlySnapshot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 8, 30, 0, 0, time.UTC)
	ec2Client := &fakePricingEC2{now: now, vcpus: map[string]int32{
		"m7i.large": 2, "m7i.xlarge": 4, "g6.xlarge": 4,
	}}
	factory := fakePricingFactory{clients: PricingReadClients{
		EC2: ec2Client, PriceList: &fakePriceList{},
		ServiceQuotas: &fakeServiceQuotas{}, CloudWatch: &fakeQuotaCloudWatch{},
	}}
	provider, err := NewPricingProvider(factory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	query := cloudquote.PricingQueryV1{
		Region: "us-east-1", Zones: []string{"us-east-1a", "us-east-1b"},
		Usage: cloudquote.UsageV1{
			RuntimeHoursPerMonth: 100, PublicIPv4Hours: 100,
			LogIngestMiB: 1024, LogStoredMiBMonths: 1024,
			SnapshotGiBMonths: 10, EntryHours: 100, InternetEgressMiB: 1024,
		},
		Candidates: []cloudquote.PricingCandidateQueryV1{
			pricingCandidate(cloudquote.CandidateEconomic, "m7i.large", cloudquote.PurchaseOnDemand, cloudquote.EntryPointNone, false, 10),
			pricingCandidate(cloudquote.CandidateRecommended, "m7i.xlarge", cloudquote.PurchaseOnDemand, cloudquote.EntryPointALB, true, 20),
			pricingCandidate(cloudquote.CandidatePerformance, "g6.xlarge", cloudquote.PurchaseSpot, cloudquote.EntryPointCloudFront, true, 30),
		},
	}

	snapshot, err := provider.Price(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.CapturedAt.Equal(now) || snapshot.Currency != "USD" {
		t.Fatalf("unexpected evidence header: %#v", snapshot)
	}
	if len(snapshot.Offerings) != 3 || len(snapshot.Quotas) != 3 || len(snapshot.Prices) != 3 {
		t.Fatalf("incomplete snapshot: offerings=%d quotas=%d prices=%d", len(snapshot.Offerings), len(snapshot.Quotas), len(snapshot.Prices))
	}
	if len(snapshot.Assumptions) == 0 || len(snapshot.Exclusions) == 0 {
		t.Fatal("evidence assumptions and exclusions must be explicit")
	}

	for _, candidate := range query.Candidates {
		offering := findOfferingForTest(snapshot, candidate.CandidateID)
		if strings.Join(offering.AvailabilityZones, ",") != "us-east-1a,us-east-1b" {
			t.Fatalf("%s offering zones = %v", candidate.CandidateID, offering.AvailabilityZones)
		}
		quota := findQuotaForTest(snapshot, candidate.CandidateID)
		if quota.Quota.LimitUnits != 64 || quota.Quota.RequiredUnits == 0 {
			t.Fatalf("%s quota evidence = %#v", candidate.CandidateID, quota.Quota)
		}
		price := findPriceForTest(snapshot, candidate.CandidateID)
		categories := make(map[cloudquote.CostCategory]bool)
		for _, item := range price.CostItems {
			categories[item.Category] = true
			if item.SourceID == "" {
				t.Fatalf("%s has cost without source ID", candidate.CandidateID)
			}
		}
		for _, category := range []cloudquote.CostCategory{
			cloudquote.CostEBS, cloudquote.CostPublicIPv4, cloudquote.CostLogs,
			cloudquote.CostSnapshot, cloudquote.CostEntry, cloudquote.CostTraffic,
		} {
			if !categories[category] {
				t.Fatalf("%s omitted %s", candidate.CandidateID, category)
			}
		}
	}

	economic := findPriceForTest(snapshot, cloudquote.CandidateEconomic)
	if got := findCostForTest(economic, cloudquote.CostComputeOnDemand).HourlyEstimateMicros; got != 1_000_000 {
		t.Fatalf("on-demand hourly estimate = %d, want 1000000", got)
	}
	if got := findCostForTest(economic, cloudquote.CostEBS).MonthlyEstimateMicros; got != 1_000_000 {
		t.Fatalf("EBS monthly estimate = %d, want 1000000", got)
	}
	performance := findPriceForTest(snapshot, cloudquote.CandidatePerformance)
	if got := findCostForTest(performance, cloudquote.CostComputeSpot).HourlyEstimateMicros; got != 400_000 {
		t.Fatalf("Spot hourly estimate = %d, want 400000", got)
	}
	if ec2Client.offeringCalls != 3 || ec2Client.spotCalls != 1 || ec2Client.instanceTypeCalls != 3 {
		t.Fatalf("unexpected read calls: offerings=%d spot=%d instance-types=%d", ec2Client.offeringCalls, ec2Client.spotCalls, ec2Client.instanceTypeCalls)
	}
}

func TestPricingProviderRejectsAmbiguousOrMalformedCatalogPrices(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 8, 30, 0, 0, time.UTC)
	provider, err := NewPricingProvider(fakePricingFactory{clients: PricingReadClients{
		EC2:       &fakePricingEC2{now: now, vcpus: map[string]int32{"m7i.large": 2}},
		PriceList: &fakePriceList{malformed: true}, ServiceQuotas: &fakeServiceQuotas{}, CloudWatch: &fakeQuotaCloudWatch{},
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Price(context.Background(), cloudquote.PricingQueryV1{
		Region: "us-east-1", Zones: []string{"us-east-1a"}, Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 1},
		Candidates: []cloudquote.PricingCandidateQueryV1{pricingCandidate(cloudquote.CandidateEconomic, "m7i.large", cloudquote.PurchaseOnDemand, cloudquote.EntryPointNone, false, 10)},
	})
	if err == nil || !strings.Contains(err.Error(), "price list") {
		t.Fatalf("expected redacted price-list error, got %v", err)
	}
}

func TestQuotaCodeClassificationCoversAcceleratorAndTrainingFamilies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		instance string
		purchase cloudquote.PurchaseOption
		want     string
	}{
		{instance: "m7i.large", purchase: cloudquote.PurchaseOnDemand, want: "L-1216C47A"},
		{instance: "g6.xlarge", purchase: cloudquote.PurchaseOnDemand, want: "L-DB2E81BA"},
		{instance: "p5.48xlarge", purchase: cloudquote.PurchaseSpot, want: "L-7212CCBC"},
		{instance: "trn2.48xlarge", purchase: cloudquote.PurchaseOnDemand, want: "L-2C3B7624"},
		{instance: "trn2.48xlarge", purchase: cloudquote.PurchaseSpot, want: "L-6B0D517C"},
		{instance: "hpc7g.16xlarge", purchase: cloudquote.PurchaseOnDemand, want: "L-F7808C92"},
		{instance: "u-6tb1.56xlarge", purchase: cloudquote.PurchaseOnDemand, want: "L-43DA4232"},
	}
	for _, test := range tests {
		got, err := quotaCodeFor(test.instance, test.purchase)
		if err != nil || got != test.want {
			t.Fatalf("quotaCodeFor(%q, %q) = %q, %v; want %q", test.instance, test.purchase, got, err, test.want)
		}
	}
	if _, err := quotaCodeFor("hpc7g.16xlarge", cloudquote.PurchaseSpot); err == nil {
		t.Fatal("unsupported HPC Spot quota mapping unexpectedly succeeded")
	}
}

func pricingCandidate(id cloudquote.CandidateProfile, instance string, purchase cloudquote.PurchaseOption, entry cloudquote.EntryPointKind, public bool, disk uint64) cloudquote.PricingCandidateQueryV1 {
	return cloudquote.PricingCandidateQueryV1{
		CandidateID: id, InstanceType: instance, InstanceCount: 1,
		Architecture: recipe.ArchitectureAMD64, DiskGiB: disk, VolumeType: "gp3",
		VolumeIOPS: 3000, VolumeThroughputMiBPS: 125,
		PurchaseOption: purchase, EntryPoint: entry, PublicExposure: public,
	}
}

type fakePricingFactory struct{ clients PricingReadClients }

func (f fakePricingFactory) ClientsForRegion(string) PricingReadClients { return f.clients }

type fakePricingEC2 struct {
	now                                         time.Time
	vcpus                                       map[string]int32
	offeringCalls, spotCalls, instanceTypeCalls int
}

func (f *fakePricingEC2) DescribeInstanceTypeOfferings(_ context.Context, input *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	f.offeringCalls++
	instance := filterValue(input.Filters, "instance-type")
	zones := filterValues(input.Filters, "location")
	offerings := make([]ec2types.InstanceTypeOffering, 0, len(zones))
	for _, zone := range zones {
		offerings = append(offerings, ec2types.InstanceTypeOffering{InstanceType: ec2types.InstanceType(instance), Location: aws.String(zone), LocationType: ec2types.LocationTypeAvailabilityZone})
	}
	return &ec2.DescribeInstanceTypeOfferingsOutput{InstanceTypeOfferings: offerings}, nil
}

func (f *fakePricingEC2) DescribeSpotPriceHistory(_ context.Context, input *ec2.DescribeSpotPriceHistoryInput, _ ...func(*ec2.Options)) (*ec2.DescribeSpotPriceHistoryOutput, error) {
	f.spotCalls++
	zone := "us-east-1a"
	return &ec2.DescribeSpotPriceHistoryOutput{SpotPriceHistory: []ec2types.SpotPrice{{
		AvailabilityZone: aws.String(zone), InstanceType: input.InstanceTypes[0],
		SpotPrice: aws.String("0.400000"), Timestamp: aws.Time(f.now.Add(-time.Minute)),
	}}}, nil
}

func (f *fakePricingEC2) DescribeInstanceTypes(_ context.Context, input *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	f.instanceTypeCalls++
	instance := string(input.InstanceTypes[0])
	vcpus := f.vcpus[instance]
	return &ec2.DescribeInstanceTypesOutput{InstanceTypes: []ec2types.InstanceTypeInfo{{
		InstanceType: input.InstanceTypes[0], VCpuInfo: &ec2types.VCpuInfo{DefaultVCpus: aws.Int32(vcpus)},
		ProcessorInfo: &ec2types.ProcessorInfo{SupportedArchitectures: []ec2types.ArchitectureType{ec2types.ArchitectureTypeX8664}},
	}}}, nil
}

type fakeServiceQuotas struct{}

func (*fakeServiceQuotas) GetServiceQuota(_ context.Context, input *servicequotas.GetServiceQuotaInput, _ ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error) {
	return &servicequotas.GetServiceQuotaOutput{Quota: &quotatypes.ServiceQuota{
		ServiceCode: input.ServiceCode, QuotaCode: input.QuotaCode, Value: aws.Float64(64), Unit: aws.String("Count"),
	}}, nil
}

type fakeQuotaCloudWatch struct{}

func (*fakeQuotaCloudWatch) GetMetricStatistics(context.Context, *cloudwatch.GetMetricStatisticsInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	return &cloudwatch.GetMetricStatisticsOutput{}, nil
}

type fakePriceList struct{ malformed bool }

func (f *fakePriceList) GetProducts(_ context.Context, input *pricing.GetProductsInput, _ ...func(*pricing.Options)) (*pricing.GetProductsOutput, error) {
	if f.malformed {
		return &pricing.GetProductsOutput{PriceList: []string{`{"product":`}}, nil
	}
	filters := pricingFilterMap(input.Filters)
	rate, unit, kind := "0.090000", "GB", "traffic"
	switch aws.ToString(input.ServiceCode) {
	case "AmazonVPC":
		rate, unit, kind = "0.005000", "Hrs", "ipv4"
	case "AmazonCloudWatch":
		if filters["group"] == "Amazon CloudWatch Standard Storage pricing current" {
			rate, unit, kind = "0.030000", "GB-Mo", "logs-storage"
		} else {
			rate, unit, kind = "0.500000", "GB", "logs-ingest"
		}
	case "AmazonCloudFront":
		if filters["productFamily"] == "Request" {
			rate, unit, kind = "0.010000", "10K Requests", "cloudfront-request"
		} else {
			rate, unit, kind = "0.085000", "GB", "cloudfront-traffic"
		}
	case "AmazonEC2":
		if filters["group"] == "ELB:Application" {
			return &pricing.GetProductsOutput{PriceList: []string{
				priceListJSON("alb-hours", "0.020000", "Hrs"),
				priceListJSON("alb-lcu", "0.008000", "LCU-Hrs"),
			}}, nil
		}
		switch {
		case filters["instanceType"] != "":
			rate, unit, kind = "1.000000", "Hrs", "compute-"+filters["instanceType"]
		case filters["volumeApiName"] != "":
			rate, unit, kind = "0.100000", "GB-Mo", "ebs-"+filters["volumeApiName"]
		case filters["productFamily"] == "Storage Snapshot":
			rate, unit, kind = "0.050000", "GB-Mo", "snapshot"
		}
	}
	return &pricing.GetProductsOutput{PriceList: []string{priceListJSON(kind, rate, unit)}}, nil
}

func priceListJSON(kind, rate, unit string) string {
	hash := sha256.Sum256([]byte(kind))
	suffix := strings.ToUpper(hex.EncodeToString(hash[:6]))
	sku := "SKU" + suffix
	dimension := sku + ".JRTCKXETXF.6YS6EN2CT7"
	document := map[string]any{
		"product": map[string]any{"sku": sku, "attributes": map[string]string{}},
		"terms": map[string]any{"OnDemand": map[string]any{sku + ".JRTCKXETXF": map[string]any{
			"priceDimensions": map[string]any{dimension: map[string]any{
				"unit": unit, "beginRange": "0", "endRange": "Inf", "pricePerUnit": map[string]string{"USD": rate},
			}},
		}}},
	}
	encoded, _ := json.Marshal(document)
	return string(encoded)
}

func pricingFilterMap(filters []pricingtypes.Filter) map[string]string {
	values := make(map[string]string, len(filters))
	for _, filter := range filters {
		values[aws.ToString(filter.Field)] = aws.ToString(filter.Value)
	}
	return values
}

func filterValue(filters []ec2types.Filter, name string) string {
	values := filterValues(filters, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func filterValues(filters []ec2types.Filter, name string) []string {
	for _, filter := range filters {
		if aws.ToString(filter.Name) == name {
			return append([]string(nil), filter.Values...)
		}
	}
	return nil
}

func findOfferingForTest(snapshot cloudquote.PricingSnapshotV1, id cloudquote.CandidateProfile) cloudquote.OfferingV1 {
	for _, value := range snapshot.Offerings {
		if value.CandidateID == id {
			return value
		}
	}
	panic(fmt.Sprintf("offering %s not found", id))
}

func findQuotaForTest(snapshot cloudquote.PricingSnapshotV1, id cloudquote.CandidateProfile) cloudquote.CandidateQuotaV1 {
	for _, value := range snapshot.Quotas {
		if value.CandidateID == id {
			return value
		}
	}
	panic(fmt.Sprintf("quota %s not found", id))
}

func findPriceForTest(snapshot cloudquote.PricingSnapshotV1, id cloudquote.CandidateProfile) cloudquote.CandidatePriceV1 {
	for _, value := range snapshot.Prices {
		if value.CandidateID == id {
			return value
		}
	}
	panic(fmt.Sprintf("price %s not found", id))
}

func findCostForTest(price cloudquote.CandidatePriceV1, category cloudquote.CostCategory) cloudquote.CostItemV1 {
	items := append([]cloudquote.CostItemV1(nil), price.CostItems...)
	sort.Slice(items, func(i, j int) bool { return items[i].SourceID < items[j].SourceID })
	for _, value := range items {
		if value.Category == category {
			return value
		}
	}
	panic(fmt.Sprintf("cost %s not found", category))
}
