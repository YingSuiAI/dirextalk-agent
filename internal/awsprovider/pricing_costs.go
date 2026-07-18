package awsprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (provider *PricingProvider) readCosts(ctx context.Context, ec2Client PricingEC2ReadAPI, catalog *priceCatalog, query cloudquote.PricingQueryV1, candidate cloudquote.PricingCandidateQueryV1, offeredZones []string, capturedAt time.Time) ([]cloudquote.CostItemV1, error) {
	items := make([]cloudquote.CostItemV1, 0, 14)
	compute, err := readComputeCost(ctx, ec2Client, catalog, query.Region, candidate, offeredZones, query.Usage, capturedAt)
	if err != nil {
		return nil, err
	}
	items = append(items, compute)

	ebs, err := readEBSCosts(ctx, catalog, query.Region, candidate)
	if err != nil {
		return nil, err
	}
	items = append(items, ebs...)

	ipv4, err := readIPv4Cost(ctx, catalog, query.Region, candidate, query.Usage)
	if err != nil {
		return nil, err
	}
	items = append(items, ipv4)

	privateEndpoints, err := readPrivateEndpointCosts(ctx, catalog, query.Region, candidate, query.Usage)
	if err != nil {
		return nil, err
	}
	items = append(items, privateEndpoints...)

	logs, err := readLogCosts(ctx, catalog, query.Region, candidate, query.Usage)
	if err != nil {
		return nil, err
	}
	items = append(items, logs...)

	snapshot, err := readSnapshotCost(ctx, catalog, query.Region, candidate, query.Usage)
	if err != nil {
		return nil, err
	}
	items = append(items, snapshot)

	entry, err := readEntryCosts(ctx, catalog, query.Region, candidate, query.Usage)
	if err != nil {
		return nil, err
	}
	items = append(items, entry...)

	traffic, err := readTrafficCost(ctx, catalog, query.Region, candidate, query.Usage)
	if err != nil {
		return nil, err
	}
	items = append(items, traffic)

	sort.Slice(items, func(i, j int) bool {
		if items[i].Category == items[j].Category {
			return items[i].SourceID < items[j].SourceID
		}
		return items[i].Category < items[j].Category
	})
	return items, nil
}

func readComputeCost(ctx context.Context, ec2Client PricingEC2ReadAPI, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, offeredZones []string, usage cloudquote.UsageV1, capturedAt time.Time) (cloudquote.CostItemV1, error) {
	category := cloudquote.CostComputeOnDemand
	var unitRate catalogRate
	var err error
	if candidate.PurchaseOption == cloudquote.PurchaseSpot {
		category = cloudquote.CostComputeSpot
		unitRate, err = readSpotRate(ctx, ec2Client, candidate.InstanceType, offeredZones, capturedAt)
	} else {
		unitRate, err = catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "Hrs", filters: map[string]string{
			"instanceType": candidate.InstanceType, "regionCode": region, "operatingSystem": "Linux",
			"tenancy": "Shared", "preInstalledSw": "NA", "capacitystatus": "Used", "productFamily": "Compute Instance",
		}})
	}
	if err != nil {
		return cloudquote.CostItemV1{}, fmt.Errorf("compute: %w", err)
	}
	hourly, err := scaleMicros(unitRate.unitMicros, uint64(candidate.InstanceCount), 1)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	monthly, err := scaleMicros(hourly, uint64(usage.RuntimeHoursPerMonth), 1)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	return cloudquote.CostItemV1{
		Category: category, Description: fmt.Sprintf("%s Linux compute x%d", candidate.InstanceType, candidate.InstanceCount), SourceID: unitRate.sourceID,
		HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: hourly,
	}, nil
}

func readSpotRate(ctx context.Context, client PricingEC2ReadAPI, instanceType string, zones []string, capturedAt time.Time) (catalogRate, error) {
	start := capturedAt.Add(-spotHistoryWindow)
	input := &ec2.DescribeSpotPriceHistoryInput{
		InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(instanceType)}, ProductDescriptions: []string{"Linux/UNIX"},
		StartTime: aws.Time(start), EndTime: aws.Time(capturedAt), MaxResults: aws.Int32(1000),
	}
	var selected *catalogRate
	for page := 0; page < 100; page++ {
		output, err := client.DescribeSpotPriceHistory(ctx, input)
		if err != nil {
			return catalogRate{}, fmt.Errorf("DescribeSpotPriceHistory: %w", err)
		}
		for _, item := range output.SpotPriceHistory {
			zone := aws.ToString(item.AvailabilityZone)
			if string(item.InstanceType) != instanceType || !containsString(zones, zone) || item.SpotPrice == nil || item.Timestamp == nil || item.Timestamp.Before(start) || item.Timestamp.After(capturedAt) {
				continue
			}
			micros, err := decimalMicros(aws.ToString(item.SpotPrice))
			if err != nil {
				return catalogRate{}, fmt.Errorf("invalid Spot price decimal: %w", err)
			}
			candidate := catalogRate{unitMicros: micros, sourceID: sourceIdentifier("awsspot", instanceType, zone, item.Timestamp.UTC().Format("20060102T150405Z"))}
			if selected == nil || candidate.unitMicros > selected.unitMicros || (candidate.unitMicros == selected.unitMicros && candidate.sourceID < selected.sourceID) {
				selected = &candidate
			}
		}
		if aws.ToString(output.NextToken) == "" {
			break
		}
		input.NextToken = output.NextToken
		if page == 99 {
			return catalogRate{}, errors.New("Spot history pagination limit exceeded")
		}
	}
	if selected == nil {
		return catalogRate{}, errors.New("recent Spot history is unavailable in offered zones")
	}
	return *selected, nil
}

func readEBSCosts(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1) ([]cloudquote.CostItemV1, error) {
	storageRate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "GB-Mo", filters: map[string]string{
		"regionCode": region, "productFamily": "Storage", "volumeApiName": candidate.VolumeType,
	}})
	if err != nil {
		return nil, fmt.Errorf("EBS storage: %w", err)
	}
	quantity, err := checkedProduct(candidate.DiskGiB, uint64(candidate.InstanceCount))
	if err != nil {
		return nil, err
	}
	for _, volume := range candidate.DataVolumes {
		dataQuantity, multiplyErr := checkedProduct(uint64(volume.SizeGiB), uint64(candidate.InstanceCount))
		if multiplyErr != nil {
			return nil, multiplyErr
		}
		quantity, err = checkedSum(quantity, dataQuantity)
		if err != nil {
			return nil, err
		}
	}
	monthly, err := scaleMicros(storageRate.unitMicros, quantity, 1)
	if err != nil {
		return nil, err
	}
	hourly, err := scaleMicros(monthly, 1, hoursPerMonth)
	if err != nil {
		return nil, err
	}
	items := []cloudquote.CostItemV1{{
		Category: cloudquote.CostEBS, Description: fmt.Sprintf("encrypted %s EBS storage", candidate.VolumeType), SourceID: storageRate.sourceID,
		HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: monthly,
	}}
	extraIOPS := uint64(0)
	if candidate.VolumeType == "gp3" && candidate.VolumeIOPS > 3000 {
		extraIOPS = uint64(candidate.VolumeIOPS - 3000)
	}
	for _, volume := range candidate.DataVolumes {
		if volume.IOPS > 3000 {
			extraIOPS, err = checkedSum(extraIOPS, uint64(volume.IOPS-3000))
			if err != nil {
				return nil, err
			}
		}
	}
	if extraIOPS > 0 {
		rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "IOPS-Mo", filters: map[string]string{
			"regionCode": region, "productFamily": "Provisioned Throughput", "group": "EBS IOPS", "volumeApiName": "gp3",
		}})
		if err != nil {
			return nil, fmt.Errorf("EBS IOPS: %w", err)
		}
		extra, err := checkedProduct(extraIOPS, uint64(candidate.InstanceCount))
		if err != nil {
			return nil, err
		}
		item, err := monthlyCost(cloudquote.CostEBS, "gp3 provisioned IOPS above included baseline", rate, extra, 1, hoursPerMonth, true)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	extraThroughput := uint64(0)
	if candidate.VolumeType == "gp3" && candidate.VolumeThroughputMiBPS > 125 {
		extraThroughput = uint64(candidate.VolumeThroughputMiBPS - 125)
	}
	for _, volume := range candidate.DataVolumes {
		if volume.ThroughputMiBPS > 125 {
			extraThroughput, err = checkedSum(extraThroughput, uint64(volume.ThroughputMiBPS-125))
			if err != nil {
				return nil, err
			}
		}
	}
	if extraThroughput > 0 {
		rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "MBps-Mo", filters: map[string]string{
			"regionCode": region, "productFamily": "Provisioned Throughput", "group": "EBS Throughput", "volumeApiName": "gp3",
		}})
		if err != nil {
			return nil, fmt.Errorf("EBS throughput: %w", err)
		}
		extra, err := checkedProduct(extraThroughput, uint64(candidate.InstanceCount))
		if err != nil {
			return nil, err
		}
		item, err := monthlyCost(cloudquote.CostEBS, "gp3 provisioned throughput above included baseline", rate, extra, 1, hoursPerMonth, true)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func readIPv4Cost(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, usage cloudquote.UsageV1) (cloudquote.CostItemV1, error) {
	if !candidate.PublicIPv4 {
		return zeroCost(cloudquote.CostPublicIPv4, "no public IPv4 requested", sourceIdentifier("estimate", "none", "ipv4", string(candidate.CandidateID))), nil
	}
	rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonVPC", unit: "Hrs", filters: map[string]string{
		"regionCode": region, "group": "VPCPublicIPv4Address",
	}})
	if err != nil {
		return cloudquote.CostItemV1{}, fmt.Errorf("public IPv4: %w", err)
	}
	hourly, err := scaleMicros(rate.unitMicros, uint64(candidate.InstanceCount), 1)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	monthly, err := scaleMicros(hourly, uint64(usage.PublicIPv4Hours), 1)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	return cloudquote.CostItemV1{Category: cloudquote.CostPublicIPv4, Description: "public IPv4 address hours", SourceID: rate.sourceID, HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: hourly}, nil
}

func readPrivateEndpointCosts(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, usage cloudquote.UsageV1) ([]cloudquote.CostItemV1, error) {
	if len(candidate.PrivateEndpoints) == 0 {
		return nil, nil
	}
	if len(candidate.PrivateEndpoints) > 4 {
		return nil, errors.New("private endpoint pricing scope exceeds the supported limit")
	}

	var pricedCount, totalHours, totalData uint64
	label := ""
	for _, endpoint := range candidate.PrivateEndpoints {
		endpointLabel := ""
		switch {
		case endpoint.EndpointType == cloudquote.PrivateEndpointTypeGateway && endpoint.Service == cloudquote.PrivateEndpointServiceS3:
			if endpoint.MonthlyHours != 0 || endpoint.DataMiBPerMonth != 0 {
				return nil, errors.New("S3 Gateway endpoint pricing usage must be zero")
			}
			continue
		case endpoint.EndpointType == cloudquote.PrivateEndpointTypeInterface && endpoint.Service == cloudquote.PrivateEndpointServiceSecretsManager:
			if endpoint.MonthlyHours == 0 || endpoint.MonthlyHours > 744 || endpoint.DataMiBPerMonth == 0 || endpoint.DataMiBPerMonth > 1<<50 {
				return nil, errors.New("Secrets Manager Interface endpoint pricing usage is invalid")
			}
			endpointLabel = "Secrets Manager Interface endpoint"
		case endpoint.EndpointType == "" && endpoint.Service == cloudquote.PrivateEndpointServiceS3:
			if endpoint.MonthlyHours == 0 || endpoint.MonthlyHours > 744 || endpoint.DataMiBPerMonth > 1<<50 {
				return nil, errors.New("legacy S3 Interface endpoint pricing usage is invalid")
			}
			endpointLabel = "S3 Interface endpoint"
		default:
			return nil, errors.New("private endpoint pricing scope is unsupported")
		}

		var err error
		pricedCount++
		totalHours, err = checkedSum(totalHours, uint64(endpoint.MonthlyHours))
		if err != nil {
			return nil, err
		}
		totalData, err = checkedSum(totalData, endpoint.DataMiBPerMonth)
		if err != nil {
			return nil, err
		}
		if label == "" {
			label = endpointLabel
		} else if label != endpointLabel {
			label = "Interface VPC endpoint"
		}
	}
	if pricedCount == 0 {
		return nil, nil
	}

	filters := map[string]string{
		"regionCode": region, "productFamily": "VpcEndpoint", "group": "VPCE:VpcEndpoint", "operation": "VpcEndpoint",
	}
	hourlyRate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonVPC", unit: "Hrs", filters: filters})
	if err != nil {
		return nil, fmt.Errorf("Interface VPC endpoint hours: %w", err)
	}
	dataRate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonVPC", unit: "GB", filters: filters})
	if err != nil {
		return nil, fmt.Errorf("Interface VPC endpoint data: %w", err)
	}
	hourly, err := scaleMicros(hourlyRate.unitMicros, pricedCount, 1)
	if err != nil {
		return nil, err
	}
	monthly, err := scaleMicros(hourlyRate.unitMicros, totalHours, 1)
	if err != nil {
		return nil, err
	}
	data, err := monthlyCost(cloudquote.CostPrivateEndpoint, label+" data processed", dataRate, totalData, 1024, runtimeDenominator(usage), false)
	if err != nil {
		return nil, err
	}
	return []cloudquote.CostItemV1{
		{
			Category: cloudquote.CostPrivateEndpoint, Description: label + " hours", SourceID: hourlyRate.sourceID,
			HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: hourly,
		},
		data,
	}, nil
}

func readLogCosts(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, usage cloudquote.UsageV1) ([]cloudquote.CostItemV1, error) {
	items := make([]cloudquote.CostItemV1, 0, 2)
	if usage.LogIngestMiB > 0 {
		rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonCloudWatch", unit: "GB", filters: map[string]string{
			"regionCode": region, "productFamily": "Data Payload", "group": "Ingested Logs",
		}})
		if err != nil {
			return nil, fmt.Errorf("CloudWatch log ingestion: %w", err)
		}
		item, err := monthlyCost(cloudquote.CostLogs, "CloudWatch Logs ingestion", rate, usage.LogIngestMiB, 1024, runtimeDenominator(usage), false)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if usage.LogStoredMiBMonths > 0 {
		rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonCloudWatch", unit: "GB-Mo", filters: map[string]string{
			"regionCode": region, "productFamily": "Storage Snapshot", "group": "Amazon CloudWatch Standard Storage pricing current",
		}})
		if err != nil {
			return nil, fmt.Errorf("CloudWatch log storage: %w", err)
		}
		item, err := monthlyCost(cloudquote.CostLogs, "CloudWatch Logs storage", rate, usage.LogStoredMiBMonths, 1024, hoursPerMonth, true)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		items = append(items, zeroCost(cloudquote.CostLogs, "no CloudWatch log usage requested", sourceIdentifier("estimate", "none", "logs", string(candidate.CandidateID))))
	}
	return items, nil
}

func readSnapshotCost(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, usage cloudquote.UsageV1) (cloudquote.CostItemV1, error) {
	if usage.SnapshotGiBMonths == 0 {
		return zeroCost(cloudquote.CostSnapshot, "no EBS snapshot usage requested", sourceIdentifier("estimate", "none", "snapshot", string(candidate.CandidateID))), nil
	}
	rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "GB-Mo", filters: map[string]string{
		"regionCode": region, "productFamily": "Storage Snapshot",
	}})
	if err != nil {
		return cloudquote.CostItemV1{}, fmt.Errorf("EBS snapshot: %w", err)
	}
	return monthlyCost(cloudquote.CostSnapshot, "EBS snapshot storage", rate, usage.SnapshotGiBMonths, 1, hoursPerMonth, true)
}

func readEntryCosts(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, usage cloudquote.UsageV1) ([]cloudquote.CostItemV1, error) {
	switch candidate.EntryPoint {
	case cloudquote.EntryPointNone:
		return []cloudquote.CostItemV1{zeroCost(cloudquote.CostEntry, "no public entry infrastructure requested", sourceIdentifier("estimate", "none", "entry", string(candidate.CandidateID)))}, nil
	case cloudquote.EntryPointALB:
		fixed, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "Hrs", filters: map[string]string{
			"regionCode": region, "productFamily": "Load Balancer", "group": "ELB:Application",
		}})
		if err != nil {
			return nil, fmt.Errorf("ALB hours: %w", err)
		}
		capacity, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonEC2", unit: "LCU-Hrs", filters: map[string]string{
			"regionCode": region, "productFamily": "Load Balancer", "group": "ELB:Application",
		}})
		if err != nil {
			return nil, fmt.Errorf("ALB LCU: %w", err)
		}
		fixedItem, err := hourlyUsageCost(cloudquote.CostEntry, "Application Load Balancer hours", fixed, usage.EntryHours)
		if err != nil {
			return nil, err
		}
		capacityItem, err := hourlyUsageCost(cloudquote.CostEntry, "Application Load Balancer one-LCU estimate", capacity, usage.EntryHours)
		if err != nil {
			return nil, err
		}
		return []cloudquote.CostItemV1{fixedItem, capacityItem}, nil
	case cloudquote.EntryPointCloudFront:
		rate, err := catalog.rate(ctx, rateSpec{serviceCode: "AmazonCloudFront", unit: "10K Requests", filters: map[string]string{
			"productFamily": "Request", "requestType": "CloudFront-Request-Tier2",
		}})
		if err != nil {
			return nil, fmt.Errorf("CloudFront requests: %w", err)
		}
		item, err := monthlyCost(cloudquote.CostEntry, "CloudFront HTTPS request estimate", rate, usage.InternetEgressMiB, 10_000, runtimeDenominator(usage), false)
		if err != nil {
			return nil, err
		}
		return []cloudquote.CostItemV1{item}, nil
	default:
		return nil, errors.New("unsupported entry point")
	}
}

func readTrafficCost(ctx context.Context, catalog *priceCatalog, region string, candidate cloudquote.PricingCandidateQueryV1, usage cloudquote.UsageV1) (cloudquote.CostItemV1, error) {
	if usage.InternetEgressMiB == 0 {
		return zeroCost(cloudquote.CostTraffic, "no internet egress requested", sourceIdentifier("estimate", "none", "traffic", string(candidate.CandidateID))), nil
	}
	spec := rateSpec{serviceCode: "AmazonEC2", unit: "GB", filters: map[string]string{
		"regionCode": region, "productFamily": "Data Transfer", "transferType": "AWS Outbound",
	}}
	description := "EC2 internet data transfer"
	if candidate.EntryPoint == cloudquote.EntryPointCloudFront {
		spec = rateSpec{serviceCode: "AmazonCloudFront", unit: "GB", filters: map[string]string{
			"productFamily": "Data Transfer", "transferType": "CloudFront Outbound", "toLocation": "External",
		}}
		description = "CloudFront internet data transfer"
	}
	rate, err := catalog.rate(ctx, spec)
	if err != nil {
		return cloudquote.CostItemV1{}, fmt.Errorf("internet traffic: %w", err)
	}
	return monthlyCost(cloudquote.CostTraffic, description, rate, usage.InternetEgressMiB, 1024, runtimeDenominator(usage), false)
}

func hourlyUsageCost(category cloudquote.CostCategory, description string, rate catalogRate, hours uint32) (cloudquote.CostItemV1, error) {
	monthly, err := scaleMicros(rate.unitMicros, uint64(hours), 1)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	return cloudquote.CostItemV1{Category: category, Description: description, SourceID: rate.sourceID, HourlyEstimateMicros: rate.unitMicros, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: rate.unitMicros}, nil
}

func monthlyCost(category cloudquote.CostCategory, description string, rate catalogRate, numerator, denominator, hourlyDenominator uint64, launchMonthly bool) (cloudquote.CostItemV1, error) {
	monthly, err := scaleMicros(rate.unitMicros, numerator, denominator)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	hourly, err := scaleMicros(monthly, 1, hourlyDenominator)
	if err != nil {
		return cloudquote.CostItemV1{}, err
	}
	launch := hourly
	if launchMonthly {
		launch = monthly
	}
	return cloudquote.CostItemV1{Category: category, Description: description, SourceID: rate.sourceID, HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: launch}, nil
}

func zeroCost(category cloudquote.CostCategory, description, source string) cloudquote.CostItemV1 {
	return cloudquote.CostItemV1{Category: category, Description: description, SourceID: source}
}

func runtimeDenominator(usage cloudquote.UsageV1) uint64 {
	if usage.RuntimeHoursPerMonth == 0 {
		return hoursPerMonth
	}
	return uint64(usage.RuntimeHoursPerMonth)
}

func checkedProduct(left, right uint64) (uint64, error) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, errors.New("pricing quantity overflows uint64")
	}
	return left * right, nil
}

func checkedSum(left, right uint64) (uint64, error) {
	if right > ^uint64(0)-left {
		return 0, errors.New("pricing quantity overflows uint64")
	}
	return left + right, nil
}
