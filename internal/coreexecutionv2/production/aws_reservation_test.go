package production

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
)

type reservationEC2Fake struct {
	pages int
}

func (f *reservationEC2Fake) DescribeInstanceTypeOfferings(_ context.Context, in *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	page := 0
	if aws.ToString(in.NextToken) != "" {
		page, _ = strconv.Atoi(aws.ToString(in.NextToken))
	}
	var next *string
	if f.pages > 0 && page+1 < f.pages {
		next = aws.String(strconv.Itoa(page + 1))
	}
	return &ec2.DescribeInstanceTypeOfferingsOutput{
		InstanceTypeOfferings: []ec2types.InstanceTypeOffering{{InstanceType: ec2types.InstanceType("t3.small"), Location: aws.String("us-east-1a"), LocationType: ec2types.LocationTypeAvailabilityZone}},
		NextToken:             next,
	}, nil
}

func (f *reservationEC2Fake) DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	return &ec2.DescribeInstanceTypesOutput{InstanceTypes: []ec2types.InstanceTypeInfo{{
		InstanceType:  ec2types.InstanceType("t3.small"),
		ProcessorInfo: &ec2types.ProcessorInfo{SupportedArchitectures: []ec2types.ArchitectureType{ec2types.ArchitectureTypeX8664}},
		VCpuInfo:      &ec2types.VCpuInfo{DefaultVCpus: aws.Int32(2)},
		MemoryInfo:    &ec2types.MemoryInfo{SizeInMiB: aws.Int64(2048)},
	}}}, nil
}

type reservationPricingFake struct {
	duplicate bool
	compute   int
	storage   int
}

func (f *reservationPricingFake) GetProducts(_ context.Context, in *pricing.GetProductsInput, _ ...func(*pricing.Options)) (*pricing.GetProductsOutput, error) {
	attributes := map[string]string{}
	for _, filter := range in.Filters {
		attributes[aws.ToString(filter.Field)] = aws.ToString(filter.Value)
	}
	if attributes["volumeApiName"] == "gp3" {
		f.storage++
		price := storagePrice("0.08")
		return &pricing.GetProductsOutput{FormatVersion: aws.String("aws_v1"), PriceList: []string{price}}, nil
	}
	f.compute++
	prices := []string{computePrice("0.02")}
	if f.duplicate {
		prices = append(prices, computePrice("0.03"))
	}
	return &pricing.GetProductsOutput{FormatVersion: aws.String("aws_v1"), PriceList: prices}, nil
}

type reservationFactoryFake struct {
	ec2     EC2ReservationClient
	pricing PricingClient
}

func (f reservationFactoryFake) NewEC2Reservation(workaws.CredentialHandle) (EC2ReservationClient, error) {
	return f.ec2, nil
}
func (f reservationFactoryFake) NewPricing(workaws.CredentialHandle) (PricingClient, error) {
	return f.pricing, nil
}

func reservationCredential() workaws.CredentialHandle {
	return workaws.CredentialHandle{
		ReferenceID:     productionCred,
		Region:          "us-east-1",
		AccountID:       "123456789012",
		PrincipalARN:    "arn:aws:iam::123456789012:role/execution",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
	}
}

func computePrice(value string) string {
	return priceDocumentJSON(map[string]string{
		"instanceType":    "t3.small",
		"operatingSystem": "Linux",
		"tenancy":         "Shared",
		"preInstalledSw":  "NA",
		"capacitystatus":  "Used",
		"regionCode":      "us-east-1",
	}, "Compute Instance", "Hrs", value)
}

func storagePrice(value string) string {
	return priceDocumentJSON(map[string]string{"volumeApiName": "gp3", "regionCode": "us-east-1"}, "Storage", "GB-Mo", value)
}

func priceDocumentJSON(attributes map[string]string, family, unit, amount string) string {
	productAttributes := map[string]string{}
	for key, value := range attributes {
		productAttributes[key] = value
	}
	value := map[string]any{
		"product": map[string]any{"productFamily": family, "attributes": productAttributes},
		"terms": map[string]any{"OnDemand": map[string]any{"term": map[string]any{"priceDimensions": map[string]any{"dimension": map[string]any{
			"unit": unit, "pricePerUnit": map[string]string{"USD": amount},
		}}}}},
	}
	b, _ := json.Marshal(value)
	return string(b)
}

func TestAWSReservationCatalogContract(t *testing.T) {
	pricingClient := &reservationPricingFake{}
	catalog := NewAWSReservationCatalog(reservationFactoryFake{ec2: &reservationEC2Fake{}, pricing: pricingClient}, fixedNow)
	offer, err := catalog.ResolveReservation(context.Background(), reservationCredential(), "t3.small", 20)
	if err != nil {
		t.Fatal(err)
	}
	if offer.InstanceType != "t3.small" || offer.AvailabilityZone != "us-east-1a" || offer.Architecture != "x86_64" || offer.ManagementTransport != "aws_ssm" || !offer.PublicIP || offer.PublicInbound || offer.CostCurrency != "USD" || offer.CostAmount == "" {
		t.Fatalf("unexpected offer: %+v", offer)
	}
	if pricingClient.compute != 1 || pricingClient.storage != 1 {
		t.Fatalf("unexpected pricing calls: compute=%d storage=%d", pricingClient.compute, pricingClient.storage)
	}
}

func TestAWSReservationCatalogRejectsAmbiguousOrUnboundedReads(t *testing.T) {
	duplicatePricing := &reservationPricingFake{duplicate: true}
	duplicate := NewAWSReservationCatalog(reservationFactoryFake{ec2: &reservationEC2Fake{}, pricing: duplicatePricing}, fixedNow)
	if _, err := duplicate.ResolveReservation(context.Background(), reservationCredential(), "t3.small", 20); !errors.Is(err, ErrReservationCatalogUnavailable) {
		t.Fatalf("duplicate pricing err=%v", err)
	}
	tooManyPages := NewAWSReservationCatalog(reservationFactoryFake{ec2: &reservationEC2Fake{pages: 6}, pricing: &reservationPricingFake{}}, fixedNow)
	if _, err := tooManyPages.ResolveReservation(context.Background(), reservationCredential(), "t3.small", 20); !errors.Is(err, ErrReservationCatalogUnavailable) {
		t.Fatalf("unbounded offerings err=%v", err)
	}
}

func TestAWSReservationCatalogRejectsUnsupportedPricingRegion(t *testing.T) {
	credential := reservationCredential()
	credential.Region = "us-gov-west-1"
	catalog := NewAWSReservationCatalog(reservationFactoryFake{ec2: &reservationEC2Fake{}, pricing: &reservationPricingFake{}}, fixedNow)
	if _, err := catalog.ResolveReservation(context.Background(), credential, "t3.small", 20); !errors.Is(err, ErrReservationCatalogUnavailable) {
		t.Fatalf("unsupported pricing region err=%v", err)
	}
}

func fixedNow() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
