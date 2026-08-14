package cloudworker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
)

type livePricingCredential struct {
	handle workaws.CredentialHandle
	calls  int
}

func (resolver *livePricingCredential) ResolveCredentialRevision(_ context.Context, id string, revision uint64) (workaws.CredentialHandle, error) {
	resolver.calls++
	if id != resolver.handle.ReferenceID || revision != 7 {
		return workaws.CredentialHandle{}, workaws.ErrPrecondition
	}
	return resolver.handle, nil
}

type livePricingClient struct{ calls int }

func (client *livePricingClient) GetProducts(_ context.Context, input *pricing.GetProductsInput, _ ...func(*pricing.Options)) (*pricing.GetProductsOutput, error) {
	client.calls++
	attributes := map[string]string{}
	for _, filter := range input.Filters {
		attributes[aws.ToString(filter.Field)] = aws.ToString(filter.Value)
	}
	unit, amount, family := "Hrs", "0.0208", "Compute Instance"
	if attributes["volumeApiName"] == "gp3" {
		unit, amount, family = "GB-Mo", "0.08", "Storage"
	} else if aws.ToString(input.ServiceCode) == "AmazonVPC" && attributes["group"] == "VPCPublicIPv4Address" {
		unit, amount, family = "Hrs", "0.005", ""
	}
	product := map[string]any{
		"product": map[string]any{"productFamily": family, "attributes": attributes},
		"terms": map[string]any{"OnDemand": map[string]any{"term": map[string]any{"priceDimensions": map[string]any{"dimension": map[string]any{
			"unit": unit, "pricePerUnit": map[string]string{"USD": amount},
		}}}}},
	}
	raw, _ := json.Marshal(product)
	return &pricing.GetProductsOutput{PriceList: []string{string(raw)}}, nil
}

type livePricingFactory struct{ client *livePricingClient }

func (factory livePricingFactory) New(workaws.CredentialHandle) (AWSPriceListAPI, error) {
	return factory.client, nil
}

func TestAWSLivePricingCatalogReadsAWSForEveryQuoteWithoutCatalogState(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	credential := &livePricingCredential{handle: workaws.CredentialHandle{
		ReferenceID: "11111111-1111-4111-8111-111111111111", Region: "ap-northeast-1", AccountID: "123456789012",
		PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret",
	}}
	client := &livePricingClient{}
	catalog, err := NewAWSLivePricingCatalog(credential, livePricingFactory{client}, 5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := PricingCatalogRequest{
		AccountID: "123456789012", AccountGeneration: 1, Region: "ap-northeast-1",
		CredentialID: credential.handle.ReferenceID, CredentialRevision: 7,
		InstanceType: "t3.small", Architecture: "x86_64", VolumeGiB: 20, VolumeType: "gp3",
		VolumeIOPS: 3000, VolumeThroughput: 125, MaxRuntimeSeconds: 3600, MaxTokens: 1000,
		BasisDigest: digestValue("basis"), WorkspaceMode: WorkspaceWrite,
	}
	first, err := catalog.Snapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := catalog.Snapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if credential.calls != 2 || client.calls != 6 || first.Rates.ComputeMicrosPerHour != 20_800 || first.Rates.PublicIPv4MicrosPerHour != 5_000 ||
		first.Rates.EBSStorageMicrosPerGiBMonth != 80_000 || first.RevisionDigest != second.RevisionDigest {
		t.Fatalf("credential_calls=%d price_calls=%d first=%+v second=%+v", credential.calls, client.calls, first, second)
	}
}
