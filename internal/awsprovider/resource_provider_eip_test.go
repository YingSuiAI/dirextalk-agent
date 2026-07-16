package awsprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEC2ResourceProviderResumesElasticIPAfterAllocateResponseLoss(t *testing.T) {
	client := &elasticIPFake{allocationID: "eipalloc-0123456789abcdef0", allocateError: errors.New("response lost")}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, ElasticIP: &resource.AWSElasticIPSpecV1{Domain: "vpc"}}
	digest, err := spec.Digest(resource.TypeEIP)
	if err != nil {
		t.Fatal(err)
	}
	request := resource.ProviderCreateRequest{
		ResourceID: "11111111-1111-4111-8111-111111111111", Type: resource.TypeEIP, LogicalName: "worker-public-ipv4", Region: "us-east-1",
		SpecDigest: digest, ClientToken: "dtx-eip-0123456789", Tags: validResourceTags("11111111-1111-4111-8111-111111111111"), AWS: spec,
		Dependencies: []resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeENI, ProviderID: "eni-0123456789abcdef0"}},
	}
	if _, found, err := provider.FindByClientToken(context.Background(), resource.TypeEIP, request.Region, request.ClientToken); err != nil || found {
		t.Fatalf("unallocated address unexpectedly discovered: found=%v err=%v", found, err)
	}
	if _, err := client.AllocateAddress(context.Background(), &ec2.AllocateAddressInput{
		Domain:            ec2types.DomainTypeVpc,
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeElasticIp, Tags: ec2Tags(provider.readyTags(request))}},
	}); err == nil {
		t.Fatal("simulated AllocateAddress response loss did not occur")
	}
	if _, found, err := provider.FindByClientToken(context.Background(), resource.TypeEIP, request.Region, request.ClientToken); !errors.Is(err, resource.ErrReadBack) || found {
		t.Fatalf("unassociated billable address was reported absent: found=%v err=%v", found, err)
	}
	candidates, err := provider.FindAllByClientToken(context.Background(), resource.TypeEIP, request.Region, request.ClientToken)
	if err != nil || len(candidates) != 1 || candidates[0].ProviderID != client.allocationID {
		t.Fatalf("lost allocation candidate=%#v err=%v", candidates, err)
	}
	observed, err := provider.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.Exists || observed.ProviderID != client.allocationID || client.allocateCalls != 1 || client.associateCalls != 1 {
		t.Fatalf("lost allocation response was not resumed exactly once: observed=%#v allocate=%d associate=%d", observed, client.allocateCalls, client.associateCalls)
	}
	if client.address == nil || aws.ToString(client.address.NetworkInterfaceId) != request.Dependencies[0].ProviderID || aws.ToString(client.address.AssociationId) == "" {
		t.Fatalf("Elastic IP was not bound to the approved ENI: %#v", client.address)
	}
	if _, found, err := provider.FindByClientToken(context.Background(), resource.TypeEIP, request.Region, request.ClientToken); err != nil || !found {
		t.Fatalf("associated address was not discoverable after recovery: found=%v err=%v", found, err)
	}
}

type elasticIPFake struct {
	EC2ResourceAPI
	allocationID   string
	allocateError  error
	allocateCalls  int
	associateCalls int
	address        *ec2types.Address
}

func (fake *elasticIPFake) AllocateAddress(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
	fake.allocateCalls++
	fake.address = &ec2types.Address{AllocationId: aws.String(fake.allocationID), Domain: input.Domain}
	if len(input.TagSpecifications) == 1 {
		fake.address.Tags = append([]ec2types.Tag(nil), input.TagSpecifications[0].Tags...)
	}
	return nil, fake.allocateError
}

func (fake *elasticIPFake) AssociateAddress(_ context.Context, input *ec2.AssociateAddressInput, _ ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error) {
	fake.associateCalls++
	if fake.address == nil || aws.ToString(input.AllocationId) != fake.allocationID || aws.ToBool(input.AllowReassociation) {
		return nil, errors.New("unexpected association")
	}
	fake.address.NetworkInterfaceId = input.NetworkInterfaceId
	fake.address.AssociationId = aws.String("eipassoc-0123456789abcdef0")
	return &ec2.AssociateAddressOutput{AssociationId: fake.address.AssociationId}, nil
}

func (fake *elasticIPFake) DescribeAddresses(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if fake.address == nil {
		return &ec2.DescribeAddressesOutput{}, nil
	}
	if len(input.AllocationIds) > 0 && (len(input.AllocationIds) != 1 || input.AllocationIds[0] != fake.allocationID) {
		return &ec2.DescribeAddressesOutput{}, nil
	}
	if len(input.Filters) > 0 && !matchesFilters(fake.address.Tags, input.Filters) {
		return &ec2.DescribeAddressesOutput{}, nil
	}
	return &ec2.DescribeAddressesOutput{Addresses: []ec2types.Address{*fake.address}}, nil
}
