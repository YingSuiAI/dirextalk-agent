package awsprovider

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestTeamComputePricingProviderBuildsReadOnlyEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 11, 0, 0, 0, time.UTC)
	ec2Client := &fakePricingEC2{
		now: now,
		vcpus: map[string]int32{
			"m7i.large": 2, "m7i.xlarge": 4,
		},
		memoryMiB: map[string]int64{
			"m7i.large": 8192, "m7i.xlarge": 16384,
		},
	}
	pricing, err := NewPricingProvider(fakePricingFactory{
		clients: PricingReadClients{
			EC2:           ec2Client,
			PriceList:     &fakePriceList{},
			ServiceQuotas: &fakeServiceQuotas{},
			CloudWatch:    &fakeQuotaCloudWatch{},
		},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewTeamComputePricingProvider(
		pricing,
		"us-east-1",
		[]string{"us-east-1b", "us-east-1a"},
		[]TeamComputeShape{
			{
				InstanceType: "m7i.xlarge",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      40,
			},
			{
				InstanceType: "m7i.large",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      20,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence, err := provider.ReadComputeOffers(
		context.Background(),
		"us-east-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Currency != "USD" ||
		len(evidence.Sources) != 2 ||
		len(evidence.Offers) != 2 {
		t.Fatalf("evidence = %#v", evidence)
	}
	first := evidence.Offers[0]
	if first.InstanceType != "m7i.large" ||
		first.VCPU != 2 ||
		first.MemoryMiB != 8192 ||
		first.DiskGiB != 20 ||
		first.HourlyMicros != 1_002_740 ||
		first.PurchaseOption != "on_demand" ||
		first.CapacityPool != "aws:ec2-quota:L-1216C47A" ||
		first.CapacityUnits != 2 ||
		first.AvailableUnits != 64 ||
		!first.Available {
		t.Fatalf("first offer = %#v", first)
	}
	if evidence.Offers[1].InstanceType != "m7i.xlarge" ||
		evidence.Offers[1].HourlyMicros != 1_005_479 ||
		evidence.Offers[1].CapacityPool != first.CapacityPool ||
		evidence.Offers[1].CapacityUnits != 4 {
		t.Fatalf("second offer = %#v", evidence.Offers[1])
	}
	for _, source := range evidence.Sources {
		if !strings.HasPrefix(source.Digest, "sha256:") ||
			len(source.Digest) != 71 ||
			!source.CapturedAt.Equal(now) {
			t.Fatalf("source receipt = %#v", source)
		}
	}
	if evidence.Sources[0].Kind != teamplan.OfferSourceComputePricing ||
		evidence.Sources[1].Kind != teamplan.OfferSourceComputeCapacity {
		t.Fatalf("source kinds = %#v", evidence.Sources)
	}
	if ec2Client.offeringCalls != 2 ||
		ec2Client.instanceTypeCalls != 2 ||
		ec2Client.spotCalls != 0 {
		t.Fatalf(
			"unexpected EC2 reads: offerings=%d types=%d spot=%d",
			ec2Client.offeringCalls,
			ec2Client.instanceTypeCalls,
			ec2Client.spotCalls,
		)
	}
}

func TestTeamComputePricingProviderNormalizesTrustedInput(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 11, 0, 0, 0, time.UTC)
	newPricing := func() *PricingProvider {
		value, err := NewPricingProvider(fakePricingFactory{
			clients: PricingReadClients{
				EC2: &fakePricingEC2{
					now: now,
					vcpus: map[string]int32{
						"m7i.large": 2, "m7i.xlarge": 4,
					},
				},
				PriceList:     &fakePriceList{},
				ServiceQuotas: &fakeServiceQuotas{},
				CloudWatch:    &fakeQuotaCloudWatch{},
			},
		}, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	left, err := NewTeamComputePricingProvider(
		newPricing(),
		"us-east-1",
		[]string{"us-east-1a", "us-east-1b"},
		[]TeamComputeShape{
			{
				InstanceType: "m7i.large",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      20,
			},
			{
				InstanceType: "m7i.xlarge",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      40,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewTeamComputePricingProvider(
		newPricing(),
		"us-east-1",
		[]string{"us-east-1b", "us-east-1a"},
		[]TeamComputeShape{
			{
				InstanceType: "m7i.xlarge",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      40,
			},
			{
				InstanceType: "m7i.large",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      20,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	leftEvidence, err := left.ReadComputeOffers(
		context.Background(),
		"us-east-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	rightEvidence, err := right.ReadComputeOffers(
		context.Background(),
		"us-east-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftEvidence, rightEvidence) {
		t.Fatalf("normalized evidence differs:\n%#v\n%#v", leftEvidence, rightEvidence)
	}
}

func TestTeamComputePricingProviderRejectsUntrustedScope(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 11, 0, 0, 0, time.UTC)
	pricing, err := NewPricingProvider(fakePricingFactory{
		clients: PricingReadClients{
			EC2: &fakePricingEC2{
				now: now,
				vcpus: map[string]int32{
					"m7i.large": 2,
				},
			},
			PriceList:     &fakePriceList{},
			ServiceQuotas: &fakeServiceQuotas{},
			CloudWatch:    &fakeQuotaCloudWatch{},
		},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	shape := TeamComputeShape{
		InstanceType: "m7i.large",
		Architecture: recipe.ArchitectureAMD64,
		DiskGiB:      20,
	}
	if _, err := NewTeamComputePricingProvider(
		pricing,
		"us-east-1",
		[]string{"us-east-1a"},
		[]TeamComputeShape{shape, shape},
	); !errors.Is(err, ErrInvalidTeamComputePricing) {
		t.Fatalf("duplicate shape error = %v", err)
	}
	provider, err := NewTeamComputePricingProvider(
		pricing,
		"us-east-1",
		[]string{"us-east-1a"},
		[]TeamComputeShape{shape},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ReadComputeOffers(
		context.Background(),
		"us-west-2",
	); !errors.Is(err, ErrInvalidTeamComputePricing) {
		t.Fatalf("Region drift error = %v", err)
	}
}
