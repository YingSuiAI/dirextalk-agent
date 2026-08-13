package main

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
)

type workerStatusPricingCatalog struct {
	snapshot cloudworker.PricingCatalogSnapshot
	request  cloudworker.PricingCatalogRequest
}

func (catalog *workerStatusPricingCatalog) Snapshot(_ context.Context, request cloudworker.PricingCatalogRequest) (cloudworker.PricingCatalogSnapshot, error) {
	catalog.request = request
	return catalog.snapshot, nil
}

func TestSSHWorkerHourlyQuoteUsesLiveInfrastructureRates(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	catalog := &workerStatusPricingCatalog{snapshot: cloudworker.PricingCatalogSnapshot{
		Currency: "USD", SourceTime: now, ExpiresAt: now.Add(5 * time.Minute),
		Rates: cloudworker.PricingCatalogRates{
			ComputeMicrosPerHour: 20_800, EBSStorageMicrosPerGiBMonth: 80_000, PublicIPv4MicrosPerHour: 5_000,
		},
	}}
	executor := &sshWorkerExecutor{pricing: catalog}
	identity := sshworker.CredentialIdentity{CredentialID: "credential-1", CredentialRevision: 7, AccountID: "123456789012", Region: "ap-east-1"}
	quote, err := executor.hourlyQuote(context.Background(), identity, "t3.small", 20)
	if err != nil {
		t.Fatal(err)
	}
	if quote.Currency != "USD" || quote.MicrosPerHour != 27_992 || quote.ObservedAt != now || quote.ExpiresAt != now.Add(5*time.Minute) {
		t.Fatalf("quote=%+v", quote)
	}
	if catalog.request.AccountID != identity.AccountID || catalog.request.Region != identity.Region || catalog.request.CredentialID != identity.CredentialID ||
		catalog.request.CredentialRevision != identity.CredentialRevision || catalog.request.InstanceType != "t3.small" || catalog.request.VolumeGiB != 20 || catalog.request.VolumeType != "gp3" {
		t.Fatalf("pricing request=%+v", catalog.request)
	}
}
