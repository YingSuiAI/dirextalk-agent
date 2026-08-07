package cloudworker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProductionQuoterUsesFreshBoundCatalogAndHardMaximum(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	catalog := &pricingCatalogFake{now: &now, rates: PricingCatalogRates{
		ComputeMicrosPerHour: 3_600_000, EBSStorageMicrosPerGiBMonth: 1_000,
		EBSIOPSMicrosPerMonth: 2, EBSThroughputMicrosPerMonth: 10,
		PublicIPv4MicrosPerHour: 360_000, ModelMicrosPerThousandTokens: 1_000,
		FixedRequestOverheadMicros: 100,
	}}
	quoter, err := NewProductionQuoter(catalog, ProductionQuoterConfig{QuoteTTL: 5 * time.Minute, MaximumCatalogAge: time.Minute,
		CleanupReserveSeconds: 600, ContingencyBasisPoints: 2_000, AbsoluteHardLimitMicros: 10_000_000}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := productionQuoteRequest()
	quote, err := quoter.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if quote.AmountMicros != 4_622_157 || quote.MaximumAuthorizedCostMicros != 5_546_589 || quote.Currency != "USD" ||
		quote.SourceTime != now || quote.ExpiresAt != now.Add(5*time.Minute) || quote.BasisDigest != request.AuthorizationBasisDigest || !validDigest(quote.Digest) {
		t.Fatalf("unexpected production quote: %+v", quote)
	}
	if catalog.calls != 1 || catalog.last.AccountID != request.AWS.AccountID || catalog.last.Region != request.AWS.Region ||
		catalog.last.InstanceType != request.Compute.InstanceType || catalog.last.MaxRuntimeSeconds != request.Limits.MaxRuntimeSeconds ||
		catalog.last.MaxTokens != request.Limits.MaxTokens || catalog.last.BasisDigest != request.AuthorizationBasisDigest {
		t.Fatalf("catalog request was not fully bound: %+v", catalog.last)
	}

	catalog.rates.ComputeMicrosPerHour++
	now = now.Add(10 * time.Second)
	requoted, err := quoter.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if requoted.AmountMicros == quote.AmountMicros || requoted.Digest == quote.Digest || catalog.calls != 2 {
		t.Fatalf("price drift did not force a fresh quote: old=%+v new=%+v calls=%d", quote, requoted, catalog.calls)
	}
}

func TestProductionQuoterFailsClosedOnStaleDriftAndHardLimit(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	request := productionQuoteRequest()
	config := ProductionQuoterConfig{QuoteTTL: time.Minute, MaximumCatalogAge: 30 * time.Second, CleanupReserveSeconds: EphemeralCleanupReserveSeconds,
		ContingencyBasisPoints: 1_000, AbsoluteHardLimitMicros: 10_000_000}
	rates := PricingCatalogRates{ComputeMicrosPerHour: 1_000_000, EBSStorageMicrosPerGiBMonth: 1_000,
		PublicIPv4MicrosPerHour: 10_000, ModelMicrosPerThousandTokens: 1_000}

	for _, test := range []struct {
		name   string
		mutate func(*pricingCatalogFake, *ProductionQuoterConfig)
	}{
		{name: "stale source", mutate: func(catalog *pricingCatalogFake, _ *ProductionQuoterConfig) { catalog.sourceOffset = -time.Minute }},
		{name: "request drift", mutate: func(catalog *pricingCatalogFake, _ *ProductionQuoterConfig) {
			catalog.requestDigestOverride = digestValue("foreign")
		}},
		{name: "revision drift", mutate: func(catalog *pricingCatalogFake, _ *ProductionQuoterConfig) {
			catalog.revisionOverride = digestValue("foreign")
		}},
		{name: "hard maximum", mutate: func(_ *pricingCatalogFake, config *ProductionQuoterConfig) { config.AbsoluteHardLimitMicros = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := &pricingCatalogFake{now: &now, rates: rates}
			copyConfig := config
			test.mutate(catalog, &copyConfig)
			quoter, err := NewProductionQuoter(catalog, copyConfig, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := quoter.Quote(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe catalog quote = %v", err)
			}
		})
	}
}

func TestProductionQuoterRequotesSamePriceCatalogRevisionDrift(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, _, source := stagingFixture(t, now)
	defer source.Body.Close()
	rates := PricingCatalogRates{
		ComputeMicrosPerHour: 3_600_000, EBSStorageMicrosPerGiBMonth: 1_000,
		EBSIOPSMicrosPerMonth: 2, EBSThroughputMicrosPerMonth: 10,
		PublicIPv4MicrosPerHour: 360_000, ModelMicrosPerThousandTokens: 1_000,
		FixedRequestOverheadMicros: 100,
	}
	catalog := &pricingCatalogFake{now: &now, rates: rates}
	quoter, err := NewProductionQuoter(catalog, ProductionQuoterConfig{QuoteTTL: 5 * time.Minute, MaximumCatalogAge: time.Minute,
		CleanupReserveSeconds: EphemeralCleanupReserveSeconds, ContingencyBasisPoints: 2_000, AbsoluteHardLimitMicros: 10_000_000}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := quoteRequestForPlan(plan)
	first, err := quoter.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote = first
	if err := plan.Seal(); err != nil {
		t.Fatal(err)
	}

	// Change a real catalog rate, then offset the exact aggregate delta in
	// fixed overhead. The price and hard maximum stay byte-identical while the
	// sealed catalog revision changes.
	changed := rates
	changed.ComputeMicrosPerHour--
	before, err := estimateMaximumCost(rates, plan.Compute, plan.Limits, EphemeralCleanupReserveSeconds)
	if err != nil {
		t.Fatal(err)
	}
	after, err := estimateMaximumCost(changed, plan.Compute, plan.Limits, EphemeralCleanupReserveSeconds)
	if err != nil || after > before {
		t.Fatalf("unexpected catalog delta: before=%d after=%d err=%v", before, after, err)
	}
	changed.FixedRequestOverheadMicros += before - after
	catalog.rates = changed
	fresh, err := quoter.Validate(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.AmountMicros != first.AmountMicros || fresh.MaximumAuthorizedCostMicros != first.MaximumAuthorizedCostMicros {
		t.Fatalf("test did not preserve price: first=%+v fresh=%+v", first, fresh)
	}
	if fresh.CatalogRevisionDigest == first.CatalogRevisionDigest || fresh.Digest == first.Digest {
		t.Fatalf("same-price catalog revision drift reused authorization: first=%+v fresh=%+v", first, fresh)
	}
}

func quoteRequestForPlan(plan Plan) QuoteRequest {
	return QuoteRequest{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		ObjectiveDigest: plan.ObjectiveDigest, UserPromptDigest: plan.UserPromptDigest,
		InputManifestDigest: plan.InputManifestDigest, WorkspaceMode: plan.WorkspaceMode,
		ProposalReason: plan.ProposalReason, ModelBindingDigest: plan.ModelAuthorization.BindingDigest,
		AuthorizationBasisDigest: plan.AuthorizationBasisDigest,
		AWS:                      plan.AWS, Compute: plan.Compute, Limits: plan.Limits,
	}
}

func productionQuoteRequest() QuoteRequest {
	return QuoteRequest{
		OwnerID: "owner-1", AccountGeneration: 3, ObjectiveDigest: digestValue("objective"), UserPromptDigest: digestValue("prompt"),
		InputManifestDigest: digestValue("manifest"), WorkspaceMode: WorkspaceWrite, ProposalReason: ProposalReasonExplicitUserCloud,
		ModelBindingDigest: digestValue("model"), AuthorizationBasisDigest: digestValue("basis"),
		AWS: AWSBinding{AccountID: "123456789012", Region: "us-east-1", CredentialID: "11111111-1111-4111-8111-111111111111", CredentialRevision: 7},
		Compute: ComputeSpec{InstanceType: "c7i.large", Architecture: "x86_64", RootDeviceName: "/dev/xvda", VolumeGiB: 32,
			VolumeType: "gp3", VolumeIOPS: 4000, VolumeThroughputMiB: 250, AMIID: "ami-0123456789abcdef0", AMIDigest: digestValue("ami"),
			WorkerReleaseDigest: digestValue("worker"), PiRuntimeDigest: digestValue("pi"), HostNetworkPolicySHA256: digestValue("host-network-policy")},
		Limits: Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20},
	}
}

type pricingCatalogFake struct {
	now                   *time.Time
	rates                 PricingCatalogRates
	sourceOffset          time.Duration
	requestDigestOverride string
	revisionOverride      string
	calls                 int
	last                  PricingCatalogRequest
}

func (catalog *pricingCatalogFake) Snapshot(_ context.Context, request PricingCatalogRequest) (PricingCatalogSnapshot, error) {
	catalog.calls++
	catalog.last = request
	source := catalog.now.UTC().Add(catalog.sourceOffset)
	requestDigest := request.digest()
	if catalog.requestDigestOverride != "" {
		requestDigest = catalog.requestDigestOverride
	}
	snapshot, err := SealPricingCatalogSnapshot(PricingCatalogSnapshot{RequestDigest: requestDigest, SourceTime: source,
		ExpiresAt: source.Add(10 * time.Minute), Rates: catalog.rates})
	if catalog.revisionOverride != "" {
		snapshot.RevisionDigest = catalog.revisionOverride
	}
	return snapshot, err
}

var _ PricingCatalog = (*pricingCatalogFake)(nil)
