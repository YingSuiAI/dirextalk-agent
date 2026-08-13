package cloudworker

import (
	"context"
	"errors"
	"math"
	"time"
)

const (
	pricingHoursPerMonth                  = uint64(730)
	EphemeralCleanupReserveSeconds uint64 = 600
)

// PricingCatalog is a production read-only seam. Implementations may read AWS
// Price List plus a protected model-price catalog, but must return a sealed,
// request-bound snapshot. An unavailable or stale catalog always fails closed.
type PricingCatalog interface {
	Snapshot(context.Context, PricingCatalogRequest) (PricingCatalogSnapshot, error)
}

type PricingCatalogRequest struct {
	AccountID          string        `json:"account_id"`
	AccountGeneration  uint64        `json:"account_generation"`
	Region             string        `json:"region"`
	CredentialID       string        `json:"credential_id"`
	CredentialRevision uint64        `json:"credential_revision"`
	InstanceType       string        `json:"instance_type"`
	Architecture       string        `json:"architecture"`
	VolumeGiB          uint64        `json:"volume_gib"`
	VolumeType         string        `json:"volume_type"`
	VolumeIOPS         uint64        `json:"volume_iops"`
	VolumeThroughput   uint64        `json:"volume_throughput_mib"`
	MaxRuntimeSeconds  uint64        `json:"max_runtime_seconds"`
	MaxTokens          uint64        `json:"max_tokens"`
	BasisDigest        string        `json:"basis_digest"`
	WorkspaceMode      WorkspaceMode `json:"workspace_mode"`
}

func (request PricingCatalogRequest) digest() string { return digestValue(request) }

type PricingCatalogRates struct {
	ComputeMicrosPerHour         uint64 `json:"compute_micros_per_hour"`
	EBSStorageMicrosPerGiBMonth  uint64 `json:"ebs_storage_micros_per_gib_month"`
	EBSIOPSMicrosPerMonth        uint64 `json:"ebs_iops_micros_per_month"`
	EBSThroughputMicrosPerMonth  uint64 `json:"ebs_throughput_micros_per_month"`
	PublicIPv4MicrosPerHour      uint64 `json:"public_ipv4_micros_per_hour"`
	ModelMicrosPerThousandTokens uint64 `json:"model_micros_per_thousand_tokens"`
	FixedRequestOverheadMicros   uint64 `json:"fixed_request_overhead_micros"`
}

type PricingCatalogSnapshot struct {
	RequestDigest  string              `json:"request_digest"`
	RevisionDigest string              `json:"revision_digest"`
	Currency       string              `json:"currency"`
	SourceTime     time.Time           `json:"source_time"`
	ExpiresAt      time.Time           `json:"expires_at"`
	Rates          PricingCatalogRates `json:"rates"`
}

func SealPricingCatalogSnapshot(snapshot PricingCatalogSnapshot) (PricingCatalogSnapshot, error) {
	snapshot.Currency = "USD"
	snapshot.SourceTime = snapshot.SourceTime.UTC()
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	if !validDigest(snapshot.RequestDigest) || snapshot.SourceTime.IsZero() || !snapshot.ExpiresAt.After(snapshot.SourceTime) ||
		snapshot.Rates.ComputeMicrosPerHour == 0 || snapshot.Rates.EBSStorageMicrosPerGiBMonth == 0 {
		return PricingCatalogSnapshot{}, ErrInvalid
	}
	snapshot.RevisionDigest = ""
	snapshot.RevisionDigest = digestValue(snapshot)
	return snapshot, nil
}

func (snapshot PricingCatalogSnapshot) validate(request PricingCatalogRequest, now time.Time, maximumAge time.Duration) error {
	sealed, err := SealPricingCatalogSnapshot(PricingCatalogSnapshot{
		RequestDigest: snapshot.RequestDigest, Currency: snapshot.Currency, SourceTime: snapshot.SourceTime,
		ExpiresAt: snapshot.ExpiresAt, Rates: snapshot.Rates,
	})
	now = now.UTC()
	if err != nil || snapshot.Currency != "USD" || snapshot.RequestDigest != request.digest() || snapshot.RevisionDigest != sealed.RevisionDigest ||
		snapshot.SourceTime != snapshot.SourceTime.UTC() || snapshot.ExpiresAt != snapshot.ExpiresAt.UTC() || now.Before(snapshot.SourceTime) {
		return ErrInvalid
	}
	if now.Sub(snapshot.SourceTime) > maximumAge || !now.Before(snapshot.ExpiresAt) {
		return ErrPricingCatalogStale
	}
	return nil
}

type ProductionQuoterConfig struct {
	QuoteTTL                time.Duration
	MaximumCatalogAge       time.Duration
	CleanupReserveSeconds   uint64
	ContingencyBasisPoints  uint32
	AbsoluteHardLimitMicros int64
}

func (config ProductionQuoterConfig) validate() error {
	if config.QuoteTTL <= 0 || config.QuoteTTL > 15*time.Minute || config.MaximumCatalogAge <= 0 || config.MaximumCatalogAge > 15*time.Minute ||
		config.CleanupReserveSeconds != EphemeralCleanupReserveSeconds || config.ContingencyBasisPoints > 10_000 ||
		config.AbsoluteHardLimitMicros <= 0 {
		return ErrInvalid
	}
	return nil
}

type ProductionQuoter struct {
	catalog PricingCatalog
	config  ProductionQuoterConfig
	now     func() time.Time
}

func NewProductionQuoter(catalog PricingCatalog, config ProductionQuoterConfig, clocks ...func() time.Time) (*ProductionQuoter, error) {
	if catalog == nil || config.validate() != nil {
		return nil, ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &ProductionQuoter{catalog: catalog, config: config, now: clock}, nil
}

func (quoter *ProductionQuoter) Quote(ctx context.Context, request QuoteRequest) (Quote, error) {
	if quoter == nil || ctx == nil {
		return Quote{}, ErrInvalid
	}
	return quoter.quote(ctx, request)
}

func (quoter *ProductionQuoter) Validate(ctx context.Context, plan Plan) (Quote, error) {
	if quoter == nil || ctx == nil {
		return Quote{}, ErrInvalid
	}
	copy := plan
	if err := copy.sealAuthorizationBasis(); err != nil {
		return Quote{}, err
	}
	request := QuoteRequest{OwnerID: copy.OwnerID, AccountGeneration: copy.AccountGeneration, ObjectiveDigest: copy.ObjectiveDigest,
		UserPromptDigest: copy.UserPromptDigest, InputManifestDigest: copy.InputManifestDigest, WorkspaceMode: copy.WorkspaceMode,
		ProposalReason: copy.ProposalReason, ModelBindingDigest: copy.ModelAuthorization.BindingDigest,
		AuthorizationBasisDigest: copy.AuthorizationBasisDigest, AWS: copy.AWS, Compute: copy.Compute, Limits: copy.Limits}
	fresh, err := quoter.quote(ctx, request)
	if err != nil {
		return Quote{}, err
	}
	now := quoter.now().UTC()
	if plan.Quote.ExpiresAt.After(now) && plan.Quote.SourceTime.Add(quoter.config.MaximumCatalogAge).After(now) &&
		plan.Quote.AmountMicros == fresh.AmountMicros && plan.Quote.MaximumAuthorizedCostMicros == fresh.MaximumAuthorizedCostMicros &&
		plan.Quote.Currency == fresh.Currency && plan.Quote.BasisDigest == fresh.BasisDigest &&
		plan.Quote.CatalogRevisionDigest == fresh.CatalogRevisionDigest {
		return plan.Quote, nil
	}
	return fresh, nil
}

func (quoter *ProductionQuoter) quote(ctx context.Context, request QuoteRequest) (Quote, error) {
	if err := validateProductionQuoteRequest(request); err != nil {
		return Quote{}, err
	}
	catalogRequest := PricingCatalogRequest{AccountID: request.AWS.AccountID, AccountGeneration: request.AccountGeneration,
		Region: request.AWS.Region, CredentialID: request.AWS.CredentialID, CredentialRevision: request.AWS.CredentialRevision,
		InstanceType: request.Compute.InstanceType, Architecture: request.Compute.Architecture,
		VolumeGiB: request.Compute.VolumeGiB, VolumeType: request.Compute.VolumeType, VolumeIOPS: request.Compute.VolumeIOPS,
		VolumeThroughput: request.Compute.VolumeThroughputMiB, MaxRuntimeSeconds: request.Limits.MaxRuntimeSeconds,
		MaxTokens: request.Limits.MaxTokens, BasisDigest: request.AuthorizationBasisDigest, WorkspaceMode: request.WorkspaceMode}
	snapshot, err := quoter.catalog.Snapshot(ctx, catalogRequest)
	if err != nil {
		return Quote{}, errors.Join(ErrInvalid, err)
	}
	now := quoter.now().UTC()
	if err := snapshot.validate(catalogRequest, now, quoter.config.MaximumCatalogAge); err != nil {
		return Quote{}, err
	}
	amount, err := estimateMaximumCost(snapshot.Rates, request.Compute, request.Limits, quoter.config.CleanupReserveSeconds)
	if err != nil || amount > uint64(math.MaxInt64) || int64(amount) > quoter.config.AbsoluteHardLimitMicros {
		return Quote{}, ErrInvalid
	}
	hard, err := scaleCostCeil(amount, uint64(10_000+quoter.config.ContingencyBasisPoints), 10_000)
	if err != nil || hard > uint64(quoter.config.AbsoluteHardLimitMicros) || hard > math.MaxInt64 {
		return Quote{}, ErrInvalid
	}
	expires := now.Add(quoter.config.QuoteTTL)
	if snapshot.ExpiresAt.Before(expires) {
		expires = snapshot.ExpiresAt
	}
	quote := Quote{AmountMicros: int64(amount), Currency: "USD", SourceTime: snapshot.SourceTime, ExpiresAt: expires,
		MaximumAuthorizedCostMicros: int64(hard), BasisDigest: request.AuthorizationBasisDigest,
		CatalogRevisionDigest: snapshot.RevisionDigest}
	if !quote.ExpiresAt.After(now) {
		return Quote{}, ErrInvalid
	}
	return quote, quote.Seal()
}

func validateProductionQuoteRequest(request QuoteRequest) error {
	if request.OwnerID == "" || request.AccountGeneration == 0 || !validDigest(request.ObjectiveDigest) || !validDigest(request.UserPromptDigest) ||
		!validDigest(request.InputManifestDigest) || !validDigest(request.ModelBindingDigest) || !validDigest(request.AuthorizationBasisDigest) ||
		!validateWorkspaceMode(request.WorkspaceMode) || validateAWS(request.AWS) != nil || validateCompute(request.Compute) != nil ||
		validateLimits(request.Limits) != nil || (request.ProposalReason != ProposalReasonExplicitUserCloud && request.ProposalReason != ProposalReasonLocalBudgetExceeded) {
		return ErrInvalid
	}
	return nil
}

func estimateMaximumCost(rates PricingCatalogRates, compute ComputeSpec, limits Limits, cleanupReserveSeconds uint64) (uint64, error) {
	runtimeSeconds, err := checkedAdd64(limits.MaxRuntimeSeconds, cleanupReserveSeconds)
	if err != nil {
		return 0, err
	}
	if runtimeSeconds < 60 {
		runtimeSeconds = 60
	}
	computeCost, err := scaleCostCeil(rates.ComputeMicrosPerHour, runtimeSeconds, 3600)
	if err != nil {
		return 0, err
	}
	ipv4Cost, err := scaleCostCeil(rates.PublicIPv4MicrosPerHour, runtimeSeconds, 3600)
	if err != nil {
		return 0, err
	}
	storageMonthly, err := multiplyCost(rates.EBSStorageMicrosPerGiBMonth, compute.VolumeGiB)
	if err != nil {
		return 0, err
	}
	extraIOPS := uint64(0)
	if compute.VolumeIOPS > 3000 {
		extraIOPS = compute.VolumeIOPS - 3000
	}
	iopsMonthly, err := multiplyCost(rates.EBSIOPSMicrosPerMonth, extraIOPS)
	if err != nil {
		return 0, err
	}
	extraThroughput := uint64(0)
	if compute.VolumeThroughputMiB > 125 {
		extraThroughput = compute.VolumeThroughputMiB - 125
	}
	throughputMonthly, err := multiplyCost(rates.EBSThroughputMicrosPerMonth, extraThroughput)
	if err != nil {
		return 0, err
	}
	ebsMonthly, err := checkedSum64(storageMonthly, iopsMonthly, throughputMonthly)
	if err != nil {
		return 0, err
	}
	ebsCost, err := scaleCostCeil(ebsMonthly, runtimeSeconds, pricingHoursPerMonth*3600)
	if err != nil {
		return 0, err
	}
	modelCost, err := scaleCostCeil(rates.ModelMicrosPerThousandTokens, limits.MaxTokens, 1000)
	if err != nil {
		return 0, err
	}
	return checkedSum64(computeCost, ipv4Cost, ebsCost, modelCost, rates.FixedRequestOverheadMicros)
}

func scaleCostCeil(rate, numerator, denominator uint64) (uint64, error) {
	if denominator == 0 || (rate != 0 && numerator > math.MaxUint64/rate) {
		return 0, ErrInvalid
	}
	product := rate * numerator
	if product > math.MaxUint64-(denominator-1) {
		return 0, ErrInvalid
	}
	return (product + denominator - 1) / denominator, nil
}

func multiplyCost(left, right uint64) (uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, ErrInvalid
	}
	return left * right, nil
}

func checkedAdd64(left, right uint64) (uint64, error) {
	if left > math.MaxUint64-right {
		return 0, ErrInvalid
	}
	return left + right, nil
}

func checkedSum64(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		var err error
		result, err = checkedAdd64(result, value)
		if err != nil {
			return 0, err
		}
	}
	return result, nil
}

var _ Quoter = (*ProductionQuoter)(nil)
