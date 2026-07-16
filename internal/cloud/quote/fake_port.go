package quote

import (
	"context"
	"fmt"
	"sync"
)

// FakePricingPort is a deterministic, read-only provider used by contract and
// recovery tests. It records only the already de-secreted PricingQueryV1.
type FakePricingPort struct {
	mu       sync.Mutex
	snapshot PricingSnapshotV1
	err      error
	queries  []PricingQueryV1
}

func NewFakePricingPort(snapshot PricingSnapshotV1) *FakePricingPort {
	return &FakePricingPort{snapshot: cloneSnapshot(snapshot)}
}

func (f *FakePricingPort) Price(ctx context.Context, query PricingQueryV1) (PricingSnapshotV1, error) {
	if ctx == nil {
		return PricingSnapshotV1{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return PricingSnapshotV1{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, cloneQuery(query))
	return cloneSnapshot(f.snapshot), f.err
}

func (f *FakePricingPort) SetResult(snapshot PricingSnapshotV1, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshot = cloneSnapshot(snapshot)
	f.err = err
}

func (f *FakePricingPort) Queries() []PricingQueryV1 {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]PricingQueryV1, len(f.queries))
	for index, query := range f.queries {
		result[index] = cloneQuery(query)
	}
	return result
}

func cloneQuery(value PricingQueryV1) PricingQueryV1 {
	value.Zones = append([]string(nil), value.Zones...)
	value.Candidates = append([]PricingCandidateQueryV1(nil), value.Candidates...)
	return value
}

func cloneSnapshot(value PricingSnapshotV1) PricingSnapshotV1 {
	value.Offerings = append([]OfferingV1(nil), value.Offerings...)
	for index := range value.Offerings {
		value.Offerings[index].AvailabilityZones = append([]string(nil), value.Offerings[index].AvailabilityZones...)
	}
	value.Quotas = append([]CandidateQuotaV1(nil), value.Quotas...)
	value.Prices = append([]CandidatePriceV1(nil), value.Prices...)
	for index := range value.Prices {
		value.Prices[index].CostItems = append([]CostItemV1(nil), value.Prices[index].CostItems...)
	}
	value.Assumptions = append([]string(nil), value.Assumptions...)
	value.Exclusions = append([]string(nil), value.Exclusions...)
	return value
}
