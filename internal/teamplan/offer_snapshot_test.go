package teamplan

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestOfferSnapshotApprovalWindowIsOneDay(t *testing.T) {
	t.Parallel()
	if OfferSnapshotValidity != 24*time.Hour {
		t.Fatalf("OfferSnapshotValidity = %s", OfferSnapshotValidity)
	}
}

func TestOfferSnapshotIsDeterministicAndDetached(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	first := validOfferSnapshot(t, request)
	document := first.Document()
	slicesReverse(document.Sources)
	slicesReverse(document.ModelOffers)
	slicesReverse(document.ComputeOffers)
	second, err := NewOfferSnapshot(document)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() ||
		first.SnapshotID() != second.SnapshotID() ||
		!reflect.DeepEqual(first.Document(), second.Document()) {
		t.Fatalf("unordered snapshots differ: %q / %q", first.Digest(), second.Digest())
	}
	firstCBOR, err := first.CanonicalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	secondCBOR, err := second.CanonicalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstCBOR, secondCBOR) {
		t.Fatal("canonical snapshot CBOR differs across input order")
	}
	document.ModelOffers[0].Model = "mutated"
	if reflect.DeepEqual(document, first.Document()) {
		t.Fatal("Document() exposed mutable snapshot state")
	}
}

func TestOfferSnapshotRejectsMissingEvidenceRegionDriftAndSecrets(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	base := validOfferSnapshot(t, request).Document()
	tests := map[string]func(*OfferSnapshotDocument){
		"invalid provider scope": func(document *OfferSnapshotDocument) {
			document.ProviderScope.ConnectionRevision = 0
		},
		"missing capacity evidence": func(document *OfferSnapshotDocument) {
			for index, source := range document.Sources {
				if source.Kind == OfferSourceComputeCapacity {
					document.Sources = append(
						document.Sources[:index],
						document.Sources[index+1:]...,
					)
					break
				}
			}
		},
		"missing compute configuration": func(document *OfferSnapshotDocument) {
			for index, source := range document.Sources {
				if source.Kind == OfferSourceComputeConfig {
					document.Sources = append(
						document.Sources[:index],
						document.Sources[index+1:]...,
					)
					break
				}
			}
		},
		"compute region drift": func(document *OfferSnapshotDocument) {
			document.ComputeOffers[0].Region = "us-east-1"
		},
		"shared capacity pool drift": func(document *OfferSnapshotDocument) {
			document.ComputeOffers[1].CapacityPool =
				document.ComputeOffers[0].CapacityPool
			document.ComputeOffers[1].AvailableUnits =
				document.ComputeOffers[0].AvailableUnits + 1
		},
		"credential in source": func(document *OfferSnapshotDocument) {
			document.Sources[0].SourceID =
				"sk-abcdefghijklmnopqrstuvwxyz"
		},
		"stale compute evidence": func(document *OfferSnapshotDocument) {
			for index := range document.Sources {
				if document.Sources[index].Kind == OfferSourceComputePricing {
					document.Sources[index].CapturedAt =
						document.CapturedAt.Add(-OfferSnapshotValidity - time.Microsecond)
				}
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			document := cloneOfferSnapshotDocument(base)
			mutate(&document)
			if _, err := NewOfferSnapshot(document); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewOfferSnapshot() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestOfferSnapshotAcceptsHistoricalModelPricingEvidence(t *testing.T) {
	t.Parallel()
	document := validOfferSnapshot(t, validCompileRequest()).Document()
	for index := range document.Sources {
		if document.Sources[index].Kind == OfferSourceModelPricing {
			document.Sources[index].CapturedAt = time.Date(
				2020, 1, 1, 0, 0, 0, 0, time.UTC,
			)
		}
	}
	if _, err := NewOfferSnapshot(document); err != nil {
		t.Fatalf("NewOfferSnapshot() error = %v", err)
	}
}

func TestOfferSnapshotValidityWindow(t *testing.T) {
	t.Parallel()
	snapshot := validOfferSnapshot(t, validCompileRequest())
	if err := snapshot.ValidateAt(snapshot.CapturedAt()); err != nil {
		t.Fatalf("ValidateAt(captured) error = %v", err)
	}
	if err := snapshot.ValidateAt(snapshot.ValidUntil()); !errors.Is(
		err,
		ErrPricingExpired,
	) {
		t.Fatalf("ValidateAt(expired) error = %v, want ErrPricingExpired", err)
	}
}

func TestOfferSnapshotRecomputesQuotedRatesScheduleAndBudget(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	snapshot := validOfferSnapshot(t, request)
	request.PricingSnapshotDigest = snapshot.Digest()
	request.ModelOffers = snapshot.ModelOffers()
	request.ComputeOffers = snapshot.ComputeOffers()
	plan, err := Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	now := snapshot.CapturedAt().Add(time.Minute)
	if err := snapshot.VerifyPlanPricing(plan, now); err != nil {
		t.Fatalf("VerifyPlanPricing() error = %v", err)
	}
	tests := map[string]func(*Plan){
		"compute rate": func(value *Plan) {
			value.Cost.Roles[0].ComputeMinimumMicros++
			value.Cost.Roles[0].TotalMinimumMicros++
			value.Cost.MinimumMicros++
		},
		"schedule": func(value *Plan) {
			value.Schedule.ExpectedWallTime += time.Second
		},
		"hard budget": func(value *Plan) {
			value.Cost.HardBudgetMicros = value.Cost.MaximumMicros * 2
		},
		"assumptions": func(value *Plan) {
			value.Cost.Assumptions[0] = "model_supplied_price"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			changed := plan
			changed.Assignments = append(
				[]WorkerAssignment(nil),
				plan.Assignments...,
			)
			changed.Cost.Roles = append(
				[]RoleCostEstimate(nil),
				plan.Cost.Roles...,
			)
			changed.Cost.Assumptions = append(
				[]string(nil),
				plan.Cost.Assumptions...,
			)
			changed.Cost.Exclusions = append(
				[]string(nil),
				plan.Cost.Exclusions...,
			)
			mutate(&changed)
			if err := snapshot.VerifyPlanPricing(
				changed,
				now,
			); !errors.Is(err, ErrPricingChanged) {
				t.Fatalf(
					"VerifyPlanPricing() error = %v, want ErrPricingChanged",
					err,
				)
			}
		})
	}
}

func slicesReverse[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right =
		left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
