package teamplan

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

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
		"stale model pricing": func(document *OfferSnapshotDocument) {
			for index := range document.Sources {
				if document.Sources[index].Kind == OfferSourceModelPricing {
					document.Sources[index].CapturedAt =
						document.CapturedAt.Add(
							-ModelPricingEvidenceValidity - time.Microsecond,
						)
				}
			}
		},
		"validity outlives compute evidence": func(document *OfferSnapshotDocument) {
			for index := range document.Sources {
				if document.Sources[index].Kind == OfferSourceComputeCapacity {
					document.Sources[index].CapturedAt =
						document.CapturedAt.Add(-time.Minute)
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

func slicesReverse[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right =
		left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
