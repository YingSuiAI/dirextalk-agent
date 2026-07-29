package teampricing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestSnapshotServiceFreezesTrustedEvidenceAndReadiness(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	models, err := NewModelOfferCatalog(validCatalogDocument(), profileCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	credentials := &fakeCredentialReadiness{ready: map[string]bool{
		"secret_ref:model/openai-codex": true,
	}}
	compute := &fakeComputePort{evidence: validComputeEvidence(now)}
	service, err := newSnapshotService(
		models,
		credentials,
		compute,
		func() time.Time { return now },
		func() (string, error) {
			return "10000000-0000-4000-8000-000000000099", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := validPricingProviderScope()

	snapshot, err := service.Build(context.Background(), scope, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SnapshotID() != "10000000-0000-4000-8000-000000000099" ||
		snapshot.ProviderScope() != scope ||
		snapshot.Currency() != "USD" ||
		!snapshot.ValidUntil().Equal(now.Add(10*time.Minute)) {
		t.Fatalf("snapshot header = %#v", snapshot.Document())
	}
	if len(credentials.calls) != 1 ||
		credentials.calls[0] != "secret_ref:model/openai-codex" {
		t.Fatalf("credential readiness calls = %v", credentials.calls)
	}
	if len(compute.calls) != 1 ||
		compute.calls[0].scope != scope ||
		compute.calls[0].region != "us-east-1" {
		t.Fatalf("compute calls = %v", compute.calls)
	}
	offers := snapshot.ModelOffers()
	if len(offers) != 2 ||
		offers[0].ProfileID != "anthropic-review" ||
		offers[0].CredentialReady ||
		offers[1].ProfileID != "openai-codex" ||
		!offers[1].CredentialReady {
		t.Fatalf("model offers = %#v", offers)
	}
	if len(snapshot.Document().Sources) != 5 {
		t.Fatalf("source receipts = %#v", snapshot.Document().Sources)
	}
}

func TestSnapshotServiceFailsClosedOnEvidenceAndCredentialErrors(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	models, err := NewModelOfferCatalog(validCatalogDocument(), profileCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		credentials *fakeCredentialReadiness
		compute     ComputeEvidence
		want        error
	}{
		"credential inspection failure": {
			credentials: &fakeCredentialReadiness{err: errors.New("unavailable")},
			compute:     validComputeEvidence(now),
			want:        ErrCredentialReadinessUnavailable,
		},
		"currency mismatch": {
			credentials: &fakeCredentialReadiness{},
			compute: func() ComputeEvidence {
				value := validComputeEvidence(now)
				value.Currency = "EUR"
				return value
			}(),
			want: ErrInvalidSnapshotRequest,
		},
		"region drift": {
			credentials: &fakeCredentialReadiness{},
			compute: func() ComputeEvidence {
				value := validComputeEvidence(now)
				value.Offers[0].Region = "us-west-2"
				return value
			}(),
			want: ErrInvalidSnapshotRequest,
		},
		"provider scope drift": {
			credentials: &fakeCredentialReadiness{},
			compute: func() ComputeEvidence {
				value := validComputeEvidence(now)
				value.ProviderScope.ConnectionRevision++
				return value
			}(),
			want: ErrInvalidSnapshotRequest,
		},
		"expired compute evidence": {
			credentials: &fakeCredentialReadiness{},
			compute: func() ComputeEvidence {
				value := validComputeEvidence(now)
				for index := range value.Sources {
					value.Sources[index].CapturedAt =
						now.Add(-teamplan.OfferSnapshotValidity)
				}
				return value
			}(),
			want: ErrPricingEvidenceExpired,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			service, err := newSnapshotService(
				models,
				test.credentials,
				&fakeComputePort{evidence: test.compute},
				func() time.Time { return now },
				func() (string, error) {
					return "10000000-0000-4000-8000-000000000099", nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, got := service.Build(
				context.Background(),
				validPricingProviderScope(),
				"us-east-1",
			)
			if !errors.Is(got, test.want) {
				t.Fatalf("Build() error = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSnapshotServiceRejectsInvalidRegionBeforeProviderCall(t *testing.T) {
	t.Parallel()
	models, err := NewModelOfferCatalog(validCatalogDocument(), profileCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	compute := &fakeComputePort{}
	service, err := newSnapshotService(
		models,
		&fakeCredentialReadiness{},
		compute,
		time.Now,
		func() (string, error) {
			return "10000000-0000-4000-8000-000000000099", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Build(
		context.Background(),
		validPricingProviderScope(),
		" us-east-1",
	); !errors.Is(err, ErrInvalidSnapshotRequest) {
		t.Fatalf("Build() error = %v", err)
	}
	if len(compute.calls) != 0 {
		t.Fatalf("compute provider called for invalid Region: %v", compute.calls)
	}
}

func TestSnapshotServiceRedactsComputeFailureAndPreservesCancellation(t *testing.T) {
	t.Parallel()
	models, err := NewModelOfferCatalog(validCatalogDocument(), profileCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	compute := &fakeComputePort{err: errors.New(
		"provider detail must not escape",
	)}
	service, err := newSnapshotService(
		models,
		&fakeCredentialReadiness{},
		compute,
		time.Now,
		func() (string, error) {
			return "10000000-0000-4000-8000-000000000099", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Build(
		context.Background(),
		validPricingProviderScope(),
		"us-east-1",
	); !errors.Is(err, ErrComputeEvidenceUnavailable) {
		t.Fatalf("Build() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Build(
		ctx,
		validPricingProviderScope(),
		"us-east-1",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Build() error = %v", err)
	}
}
