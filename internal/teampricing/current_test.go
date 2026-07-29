package teampricing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestModelOfferCatalogVerifiesCurrentSnapshotModels(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	catalog, err := NewModelOfferCatalog(
		validCatalogDocument(),
		profileCatalog(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	credentials := &fakeCredentialReadiness{
		ready: map[string]bool{
			"secret_ref:model/openai-codex": true,
		},
	}
	service, err := newSnapshotService(
		catalog,
		credentials,
		&fakeComputePort{
			evidence: validComputeEvidence(now),
		},
		func() time.Time { return now },
		func() (string, error) {
			return "30000000-0000-4000-8000-000000000001", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Build(
		context.Background(),
		validPricingProviderScope(),
		"us-east-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.VerifyCurrentModels(
		context.Background(),
		snapshot,
		credentials,
	); err != nil {
		t.Fatalf("VerifyCurrentModels() error=%v", err)
	}

	credentials.ready["secret_ref:model/openai-codex"] = false
	if err := catalog.VerifyCurrentModels(
		context.Background(),
		snapshot,
		credentials,
	); !errors.Is(err, teamplan.ErrPricingChanged) {
		t.Fatalf("changed readiness error=%v", err)
	}
	credentials.ready["secret_ref:model/openai-codex"] = true

	changedCatalogDocument := validCatalogDocument()
	changedCatalogDocument.Offers[0].InputMicrosPerMillion++
	changedCatalog, err := NewModelOfferCatalog(
		changedCatalogDocument,
		profileCatalog(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := changedCatalog.VerifyCurrentModels(
		context.Background(),
		snapshot,
		credentials,
	); !errors.Is(err, teamplan.ErrPricingChanged) {
		t.Fatalf("current catalog drift error=%v", err)
	}

	document := snapshot.Document()
	document.ModelOffers[1].InputMicrosPerMillion++
	changed, err := teamplan.NewOfferSnapshot(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.VerifyCurrentModels(
		context.Background(),
		changed,
		credentials,
	); !errors.Is(err, teamplan.ErrPricingChanged) {
		t.Fatalf("changed model pricing error=%v", err)
	}
}
