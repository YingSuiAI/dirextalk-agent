package teamplan

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCatalogCompilerInjectsVerifiedCatalogAndRechecksPlan(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if plan.CatalogRevision != catalog.Revision() ||
		compiler.CatalogRevision() != catalog.Revision() {
		t.Fatalf(
			"catalog revisions = plan:%q compiler:%q catalog:%q",
			plan.CatalogRevision,
			compiler.CatalogRevision(),
			catalog.Revision(),
		)
	}
	if err := compiler.VerifyPlan(
		plan,
		request.Offers,
		request.CompileTime,
	); err != nil {
		t.Fatalf("VerifyPlan() error = %v", err)
	}

	tampered := plan
	tampered.Assignments = append(
		[]WorkerAssignment(nil),
		plan.Assignments...,
	)
	tampered.Assignments[0].RuntimeImageDigest =
		"sha256:" + strings.Repeat("f", 64)
	if err := compiler.VerifyPlan(
		tampered,
		request.Offers,
		request.CompileTime,
	); !errors.Is(err, ErrCatalogChanged) {
		t.Fatalf("tampered VerifyPlan() error = %v, want ErrCatalogChanged", err)
	}
}

func TestCatalogCompilerRejectsPlanFromSupersededCatalog(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	firstPayload := validRuntimeCatalogPayload(publicKey)
	firstCatalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, firstPayload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstCompiler, err := NewCatalogCompiler(firstCatalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	plan, err := firstCompiler.Compile(request)
	if err != nil {
		t.Fatal(err)
	}

	secondPayload := validRuntimeCatalogPayload(publicKey)
	secondPayload.GeneratedAt = secondPayload.GeneratedAt.Add(time.Minute)
	secondPayload.Releases[0].ImageDigest =
		"sha256:" + strings.Repeat("f", 64)
	secondCatalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, secondPayload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCompiler, err := NewCatalogCompiler(secondCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if secondCompiler.CatalogRevision() == firstCompiler.CatalogRevision() {
		t.Fatal("catalog mutation did not change revision")
	}
	if err := secondCompiler.VerifyPlan(
		plan,
		request.Offers,
		request.CompileTime,
	); !errors.Is(
		err,
		ErrCatalogChanged,
	) {
		t.Fatalf("superseded VerifyPlan() error = %v, want ErrCatalogChanged", err)
	}
}

func TestNewCatalogCompilerRejectsMissingCatalog(t *testing.T) {
	t.Parallel()
	if _, err := NewCatalogCompiler(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewCatalogCompiler(nil) error = %v, want ErrInvalid", err)
	}
	var compiler *CatalogCompiler
	if _, err := compiler.Compile(CatalogCompileRequest{}); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("nil Compile() error = %v, want ErrInvalid", err)
	}
}

func TestCatalogCompilerReportsCatalogWithoutQualifiedRelease(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	payload := validRuntimeCatalogPayload(publicKey)
	for index := range payload.Releases {
		payload.Releases[index].Trust = RuntimeTrustCandidate
		payload.Releases[index].Qualification = nil
	}
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, payload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	if _, err := compiler.Compile(request); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf("Compile() error = %v, want ErrNoRuntime", err)
	}
}

func TestCatalogCompilerRejectsPricingMutationAndExpiry(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	changedDocument := request.Offers.Document()
	changedDocument.ModelOffers[0].InputMicrosPerMillion++
	changedOffers, err := NewOfferSnapshot(changedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.VerifyPlan(
		plan,
		changedOffers,
		request.CompileTime,
	); !errors.Is(err, ErrPricingChanged) {
		t.Fatalf("changed pricing VerifyPlan() error = %v, want ErrPricingChanged", err)
	}
	request.CompileTime = request.Offers.ValidUntil()
	if _, err := compiler.Compile(request); !errors.Is(err, ErrPricingExpired) {
		t.Fatalf("expired Compile() error = %v, want ErrPricingExpired", err)
	}
}

func trustedCompileRequestFrom(
	t *testing.T,
	request CompileRequest,
) CatalogCompileRequest {
	t.Helper()
	return CatalogCompileRequest{
		PlanID: request.PlanID, Revision: request.Revision,
		OwnerID: request.OwnerID, GoalDigest: request.GoalDigest,
		Proposal: request.Proposal, Policy: request.Policy,
		Offers:      validOfferSnapshot(t, request),
		CompileTime: request.QuotedAt.Add(time.Minute),
	}
}

func validOfferSnapshot(
	t *testing.T,
	request CompileRequest,
) *OfferSnapshot {
	t.Helper()
	snapshot, err := NewOfferSnapshot(OfferSnapshotDocument{
		SchemaVersion: OfferSnapshotSchemaV1,
		SnapshotID:    request.PricingSnapshotID,
		Region:        request.Region, Currency: request.Currency,
		CapturedAt: request.QuotedAt, ValidUntil: request.ValidUntil,
		Sources: []OfferSourceReceipt{
			{
				Kind:       OfferSourceModelPricing,
				SourceID:   "model-catalog-v1",
				Digest:     "sha256:" + strings.Repeat("4", 64),
				CapturedAt: request.QuotedAt.Add(-time.Hour),
			},
			{
				Kind:       OfferSourceComputePricing,
				SourceID:   "aws-price-list-ap-southeast-3",
				Digest:     "sha256:" + strings.Repeat("5", 64),
				CapturedAt: request.QuotedAt,
			},
			{
				Kind:       OfferSourceComputeCapacity,
				SourceID:   "aws-ec2-offerings-ap-southeast-3",
				Digest:     "sha256:" + strings.Repeat("6", 64),
				CapturedAt: request.QuotedAt,
			},
		},
		ModelOffers:   request.ModelOffers,
		ComputeOffers: request.ComputeOffers,
	})
	if err != nil {
		t.Fatalf("NewOfferSnapshot() error = %v", err)
	}
	return snapshot
}
