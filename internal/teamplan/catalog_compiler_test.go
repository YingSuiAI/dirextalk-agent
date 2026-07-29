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
	request := trustedCompileRequestFrom(validCompileRequest())
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
	if err := compiler.VerifyPlan(plan); err != nil {
		t.Fatalf("VerifyPlan() error = %v", err)
	}

	tampered := plan
	tampered.Assignments = append(
		[]WorkerAssignment(nil),
		plan.Assignments...,
	)
	tampered.Assignments[0].RuntimeImageDigest =
		"sha256:" + strings.Repeat("f", 64)
	if err := compiler.VerifyPlan(tampered); !errors.Is(err, ErrCatalogChanged) {
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
	plan, err := firstCompiler.Compile(
		trustedCompileRequestFrom(validCompileRequest()),
	)
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
	if err := secondCompiler.VerifyPlan(plan); !errors.Is(
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
	if _, err := compiler.Compile(
		trustedCompileRequestFrom(validCompileRequest()),
	); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf("Compile() error = %v, want ErrNoRuntime", err)
	}
}

func trustedCompileRequestFrom(
	request CompileRequest,
) CatalogCompileRequest {
	return CatalogCompileRequest{
		PlanID:            request.PlanID,
		Revision:          request.Revision,
		OwnerID:           request.OwnerID,
		GoalDigest:        request.GoalDigest,
		Region:            request.Region,
		PricingSnapshotID: request.PricingSnapshotID,
		Currency:          request.Currency,
		QuotedAt:          request.QuotedAt,
		ValidUntil:        request.ValidUntil,
		Proposal:          request.Proposal,
		ModelOffers:       request.ModelOffers,
		ComputeOffers:     request.ComputeOffers,
		Policy:            request.Policy,
	}
}
