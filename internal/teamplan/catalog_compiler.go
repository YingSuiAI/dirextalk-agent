package teamplan

import (
	"slices"
	"time"
)

// CatalogCompileRequest deliberately omits runtime releases and catalog
// revision. Those values come only from the verified startup catalog.
type CatalogCompileRequest struct {
	PlanID      string
	Revision    uint64
	OwnerID     string
	GoalDigest  string
	Proposal    TeamProposal
	Policy      Policy
	Offers      *OfferSnapshot
	CompileTime time.Time
}

// CatalogCompiler binds every compiled Team Plan to one verified runtime
// catalog. It is immutable and safe for concurrent use.
type CatalogCompiler struct {
	catalog *RuntimeCatalog
}

func NewCatalogCompiler(catalog *RuntimeCatalog) (*CatalogCompiler, error) {
	if catalog == nil || !sha256Pattern.MatchString(catalog.Revision()) ||
		catalog.SignerKeyID() == "" || catalog.GeneratedAt().IsZero() {
		return nil, ErrInvalid
	}
	return &CatalogCompiler{catalog: catalog}, nil
}

func (compiler *CatalogCompiler) CatalogRevision() string {
	if compiler == nil || compiler.catalog == nil {
		return ""
	}
	return compiler.catalog.Revision()
}

func (compiler *CatalogCompiler) Compile(
	request CatalogCompileRequest,
) (Plan, error) {
	if compiler == nil || compiler.catalog == nil {
		return Plan{}, ErrInvalid
	}
	if request.Offers == nil {
		return Plan{}, ErrInvalid
	}
	if err := request.Offers.ValidateAt(request.CompileTime); err != nil {
		return Plan{}, err
	}
	releases := compiler.catalog.QualifiedReleases()
	if len(releases) == 0 {
		return Plan{}, ErrNoRuntime
	}
	return Compile(CompileRequest{
		PlanID:                request.PlanID,
		Revision:              request.Revision,
		OwnerID:               request.OwnerID,
		GoalDigest:            request.GoalDigest,
		ProviderScope:         request.Offers.ProviderScope(),
		Region:                request.Offers.Region(),
		CatalogRevision:       compiler.catalog.Revision(),
		PricingSnapshotID:     request.Offers.SnapshotID(),
		PricingSnapshotDigest: request.Offers.Digest(),
		Currency:              request.Offers.Currency(),
		QuotedAt:              request.Offers.CapturedAt(),
		ValidUntil:            request.Offers.ValidUntil(),
		Proposal:              request.Proposal,
		RuntimeReleases:       releases,
		ModelOffers:           request.Offers.ModelOffers(),
		ComputeOffers:         request.Offers.ComputeOffers(),
		Policy:                request.Policy,
	})
}

// VerifyPlan rejects an old Plan after either startup catalog or Offer
// Snapshot changes. It rechecks every selected runtime, model and machine
// against those immutable inputs before approval or execution.
func (compiler *CatalogCompiler) VerifyPlan(
	plan Plan,
	offers *OfferSnapshot,
	now time.Time,
) error {
	if compiler == nil || compiler.catalog == nil || offers == nil {
		return ErrInvalid
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	if plan.CatalogRevision != compiler.catalog.Revision() {
		return ErrCatalogChanged
	}
	if err := offers.VerifyPlanPricing(plan, now); err != nil {
		return err
	}
	releases := make(map[string]RuntimeRelease)
	for _, release := range compiler.catalog.QualifiedReleases() {
		releases[release.ReleaseID] = release
	}
	for _, assignment := range plan.Assignments {
		release, exists := releases[assignment.RuntimeReleaseID]
		if !exists ||
			assignment.RuntimeFamily != release.Family ||
			assignment.RuntimeVersion != release.Version ||
			assignment.RuntimeImageDigest != release.ImageDigest ||
			assignment.RuntimeAdapter != release.Adapter ||
			assignment.ModelInterface != "" &&
				!slices.Contains(release.ModelInterfaces, assignment.ModelInterface) ||
			assignment.Resources.Arch != release.Recommended.Arch ||
			assignment.Resources.VCPU < release.Recommended.VCPU ||
			assignment.Resources.MemoryMiB < release.Recommended.MemoryMiB ||
			assignment.Resources.DiskGiB < release.Recommended.DiskGiB ||
			assignment.ColdStart != release.ColdStart ||
			!runtimeCoversAssignment(release, assignment) {
			return ErrCatalogChanged
		}
		if _, suitable := runtimeSuitability(release, assignment.WorkClass); !suitable {
			return ErrCatalogChanged
		}
	}
	return nil
}

func runtimeCoversAssignment(
	release RuntimeRelease,
	assignment WorkerAssignment,
) bool {
	for _, required := range assignment.RequiredCapabilities {
		if !slices.Contains(release.Capabilities, required) {
			return false
		}
	}
	return true
}
