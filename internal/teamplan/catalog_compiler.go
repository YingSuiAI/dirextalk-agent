package teamplan

import (
	"slices"
	"time"
)

// CatalogCompileRequest deliberately omits runtime releases and catalog
// revision. Those values come only from the verified startup catalog.
//
// Model and compute offers are validated here but are not authenticated by the
// runtime catalog. The application must source them from its server-owned
// pricing and capacity adapters rather than model or RPC input.
type CatalogCompileRequest struct {
	PlanID            string
	Revision          uint64
	OwnerID           string
	GoalDigest        string
	Region            string
	PricingSnapshotID string
	Currency          string
	QuotedAt          time.Time
	ValidUntil        time.Time
	Proposal          TeamProposal
	ModelOffers       []ModelOffer
	ComputeOffers     []ComputeOffer
	Policy            Policy
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
	releases := compiler.catalog.QualifiedReleases()
	if len(releases) == 0 {
		return Plan{}, ErrNoRuntime
	}
	return Compile(CompileRequest{
		PlanID:            request.PlanID,
		Revision:          request.Revision,
		OwnerID:           request.OwnerID,
		GoalDigest:        request.GoalDigest,
		Region:            request.Region,
		CatalogRevision:   compiler.catalog.Revision(),
		PricingSnapshotID: request.PricingSnapshotID,
		Currency:          request.Currency,
		QuotedAt:          request.QuotedAt,
		ValidUntil:        request.ValidUntil,
		Proposal:          request.Proposal,
		RuntimeReleases:   releases,
		ModelOffers:       append([]ModelOffer(nil), request.ModelOffers...),
		ComputeOffers:     append([]ComputeOffer(nil), request.ComputeOffers...),
		Policy:            request.Policy,
	})
}

// VerifyPlan rejects an old Plan after the startup catalog changes and checks
// that every assignment still describes the exact qualified release selected
// by the compiler.
func (compiler *CatalogCompiler) VerifyPlan(plan Plan) error {
	if compiler == nil || compiler.catalog == nil {
		return ErrInvalid
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	if plan.CatalogRevision != compiler.catalog.Revision() {
		return ErrCatalogChanged
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
