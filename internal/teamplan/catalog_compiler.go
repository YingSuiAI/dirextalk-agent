package teamplan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
)

// CatalogCompileRequest deliberately omits runtime releases and catalog
// revision. Those values come only from the verified startup catalog.
type CatalogCompileRequest struct {
	PlanID      string
	Revision    uint64
	OwnerID     string
	GoalDigest  string
	TaskInput   taskinput.BindingV2
	Proposal    TeamProposal
	Policy      Policy
	Offers      *OfferSnapshot
	CompileTime time.Time
}

// WorkerReleaseApprovalGate is the mandatory Marketplace boundary when
// configured. It verifies the exact signed release both before selection and
// again against the resulting role assignment.
type WorkerReleaseApprovalGate interface {
	Revision() string
	VerifyRuntime(RuntimeRelease, time.Time) error
	BindAssignment(
		RuntimeRelease,
		WorkerAssignment,
		time.Time,
	) (WorkerMarketplaceBindingV1, error)
	VerifyAssignment(
		RuntimeRelease,
		WorkerAssignment,
		time.Time,
	) error
}

// CatalogCompiler binds every compiled Team Plan to one verified runtime
// catalog. It is immutable and safe for concurrent use.
type CatalogCompiler struct {
	catalog           *RuntimeCatalog
	supportedAdapters map[RuntimeAdapter]struct{}
	approvalGate      WorkerReleaseApprovalGate
	catalogRevision   string
	now               func() time.Time
}

// RuntimePlanningProfile is the de-secreted planning surface of one currently
// qualified runtime. It intentionally omits release IDs, images, launch facts,
// pricing, credentials, and provider coordinates.
type RuntimePlanningProfile struct {
	Family       RuntimeFamily
	Capabilities []Capability
	WorkClasses  []WorkClass
}

func NewCatalogCompiler(catalog *RuntimeCatalog) (*CatalogCompiler, error) {
	return newCatalogCompiler(catalog, nil, nil, time.Now)
}

// NewCatalogCompilerForAdapters limits planning and verification to runtime
// adapters that the installed Worker image can actually execute.
func NewCatalogCompilerForAdapters(
	catalog *RuntimeCatalog,
	adapters []RuntimeAdapter,
) (*CatalogCompiler, error) {
	if len(adapters) == 0 {
		return nil, ErrInvalid
	}
	supported := make(map[RuntimeAdapter]struct{}, len(adapters))
	for _, adapter := range adapters {
		if !validRuntimeAdapter(adapter) {
			return nil, ErrInvalid
		}
		if _, duplicate := supported[adapter]; duplicate {
			return nil, ErrInvalid
		}
		supported[adapter] = struct{}{}
	}
	return newCatalogCompiler(catalog, supported, nil, time.Now)
}

// NewCatalogCompilerForMarketplace requires every runtime candidate to be
// present in the signed Worker Marketplace registry. The combined revision is
// bound into the Team Plan, so either catalog changing invalidates approval.
func NewCatalogCompilerForMarketplace(
	catalog *RuntimeCatalog,
	adapters []RuntimeAdapter,
	gate WorkerReleaseApprovalGate,
	now func() time.Time,
) (*CatalogCompiler, error) {
	if len(adapters) == 0 || gate == nil || now == nil {
		return nil, ErrInvalid
	}
	supported := make(map[RuntimeAdapter]struct{}, len(adapters))
	for _, adapter := range adapters {
		if !validRuntimeAdapter(adapter) {
			return nil, ErrInvalid
		}
		if _, duplicate := supported[adapter]; duplicate {
			return nil, ErrInvalid
		}
		supported[adapter] = struct{}{}
	}
	return newCatalogCompiler(catalog, supported, gate, now)
}

func newCatalogCompiler(
	catalog *RuntimeCatalog,
	supported map[RuntimeAdapter]struct{},
	gate WorkerReleaseApprovalGate,
	now func() time.Time,
) (*CatalogCompiler, error) {
	if catalog == nil || !sha256Pattern.MatchString(catalog.Revision()) ||
		catalog.SignerKeyID() == "" ||
		catalog.GeneratedAt().IsZero() ||
		now == nil {
		return nil, ErrInvalid
	}
	revision := catalog.Revision()
	if gate != nil {
		if !sha256Pattern.MatchString(gate.Revision()) {
			return nil, ErrInvalid
		}
		revision = combinedCatalogRevision(
			catalog.Revision(),
			gate.Revision(),
		)
	}
	return &CatalogCompiler{
		catalog:           catalog,
		supportedAdapters: supported,
		approvalGate:      gate,
		catalogRevision:   revision,
		now:               now,
	}, nil
}

func (compiler *CatalogCompiler) CatalogRevision() string {
	if compiler == nil || compiler.catalog == nil {
		return ""
	}
	return compiler.catalogRevision
}

// PlanningProfiles gives model-facing planning code a current, trusted hint
// without weakening compile-time runtime qualification.
func (compiler *CatalogCompiler) PlanningProfiles() (
	[]RuntimePlanningProfile,
	error,
) {
	if compiler == nil || compiler.catalog == nil || compiler.now == nil {
		return nil, ErrInvalid
	}
	now := compiler.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return nil, ErrInvalid
	}
	releases, err := compiler.qualifiedReleases(now)
	if err != nil {
		return nil, err
	}
	if len(releases) == 0 {
		return nil, ErrNoRuntime
	}
	profiles := make([]RuntimePlanningProfile, 0, len(releases))
	for _, release := range releases {
		workClasses := make([]WorkClass, 0, len(release.Suitability))
		for _, suitability := range release.Suitability {
			workClasses = append(workClasses, suitability.WorkClass)
		}
		slices.Sort(workClasses)
		profiles = append(profiles, RuntimePlanningProfile{
			Family:       release.Family,
			Capabilities: append([]Capability(nil), release.Capabilities...),
			WorkClasses:  workClasses,
		})
	}
	slices.SortFunc(profiles, func(left, right RuntimePlanningProfile) int {
		if byFamily := strings.Compare(string(left.Family), string(right.Family)); byFamily != 0 {
			return byFamily
		}
		return strings.Compare(
			strings.Join(capabilityStrings(left.Capabilities), "\x00"),
			strings.Join(capabilityStrings(right.Capabilities), "\x00"),
		)
	})
	return profiles, nil
}

func capabilityStrings(values []Capability) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

func (compiler *CatalogCompiler) ResolveRuntimeLaunchEvidence(
	releaseID string,
) (RuntimeLaunchEvidence, error) {
	if compiler == nil || compiler.catalog == nil {
		return RuntimeLaunchEvidence{}, ErrInvalid
	}
	release, found := compiler.releaseByID(releaseID)
	if !found {
		return RuntimeLaunchEvidence{}, ErrNoRuntime
	}
	if compiler.approvalGate != nil {
		now := compiler.now().UTC().Truncate(time.Second)
		if now.IsZero() {
			return RuntimeLaunchEvidence{}, ErrNoRuntime
		}
		if err := compiler.approvalGate.VerifyRuntime(
			release,
			now,
		); err != nil {
			if errors.Is(err, ErrRuntimeRegistryUnavailable) {
				return RuntimeLaunchEvidence{}, err
			}
			return RuntimeLaunchEvidence{}, ErrNoRuntime
		}
	}
	evidence, found := compiler.catalog.LaunchEvidence(releaseID)
	if !found {
		return RuntimeLaunchEvidence{}, ErrNoRuntime
	}
	return evidence, nil
}

// ResolveAssignmentLaunchEvidence revalidates the complete device-approved
// runtime and Marketplace binding immediately before launch authorization is
// constructed. A release ID alone is not sufficient for this boundary.
func (compiler *CatalogCompiler) ResolveAssignmentLaunchEvidence(
	assignment WorkerAssignment,
) (RuntimeLaunchEvidence, error) {
	if compiler == nil ||
		compiler.catalog == nil ||
		validateAssignment(assignment) != nil {
		return RuntimeLaunchEvidence{}, ErrNoRuntime
	}
	release, found := compiler.releaseByID(
		assignment.RuntimeReleaseID,
	)
	if !found ||
		assignment.RuntimeFamily != release.Family ||
		assignment.RuntimeVersion != release.Version ||
		assignment.RuntimeImageDigest != release.ImageDigest ||
		assignment.RuntimeAdapter != release.Adapter {
		return RuntimeLaunchEvidence{}, ErrNoRuntime
	}
	if compiler.approvalGate == nil {
		if assignment.Marketplace != nil {
			return RuntimeLaunchEvidence{}, ErrNoRuntime
		}
	} else {
		now := compiler.now().UTC().Truncate(time.Second)
		if now.IsZero() ||
			compiler.approvalGate.VerifyAssignment(
				release,
				assignment,
				now,
			) != nil {
			return RuntimeLaunchEvidence{}, ErrNoRuntime
		}
	}
	evidence, found := compiler.catalog.LaunchEvidence(
		assignment.RuntimeReleaseID,
	)
	if !found {
		return RuntimeLaunchEvidence{}, ErrNoRuntime
	}
	return evidence, nil
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
	releases, err := compiler.qualifiedReleases(request.CompileTime)
	if err != nil {
		return Plan{}, err
	}
	if len(releases) == 0 {
		return Plan{}, ErrNoRuntime
	}
	plan, err := Compile(CompileRequest{
		PlanID:                request.PlanID,
		Revision:              request.Revision,
		OwnerID:               request.OwnerID,
		GoalDigest:            request.GoalDigest,
		TaskInput:             request.TaskInput,
		ProviderScope:         request.Offers.ProviderScope(),
		Region:                request.Offers.Region(),
		CatalogRevision:       compiler.catalogRevision,
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
	if err != nil {
		return Plan{}, err
	}
	if compiler.approvalGate != nil {
		plan, err = compiler.bindAssignments(
			plan,
			releases,
			request.CompileTime,
		)
		if err != nil ||
			compiler.verifyAssignments(
				plan,
				releases,
				request.CompileTime,
			) != nil {
			return Plan{}, ErrNoRuntime
		}
		if validatePlan(plan) != nil {
			return Plan{}, ErrInvalid
		}
	}
	return plan, nil
}

// VerifyPlan rejects an old Plan after either startup catalog or Offer
// Snapshot changes. It rechecks every selected runtime, model and machine
// against those immutable inputs before approval or execution.
func (compiler *CatalogCompiler) VerifyPlan(
	plan Plan,
	offers *OfferSnapshot,
	policy Policy,
	now time.Time,
) error {
	if compiler == nil || compiler.catalog == nil || offers == nil {
		return ErrInvalid
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	if plan.CatalogRevision != compiler.catalogRevision {
		return ErrCatalogChanged
	}
	if err := verifyPlanPolicy(plan, policy); err != nil {
		return err
	}
	if err := offers.VerifyPlanPricing(plan, now); err != nil {
		return err
	}
	releases := make(map[string]RuntimeRelease)
	qualified, err := compiler.qualifiedReleases(now)
	if err != nil {
		return ErrCatalogChanged
	}
	for _, release := range qualified {
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
		if compiler.approvalGate != nil &&
			compiler.approvalGate.VerifyAssignment(
				release,
				assignment,
				now,
			) != nil {
			return ErrCatalogChanged
		}
	}
	return nil
}

func (compiler *CatalogCompiler) qualifiedReleases(
	at time.Time,
) ([]RuntimeRelease, error) {
	if compiler == nil || compiler.catalog == nil {
		return nil, ErrInvalid
	}
	releases := compiler.catalog.QualifiedReleases()
	if compiler.supportedAdapters == nil {
		return releases, nil
	}
	filtered := make([]RuntimeRelease, 0, len(releases))
	registryUnavailable := false
	for _, release := range releases {
		if _, supported := compiler.supportedAdapters[release.Adapter]; supported {
			if compiler.approvalGate == nil {
				filtered = append(filtered, release)
				continue
			}
			err := compiler.approvalGate.VerifyRuntime(release, at)
			if err == nil {
				filtered = append(filtered, release)
			} else if errors.Is(err, ErrRuntimeRegistryUnavailable) {
				registryUnavailable = true
			}
		}
	}
	if len(filtered) == 0 && registryUnavailable {
		return nil, ErrRuntimeRegistryUnavailable
	}
	return filtered, nil
}

func (compiler *CatalogCompiler) releaseByID(
	releaseID string,
) (RuntimeRelease, bool) {
	if compiler == nil || compiler.catalog == nil {
		return RuntimeRelease{}, false
	}
	for _, release := range compiler.catalog.QualifiedReleases() {
		if release.ReleaseID != releaseID {
			continue
		}
		if compiler.supportedAdapters != nil {
			if _, supported := compiler.supportedAdapters[release.Adapter]; !supported {
				return RuntimeRelease{}, false
			}
		}
		return release, true
	}
	return RuntimeRelease{}, false
}

func (compiler *CatalogCompiler) verifyAssignments(
	plan Plan,
	releases []RuntimeRelease,
	at time.Time,
) error {
	byID := make(map[string]RuntimeRelease, len(releases))
	for _, release := range releases {
		byID[release.ReleaseID] = release
	}
	for _, assignment := range plan.Assignments {
		release, found := byID[assignment.RuntimeReleaseID]
		if !found ||
			compiler.approvalGate.VerifyAssignment(
				release,
				assignment,
				at,
			) != nil {
			return ErrNoRuntime
		}
	}
	return nil
}

func (compiler *CatalogCompiler) bindAssignments(
	plan Plan,
	releases []RuntimeRelease,
	at time.Time,
) (Plan, error) {
	if compiler == nil || compiler.approvalGate == nil {
		return Plan{}, ErrInvalid
	}
	byID := make(map[string]RuntimeRelease, len(releases))
	for _, release := range releases {
		byID[release.ReleaseID] = release
	}
	assignments := append([]WorkerAssignment(nil), plan.Assignments...)
	for index := range assignments {
		release, found := byID[assignments[index].RuntimeReleaseID]
		if !found {
			return Plan{}, ErrNoRuntime
		}
		binding, err := compiler.approvalGate.BindAssignment(
			release,
			assignments[index],
			at,
		)
		if err != nil {
			return Plan{}, ErrNoRuntime
		}
		binding = binding.Clone()
		assignments[index].Marketplace = &binding
	}
	plan.Assignments = assignments
	return plan, nil
}

func combinedCatalogRevision(
	runtimeRevision,
	marketRevision string,
) string {
	digest := sha256.Sum256([]byte(
		"dirextalk.teamplan.catalog-composition/v1\x00" +
			runtimeRevision + "\x00" + marketRevision,
	))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validRuntimeAdapter(value RuntimeAdapter) bool {
	switch value {
	case AdapterClaudeCodeV1,
		AdapterCodexV1,
		AdapterOpenClawV1,
		AdapterHermesV1,
		AdapterOpenCodeV1,
		AdapterPiV1:
		return true
	default:
		return false
	}
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
